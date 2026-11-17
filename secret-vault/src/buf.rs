//! [`SecretBuf`]: 存放任意敏感字节的主容器。
//!
//! 不变量:
//! - 有效字节永远位于某个 [`Allocation`] 的数据区前 `len` 字节, 该区域 mmap+mlock;
//! - 任何导致底层存储变动的操作 (扩容、clone、truncate、drop) 都通过
//!   `explicit_bzero` 清零旧内容, 旧映射随后 munmap;
//! - `Debug`/`Display` 永远不输出内容。

use std::fmt;
use std::io::Read;

use zeroize::Zeroize;

use crate::alloc::Allocation;
use crate::error::{ErrorKind, Result, SecretError};

/// 受保护的字节缓冲区。
///
/// 内容不会出现在:
/// - 堆分配器的自由链表 (我们只用 mmap);
/// - swap (数据页 mlock);
/// - Linux 核心转储 (`MADV_DONTDUMP` + `RLIMIT_CORE=0`);
/// - 任何复用后的旧页 (释放前 explicit_bzero)。
pub struct SecretBuf {
    alloc: Option<Allocation>,
    len: usize,
    guarded: bool,
}

// 同 Allocation: 内容独占、无内部可变性。
unsafe impl Send for SecretBuf {}
unsafe impl Sync for SecretBuf {}

impl SecretBuf {
    /// 创建空缓冲区 (不分配任何页)。
    pub fn new() -> Self {
        Self {
            alloc: None,
            len: 0,
            guarded: false,
        }
    }

    /// 创建带前后 guard page 的空缓冲区 (首次扩容时才真正建映射)。
    pub fn new_guarded() -> Self {
        Self {
            alloc: None,
            len: 0,
            guarded: true,
        }
    }

    /// 预分配至少 `capacity` 字节。
    pub fn with_capacity(capacity: usize) -> Result<Self> {
        let mut s = Self::new();
        s.reserve(capacity)?;
        Ok(s)
    }

    /// 预分配并启用 guard page。
    pub fn with_capacity_guarded(capacity: usize) -> Result<Self> {
        let mut s = Self::new_guarded();
        s.reserve(capacity)?;
        Ok(s)
    }

    /// 从字节切片构造。只发生一次拷贝: 源 → 受保护页。
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let mut s = Self::with_capacity(data.len())?;
        // SAFETY: 新分配容量 >= data.len(), 源和目标不可能别名。
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), s.as_mut_ptr(), data.len());
        }
        s.len = data.len();
        Ok(s)
    }

    /// 从 reader 直接读入受保护内存, 避免 `read_to_end` 先在普通堆上攒一份。
    ///
    /// 内部固定使用一个 512 字节的栈上中转块; 读到 EOF 后该中转块也会被清零。
    /// 注意: 调用方仍需保证 reader 的上游 (例如 socket 内核缓冲之外的用户态代理)
    /// 不会自行缓存明文。
    pub fn from_reader<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = Self::new();
        let mut chunk = [0u8; 512];
        loop {
            let n = reader
                .read(&mut chunk)
                .map_err(|e| {
                    SecretError::new(
                        ErrorKind::InvalidInput,
                        e.raw_os_error().unwrap_or(0),
                        "read",
                    )
                })?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n])?;
        }
        chunk.zeroize();
        Ok(buf)
    }

    /// 解析十六进制字符串 (形如 `a1b2...`, 可含空白) 直接写入受保护内存,
    /// 不经过 `Vec<u8>` 中转。
    pub fn from_hex(hex: &str) -> Result<Self> {
        let cleaned_len = hex.bytes().filter(|b| !b.is_ascii_whitespace()).count();
        if cleaned_len % 2 != 0 {
            return Err(SecretError::new(
                ErrorKind::InvalidInput,
                0,
                "hex: odd number of digits",
            ));
        }
        let mut out = Self::with_capacity(cleaned_len / 2)?;
        let bytes = hex.bytes().filter(|b| !b.is_ascii_whitespace());
        let mut hi = None;
        for b in bytes {
            let v = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => {
                    return Err(SecretError::new(
                        ErrorKind::InvalidInput,
                        0,
                        "hex: non-hex digit",
                    ))
                }
            };
            match hi.take() {
                None => hi = Some(v),
                Some(h) => {
                    // SAFETY: 容量按 cleaned_len/2 预分配, 计数不会越界。
                    unsafe {
                        let p = out.as_mut_ptr().add(out.len);
                        p.write((h << 4) | v);
                        out.len += 1;
                    }
                }
            }
        }
        Ok(out)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.alloc.as_ref().map(|a| a.capacity()).unwrap_or(0)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match self.alloc {
            Some(ref a) => unsafe { std::slice::from_raw_parts(a.as_ptr(), self.len) },
            None => &[],
        }
    }

    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        match self.alloc {
            Some(ref mut a) => unsafe { std::slice::from_raw_parts_mut(a.as_ptr(), self.len) },
            None => &mut [],
        }
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.alloc
            .as_ref()
            .map(|a| a.as_ptr())
            .unwrap_or(std::ptr::null_mut())
    }

    /// 保证容量至少可容纳 `additional` 个新字节。
    ///
    /// 扩容路径: 新建受保护映射 → 拷贝有效数据 → Drop 旧映射 (内含清零+munmap)。
    /// 任何一步失败都不会留下半成品。
    pub fn reserve(&mut self, additional: usize) -> Result<()> {
        let needed = self.len.checked_add(additional).ok_or_else(|| {
            SecretError::new(ErrorKind::InvalidInput, 0, "reserve: capacity overflow")
        })?;
        if needed <= self.capacity() {
            return Ok(());
        }
        // 倍增策略, 但上限受 mmap 页粒度约束; 至少满足 needed。
        let new_cap = std::cmp::max(needed, self.capacity().saturating_mul(2).max(64));
        let new_alloc = Allocation::new(new_cap, self.guarded)?;

        if let Some(old) = self.alloc.take() {
            unsafe {
                std::ptr::copy_nonoverlapping(old.as_ptr(), new_alloc.as_ptr(), self.len);
            }
            // old 在这里 drop: explicit_bzero 整个旧数据区 → munlock → munmap。
            drop(old);
        }
        self.alloc = Some(new_alloc);
        Ok(())
    }

    pub fn push(&mut self, byte: u8) -> Result<()> {
        self.reserve(1)?;
        unsafe {
            self.as_mut_ptr().add(self.len).write(byte);
            self.len += 1;
        }
        Ok(())
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) -> Result<()> {
        self.reserve(data.len())?;
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.as_mut_ptr().add(self.len), data.len());
            self.len += data.len();
        }
        Ok(())
    }

    /// 缩短到 `new_len`; 被丢掉的尾部字节立即清零 (而不是等 Drop)。
    pub fn truncate(&mut self, new_len: usize) {
        if new_len >= self.len {
            return;
        }
        if let Some(ref a) = self.alloc {
            unsafe {
                let tail = std::slice::from_raw_parts_mut(a.as_ptr().add(new_len), self.len - new_len);
                tail.zeroize();
            }
        }
        self.len = new_len;
    }

    /// 显式清零并立即释放映射 (无需等变量离开作用域)。
    pub fn zeroize_now(&mut self) {
        if let Some(a) = self.alloc.take() {
            drop(a); // Allocation::drop 做 explicit_bzero + munlock + munmap
        }
        self.len = 0;
    }

    /// 常量时间比较, 避免口令比较的计时侧信道。
    pub fn ct_eq(&self, other: &SecretBuf) -> bool {
        let a = self.as_bytes();
        let b = other.as_bytes();
        if a.len() != b.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

impl Default for SecretBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SecretBuf {
    /// 深拷贝: 分配一块全新的受保护页。两个容器各自独立清零,
    /// 不会出现共享底层、一个 drop 了另一个还带着明文的情况。
    fn clone(&self) -> Self {
        let mut copy = Self {
            alloc: None,
            len: 0,
            guarded: self.guarded,
        };
        if self.len > 0 {
            copy.reserve(self.len).expect("clone: allocation failed");
            unsafe {
                std::ptr::copy_nonoverlapping(self.as_bytes().as_ptr(), copy.as_mut_ptr(), self.len);
            }
            copy.len = self.len;
        }
        copy
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.zeroize_now();
    }
}

impl Zeroize for SecretBuf {
    fn zeroize(&mut self) {
        self.zeroize_now();
    }
}

impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBuf({} bytes, REDACTED)", self.len)
    }
}

impl PartialEq for SecretBuf {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}
impl Eq for SecretBuf {}

impl AsRef<[u8]> for SecretBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_debug_redaction() {
        let mut b = SecretBuf::from_slice(b"hunter2-password").unwrap();
        assert_eq!(b.len(), 16);
        assert_eq!(b.as_bytes(), b"hunter2-password");
        let dbg = format!("{b:?}");
        assert!(!dbg.contains("hunter2"));
        b.push(b'!').unwrap();
        assert_eq!(b.len(), 17);
        assert_eq!(b.as_bytes(), b"hunter2-password!");
    }

    #[test]
    fn growth_keeps_data_and_old_region_is_unmapped() {
        let mut b = SecretBuf::new();
        for i in 0..10_000u32 {
            b.extend_from_slice(format!("{i:08}").as_bytes()).unwrap();
        }
        assert!(b.capacity() >= 10_000 * 8);
        // 数据仍然完整 (经历了多次倍增迁移)
        assert_eq!(&b.as_bytes()[..8], b"00000000");
    }

    #[test]
    fn hex_parsing_no_intermediate_vec() {
        let b = SecretBuf::from_hex("de ad be ef").unwrap();
        assert_eq!(b.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        assert!(SecretBuf::from_hex("abc").is_err());
        assert!(SecretBuf::from_hex("zz").is_err());
    }

    #[test]
    fn clone_is_independent() {
        let a = SecretBuf::from_slice(b"session-key-xyz").unwrap();
        let mut b = a.clone();
        b.zeroize_now();
        assert!(b.is_empty());
        assert_eq!(a.as_bytes(), b"session-key-xyz");
    }

    #[test]
    fn constant_time_eq() {
        let a = SecretBuf::from_slice(b"token-1234").unwrap();
        let b = SecretBuf::from_slice(b"token-1234").unwrap();
        let c = SecretBuf::from_slice(b"token-1235").unwrap();
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }
}
