//! [`SecretBox<T>`]: 定长敏感值容器, 面向加密密钥、会话密钥等 `Copy` 类型。
//!
//! 与 [`crate::SecretBuf`] 的区别: 长度编译期已知, 单页分配, 适合存
//! `[u8; 32]` 这类 key material。约束 `T: Copy` 是有意的 —— 带析构、
//! 带堆分配的类型放进来会绕过我们的清零保证。

use std::fmt;
use std::marker::PhantomData;

use crate::alloc::Allocation;
use crate::error::{ErrorKind, Result, SecretError};

pub struct SecretBox<T: Copy + 'static> {
    alloc: Allocation,
    _marker: PhantomData<T>,
}

unsafe impl<T: Copy + 'static> Send for SecretBox<T> {}
unsafe impl<T: Copy + 'static> Sync for SecretBox<T> {}

impl<T: Copy + 'static> SecretBox<T> {
    /// 把 `value` 移动进受保护页。
    ///
    /// 注意: 调用处栈上的原变量不会被自动清零, 推荐写法是
    /// `let key = SecretBox::new(raw_key);` 之后立刻让 `raw_key` 离开作用域,
    /// 或对其调用 `zeroize`。
    pub fn new(value: T) -> Result<Self> {
        let size = std::mem::size_of::<T>().max(1);
        let alloc = Allocation::new(size, false)?;
        unsafe {
            std::ptr::write_unaligned(alloc.as_ptr() as *mut T, value);
        }
        Ok(Self {
            alloc,
            _marker: PhantomData,
        })
    }

    /// 带 guard page 的变体。
    pub fn new_guarded(value: T) -> Result<Self> {
        let size = std::mem::size_of::<T>().max(1);
        let alloc = Allocation::new(size, true)?;
        unsafe {
            std::ptr::write_unaligned(alloc.as_ptr() as *mut T, value);
        }
        Ok(Self {
            alloc,
            _marker: PhantomData,
        })
    }

    #[inline]
    pub fn get(&self) -> &T {
        unsafe { &*(self.alloc.as_ptr() as *const T) }
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        unsafe { &mut *(self.alloc.as_ptr() as *mut T) }
    }

    /// 取出值的拷贝。返回的普通 `T` 脱离保护, 调用方负责尽快用完并清零。
    #[inline]
    pub fn expose(&self) -> T {
        unsafe { std::ptr::read_unaligned(self.alloc.as_ptr() as *const T) }
    }

    /// 立即对类型占用字节做语义清零 (整页的彻底清零在 Drop 时发生)。
    pub fn zeroize_now(&mut self) {
        unsafe {
            let p = self.alloc.as_ptr() as *mut T;
            std::ptr::drop_in_place(p);
            std::ptr::write_bytes(p as *mut u8, 0, std::mem::size_of::<T>());
        }
    }
}

impl<T: Copy + 'static> Clone for SecretBox<T> {
    fn clone(&self) -> Self {
        let value = self.expose();
        // 与 new 相同的单页受保护分配; 失败属于 OOM, 与 Vec::clone 一样 panic。
        Self::new(value).expect("SecretBox clone: allocation failed")
    }
}

impl<T: Copy + 'static> Drop for SecretBox<T> {
    fn drop(&mut self) {
        // 先按类型语义 drop (Copy 类型无实际析构逻辑), 再整页清零。
        unsafe {
            let p = self.alloc.as_ptr() as *mut T;
            std::ptr::drop_in_place(p);
        }
        // Allocation 自身的 Drop: explicit_bzero 整页 → munlock → munmap
    }
}

impl<T: Copy + 'static> fmt::Debug for SecretBox<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecretBox<{}>({} bytes, REDACTED)",
            std::any::type_name::<T>(),
            std::mem::size_of::<T>()
        )
    }
}

/// 常用: 原始密钥字节数组的类型别名。
pub type SecretKey<const N: usize> = SecretBox<[u8; N]>;

/// 辅助: 把一个字节切片收进定长密钥, 长度不符直接报错, 不做任何截断/填充。
impl<const N: usize> SecretBox<[u8; N]> {
    pub fn from_slice_exact(data: &[u8]) -> Result<Self> {
        if data.len() != N {
            return Err(SecretError::new(
                ErrorKind::InvalidInput,
                0,
                "SecretKey: slice length mismatch",
            ));
        }
        let mut key = [0u8; N];
        key.copy_from_slice(data);
        Self::new(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_size_key_roundtrip() {
        let raw: [u8; 32] = (0..32u8).collect::<Vec<u8>>().try_into().unwrap();
        let k = SecretBox::new(raw).unwrap();
        assert_eq!(k.get(), &raw);
        let dbg = format!("{k:?}");
        assert!(dbg.contains("REDACTED"));
        let again = k.clone();
        assert_eq!(again.get(), k.get());
    }

    #[test]
    fn exact_slice_rejects_wrong_length() {
        assert!(SecretBox::<[u8; 16]>::from_slice_exact(&[0u8; 15]).is_err());
        let k = SecretBox::<[u8; 16]>::from_slice_exact(&[7u8; 16]).unwrap();
        assert_eq!(k.get(), &[7u8; 16]);
    }
}
