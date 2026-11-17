//! 扫描器的受保护暂存缓冲。
//!
//! 内存扫描有个固有矛盾: 必须先把目标进程的字节读到自己进程的一块缓冲里
//! 才能搜索, 于是这块缓冲在扫描期间会回显所有被测内容。如果它是普通
//! `Vec`, 明文就短暂落到了 malloc 堆上 —— 测量仪器自己成了泄漏点。
//!
//! 这里用 secret-vault 的受保护页承载暂存缓冲: mmap+mlock、不进堆、
//! Drop 时整页 explicit-zero + munmap。扫描结束后缓冲清零, 不留回声。

use secret_vault::SecretBuf;

pub(crate) struct ProtectedScratch {
    buf: SecretBuf,
    capacity: usize,
}

impl ProtectedScratch {
    /// 分配至少 `capacity` 字节的受保护暂存区 (实际按页向上取整)。
    pub(crate) fn new(capacity: usize) -> std::io::Result<Self> {
        let buf = SecretBuf::with_capacity(capacity).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::OutOfMemory, e.to_string())
        })?;
        let capacity = buf.capacity(); // 以实际页对齐容量为准
        Ok(Self { buf, capacity })
    }

    /// 可写的原始指针 (供 mach_vm_read_overwrite / pread 直接写入)。
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        // 底层分配容量为 self.capacity; 写入不超过它即安全。
        // SecretBuf 的 len 为 0 不影响对已分配页的原始写, 我们手动管理有效长度。
        self.buf.as_bytes().as_ptr() as *mut u8
    }

    /// 已读取 `n` 字节后, 返回这部分的只读视图。
    ///
    /// # Safety
    /// 调用方必须保证前 `n` 字节已由系统调用真实写入, 且 `n <= capacity()`。
    pub(crate) unsafe fn filled(&self, n: usize) -> &[u8] {
        std::slice::from_raw_parts(self.buf.as_bytes().as_ptr(), n.min(self.capacity))
    }

    /// 暂存页的虚拟地址区间 (start, end), 供扫描器在报告里标注自身回显。
    pub(crate) fn address_range(&self) -> (u64, u64) {
        let start = self.buf.as_bytes().as_ptr() as u64;
        (start, start + self.capacity as u64)
    }
}

impl Drop for ProtectedScratch {
    fn drop(&mut self) {
        // SecretBuf 的 Drop 已做整页清零+munmap; 这里显式再触发一次语义清零。
        self.buf.zeroize_now();
    }
}
