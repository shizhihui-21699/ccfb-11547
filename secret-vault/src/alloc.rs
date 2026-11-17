//! 页面级分配器: 所有敏感数据的唯一内存来源。
//!
//! # 设计要点
//!
//! 1. **只走 mmap, 不碰 malloc/堆分配器**。glibc/jemalloc 的扩容会把旧块留在
//!    自由链表里等复用, 没人保证覆盖; mmap 的区域生命周期完全由我们自己掌控。
//! 2. **`MAP_PRIVATE | MAP_ANON`**: 匿名页, 没有文件后端, 不会被 page cache 关联。
//! 3. **`mlock`**: 锁住物理页, 内核不会把它换出到 swap。
//! 4. **Linux 上 `madvise(MADV_DONTDUMP)`**: 核心转储里直接排除这段区域。
//! 5. **Drop 顺序固定**: explicit_bzero 清零 → (可选 MADV_DONTNEED) → munlock → munmap。
//!    先清零再解除映射, 防止物理页被回收后带着数据分给别人。
//! 6. **可选 guard page**: 数据区前后各放一个 `PROT_NONE` 页, 越界访问立刻 SIGSEGV,
//!    同时也让数据区在地址空间里和别的分配隔离开, 扫描时定位更明确。

use std::ptr::NonNull;

use libc::{
    c_void, mlock, mmap, mprotect, munlock, munmap, MAP_ANON, MAP_FAILED, MAP_PRIVATE, PROT_NONE,
    PROT_READ, PROT_WRITE,
};

use crate::error::{errno, ErrorKind, Result, SecretError};
use crate::harden;

#[cfg(target_os = "linux")]
use libc::{madvise, MADV_DONTDUMP};

/// 强制清零: 易失写 + 编译器屏障。
///
/// 不依赖 libc 的 `explicit_bzero` 绑定 (libc 0.2 在 macOS 未导出该符号)。
/// `write_volatile` 保证每次存储不可被优化掉, `compiler_fence` 阻止清零被
/// 重排到 munmap 之后。与 `zeroize` crate 的核心手法一致。
unsafe fn explicit_zero(s: *mut c_void, n: usize) {
    let p = s as *mut u8;
    for i in 0..n {
        unsafe {
            std::ptr::write_volatile(p.add(i), 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// 一次受保护的内存分配。
///
/// `ptr` 指向数据区起始 (guard page 模式下也是数据区, 不含 guard 页),
/// `data_len` 是数据区字节数, `mapping_len` 是整个映射 (含 guard 页) 的字节数。
pub(crate) struct Allocation {
    ptr: NonNull<u8>,
    data_len: usize,
    mapping_len: usize,
    guarded: bool,
    locked: bool,
}

// 数据区内容由我们独占, 没有内部可变性, 发送/共享都是安全的。
unsafe impl Send for Allocation {}
unsafe impl Sync for Allocation {}

impl Allocation {
    /// 分配至少 `data_len` 字节的数据区 (向上取整到整页)。
    ///
    /// `guard_pages = true` 时数据区前后各加一个不可访问页。
    /// 默认会执行 mlock; 失败时整个分配回滚并返回错误。
    pub(crate) fn new(data_len: usize, guard_pages: bool) -> Result<Self> {
        if data_len == 0 {
            return Err(SecretError::new(
                ErrorKind::InvalidInput,
                0,
                "Allocation::new: zero length",
            ));
        }

        let page_size = page_size();
        let data_pages = data_len.div_ceil(page_size);
        let aligned_data = data_pages * page_size;
        let guard = if guard_pages { page_size } else { 0 };
        let mapping_len = aligned_data + guard * 2;

        // 先以 PROT_NONE 建立整个映射 (含 guard 位), 再只放开数据区。
        let raw = unsafe {
            mmap(
                std::ptr::null_mut(),
                mapping_len,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };
        if raw == MAP_FAILED {
            return Err(SecretError::new(
                ErrorKind::MapFailed,
                errno(),
                "mmap(PROT_NONE)",
            ));
        }

        let mapping_base = raw as usize;
        let data_ptr = mapping_base + guard;

        let protect_rc = unsafe {
            mprotect(
                data_ptr as *mut c_void,
                aligned_data,
                PROT_READ | PROT_WRITE,
            )
        };
        if protect_rc != 0 {
            let e = SecretError::new(
                ErrorKind::MapFailed,
                errno(),
                "mprotect(data RW)",
            );
            // 回滚映射
            unsafe { munmap(raw, mapping_len) };
            return Err(e);
        }

        // mlock 只锁数据区, guard 页不可访问不能锁。
        let lock_rc = unsafe { mlock(data_ptr as *mut c_void, aligned_data) };
        let locked = lock_rc == 0;
        if !locked {
            let e = SecretError::new(
                ErrorKind::LockFailed,
                errno(),
                "mlock(data region)",
            );
            unsafe { munmap(raw, mapping_len) };
            return Err(e);
        }

        // Linux: 从核心转储中排除 (macOS 没有等价 madvise, 用 RLIMIT_CORE=0 兜底,
        // 见 harden::disable_core_dumps)。
        #[cfg(target_os = "linux")]
        {
            let rc = unsafe { madvise(data_ptr as *mut c_void, aligned_data, MADV_DONTDUMP) };
            if rc != 0 {
                let e = SecretError::new(
                    ErrorKind::AdviseFailed,
                    errno(),
                    "madvise(MADV_DONTDUMP)",
                );
                unsafe {
                    munlock(data_ptr as *mut c_void, aligned_data);
                    munmap(raw, mapping_len);
                }
                return Err(e);
            }
        }

        harden::record_locked_bytes(aligned_data);

        Ok(Self {
            ptr: NonNull::new(data_ptr as *mut u8).expect("mmap returned non-null"),
            data_len: aligned_data,
            mapping_len,
            guarded: guard_pages,
            locked,
        })
    }

    #[inline]
    pub(crate) fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// 数据区容量 (整页对齐后的字节数)。
    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        self.data_len
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn is_guarded(&self) -> bool {
        self.guarded
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn is_locked(&self) -> bool {
        self.locked
    }

    /// 对数据区做一次编译器不可优化掉的全量清零。
    #[inline]
    pub(crate) fn explicit_zero(&self) {
        unsafe { explicit_zero(self.as_ptr() as *mut c_void, self.data_len) };
    }
}

impl Drop for Allocation {
    fn drop(&mut self) {
        // 1. 先清零 —— 这一步绝对不能省, 也不能被优化。
        self.explicit_zero();

        // 2. 可选: 主动断开物理页 (Linux)。MADV_DONTNEED 让匿名页立刻被回收,
        //    后续访问得到全新零页, 进一步降低旧内容经页复用泄漏的窗口。
        #[cfg(all(target_os = "linux", feature = "madvise"))]
        unsafe {
            libc::madvise(
                self.as_ptr() as *mut c_void,
                self.data_len,
                libc::MADV_DONTNEED,
            );
        }

        // 3. 解锁。
        if self.locked {
            unsafe {
                munlock(self.as_ptr() as *mut c_void, self.data_len);
            }
        }

        // 4. 解除映射。munmap 的基址要回到整个映射的起点 (guard 模式下有前导页)。
        let base = if self.guarded {
            self.as_ptr() as usize - page_size()
        } else {
            self.as_ptr() as usize
        };
        unsafe {
            munmap(base as *mut c_void, self.mapping_len);
        }
    }
}

pub(crate) fn page_size() -> usize {
    // libc 常量在主流目标上都是编译期可用的; 再用 sysconf 兜底。
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 {
        v as usize
    } else {
        4096
    }
}
