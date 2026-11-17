//! 错误类型。
//!
//! 所有失败都带上 `errno` 和发生位置, 方便排查 mlock/mmap 这类系统调用失败。

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// mmap/mach_vm_allocate 失败
    MapFailed,
    /// mlock 失败 (常见原因: 超过 RLIMIT_MEMLOCK, 权限不足)
    LockFailed,
    /// madvise/mprotect 等内存属性调整失败
    AdviseFailed,
    /// 输入不合法 (空指针、长度越界、UTF-8 校验失败等)
    InvalidInput,
}

#[derive(Debug, Clone)]
pub struct SecretError {
    kind: ErrorKind,
    errno: i32,
    context: &'static str,
}

impl SecretError {
    pub fn new(kind: ErrorKind, errno: i32, context: &'static str) -> Self {
        Self {
            kind,
            errno,
            context,
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn raw_os_error(&self) -> i32 {
        self.errno
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "secret-vault error: {:?} at {} (errno={})",
            self.kind, self.context, self.errno
        )
    }
}

impl std::error::Error for SecretError {}

pub(crate) fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub type Result<T> = std::result::Result<T, SecretError>;
