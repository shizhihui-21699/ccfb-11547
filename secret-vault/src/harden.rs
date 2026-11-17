//! 进程级加固: 核心转储限制、mlock 用量统计。
//!
//! 这些是 "容器之外" 的纵深防御 —— 单靠容器本身挡不住别人往普通内存里写秘密,
//! 所以服务启动时应当调用一次 [`harden_process`]。

use std::sync::atomic::{AtomicUsize, Ordering};

use libc::{rlimit, setrlimit, RLIMIT_CORE};

/// 进程内累计被 mlock 的字节数 (仅统计, 便于自检和测试断言)。
static LOCKED_BYTES: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn record_locked_bytes(n: usize) {
    LOCKED_BYTES.fetch_add(n, Ordering::Relaxed);
}

/// 当前进程通过本库 mlock 的总字节数。
pub fn locked_bytes() -> usize {
    LOCKED_BYTES.load(Ordering::Relaxed)
}

/// 把核心转储大小限制设为 0。
///
/// - Linux: 除了这里, 每个分配还会做 `MADV_DONTDUMP`, 双保险。
/// - macOS: 没有 per-region 的 dump-exclude 接口, 全进程禁 core 是唯一手段;
///   另外 macOS 系统默认 swap 加密, 但崩溃转储、`lldb -c` 仍受这个限制约束。
///
/// 返回 `Some(旧的 soft limit)`; 设置失败返回错误。
pub fn disable_core_dumps() -> std::io::Result<Option<u64>> {
    let mut old: rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(RLIMIT_CORE, &mut old) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let previous = if old.rlim_cur == libc::RLIM_INFINITY {
        None
    } else {
        Some(old.rlim_cur as u64)
    };

    let zero = rlimit {
        rlim_cur: 0,
        rlim_max: old.rlim_max, // hard limit 不动, 不需要提权就能改 soft
    };
    if unsafe { setrlimit(RLIMIT_CORE, &zero) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(previous)
}

/// 一次性进程加固, 服务 `main` 开头调用。
///
/// 当前包含: 禁用核心转储。后续可在此扩展 (如 Linux 的 PR_SET_DUMPABLE=0、
/// seccomp 白名单等)。
pub fn harden_process() -> std::io::Result<HardeningReport> {
    let previous_core_limit = disable_core_dumps()?;
    Ok(HardeningReport {
        previous_core_limit,
        core_dumps_disabled: true,
    })
}

#[derive(Debug, Clone)]
pub struct HardeningReport {
    pub previous_core_limit: Option<u64>,
    pub core_dumps_disabled: bool,
}

/// Linux 专有: 把 dumpable 标志清掉 (ptrace 附加、`/proc/pid/mem` 读取都会受限)。
#[cfg(target_os = "linux")]
pub fn set_non_dumpable() -> std::io::Result<()> {
    // PR_SET_DUMPABLE = 4
    if unsafe { libc::prctl(4, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
