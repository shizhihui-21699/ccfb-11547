//! Linux: `/proc/self/maps` enumeration and `process_vm_readv` copying.
//!
//! Reading through `process_vm_readv` rather than a pointer dereference keeps
//! a racing `munmap` from faulting the audit: the kernel returns `EFAULT` for
//! a vanished range, which is recorded as a skip.

use std::ffi::c_void;

use crate::report::{RegionKind, ScanRegion};
use crate::{Error, Result};

/// A target process. On Linux, reading another process is governed by
/// `ptrace` access; `process_vm_readv` returns `EPERM` when it is denied.
pub(crate) struct TaskHandle {
    pid: libc::pid_t,
}

impl TaskHandle {
    pub(crate) fn current() -> TaskHandle {
        TaskHandle { pid: 0 }
    }

    pub(crate) fn port(&self) -> libc::pid_t {
        self.pid
    }

    pub(crate) fn pid(&self) -> libc::pid_t {
        self.pid
    }

    pub(crate) fn for_pid(pid: libc::c_int) -> Result<TaskHandle> {
        // Fail early with a clear message rather than EPERM deep in the scan.
        let status = format!("/proc/{pid}/status");
        let text = std::fs::read_to_string(&status)
            .map_err(|e| Error::Scan(format!("cannot read {status}: {e}")))?;
        let _ = text;
        Ok(TaskHandle { pid })
    }
}

pub(crate) fn regions() -> Result<Vec<ScanRegion>> {
    regions_of(&TaskHandle::current())
}

pub(crate) fn regions_of(task: &TaskHandle) -> Result<Vec<ScanRegion>> {
    let path = if task.pid() == 0 {
        "/proc/self/maps".to_string()
    } else {
        format!("/proc/{}/maps", task.pid())
    };
    let maps = std::fs::read_to_string(&path)
        .map_err(|e| Error::Scan(format!("{path}: {e}")))?;
    let mut out = Vec::with_capacity(256);
    for line in maps.lines() {
        // Format: start-end perms offset dev inode [path]
        let mut it = line.split_whitespace();
        let (Some(range), Some(perms)) = (it.next(), it.next()) else {
            continue;
        };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        let bytes = perms.as_bytes();
        if bytes.len() < 3 {
            continue;
        }
        let readable = bytes[0] == b'r';
        let writable = bytes[1] == b'w';
        let executable = bytes[2] == b'x';
        let name = it.next().map(|s| s.to_string()).filter(|s| !s.is_empty());
        let kind = if let Some(n) = name.as_deref() {
            // [heap] / [stack] / [anon:*] are anonymous; anything else is a file.
            if n.starts_with('[') {
                RegionKind::Anonymous
            } else if executable {
                RegionKind::Image
            } else {
                RegionKind::FileBacked
            }
        } else {
            RegionKind::Anonymous
        };
        out.push(ScanRegion {
            start,
            end,
            readable,
            writable,
            executable,
            kind,
            name,
            skipped: None,
        });
    }
    Ok(out)
}

pub(crate) struct Scratch {
    ptr: *mut u8,
    len: usize,
    mapped: usize,
    pid: libc::pid_t,
}

impl Scratch {
    pub(crate) fn new(n: usize) -> Result<Self> {
        Self::new_for(n, 0)
    }

    pub(crate) fn new_for(n: usize, pid: libc::pid_t) -> Result<Self> {
        let page = secretmem::page_size();
        let len = n.div_ceil(page) * page;
        // SAFETY: anonymous private mapping, exclusively owned.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(Error::Scan(format!(
                "scratch mmap failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Scratch { ptr: p as *mut u8, len, mapped: len, pid })
    }

    pub(crate) fn range(&self) -> (u64, u64) {
        (self.ptr as u64, self.ptr as u64 + self.len as u64)
    }

    pub(crate) fn bytes(&self, n: usize) -> &[u8] {
        debug_assert!(n <= self.len);
        // SAFETY: the mapping is len bytes and owned by us.
        unsafe { std::slice::from_raw_parts(self.ptr, n) }
    }

    pub(crate) fn read_from(&mut self, _region: &ScanRegion, pos: u64, want: usize) -> Result<usize> {
        let want = want.min(self.len);
        let local = libc::iovec { iov_base: self.ptr as *mut c_void, iov_len: want };
        let remote = libc::iovec { iov_base: pos as usize as *mut c_void, iov_len: want };
        // SAFETY: both iovecs describe ranges valid for this call; pid 0 means
        // "this process".
        let n = unsafe { libc::process_vm_readv(self.pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            return Err(Error::Scan(format!(
                "read of {pos:#x}..{:#x} failed: {err}",
                pos + want as u64
            )));
        }
        Ok(n as usize)
    }

    pub(crate) fn wipe(&mut self) {
        // SAFETY: our own mapping.
        unsafe { libc::explicit_bzero(self.ptr as *mut c_void, self.len) };
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.wipe();
        // SAFETY: our own mapping, unmapped once.
        unsafe { libc::munmap(self.ptr as *mut c_void, self.mapped) };
    }
}

// SAFETY: the scratch owns its mapping exclusively; `&mut` is required to read.
unsafe impl Send for Scratch {}
