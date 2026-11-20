//! Kernel-level region enumeration and reading, per platform.
//!
//! The scan must read memory *as the kernel sees it*, not by dereferencing raw
//! pointers: dereferencing a stale or guard page faults and kills the process
//! being audited. Both backends here go through the same interfaces a debugger
//! or crash reporter uses.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use crate::report::ScanRegion;
use crate::Result;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use crate::Error;

#[cfg(target_os = "macos")]
#[path = "platform/mach.rs"]
mod mach;
#[cfg(target_os = "linux")]
#[path = "platform/linux.rs"]
mod linux;

#[cfg(target_os = "macos")]
pub(crate) use mach::{regions, regions_of, Scratch, TaskHandle};
#[cfg(target_os = "linux")]
pub(crate) use linux::{regions, regions_of, Scratch, TaskHandle};

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) use unsupported::{regions, Scratch};

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) use unsupported::{regions_of, TaskHandle};

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod unsupported {
    use super::*;
    pub(crate) fn ensure_supported() -> Result<()> {
        Err(Error::Unsupported)
    }
    pub(crate) fn regions() -> Result<Vec<ScanRegion>> {
        Err(Error::Unsupported)
    }
    pub(crate) struct TaskHandle;
    impl TaskHandle {
        pub(crate) fn current() -> Self {
            TaskHandle
        }
        pub(crate) fn port(&self) -> i32 {
            0
        }
        pub(crate) fn pid(&self) -> i32 {
            0
        }
        pub(crate) fn for_pid(_pid: libc::c_int) -> Result<Self> {
            Err(Error::Unsupported)
        }
    }
    pub(crate) fn regions_of(_t: &TaskHandle) -> Result<Vec<ScanRegion>> {
        Err(Error::Unsupported)
    }
    pub(crate) struct Scratch;
    impl Scratch {
        pub(crate) fn new(_n: usize) -> Result<Self> {
            Err(Error::Unsupported)
        }
        pub(crate) fn range(&self) -> (u64, u64) {
            (0, 0)
        }
        pub(crate) fn bytes(&self, _n: usize) -> &[u8] {
            &[]
        }
        pub(crate) fn read_from(&mut self, _r: &ScanRegion, _pos: u64, _want: usize) -> Result<usize> {
            Err(Error::Unsupported)
        }
        pub(crate) fn wipe(&mut self) {}
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) fn ensure_supported() -> Result<()> {
    Ok(())
}
