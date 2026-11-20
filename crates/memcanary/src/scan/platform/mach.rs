//! macOS: Mach VM enumeration and reading.
//!
//! * `mach_vm_region_recurse` walks the task's address space.
//! * `mach_vm_read_overwrite` copies a range into our own buffer without a
//!   pointer dereference, so guard pages and unmapped holes are errors rather
//!   than faults.
//! * `proc_regionfilename` names file-backed regions so code pages can be told
//!   apart from anonymous memory.
//!
//! Struct sizes matter: `mach_vm_region_recurse` validates its `count` against
//! the exact struct size and returns `KERN_INVALID_ARGUMENT` otherwise. The
//! `vm_region_submap_info_64` layout below matches `<mach/vm_region.h>` on the
//! current SDK and is 80 bytes.

use std::ffi::{c_void, CStr};

use crate::report::{RegionKind, ScanRegion};
use crate::{Error, Result};

type KernReturn = libc::c_int;
type MachPort = libc::c_uint;

const KERN_SUCCESS: KernReturn = 0;

const VM_PROT_READ: i32 = 0x1;
const VM_PROT_WRITE: i32 = 0x2;
const VM_PROT_EXECUTE: i32 = 0x4;

const VM_REGION_BASIC_INFO_64: libc::c_int = 9;

/// `struct vm_region_submap_info_64` — needed for `user_wired_count`, which is
/// how a `secretmem` range is recognised from **outside** the owning process
/// (its own registry is not readable across a task boundary).
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VmRegionSubmapInfo64 {
    protection: i32,
    max_protection: i32,
    inheritance: u32,
    offset: u64,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    ref_count: u32,
    shadow_depth: u16,
    external_pager: u8,
    share_mode: u8,
    is_submap: u32,
    behavior: i32,
    object_id: u32,
    user_wired_count: u16,
    flags: u16,
    pages_reusable: u32,
    object_id_full: u64,
}

/// `struct vm_region_basic_info_64` from `<mach/vm_region.h>`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct VmRegionBasicInfo64 {
    protection: i32,
    max_protection: i32,
    inheritance: u32,
    shared: u32,
    reserved: u32,
    offset: u64,
    behavior: i32,
    user_wired_count: u16,
    _padding: u16,
}

impl VmRegionBasicInfo64 {
    const COUNT: u32 = (std::mem::size_of::<Self>() / std::mem::size_of::<libc::c_int>()) as u32;
}

extern "C" {
    fn mach_task_self() -> MachPort;
    fn task_for_pid(host: MachPort, pid: libc::c_int, task: *mut MachPort) -> KernReturn;
    fn mach_port_deallocate(task: MachPort, name: MachPort) -> KernReturn;
    fn mach_vm_region(
        target_task: MachPort,
        address: *mut u64,
        size: *mut u64,
        flavor: libc::c_int,
        info: *mut libc::c_int,
        info_count: *mut u32,
        object_name: *mut MachPort,
    ) -> KernReturn;
    fn mach_vm_region_recurse(
        target_task: MachPort,
        address: *mut u64,
        size: *mut u64,
        nesting_depth: *mut u32,
        info: *mut libc::c_int,
        info_count: *mut u32,
    ) -> KernReturn;
    fn mach_vm_read_overwrite(
        target_task: MachPort,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> KernReturn;
    fn proc_regionfilename(
        pid: libc::c_int,
        address: u64,
        buffer: *mut c_void,
        buffersize: u32,
    ) -> libc::c_int;
    fn mach_error_string(error_value: KernReturn) -> *const libc::c_char;
}

#[inline]
fn task_self() -> MachPort {
    // SAFETY: reads a Mach-initialised constant.
    unsafe { mach_task_self() }
}

/// A handle to a task we can enumerate.
///
/// Scanning another process needs `task_for_pid`, which macOS refuses unless the
/// target is signed with `com.apple.security.get-task-allow` (or we are root
/// with SIP disabled, or the target is our own child and we hold the
/// entitlement). That is a deliberate security boundary: this crate does not
/// try to bypass it, it reports the kernel's refusal and tells the operator what
/// to do.
pub(crate) struct TaskHandle {
    port: MachPort,
    pid: libc::c_int,
    /// Whether this handle refers to another process (and must be released).
    foreign: bool,
}

impl TaskHandle {
    pub(crate) fn current() -> TaskHandle {
        TaskHandle { port: task_self(), pid: std::process::id() as libc::c_int, foreign: false }
    }

    /// The Mach port to read through. `Scratch` borrows this by value; it must
    /// not take ownership, or dropping the scratch would deallocate the port
    /// out from under the auditor.
    pub(crate) fn port(&self) -> MachPort {
        self.port
    }

    pub(crate) fn pid(&self) -> libc::c_int {
        self.pid
    }

    pub(crate) fn for_pid(pid: libc::c_int) -> Result<TaskHandle> {
        if pid == std::process::id() as libc::c_int {
            return Ok(TaskHandle::current());
        }
        let mut port: MachPort = 0;
        // SAFETY: host port is MACH_PORT_NULL for the default host; the call
        // writes the task port on success.
        let kr = unsafe { task_for_pid(task_self(), pid, &mut port) };
        if kr != KERN_SUCCESS || port == 0 {
            return Err(Error::Scan(format!(
                "cannot attach to pid {pid}: {} ({}). On macOS the target must be \
                 signed with com.apple.security.get-task-allow, e.g. \
                 `codesign -s - --entitlements ent.plist <binary>`; on Linux the \
                 reader needs ptrace permission (`yama/ptrace_scope`).",
                mach_str(kr),
                kr
            )));
        }
        Ok(TaskHandle { port, pid, foreign: true })
    }
}

impl Drop for TaskHandle {
    fn drop(&mut self) {
        if self.foreign && self.port != 0 {
            // SAFETY: we own this send right.
            unsafe { mach_port_deallocate(task_self(), self.port) };
            self.port = 0;
        }
    }
}

/// Every region in this process's address space, in address order.
pub(crate) fn regions() -> Result<Vec<ScanRegion>> {
    regions_of(&TaskHandle::current())
}

/// Every region in `task`'s address space.
pub(crate) fn regions_of(task: &TaskHandle) -> Result<Vec<ScanRegion>> {
    let pid = task.pid();
    let mut out = Vec::with_capacity(256);
    let mut address: u64 = 0;
    loop {
        let mut size: u64 = 0;
        let mut info = VmRegionBasicInfo64::default();
        let mut count = VmRegionBasicInfo64::COUNT;
        let mut object_name: MachPort = 0;
        // SAFETY: all pointers are to locals of the exact expected types.
        let kr = unsafe {
            mach_vm_region(
                task.port,
                &mut address,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                &mut info as *mut VmRegionBasicInfo64 as *mut libc::c_int,
                &mut count,
                &mut object_name,
            )
        };
        if kr != KERN_SUCCESS {
            // `KERN_INVALID_ADDRESS` at the top of the walk is the normal exit.
            // Anything else — or a failure on the *first* call — means the task
            // port is unusable, which must be an error rather than an empty,
            // falsely-clean report.
            if address == 0 && kr != libc::KERN_INVALID_ADDRESS {
                return Err(Error::Scan(format!(
                    "region enumeration failed: {} ({kr})",
                    mach_str(kr)
                )));
            }
            break;
        }
        if size == 0 {
            break;
        }
        let end = address.checked_add(size).ok_or_else(|| {
            Error::Scan(format!("region at {address:#x} overflows address space"))
        })?;

        let name = region_name(pid, address);
        let executable = info.protection & VM_PROT_EXECUTE != 0;
        let kind = classify(name.as_deref(), executable);
        out.push(ScanRegion {
            start: address,
            end,
            readable: info.protection & VM_PROT_READ != 0,
            writable: info.protection & VM_PROT_WRITE != 0,
            executable,
            wired: region_is_wired(task.port(), address, size),
            kind,
            name,
            skipped: None,
        });
        address = end;
    }
    Ok(out)
}

/// Whether the region at `address` has wired (unevictable) pages.
///
/// This is the signal that identifies a `secretmem` range from outside the
/// owning process: the registry is process-private, but `mlock` shows up in the
/// region's `user_wired_count` to anyone holding the task port. An ordinary
/// heap allocation is not wired, so the two are distinguishable.
fn region_is_wired(task: MachPort, address: u64, _size: u64) -> bool {
    let mut addr = address;
    let mut size = 0u64;
    let mut depth = 0u32;
    let mut info = VmRegionSubmapInfo64::default();
    let mut count = (std::mem::size_of::<VmRegionSubmapInfo64>() / std::mem::size_of::<libc::c_int>()) as u32;
    // SAFETY: locals of the exact expected types.
    let kr = unsafe {
        mach_vm_region_recurse(
            task,
            &mut addr,
            &mut size,
            &mut depth,
            &mut info as *mut VmRegionSubmapInfo64 as *mut libc::c_int,
            &mut count,
        )
    };
    kr == KERN_SUCCESS && info.user_wired_count > 0
}

fn region_name(pid: libc::c_int, address: u64) -> Option<String> {
    let mut buf = [0u8; 1024];
    // SAFETY: buffer is a local of the declared size.
    let n = unsafe {
        proc_regionfilename(
            pid,
            address,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
        )
    };
    if n <= 0 {
        return None;
    }
    // SAFETY: the kernel NUL-terminates within the buffer.
    let s = unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
    let s = s.to_string_lossy().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn classify(name: Option<&str>, executable: bool) -> RegionKind {
    match name {
        None => RegionKind::Anonymous,
        Some(_) if executable => RegionKind::Image,
        Some(n) if n.starts_with("/usr/lib/dyld") || n.contains("dyld_shared_cache") => {
            RegionKind::FileBacked
        }
        Some(_) => RegionKind::FileBacked,
    }
}

/// A page-aligned scratch buffer, allocated outside the normal allocator and
/// excluded from the scan.
pub(crate) struct Scratch {
    ptr: *mut u8,
    len: usize,
    mapped: usize,
    /// The task reads go to. A bare port, not an owning handle: the auditor
    /// owns the handle and outlives every scratch.
    port: MachPort,
}

impl Scratch {
    pub(crate) fn new(n: usize) -> Result<Self> {
        Self::new_for(n, task_self())
    }

    pub(crate) fn new_for(n: usize, port: MachPort) -> Result<Self> {
        let page = secretmem::page_size();
        let len = n.div_ceil(page) * page;
        let mapped = len;
        // SAFETY: anonymous private mapping, exclusively owned.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapped,
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
        Ok(Scratch { ptr: p as *mut u8, len, mapped, port })
    }

    pub(crate) fn range(&self) -> (u64, u64) {
        (self.ptr as u64, self.ptr as u64 + self.len as u64)
    }

    pub(crate) fn bytes(&self, n: usize) -> &[u8] {
        debug_assert!(n <= self.len);
        // SAFETY: the mapping is len bytes and owned by us.
        unsafe { std::slice::from_raw_parts(self.ptr, n) }
    }

    /// Copies `want` bytes from `region` at `pos` into the scratch buffer.
    /// Returns how many bytes the kernel actually delivered (`0` at the end of
    /// the region or if it disappeared).
    pub(crate) fn read_from(
        &mut self,
        _region: &ScanRegion,
        pos: u64,
        want: usize,
    ) -> Result<usize> {
        let want = want.min(self.len);
        let out = want as u64;
        let mut got: u64 = 0;
        // SAFETY: destination is our own mapping of at least `want` bytes.
        let kr = unsafe {
            mach_vm_read_overwrite(self.port, pos, out, self.ptr as u64, &mut got)
        };
        if kr != KERN_SUCCESS {
            // A region can be freed between enumeration and reading. Report it
            // as a skip, not a hard failure.
            let msg = mach_str(kr);
            return Err(Error::Scan(format!(
                "read of {:#x}..{:#x} failed: {msg}",
                pos,
                pos + out
            )));
        }
        Ok(got as usize)
    }

    /// Zero the scratch so a scanned secret is not left in the auditor's own
    /// memory between chunks.
    pub(crate) fn wipe(&mut self) {
        // SAFETY: our own mapping.
        unsafe { libc::memset_s(self.ptr as *mut c_void, self.len, 0, self.len) };
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

fn mach_str(kr: KernReturn) -> String {
    // SAFETY: mach_error_string returns a static C string for any code.
    let p = unsafe { mach_error_string(kr) };
    if p.is_null() {
        return format!("kern_return {kr}");
    }
    // SAFETY: non-null, NUL-terminated static string.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().to_string()
}
