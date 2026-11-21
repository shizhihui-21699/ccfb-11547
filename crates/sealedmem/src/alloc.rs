//! Low-level platform binding plus the safe wrappers the crate uses.
//!
//! On macOS this declares only the handful of Mach traps we need; on other
//! Unixes it degrades gracefully (no fork isolation, no Mach stats), and the
//! verification tool reports which claims are `n/a` rather than pretending.

#[cfg(target_os = "macos")]
pub mod mach {
    //! Minimal Mach bindings: exactly the calls `Region` needs, nothing more.

    use core::ffi::c_int;

    type KernReturn = c_int;
    type MachPort = u32;
    type MachVmAddress = u64;
    type MachVmSize = u64;

    const KERN_SUCCESS: KernReturn = 0;

    /// `VM_INHERIT_NONE`: the mapping is absent from the child after `fork`.
    const VM_INHERIT_NONE: u32 = 2;

    /// `VM_REGION_SUBMAP_INFO_COUNT_64` on Darwin/arm64.
    const SUBMAP_INFO_COUNT: u32 = 19;
    /// Index `12` of the submap-info word array is `is_submap` (byte 48).
    const IS_SUBMAP_IDX: usize = 12;
    /// Word `11` low byte is `external_pager`, high byte is `share_mode`.
    ///
    /// `share_mode` layout in the packed struct: protection(0..4),
    /// max_protection(4..8), inheritance(8..12), offset(12..20), user_tag(20..24),
    /// pages_resident(24..28), pages_shared_now_private(28..32),
    /// pages_swapped_out(32..36), pages_dirtied(36..40), ref_count(40..44),
    /// shadow_depth(44..46), external_pager(46..47), share_mode(47..48).
    const SHARE_MODE_WORD: usize = 11;
    /// `user_wired_count` is at byte 60, i.e. low half of word 15.
    const USER_WIRED_WORD: usize = 15;


    extern "C" {
        static mach_task_self_: MachPort;

        fn mach_vm_region_recurse(
            target_task: MachPort,
            address: *mut MachVmAddress,
            size: *mut MachVmSize,
            nesting_depth: *mut u32,
            info: *mut u32,
            info_cnt: *mut u32,
        ) -> KernReturn;

        fn mach_vm_inherit(
            target_task: MachPort,
            address: MachVmAddress,
            size: MachVmSize,
            new_inheritance: u32,
        ) -> KernReturn;

        fn mach_vm_protect(
            target_task: MachPort,
            address: MachVmAddress,
            size: MachVmSize,
            set_maximum: c_int,
            new_protection: c_int,
        ) -> KernReturn;

        fn mach_vm_read_overwrite(
            target_task: MachPort,
            address: MachVmAddress,
            size: MachVmSize,
            data: MachVmAddress,
            out_size: *mut MachVmSize,
        ) -> KernReturn;

        fn task_for_pid(host: MachPort, pid: c_int, task: *mut MachPort) -> KernReturn;
        fn mach_error_string(kr: KernReturn) -> *mut core::ffi::c_char;
    }

    /// Facts about the region containing a given address, in the **current**
    /// task.
    #[derive(Debug, Clone, Copy, Default)]
    pub(crate) struct RegionInfo {
        /// Raw `vm_prot_t` (1 = read, 2 = write, 4 = exec).
        pub protection: u32,
        /// Kernel-reported `user_wired_count`.
        pub wired: bool,
        /// `vm_inherit_t` (`2` == `VM_INHERIT_NONE`).
        pub inheritance: u32,
        /// `share_mode` (1 COW, 2 private, 5 shared, ...).
        pub share_mode: u8,
    }

    /// Find the submap region containing `addr` and report its attributes.
    pub(crate) fn region_info(addr: usize) -> Option<RegionInfo> {
        // SAFETY: reading the task port and walking regions are read-only
        // operations on our own task; pointers point to our own stack locals.
        unsafe {
            let task = mach_task_self_;
            let mut a: MachVmAddress = 0;
            let mut depth: u32 = 0;
            loop {
                let mut size: MachVmSize = 0;
                let mut info = [0u32; SUBMAP_INFO_COUNT as usize];
                let mut cnt = SUBMAP_INFO_COUNT;
                let kr = mach_vm_region_recurse(
                    task,
                    &mut a,
                    &mut size,
                    &mut depth,
                    info.as_mut_ptr(),
                    &mut cnt,
                );
                if kr != KERN_SUCCESS {
                    return None;
                }
                let is_submap = info[IS_SUBMAP_IDX] & 0xff;
                if is_submap != 0 {
                    depth += 1;
                    continue;
                }
                if (a as usize) <= addr && addr < (a + size) as usize {
                    return Some(RegionInfo {
                        protection: info[0] & 0xff,
                        inheritance: info[2] & 0xff,
                        share_mode: ((info[SHARE_MODE_WORD] >> 24) & 0xff) as u8,
                        wired: (info[USER_WIRED_WORD] & 0xffff) != 0,
                    });
                }
                a += size;
            }
        }
    }

    /// Mark the current task's mapping at `addr..addr+size` as
    /// `VM_INHERIT_NONE`.
    pub(crate) fn vm_inherit_none(addr: usize, size: usize) -> KernReturn {
        // SAFETY: operate on our own task's mapping; the caller passes a range
        // that `Region` owns.
        unsafe {
            let task = mach_task_self_;
            mach_vm_inherit(task, addr as MachVmAddress, size as MachVmSize, VM_INHERIT_NONE)
        }
    }

    /// Human-readable description of a `kern_return_t`.
    pub(crate) fn err_string(kr: KernReturn) -> &'static str {
        // SAFETY: `mach_error_string` returns a static C string for any kr.
        unsafe {
            let p = mach_error_string(kr);
            if p.is_null() {
                return "unknown Mach error";
            }
            // `mach_error_string` results are short, well under 64 bytes.
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(p.cast::<u8>(), 64))
        }
    }

    /// Result of reading another task's memory.
    pub(crate) enum ForeignRead {
        /// We could read it: the bytes are a copy, and the caller owns them.
        Ok(Vec<u8>),
        /// `task_for_pid` was refused (no entitlement / different uid).
        NoTaskPort,
        /// We have the task port, but the page was `PROT_NONE` or otherwise
        /// unreadable.
        Unreadable,
    }

    /// Attempt to read `size` bytes from task `pid` at `addr`.  This exists only
    /// so the verification tool can *demonstrate* both the good case (sealed
    /// pages are not readable by a sibling) and the bad case (a debug build
    /// with `get-task-allow` **is** readable after `mach_vm_protect`).
    pub(crate) fn read_foreign(pid: i32, addr: usize, size: usize) -> ForeignRead {
        // SAFETY: `task_for_pid` is the standard, entitlement-gated lookup.
        unsafe {
            let mut task: MachPort = 0;
            let kr = task_for_pid(mach_task_self_, pid, &mut task);
            if kr != KERN_SUCCESS {
                return ForeignRead::NoTaskPort;
            }
            let mut buf = vec![0u8; size];
            let mut out: MachVmSize = 0;
            let kr = mach_vm_read_overwrite(
                task,
                addr as MachVmAddress,
                size as MachVmSize,
                buf.as_mut_ptr() as MachVmAddress,
                &mut out,
            );
            if kr == KERN_SUCCESS && out as usize == size {
                return ForeignRead::Ok(buf);
            }
            // A `PROT_NONE` page refuses `mach_vm_read_overwrite`; try to lift it.
            // This is exactly the attack the threat model says we cannot stop
            // for a `get-task-allow` target, so the tool probes it deliberately.
            let prot = mach_vm_protect(
                task,
                addr as MachVmAddress,
                size as MachVmSize,
                0,
                libc::VM_PROT_READ | libc::VM_PROT_WRITE,
            );
            if prot != KERN_SUCCESS {
                return ForeignRead::Unreadable;
            }
            let mut out2: MachVmSize = 0;
            let kr = mach_vm_read_overwrite(
                task,
                addr as MachVmAddress,
                size as MachVmSize,
                buf.as_mut_ptr() as MachVmAddress,
                &mut out2,
            );
            if kr == KERN_SUCCESS && out2 as usize == size {
                ForeignRead::Ok(buf)
            } else {
                ForeignRead::Unreadable
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub mod mach {
    //! Non-macOS stubs.  The library still works (wipe-on-drop, `mlock`, guard
    //! pages) but fork isolation and Mach stats are unavailable.

    /// Facts about a region; always unavailable off macOS.
    #[derive(Debug, Clone, Copy, Default)]
    pub(crate) struct RegionInfo {
        /// protection bits, unused off macOS.
        pub protection: u32,
        /// wire state, unused off macOS.
        pub wired: bool,
        /// inheritance, unused off macOS.
        pub inheritance: u32,
        /// share mode, unused off macOS.
        pub share_mode: u8,
    }

    /// Always `None`: there is no Mach region walker here.
    pub(crate) fn region_info(_addr: usize) -> Option<RegionInfo> {
        None
    }

    /// No-op: fork isolation is not implemented off macOS.
    pub(crate) fn vm_inherit_none(_addr: usize, _size: usize) -> i32 {
        0
    }

    /// Placeholder error string.
    pub(crate) fn err_string(_kr: i32) -> &'static str {
        "Mach unavailable on this platform"
    }

    /// Result of a foreign read; always refused off macOS.
    pub(crate) enum ForeignRead {
        /// Unused.
        Ok(Vec<u8>),
        /// Unused.
        NoTaskPort,
        /// Unused.
        Unreadable,
    }

    /// Always refused off macOS.
    pub(crate) fn read_foreign(_pid: i32, _addr: usize, _size: usize) -> ForeignRead {
        ForeignRead::NoTaskPort
    }
}

/// Whether the current platform provides the Mach-backed guarantees.
pub(crate) fn mach_available() -> bool {
    cfg!(target_os = "macos")
}
