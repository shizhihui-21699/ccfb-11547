//! Environment and argv hygiene.
//!
//! On Darwin the kernel keeps a per-process snapshot of `argv` and `environ`
//! that `sysctl(KERN_PROCARGS2)` hands to any same-user process.  Zeroing the
//! process's own `environ` strings updates that snapshot (verified on macOS 26,
//! see `docs/PLATFORM-NOTES.md`), but there is an observable window between
//! `execve` and the scrub.  This module makes that a one-call fix and the demo
//! shows the window closing.
//!
//! Rules:
//! * never pass a secret as a command-line argument — `ps` shows it to every user
//!   on the box for the whole process lifetime, regardless of what we do here;
//! * read secrets from a file descriptor or a prompt, then [`scrub_env_var`] if
//!   you accepted them via the environment.

/// Overwrite a NUL-terminated environment value **in the live environment** and
/// remove the variable.  The write happens in place on the string the kernel
/// copied at `execve` time, so the `KERN_PROCARGS2` snapshot stops containing it.
///
/// Returns `true` if the variable existed and was scrubbed.
///
/// # Safety-ish notes
/// This mutates memory owned by libc's `environ`.  It is what every mature
/// secret-handling process does; on Darwin the storage is a writable heap string.
pub fn scrub_env_var(name: &str) -> bool {
    let Ok(cname) = CStringLike::new(name) else {
        return false;
    };
    // SAFETY: `getenv` returns a pointer into the live environment; we read its
    // length before writing, and only write into the value string itself.
    unsafe {
        let value = libc::getenv(cname.as_ptr());
        if value.is_null() {
            return false;
        }
        let len = {
            let mut n = 0usize;
            while *value.add(n) != 0 {
                n += 1;
            }
            n
        };
        let mut i = 0;
        while i < len {
            core::ptr::write_volatile(value.add(i), 0i8);
            i += 1;
        }
        let _ = libc::unsetenv(cname.as_ptr());
    }
    true
}

/// Scrub a secret that arrived as a command-line argument.
///
/// The kernel's `KERN_PROCARGS2` copy follows the same rules as `environ`: once
/// you overwrite the argv string in place, the snapshot no longer shows it.
/// **This does not make argv a safe channel** — from `execve` until this call the
/// value is visible to `ps` and to `KERN_PROCARGS2`, and a supervisor may have
/// logged it.  It narrows the window; it does not close it.
///
/// `index` is the argv index (0 is the program path).  Returns `true` if that
/// index existed and was scrubbed.
pub fn scrub_argv(index: usize) -> bool {
    // SAFETY: `_NSGetArgv` returns the process's argv vector, valid for the
    // process lifetime.  We only overwrite the string it points at.
    #[cfg(target_os = "macos")]
    unsafe {
        let argv = libc::_NSGetArgv();
        if argv.is_null() {
            return false;
        }
        let argc = *libc::_NSGetArgc();
        if argc < 0 {
            return false;
        }
        let n = argc as usize;
        if index >= n {
            return false;
        }
        let arg = (*argv).add(index);
        if arg.is_null() || (*arg).is_null() {
            return false;
        }
        let s = *arg;
        let mut len = 0usize;
        while *s.add(len) != 0 {
            len += 1;
        }
        let mut i = 0;
        while i < len {
            core::ptr::write_volatile(s.add(i), 0i8);
            i += 1;
        }
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = index;
        false
    }
}

/// Read the current value of `KERN_PROCARGS2` for `pid` and report whether a
/// needle occurs in it.  Used by the verification tooling (and the demo) to prove
/// the scrub worked, from a **different** process where possible.
#[cfg(target_os = "macos")]
pub fn procargs_contains(pid: i32, needle: &[u8]) -> Option<bool> {
    let mut size: libc::size_t = 0;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // SAFETY: standard two-step sysctl sizing probe.
    unsafe {
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            core::ptr::null_mut(),
            &mut size,
            core::ptr::null_mut(),
            0,
        ) != 0
            || size == 0
        {
            return None;
        }
        let mut buf = vec![0u8; size];
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            core::ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
        let hay = &buf[..size.min(buf.len())];
        Some(!hay.is_empty() && memmem(hay, needle))
    }
}

#[cfg(not(target_os = "macos"))]
/// Non-macOS placeholder: returns `None` (no kernel snapshot API).
pub fn procargs_contains(_pid: i32, _needle: &[u8]) -> Option<bool> {
    None
}

/// Tiny byte-substring search (no allocation).
pub fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}

/// A small owned C string for passing a `*const c_char` to libc.
struct CStringLike {
    bytes: [u8; 256],
    len: usize,
}

impl CStringLike {
    fn new(s: &str) -> core::result::Result<Self, ()> {
        let b = s.as_bytes();
        if b.len() + 1 > 256 || b.contains(&0) {
            return Err(());
        }
        let mut bytes = [0u8; 256];
        bytes[..b.len()].copy_from_slice(b);
        Ok(Self {
            bytes,
            len: b.len(),
        })
    }
    fn as_ptr(&self) -> *const libc::c_char {
        debug_assert_eq!(self.bytes[self.len], 0);
        self.bytes.as_ptr().cast()
    }
}
