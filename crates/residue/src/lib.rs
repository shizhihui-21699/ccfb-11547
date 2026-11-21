//! Scanning of memory images and live tasks for canary secrets.
//!
//! The scanner is the part that has to be *convincing*, so it deliberately uses
//! two independent acquisition methods:
//!
//! 1. **Live task read** — `task_for_pid` + `mach_vm_region_recurse` +
//!    `mach_vm_read_overwrite`, i.e. exactly what a `ptrace(2)`-class attacker or
//!    a debugger does.  This sees the process as another process sees it.
//! 2. **Core file read** — parse a Mach-O core (`LC_SEGMENT_64` commands) and
//!    scan the bytes.  This is what a crash reporter or `lldb process save-core`
//!    would leave on disk.
//!
//! Both feed the same [`scan_bytes`] matcher, which reports **offset-accurate
//! hits** and never stops at the first one: a single leftover copy is proof of
//! residue, so we want the full count.

use std::path::Path;

/// A single occurrence of a needle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Hit {
    /// Human-readable location, e.g. `region 0x100004000 page 3` or `file off 0x1a4`.
    pub where_: String,
    /// Byte offset inside the scanned image for file scans, or inside the region
    /// for live scans.
    pub offset: usize,
    /// Protection of the containing region, when known (live scans only).
    pub protection: Option<u32>,
    /// Whether the containing region was wired, when known (live scans only).
    pub wired: Option<bool>,
    /// The 16 bytes following the match, for triage.  Never the secret itself
    /// beyond the matched needle (which the caller already knows).
    pub context: String,
}

/// Count occurrences of `needle` in `haystack`, collecting every offset.
pub fn find_all(haystack: &[u8], needle: &[u8], base: usize, label: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    if needle.is_empty() || needle.len() > haystack.len() {
        return hits;
    }
    let mut start = 0usize;
    while let Some(rel) = memchr::memmem::find(&haystack[start..], needle) {
        let at = start + rel;
        hits.push(Hit {
            where_: label.to_string(),
            offset: base + at,
            protection: None,
            wired: None,
            context: hex_preview(&haystack[at..(at + needle.len() + 16).min(haystack.len())]),
        });
        start = at + 1;
    }
    hits
}

/// Render a byte slice as spaced hex, truncated.
pub fn hex_preview(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().take(24).enumerate() {
        if i != 0 {
            s.push(' ');
        }
        if b.is_ascii_graphic() {
            s.push(char::from(*b));
        } else {
            let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
        }
    }
    if bytes.len() > 24 {
        s.push_str("...");
    }
    s
}

/// A region of a live task.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct LiveRegion {
    /// Base address.
    pub addr: usize,
    /// Size in bytes.
    pub size: usize,
    /// Protection bits.
    pub protection: u32,
    /// Wire state.
    pub wired: bool,
    /// `vm_inherit_t`.
    pub inheritance: u32,
    /// `share_mode`.
    pub share_mode: u8,
}

impl LiveRegion {
    /// `PROT_READ | PROT_WRITE`.
    pub fn readable(&self) -> bool {
        self.protection & 0b011 != 0
    }
    /// Whether the region is sealed (no read or write permission).
    pub fn sealed(&self) -> bool {
        self.protection & 0b011 == 0
    }
}

/// One page of a live task.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LivePage {
    /// Region the page belongs to.
    pub region: LiveRegion,
    /// Page-virtual address.
    pub addr: usize,
    /// Bytes read (empty when the page was unreadable).
    pub data: Vec<u8>,
}

/// Result of enumerating a live task.
#[derive(Debug, Default, serde::Serialize)]
pub struct LiveImage {
    /// Every readable page that was actually read, plus the unreadable ones the
    /// caller asked for (`include_unreadable`).
    pub pages: Vec<LivePage>,
    /// All regions seen, whether or not their pages were read.
    pub regions: Vec<LiveRegion>,
    /// Total bytes read.
    pub bytes_read: usize,
}

/// Fix a `needle` in the scanner's hand while lower layers may try to read it.
/// Enumerate the regions of task `pid` and read their readable pages.
///
/// `exclude_sealed`: when a region is `PROT_NONE`, a debugger with a task port
/// would call `mach_vm_protect` and read it anyway. This function *does not* do
/// that by default, matching the honest threat model: `PROT_NONE` protects
/// against dump writers, not against an attacker holding the task port. Set it
/// to `false` to reproduce the attacker behaviour and show the difference.
pub fn read_live(pid: i32, exclude_sealed: bool, max_bytes: usize) -> Result<LiveImage, String> {
    read_live_filtered(pid, exclude_sealed, max_bytes, true)
}

/// As [`read_live`], with control over whether read-only regions are scanned.
///
/// A secret is written by the process, so it can only be in memory the process
/// can write: writable regions, or sealed (`PROT_NONE`) regions whose previous
/// protection was writable.  Scanning the ~5.8 GB of read-only dyld shared-cache
/// mappings costs minutes and can never produce a true positive, so it is off by
/// default and turned back on only with `--scan-readonly`.
pub fn read_live_filtered(
    pid: i32,
    exclude_sealed: bool,
    max_bytes: usize,
    writable_only: bool,
) -> Result<LiveImage, String> {
    #[cfg(target_os = "macos")]
    {
        mach_live::read(pid, exclude_sealed, max_bytes, writable_only)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (pid, exclude_sealed, max_bytes, writable_only);
        Err("live task reading needs macOS Mach APIs".to_string())
    }
}

/// Parse a Mach-O core file's segments and return (virutal_address, protection,
/// bytes) triples.
#[cfg(target_os = "macos")]
pub mod corefile {
    use super::{find_all, Hit};

    /// One segment of a core file.
    #[derive(Debug, Clone)]
    pub struct Segment {
        /// VM address the segment was mapped at.
        pub vmaddr: u64,
        /// Virtual size.
        pub vmsize: u64,
        /// File offset of the data.
        pub fileoff: u64,
        /// File size of the data.
        pub filesize: u64,
        /// Initial protection.
        pub protection: u32,
    }

    /// A parsed core file.
    #[derive(Debug, Clone)]
    pub struct CoreFile {
        /// Segments present in the file.
        pub segments: Vec<Segment>,
        /// The raw file bytes.
        pub bytes: Vec<u8>,
    }

    /// Parse a Mach-O core (magic `0xfeedfacf`) at `path`.
    pub fn parse(path: &std::path::Path) -> Result<CoreFile, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        if bytes.len() < 32 {
            return Err("file too short to be a Mach-O core".into());
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if magic != 0xfeed_facf && magic != 0xcffa_edfe {
            return Err(format!(
                "not a 64-bit Mach-O (magic {magic:#x}); this scanner only understands \
                 Mach-O cores written by lldb/os_crash"
            ));
        }
        let ncmds = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let sizeofcmds = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
        let mut off = 32usize;
        let end = (32 + sizeofcmds).min(bytes.len());
        let mut segments = Vec::new();
        for _ in 0..ncmds {
            if off + 8 > end {
                break;
            }
            let cmd = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
            let cmdsize = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap()) as usize;
            if cmdsize < 8 || off + cmdsize > bytes.len() {
                break;
            }
            // LC_SEGMENT_64 == 0x19
            if cmd == 0x19 && off + 72 <= bytes.len() {
                let vmaddr = u64::from_le_bytes(bytes[off + 24..off + 32].try_into().unwrap());
                let vmsize = u64::from_le_bytes(bytes[off + 32..off + 40].try_into().unwrap());
                let fileoff = u64::from_le_bytes(bytes[off + 40..off + 48].try_into().unwrap());
                let filesize = u64::from_le_bytes(bytes[off + 48..off + 56].try_into().unwrap());
                let initprot = i32::from_le_bytes(bytes[off + 64..off + 68].try_into().unwrap());
                segments.push(Segment {
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    protection: initprot as u32,
                });
            }
            off += cmdsize;
        }
        if segments.is_empty() {
            return Err("core file contained no LC_SEGMENT_64 commands".into());
        }
        Ok(CoreFile { segments, bytes })
    }

    impl CoreFile {
        /// Search every segment for `needle`, reporting `where_` as
        /// `core seg @0x…` plus the virtual address.
        pub fn scan(&self, needle: &[u8]) -> Vec<Hit> {
            let mut hits = Vec::new();
            for seg in &self.segments {
                let start = seg.fileoff as usize;
                let len = seg.filesize as usize;
                if len == 0 || start > self.bytes.len() {
                    continue;
                }
                let end = (start + len).min(self.bytes.len());
                let slice = &self.bytes[start..end];
                let label = format!(
                    "core seg vm={:#x} filesz={:#x} prot={}",
                    seg.vmaddr, seg.filesize, seg.protection
                );
                let mut local = find_all(slice, needle, 0, &label);
                for h in local.iter_mut() {
                    h.offset += seg.vmaddr as usize;
                    h.protection = Some(seg.protection);
                }
                hits.extend(local);
            }
            hits
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub mod corefile {
    //! Placeholder: Mach-O core parsing is macOS-oriented, but the format is
    //! portable. Kept unavailable here to avoid untested code paths.

    /// A parsed core file; unavailable.
    pub struct CoreFile;

    /// Always an error off macOS.
    pub fn parse(_path: &std::path::Path) -> Result<CoreFile, String> {
        Err("Mach-O core parsing is only enabled on macOS".into())
    }

    impl CoreFile {
        /// Always empty.
        pub fn scan(&self, _needle: &[u8]) -> Vec<super::Hit> {
            Vec::new()
        }
    }
}

/// Scan a file for `needle` with the generic matcher.
pub fn scan_file(path: &Path, needle: &[u8]) -> Result<Vec<Hit>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(find_all(&bytes, needle, 0, "file"))
}

#[cfg(target_os = "macos")]
mod mach_live {
    use super::{LiveImage, LivePage, LiveRegion};

    type Kr = i32;
    type Port = u32;

    extern "C" {
        static mach_task_self_: Port;
        fn task_for_pid(host: Port, pid: i32, task: *mut Port) -> Kr;
        fn mach_vm_region_recurse(
            task: Port,
            addr: *mut u64,
            size: *mut u64,
            depth: *mut u32,
            info: *mut u32,
            cnt: *mut u32,
        ) -> Kr;
        fn mach_vm_read_overwrite(
            task: Port,
            addr: u64,
            size: u64,
            dest: u64,
            out: *mut u64,
        ) -> Kr;
        fn mach_vm_protect(task: Port, addr: u64, size: u64, set_max: i32, prot: i32) -> Kr;
        fn mach_error_string(kr: Kr) -> *mut i8;
    }

    const PAGE: usize = 16 * 1024;

    pub fn err(kr: Kr) -> String {
        unsafe {
            let p = mach_error_string(kr);
            if p.is_null() {
                return format!("kr {kr}");
            }
            let mut n = 0;
            while *p.add(n) != 0 && n < 200 {
                n += 1;
            }
            String::from_utf8_lossy(std::slice::from_raw_parts(p as *const u8, n)).into_owned()
        }
    }

    pub fn read(
        pid: i32,
        exclude_sealed: bool,
        max_bytes: usize,
        writable_only: bool,
    ) -> Result<LiveImage, String> {
        unsafe {
            let mut task: Port = 0;
            let kr = task_for_pid(mach_task_self_, pid, &mut task);
            if kr != 0 {
                return Err(format!(
                    "task_for_pid({pid}) refused: {}. The target must carry \
                     com.apple.security.get-task-allow (ad-hoc signed debug builds do); \
                     production builds should not.",
                    err(kr)
                ));
            }
            let mut regions = Vec::new();
            let mut pages = Vec::new();
            let mut bytes_read = 0usize;
            let mut addr: u64 = 0;
            let mut depth: u32 = 0;
            loop {
                let mut size: u64 = 0;
                let mut info = [0u32; 19];
                let mut cnt = 19u32;
                let kr = mach_vm_region_recurse(
                    task,
                    &mut addr,
                    &mut size,
                    &mut depth,
                    info.as_mut_ptr(),
                    &mut cnt,
                );
                if kr != 0 {
                    break;
                }
                let is_submap = info[12] & 0xff;
                if is_submap != 0 {
                    depth += 1;
                    continue;
                }
                let protection = info[0] & 0xff;
                let inheritance = info[2] & 0xff;
                let share_mode = ((info[11] >> 24) & 0xff) as u8;
                let wired = (info[15] & 0xffff) != 0;
                let region = LiveRegion {
                    addr: addr as usize,
                    size: size as usize,
                    protection,
                    wired,
                    inheritance,
                    share_mode,
                };
                regions.push(region);
                let worth_scanning = region.protection & 0b10 != 0
                    || (!exclude_sealed && region.sealed());
                if (region.readable() || (!exclude_sealed && region.sealed()))
                    && (!writable_only || worth_scanning)
                {
                    let mut page = addr;
                    while page < addr + size && bytes_read < max_bytes {
                        let this = ((addr + size - page) as usize).min(PAGE);
                        let mut buf = vec![0u8; this];
                        let mut out: u64 = 0;
                        let mut can = region.readable();
                        if !can {
                            // Attacker behaviour: lift PROT_NONE first.
                            can = mach_vm_protect(task, page, this as u64, 0, 3) == 0;
                        }
                        if can {
                            let kr = mach_vm_read_overwrite(
                                task,
                                page,
                                this as u64,
                                buf.as_mut_ptr() as u64,
                                &mut out,
                            );
                            if kr == 0 && out as usize == this {
                                bytes_read += this;
                                pages.push(LivePage {
                                    region,
                                    addr: page as usize,
                                    data: buf,
                                });
                            } else {
                                pages.push(LivePage {
                                    region,
                                    addr: page as usize,
                                    data: Vec::new(),
                                });
                            }
                        } else {
                            pages.push(LivePage {
                                region,
                                addr: page as usize,
                                data: Vec::new(),
                            });
                        }
                        page += this as u64;
                    }
                }
                addr += size;
            }
            Ok(LiveImage {
                pages,
                regions,
                bytes_read,
            })
        }
    }
}
