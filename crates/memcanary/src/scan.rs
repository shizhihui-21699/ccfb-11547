//! Memory scanning: enumerate regions, read them, find fingerprints.
//!
//! # Scan strategy
//!
//! A secret may appear at any offset, so matching is anchored rather than
//! aligned. Each fingerprint's first four bytes fold into a 32-bit anchor; the
//! scan keeps one rolling 4-byte hash over the chunk and looks the anchor up in
//! a hash map. That makes the pass O(bytes) regardless of how many needles are
//! registered, which matters when the address space is gigabytes.
//!
//! A candidate anchor is confirmed with SHA-256 over the full window before it
//! is reported, so an anchor collision never becomes a false finding.
//!
//! # Reading your own memory
//!
//! The scan reads through the same kernel path a debugger or crash reporter
//! uses (`mach_vm_read_overwrite` on macOS, `process_vm_readv` on Linux), not by
//! dereferencing pointers. A raw pointer dereference of a stale region would
//! fault and kill the process being audited; reading through the kernel is also
//! what actually proves the bytes are present in the process image.
//!
//! # Chunking
//!
//! Regions are read in chunks, and consecutive chunks overlap by
//! `max_needle_len - 1` bytes so a window straddling a boundary is still seen
//! in full. Duplicates from the overlap are removed before reporting.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::needle::{Needle, ANCHOR_LEN, STRONG_MIN_LEN};
use crate::report::{Finding, Provenance, RegionKind, Report, ScanRegion};
use crate::{Error, Result};

#[path = "scan/platform.rs"]
mod platform;

/// Rolling-hash base for the anchor pass; must match `needle::ANCHOR_BASE`.
const ANCHOR_BASE: u64 = crate::needle::ANCHOR_BASE;

/// Knobs for a scan.
#[derive(Debug, Clone)]
pub struct AuditorOptions {
    /// Scan executable mappings. Cleaning code pages is meaningless (they are
    /// file-backed and read-only), so this is off by default; turned on to show
    /// that a *literal* secret compiled into a binary is out of scope for this
    /// library.
    pub scan_images: bool,
    /// Skip regions larger than this many bytes. Protects the scan from
    /// pathologically large reservations (macOS shows hundreds of GiB of mostly
    /// untouched virtual mappings). `None` means no limit.
    pub max_region_bytes: Option<usize>,
    /// Skip regions smaller than this many bytes.
    pub min_region_bytes: usize,
    /// Read size per kernel call.
    pub chunk_bytes: usize,
}

impl Default for AuditorOptions {
    fn default() -> Self {
        AuditorOptions {
            scan_images: false,
            max_region_bytes: Some(512 * 1024 * 1024),
            min_region_bytes: 1,
            chunk_bytes: 4 * 1024 * 1024,
        }
    }
}

/// `(bytes_read, anchor_probes, hits)`, where a hit is
/// `(needle_index, fingerprint_index, address)`.
type RegionScan = (u64, u64, Vec<(usize, usize, u64)>);

/// Counters from one scan.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ScanStats {
    /// Regions the kernel described.
    pub regions_total: usize,
    /// Regions actually read.
    pub regions_read: usize,
    /// Regions skipped.
    pub regions_skipped: usize,
    /// Bytes copied through the kernel.
    pub bytes_read: u64,
    /// Anchor candidates examined.
    pub anchors_probed: u64,
    /// Wall time.
    pub elapsed: Duration,
}

/// A named stage capture: the service calls [`Auditor::checkpoint`] at each
/// phase it wants evidence for, and the report is stored under the label.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Caller-provided stage name.
    pub label: String,
    /// The scan taken at that moment.
    pub report: Report,
}

/// Scans this process's own memory for registered needles.
pub struct Auditor {
    needles: Vec<Needle>,
    options: AuditorOptions,
    checkpoints: Vec<Checkpoint>,
    /// `None` scans this process; `Some` scans another.
    target: Option<platform::TaskHandle>,
    /// Ranges the target declared as managed containers (cooperative mode).
    /// Empty when scanning ourselves: the registry answers directly instead.
    declared_protected: Vec<(u64, u64)>,
}

impl Auditor {
    /// Creates an auditor with default options.
    pub fn new() -> Result<Self> {
        Self::with_options(AuditorOptions::default())
    }

    /// Creates an auditor with the given options.
    pub fn with_options(options: AuditorOptions) -> Result<Self> {
        platform::ensure_supported()?;
        Ok(Auditor {
            needles: Vec::new(),
            options,
            checkpoints: Vec::new(),
            target: None,
            declared_protected: Vec::new(),
        })
    }

    /// Adds a secret to search for. Chainable.
    pub fn watch(&mut self, needle: Needle) -> &mut Self {
        self.needles.push(needle);
        self
    }

    /// Number of registered needles.
    pub fn needle_count(&self) -> usize {
        self.needles.len()
    }

    /// Creates an auditor that scans **another process**, given its pid.
    ///
    /// On macOS this needs the target to be signed with
    /// `com.apple.security.get-task-allow`; the kernel refuses otherwise and the
    /// error says so. On Linux the reader needs `ptrace` permission for the
    /// target. This is the mode used to inspect a service while it runs, or to
    /// take evidence around a crash.
    pub fn for_pid(pid: u32, options: AuditorOptions) -> Result<Self> {
        platform::ensure_supported()?;
        let task = platform::TaskHandle::for_pid(pid as libc::c_int)?;
        Ok(Auditor {
            needles: Vec::new(),
            options,
            checkpoints: Vec::new(),
            target: Some(task),
            declared_protected: Vec::new(),
        })
    }

    /// Declares ranges the target considers managed (cooperative mode).
    ///
    /// Only meaningful for [`Auditor::for_pid`]. Hits inside these ranges are
    /// classified [`Provenance::Protected`]; hits outside stay `Foreign` and
    /// count as leaks. The ranges come from the target itself — see
    /// `secretmem::protected_ranges` — so this is cooperation, not detection:
    /// a target that lies about its ranges also defeats its own audit.
    pub fn declare_protected(&mut self, ranges: impl IntoIterator<Item = (u64, u64)>) {
        self.declared_protected = ranges.into_iter().collect();
    }

    /// Runs a scan without storing a checkpoint.
    pub fn scan(&self) -> Result<Report> {
        self.scan_inner(None)
    }

    /// Runs a scan and stores it under `label`.
    pub fn checkpoint(&mut self, label: impl Into<String>) -> Result<&Report> {
        let label = label.into();
        let report = self.scan_inner(Some(label.clone()))?;
        self.checkpoints.push(Checkpoint { label, report });
        Ok(&self.checkpoints.last().expect("just pushed").report)
    }

    /// All checkpoints taken so far, in order.
    pub fn checkpoints(&self) -> &[Checkpoint] {
        &self.checkpoints
    }

    fn scan_inner(&self, label: Option<String>) -> Result<Report> {
        platform::ensure_supported()?;
        let started = Instant::now();

        let max_needle = self.needles.iter().map(|n| n.len()).max().unwrap_or(ANCHOR_LEN).max(ANCHOR_LEN);

        // Index fingerprints by anchor so the pass is one lookup per offset.
        let mut index: HashMap<u32, Vec<(usize, usize)>> = HashMap::new();
        let mut short_needles: Vec<(usize, usize)> = Vec::new();
        for (ni, n) in self.needles.iter().enumerate() {
            for (fi, fp) in n.prints.iter().enumerate() {
                match fp.anchor {
                    Some(a) => index.entry(a).or_default().push((ni, fi)),
                    None => short_needles.push((ni, fi)),
                }
            }
        }

        // The scratch buffer is the auditor's own working memory: allocated
        // through the kernel, wiped after every chunk, and excluded from the
        // scan so the auditor cannot report its own transient copy as a leak.
        // It must be big enough for the largest chunk *and* for one window.
        let chunk = self.options.chunk_bytes.max(max_needle + 64 * 1024);
        // When scanning another process, the scratch is ours but reads go to
        // the target.
        let mut scratch = match &self.target {
            Some(t) => platform::Scratch::new_for(chunk + ANCHOR_LEN + 64, t.port())?,
            None => platform::Scratch::new(chunk + ANCHOR_LEN + 64)?,
        };
        let scratch_range = scratch.range();
        let regions_iter = match &self.target {
            Some(t) => platform::regions_of(t)?,
            None => platform::regions()?,
        };

        let mut regions: Vec<ScanRegion> = Vec::new();
        let mut hits: Vec<(usize, usize, u64)> = Vec::new();
        let mut stats = ScanStats::default();

        for mut region in regions_iter {
            stats.regions_total += 1;
            // The scratch is only meaningful when auditing ourselves; while
            // scanning another process the scratch lives in our address space
            // and could never match a region of the target, but the guard is
            // harmless and keeps the two paths identical.
            if region.start == scratch_range.0 && region.end == scratch_range.1 {
                region.kind = RegionKind::AuditorScratch;
                region.skipped = Some("auditor scratch".into());
                stats.regions_skipped += 1;
                regions.push(region);
                continue;
            }
            if !region.readable {
                region.skipped = Some("not readable".into());
                stats.regions_skipped += 1;
                regions.push(region);
                continue;
            }
            if region.kind == RegionKind::Image && !self.options.scan_images {
                region.skipped = Some("executable image (scan_images=false)".into());
                stats.regions_skipped += 1;
                regions.push(region);
                continue;
            }
            let len = region.end.saturating_sub(region.start);
            if len < self.options.min_region_bytes as u64 {
                region.skipped = Some("below min_region_bytes".into());
                stats.regions_skipped += 1;
                regions.push(region);
                continue;
            }
            if let Some(max) = self.options.max_region_bytes {
                if len > max as u64 {
                    region.skipped = Some(format!("larger than max_region_bytes ({max})"));
                    stats.regions_skipped += 1;
                    regions.push(region);
                    continue;
                }
            }

            match self.scan_region(&region, &index, &short_needles, &mut scratch, chunk, max_needle) {
                Ok((bytes, probes, mut found)) => {
                    stats.regions_read += 1;
                    stats.bytes_read += bytes;
                    stats.anchors_probed += probes;
                    hits.append(&mut found);
                    regions.push(region);
                }
                Err(Error::Scan(msg)) => {
                    // The region vanished mid-walk. Record the race rather than
                    // aborting the whole audit.
                    region.skipped = Some(msg);
                    stats.regions_skipped += 1;
                    regions.push(region);
                }
                Err(e) => return Err(e),
            }
        }

        // The overlap between chunks can surface the same occurrence twice;
        // deduplicate on (needle, derivation, address).
        hits.sort_unstable();
        hits.dedup();

        // Provenance can only be established for our own address space: a
        // container registry and a stack bound describe *this* process.
        let self_scan = self.target.is_none();
        let stack = if self_scan { stack_range() } else { None };
        let mut findings: Vec<Finding> = hits
            .into_iter()
            .map(|(ni, fi, addr)| {
                let n = &self.needles[ni];
                let fp = &n.prints[fi];
                let region = region_at(&regions, addr);
                let provenance = if self_scan {
                    classify(addr, &region, stack)
                } else if self
                    .declared_protected
                    .iter()
                    .any(|&(lo, hi)| addr >= lo && addr < hi)
                {
                    Provenance::Protected
                } else {
                    classify_foreign(&region)
                };
                Finding {
                    needle: n.name().to_string(),
                    derivation: fp.derivation,
                    address: addr,
                    length: fp.len,
                    provenance,
                    region,
                    weak: fp.len < STRONG_MIN_LEN,
                }
            })
            .collect();
        findings.sort_by_key(|f| f.address);

        stats.elapsed = started.elapsed();
        Ok(Report { label, findings, regions, stats, scratch_range })
    }

    /// Reads one region in overlapping chunks and returns (bytes read, anchor
    /// probes, hits as `(needle_idx, fingerprint_idx, address)`).
    #[allow(clippy::too_many_arguments)]
    fn scan_region(
        &self,
        region: &ScanRegion,
        index: &HashMap<u32, Vec<(usize, usize)>>,
        short_needles: &[(usize, usize)],
        scratch: &mut platform::Scratch,
        chunk: usize,
        max_needle: usize,
    ) -> Result<RegionScan> {
        let mut hits: Vec<(usize, usize, u64)> = Vec::new();
        let mut bytes = 0u64;
        let mut probes = 0u64;

        // Overlap so a window straddling a boundary is seen whole next round.
        let overlap = max_needle.saturating_sub(1).min(chunk / 2);
        let mut pos = region.start;

        while pos < region.end {
            let want = (region.end - pos).min(chunk as u64) as usize;
            let got = scratch.read_from(region, pos, want)?;
            if got == 0 {
                break;
            }
            bytes += got as u64;
            let data = scratch.bytes(got);

            probes += scan_chunk(
                data,
                pos,
                index,
                &self.needles,
                short_needles,
                &mut hits,
            );

            // Do not leave a scanned secret in the auditor's own buffer.
            scratch.wipe();

            if pos + got as u64 >= region.end || got < want {
                break;
            }
            let advance = got.saturating_sub(overlap).max(1);
            pos += advance as u64;
        }

        Ok((bytes, probes, hits))
    }
}

/// One rolling pass over `data`, appending confirmed hits to `out`.
///
/// Returns the number of anchor candidates probed.
fn scan_chunk(
    data: &[u8],
    base: u64,
    index: &HashMap<u32, Vec<(usize, usize)>>,
    needles: &[Needle],
    short_needles: &[(usize, usize)],
    out: &mut Vec<(usize, usize, u64)>,
) -> u64 {
    let mut probes = 0u64;
    if data.len() < ANCHOR_LEN {
        return probes;
    }

    // pow = ANCHOR_BASE^(ANCHOR_LEN-1), for rolling the oldest byte out.
    let mut pow: u64 = 1;
    for _ in 0..ANCHOR_LEN - 1 {
        pow = pow.wrapping_mul(ANCHOR_BASE);
    }

    let mut h: u64 = 0;
    for i in 0..data.len() {
        h = h.wrapping_mul(ANCHOR_BASE).wrapping_add(data[i] as u64 + 1);
        if i + 1 < ANCHOR_LEN {
            continue;
        }
        let win_start = i + 1 - ANCHOR_LEN;
        let key = (h as u32) ^ ((h >> 32) as u32);
        if let Some(cands) = index.get(&key) {
            probes += 1;
            for &(ni, fi) in cands {
                let fp = &needles[ni].prints[fi];
                if fp.len > data.len() - win_start {
                    continue; // window would run past the chunk
                }
                let window = &data[win_start..win_start + fp.len];
                if needles[ni].digest(window) == fp.digest {
                    out.push((ni, fi, base + win_start as u64));
                }
            }
        }
        // Roll out the oldest byte of the window.
        h = h.wrapping_sub((data[win_start] as u64 + 1).wrapping_mul(pow));
    }

    // Derivations shorter than the anchor width cannot be hashed into a
    // 4-byte key; search them naively. They are weak by definition and few.
    for &(ni, fi) in short_needles {
        let fp = &needles[ni].prints[fi];
        if fp.len == 0 || fp.len > data.len() {
            continue;
        }
        let digest = fp.digest;
        for off in 0..=data.len() - fp.len {
            if needles[ni].digest(&data[off..off + fp.len]) == digest {
                out.push((ni, fi, base + off as u64));
            }
        }
    }

    probes
}

/// Decides what a hit at `addr` is.
///
/// Order matters: the container check comes first, because a `secretmem`
/// mapping is itself anonymous and would otherwise be classified as heap.
fn classify(addr: u64, region: &ScanRegion, stack: Option<(u64, u64)>) -> Provenance {
    if secretmem::is_protected_address(addr as usize) {
        return Provenance::Protected;
    }
    match region.kind {
        RegionKind::FileBacked | RegionKind::Image => Provenance::FileBacked,
        RegionKind::Anonymous => {
            if let Some((lo, hi)) = stack {
                if addr >= lo && addr < hi {
                    return Provenance::Stack;
                }
            }
            Provenance::Heap
        }
        RegionKind::AuditorScratch => Provenance::Unknown,
        _ => Provenance::Unknown,
    }
}

/// What a hit in **another** process is.
///
/// Deliberately conservative, and deliberately narrow. The container registry is
/// private to the owning process, and the obvious external signals do not work
/// on current macOS: `vm_region` reports `user_wired_count == 0` even for an
/// `mlock`ed, PROT_NONE-flanked range, and `inheritance` does not report
/// `VM_INHERIT_NONE`. Inferring "protected" from mapping shape would be a guess
/// that hides real leaks, so a foreign hit is only ever `FileBacked` (the
/// mapping says so) or `Foreign` (cannot tell, therefore counts as a leak).
///
/// Callers that need precise external classification can have the target expose
/// its container addresses (see `secretmem::is_protected_address`) — that is
/// cooperation, not inspection, and should be labelled as such.
fn classify_foreign(region: &ScanRegion) -> Provenance {
    match region.kind {
        RegionKind::FileBacked | RegionKind::Image => Provenance::FileBacked,
        _ => Provenance::Foreign,
    }
}

/// The main thread's stack bounds, when the platform will tell us.
///
/// Only the main thread: a secret leaked on a worker thread's stack is
/// classified as heap, which is less precise but errs toward reporting it.
#[cfg(target_os = "macos")]
fn stack_range() -> Option<(u64, u64)> {
    extern "C" {
        fn pthread_self() -> *mut libc::c_void;
        fn pthread_get_stackaddr_np(thread: *mut libc::c_void) -> *mut libc::c_void;
        fn pthread_get_stacksize_np(thread: *mut libc::c_void) -> usize;
    }
    // SAFETY: pthread_get_stack* take the current thread and return its bounds.
    unsafe {
        let t = pthread_self();
        let top = pthread_get_stackaddr_np(t) as u64;
        let size = pthread_get_stacksize_np(t) as u64;
        if top == 0 || size == 0 {
            return None;
        }
        Some((top.saturating_sub(size), top))
    }
}

#[cfg(target_os = "linux")]
fn stack_range() -> Option<(u64, u64)> {
    // pthread_getattr_np reports the calling thread's stack.
    // SAFETY: standard pthread attribute query on our own thread.
    unsafe {
        let mut attr: libc::pthread_attr_t = std::mem::zeroed();
        if libc::pthread_getattr_np(libc::pthread_self(), &mut attr) != 0 {
            return None;
        }
        let mut addr: *mut libc::c_void = std::ptr::null_mut();
        let mut size: usize = 0;
        let rc = libc::pthread_attr_getstack(&attr, &mut addr, &mut size);
        libc::pthread_attr_destroy(&mut attr);
        if rc != 0 || addr.is_null() {
            return None;
        }
        Some((addr as u64, addr as u64 + size as u64))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn stack_range() -> Option<(u64, u64)> {
    None
}

fn region_at(regions: &[ScanRegion], addr: u64) -> ScanRegion {
    regions
        .iter()
        .find(|r| addr >= r.start && addr < r.end)
        .cloned()
        .unwrap_or(ScanRegion {
            start: addr,
            end: addr,
            readable: true,
            writable: false,
            executable: false,
            wired: false,
            kind: RegionKind::Other,
            name: None,
            skipped: None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolling_anchor_matches_direct_computation() {
        let data = b"abcdefghijklmnop";
        let mut pow: u64 = 1;
        for _ in 0..ANCHOR_LEN - 1 {
            pow = pow.wrapping_mul(ANCHOR_BASE);
        }
        let mut h: u64 = 0;
        for i in 0..data.len() {
            h = h.wrapping_mul(ANCHOR_BASE).wrapping_add(data[i] as u64 + 1);
            if i + 1 < ANCHOR_LEN {
                continue;
            }
            let start = i + 1 - ANCHOR_LEN;
            let mut direct: u64 = 0;
            for &b in &data[start..=i] {
                direct = direct.wrapping_mul(ANCHOR_BASE).wrapping_add(b as u64 + 1);
            }
            assert_eq!(h, direct, "window at {start}");
            h = h.wrapping_sub((data[start] as u64 + 1).wrapping_mul(pow));
        }
    }

    #[test]
    fn chunk_scan_finds_a_known_needle() {
        let needle = Needle::label("t").from_bytes(b"a-distinctive-secret-value").unwrap();
        let mut index: HashMap<u32, Vec<(usize, usize)>> = HashMap::new();
        let mut short = Vec::new();
        for (fi, fp) in needle.prints.iter().enumerate() {
            match fp.anchor {
                Some(a) => index.entry(a).or_default().push((0, fi)),
                None => short.push((0, fi)),
            }
        }
        let mut data = vec![0u8; 1000];
        let needle_text = b"a-distinctive-secret-value";
        data[500..500 + needle_text.len()].copy_from_slice(needle_text);
        let mut hits = Vec::new();
        let needles = vec![needle];
        scan_chunk(&data, 0, &index, &needles, &short, &mut hits);
        assert!(hits.iter().any(|&(_, _, addr)| addr == 500), "hits={hits:?}");
    }

    #[test]
    fn chunk_scan_reports_nothing_when_absent() {
        let needle = Needle::label("t").from_bytes(b"a-distinctive-secret-value").unwrap();
        let mut index: HashMap<u32, Vec<(usize, usize)>> = HashMap::new();
        let mut short = Vec::new();
        for (fi, fp) in needle.prints.iter().enumerate() {
            match fp.anchor {
                Some(a) => index.entry(a).or_default().push((0, fi)),
                None => short.push((0, fi)),
            }
        }
        let data = vec![0x42u8; 2000];
        let mut hits = Vec::new();
        let needles = vec![needle];
        scan_chunk(&data, 0, &index, &needles, &short, &mut hits);
        assert!(hits.is_empty(), "hits={hits:?}");
    }
}
