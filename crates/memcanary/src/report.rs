//! Scan results.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use crate::needle::Derivation;
use crate::scan::ScanStats;

/// What a mapped region is, as well as the platform can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RegionKind {
    /// Anonymous memory: heap, stacks, and `secretmem` regions. This is where
    /// a leak is meaningful.
    Anonymous,
    /// A file-backed executable mapping (the binary, a dylib, the JIT).
    Image,
    /// A file-backed non-executable mapping (the dyld shared cache, mmapped
    /// files).
    FileBacked,
    /// The auditor's own scratch buffer, excluded so it cannot report itself.
    AuditorScratch,
    /// Something the platform did not classify.
    Other,
}

impl RegionKind {
    /// Human-readable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            RegionKind::Anonymous => "anonymous",
            RegionKind::Image => "image",
            RegionKind::FileBacked => "file-backed",
            RegionKind::AuditorScratch => "auditor-scratch",
            RegionKind::Other => "other",
        }
    }
}

impl fmt::Display for RegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One mapped region the scan considered.
#[derive(Debug, Clone)]
pub struct ScanRegion {
    /// First address.
    pub start: u64,
    /// One past the last address.
    pub end: u64,
    /// Readable by the process.
    pub readable: bool,
    /// Writable by the process.
    pub writable: bool,
    /// Executable.
    pub executable: bool,
    /// Pages are wired (`mlock`). A `secretmem` range is always wired; this is
    /// how it is recognised when scanning another process.
    pub wired: bool,
    /// Classification.
    pub kind: RegionKind,
    /// Path, when the region is file-backed.
    pub name: Option<String>,
    /// Why the region was not read, if it was skipped.
    pub skipped: Option<String>,
}

impl ScanRegion {
    /// Region length in bytes.
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the region is empty (should never be).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Where a hit lives, which decides whether it is a leak.
///
/// The distinction is the whole point of the audit. A service is *supposed* to
/// hold its DB password while it is connected; the question is whether it holds
/// it only inside containers that will wipe it, or also in copies nothing can
/// reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Provenance {
    /// Inside a live `secretmem` container: expected, and it will be wiped.
    Protected,
    /// On the stack. Transient, but a copy made here is outside the wiping
    /// machinery.
    Stack,
    /// On the heap (malloc arena, Rust global allocator): the classic leak.
    Heap,
    /// In a file-backed mapping — most often the binary's own rodata, i.e. a
    /// literal compiled in. No library can wipe that; the fix is not to embed
    /// the value.
    FileBacked,
    /// Not classifiable.
    Unknown,
    /// Scanning another process, where the container registry is not readable.
    ///
    /// This is reported separately from `Unknown` because it is a *known*
    /// limitation of external scanning, not a failure to classify: without
    /// cooperation from the target there is no reliable way to tell its
    /// container from its heap. See [`crate::Auditor::for_pid`].
    Foreign,
}

impl Provenance {
    /// Stable name for reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Provenance::Protected => "protected",
            Provenance::Stack => "stack",
            Provenance::Heap => "heap",
            Provenance::FileBacked => "file-backed",
            Provenance::Unknown => "unknown",
            Provenance::Foreign => "foreign",
        }
    }

    /// Whether a hit from this provenance counts as a leak.
    ///
    /// Protected is not; everything else is. A file-backed hit is reported but
    /// separately flagged, because the remedy is at the source, not runtime.
    ///
    /// `Foreign` is treated as a leak: when the auditor cannot tell, it must not
    /// quietly excuse a hit. External scans are therefore conservative — they
    /// over-report rather than under-report.
    pub const fn is_leak(self) -> bool {
        !matches!(self, Provenance::Protected)
    }
}

/// One confirmed occurrence of a needle in memory.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The needle's label.
    pub needle: String,
    /// Which encoding of it was found.
    pub derivation: Derivation,
    /// Address where the window begins.
    pub address: u64,
    /// Window length.
    pub length: usize,
    /// The region it was found in.
    pub region: ScanRegion,
    /// Where it lives, which decides whether it is a leak.
    pub provenance: Provenance,
    /// Whether the match is short enough that it may be coincidence.
    pub weak: bool,
}

impl Finding {
    /// A hit that counts as residue: strong, and not inside a container.
    pub fn is_leak(&self) -> bool {
        !self.weak && self.provenance.is_leak()
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}] at {:#x} ({} bytes, {}{}) in {} region {:#x}..{:#x}",
            self.needle,
            self.derivation.as_str(),
            self.address,
            self.length,
            self.provenance.as_str(),
            if self.weak { ", weak" } else { "" },
            self.region.kind,
            self.region.start,
            self.region.end,
        )
    }
}

/// The outcome of one scan.
#[derive(Debug, Clone)]
pub struct Report {
    pub(crate) label: Option<String>,
    /// Confirmed occurrences, sorted by address.
    pub findings: Vec<Finding>,
    /// Every region considered, in address order.
    pub regions: Vec<ScanRegion>,
    /// Counters.
    pub stats: ScanStats,
    /// The auditor scratch range, for callers that want to confirm exclusion.
    pub scratch_range: (u64, u64),
}

impl Report {
    /// The checkpoint label, if this scan was stored as one.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Strong findings (long enough that coincidence is implausible).
    pub fn strong_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| !f.weak)
    }

    /// Weak findings (short needles).
    pub fn weak_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.weak)
    }

    /// Leaks: strong hits outside a protected container.
    pub fn leaks(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| f.is_leak())
    }

    /// Strong hits inside a live container (expected, and will be wiped).
    pub fn protected_hits(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| !f.weak && f.provenance == Provenance::Protected)
    }

    /// Whether no leak was found. Hits inside `secretmem` containers do not
    /// count — the container holds the value on purpose and will wipe it — and
    /// weak hits are coincidence-prone.
    pub fn is_clean(&self) -> bool {
        self.leaks().next().is_none()
    }

    /// Whether the scan was clean *including* weak findings and container hits.
    pub fn is_clean_strict(&self) -> bool {
        self.findings.is_empty()
    }

    /// Bytes that were actually read.
    pub fn bytes_read(&self) -> u64 {
        self.stats.bytes_read
    }

    /// Wall time of the scan.
    pub fn elapsed(&self) -> Duration {
        self.stats.elapsed
    }

    /// Findings grouped by region kind, for a summary.
    pub fn findings_by_kind(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for f in &self.findings {
            *m.entry(f.region.kind.as_str()).or_insert(0) += 1;
        }
        m
    }

    /// A Markdown table of findings, suitable for a report file.
    pub fn findings_markdown(&self) -> String {
        let mut s = String::new();
        s.push_str("| needle | encoding | address | bytes | provenance | region | weak |\n");
        s.push_str("|---|---|---|---|---|---|---|\n");
        for f in &self.findings {
            s.push_str(&format!(
                "| {} | {} | `{:#x}` | {} | {} | {} | {} |\n",
                f.needle,
                f.derivation.as_str(),
                f.address,
                f.length,
                f.provenance.as_str(),
                f.region.kind,
                if f.weak { "yes" } else { "no" }
            ));
        }
        if self.findings.is_empty() {
            s.push_str("| _(none)_ | | | | | | |\n");
        }
        s
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let strong = self.findings.iter().filter(|f| !f.weak).count();
        let weak = self.findings.len() - strong;
        write!(
            f,
            "{}: {} strong, {} weak finding(s); read {} bytes from {} region(s) in {:?}",
            self.label.as_deref().unwrap_or("scan"),
            strong,
            weak,
            self.stats.bytes_read,
            self.stats.regions_read,
            self.stats.elapsed
        )
    }
}
