//! # memscan
//!
//! 遍历目标进程的可读内存区域, 搜索指定字节串的残留。
//!
//! - **macOS**: Mach `mach_vm_region` 枚举区域 + `mach_vm_read_overwrite` 读取,
//!   `proc_regionfilename` 给区域打标签 (堆栈/匿名映射/文件映射)。
//! - **Linux**: 解析 `/proc/self/maps`(或 `/proc/<pid>/maps`), 经
//!   `/proc/<pid>/mem` 按地址读取, `EIO` 表示该页不可读, 跳过。
//!
//! 扫描结果带区域标签, 演示程序据此区分 "活容器所在页" 与 "残留副本"。

use std::fmt;

#[cfg(target_os = "macos")]
mod backend_macos;
#[cfg(target_os = "linux")]
mod backend_linux;

mod scratch;
mod search;

#[cfg(target_os = "macos")]
use backend_macos as backend;
#[cfg(target_os = "linux")]
use backend_linux as backend;

/// 一块可读内存区域的元数据。
#[derive(Debug, Clone)]
pub struct Region {
    /// 区域起始地址
    pub start: u64,
    /// 区域字节数
    pub size: u64,
    /// 是否可写 (可写匿名区通常就是堆/栈)
    pub writable: bool,
    /// 区域标签: 文件路径、`[stack]`、`[heap]`、`[anon]` 等
    pub label: String,
    /// 该区域中被 mlock 锁定的字节数 (无法探测时为 None)
    pub locked_bytes: Option<u64>,
}

impl Region {
    /// 是否为匿名可写内存 (堆分配、mmap 私有匿名页都落在这一类)
    pub fn is_anonymous_writable(&self) -> bool {
        self.writable && (self.label.is_empty() || self.label.starts_with('[') && !self.label.contains('/'))
    }
}

/// 一次命中。
#[derive(Debug, Clone)]
pub struct Hit {
    /// 命中的绝对虚拟地址
    pub address: u64,
    /// 落在第几个区域 (对应 [`ScanReport::regions`] 的下标)
    pub region_index: usize,
    /// 是第几个 needle 命中的
    pub needle_index: usize,
}

/// 一次全量扫描的报告。
#[derive(Debug, Clone, Default)]
pub struct ScanReport {
    pub regions: Vec<Region>,
    pub bytes_scanned: u64,
    pub hits: Vec<Hit>,
    /// 扫描器自身受保护暂存页的地址区间 (start, end)。
    /// 落在此区间的命中是测量仪器的瞬时回显 (mmap+mlock, 扫描结束即清零),
    /// 不计入真实残留。
    pub scratch_range: Option<(u64, u64)>,
}

impl ScanReport {
    /// 指定 needle 的命中次数。
    pub fn hit_count(&self, needle_index: usize) -> usize {
        self.hits.iter().filter(|h| h.needle_index == needle_index).count()
    }

    /// 判断某命中地址是否落在扫描器暂存页内。
    fn in_scratch(&self, addr: u64) -> bool {
        self.scratch_range
            .map(|(s, e)| addr >= s && addr < e)
            .unwrap_or(false)
    }

    /// 排除扫描器自身受保护暂存页后的 "真实残留" 命中数。
    ///
    /// 扫描器为读取内存必须有暂存缓冲, 扫描期间它会回显被测内容;
    /// 该缓冲是 mmap+mlock 受保护页且扫描结束即清零, 不算持久泄漏。
    /// 验证清零保证时应使用本方法而非裸 `hits.len()`。
    pub fn residual_hits(&self) -> usize {
        self.hits.iter().filter(|h| !self.in_scratch(h.address)).count()
    }

    /// 本报告中命中地址的集合 (供多次扫描做稳定性比对)。
    pub fn hit_addresses(&self) -> std::collections::HashSet<u64> {
        self.hits.iter().map(|h| h.address).collect()
    }

    /// 判断命中是否落在 "页级受保护小映射" 内。
    ///
    /// secret-vault 的容器是独立 mmap, 特征明确: 区域很小 (按页分配,
    /// 典型 16KB/4KB), 且命中地址页对齐。malloc 的堆缓冲位于 MB 级巨型
    /// 匿名区, 扫描器的瞬态回显也在那里。用区域大小 + 对齐两个独立信号
    /// 区分, 比单一启发式可靠。
    pub fn hit_in_small_page_mapping(&self, hit: &Hit) -> bool {
        let Some(region) = self.regions.get(hit.region_index) else {
            return false;
        };
        const PAGE: u64 = 4096;
        let small = region.size <= 64 * 1024; // 页级映射, 远小于 malloc 的 MB 级 arena
        let aligned = hit.address & (PAGE - 1) == 0;
        small && aligned
    }

    /// 统计落在页级受保护小映射内的命中 —— 即 "活容器" 持有的明文。
    pub fn live_container_hits(&self) -> usize {
        self.hits
            .iter()
            .filter(|h| self.hit_in_small_page_mapping(h))
            .count()
    }

    /// 命中是否全部落在给定地址区间内 (用来判断 "只剩活容器, 没有别处残留")。
    pub fn hits_all_within(&self, needle_index: usize, ranges: &[(u64, u64)]) -> bool {
        self.hits
            .iter()
            .filter(|h| h.needle_index == needle_index)
            .all(|h| ranges.iter().any(|(s, e)| h.address >= *s && h.address < *e))
    }

    /// 命中所在区域的标签分布, 便于报告 "堆上 3 处、栈上 1 处"。
    pub fn hit_labels(&self, needle_index: usize) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = Vec::new();
        for h in self.hits.iter().filter(|h| h.needle_index == needle_index) {
            let label = self
                .regions
                .get(h.region_index)
                .map(|r| if r.label.is_empty() { "[anon]".to_string() } else { r.label.clone() })
                .unwrap_or_else(|| "?".to_string());
            if let Some(slot) = out.iter_mut().find(|(l, _)| *l == label) {
                slot.1 += 1;
            } else {
                out.push((label, 1));
            }
        }
        out
    }
}

impl fmt::Display for ScanReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "scanned {} regions, {} bytes, {} hits",
            self.regions.len(),
            self.bytes_scanned,
            self.hits.len()
        )?;
        for h in &self.hits {
            let r = &self.regions[h.region_index];
            writeln!(
                f,
                "  needle#{} @ {:#x} in {} ({:#x}+{:#x})",
                h.needle_index,
                h.address,
                if r.label.is_empty() { "[anon]" } else { &r.label },
                r.start,
                r.size
            )?;
        }
        Ok(())
    }
}

/// 扫描自身进程的全部可读区域, 搜索 `needles` 中任意一个模式。
///
/// 只借用模式切片, 不产生任何模式拷贝; 调用方可把模式放在 secret-vault
/// 容器里, 扫描过程本身不会成为新的明文来源。
pub fn scan_self(needles: &[&[u8]]) -> std::io::Result<ScanReport> {
    backend::scan(backend::Target::CurrentProcess, needles)
}

/// 扫描指定 pid。
///
/// - Linux: 同权限用户即可读 `/proc/<pid>/mem`;
/// - macOS: 仅支持自身 (task_for_pid 对其他进程需要 hardened-runtime 授权,
///   外部附加请用 `tools/lldb_dump.sh`)。
pub fn scan_pid(pid: u32, needles: &[&[u8]]) -> std::io::Result<ScanReport> {
    backend::scan(backend::Target::Pid(pid), needles)
}

/// 列出全部可读区域 (含 mlock 信息), 用于验证 "数据页确实被锁"。
pub fn list_regions() -> std::io::Result<Vec<Region>> {
    backend::list_regions(backend::Target::CurrentProcess)
}

/// 便捷封装: 扫描自身并返回某模式的全部命中地址。
pub fn find_in_self(needle: &[u8]) -> std::io::Result<Vec<u64>> {
    let report = scan_self(&[needle])?;
    Ok(report.hits.iter().map(|h| h.address).collect())
}

/// 多次扫描取地址交集, 得到 "稳定持久残留" 的地址集合。
///
/// # 为什么需要多次扫描
///
/// 扫描器自身的工作缓冲 (读暂存页、搜索器状态) 在每次扫描时会瞬态回显
/// 被测内容, 但这些缓冲每次落在不同地址、扫描结束即清零, 因此它们的命中
/// 地址在多次扫描间会漂移。真正持久存在于某固定位置的明文 (无论是受保护
/// 容器还是泄漏副本) 地址保持稳定。取多次扫描的地址交集即可把两者分开,
/// 这比依赖区域大小/标签的启发式判断可靠得多。
///
/// 返回的地址集合即 "此刻确实持久持有明文的位置"。
pub fn stable_residual_addresses(needles: &[&[u8]], scans: usize) -> std::io::Result<std::collections::HashSet<u64>> {
    assert!(scans >= 2, "稳定性判定至少需要 2 次扫描");
    let mut intersection: Option<std::collections::HashSet<u64>> = None;
    for _ in 0..scans {
        let report = scan_self(needles)?;
        let addrs = report.hit_addresses();
        intersection = Some(match intersection {
            None => addrs,
            Some(prev) => prev.intersection(&addrs).copied().collect(),
        });
    }
    Ok(intersection.unwrap_or_default())
}

pub use search::find_all;
