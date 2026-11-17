//! Linux 后端: 解析 `/proc/<pid>/maps` 枚举区域, 经 `/proc/<pid>/mem`
//! 按虚拟地址直接读取 (`pread`), 不可读页返回 EIO 时跳过。

use std::fs::File;

use crate::scratch::ProtectedScratch;
use crate::search::StreamSearcher;
use crate::{Hit, Region, ScanReport};

#[derive(Clone, Copy)]
pub enum Target {
    CurrentProcess,
    Pid(u32),
}

#[derive(Debug)]
struct MapsLine {
    start: u64,
    end: u64,
    readable: bool,
    writable: bool,
    label: String,
}

fn pid_of(target: Target) -> u32 {
    match target {
        Target::CurrentProcess => std::process::id(),
        Target::Pid(pid) => pid,
    }
}

fn parse_maps(pid: u32) -> std::io::Result<Vec<MapsLine>> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut out = Vec::new();
    for line in text.lines() {
        // 形如: 7f8a..-7f8b.. rw-p 00000000 00:00 0  [heap]
        let mut parts = line.splitn(6, ' ');
        let range = parts.next().unwrap_or("");
        let perms = parts.next().unwrap_or("");
        let mut rest = parts.skip(3); // offset dev inode
        let label = rest.next().unwrap_or("").trim_start().to_string();

        let (s, e) = range.split_once('-').ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "bad maps line")
        })?;
        let start = u64::from_str_radix(s, 16)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let end = u64::from_str_radix(e, 16)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let bytes = perms.as_bytes();
        out.push(MapsLine {
            start,
            end,
            readable: bytes.first() == Some(&b'r'),
            writable: bytes.get(1) == Some(&b'w'),
            label,
        });
    }
    Ok(out)
}

/// 通过 `/proc/<pid>/smaps` 汇总每个区域的 mlock 字节 (`VmLck` 是整进程的,
/// 逐区域没有直接字段; 这里返回 None, CLI 用全局 VmLck 做证据)。
pub fn list_regions(target: Target) -> std::io::Result<Vec<Region>> {
    let pid = pid_of(target);
    let lines = parse_maps(pid)?;
    Ok(lines
        .into_iter()
        .filter(|m| m.readable)
        .map(|m| Region {
            start: m.start,
            size: m.end - m.start,
            writable: m.writable,
            label: m.label,
            locked_bytes: None,
        })
        .collect())
}

pub fn scan(target: Target, needles: &[&[u8]]) -> std::io::Result<ScanReport> {
    let pid = pid_of(target);
    // 只扫可写数据页: 明文不会在只读代码段, 跳过它们大幅缩小扫描面
    let regions = list_regions(target)?
        .into_iter()
        .filter(|r| r.writable)
        .collect::<Vec<_>>();
    let mem = File::open(format!("/proc/{pid}/mem"))?;
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&mem);
    let mut report = ScanReport::default();
    // 读缓冲走受保护 mmap+mlock 页, 回显不落普通堆, Drop 即整页清零
    let chunk = 4 * 1024 * 1024;
    let mut read_buf = ProtectedScratch::new(chunk)?;
    let mut report = ScanReport {
        scratch_range: Some(read_buf.address_range()),
        ..Default::default()
    };

    for (region_index, region) in regions.iter().enumerate() {
        let mut cursor = region.start;
        let region_end = region.start + region.size;
        let mut searcher = StreamSearcher::new(needles);

        while cursor < region_end {
            let want = std::cmp::min(chunk as u64, region_end - cursor) as usize;
            // pread 按偏移读, 无需 lseek, 直接写入受保护暂存页
            let rc = unsafe {
                libc::pread(
                    fd,
                    read_buf.as_mut_ptr() as *mut libc::c_void,
                    want,
                    cursor as libc::off_t,
                )
            };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EIO) {
                    // 该页未驻留/不可读 (guard page、未提交页), 跳过整页
                    cursor = (cursor + 4096).min(region_end);
                    continue;
                }
                return Err(err);
            }
            let n = rc as usize;
            if n == 0 {
                break;
            }
            let got = unsafe { read_buf.filled(n) };
            for (in_region_off, needle_index) in searcher.push(got) {
                report.hits.push(Hit {
                    address: region.start + in_region_off,
                    region_index,
                    needle_index,
                });
            }
            report.bytes_scanned += n as u64;
            cursor += n as u64;
        }
        report.regions.push(region.clone());
    }

    drop(read_buf); // 受保护页整页清零 + munmap
    Ok(report)
}
