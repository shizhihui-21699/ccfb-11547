//! macOS 后端: 通过 Mach VM API 枚举并读取当前进程的内存区域。

use std::ffi::CStr;
use std::io;

use mach2::kern_return::{KERN_INVALID_ADDRESS, KERN_SUCCESS};
use mach2::mach_types::vm_task_entry_t;
use mach2::message::mach_msg_type_number_t;
use mach2::port::mach_port_t;
use mach2::traps::mach_task_self;
use mach2::vm::{mach_vm_read_overwrite, mach_vm_region};
use mach2::vm_prot::{VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_region::{
    vm_region_basic_info_data_64_t, VM_REGION_BASIC_INFO_64, VM_REGION_BASIC_INFO_COUNT_64,
};

use crate::scratch::ProtectedScratch;
use crate::search::StreamSearcher;
use crate::{Hit, Region, ScanReport};

#[derive(Clone, Copy)]
pub enum Target {
    CurrentProcess,
    // macOS 后端暂不支持扫描其他进程; 保留字段以与 Linux 后端 API 对齐
    #[allow(dead_code)]
    Pid(u32),
}

// libproc 的区域文件名接口 (mach2 不提供, 自己声明)。
extern "C" {
    fn proc_regionfilename(
        pid: libc::c_int,
        address: u64,
        buf: *mut libc::c_char,
        buffersize: u32,
    ) -> libc::c_int;
}

/// 单次 mach_vm_read_overwrite 的块大小; 太大的区域分块读取。
const CHUNK: u64 = 4 * 1024 * 1024;

fn task_for(target: Target) -> io::Result<vm_task_entry_t> {
    match target {
        Target::CurrentProcess => Ok(unsafe { mach_task_self() }),
        Target::Pid(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "macOS 后端只支持扫描自身; 扫描其他进程请用 tools/lldb_dump.sh",
        )),
    }
}

fn region_label(address: u64) -> String {
    let mut buf = [0i8; 1024];
    let n = unsafe {
        proc_regionfilename(
            libc::getpid(),
            address,
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };
    if n <= 0 {
        return String::new();
    }
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr()) };
    cstr.to_string_lossy().into_owned()
}

/// 枚举当前进程全部可读区域。
pub fn list_regions(target: Target) -> io::Result<Vec<Region>> {
    let task = task_for(target)?;
    let mut out = Vec::new();
    let mut address: u64 = 0;

    loop {
        let mut size: u64 = 0;
        let mut info = vm_region_basic_info_data_64_t {
            protection: 0,
            max_protection: 0,
            inheritance: 0,
            shared: 0,
            reserved: 0,
            offset: 0,
            behavior: 0,
            user_wired_count: 0,
        };
        let mut count: mach_msg_type_number_t = VM_REGION_BASIC_INFO_COUNT_64;
        let mut object_name: mach_port_t = 0;

        let kr = unsafe {
            mach_vm_region(
                task,
                &mut address,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                (&mut info as *mut vm_region_basic_info_data_64_t).cast::<libc::c_int>(),
                &mut count,
                &mut object_name,
            )
        };

        if kr == KERN_INVALID_ADDRESS {
            break; // 地址空间走到头
        }
        if kr != KERN_SUCCESS {
            return Err(io::Error::other(format!(
                "mach_vm_region failed: kr={kr}"
            )));
        }

        if (info.protection & VM_PROT_READ) != 0 && size > 0 {
            out.push(Region {
                start: address,
                size,
                writable: (info.protection & VM_PROT_WRITE) != 0,
                label: region_label(address),
                // macOS 不暴露逐区域 locked 统计; 全局证据由 CLI 的 vm_stat 给出
                locked_bytes: None,
            });
        }
        address = address.saturating_add(size);
        if address == 0 {
            break;
        }
    }
    Ok(out)
}

pub fn scan(target: Target, needles: &[&[u8]]) -> std::io::Result<ScanReport> {
    let task = task_for(target)?;
    // 明文秘密只会出现在可写数据页; 只读代码段/文件映射跳过,
    // 既快又能把 "硬编码在二进制里的秘密" 这类独立问题区分开。
    let regions = list_regions(target)?
        .into_iter()
        .filter(|r| r.writable)
        .collect::<Vec<_>>();
    let mut read_buf = ProtectedScratch::new(CHUNK as usize)?;
    let mut report = ScanReport {
        scratch_range: Some(read_buf.address_range()),
        ..Default::default()
    };

    for (region_index, region) in regions.iter().enumerate() {
        let region_end = region.start.saturating_add(region.size);
        let mut cursor = region.start;
        // 每个 region 独立的流式搜索器, push 返回的偏移即区域内偏移
        let mut searcher = StreamSearcher::new(needles);

        while cursor < region_end {
            let this = std::cmp::min(CHUNK, region_end - cursor);
            let mut out_size: u64 = 0;
            let kr = unsafe {
                mach_vm_read_overwrite(
                    task,
                    cursor,
                    this,
                    read_buf.as_mut_ptr() as u64,
                    &mut out_size,
                )
            };
            if kr != KERN_SUCCESS {
                // 页保护中途变化或被回收: 跳过该块
                cursor = cursor.saturating_add(this);
                continue;
            }
            if out_size == 0 {
                break;
            }
            let got = unsafe { read_buf.filled(out_size as usize) };
            for (in_region_off, needle_index) in searcher.push(got) {
                report.hits.push(Hit {
                    address: region.start + in_region_off,
                    region_index,
                    needle_index,
                });
            }
            report.bytes_scanned += out_size;
            cursor = cursor.saturating_add(out_size);
        }
        report.regions.push(region.clone());
    }

    // read_buf 在 Drop 时整页清零; 无需也无法对受保护页做普通 fill(0)
    drop(read_buf);
    Ok(report)
}
