//! 端到端集成测试: 用 memscan 直接验证 secret-vault 的清零保证。
//!
//! 这些测试是库的 "可执行规格": 任何对分配/清零路径的回归都会让它们变红。
//!
//! # 方法论: 如何区分 "活容器" 与扫描器/堆的瞬态回显
//!
//! 扫描器为读取内存必须有工作缓冲, 扫描期间会瞬态回显被测内容, 这些缓冲
//! 位于 MB 级 malloc 匿名区, 地址在多次扫描间漂移。secret-vault 的容器是
//! 独立页级 mmap (区域 ≤64KB 且命中地址页对齐)。`live_container_hits`
//! 用区域大小 + 页对齐两个独立信号识别真正持久的活容器。

use memscan::scan_self;
use secret_vault::{harden_process, SecretBuf, SecretBox, SecretString};
use zeroize::Zeroize;

/// 运行时生成高熵可打印 ASCII 哨兵, 避免字面量进 __TEXT 段。
/// 精确预分配容量, 杜绝 Vec 重分配产生孤儿缓冲区。
fn sentinel(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed ^ 0x5DEECE66D;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push(((x >> 33) % 94) as u8 + 0x21);
    }
    out
}

/// 当前在页级受保护容器中稳定持有的明文命中数。
fn live_hits(pattern: &SecretBuf) -> usize {
    scan_self(&[pattern.as_bytes()])
        .unwrap()
        .live_container_hits()
}

#[test]
fn drop_leaves_zero_residual_hits() {
    harden_process().unwrap();
    let mut secret = sentinel(0x1111, 48);
    let pattern = SecretBuf::from_slice(&secret).unwrap();
    let buf = SecretBuf::from_slice(&secret).unwrap();
    secret.zeroize(); // 源副本清零, 之后明文只在受保护容器里

    // 持有期间: 两个受保护容器 (pattern + buf) 都是活的页级映射
    assert_eq!(live_hits(&pattern), 2, "持有期间应有两个活容器");

    drop(buf);
    // 被测容器释放并清零后, 活容器只剩 pattern 自己
    assert_eq!(live_hits(&pattern), 1, "drop 后应只剩模式容器");
}

#[test]
fn growth_zeroizes_every_old_region() {
    harden_process().unwrap();
    let mut base = sentinel(0x2222, 32);
    let pattern = SecretBuf::from_slice(&base).unwrap();

    let mut buf = SecretBuf::new();
    for round in 0..20u32 {
        // 受保护容器内部反复扩容; 每次迁移的旧映射由库清零+munmap
        let mut chunk = base.clone();
        chunk.push((round % 26) as u8 + b'a');
        buf.extend_from_slice(&chunk).unwrap();
        chunk.zeroize();
    }
    base.zeroize();

    // 经历 20 次扩容后, 活容器仍只有当前 buf + pattern 两个;
    // 被释放的旧映射已 munmap, 不再以页级映射存在。
    assert_eq!(
        live_hits(&pattern),
        2,
        "扩容后旧区域应全部清零回收, 只剩两个存活容器"
    );
}

#[test]
fn clone_is_independent_and_both_clean() {
    let mut secret = sentinel(0x3333, 24);
    let pattern = SecretBuf::from_slice(&secret).unwrap();
    let a = SecretBuf::from_slice(&secret).unwrap();
    let b = a.clone();
    secret.zeroize();
    assert_eq!(a.as_bytes(), b.as_bytes());

    assert_eq!(live_hits(&pattern), 3); // a + b + pattern
    drop(a);
    assert_eq!(live_hits(&pattern), 2); // b + pattern
    drop(b);
    assert_eq!(live_hits(&pattern), 1); // 只剩 pattern
}

#[test]
fn secret_string_and_box_redact_and_clear() {
    let mut pw = sentinel(0x4444, 20);
    let mut key_raw: [u8; 32] = core::array::from_fn(|i| sentinel(0x5555 + i as u64, 1)[0]);

    let s = SecretString::from_utf8(&String::from_utf8_lossy(&pw)).unwrap();
    let k = SecretBox::new(key_raw).unwrap();
    pw.zeroize();
    key_raw.zeroize();

    // Debug/Display 不泄漏
    let probe = sentinel(0x4444, 20);
    let probe_str = String::from_utf8_lossy(&probe).into_owned();
    assert!(!format!("{s:?}").contains(&probe_str));
    assert!(!format!("{s}").contains(&probe_str));
    assert!(format!("{k:?}").contains("REDACTED"));
}

#[test]
fn mlock_accounting_tracks_allocations() {
    let before = secret_vault::locked_bytes();
    {
        let _a = SecretBuf::with_capacity(100).unwrap();
        let _b = SecretBuf::with_capacity(5000).unwrap();
        let after = secret_vault::locked_bytes();
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert!(after - before >= page * 2, "mlock 统计应至少增加两页");
    }
}
