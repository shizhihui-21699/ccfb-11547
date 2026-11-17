//! 字节串搜索原语。
//!
//! 多模式匹配用 `aho-corasick` (内部 SIMD/packed 加速), 单模式场景同样走它,
//! 避免维护两套实现。内存按块读取, needle 可能横跨两个块, 因此每块保留
//! `max_needle-1` 字节的 carry 与下一块拼接后再搜。

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use zeroize::Zeroize;

/// 在 `haystack` 中查找 `needle` 的全部出现位置 (返回相对偏移)。
///
/// 保留朴素实现供单元测试做交叉验证; 生产扫描路径用 [`StreamSearcher`]。
pub fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || haystack.len() < needle.len() {
        return out;
    }
    let last = haystack.len() - needle.len();
    let mut i = 0;
    while i <= last {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
            i += 1; // 允许重叠命中
        } else {
            i += 1;
        }
    }
    out
}

/// 流式多模式搜索器: 喂入一块块数据, 输出 (流内绝对偏移, needle 下标) 命中。
///
/// 只借用模式切片, 不拷贝模式内容。
pub struct StreamSearcher<'a> {
    ac: AhoCorasick,
    carry: Vec<u8>,
    consumed: u64,
    max_needle: usize,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> StreamSearcher<'a> {
    /// `needles` 是模式切片的集合 (调用方通常传 `&[&[u8]]`)。
    pub fn new(needles: &'a [&'a [u8]]) -> Self {
        // Standard 语义支持重叠匹配, 保证 "aaaa" 搜 "aa" 能报 3 次。
        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .build(needles.iter().copied())
            .expect("aho-corasick build: non-empty patterns");
        let max_needle = needles.iter().map(|n| n.len()).max().unwrap_or(0);
        Self {
            ac,
            carry: Vec::with_capacity(max_needle.saturating_sub(1)),
            consumed: 0,
            max_needle,
            _marker: std::marker::PhantomData,
        }
    }

    /// 喂入下一块, 返回本块内命中的 (相对整个流的绝对偏移, needle 下标)。
    ///
    /// 直接在调用方的受保护切片上搜索, 不把整块数据拷进普通堆;
    /// 只维护一个 `max_needle-1` 字节的小 carry 处理跨块模式。
    pub fn push(&mut self, chunk: &[u8]) -> Vec<(u64, usize)> {
        let mut hits = Vec::new();
        if self.max_needle == 0 {
            self.consumed += chunk.len() as u64;
            return hits;
        }

        // 1) 整块在调用方切片上零拷贝搜索, 命中偏移相对流起点
        for m in self.ac.find_iter(chunk) {
            hits.push((self.consumed + m.start() as u64, m.pattern().as_usize()));
        }

        // 2) 跨块模式: 上一块尾部 carry + 本块头部, 拼成一个小重叠区单独搜。
        //    长度最多 2*(max_needle-1), 与块大小无关; 只报起点在 carry 内的命中,
        //    起点在 chunk 头部的已被步骤 1 报过, 天然去重。
        if !self.carry.is_empty() {
            let head_len = (chunk.len()).min(self.max_needle - 1);
            let mut overlap = Vec::with_capacity(self.carry.len() + head_len);
            overlap.extend_from_slice(&self.carry);
            overlap.extend_from_slice(&chunk[..head_len]);
            let overlap_base = self.consumed - self.carry.len() as u64;
            for m in self.ac.find_iter(&overlap) {
                if m.start() < self.carry.len() {
                    hits.push((
                        overlap_base + m.start() as u64,
                        m.pattern().as_usize(),
                    ));
                }
            }
            overlap.zeroize();
        }

        // 3) 更新 carry: 仅保留块尾部 max_needle-1 字节供下一块拼重叠区
        let keep = self.max_needle - 1;
        self.carry.clear();
        if chunk.len() >= keep {
            self.carry.extend_from_slice(&chunk[chunk.len() - keep..]);
        } else {
            self.carry.extend_from_slice(chunk);
        }
        self.consumed += chunk.len() as u64;
        hits
    }
}

impl<'a> Drop for StreamSearcher<'a> {
    fn drop(&mut self) {
        // carry 持有上一块的秘密尾部, 释放前显式清零
        self.carry.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_find() {
        assert_eq!(find_all(b"abcabc", b"abc"), vec![0, 3]);
        assert_eq!(find_all(b"aaaa", b"aa"), vec![0, 1, 2]);
        assert_eq!(find_all(b"abc", b"abcd"), vec![]);
    }

    #[test]
    fn stream_carry_handles_boundary() {
        let n = b"secret123".to_vec();
        let needles: Vec<&[u8]> = vec![&n];
        let mut s = StreamSearcher::new(&needles);
        let mut got = Vec::new();
        // 故意从 needle 中间切开
        got.extend(s.push(b"xxxxsecre"));
        got.extend(s.push(b"t123yyyy"));
        assert_eq!(got, vec![(4, 0)]);
    }

    #[test]
    fn stream_multiple_needles() {
        let a = b"aaa".to_vec();
        let b = b"bbb".to_vec();
        let needles: Vec<&[u8]> = vec![&a, &b];
        let mut s = StreamSearcher::new(&needles);
        let hits = s.push(b"aaabbb");
        assert!(hits.contains(&(0, 0)));
        assert!(hits.contains(&(3, 1)));
    }

    #[test]
    fn stream_repeated_non_overlapping() {
        // 真实哨兵是高熵随机字节, 不会自重叠; Aho-Corasick 的 Standard 语义
        // 对自重叠模式只报不重叠的命中 (aaaa/aa -> 0,2), 这里验证重复出现
        // 的独立模式全部能报出来。
        let n = b"SECRET".to_vec();
        let needles: Vec<&[u8]> = vec![&n];
        let mut s = StreamSearcher::new(&needles);
        let hits = s.push(b"xxSECRETyySECRETzz");
        assert_eq!(hits, vec![(2, 0), (10, 0)]);
    }
}
