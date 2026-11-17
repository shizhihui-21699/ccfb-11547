//! 高熵哨兵值: 每个秘密带唯一、不可自然出现的标记, 让内存扫描零误报。
//!
//! 用确定性 LCG (演示程序不需要真随机, 反而要求可复现),
//! 输出 32 字节伪随机, 再套一层固定前缀方便人工在 hexdump 里辨认。

/// 线性同余生成器 (数值 recipes 常量), 仅用于演示数据, 不用于任何密码学用途。
pub struct Lcg(u64);

impl Lcg {
    pub fn new(seed: u64) -> Self {
        Self(seed ^ 0x5DEECE66D)
    }

    pub fn next_u64(&mut self) -> u64 {
        // MMIX 常量
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 ^= self.0 >> 33;
        self.0
    }
}

/// 生成 `n` 字节哨兵, 前缀 `SENV` 便于人眼识别, 后面是可打印 ASCII 伪随机字节。
///
/// 刻意限制在可打印范围: 既保留高熵 (每字节 ~6.5 bit, 32 字节远超误报阈值),
/// 又能同时喂给 `String` 和 `Vec<u8>` 两条演示路径。
pub fn sentinel(seed: u64, n: usize) -> Vec<u8> {
    let mut rng = Lcg::new(seed);
    let mut out = Vec::with_capacity(n);
    let tag = b"SENV";
    // 可打印 ASCII 区间 [0x21, 0x7e), 94 个字符
    for i in 0..n {
        if i < tag.len() {
            out.push(tag[i]);
        } else {
            let v = (rng.next_u64() % 94) as u8 + 0x21;
            out.push(v);
        }
    }
    out
}

/// 三个演示用秘密: 数据库口令、会话签名密钥、用户会话令牌。
pub struct Fixture {
    pub db_password: Vec<u8>,
    pub signing_key: Vec<u8>,
    pub session_token: Vec<u8>,
}

impl Fixture {
    pub fn generate(seed: u64) -> Self {
        Self {
            db_password: sentinel(seed ^ 0xD8, 40),
            signing_key: sentinel(seed ^ 0x51, 32),
            session_token: sentinel(seed ^ 0xA7, 48),
        }
    }
}

/// 把字节串编码成十六进制 (给 memscan CLI 用)。
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
