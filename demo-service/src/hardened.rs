//! 改造后的加固实现 —— 同样的业务动作, 所有秘密只存在于 secret-vault 容器里。
//!
//! 与 naive 版逐条对应:
//! 1. 秘密全部存进 mmap+mlock 的受保护页, 不进堆;
//! 2. "复制" 是深拷贝到新的受保护页, 两份各自独立清零;
//! 3. 扩容走 SecretBuf::reserve: 新映射 + 迁移 + 旧区 explicit_zero + munmap;
//! 4. 不允许 `format!` 秘密; 连接串在受保护缓冲内手工拼装, 用完即弃;
//! 5. HMAC key 通过 `expose()` 短暂借出到栈上数组, 计算完立刻 zeroize;
//! 6. 错误路径用显式 zeroize + `?` 配合 Drop, 任何返回方式都会清零。

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use secret_vault::{SecretBox, SecretBuf, SecretString};

type HmacSha256 = Hmac<Sha256>;

pub struct HardenedService {
    db_password: SecretString,
    signing_key: SecretBox<[u8; 32]>,
    session_token: SecretBuf,
}

impl HardenedService {
    /// 从字节源直接落地到受保护页。
    ///
    /// 注意: 入参的 `Vec<u8>` 是测试夹具 (naive/secure 两条进程独立,
    /// 互不污染); 真实服务应改用 `SecretString::from_reader_*` 从 socket/
    /// 文件描述符直接读入, 让明文从不经过普通堆。
    pub fn bootstrap(
        db_password: &[u8],
        signing_key: &[u8],
        session_token: &[u8],
    ) -> secret_vault::Result<Self> {
        let db_password = SecretString::from_utf8(&String::from_utf8_lossy(db_password))?;
        let signing_key = SecretBox::<[u8; 32]>::from_slice_exact(signing_key)?;
        let session_token = SecretBuf::from_slice(session_token)?;
        Ok(Self {
            db_password,
            signing_key,
            session_token,
        })
    }

    /// 对应 naive::connect_database: 连接串在受保护缓冲内拼装, 函数返回前清零。
    pub fn connect_database(&self) -> secret_vault::Result<()> {
        let mut conn_string = SecretBuf::new();
        conn_string.extend_from_slice(b"postgres://svc:")?;
        conn_string.extend_from_slice(self.db_password.reveal().as_bytes())?;
        conn_string.extend_from_slice(b"@db.internal:5432/app")?;
        // 模拟驱动消费连接串... 这里只做一次 HMAC 式使用, 不输出明文
        let mut mac = HmacSha256::new_from_slice(b"driver-handshake").unwrap();
        mac.update(conn_string.as_bytes());
        let _ = mac.finalize().into_bytes();
        // 显式清零; 即使忘了写, Drop 也会兜底
        conn_string.zeroize_now();
        Ok(())
    }

    /// 对应 naive::accumulate_sessions: 受保护缓冲扩容, 旧映射立即清零回收。
    pub fn accumulate_sessions(&mut self, extra: &[u8]) -> secret_vault::Result<()> {
        self.session_token.extend_from_slice(extra)
    }

    /// 对应 naive::sign: key 只在栈上短暂出现, 用完立即 zeroize。
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut key_exposed = self.signing_key.expose(); // [u8; 32] 栈拷贝
        let result = {
            let mut mac = HmacSha256::new_from_slice(&key_exposed)
                .expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        };
        key_exposed.zeroize(); // 栈上副本立刻清零
        result
    }

    /// 对应 naive::fallible_operation: 错误路径同样保证清零。
    pub fn fallible_operation(&self, fail: bool) -> secret_vault::Result<SecretBuf> {
        let mut scratch = SecretBuf::new();
        scratch.extend_from_slice(b"prefix-")?;
        scratch.extend_from_slice(self.db_password.reveal().as_bytes())?;
        scratch.extend_from_slice(b"-suffix")?;
        if fail {
            scratch.zeroize_now(); // 显式清零, 然后返回错误 (不含任何秘密)
            return Err(secret_vault::SecretError::new(
                secret_vault::ErrorKind::InvalidInput,
                0,
                "simulated failure",
            ));
        }
        Ok(scratch) // 调用方负责 drop, drop 即清零
    }

    /// 当前会话令牌的容器地址区间 (验证报告用来区分 "活容器" 与 "残留")。
    pub fn session_token_range(&self) -> (u64, u64) {
        let bytes = self.session_token.as_bytes();
        let start = bytes.as_ptr() as u64;
        (start, start + bytes.len() as u64)
    }

    pub fn db_password_range(&self) -> (u64, u64) {
        let bytes = self.db_password.reveal().as_bytes();
        let start = bytes.as_ptr() as u64;
        (start, start + bytes.len() as u64)
    }

    pub fn signing_key_range(&self) -> (u64, u64) {
        let key = self.signing_key.get();
        let start = key.as_ptr() as u64;
        (start, start + key.len() as u64)
    }

    pub fn shutdown(mut self) {
        // 显式清零 + Drop 双保险
        self.db_password.zeroize_now();
        self.session_token.zeroize_now();
        // signing_key 随 self drop 自动整页清零
    }
}
