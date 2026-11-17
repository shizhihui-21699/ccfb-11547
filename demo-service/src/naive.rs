//! 改造前的朴素实现 —— 故意写出真实代码里最常见的泄漏模式。
//!
//! 问题点 (每一条都会在验证报告里被抓到):
//! 1. 秘密存进普通 `String`/`Vec<u8>`, 落在堆上, 释放后字节仍在自由块里;
//! 2. `clone()` 产生无主副本, 生命周期不受控;
//! 3. 扩容 (`String::push_str`/`Vec::grow`) 后旧缓冲区成为孤儿;
//! 4. `format!`/日志把秘密格式化进新的临时字符串;
//! 5. HMAC 用的 key 切片到处借, 没有清零点;
//! 6. 错误路径提前 return, 清理代码被跳过。

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct NaiveService {
    /// 数据库口令: 普通 String
    pub db_password: String,
    /// 签名密钥: 普通 Vec
    pub signing_key: Vec<u8>,
    /// 会话令牌缓存: 普通 String, 会不断追加/扩容
    pub session_tokens: Vec<String>,
}

impl NaiveService {
    /// 模拟 "从配置/环境读到秘密" 的典型构造。
    pub fn bootstrap(db_password: &[u8], signing_key: &[u8], session_token: &[u8]) -> Self {
        let db_password = String::from_utf8(db_password.to_vec()).unwrap();
        let signing_key = signing_key.to_vec();
        let session_tokens = vec![String::from_utf8(session_token.to_vec()).unwrap()];
        Self {
            db_password,
            signing_key,
            session_tokens,
        }
    }

    /// 泄漏点 1: clone 出独立副本, 原变量释放了副本还在。
    pub fn connect_database(&self) -> String {
        let _password_copy = self.db_password.clone(); // 模拟驱动拿一份
        // 模拟连接串拼接 —— 又一份临时副本
        let conn_string = format!("postgres://svc:{}@db.internal:5432/app", self.db_password);
        conn_string
    }

    /// 泄漏点 2: 反复扩容, 每次 grow 都可能把旧缓冲区遗弃在堆里。
    pub fn accumulate_sessions(&mut self, extra: &[u8]) {
        let token = &mut self.session_tokens[0];
        for chunk in extra.chunks(8) {
            token.push_str(&String::from_utf8_lossy(chunk));
        }
    }

    /// 泄漏点 3: HMAC 计算。hmac crate 内部会拷贝 key, 我们管不到它的清理;
    /// 而传入的 `&[u8]` 本身就来自普通 Vec。
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.signing_key).unwrap();
        mac.update(message);
        mac.finalize().into_bytes().to_vec()
    }

    /// 泄漏点 4: 错误路径提前返回, 调用方期待的清理永远不执行。
    pub fn fallible_operation(&self, fail: bool) -> Result<Vec<u8>, String> {
        let scratch = format!("prefix-{}-suffix", self.db_password);
        if fail {
            // 直接返回: scratch  drop 了, 但堆字节没清零
            return Err("simulated failure".to_string());
        }
        Ok(scratch.into_bytes())
    }

    /// 普通 drop: 内存归还分配器, 内容原样保留直到被复用覆盖。
    pub fn shutdown(self) {
        // 什么都不做, 模拟真实项目里 "变量离开作用域就完事"
        drop(self);
    }
}
