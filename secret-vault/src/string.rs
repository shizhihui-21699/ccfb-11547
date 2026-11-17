//! [`SecretString`]: 面向口令、API key、会话令牌等文本秘密。
//!
//! 内部就是一个 [`SecretBuf`], 额外保证 UTF-8 合法性, 并提供
//! 显式的 `reveal()` 访问 —— 名字本身就是代码审计时的检索锚点。

use std::fmt;

use crate::buf::SecretBuf;
use crate::error::{ErrorKind, Result, SecretError};

#[derive(Clone)]
pub struct SecretString {
    inner: SecretBuf,
}

impl SecretString {
    pub fn new() -> Self {
        Self {
            inner: SecretBuf::new(),
        }
    }

    /// 从 `&str` 构造。源切片本身通常来自调用方的普通内存,
    /// 文档会强调: 尽量改用 [`SecretString::from_reader_utf8`] 从源头直接落地。
    ///
    /// 命名刻意避开 `FromStr::from_str` (那是可能失败的解析 trait 方法),
    /// 用 `from_utf8` 明确表达 "输入已是合法 UTF-8 的一次性落地"。
    pub fn from_utf8(s: &str) -> Result<Self> {
        Ok(Self {
            inner: SecretBuf::from_slice(s.as_bytes())?,
        })
    }

    /// 从 reader 读入并做 UTF-8 校验, 全程不经过普通 `String`。
    pub fn from_reader_utf8<R: std::io::Read>(reader: &mut R) -> Result<Self> {
        let inner = SecretBuf::from_reader(reader)?;
        std::str::from_utf8(inner.as_bytes()).map_err(|_| {
            SecretError::new(ErrorKind::InvalidInput, 0, "input is not valid UTF-8")
        })?;
        Ok(Self { inner })
    }

    /// 读取一行 (去掉行尾 `\n`/`\r\n`), 典型用途: 交互式口令输入。
    pub fn from_reader_line<R: std::io::BufRead>(reader: &mut R) -> Result<Self> {
        let inner = SecretBuf::from_reader(reader)?;
        let n = inner.len();
        let trim = if n >= 2 && &inner.as_bytes()[n - 2..] == b"\r\n" {
            2
        } else if n >= 1 && inner.as_bytes()[n - 1] == b'\n' {
            1
        } else {
            0
        };
        let mut s = Self { inner };
        s.inner.truncate(n - trim);
        std::str::from_utf8(s.inner.as_bytes()).map_err(|_| {
            SecretError::new(ErrorKind::InvalidInput, 0, "input is not valid UTF-8")
        })?;
        Ok(s)
    }

    /// 显式揭示内容。审计时全局搜索 `reveal(` 即可找到所有明文出口。
    #[inline]
    pub fn reveal(&self) -> &str {
        // 构造路径已保证 UTF-8 合法
        unsafe { std::str::from_utf8_unchecked(self.inner.as_bytes()) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline]
    pub fn as_secret_buf(&self) -> &SecretBuf {
        &self.inner
    }

    #[inline]
    pub fn into_secret_buf(self) -> SecretBuf {
        self.inner
    }

    pub fn zeroize_now(&mut self) {
        self.inner.zeroize_now();
    }

    /// 常量时间比较。
    pub fn ct_eq(&self, other: &SecretString) -> bool {
        self.inner.ct_eq(&other.inner)
    }
}

impl Default for SecretString {
    fn default() -> Self {
        Self::new()
    }
}

/// 刻意不打印内容 —— 日志里混入 `{:?}` 是真实泄漏事件的高发来源。
impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString({} chars, REDACTED)", self.len())
    }
}

/// 刻意不打印内容。需要明文请显式调用 [`SecretString::reveal`]。
impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***REDACTED***")
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}
impl Eq for SecretString {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_holds() {
        let s = SecretString::from_utf8("db-password-123").unwrap();
        assert!(!format!("{s:?}").contains("db-password"));
        assert!(!format!("{s}").contains("db-password"));
        assert_eq!(s.reveal(), "db-password-123");
    }

    #[test]
    fn line_reader_trims_newline() {
        let data = b"hunter2\n".as_slice();
        let mut reader = std::io::BufReader::new(data);
        let s = SecretString::from_reader_line(&mut reader).unwrap();
        assert_eq!(s.reveal(), "hunter2");
    }
}
