use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("TLS library error: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("NTS-KE protocol error: {0}")]
    KeProtocol(String),

    #[error("NTS-KE server returned error code {code}: {message}")]
    KeServerError { code: u16, message: String },

    #[error("NTP protocol error: {0}")]
    NtpProtocol(String),

    #[error("AEAD seal/open failure: {0}")]
    Aead(String),

    #[error("unsupported AEAD algorithm id {0}")]
    UnsupportedAead(u16),

    #[error("cookie error: {0}")]
    Cookie(String),

    #[error("no cookies left; a new NTS-KE exchange is required")]
    NoCookies,

    #[error("clock error: {0}")]
    Clock(String),

    #[error("key store error: {0}")]
    KeyStore(String),

    #[error("response failed authentication: {0}")]
    AuthFailed(String),

    #[error("packet too short: have {got} bytes, need {need}")]
    TooShort { got: usize, need: usize },
}

impl Error {
    pub fn ke(msg: impl Into<String>) -> Self {
        Error::KeProtocol(msg.into())
    }
    pub fn ntp(msg: impl Into<String>) -> Self {
        Error::NtpProtocol(msg.into())
    }
    pub fn aead(msg: impl Into<String>) -> Self {
        Error::Aead(msg.into())
    }
    pub fn cookie(msg: impl Into<String>) -> Self {
        Error::Cookie(msg.into())
    }
}
