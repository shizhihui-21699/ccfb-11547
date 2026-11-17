use std::fmt;

/// Errors produced by the protocol core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed NTP packet: {0}")]
    Ntp(String),
    #[error("malformed NTS-KE message: {0}")]
    Ke(String),
    #[error("NTS-KE server returned error code {0}")]
    KeError(u16),
    #[error("NTS-KE server returned warning code {0}")]
    KeWarning(u16),
    #[error("AEAD failure: {0}")]
    Aead(#[from] AeadError),
    #[error("NTS NAK: server rejected our cookie")]
    NtsNak,
    #[error("unknown AEAD algorithm identifier {0}")]
    UnknownAead(u16),
    #[error("cookie rejected: {0}")]
    Cookie(String),
    #[error("key material error: {0}")]
    KeyMaterial(String),
    #[error("packet rejected: {0}")]
    Rejected(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// AEAD failures, kept separate so callers can distinguish "forged packet"
/// from "unparsable packet".
#[derive(Debug)]
pub struct AeadError(pub &'static str);

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for AeadError {}
