//! Network Time Security (RFC 8915) — client and server implementation in Rust.
//!
//! Two protocols make up NTS:
//!   * NTS-KE (key establishment) runs over TLS 1.3 on TCP port 4460 (section 4)
//!   * NTS-protected NTP (section 5) exchanges NTPv4 packets over UDP with
//!     AEAD-authenticated extension fields.
//!
//! AEAD algorithms supported (RFC 8915 section 5.1, both are MUST-implement):
//!   * id 15: AEAD_AES_SIV_CMAC_256 (RFC 5297)
//!   * id 16: AEAD_AES_128_GCM      (RFC 5116)

pub mod aead;
pub mod cert;
pub mod constants;
pub mod cookie;
pub mod error;
pub mod ke;
pub mod ke_client;
pub mod ke_server;
pub mod keyderive;
pub mod ntp;
pub mod ntp_client;
pub mod ntp_server;
pub mod stats;
pub mod time_util;

pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
