//! Core wire-format, AEAD and cookie primitives for NTS (RFC 8915).
//!
//! This crate contains no I/O: it is shared by the client, the server and the
//! benchmark harness so that all three agree byte-for-byte on the protocol.

pub mod aead;
pub mod auth;
pub mod cookie;
pub mod error;
pub mod ke;
pub mod keyring;
pub mod ntp;

pub use aead::AeadAlg;
pub use error::{AeadError, Error, Result};
pub use ke::{Record, RecordType};
