//! A small authentication service, in two implementations.
//!
//! The service does what a real one does:
//!
//! 1. holds a database password and a session-signing key from startup,
//! 2. accepts a login (username + password), verifies it against a stored
//!    password hash,
//! 3. on success mints a session token signed with the key,
//! 4. verifies subsequent requests with that token.
//!
//! The only difference between the two implementations is *where the sensitive
//! values live*. Everything else — the request flow, the crypto, the response
//! shape — is identical, so the memory evidence differs only because of the
//! containers.
//!
//! * [`naive`] uses `String`/`Vec<u8>`, which is what the service looked like
//!   when a memory dump turned up the DB password and session keys.
//! * [`hardened`] uses `secretmem` containers.
//!
//! Both are driven by the same [`Flow`], so `cargo run -- compare` can run them
//! back to back in separate processes and print the difference.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod hardened;
pub mod naive;
pub mod wire;

use std::fmt;

/// Which implementation a request should be served by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Ordinary `String`/`Vec<u8>` storage.
    Naive,
    /// `secretmem` containers.
    Hardened,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Naive => "naive",
            Mode::Hardened => "hardened",
        })
    }
}

impl std::str::FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "naive" => Ok(Mode::Naive),
            "hardened" => Ok(Mode::Hardened),
            other => Err(format!("unknown mode {other:?}; expected naive|hardened")),
        }
    }
}

/// A stage of the request lifecycle at which memory can be inspected.
///
/// These are the checkpoints the auditor captures. The names are stable because
/// they appear in report files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Stage {
    /// Configuration has been loaded; long-lived secrets exist.
    Loaded,
    /// A login request is in flight (password materialised).
    LoginInFlight,
    /// The login finished and its transient material should be gone.
    LoginSettled,
    /// A token was verified and the per-request material should be gone.
    TokenVerified,
    /// The service is shutting down; long-lived secrets should be gone.
    Shutdown,
    /// The process died without unwinding (only reachable in a crash run).
    Crashed,
}

impl Stage {
    /// Every stage, in lifecycle order.
    pub const ALL: [Stage; 6] = [
        Stage::Loaded,
        Stage::LoginInFlight,
        Stage::LoginSettled,
        Stage::TokenVerified,
        Stage::Shutdown,
        Stage::Crashed,
    ];

    /// Stable lowercase name for reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Loaded => "loaded",
            Stage::LoginInFlight => "login-in-flight",
            Stage::LoginSettled => "login-settled",
            Stage::TokenVerified => "token-verified",
            Stage::Shutdown => "shutdown",
            Stage::Crashed => "crashed",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The credentials and keys a service instance is built with.
///
/// In a real service these come from a secret manager or the environment. Here
/// they are constructor arguments so the demo can supply known values and the
/// auditor can search for them.
#[derive(Debug, Clone)]
pub struct Config {
    /// Name of the database the service connects to (not sensitive).
    pub database_url: String,
    /// Password part of the database URL (sensitive).
    pub database_password: Vec<u8>,
    /// Key used to sign session tokens (sensitive).
    pub session_signing_key: Vec<u8>,
    /// Users and their password hashes (sensitive: hashes are offline-crackable).
    pub users: Vec<UserRecord>,
}

/// One user, with a password hash.
#[derive(Debug, Clone)]
pub struct UserRecord {
    /// Login name (not sensitive).
    pub username: String,
    /// Salt for the password hash.
    pub salt: Vec<u8>,
    /// HMAC-SHA256(salt, password), the "stored" verifier.
    pub password_verifier: Vec<u8>,
}

/// A request the service can serve.
#[derive(Debug, Clone)]
pub enum Request {
    /// Authenticate and mint a token.
    Login {
        /// Login name.
        username: String,
        /// Password, as it arrived over the wire.
        password: Vec<u8>,
    },
    /// Verify a bearer token.
    Verify {
        /// Token from the `Authorization` header.
        token: String,
    },
}

/// A response the service can return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// Login succeeded.
    Token(String),
    /// Login failed. Deliberately does not say whether the user exists.
    Unauthorized,
    /// Token is valid.
    Ok,
    /// Token is invalid or forged.
    Forbidden,
}

/// The lifecycle both implementations share.
///
/// Written once, against a set of ops, so the naive and hardened services
/// cannot accidentally diverge in behaviour — only in storage.
pub trait Flow {
    /// Loads configuration and prepares long-lived secrets.
    fn startup(config: Config) -> Self;
    /// Serves one request.
    fn handle(&mut self, request: Request) -> Response;
    /// Releases long-lived secrets at shutdown.
    fn shutdown(self);
}
