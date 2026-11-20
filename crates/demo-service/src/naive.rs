//! The service as it was when the dump leaked: ordinary `String`/`Vec<u8>`.
//!
//! Nothing here is especially careless. It is what a reasonable implementation
//! looks like when nobody has thought about memory lifetime:
//!
//! * the DB password and signing key live in `Vec<u8>` for the process lifetime;
//! * each login's password arrives in a `Vec<u8>`, is used, and is dropped —
//!   which frees it *without* clearing it;
//! * the token is a `String` that is cloned into the response;
//! * `format!` and `to_vec()` make copies along the way.
//!
//! Every one of those is a place the plaintext can be read after the code that
//! used it has finished. This is the baseline the hardened version is measured
//! against.

use crate::wire;
use crate::{Config, Flow, Request, Response};

/// Ordinary-storage authentication service.
pub struct Service {
    database_url: String,
    database_password: Vec<u8>,
    signing_key: Vec<u8>,
    users: Vec<UserRecord>,
}

struct UserRecord {
    username: String,
    salt: Vec<u8>,
    verifier: Vec<u8>,
}

impl Service {
    /// The DB URL with its password inlined, as a logging library or a
    /// connection-pool error message might render it.
    pub fn connection_string(&self) -> String {
        format!(
            "{}:{}@{}",
            "app",
            String::from_utf8_lossy(&self.database_password),
            self.database_url
        )
    }

    /// The signing key as regular bytes, for anything that needs it.
    pub fn signing_key(&self) -> &[u8] {
        &self.signing_key
    }
}

impl Flow for Service {
    fn startup(config: Config) -> Self {
        Service {
            database_url: config.database_url,
            database_password: config.database_password,
            signing_key: config.session_signing_key,
            users: config
                .users
                .into_iter()
                .map(|u| UserRecord {
                    username: u.username,
                    salt: u.salt,
                    verifier: u.password_verifier,
                })
                .collect(),
        }
    }

    fn handle(&mut self, request: Request) -> Response {
        match request {
            Request::Login { username, password } => {
                let Some(user) = self.users.iter().find(|u| u.username == username) else {
                    // Still drop the password; the free does not clear it.
                    drop(password);
                    return Response::Unauthorized;
                };
                if !wire::verify(&user.salt, &user.verifier, &password) {
                    drop(password);
                    return Response::Unauthorized;
                }
                // `password` is dropped here. Its bytes stay in the allocator.
                let token = wire::mint_token(&self.signing_key, &user.username, wire::epoch());
                // A copy for the response, and the original dropped.
                let response_token = token.clone();
                drop(token);
                Response::Token(response_token)
            }
            Request::Verify { token } => {
                // Verification re-mints, creating another copy of the token.
                for user in &self.users {
                    if wire::verify_token(&self.signing_key, &user.username, wire::epoch(), &token)
                    {
                        return Response::Ok;
                    }
                }
                Response::Forbidden
            }
        }
    }

    fn shutdown(self) {
        // Dropping the fields frees them without clearing. The process may keep
        // running, or exit; either way the bytes stayed until the allocator
        // reused the pages.
        drop(self);
    }
}
