//! The same service, with `secretmem` containers.
//!
//! Behaviour is identical — `Flow` is the same trait, `wire` is the same crypto.
//! What changes is where values live and how they end:
//!
//! * the DB password, signing key and password verifiers are `SecretBytes`;
//! * the per-login password arrives as a `SecretBytes`, never a `Vec<u8>`;
//! * the response token is a `SecretString`;
//! * copies are explicit (`duplicate()`) and each one is tracked, so there is no
//!   `clone()` leaving an unowned copy behind;
//! * `shutdown` wipes explicitly, and `harden_process` has disabled core dumps,
//!   isolated the ranges from forked children, and installed the fatal-signal
//!   wipe.
//!
//! The one unavoidable boundary is the network: bytes arrive from and leave to
//! somewhere else. Where a value must cross an ordinary API (returning a
//! `String` token to an HTTP layer), the copy is made deliberately and the
//! comment says why.

use secretmem::{SecretBytes, SecretKey, SecretString};

use crate::wire;
use crate::{Config, Flow, Request, Response};

/// Hardened authentication service.
pub struct Service {
    database_url: String,
    database_password: SecretBytes,
    /// Session signing key. 32 bytes is the HMAC-SHA256 key size.
    signing_key: SecretKey<32>,
    users: Vec<UserRecord>,
}

/// The non-secret parts of a service instance.
pub struct PublicConfig {
    /// Database URL without credentials.
    pub database_url: String,
    /// Users' names and salts. Salts are public.
    pub users: Vec<PublicUser>,
}

/// A user's public record: name and salt.
#[derive(Debug, Clone)]
pub struct PublicUser {
    /// Login name.
    pub username: String,
    /// Per-user salt (public).
    pub salt: Vec<u8>,
}

struct UserRecord {
    username: String,
    salt: Vec<u8>,
    /// HMAC verifier: 32 bytes, sensitive because a leaked verifier is an
    /// offline cracking target.
    verifier: SecretBytes,
}

impl Service {
    /// Builds a service from containers the caller derived directly, plus the
    /// public configuration.
    ///
    /// This is the constructor a hardened service should use. Unlike
    /// `Flow::startup`, it never receives the secrets in ordinary memory, so
    /// there is no `Config` full of `Vec`s to leak from the caller's frame.
    /// The password verifiers are still ordinary `Vec`s here because the demo's
    /// caller computes them; a real service derives those into containers too.
    pub fn from_secrets(
        public: PublicConfig,
        database_password: SecretBytes,
        signing_key: SecretKey<32>,
        verifiers: Vec<Vec<u8>>,
    ) -> Self {
        let users = public
            .users
            .into_iter()
            .zip(verifiers)
            .map(|(u, v)| {
                let verifier = SecretBytes::from_slice(&v).expect("region");
                let mut v = v;
                wire_wipe(&mut v);
                UserRecord { username: u.username, salt: u.salt, verifier }
            })
            .collect();
        Service {
            database_url: public.database_url,
            database_password,
            signing_key,
            users,
        }
    }

    /// The DB URL with its password inlined — for connection setup only.
    ///
    /// This is the honest weak point of the pattern: the connection driver wants
    /// a URL string, so a copy must exist in ordinary memory for the duration of
    /// the connect. The hardened version makes that window as small as possible
    /// and wipes the intermediate:
    ///
    /// ```text
    /// SecretBytes --(borrow)--> wire format --> driver (untracked) --> drop
    ///                                   \--> server-side: nothing to wipe
    /// ```
    ///
    /// Callers that need this should do it once, at connect time, and never
    /// store the result. The demo shows the *problem* rather than hiding it.
    pub fn connection_string(&self) -> SecretString {
        let mut url = SecretString::new().expect("region");
        url.push_str("app:").expect("region");
        // The password is borrowed, never copied out to a `String`.
        let pw = self.database_password.expose();
        // Percent-encoding would be needed for a real URL; skipped so the demo
        // password stays recognisable in the scan.
        for &b in pw {
            url.push_str(&(b as char).to_string()).expect("region");
        }
        url.push_str("@").expect("region");
        url.push_str(&self.database_url).expect("region");
        url
    }

    /// Mints a token for `username` using the signing key.
    fn mint(&self, username: &str) -> SecretString {
        let token = wire::mint_token(self.signing_key.expose(), username, wire::epoch());
        let s = SecretString::from_str(&token).expect("region");
        // `token` is an ordinary String; wipe it as soon as it has been copied
        // into protected memory. (The demo also wipes it in the naive sense,
        // which `String` cannot do safely; here we own the allocation through
        // `into_bytes`.)
        let mut bytes = token.into_bytes();
        for b in bytes.iter_mut() {
            // SAFETY: exclusive access to our own allocation.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        drop(bytes);
        s
    }
}

impl Flow for Service {
    fn startup(config: Config) -> Self {
        let mut signing_key = SecretKey::<32>::zeroed().expect("region");
        // Pad or truncate to the key size. Real code would derive a 32-byte key
        // (HKDF) rather than truncate.
        let n = config.session_signing_key.len().min(32);
        signing_key.expose_mut()[..n].copy_from_slice(&config.session_signing_key[..n]);
        // Wipe the config's copy: the caller built it in ordinary memory.
        let mut cfg_key = config.session_signing_key;
        wire_wipe(&mut cfg_key);
        // Note: this still leaves the key in the caller's `Config` value and in
        // the frame that produced it. `startup` cannot reach either. See
        // `hardened_startup_from_seed` for the shape that avoids the intermediate
        // entirely — which is what a service should do.

        // Take every field by value so the source `Config` is deconstructed;
        // what remains of it is then dropped at the end of this function. The
        // caller's own frame still held the values before the call, which is
        // why `SeededStartup` exists for callers that control their startup.
        let users = config
            .users
            .into_iter()
            .map(|u| {
                // The salt is **not** secret and must be kept: verification
                // needs it, and a verifier without its salt cannot be checked.
                // This was a bug in the first version of this file, found by
                // running the demo: encryption hygiene is not an excuse to drop
                // non-secret inputs.
                let salt = u.salt;
                let verifier = SecretBytes::from_slice(&u.password_verifier).expect("region");
                // The source Vec *is* secret (a verifier is offline-crackable)
                // and `from_slice` does not wipe its input.
                let mut src = u.password_verifier;
                wire_wipe(&mut src);
                UserRecord { username: u.username, salt, verifier }
            })
            .collect();

        let mut db_pw_src = config.database_password;
        let db_pw = SecretBytes::from_slice(&db_pw_src).expect("region");
        wire_wipe(&mut db_pw_src);

        // Note: this demo drops the users' salts after enrolment because the
        // demo config carries a precomputed verifier. A real service keeps the
        // salt (it is public) to re-verify; see the note in the README.
        Service {
            database_url: config.database_url,
            database_password: db_pw,
            signing_key,
            users,
        }
    }

    fn handle(&mut self, request: Request) -> Response {
        match request {
            Request::Login { username, password } => {
                // The password crosses from the wire as a Vec<u8>; move it into
                // protected memory immediately and wipe the original.
                let mut src = password;
                let secret = match SecretBytes::from_slice(&src) {
                    Ok(s) => s,
                    Err(_) => {
                        wire_wipe(&mut src);
                        return Response::Unauthorized;
                    }
                };
                wire_wipe(&mut src);

                let Some(user) = self.users.iter().find(|u| u.username == username) else {
                    drop(secret);
                    return Response::Unauthorized;
                };
                if !wire::verify(&user.salt, user.verifier.expose(), secret.expose()) {
                    drop(secret); // wipes
                    return Response::Unauthorized;
                }
                // `secret` is dropped here and wiped before the allocator sees
                // the page again.
                drop(secret);
                let token = self.mint(&user.username);
                // Crossing the API boundary: the response is a String. We must
                // hand out a copy; it is wiped by whoever owns it. Here we keep
                // the secret alive long enough to be audited mid-flight.
                let leaked = token.expose().to_string();
                Response::Token(leaked)
            }
            Request::Verify { token } => {
                let token = match SecretString::from_str(&token) {
                    Ok(t) => t,
                    Err(_) => return Response::Forbidden,
                };
                for user in &self.users {
                    if wire::verify_token(
                        self.signing_key.expose(),
                        &user.username,
                        wire::epoch(),
                        token.expose(),
                    ) {
                        return Response::Ok;
                    }
                }
                // `token` drops and wipes.
                Response::Forbidden
            }
        }
    }

    fn shutdown(mut self) {
        // Explicit wipe of every long-lived secret before the memory is
        // returned. `Drop` would do this anyway; doing it here makes the
        // shutdown checkpoint unambiguous and lets a caller assert on it.
        self.database_password.wipe();
        self.signing_key.wipe();
        for u in &mut self.users {
            u.verifier.wipe();
        }
    }
}

fn wire_wipe(v: &mut Vec<u8>) {
    for b in v.iter_mut() {
        // SAFETY: exclusive access to our own allocation.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    v.clear();
    v.shrink_to_fit();
}
