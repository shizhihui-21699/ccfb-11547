//! The cryptographic operations, written once so both implementations use
//! identical logic and differ only in storage.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Salt and verifier for a password.
pub struct Enrolled {
    /// Random salt.
    pub salt: [u8; 16],
    /// HMAC-SHA256(salt, password).
    pub verifier: [u8; 32],
}

/// Enrols a password: draws a fresh salt and computes the verifier.
///
/// This is a demonstration KDF, not a production one: a real service uses
/// Argon2id or scrypt with a memory/time cost. The point of the demo is the
/// lifetime of the plaintext, not the strength of the hash.
pub fn enrol(password: &[u8]) -> Enrolled {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).expect("OS CSPRNG");
    let verifier = verify_with_salt(&salt, password);
    Enrolled { salt, verifier }
}

fn verify_with_salt(salt: &[u8], password: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt).expect("any key length");
    mac.update(password);
    mac.finalize().into_bytes().into()
}

/// Checks a password against a stored salt+verifier in constant time.
pub fn verify(salt: &[u8], expected: &[u8], password: &[u8]) -> bool {
    let got = verify_with_salt(salt, password);
    // Length is fixed at 32 for both sides of a real record; guard anyway.
    got.ct_eq(expected).into()
}

/// Mints a session token: `hex(hmac(signing_key, username || issue_epoch))`.
///
/// A real token also carries an expiry and is base64url; the shape does not
/// affect what the memory audit sees.
pub fn mint_token(signing_key: &[u8], username: &str, issue: u64) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(signing_key).expect("any key length");
    mac.update(username.as_bytes());
    mac.update(&issue.to_be_bytes());
    hex(&mac.finalize().into_bytes())
}

/// Whether `token` is the token this key would mint for `username` now.
pub fn verify_token(signing_key: &[u8], username: &str, issue: u64, token: &str) -> bool {
    let expected = mint_token(signing_key, username, issue);
    expected.as_bytes().ct_eq(token.as_bytes()).into()
}

/// A stable "current epoch" for the demo. It is fixed so a token minted during
/// the login stage still verifies during the token stage.
pub fn epoch() -> u64 {
    1_700_000_000
}

/// Lowercase hex, without allocating through `format!` (which would create an
/// untracked copy in the naive path).
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// SHA-256 of a byte slice.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrol_and_verify() {
        let e = enrol(b"hunter2");
        assert!(verify(&e.salt, &e.verifier, b"hunter2"));
        assert!(!verify(&e.salt, &e.verifier, b"hunter3"));
    }

    #[test]
    fn tokens_are_key_and_name_bound() {
        let key = b"signing-key-material-0000000000";
        let t = mint_token(key, "alice", epoch());
        assert!(verify_token(key, "alice", epoch(), &t));
        assert!(!verify_token(key, "bob", epoch(), &t));
        assert!(!verify_token(b"other-key-material-0000000000", "alice", epoch(), &t));
    }
}
