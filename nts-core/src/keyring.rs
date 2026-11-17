//! Client-side cookie pool and server-side key material.
//!
//! RFC 8915 §5.7 asks a client to keep roughly eight unused cookies so that
//! lost packets do not force an NTS-KE round trip, and to prefer not reusing a
//! cookie. This module implements that policy:
//!
//! * cookies are handed out one at a time, oldest first;
//! * a consumed cookie is dropped rather than recycled, so capture of a request
//!   does not let an observer link later requests;
//! * when the pool runs dry the client must re-run NTS-KE, which the client
//!   crate does.

use std::collections::VecDeque;
use zeroize::Zeroizing;

use crate::aead::AeadAlg;
use crate::cookie::Cookie;

/// Target pool size (RFC 8915 §5.7: "eight unused cookies").
pub const TARGET_POOL: usize = 8;

/// Maximum cookies we will send placeholders for in one request
/// (RFC 8915 §5.7: "SHOULD NOT include more than seven").
pub const MAX_PLACEHOLDERS: usize = 7;

/// Key material negotiated in one NTS-KE exchange.
#[derive(Clone)]
pub struct AssociationKeys {
    pub alg: AeadAlg,
    pub c2s: Zeroizing<Vec<u8>>,
    pub s2c: Zeroizing<Vec<u8>>,
}

impl AssociationKeys {
    pub fn new(alg: AeadAlg, c2s: Vec<u8>, s2c: Vec<u8>) -> Self {
        Self {
            alg,
            c2s: Zeroizing::new(c2s),
            s2c: Zeroizing::new(s2c),
        }
    }
}

/// Client-side association state: negotiated keys plus a pool of cookies.
pub struct Association {
    pub keys: AssociationKeys,
    pub cookie_len: usize,
    cookies: VecDeque<Cookie>,
}

impl Association {
    pub fn new(keys: AssociationKeys, cookies: Vec<Cookie>) -> Self {
        let cookie_len = cookies.first().map(|c| c.len()).unwrap_or(0);
        Self {
            keys,
            cookie_len,
            cookies: cookies.into(),
        }
    }

    pub fn cookie_count(&self) -> usize {
        self.cookies.len()
    }

    /// Take the next cookie to spend on a request. Returns `None` when the pool
    /// is empty, which means the caller must re-run NTS-KE.
    pub fn take_cookie(&mut self) -> Option<Cookie> {
        self.cookies.pop_front()
    }

    /// Number of Cookie Placeholder EFs to ask for, so the pool returns to
    /// `TARGET_POOL` after this exchange (one fresh cookie arrives per
    /// placeholder plus one for the one we are spending).
    pub fn placeholders_for(&self) -> usize {
        let wanted = TARGET_POOL.saturating_sub(self.cookies.len() + 1);
        wanted.min(MAX_PLACEHOLDERS)
    }

    /// Absorb cookies returned by the server. Rejects a cookie whose length
    /// disagrees with the pool, because the response would then not fit the
    /// no-amplification rule and something is wrong with the peer.
    pub fn absorb_cookies(&mut self, cookies: Vec<Cookie>) {
        for c in cookies {
            if self.cookie_len == 0 {
                self.cookie_len = c.len();
            }
            if c.len() != self.cookie_len {
                tracing::debug!(got = c.len(), want = self.cookie_len, "ignoring odd-length cookie");
                continue;
            }
            if self.cookies.len() >= TARGET_POOL {
                continue;
            }
            self.cookies.push_back(c);
        }
    }
}

/// Server-side per-request key material recovered from a cookie.
#[derive(Clone)]
pub struct RecoveredKeys {
    pub alg: AeadAlg,
    pub c2s: Zeroizing<Vec<u8>>,
    pub s2c: Zeroizing<Vec<u8>>,
}

impl RecoveredKeys {
    pub fn new(alg: AeadAlg, c2s: Zeroizing<Vec<u8>>, s2c: Zeroizing<Vec<u8>>) -> Self {
        Self { alg, c2s, s2c }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assoc(n: usize) -> Association {
        let keys = AssociationKeys::new(AeadAlg::AesSivCmac256, vec![1; 32], vec![2; 32]);
        Association::new(keys, (0..n).map(|i| vec![i as u8; 96]).collect())
    }

    #[test]
    fn cookies_are_consumed_not_reused() {
        let mut a = assoc(3);
        assert_eq!(a.take_cookie().unwrap()[0], 0);
        assert_eq!(a.take_cookie().unwrap()[0], 1);
        assert_eq!(a.take_cookie().unwrap()[0], 2);
        assert!(a.take_cookie().is_none());
        assert_eq!(a.cookie_count(), 0);
    }

    #[test]
    fn placeholder_count_refills_pool() {
        // Spending one of eight leaves seven; one placeholder brings us back.
        assert_eq!(assoc(8).placeholders_for(), 0);
        assert_eq!(assoc(7).placeholders_for(), 0);
        assert_eq!(assoc(6).placeholders_for(), 1);
        assert_eq!(assoc(1).placeholders_for(), 6);
        assert_eq!(assoc(0).placeholders_for(), MAX_PLACEHOLDERS);
    }

    #[test]
    fn pool_is_capped_at_target() {
        let mut a = assoc(0);
        a.absorb_cookies((0..20).map(|_| vec![9; 96]).collect());
        assert_eq!(a.cookie_count(), TARGET_POOL);
    }

    #[test]
    fn mixed_length_cookies_are_dropped() {
        let mut a = assoc(0);
        a.absorb_cookies(vec![vec![1; 96], vec![2; 80], vec![3; 96]]);
        assert_eq!(a.cookie_count(), 2);
        assert_eq!(a.cookie_len, 96);
    }
}
