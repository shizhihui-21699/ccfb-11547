//! Protecting and verifying NTPv4 packets with NTS (RFC 8915 section 5).
//!
//! Client request (mode 3), in order:
//!
//! ```text
//!   NTP header
//!   Unique Identifier EF          authenticated, not encrypted
//!   Cookie EF                     authenticated, not encrypted
//!   Cookie Placeholder EF x N     authenticated, not encrypted
//!   Authenticator + encrypted EFs authenticator over everything above
//! ```
//!
//! Server response (mode 4):
//!
//! ```text
//!   NTP header
//!   Unique Identifier EF          echoed, authenticated
//!   Authenticator + encrypted EFs containing NTS Cookie EFs
//! ```
//!
//! The client's cookie goes on the wire in the clear: the server needs it to
//! recover its key before it can verify anything.  Cookies in the *response* are
//! encrypted, which is what keeps an observer from linking successive requests
//! to one session (RFC 8915 section 5.7).

use rand::RngCore;

use crate::aead::{Aead, AeadKey};
use crate::cookie::CookieContents;
use crate::ntp::{
    AuthField, ExtField, Packet, EF_COOKIE, EF_COOKIE_PLACEHOLDER, EF_UNIQUE_ID,
    MIN_EF_LEN, MODE_CLIENT, MODE_SERVER,
};

/// RFC 8915 section 5.3: at least 32 octets.
pub const UNIQUE_ID_LEN: usize = 32;
/// RFC 8915 section 5.7: clients should hold eight cookies.
pub const TARGET_COOKIE_STOCK: usize = 8;
/// RFC 8915 section 5.7: clients should not send more than seven placeholders.
pub const MAX_PLACEHOLDERS: usize = 7;

#[derive(Debug, thiserror::Error)]
pub enum NtsError {
    #[error("packet is not NTS protected: {0}")]
    NotProtected(&'static str),
    #[error("cookie was rejected")]
    BadCookie,
    #[error("packet authentication failed")]
    AuthFailed,
    #[error("unique identifier missing or does not match an outstanding request")]
    UniqueIdMismatch,
    #[error("malformed packet: {0}")]
    Malformed(&'static str),
    #[error("server replied with NTS NAK (NTSN): cookie no longer accepted")]
    NtsNak,
}

/// Additional Padding for the client's authenticator field (RFC 8915 §5.6).
///
/// This field exists only to bring the *nonce* region up to `min(16, N_MAX)`
/// octets, so that a client cannot make its request smaller than the response a
/// server is entitled to send.  The space for the cookies themselves is already
/// reserved by the Cookie Placeholder fields (RFC 8915 §5.5), so it must not be
/// counted again here — doing so would push the request past the 1280-octet MTU
/// that section 5.7 specifically asks implementations to stay under.
fn auth_extra_padding(algo: Aead) -> usize {
    let nonce_padded = algo.default_nonce_len().div_ceil(4) * 4;
    let n_req = std::cmp::min(16, algo.max_nonce_len()).div_ceil(4) * 4;
    n_req.saturating_sub(nonce_padded)
}

/// Build a mode-3 NTS request.
///
/// Each placeholder is sized to the cookie being sent, as RFC 8915 section 5.5
/// requires: the response is then exactly as large as the request, which is
/// what keeps NTS from being a DDoS amplifier.
pub fn build_request(
    packet: &mut Packet,
    contents: &CookieContents,
    cookie: &[u8],
    placeholders: usize,
) -> Result<(), NtsError> {
    debug_assert_eq!(packet.mode(), MODE_CLIENT);
    let algo = contents.aead;
    let key_len = algo.key_len();
    if contents.c2s_key.len() != key_len || contents.s2c_key.len() != key_len {
        return Err(NtsError::Malformed("cookie key length does not match algorithm"));
    }

    let mut uid = vec![0u8; UNIQUE_ID_LEN];
    rand::rngs::OsRng.fill_bytes(&mut uid);
    packet.push(ExtField::new(EF_UNIQUE_ID, uid));
    packet.push(ExtField::new(EF_COOKIE, cookie.to_vec()));
    for _ in 0..placeholders {
        packet.push(ExtField::new(EF_COOKIE_PLACEHOLDER, vec![0u8; cookie.len()]));
    }

    let auth_offset = packet.encoded_len();
    // `default_nonce_len` is already what each algorithm requires: 16 octets for
    // AES-SIV (>= the RFC 8915 5.6 minimum) and exactly 12 for AES-GCM-SIV.
    let mut nonce = vec![0u8; algo.default_nonce_len()];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let c2s = AeadKey::new(algo, &contents.c2s_key);
    let ad = packet.associated_data(auth_offset);
    let ciphertext = c2s
        .seal(&nonce, &ad, &[])
        .map_err(|_| NtsError::Malformed("failed to seal request"))?;

    let additional = auth_extra_padding(algo);
    let mut auth = AuthField { nonce, ciphertext }.encode(additional);
    // RFC 7822 requires at least 16 octets; the authenticator always is, but
    // pad defensively rather than emitting an illegal field.
    if auth.body.len() + 4 < MIN_EF_LEN {
        let pad = MIN_EF_LEN - 4 - auth.body.len();
        auth.body.resize(auth.body.len() + pad, 0);
    }
    packet.push(auth);
    Ok(())
}

/// What a verified request tells the server.
pub struct VerifiedRequest {
    pub unique_id: Vec<u8>,
    pub contents: CookieContents,
    /// The cookie exactly as received, so it can be echoed into the response.
    pub cookie: Vec<u8>,
    /// Number of valid cookie placeholders, capped per RFC 8915 section 5.7.
    pub placeholder_count: usize,
    /// The client's transmit timestamp, echoed as the response's origin.
    pub client_transmit_ts: u64,
}

/// Verify a mode-3 request.  `ring` supplies the cookie keys.
pub fn verify_request(
    packet: &Packet,
    cookie_key_ring: &crate::cookie::KeyRing,
) -> Result<VerifiedRequest, NtsError> {
    if packet.mode() != MODE_CLIENT {
        return Err(NtsError::NotProtected("mode is not client"));
    }
    let auth_index = packet
        .auth_index()
        .ok_or(NtsError::NotProtected("no authenticator"))?;
    if auth_index != packet.efs.len() - 1 {
        return Err(NtsError::Malformed(
            "authenticator is not the last extension field",
        ));
    }

    let uid = packet
        .find(EF_UNIQUE_ID)
        .ok_or(NtsError::NotProtected("no unique identifier"))?;
    if uid.body.len() < UNIQUE_ID_LEN {
        return Err(NtsError::Malformed("unique identifier too short"));
    }
    if packet.find_all(EF_UNIQUE_ID).count() != 1 {
        return Err(NtsError::Malformed("more than one unique identifier field"));
    }

    let cookie_ef = packet
        .find(EF_COOKIE)
        .ok_or(NtsError::NotProtected("no cookie"))?;
    // Exactly one cookie field in a request (RFC 8915 section 5.7).
    if packet.find_all(EF_COOKIE).count() != 1 {
        return Err(NtsError::Malformed("more than one cookie field"));
    }
    let cookie = cookie_ef.body.clone();

    // Every placeholder must match the cookie's body length; a mismatch is what
    // would otherwise let a request be smaller than its response.
    let placeholders = packet.find_all(EF_COOKIE_PLACEHOLDER).collect::<Vec<_>>();
    for ph in &placeholders {
        if ph.body.len() != cookie.len() {
            return Err(NtsError::Malformed(
                "placeholder length differs from cookie length",
            ));
        }
    }

    // Cookies must be authenticated but never encrypted on the way in; the
    // cookie field is checked here by looking only outside the authenticator,
    // which the loop above does implicitly by scanning all EFs.  Anything after
    // the authenticator cannot carry a cookie (the authenticator is last).
    let contents = cookie_key_ring
        .open(&cookie)
        .map_err(|_| NtsError::BadCookie)?;
    let algo = contents.aead;

    // The authenticator's padding rules depend on the algorithm's N_MAX, which
    // is only known once the cookie has been opened, so parse it here.
    let auth = AuthField::parse(&packet.efs[auth_index].body, algo.max_nonce_len(), algo.tag_len())
        .ok_or(NtsError::Malformed("authenticator field is malformed"))?;
    let c2s = AeadKey::new(algo, &contents.c2s_key);
    let ad = packet.associated_data(packet.ef_offset(auth_index));
    c2s.open(&auth.nonce, &ad, &auth.ciphertext)
        .map_err(|_| NtsError::AuthFailed)?;

    Ok(VerifiedRequest {
        unique_id: uid.body.clone(),
        contents,
        cookie,
        placeholder_count: placeholders.len().min(MAX_PLACEHOLDERS),
        client_transmit_ts: packet.transmit_ts(),
    })
}

/// Build a mode-4 response to a verified request.
///
/// `fresh_cookies` are the cookies to hand back, already minted so that exactly
/// one plus the number of placeholders are returned (RFC 8915 section 5.7).
///
/// The response's receive and transmit timestamps must already be set by the
/// caller.  This function sets the origin timestamp (it has to echo the
/// client's transmit timestamp) and then authenticates, so **no header field
/// may be modified after this returns** — the authenticator covers the header.
pub fn build_response(
    request: &VerifiedRequest,
    response: &mut Packet,
    fresh_cookies: &[Vec<u8>],
) -> Result<(), NtsError> {
    let algo = request.contents.aead;
    response.set_mode(MODE_SERVER);
    response.set_origin_ts(request.client_transmit_ts);
    response.push(ExtField::new(EF_UNIQUE_ID, request.unique_id.clone()));

    // Cookies go inside the authenticator, so they are encrypted.
    let mut plaintext = Vec::new();
    for c in fresh_cookies {
        // Encrypted extension fields must be a multiple of 4 octets.  The
        // cookie format must already satisfy this: silently padding here would
        // hand the client a cookie that no longer decrypts, and the failure
        // would surface much later as an unexplained NTS NAK.
        if (c.len() + 4) % 4 != 0 {
            return Err(NtsError::Malformed(
                "cookie length is not a multiple of 4; cannot encode as an extension field",
            ));
        }
        ExtField::new(EF_COOKIE, c.clone()).encode_into(&mut plaintext);
    }

    let auth_offset = response.encoded_len();
    let mut nonce = vec![0u8; algo.default_nonce_len()];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let s2c = AeadKey::new(algo, &request.contents.s2c_key);
    let ad = response.associated_data(auth_offset);
    let ciphertext = s2c
        .seal(&nonce, &ad, &plaintext)
        .map_err(|_| NtsError::Malformed("failed to seal response"))?;

    let mut auth = AuthField { nonce, ciphertext }.encode(0);
    if auth.body.len() + 4 < MIN_EF_LEN {
        let pad = MIN_EF_LEN - 4 - auth.body.len();
        auth.body.resize(auth.body.len() + pad, 0);
    }
    response.push(auth);
    Ok(())
}

/// A verified server response.
pub struct VerifiedResponse {
    pub cookies: Vec<Vec<u8>>,
}

/// Verify a mode-4 response against the outstanding request.
pub fn verify_response(
    response: &Packet,
    contents: &CookieContents,
    expected_unique_id: &[u8],
) -> Result<VerifiedResponse, NtsError> {
    // A Kiss-o'-Death is legitimately unauthenticated, but must still echo the
    // unique identifier if we ever had an authenticated exchange (RFC 8915
    // section 5.7).  Report it as such so the caller can re-run NTS-KE.
    if response.stratum() == 0 && response.reference_id() == crate::ntp::KOD_NTSN {
        if response
            .find(EF_UNIQUE_ID)
            .map(|e| e.body == expected_unique_id)
            .unwrap_or(false)
        {
            return Err(NtsError::NtsNak);
        }
        return Err(NtsError::UniqueIdMismatch);
    }

    if response.mode() != MODE_SERVER {
        return Err(NtsError::NotProtected("mode is not server"));
    }
    let auth_index = response
        .auth_index()
        .ok_or(NtsError::NotProtected("no authenticator"))?;
    if auth_index != response.efs.len() - 1 {
        return Err(NtsError::Malformed(
            "authenticator is not the last extension field",
        ));
    }
    let uid = response
        .find(EF_UNIQUE_ID)
        .ok_or(NtsError::UniqueIdMismatch)?;
    if uid.body != expected_unique_id {
        return Err(NtsError::UniqueIdMismatch);
    }
    // An unencrypted cookie in a response would defeat unlinkability.
    if response.find(EF_COOKIE).is_some() {
        return Err(NtsError::Malformed("cookie field outside authenticator"));
    }

    let algo = contents.aead;
    let auth = AuthField::parse(
        &response.efs[auth_index].body,
        algo.max_nonce_len(),
        algo.tag_len(),
    )
    .ok_or(NtsError::Malformed("authenticator field is malformed"))?;
    let s2c = AeadKey::new(algo, &contents.s2c_key);
    let ad = response.associated_data(response.ef_offset(auth_index));
    let mut plaintext = s2c
        .open(&auth.nonce, &ad, &auth.ciphertext)
        .map_err(|_| NtsError::AuthFailed)?;

    // Decrypt-then-parse the encrypted extension fields.  They are parsable as
    // ordinary EFs except that they may be shorter than RFC 7822's 16 octets.
    let mut cookies = Vec::new();
    let mut off = 0;
    while off < plaintext.len() {
        if plaintext.len() - off < 4 {
            return Err(NtsError::Malformed("truncated encrypted extension field"));
        }
        let typ = u16::from_be_bytes([plaintext[off], plaintext[off + 1]]);
        let len = u16::from_be_bytes([plaintext[off + 2], plaintext[off + 3]]) as usize;
        if len < 4 || len % 4 != 0 || off + len > plaintext.len() {
            return Err(NtsError::Malformed("bad encrypted extension field length"));
        }
        if typ == EF_COOKIE {
            cookies.push(plaintext[off + 4..off + len].to_vec());
        }
        off += len;
    }
    zeroize(&mut plaintext);

    Ok(VerifiedResponse { cookies })
}

fn zeroize(v: &mut Vec<u8>) {
    use zeroize::Zeroize;
    v.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cookie::KeyRing;
    use crate::ntp::MODE_CLIENT;

    fn setup(aead: Aead) -> (KeyRing, CookieContents, Vec<u8>) {
        let ring = KeyRing::generate(2);
        let n = aead.key_len();
        let contents = CookieContents {
            aead,
            c2s_key: vec![0x33; n],
            s2c_key: vec![0x44; n],
        };
        let cookie = ring.mint(&contents);
        (ring, contents, cookie)
    }

    fn client_request(contents: &CookieContents, cookie: &[u8], placeholders: usize) -> (Packet, Vec<u8>) {
        let mut p = Packet::new();
        p.set_transmit_ts(crate::ntp::ntp_now());
        build_request(&mut p, contents, cookie, placeholders).unwrap();
        let uid = p.find(EF_UNIQUE_ID).unwrap().body.clone();
        (p, uid)
    }

    #[test]
    fn full_volley_both_algorithms() {
        for aead in [Aead::AesSivCmac256, Aead::Aes128GcmSiv] {
            let (ring, contents, cookie) = setup(aead);
            let (req, uid) = client_request(&contents, &cookie, 7);
            let encoded = req.encode();
            let parsed = Packet::parse(&encoded).unwrap();
            let verified = verify_request(&parsed, &ring).unwrap();
            assert_eq!(verified.unique_id, uid);
            assert_eq!(verified.placeholder_count, 7);

            let fresh: Vec<Vec<u8>> = (0..8).map(|i| ring.mint(&CookieContents {
                aead,
                c2s_key: vec![i as u8; aead.key_len()],
                s2c_key: vec![i as u8; aead.key_len()],
            })).collect();

            let mut resp = Packet::new();
            build_response(&verified, &mut resp, &fresh).unwrap();

            let resp_parsed = Packet::parse(&resp.encode()).unwrap();
            let out = verify_response(&resp_parsed, &contents, &uid)
                .unwrap_or_else(|e| panic!("{aead:?} verify_response: {e}"));
            assert_eq!(out.cookies.len(), 8);
            // Responses must not be larger than requests (RFC 8915 section 8.4).
            assert!(
                resp_parsed.encode().len() <= parsed.encode().len(),
                "{aead:?}: response {} > request {}",
                resp_parsed.encode().len(),
                parsed.encode().len()
            );
        }
    }

    #[test]
    fn tampered_request_fails_authentication() {
        let (ring, contents, cookie) = setup(Aead::AesSivCmac256);
        let (req, _) = client_request(&contents, &cookie, 1);
        let mut raw = req.encode();
        // Flip a bit in the transmit timestamp: it is part of the AD.
        raw[40] ^= 0x01;
        let parsed = Packet::parse(&raw).unwrap();
        assert!(matches!(
            verify_request(&parsed, &ring),
            Err(NtsError::AuthFailed)
        ));
    }

    #[test]
    fn unknown_cookie_is_rejected() {
        let (ring, contents, _) = setup(Aead::AesSivCmac256);
        let bogus = vec![0u8; crate::cookie::cookie_len(Aead::AesSivCmac256)];
        let (req, _) = client_request(&contents, &bogus, 0);
        assert!(matches!(
            verify_request(&req, &ring),
            Err(NtsError::BadCookie)
        ));
    }

    #[test]
    fn response_with_wrong_unique_id_is_rejected() {
        let (ring, contents, cookie) = setup(Aead::AesSivCmac256);
        let (req, uid) = client_request(&contents, &cookie, 0);
        let verified = verify_request(&req, &ring).unwrap();
        let mut resp = Packet::new();
        build_response(&verified, &mut resp, &[ring.mint(&contents)]).unwrap();
        let parsed = Packet::parse(&resp.encode()).unwrap();

        let mut wrong = uid.clone();
        wrong[0] ^= 0xff;
        assert!(matches!(
            verify_response(&parsed, &contents, &wrong),
            Err(NtsError::UniqueIdMismatch)
        ));
        assert!(verify_response(&parsed, &contents, &uid).is_ok());
    }

    #[test]
    fn unencrypted_cookie_in_response_is_rejected() {
        let (ring, contents, cookie) = setup(Aead::AesSivCmac256);
        let (req, uid) = client_request(&contents, &cookie, 0);
        let verified = verify_request(&req, &ring).unwrap();

        let mut resp = Packet::new();
        build_response(&verified, &mut resp, &[ring.mint(&contents)]).unwrap();
        // Splice a plaintext cookie EF in before the authenticator.
        let auth = resp.efs.pop().unwrap();
        resp.push(ExtField::new(EF_COOKIE, cookie.clone()));
        resp.push(auth);
        let parsed = Packet::parse(&resp.encode()).unwrap();
        assert!(matches!(
            verify_response(&parsed, &contents, &uid),
            Err(NtsError::Malformed("cookie field outside authenticator"))
        ));
    }

    #[test]
    fn placeholder_length_mismatch_is_rejected() {
        let (ring, contents, cookie) = setup(Aead::AesSivCmac256);
        let mut p = Packet::new();
        p.set_transmit_ts(crate::ntp::ntp_now());
        build_request(&mut p, &contents, &cookie, 2).unwrap();
        // Corrupt one placeholder's length.
        for ef in p.efs.iter_mut() {
            if ef.typ == EF_COOKIE_PLACEHOLDER {
                ef.body.pop();
                break;
            }
        }
        assert!(matches!(
            verify_request(&p, &ring),
            Err(NtsError::Malformed(_))
        ));
    }

    #[test]
    fn plain_ntp_packet_is_rejected() {
        let mut p = Packet::new();
        p.set_mode(MODE_CLIENT);
        let ring = KeyRing::generate(1);
        assert!(matches!(
            verify_request(&p, &ring),
            Err(NtsError::NotProtected(_))
        ));
    }

    #[test]
    fn nts_nak_is_reported() {
        let contents = CookieContents {
            aead: Aead::AesSivCmac256,
            c2s_key: vec![0; 32],
            s2c_key: vec![0; 32],
        };
        let uid = vec![9u8; 32];
        let mut p = Packet::new();
        p.set_mode(MODE_SERVER);
        p.set_stratum(0);
        p.set_reference_id(crate::ntp::KOD_NTSN);
        p.push(ExtField::new(EF_UNIQUE_ID, uid.clone()));
        assert!(matches!(
            verify_response(&p, &contents, &uid),
            Err(NtsError::NtsNak)
        ));
    }

    /// RFC 8915 section 5.7 asks implementations to keep a request with a
    /// cookie and seven placeholders below the 1280-octet IPv6 minimum MTU.
    #[test]
    fn request_with_max_placeholders_fits_the_mtu() {
        for aead in [Aead::AesSivCmac256, Aead::Aes128GcmSiv] {
            let (_ring, contents, cookie) = setup(aead);
            let mut p = Packet::new();
            p.set_transmit_ts(crate::ntp::ntp_now());
            build_request(&mut p, &contents, &cookie, MAX_PLACEHOLDERS).unwrap();
            let len = p.encode().len();
            assert!(
                len <= 1280,
                "{aead:?}: {len} octets with {MAX_PLACEHOLDERS} placeholders exceeds the MTU"
            );
        }
    }

    #[test]
    fn nonce_lengths_are_sane_per_algorithm() {
        // GCM-SIV must emit a 12-octet nonce even though MIN_NONCE_LEN is 16.
        let (ring, contents, cookie) = setup(Aead::Aes128GcmSiv);
        let (req, _) = client_request(&contents, &cookie, 0);
        let idx = req.auth_index().unwrap();
        let auth = AuthField::parse(
            &req.efs[idx].body,
            Aead::Aes128GcmSiv.max_nonce_len(),
            Aead::Aes128GcmSiv.tag_len(),
        )
        .unwrap();
        assert_eq!(auth.nonce.len(), 12);
        assert!(verify_request(&req, &ring).is_ok());
    }
}
