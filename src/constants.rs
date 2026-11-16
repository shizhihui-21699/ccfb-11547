//! Wire constants from RFC 8915 (NTS) and the NTP extension field registries.

// ---- AEAD algorithm identifiers (RFC 8915 §5.1, IANA "AEAD Algorithms" registry) ----
/// AEAD_AES_SIV_CMAC_256 — RFC 5297. Mandatory in RFC 8915.
pub const AEAD_AES_SIV_CMAC_256: u16 = 15;
/// AEAD_AES_128_GCM — RFC 5116. Mandatory in RFC 8915.
pub const AEAD_AES_128_GCM: u16 = 16;

/// Algorithms this implementation can negotiate, in preference order.
pub const SUPPORTED_AEAD_IDS: [u16; 2] = [AEAD_AES_128_GCM, AEAD_AES_SIV_CMAC_256];

// ---- NTS-KE record types (RFC 8915 §4.1, Table in §4). Values are the
// base Record Type; the 0x8000 Critical Bit is OR-ed in on the wire. ----
/// All record types below 0x8000 are "critical": an implementation that does
/// not understand a critical record MUST abort the handshake.
pub const KE_RECORD_CRITICAL_BIT: u16 = 0x8000;

/// End of Message (§4.1.1), record type 0.
pub const KE_RECORD_END_OF_MESSAGE: u16 = 0x0000;
/// NTS Next Protocol Negotiation (§4.1.2), record type 1.
pub const KE_RECORD_NEXT_PROTOCOL: u16 = 0x0001;
/// Error (§4.1.3), record type 2.
pub const KE_RECORD_ERROR: u16 = 0x0002;
/// Warning (§4.1.4), record type 3.
pub const KE_RECORD_WARNING: u16 = 0x0003;
/// AEAD Algorithm Negotiation (§4.1.5), record type 4.
pub const KE_RECORD_ALGO_NEGOTIATION: u16 = 0x0004;
/// New Cookie for NTPv4 (§4.1.6), record type 5.
pub const KE_RECORD_NEW_COOKIE: u16 = 0x0005;
/// NTPv4 Server Negotiation (§4.1.7), record type 6.
pub const KE_RECORD_SERVER_NEGOTIATION: u16 = 0x0006;
/// NTPv4 Port Negotiation (§4.1.8), record type 7.
pub const KE_RECORD_PORT_NEGOTIATION: u16 = 0x0007;

// ---- NTS-KE protocol versions (§4.1.1) ----
pub const NTS_PROTOCOL_VERSION_1: u16 = 0;

/// NTS Next Protocol identifier for NTPv4 (§4.1.2 / IANA registry).
pub const NEXT_PROTOCOL_NTPV4: u16 = 0;

// ---- NTS-KE error codes (§4.1.3) ----
pub const KE_ERR_UNRECOGNIZED_CRITICAL_RECORD: u16 = 0;
pub const KE_ERR_BAD_REQUEST: u16 = 1;
pub const KE_ERR_INTERNAL_SERVER_ERROR: u16 = 2;

// ---- NTP extension field type IDs (RFC 8915 §5.1.2 / §5.3, IANA registry) ----
pub const EF_UNIQUE_IDENTIFIER: u16 = 0x0104;
pub const EF_NTS_COOKIE: u16 = 0x0204;
pub const EF_NTS_COOKIE_PLACEHOLDER: u16 = 0x0304;
pub const EF_NTS_AUTHENTICATOR: u16 = 0x0404;
pub const EF_NTS_NEGOTIATED_AEAD: u16 = 0x0504;

// ---- Ports / sizes ----
pub const DEFAULT_NTS_KE_PORT: u16 = 4460;
pub const DEFAULT_NTP_PORT: u16 = 123;
pub const NTP_HEADER_LEN: usize = 48;
/// NTS Unique Identifier nonce length (RFC 8915 §5.3): 32 octets.
pub const UNIQUE_ID_LEN: usize = 32;
/// Number of cookies a KE server hands out per handshake (§5.7 example uses 8).
pub const DEFAULT_COOKIES_PER_KE: usize = 8;

/// TLS exporter label, exactly as given in RFC 8915 §4.3 / §5.1.
pub const EXPORTER_LABEL: &str = "EXPORTER-network-time-security";
/// Final context octet for the client-to-server and server-to-client keys.
pub const EXPORTER_DIRECTION_C2S: u8 = 0x00;
pub const EXPORTER_DIRECTION_S2C: u8 = 0x01;
