//! NTS-KE record framing (RFC 8915 §4).
//!
//! Every KE record is a 4-octet header `u16 type | u16 body_length` followed
//! by the body. The high bit of the type word is the "critical" flag
//! (§4.1.2): a peer that does not recognize a critical record must abort
//! with an Error record. This module owns only the framing; the TLS layer
//! and request/response semantics live in [`crate::ke_client`] /
//! [`crate::ke_server`].

use std::io::{Read, Write};

#[allow(unused_imports)]
use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};

use crate::constants::*;
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeRecord {
    pub r#type: u16,
    pub critical: bool,
    pub body: Vec<u8>,
}

impl KeRecord {
    pub fn new(r#type: u16, critical: bool, body: Vec<u8>) -> Self {
        Self {
            r#type,
            critical,
            body,
        }
    }

    pub fn algo_negotiation(ids: &[u16]) -> Self {
        let mut body = Vec::with_capacity(ids.len() * 2);
        for id in ids {
            body.write_u16::<BigEndian>(*id).unwrap();
        }
        Self::new(KE_RECORD_ALGO_NEGOTIATION, true, body)
    }

    /// NTS Next Protocol Negotiation record listing the protocols the peer
    /// wants to protect. We only support NTPv4 (protocol id 0).
    pub fn next_protocol(protocols: &[u16]) -> Self {
        let mut body = Vec::with_capacity(protocols.len() * 2);
        for p in protocols {
            body.write_u16::<BigEndian>(*p).unwrap();
        }
        Self::new(KE_RECORD_NEXT_PROTOCOL, true, body)
    }

    /// New Cookie record. RFC 8915 §4.1.6: the Critical Bit SHOULD NOT be set.
    pub fn new_cookie(cookie: Vec<u8>) -> Self {
        Self::new(KE_RECORD_NEW_COOKIE, false, cookie)
    }

    pub fn server_negotiation(name: &str) -> Self {
        Self::new(
            KE_RECORD_SERVER_NEGOTIATION,
            true,
            name.as_bytes().to_vec(),
        )
    }

    pub fn port_negotiation(port: u16) -> Self {
        let mut body = Vec::with_capacity(2);
        body.write_u16::<BigEndian>(port).unwrap();
        Self::new(KE_RECORD_PORT_NEGOTIATION, true, body)
    }

    pub fn end_of_message() -> Self {
        Self::new(KE_RECORD_END_OF_MESSAGE, true, Vec::new())
    }

    pub fn error(code: u16) -> Self {
        let mut body = Vec::with_capacity(2);
        body.write_u16::<BigEndian>(code).unwrap();
        Self::new(KE_RECORD_ERROR, true, body)
    }

    pub fn is_known_type(t: u16) -> bool {
        matches!(
            t,
            KE_RECORD_END_OF_MESSAGE
                | KE_RECORD_NEXT_PROTOCOL
                | KE_RECORD_ERROR
                | KE_RECORD_WARNING
                | KE_RECORD_ALGO_NEGOTIATION
                | KE_RECORD_NEW_COOKIE
                | KE_RECORD_SERVER_NEGOTIATION
                | KE_RECORD_PORT_NEGOTIATION
        )
    }
}

/// Write one record to `w`, OR-ing the critical bit into the type word.
pub fn write_record<W: Write>(w: &mut W, rec: &KeRecord) -> Result<()> {
    let mut raw_type = rec.r#type & 0x7fff;
    if rec.critical {
        raw_type |= KE_RECORD_CRITICAL_BIT;
    }
    w.write_u16::<BigEndian>(raw_type)?;
    w.write_u16::<BigEndian>(
        rec.body
            .len()
            .try_into()
            .map_err(|_| Error::ke("KE record body larger than 65535 octets"))?,
    )?;
    w.write_all(&rec.body)?;
    Ok(())
}

pub fn write_records<W: Write>(w: &mut W, recs: &[KeRecord]) -> Result<()> {
    for r in recs {
        write_record(w, r)?;
    }
    w.flush()?;
    Ok(())
}

/// Read one record. Returns `Ok(None)` on clean EOF before any bytes.
pub fn read_record<R: Read>(r: &mut R) -> Result<Option<KeRecord>> {
    let raw_type = match r.read_u16::<BigEndian>() {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    };
    let len = r.read_u16::<BigEndian>()? as usize;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(KeRecord {
        r#type: raw_type & 0x7fff,
        critical: raw_type & KE_RECORD_CRITICAL_BIT != 0,
        body,
    }))
}

/// Read until End-of-Message (consumed) or EOF.
/// Unknown critical records cause an error per §4.1.2.
pub fn read_until_eom<R: Read>(r: &mut R) -> Result<Vec<KeRecord>> {
    let mut out = Vec::new();
    loop {
        match read_record(r)? {
            None => return Err(Error::ke("peer closed KE connection without EOM")),
            Some(rec) => {
                if rec.r#type == KE_RECORD_END_OF_MESSAGE {
                    out.push(rec);
                    return Ok(out);
                }
                if rec.critical && !KeRecord::is_known_type(rec.r#type) {
                    return Err(Error::ke(format!(
                        "unrecognized critical KE record type 0x{:04x}",
                        rec.r#type
                    )));
                }
                out.push(rec);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn record_roundtrip_and_critical_bit() {
        let recs = vec![
            KeRecord::next_protocol(&[0]),
            KeRecord::algo_negotiation(&[16, 15]),
            KeRecord::new_cookie(vec![1, 2, 3, 4]),
            KeRecord::server_negotiation("ntp.example.test"),
            KeRecord::port_negotiation(4123),
            KeRecord::end_of_message(),
        ];
        let mut buf = Vec::new();
        write_records(&mut buf, &recs).unwrap();

        let mut cur = Cursor::new(buf);
        let back = read_until_eom(&mut cur).unwrap();
        assert_eq!(back.len(), 6);
        // New Cookie (index 2) is non-critical per RFC 8915 §4.1.6.
        assert!(!back[2].critical);
        assert!(back
            .iter()
            .enumerate()
            .all(|(i, r)| i == 2 || r.critical));
        assert_eq!(back[0].r#type, KE_RECORD_NEXT_PROTOCOL);
        assert_eq!(back[1].r#type, KE_RECORD_ALGO_NEGOTIATION);
        assert_eq!(back[2].body, vec![1, 2, 3, 4]);
        assert_eq!(back[3].body, b"ntp.example.test");
        assert_eq!(BigEndian::read_u16(&back[4].body), 4123);
        assert_eq!(back[5].r#type, KE_RECORD_END_OF_MESSAGE);
    }

    #[test]
    fn unknown_critical_record_aborts() {
        let mut buf = Vec::new();
        write_record(
            &mut buf,
            &KeRecord::new(0x0099, true, b"x".to_vec()),
        )
        .unwrap();
        write_record(&mut buf, &KeRecord::end_of_message()).unwrap();
        let mut cur = Cursor::new(buf);
        assert!(read_until_eom(&mut cur).is_err());
    }

    #[test]
    fn truncated_record_is_error() {
        let mut buf = Vec::new();
        write_record(&mut buf, &KeRecord::new_cookie(vec![0u8; 10])).unwrap();
        buf.truncate(buf.len() - 3);
        let mut cur = Cursor::new(buf);
        assert!(read_record(&mut cur).is_err());
    }
}
