//! The wire layer: every message of the kpasswd-front ↔ dird channel as
//! fixed-order fields over `ipc` (lengths, markers, closed tables, no
//! trailing octet). The Kerberos messages stay opaque here: keyd decodes the
//! request's (docs/53 §5.3–§5.4), the client the reply's.
//!
//! | message | fields |
//! |---|---|
//! | `Ping` | — |
//! | `ChangePassword` | `ap_req: bytes<65528>`, `krb_priv: bytes<65528>` (together ≤ 65529), `peer: address`, `local: address` |
//! | `Pong` | `zone: u8` |
//! | `Sealed` | `ap_rep: bytes<8176>`, `krb_priv: bytes<8176>` (together ≤ 8176) |
//! | `Unsealed` | `code: u8 {2 HARDERROR, 3 AUTHERROR}` |
//!
//! `address := family: u8 {1 IPv4, 2 IPv6} ‖ [u8; 4] or [u8; 16]`.
//!
//! # Field domains
//!
//! Beyond `ipc`'s own rules, every field admits only the values its value
//! type can hold ([`ApReqOctets`], [`KrbPrivOctets`], [`ApRepOctets`],
//! [`ObservedAddress`], [`ChangePasswordRequest`], [`SealedReply`],
//! [`UnsealedCode`]). A value outside its domain is refused as follows (fail
//! closed; each is `Refused{Malformed}` on dird's side, `ipc::Error::refusal`):
//!
//! * a Kerberos message that does not start with its identifier octet (an
//!   AP-REQ not `[APPLICATION 14]`, a KRB-PRIV not `[APPLICATION 21]` — the
//!   cleartext EncKrbPrivPart `[APPLICATION 28]` included —, an AP-REP not
//!   `[APPLICATION 15]`), an IPv4-mapped IPv6 address (its IPv4 form is its
//!   only spelling) → [`Error::UnknownCode`] — the house reading of "a value
//!   outside the field's closed table" (precedent: crates/ipc-keyd refuses a
//!   mapped IPv6 `HostAddr` the same way, crates/ipc-dns a mapped peer);
//! * an empty message, or two messages over their joint bound →
//!   [`Error::LengthOverBound`] — the field's bound for that case
//!   (precedent: crates/ipc-dns's message rule).
//!
//! **No field lets the front claim an identity, a zone, a target or a
//! decision, and no field can hold the password in clear** (docs/53 §4.3,
//! R53-4, R53-8): the front reports only the two messages it received and
//! the two addresses its socket observed.
//!
//! Spec: docs/53 §4.3, §5.5, §5.7; docs/50 §3.3 (primitives, one encoding
//! per value); RFC 3244 §2; RFC 4120 §5.10, §7.1.

use crate::channel::{codes, reply_kind, request_kind, MAX_REQUEST_FIELD, MAX_SEALED_MESSAGES};
use crate::values::{
    ApRepOctets, ApReqOctets, ChangePasswordRequest, FrontZone, KrbPrivOctets, ObservedAddress,
    SealedReply, UnsealedCode,
};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipc::{Error, MessageSet, Reader, Result, Writer};

// ---- field helpers -----------------------------------------------------------

/// An address: `family: u8` (closed table) then the octets.
/// Spec: docs/50 §3.3; RFC 4120 §7.1.
fn write_address(writer: &mut Writer, address: ObservedAddress) -> Result<()> {
    match address.address() {
        IpAddr::V4(v4) => {
            writer.write_enum(codes::FAMILY_IPV4)?;
            writer.write_array(&v4.octets())
        }
        IpAddr::V6(v6) => {
            writer.write_enum(codes::FAMILY_IPV6)?;
            writer.write_array(&v6.octets())
        }
    }
}

/// An IPv4-mapped address in the IPv6 form is refused: its IPv4 form is its
/// only spelling ([`ObservedAddress`]; docs/50 §3.3, one encoding per value).
/// Spec: docs/50 §3.3; RFC 4120 §7.1; std `IpAddr::to_canonical`.
fn read_address(reader: &mut Reader<'_>) -> Result<ObservedAddress> {
    let family = reader.read_enum(|code| {
        (code == codes::FAMILY_IPV4 || code == codes::FAMILY_IPV6).then_some(code)
    })?;
    let address = if family == codes::FAMILY_IPV4 {
        IpAddr::V4(Ipv4Addr::from(reader.read_array::<4>()?))
    } else {
        IpAddr::V6(Ipv6Addr::from(reader.read_array::<16>()?))
    };
    let observed = ObservedAddress::new(address);
    if observed.address() != address {
        return Err(Error::UnknownCode);
    }
    Ok(observed)
}

/// A Kerberos message field: an empty one is outside the field's bound
/// (`LengthOverBound`), one with another identifier outside its domain
/// (`UnknownCode`).
/// Spec: module documentation; docs/53 §5.1; X.690 8.1.2.2.
fn read_message<T>(
    reader: &mut Reader<'_>,
    max: u32,
    build: impl FnOnce(&[u8]) -> Option<T>,
) -> Result<T> {
    let octets = reader.read_bytes(max)?;
    if octets.is_empty() {
        return Err(Error::LengthOverBound);
    }
    build(octets).ok_or(Error::UnknownCode)
}

// ---- requests ----------------------------------------------------------------

/// The messages kpasswd-front sends.
/// Spec: docs/53 §4.3, §5.6 step 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KpasswdRequest {
    /// Peer verification on every new connection, and health check.
    Ping,
    /// One RFC 3244 request, for dird (and through it keyd).
    ChangePassword(ChangePasswordRequest),
}

impl MessageSet for KpasswdRequest {
    const KINDS: &'static [u8] = request_kind::ALL;

    fn kind(&self) -> u8 {
        match self {
            KpasswdRequest::Ping => request_kind::PING,
            KpasswdRequest::ChangePassword(_) => request_kind::CHANGE_PASSWORD,
        }
    }

    /// Spec: module table; docs/50 §3.3.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            KpasswdRequest::Ping => Ok(()),
            KpasswdRequest::ChangePassword(request) => {
                writer.write_bytes(request.ap_req().as_bytes(), MAX_REQUEST_FIELD)?;
                writer.write_bytes(request.krb_priv().as_bytes(), MAX_REQUEST_FIELD)?;
                write_address(writer, request.peer())?;
                write_address(writer, request.local())
            }
        }
    }

    /// Spec: module table; docs/50 §3.3.
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<KpasswdRequest> {
        match kind {
            request_kind::PING => Ok(KpasswdRequest::Ping),
            request_kind::CHANGE_PASSWORD => {
                let ap_req = read_message(reader, MAX_REQUEST_FIELD, ApReqOctets::new)?;
                let krb_priv = read_message(reader, MAX_REQUEST_FIELD, KrbPrivOctets::new)?;
                let peer = read_address(reader)?;
                let local = read_address(reader)?;
                ChangePasswordRequest::new(ap_req, krb_priv, peer, local)
                    .map(KpasswdRequest::ChangePassword)
                    .ok_or(Error::LengthOverBound)
            }
            _ => Err(Error::UnknownKind),
        }
    }
}

// ---- replies -----------------------------------------------------------------

/// The messages dird sends.
/// Spec: docs/53 §5.5–§5.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KpasswdReply {
    /// The reply to `Ping`: the zone dird assigned this connection from the
    /// front's peer uid.
    Pong {
        /// The connection's zone.
        zone: FrontZone,
    },
    /// keyd's sealed reply to a `ChangePassword`.
    Sealed(SealedReply),
    /// No context to seal in: the front's KRB-ERROR carries this code.
    Unsealed(UnsealedCode),
}

impl MessageSet for KpasswdReply {
    const KINDS: &'static [u8] = reply_kind::ALL;

    fn kind(&self) -> u8 {
        match self {
            KpasswdReply::Pong { .. } => reply_kind::PONG,
            KpasswdReply::Sealed(_) => reply_kind::SEALED,
            KpasswdReply::Unsealed(_) => reply_kind::UNSEALED,
        }
    }

    /// Spec: module table; docs/50 §3.3.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            KpasswdReply::Pong { zone } => writer.write_enum(zone.code()),
            KpasswdReply::Sealed(sealed) => {
                writer.write_bytes(sealed.ap_rep().as_bytes(), MAX_SEALED_MESSAGES)?;
                writer.write_bytes(sealed.krb_priv().as_bytes(), MAX_SEALED_MESSAGES)
            }
            KpasswdReply::Unsealed(code) => writer.write_enum(code.code()),
        }
    }

    /// Spec: module table; docs/50 §3.3 (replies decoded with the same
    /// strictness as requests).
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<KpasswdReply> {
        match kind {
            reply_kind::PONG => Ok(KpasswdReply::Pong {
                zone: reader.read_enum(FrontZone::from_code)?,
            }),
            reply_kind::SEALED => {
                let ap_rep = read_message(reader, MAX_SEALED_MESSAGES, ApRepOctets::new)?;
                let krb_priv = read_message(reader, MAX_SEALED_MESSAGES, KrbPrivOctets::new)?;
                SealedReply::new(ap_rep, krb_priv)
                    .map(KpasswdReply::Sealed)
                    .ok_or(Error::LengthOverBound)
            }
            reply_kind::UNSEALED => Ok(KpasswdReply::Unsealed(
                reader.read_enum(UnsealedCode::from_code)?,
            )),
            _ => Err(Error::UnknownKind),
        }
    }
}
