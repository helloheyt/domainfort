//! The wire layer: every message of the ldap-front ↔ dird channel as
//! fixed-order fields over `ipc` (lengths, markers, closed tables, no trailing
//! octet). The canonical LDAPMessage and the response parts stay opaque here:
//! the engine decodes the request with parse-ldap's canonical profile
//! (R49-16), the front writes the responses to the client as they are.
//!
//! | message | fields |
//! |---|---|
//! | `Open` | `listener: u8`, `peer_addr: family u8 ‖ [u8; 4] or [u8; 16]` |
//! | `Message` | `canonical: bytes<MAX_CANONICAL_MESSAGE>`, `tls_established: bool`, `input_pending: bool` |
//! | `TlsEstablished`, `Close`, `Ping`, `Pong` | — |
//! | `Opened`, `TlsAccepted` | `framing: u8` |
//! | `Response` | `part: bytes<MAX_RESPONSE_PART>` (never empty), `more: bool` (`true` only on a part of exactly `MAX_RESPONSE_PART`) |
//! | `Done` | `action: u8`, `framing: u8` |
//!
//! **No field lets the front claim an identity or a channel binding** (A-47,
//! A-54): `Message` carries only the two transport facts the engine's
//! `TransportReport` defines besides the zone — and the zone itself is not
//! sent: the front sends the peer **address** and dird maps it through its
//! own zone table (docs/50 §4.2: "the mapping belongs to the PEP"). The
//! channel-binding value is computed by dird from the configured certificate
//! (docs/50 R50-13), never by the front.
//!
//! Spec: docs/50 §3.3 (primitives, one encoding per value), §4.2, §4.3,
//! R50-13; docs/49 R49-16; A-47; A-54 (Q-190 item 11).

use crate::channel::{
    codes, reply_kind, request_kind, ConnectionAction, Listener, MAX_CANONICAL_MESSAGE,
    MAX_RESPONSE_MESSAGE, MAX_RESPONSE_PART,
};
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipc::{Error, MessageSet, Reader, Result, Writer};
use parse_ldap::AuthState;
use zeroize::Zeroizing;

/// [`MAX_RESPONSE_PART`] as a slice length.
const PART: usize = MAX_RESPONSE_PART as usize;

/// What the front observed about the transport when it framed the message —
/// exactly the engine's `TransportReport` minus the zone (which dird derives
/// from the peer address, docs/50 §4.2).
/// Spec: docs/50 §4.2 (`Message { canonical, tls_established, input_pending
/// }`), §4.3 step 1; crates/ldap inputs.rs; A-47.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransportFacts {
    /// A TLS layer with an AEAD cipher suite protects this message's octets
    /// (docs/49 §4.3: "`encrypted` only after TLS completed with an AEAD
    /// suite").
    pub tls_established: bool,
    /// The front's framer already holds octets after this message (RFC 4513
    /// §3.1.1; RFC 4511 §4.14.1; docs/50 §4.3 step 1).
    pub input_pending: bool,
}

/// `Message`: one canonical LDAPMessage and the transport facts. The octets
/// are held in a zeroizing buffer and never printed (`Debug` shows only the
/// length).
/// Spec: docs/50 §4.2; docs/49 R49-16.
#[derive(Clone, PartialEq, Eq)]
pub struct MessageRequest {
    /// The client's LDAPMessage, re-encoded by the front in parse-ldap's
    /// canonical form (docs/50 §4.2: "the front decodes with `Profile::Wire`
    /// and encodes with `encode_message`").
    pub canonical: Zeroizing<Vec<u8>>,
    /// The transport facts.
    pub transport: TransportFacts,
}

impl fmt::Debug for MessageRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageRequest")
            .field("canonical_len", &self.canonical.len())
            .field("transport", &self.transport)
            .finish()
    }
}

/// The messages the front sends.
/// Spec: docs/50 §4.2, §4.3, §7.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapRequest {
    /// The first message of a session: which listener accepted the client,
    /// and the client's address (dird maps it to a zone, docs/50 §4.2).
    Open {
        /// The listener.
        listener: Listener,
        /// The client's IP address as the front's socket reports it.
        peer_addr: IpAddr,
    },
    /// One canonical LDAPMessage.
    Message(MessageRequest),
    /// The TLS layer that the last `StartTls` asked for is up (docs/50 §4.3
    /// step 4).
    TlsEstablished,
    /// The client connection ended; dird destroys the session. No reply.
    Close,
    /// Health check (docs/50 §7.5), only as the first message.
    Ping,
}

/// A peer address: `family: u8` (closed table) then the octets.
/// Spec: docs/50 §3.3 ("enum = `u8` from a closed table"), §4.2.
fn write_peer_addr(writer: &mut Writer, peer: &IpAddr) -> Result<()> {
    match peer {
        IpAddr::V4(v4) => {
            writer.write_enum(codes::FAMILY_V4)?;
            writer.write_array(&v4.octets())
        }
        IpAddr::V6(v6) => {
            writer.write_enum(codes::FAMILY_V6)?;
            writer.write_array(&v6.octets())
        }
    }
}

/// Spec: docs/50 §3.3, §4.2.
fn read_peer_addr(reader: &mut Reader<'_>) -> Result<IpAddr> {
    let family = reader
        .read_enum(|code| (code == codes::FAMILY_V4 || code == codes::FAMILY_V6).then_some(code))?;
    if family == codes::FAMILY_V4 {
        Ok(IpAddr::V4(Ipv4Addr::from(reader.read_array::<4>()?)))
    } else {
        Ok(IpAddr::V6(Ipv6Addr::from(reader.read_array::<16>()?)))
    }
}

impl MessageSet for LdapRequest {
    const KINDS: &'static [u8] = request_kind::ALL;

    fn kind(&self) -> u8 {
        match self {
            LdapRequest::Open { .. } => request_kind::OPEN,
            LdapRequest::Message(_) => request_kind::MESSAGE,
            LdapRequest::TlsEstablished => request_kind::TLS_ESTABLISHED,
            LdapRequest::Close => request_kind::CLOSE,
            LdapRequest::Ping => request_kind::PING,
        }
    }

    /// Spec: crate module table; docs/50 §3.3.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            LdapRequest::Open {
                listener,
                peer_addr,
            } => {
                writer.write_enum(codes::listener(*listener))?;
                write_peer_addr(writer, peer_addr)
            }
            LdapRequest::Message(message) => {
                writer.write_bytes(&message.canonical, MAX_CANONICAL_MESSAGE)?;
                writer.write_bool(message.transport.tls_established)?;
                writer.write_bool(message.transport.input_pending)
            }
            LdapRequest::TlsEstablished | LdapRequest::Close | LdapRequest::Ping => Ok(()),
        }
    }

    /// Spec: crate module table; docs/50 §3.3.
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<LdapRequest> {
        match kind {
            request_kind::OPEN => {
                let listener = reader.read_enum(codes::listener_from)?;
                let peer_addr = read_peer_addr(reader)?;
                Ok(LdapRequest::Open {
                    listener,
                    peer_addr,
                })
            }
            request_kind::MESSAGE => {
                let octets = reader.read_bytes(MAX_CANONICAL_MESSAGE)?;
                let mut canonical = Zeroizing::new(Vec::with_capacity(octets.len()));
                canonical.extend_from_slice(octets);
                let tls_established = reader.read_bool()?;
                let input_pending = reader.read_bool()?;
                Ok(LdapRequest::Message(MessageRequest {
                    canonical,
                    transport: TransportFacts {
                        tls_established,
                        input_pending,
                    },
                }))
            }
            request_kind::TLS_ESTABLISHED => Ok(LdapRequest::TlsEstablished),
            request_kind::CLOSE => Ok(LdapRequest::Close),
            request_kind::PING => Ok(LdapRequest::Ping),
            _ => Err(Error::UnknownKind),
        }
    }
}

/// One part of one canonical LDAP response. Invariant (checked by
/// [`ResponsePart::new`] and by the decoder): 1 ..= [`MAX_RESPONSE_PART`]
/// octets, and exactly [`MAX_RESPONSE_PART`] when `more` is set — so every
/// response has exactly one division into parts ([`split_response`]).
/// `Debug` shows only the length.
/// Spec: docs/50 §3.3 ("a single encoding per value"); crate::channel module
/// documentation.
#[derive(Clone, PartialEq, Eq)]
pub struct ResponsePart {
    part: Zeroizing<Vec<u8>>,
    more: bool,
}

impl fmt::Debug for ResponsePart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponsePart")
            .field("len", &self.part.len())
            .field("more", &self.more)
            .finish()
    }
}

/// Whether a part of `len` octets with `more` keeps the invariant.
const fn part_is_valid(len: usize, more: bool) -> bool {
    if more {
        len == PART
    } else {
        len >= 1 && len <= PART
    }
}

impl ResponsePart {
    /// A part, or `None` if it breaks the invariant.
    /// Spec: crate::channel module documentation.
    #[must_use]
    pub fn new(part: &[u8], more: bool) -> Option<ResponsePart> {
        if !part_is_valid(part.len(), more) {
            return None;
        }
        let mut octets = Zeroizing::new(Vec::with_capacity(part.len()));
        octets.extend_from_slice(part);
        Some(ResponsePart { part: octets, more })
    }

    /// The part's octets.
    #[must_use]
    pub fn octets(&self) -> &[u8] {
        &self.part
    }

    /// Whether more parts of the same response follow.
    #[must_use]
    pub fn more(&self) -> bool {
        self.more
    }
}

/// The one division of a response into parts: full parts of
/// [`MAX_RESPONSE_PART`] octets, then the rest (if the length is a multiple
/// of the part size, the last full part ends the response). `None` for an
/// empty response or one longer than [`MAX_RESPONSE_MESSAGE`].
/// Spec: crate::channel module documentation.
#[must_use]
pub fn split_response(response: &[u8]) -> Option<Vec<ResponsePart>> {
    if response.is_empty() || response.len() > MAX_RESPONSE_MESSAGE {
        return None;
    }
    let count = response.len().div_ceil(PART);
    let mut parts = Vec::with_capacity(count);
    for (index, chunk) in response.chunks(PART).enumerate() {
        parts.push(ResponsePart::new(chunk, index + 1 < count)?);
    }
    Some(parts)
}

/// The messages dird sends.
/// Spec: docs/50 §4.2, §4.3, §7.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapReply {
    /// The session exists; the framing state of its first message.
    Opened {
        /// The authentication state whose size bound the front applies.
        framing: AuthState,
    },
    /// One part of one response.
    Response(ResponsePart),
    /// The end of the reply to a `Message`.
    Done {
        /// What the front does with the client connection.
        action: ConnectionAction,
        /// The authentication state whose size bound the front applies to
        /// the next message (docs/50 §4.2: "`auth` comes from the last
        /// `Done.framing`").
        framing: AuthState,
    },
    /// The reply to `TlsEstablished`.
    TlsAccepted {
        /// The framing state.
        framing: AuthState,
    },
    /// The reply to `Ping`.
    Pong,
}

impl MessageSet for LdapReply {
    const KINDS: &'static [u8] = reply_kind::ALL;

    fn kind(&self) -> u8 {
        match self {
            LdapReply::Opened { .. } => reply_kind::OPENED,
            LdapReply::Response(_) => reply_kind::RESPONSE,
            LdapReply::Done { .. } => reply_kind::DONE,
            LdapReply::TlsAccepted { .. } => reply_kind::TLS_ACCEPTED,
            LdapReply::Pong => reply_kind::PONG,
        }
    }

    /// Spec: crate module table; docs/50 §3.3.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            LdapReply::Opened { framing } | LdapReply::TlsAccepted { framing } => {
                writer.write_enum(codes::framing(*framing))
            }
            LdapReply::Response(part) => {
                // Never produce a part the peer would refuse.
                if !part_is_valid(part.part.len(), part.more) {
                    return Err(Error::LengthOverBound);
                }
                writer.write_bytes(&part.part, MAX_RESPONSE_PART)?;
                writer.write_bool(part.more)
            }
            LdapReply::Done { action, framing } => {
                writer.write_enum(codes::action(*action))?;
                writer.write_enum(codes::framing(*framing))
            }
            LdapReply::Pong => Ok(()),
        }
    }

    /// Spec: crate module table; docs/50 §3.3 (replies decoded with the same
    /// strictness as requests).
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<LdapReply> {
        match kind {
            reply_kind::OPENED => Ok(LdapReply::Opened {
                framing: reader.read_enum(codes::framing_from)?,
            }),
            reply_kind::RESPONSE => {
                let octets = reader.read_bytes(MAX_RESPONSE_PART)?;
                let more = reader.read_bool()?;
                // An empty part, or a short part that says more follows, is
                // outside the field's bound for that marker.
                ResponsePart::new(octets, more)
                    .map(LdapReply::Response)
                    .ok_or(Error::LengthOverBound)
            }
            reply_kind::DONE => {
                let action = reader.read_enum(codes::action_from)?;
                let framing = reader.read_enum(codes::framing_from)?;
                Ok(LdapReply::Done { action, framing })
            }
            reply_kind::TLS_ACCEPTED => Ok(LdapReply::TlsAccepted {
                framing: reader.read_enum(codes::framing_from)?,
            }),
            reply_kind::PONG => Ok(LdapReply::Pong),
            _ => Err(Error::UnknownKind),
        }
    }
}
