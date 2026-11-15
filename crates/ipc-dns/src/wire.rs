//! The wire layer: every message of the dnsd ↔ dird channel as fixed-order
//! fields over `ipc` (lengths, markers, closed tables, no trailing octet).
//! Forwarded DNS messages stay opaque here: dird decodes them with
//! parse-dns's `Forwarded` profile (docs/54 §6.1), dnsd sends dird's replies
//! as they are (after dns-zone's size rule — A-140).
//!
//! `DescribeZone` / `ZoneDescription` (kinds `0x02` / `0x82`) are retired by
//! A-152 (docs/questions/Q-922): `FetchZoneImage { have }` answers the same
//! question, so the channel carries one operation fewer. Their kinds are not
//! in the closed tables and are refused like any unknown kind.
//!
//! | message | fields |
//! |---|---|
//! | `Ping` | — |
//! | `FetchZoneImage` | `have: Option<serial:u32>` |
//! | `Forward` | `transport: u8`, `peer: family u8 ‖ [u8; 4] or [u8; 16]`, `message: bytes<65535>` |
//! | `Pong` | `zone: u8` |
//! | `Unchanged` | `serial: u32` |
//! | `ImageChunk` | `chunk: bytes<1 MiB>` (never empty), `more: bool` (`true` only on a chunk of exactly 1 MiB) |
//! | `Forwarded` | `reply: Option<bytes<65535>>`, `serial: u32` |
//!
//! # Field domains
//!
//! Beyond `ipc`'s own rules, every field admits only the values its value
//! type can hold ([`Serial`], [`PeerAddress`], [`DnsMessage`],
//! [`ForwardRequest`], [`ImageChunk`]). A value outside its domain is
//! refused as follows (fail closed; each is `Refused{Malformed}` on dird's side,
//! `ipc::Error::refusal`):
//!
//! * a SERIAL of zero (RFC 2136 §7.11), an IPv4-mapped IPv6 peer address
//!   (its IPv4 form is its only spelling), a name (in the zone image) that
//!   is not exactly one uncompressed RFC 1035 §3.1 name →
//!   [`Error::UnknownCode`] — the house reading of "a value
//!   outside the field's closed table" (precedent: crates/ipc-keyd refuses a
//!   mapped IPv6 `HostAddr` and a zero result code the same way);
//! * a DNS message shorter than a header (RFC 1035 §4.1.1), a UDP-borne
//!   message over 512 octets (RFC 1035 §2.3.4, §4.2.1), an empty image
//!   chunk or a short one marked `more` → [`Error::LengthOverBound`] — the
//!   field's bound for that case (precedent: crates/ipc-ldap's response-part
//!   rule).
//!
//! **No field lets dnsd claim an identity, a zone or a decision** (docs/54
//! §4.1, C3): dnsd reports only how a message arrived — the transport and the
//! source address its socket observed (A-140; r3-c W21) — and the message
//! itself, whose TSIG only keyd verifies. The zone is dird's, from dnsd's
//! peer uid.
//!
//! Spec: docs/54 §4.6; A-140; A-152 (Q-922); docs/50 §3.3 (primitives, one
//! encoding per value); RFC 1035 §2.3.4, §3.1, §4.1.1, §4.2; RFC 2136 §7.11.

use crate::channel::{
    codes, reply_kind, request_kind, MAX_IMAGE_CHUNK, MAX_MESSAGE, MAX_NAME, MAX_UDP_MESSAGE,
};
use crate::image::{chunk_is_valid, ImageChunk};
use crate::values::{DnsMessage, ForwardRequest, Forwarded, FrontZone, PeerAddress, Serial};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipc::{Error, MessageSet, Reader, Result, Writer};
use parse_dns::{Name, Transport};

// ---- field helpers ---------------------------------------------------------

/// A SERIAL: `u32`, never zero. Spec: RFC 2136 §7.11; docs/54 §5.4.
pub(crate) fn write_serial(writer: &mut Writer, serial: Serial) -> Result<()> {
    writer.write_u32(serial.get())
}

/// Spec: RFC 2136 §7.11 (zero ⇒ outside the field's domain).
pub(crate) fn read_serial(reader: &mut Reader<'_>) -> Result<Serial> {
    Serial::new(reader.read_u32()?).ok_or(Error::UnknownCode)
}

/// A domain name: `bytes<255>` holding its uncompressed wire form.
/// Spec: RFC 1035 §3.1, §2.3.4; parse-dns `Name::as_wire`.
pub(crate) fn write_name(writer: &mut Writer, name: &Name) -> Result<()> {
    writer.write_bytes(name.as_wire(), MAX_NAME)
}

/// Exactly one uncompressed name filling the field (no pointer: there is no
/// message to point into; no octet after the root label).
/// Spec: RFC 1035 §3.1, §4.1.4; parse-dns `Name::decode_uncompressed`.
pub(crate) fn read_name(reader: &mut Reader<'_>) -> Result<Name> {
    Name::decode_uncompressed(reader.read_bytes(MAX_NAME)?).map_err(|_| Error::UnknownCode)
}

/// The transport a forwarded message arrived on: one code.
/// Spec: RFC 1035 §4.2; A-140.
fn write_transport(writer: &mut Writer, transport: Transport) -> Result<()> {
    writer.write_enum(match transport {
        Transport::Udp => codes::TRANSPORT_UDP,
        Transport::Tcp => codes::TRANSPORT_TCP,
    })
}

/// Spec: RFC 1035 §4.2; A-140.
fn read_transport(reader: &mut Reader<'_>) -> Result<Transport> {
    reader.read_enum(|code| match code {
        codes::TRANSPORT_UDP => Some(Transport::Udp),
        codes::TRANSPORT_TCP => Some(Transport::Tcp),
        _ => None,
    })
}

/// A peer address: `family: u8` (closed table) then the octets.
/// Spec: docs/50 §3.3; A-140.
fn write_peer(writer: &mut Writer, peer: PeerAddress) -> Result<()> {
    match peer.address() {
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

/// An IPv4-mapped address in the IPv6 form is refused: its IPv4 form is its
/// only spelling ([`PeerAddress`]; docs/50 §3.3, one encoding per value).
/// Spec: docs/50 §3.3; A-140; std `IpAddr::to_canonical`.
fn read_peer(reader: &mut Reader<'_>) -> Result<PeerAddress> {
    let family = reader
        .read_enum(|code| (code == codes::FAMILY_V4 || code == codes::FAMILY_V6).then_some(code))?;
    let address = if family == codes::FAMILY_V4 {
        IpAddr::V4(Ipv4Addr::from(reader.read_array::<4>()?))
    } else {
        IpAddr::V6(Ipv6Addr::from(reader.read_array::<16>()?))
    };
    let peer = PeerAddress::new(address);
    if peer.address() != address {
        return Err(Error::UnknownCode);
    }
    Ok(peer)
}

/// A DNS message: `bytes<max>`, at least a header.
/// Spec: RFC 1035 §4.1.1, §4.2.
fn write_message(writer: &mut Writer, message: &DnsMessage, max: u32) -> Result<()> {
    writer.write_bytes(message.as_bytes(), max)
}

/// Spec: RFC 1035 §4.1.1 (a message has its 12-octet header), §4.2.
fn read_message(reader: &mut Reader<'_>, max: u32) -> Result<DnsMessage> {
    // `read_bytes` applies the upper bound; `DnsMessage::new` refuses fewer
    // than `MIN_MESSAGE` octets.
    DnsMessage::new(reader.read_bytes(max)?).ok_or(Error::LengthOverBound)
}

/// The field bound of a forwarded message on `transport`.
/// Spec: RFC 1035 §2.3.4, §4.2.1, §4.2.2.
const fn message_bound(transport: Transport) -> u32 {
    match transport {
        Transport::Udp => MAX_UDP_MESSAGE,
        Transport::Tcp => MAX_MESSAGE,
    }
}

// ---- requests --------------------------------------------------------------

/// The messages dnsd sends (`DescribeZone` retired — module
/// documentation).
/// Spec: docs/54 §4.6; A-140; A-152 (Q-922).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRequest {
    /// Peer verification on every new connection, and health check.
    Ping,
    /// The zone image, unless `have` is its current SERIAL.
    FetchZoneImage {
        /// The SERIAL of the image dnsd answers from, if any.
        have: Option<Serial>,
    },
    /// One message for dird's PEP, with how it arrived.
    Forward(ForwardRequest),
}

impl MessageSet for DnsRequest {
    const KINDS: &'static [u8] = request_kind::ALL;

    fn kind(&self) -> u8 {
        match self {
            DnsRequest::Ping => request_kind::PING,
            DnsRequest::FetchZoneImage { .. } => request_kind::FETCH_ZONE_IMAGE,
            DnsRequest::Forward(_) => request_kind::FORWARD,
        }
    }

    /// Spec: module table; docs/50 §3.3.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            DnsRequest::Ping => Ok(()),
            DnsRequest::FetchZoneImage { have } => writer
                .write_option(have.as_ref(), |writer, serial| {
                    write_serial(writer, *serial)
                }),
            DnsRequest::Forward(forward) => {
                write_transport(writer, forward.transport())?;
                write_peer(writer, forward.peer())?;
                write_message(
                    writer,
                    forward.message(),
                    message_bound(forward.transport()),
                )
            }
        }
    }

    /// Spec: module table; docs/50 §3.3.
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<DnsRequest> {
        match kind {
            request_kind::PING => Ok(DnsRequest::Ping),
            request_kind::FETCH_ZONE_IMAGE => Ok(DnsRequest::FetchZoneImage {
                have: reader.read_option(read_serial)?,
            }),
            request_kind::FORWARD => {
                let transport = read_transport(reader)?;
                let peer = read_peer(reader)?;
                let message = read_message(reader, message_bound(transport))?;
                ForwardRequest::new(transport, peer, message)
                    .map(DnsRequest::Forward)
                    .ok_or(Error::LengthOverBound)
            }
            _ => Err(Error::UnknownKind),
        }
    }
}

// ---- replies ---------------------------------------------------------------

/// The messages dird sends (`ZoneDescription` retired — module
/// documentation).
/// Spec: docs/54 §4.6; A-140; A-152 (Q-922).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsReply {
    /// The reply to `Ping`: the zone dird assigned this connection from
    /// dnsd's peer uid.
    Pong {
        /// The connection's zone.
        zone: FrontZone,
    },
    /// The reply to `FetchZoneImage { have }` when `have` is current.
    Unchanged {
        /// The current SERIAL (equal to `have`).
        serial: Serial,
    },
    /// One chunk of the reply to `FetchZoneImage`.
    ImageChunk(ImageChunk),
    /// The reply to `Forward`.
    Forwarded(Forwarded),
}

impl MessageSet for DnsReply {
    const KINDS: &'static [u8] = reply_kind::ALL;

    fn kind(&self) -> u8 {
        match self {
            DnsReply::Pong { .. } => reply_kind::PONG,
            DnsReply::Unchanged { .. } => reply_kind::UNCHANGED,
            DnsReply::ImageChunk(_) => reply_kind::IMAGE_CHUNK,
            DnsReply::Forwarded(_) => reply_kind::FORWARDED,
        }
    }

    /// Spec: module table; docs/50 §3.3.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            DnsReply::Pong { zone } => writer.write_enum(zone.code()),
            DnsReply::Unchanged { serial } => write_serial(writer, *serial),
            DnsReply::ImageChunk(chunk) => {
                // Never produce a chunk the peer would refuse.
                if !chunk_is_valid(chunk.octets().len(), chunk.more()) {
                    return Err(Error::LengthOverBound);
                }
                writer.write_bytes(chunk.octets(), MAX_IMAGE_CHUNK)?;
                writer.write_bool(chunk.more())
            }
            DnsReply::Forwarded(forwarded) => {
                writer.write_option(forwarded.reply.as_ref(), |writer, reply| {
                    write_message(writer, reply, MAX_MESSAGE)
                })?;
                write_serial(writer, forwarded.serial)
            }
        }
    }

    /// Spec: module table; docs/50 §3.3 (replies decoded with the same
    /// strictness as requests).
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<DnsReply> {
        match kind {
            reply_kind::PONG => Ok(DnsReply::Pong {
                zone: reader.read_enum(FrontZone::from_code)?,
            }),
            reply_kind::UNCHANGED => Ok(DnsReply::Unchanged {
                serial: read_serial(reader)?,
            }),
            reply_kind::IMAGE_CHUNK => {
                let octets = reader.read_bytes(MAX_IMAGE_CHUNK)?;
                let more = reader.read_bool()?;
                // An empty chunk, or a short chunk that says more follows, is
                // outside the field's bound for that marker.
                ImageChunk::new(octets, more)
                    .map(DnsReply::ImageChunk)
                    .ok_or(Error::LengthOverBound)
            }
            reply_kind::FORWARDED => {
                let reply = reader.read_option(|reader| read_message(reader, MAX_MESSAGE))?;
                let serial = read_serial(reader)?;
                Ok(DnsReply::Forwarded(Forwarded { reply, serial }))
            }
            _ => Err(Error::UnknownKind),
        }
    }
}
