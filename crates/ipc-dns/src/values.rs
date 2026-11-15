//! The channel's value types. Each one can hold only a value the channel
//! admits, so a value that would be refused on the wire cannot be built in
//! the first place (docs/CLEAN-ROOM.md — unrepresentable states), and the
//! decoder and the constructors apply the same rules.
//!
//! Spec: docs/54 §4.6; docs/research/r3-c-dns.md §4.1, §4.4 (A-140);
//! docs/50 §3.3 ("a single encoding per value").

use crate::channel::{codes, MAX_MESSAGE, MIN_MESSAGE};
use core::fmt;
use core::net::IpAddr;
use core::num::NonZeroU32;
use parse_dns::Transport;
use zeroize::Zeroizing;

/// A zone SERIAL as the channel carries it: never zero.
///
/// Spec: RFC 2136 §7.11 ("A zone's SOA SERIAL should never be set to zero
/// (0)"); docs/54 §5.4; dns-zone `ZoneImageError::SerialZero`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Serial(NonZeroU32);

impl Serial {
    /// The SERIAL `value`, or `None` for zero.
    /// Spec: RFC 2136 §7.11.
    #[must_use]
    pub const fn new(value: u32) -> Option<Serial> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Serial(value)),
            None => None,
        }
    }

    /// The SERIAL as an integer (never zero).
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// The zone of the dnsd front, as dird derives it from the peer uid of the
/// channel connection (a kernel fact, docs/50 R50-3) and names it in every
/// `Pong`; dnsd refuses a dird that names another (docs/54 §4.6: "`Pong`
/// carrying the zone dird assigned … the client refuses anything else" —
/// the R14 + R9b pattern). Phase 1 has one dnsd and only the internal zone
/// (A-114: "phase 1: one dnsd, internal only"); an external zone has no code
/// path.
///
/// Spec: docs/54 §4.6; docs/52 §7 R14; A-114; A-115 (R9b).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrontZone {
    /// The internal front: dnsd listens only on addresses inside
    /// `internal_networks` and serves only sources inside them (A-114).
    Internal,
}

impl FrontZone {
    /// The wire code. Spec: docs/50 §3.3.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            FrontZone::Internal => codes::ZONE_INTERNAL,
        }
    }

    /// Code → zone (closed table).
    #[must_use]
    pub const fn from_code(code: u8) -> Option<FrontZone> {
        match code {
            codes::ZONE_INTERNAL => Some(FrontZone::Internal),
            _ => None,
        }
    }
}

/// The source IP address of a forwarded message, as dnsd's socket observed
/// it — always the canonical form: an IPv4-mapped IPv6 address is held as
/// the IPv4 address it maps, so one host has one spelling on the channel.
///
/// **Whose fact this is.** dnsd owns the client's socket, so the source
/// address is dnsd's kernel-observed fact — it has no other owner
/// (docs/research/r3-c-dns.md §6 W21). dird uses it as part of the key of its
/// GSS context table, `(TKEY peer, key_name)`: a context is established only
/// by a TKEY over TCP, whose handshake proved the address, and a signed
/// UPDATE over UDP is accepted only on a context of the same address
/// (A-140; r3-c §4.1 (d), §4.4 item 1). The canonical form keeps that
/// comparison exact whatever socket family dnsd's TCP and UDP listeners use.
/// A compromised dnsd can report any address — the binding protects against
/// a network attacker spoofing a source, not against dnsd, which can answer
/// anything anyway (docs/54 §8, "dnsd compromised").
///
/// No port: the binding is to the address (the observed client used another
/// port for UDP than for TCP — r3-c §3 O-5), and nothing on dird's side needs
/// the port (RFC 2136 §3.8 sends the UDP response "to the requestor's source
/// UDP port" — dnsd's job, which keeps it).
///
/// Spec: A-140; docs/research/r3-c-dns.md §4.1, §4.4, §6 W1, W21; RFC 3645
/// §4 ("The server maintains a mapping of key names to handles"); std 1.95.0
/// API documentation, `IpAddr::to_canonical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerAddress(IpAddr);

impl PeerAddress {
    /// The source address `address`, in canonical form (an IPv4-mapped IPv6
    /// address becomes its IPv4 address).
    /// Spec: type documentation.
    #[must_use]
    pub const fn new(address: IpAddr) -> PeerAddress {
        PeerAddress(address.to_canonical())
    }

    /// The address (canonical: never an IPv4-mapped IPv6 address).
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.0
    }
}

/// The octets of one DNS message, uninterpreted by this channel: at least a
/// header ([`MIN_MESSAGE`]) and at most [`MAX_MESSAGE`] octets. Held in a
/// zeroizing buffer; `Debug` shows only the length (docs/54 §9: message
/// octets, GSS tokens and MICs never in a log).
///
/// The channel never re-encodes a message: dnsd forwards the client's exact
/// octets because the TSIG MAC covers "the whole/complete DNS message in
/// wire format" (RFC 8945 §4.3.2), and a server sharing no secret with the
/// originator "MUST forward the message unchanged including the TSIG" (RFC
/// 8945 §5.5); dird parses the same octets keyd verifies the MAC over
/// (docs/54 §4.1, C2).
///
/// Spec: RFC 1035 §4.1.1, §4.2.2; RFC 8945 §4.3.2, §5.5; docs/54 §4.1, §4.6.
#[derive(Clone, PartialEq, Eq)]
pub struct DnsMessage(Zeroizing<Vec<u8>>);

impl DnsMessage {
    /// The message `octets`, or `None` if they are fewer than a header or
    /// more than [`MAX_MESSAGE`].
    /// Spec: RFC 1035 §4.1.1, §4.2.2.
    #[must_use]
    pub fn new(octets: &[u8]) -> Option<DnsMessage> {
        if octets.len() < MIN_MESSAGE || octets.len() > MAX_MESSAGE as usize {
            return None;
        }
        let mut buffer = Zeroizing::new(Vec::with_capacity(octets.len()));
        // Within the reserved capacity: no reallocation.
        buffer.extend_from_slice(octets);
        Some(DnsMessage(buffer))
    }

    /// The message octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Octets of the message.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: a message has at least its header.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for DnsMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsMessage")
            .field("len", &self.0.len())
            .finish()
    }
}

/// `Forward`: one message dnsd hands to dird's PEP, with the two facts dird
/// needs about how it arrived — the transport and the source address — and
/// nothing else (A-140; docs/research/r3-c-dns.md §5 row 2: `Forward {
/// transport, peer, message }`).
///
/// * **transport** — dird accepts a signed UPDATE over UDP only on a context
///   that a TKEY over TCP established from the same address, answers an
///   unmatched UDP UPDATE with silence (`reply: None`), and never runs a TKEY
///   that came over UDP (A-140: "TKEY only over TCP"; r3-c §4.1 (d) step 2).
/// * **peer** — the source address, the first half of dird's context-table
///   key ([`PeerAddress`]).
/// * **message** — the client's exact octets, at most what its transport
///   carries: 512 octets over UDP (RFC 1035 §2.3.4, §4.2.1), 65535 over TCP
///   (§4.2.2).
///
/// Spec: docs/54 §4.5, §4.6; A-140; RFC 2136 §2.1 ("may be carried in a UDP
/// datagram, if the request fits, or in a TCP connection"); RFC 1035 §4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRequest {
    transport: Transport,
    peer: PeerAddress,
    message: DnsMessage,
}

impl ForwardRequest {
    /// The forward of `message`, received over `transport` from `peer`, or
    /// `None` if the message is longer than the transport carries.
    /// Spec: RFC 1035 §2.3.4, §4.2.1, §4.2.2.
    #[must_use]
    pub fn new(transport: Transport, peer: PeerAddress, message: DnsMessage) -> Option<Self> {
        if message.len() > transport.max_message_octets() {
            return None;
        }
        Some(ForwardRequest {
            transport,
            peer,
            message,
        })
    }

    /// The transport the message arrived on.
    #[must_use]
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// The source address the message came from.
    #[must_use]
    pub fn peer(&self) -> PeerAddress {
        self.peer
    }

    /// The message, exactly as received.
    #[must_use]
    pub fn message(&self) -> &DnsMessage {
        &self.message
    }
}

/// `Forwarded`: dird's answer to a `Forward` — the DNS reply dnsd sends to
/// the client, if any, and the zone's SERIAL after dird processed the
/// message.
///
/// * `reply: None` — send nothing: over TCP dnsd closes without a reply;
///   over UDP it stays silent (docs/54 §4.6: "`None` ⇒ dnsd closes without a
///   reply"; A-140: a UDP UPDATE on no context of its address ⇒ silence — a
///   reply would go to an address nothing proved).
/// * `serial` — when it differs from the image dnsd answers from, dnsd fetches
///   the new image **before** it sends the reply (docs/54 §4.4 (a); RFC 2136
///   §3.6: "If the zone appears to change, the SOA must appear to change as
///   well").
///
/// The UDP size rule for the reply (≤ the request, A-140) is **not** applied
/// here: it is applied in its one construction place, dns-zone's reply
/// constructor for forwarded replies (A-124 pattern; docs/research/
/// r3-c-dns.md R3C-10, task DR2), so the channel carries no second copy of
/// the rule (docs/questions/Q-920 item 4).
///
/// Spec: docs/54 §4.4, §4.6; A-140; RFC 2136 §3.5 ("commit the change … before
/// sending a response"), §3.6, §6.4 ("The forwarder will not respond to its
/// requestor until it receives a response").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forwarded {
    /// The DNS reply for the client, or `None` (send nothing).
    pub reply: Option<DnsMessage>,
    /// The zone's SERIAL after dird processed the message.
    pub serial: Serial,
}
