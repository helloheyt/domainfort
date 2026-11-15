#![forbid(unsafe_code)]
//! `ipc-dns-server`: dird's side of the dnsd ↔ dird channel (docs/54 §4.6,
//! as amended by decision A-140; build task DN7).
//!
//! [`DnsConnection`] is the state of **one** channel connection from dnsd.
//! [`DnsConnection::handle`] decodes one request body, asks the host
//! ([`ZoneHost`] — dird) for the answer, and encodes the reply. It holds no
//! socket, no thread, no clock, no directory and no keyd client: dird (task
//! DN10) owns those — its DNS thread with the bounded queue, the zone
//! projection over its authority snapshot (docs/54 §4.4), and the DNS PEP
//! (task DN8: TSIG through keyd, the `(TKEY peer, key_name)` context table,
//! the PDP, the one write checker, audit before commit).
//!
//! # The connection's zone (docs/52 §3.3 C3, §7 R14)
//!
//! The zone is fixed when the connection is made — [`DnsConnection::new`]
//! takes a [`FrontZone`], which dird derives from the **peer uid** of the
//! channel connection (dnsd's identity, a kernel fact: docs/50 R50-3) through
//! [`DnsFronts`] before any frame is read; a peer that is not dnsd is closed
//! without a reply. dird holds no zone table (A-114): phase 1 has one dnsd,
//! internal only. Every `Pong` names that zone, so dnsd can refuse a dird
//! that would treat it as another front (docs/54 §4.6; the R9b pattern), and
//! every forwarded message reaches the host with it.
//!
//! # Requests
//!
//! | request | host call | reply |
//! |---|---|---|
//! | `Ping` | — | `Pong { zone: the connection's zone }` |
//! | `DescribeZone` | [`ZoneHost::describe_zone`] | `ZoneDescription { apex, serial }` |
//! | `FetchZoneImage { have }` | [`ZoneHost::zone_image`] | the host's `Unchanged(s)` with `have == Some(s)` ⇒ `Unchanged { s }`; an image whose SERIAL equals `have` ⇒ `Unchanged`; another image ⇒ its `ImageChunk` frames; an `Unchanged(s)` with `have ≠ Some(s)` ⇒ `Refused{Unavailable}` + close (the host contradicts the request — fail closed) |
//! | `Forward { transport, peer, message }` | [`ZoneHost::forward`] with the connection's zone | `Forwarded { reply, serial }` — `reply: None` tells dnsd to stay silent (UDP) or to close without a reply (TCP) |
//!
//! A request that does not decode follows docs/50 §3.3: a wrong magic, an
//! unknown kind or a body outside the envelope bounds ⇒ close without a
//! reply; another version ⇒ `Refused{VersionMismatch}` + close; a payload
//! error ⇒ `Refused{Malformed}` + close — nothing malformed reaches the host.
//! A host refusal ([`Unserved::Busy`] — dird's bounded DNS queue is full;
//! [`Unserved::Unavailable`] — a dependency or the image is not available)
//! ⇒ the shared `Refused{Busy}` / `Refused{Unavailable}` + close; dnsd
//! answers its client SERVFAIL (docs/54 §4.6, §6.6) and its next call
//! reconnects and verifies again. Once closed, a connection answers nothing.
//!
//! Spec: docs/54 §4.4, §4.6, §6.6; A-114; A-140; docs/50 R50-3, R50-7, §3.2,
//! §3.3, §7.5; docs/52 §3.3, §7 R14; A-59.
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session
//! (docs/54, docs/research/r3-c-dns.md, docs/50, docs/questions
//! PENDING-OWNER A-114, A-119, A-140, Q-613, Q-619, Q-810, Q-815) and the
//! public API of this project's crates ipc and ipc-dns (ipc-ldap-server as
//! the pattern). No other implementation, DNS server or RPC framework was
//! consulted or recalled (AGENTS.md §1-3).

use core::fmt;
use ipc::{EncodedFrame, Refused};
use ipc_dns::{
    decode_request, encode_image_chunks, encode_refusal, encode_reply, DnsReply, DnsRequest,
    ForwardRequest, Forwarded, FrontZone, ImageTransfer, Rejection, Serial, ZoneDescription,
};

/// The connection a request came on, as dird numbers them (never anything
/// the peer sent) — for dird's own bookkeeping and audit records.
/// Spec: docs/50 §3.2.
pub type ConnectionId = u64;

/// The dnsd front dird admits on `dird-dns.sock`, by peer uid (docs/54 §4.6:
/// "dird accepts only `dnsd_uid` (R50-3)"): phase 1 has one, the internal
/// one (A-114).
/// Spec: docs/54 §4.6; docs/50 R50-3, §3.2; docs/52 §7 R14.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsFronts {
    internal: u32,
}

impl DnsFronts {
    /// The fronts of a dird whose dnsd runs as `dnsd_uid` (dird's
    /// configuration, docs/questions/Q-619 item 5).
    /// Spec: docs/54 §4.6.
    #[must_use]
    pub const fn new(dnsd_uid: u32) -> DnsFronts {
        DnsFronts { internal: dnsd_uid }
    }

    /// The zone of the dnsd whose channel connection has the peer uid
    /// `peer_uid` (read from the kernel's peer credentials, never from the
    /// peer), or `None`: not dnsd — the connection is closed without a
    /// reply. uid 0 is never a front (R50-3: "uid 0 is never mapped").
    /// Spec: docs/50 R50-3, §3.2; docs/54 §4.6; A-114.
    #[must_use]
    pub const fn zone_of(&self, peer_uid: u32) -> Option<FrontZone> {
        if peer_uid != 0 && peer_uid == self.internal {
            Some(FrontZone::Internal)
        } else {
            None
        }
    }
}

/// Why the host did not answer a request (module documentation).
/// Spec: docs/54 §4.6 ("queue full ⇒ `Busy` ⇒ dnsd answers SERVFAIL");
/// docs/50 R50-7, §3.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unserved {
    /// dird's bounded DNS queue is full.
    Busy,
    /// A dependency the request needs (keyd, auditd, the store, the zone
    /// projection) is not available.
    Unavailable,
}

/// The host's answer to `FetchZoneImage { have }`.
/// Spec: docs/54 §4.4, §4.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageAnswer {
    /// The zone's SERIAL is `have` — nothing to send.
    Unchanged(Serial),
    /// The zone's current image, validated and divided ([`ImageTransfer`]
    /// is built only from parts `ZoneImage::new` accepts).
    Image(ImageTransfer),
}

/// What dird supplies for the requests of dnsd's connections (task DN10).
/// Spec: docs/54 §4.4–§4.6, §7.5.
pub trait ZoneHost {
    /// The zone's apex and current SERIAL.
    ///
    /// # Errors
    /// [`Unserved`].
    ///
    /// Spec: docs/54 §4.6.
    fn describe_zone(&mut self) -> Result<ZoneDescription, Unserved>;

    /// The zone image, or `Unchanged` when `have` is the current SERIAL —
    /// from one authority snapshot through dird's one zone projection
    /// (docs/54 §4.4).
    ///
    /// # Errors
    /// [`Unserved`].
    ///
    /// Spec: docs/54 §4.4, §4.6.
    fn zone_image(&mut self, have: Option<Serial>) -> Result<ImageAnswer, Unserved>;

    /// Run dird's DNS PEP over one forwarded message — the order of docs/54
    /// §7.5 (key, MAC in keyd, time, then Subject, PDP, the structural
    /// self-only check, RFC 2136), with the context looked up under
    /// `(request.peer(), key_name)` and a UDP message on no context of its
    /// address answered with silence (A-140) — and return the DNS reply (or
    /// `None`) and the zone's SERIAL after it.
    ///
    /// # Errors
    /// [`Unserved`].
    ///
    /// Spec: docs/54 §4.5, §7.5; A-140; docs/research/r3-c-dns.md §4.1 (d),
    /// §4.4.
    fn forward(&mut self, zone: FrontZone, request: &ForwardRequest)
        -> Result<Forwarded, Unserved>;
}

/// What to send, and whether the connection then closes.
/// Spec: docs/50 §3.3 (bad prefix, wrong magic, unknown kind ⇒ close without
/// a reply; wrong version ⇒ `Refused{VersionMismatch}` + close; malformed ⇒
/// `Malformed` + close).
pub enum Dispatch {
    /// Send the frames in order; the connection stays open.
    Reply(Vec<EncodedFrame>),
    /// Send the frames in order, then close the connection.
    ReplyAndClose(Vec<EncodedFrame>),
    /// Close the connection without a reply.
    Close,
}

impl fmt::Debug for Dispatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dispatch::Reply(frames) => f.debug_tuple("Reply").field(&frames.len()).finish(),
            Dispatch::ReplyAndClose(frames) => {
                f.debug_tuple("ReplyAndClose").field(&frames.len()).finish()
            }
            Dispatch::Close => f.write_str("Close"),
        }
    }
}

impl Dispatch {
    /// The frames to send (none for [`Dispatch::Close`]).
    #[must_use]
    pub fn frames(&self) -> &[EncodedFrame] {
        match self {
            Dispatch::Reply(frames) | Dispatch::ReplyAndClose(frames) => frames,
            Dispatch::Close => &[],
        }
    }

    /// Whether the connection closes after the frames.
    #[must_use]
    pub fn closes(&self) -> bool {
        !matches!(self, Dispatch::Reply(_))
    }
}

/// The shared refusal frame, then close; a refusal that cannot be encoded
/// (never, given ipc's minimum body bound) closes without a reply.
/// Spec: docs/50 §3.3; A-59.
#[must_use]
pub fn refuse(refused: Refused) -> Dispatch {
    match encode_refusal(refused) {
        Ok(frame) => Dispatch::ReplyAndClose(vec![frame]),
        Err(_) => Dispatch::Close,
    }
}

/// One channel connection from dnsd (module documentation).
/// Spec: docs/54 §4.6; docs/52 R14.
pub struct DnsConnection {
    id: ConnectionId,
    /// The zone of the front this connection came from — fixed at
    /// construction, from the peer uid.
    zone: FrontZone,
    closed: bool,
}

impl fmt::Debug for DnsConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsConnection")
            .field("id", &self.id)
            .field("zone", &self.zone)
            .field("closed", &self.closed)
            .finish()
    }
}

impl DnsConnection {
    /// A new connection numbered `id` by dird, from the front of `zone`
    /// ([`DnsFronts::zone_of`] the connection's peer uid).
    /// Spec: docs/54 §4.6; docs/50 §3.2; docs/52 §7 R14.
    #[must_use]
    pub fn new(id: ConnectionId, zone: FrontZone) -> DnsConnection {
        DnsConnection {
            id,
            zone,
            closed: false,
        }
    }

    /// dird's number for this connection.
    #[must_use]
    pub fn id(&self) -> ConnectionId {
        self.id
    }

    /// The zone of the front this connection came from.
    #[must_use]
    pub fn zone(&self) -> FrontZone {
        self.zone
    }

    /// Whether the connection is over (nothing more is processed).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Close and send `refused`.
    fn refuse(&mut self, refused: Refused) -> Dispatch {
        self.closed = true;
        refuse(refused)
    }

    /// Frames that keep the connection open; frames that do not encode
    /// (cannot happen with the value types) fail closed.
    fn reply(&mut self, frames: Result<Vec<EncodedFrame>, ipc::Error>) -> Dispatch {
        match frames {
            Ok(frames) => Dispatch::Reply(frames),
            Err(_) => self.refuse(Refused::Unavailable),
        }
    }

    /// One reply message.
    fn reply_one(&mut self, reply: &DnsReply) -> Dispatch {
        let frame = encode_reply(reply).map(|frame| vec![frame]);
        self.reply(frame)
    }

    /// A host refusal: the shared refusal, then close.
    fn unserved(&mut self, unserved: Unserved) -> Dispatch {
        self.refuse(match unserved {
            Unserved::Busy => Refused::Busy,
            Unserved::Unavailable => Refused::Unavailable,
        })
    }

    /// Handle one request body (module documentation).
    /// Spec: docs/54 §4.4, §4.6; docs/50 §3.3; A-59; A-140.
    pub fn handle(&mut self, body: &[u8], host: &mut dyn ZoneHost) -> Dispatch {
        if self.closed {
            return Dispatch::Close;
        }
        let request = match decode_request(body) {
            Ok(request) => request,
            Err(Rejection::Close) => {
                self.closed = true;
                return Dispatch::Close;
            }
            Err(Rejection::Refuse(refused)) => return self.refuse(refused),
        };
        match request {
            DnsRequest::Ping => self.reply_one(&DnsReply::Pong { zone: self.zone }),
            DnsRequest::DescribeZone => match host.describe_zone() {
                Ok(description) => self.reply_one(&DnsReply::ZoneDescription(description)),
                Err(unserved) => self.unserved(unserved),
            },
            DnsRequest::FetchZoneImage { have } => match host.zone_image(have) {
                Ok(ImageAnswer::Unchanged(serial)) if have == Some(serial) => {
                    self.reply_one(&DnsReply::Unchanged { serial })
                }
                // The host says "unchanged" for a SERIAL dnsd does not have:
                // the answer contradicts the request — fail closed.
                Ok(ImageAnswer::Unchanged(_)) => self.refuse(Refused::Unavailable),
                // dnsd already has this image.
                Ok(ImageAnswer::Image(transfer)) if have == Some(transfer.serial()) => self
                    .reply_one(&DnsReply::Unchanged {
                        serial: transfer.serial(),
                    }),
                Ok(ImageAnswer::Image(transfer)) => {
                    let frames = encode_image_chunks(&transfer);
                    self.reply(frames)
                }
                Err(unserved) => self.unserved(unserved),
            },
            DnsRequest::Forward(forward) => match host.forward(self.zone, &forward) {
                Ok(forwarded) => self.reply_one(&DnsReply::Forwarded(forwarded)),
                Err(unserved) => self.unserved(unserved),
            },
        }
    }
}
