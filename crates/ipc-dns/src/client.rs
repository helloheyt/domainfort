//! dnsd's side: a synchronous client of the dird-dns channel (crate API only
//! — dnsd itself is task DN11). It links no store, no keyd and no Kerberos
//! crypto (tests/no_store_dependency.rs).
//!
//! # Connections
//!
//! [`Connector`] opens a connection; [`Connection`] reports the peer's uid
//! (from the transport's peer credentials — never from anything the peer
//! sends), writes one whole frame, reads exactly one frame (its declared
//! length checked against the bound before the body is awaited), and says —
//! without blocking or sending — whether a held connection is still usable.
//! Tests use an in-process loopback; dnsd a blocking Unix stream socket
//! (`crate::unix`).
//!
//! # The peer is verified on every connection, by construction (C12)
//!
//! A [`DnsClient`] cannot be built without an [`ExpectedDird`]: dird's uid
//! and the [`FrontZone`] dird must have assigned **this** process. On every
//! new connection — the first and every reconnection — the client checks,
//! **before** anything else is sent on it:
//!
//! 1. the peer uid is dird's (docs/50 R50-3: a process that captured the
//!    socket path receives no request — not one forwarded message);
//! 2. dird answers `Ping` with a `Pong` naming the expected zone: the zone
//!    dird derived for this connection from dnsd's peer uid (docs/54 §4.6:
//!    "dnsd verifies dird's uid **and** a `Pong` carrying the zone dird
//!    assigned it … there is no client without an expectation (C12)").
//!
//! Anything else — another uid, another zone, a refusal or failure of the
//! probe — drops the connection and the call is not sent. There is no
//! constructor without the expectation and nothing to switch it off (the
//! pattern of crates/ipc-keyd `ExpectedPeer` and crates/ipc-audit
//! `ExpectedAuditd`). Every later `Pong` must name the same zone.
//!
//! # One request in flight; a held connection is checked; no resend
//!
//! Strict request → reply, one request in flight per connection (docs/54
//! §4.6). Before a call reuses the connection it holds, the client asks it,
//! without blocking and without sending, whether it is still usable
//! ([`Connection::check_idle`] — no default: every connection decides); a
//! dead or misbehaving one is dropped and a fresh one opened — and verified —
//! before the request is sent. A request is never sent twice: once written,
//! any failure ends the call (dird may already have committed a forwarded
//! UPDATE; its audit trail says so) and the next call starts over. For a
//! forwarded message dnsd then answers SERVFAIL (docs/54 §6.6, last row);
//! the observed client's UPDATE is idempotent (docs/research/r3-c-dns.md
//! §4.1, residual (a)).
//!
//! # What the caller sees
//!
//! | what happened | result |
//! |---|---|
//! | connect, I/O, peer closed, deadline | `Err(Unserved::Transport)` |
//! | peer uid unreadable or not dird's (nothing sent) | `Err(Unserved::Transport(PeerCredentials))` / `Err(Unserved::PeerMismatch)` |
//! | the `Pong` named another zone (only the `Ping` was sent) | `Err(Unserved::ZoneMismatch)` |
//! | the shared `Refused` (Busy, Unavailable, Malformed, VersionMismatch) | `Err(Unserved::Refused)` |
//! | a reply that does not decode | `Err(Unserved::MalformedReply)` |
//! | a reply that does not answer the request | `Err(Unserved::UnexpectedReply)` |
//! | image chunks over the bound, or an image that does not decode or is not a valid zone | `Err(Unserved::InvalidImage)` |
//! | dird's answer | `Ok(…)` |
//!
//! Spec: docs/54 §4.4, §4.6, §4.8, §6.6; docs/50 R50-3, R50-7, R50-8, §3.6,
//! §3.7; docs/52 §3.12 (C12); docs/questions/Q-312 (A-82: idle check, no
//! resend).

use crate::channel::{DNS_CHANNEL, REPLY_LIMIT};
use crate::image::{ImageAssembly, ImageError};
use crate::values::{ForwardRequest, Forwarded, FrontZone, Serial, ZoneDescription};
use crate::wire::{DnsReply, DnsRequest};
use core::fmt;
use core::time::Duration;
use dns_zone::ZoneImage;
use ipc::{decode_reply, encode_frame, Direction, FrameLimit, Refused};
use std::time::Instant;
use zeroize::Zeroizing;

/// A transport failure. Carries no octet of any frame.
/// Spec: docs/50 §3.6, §3.7, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// The connection could not be opened.
    Connect,
    /// The peer's credentials could not be read (or are not available on
    /// this platform — fail closed).
    PeerCredentials,
    /// The peer closed the connection.
    Closed,
    /// The deadline passed before the exchange completed.
    DeadlineExceeded,
    /// Another I/O failure.
    Io,
    /// A frame did not frame (bad length prefix, over the bound), or an
    /// octet arrived on an idle connection.
    Framing,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TransportError::Connect => "dird dns connection could not be opened",
            TransportError::PeerCredentials => "dird peer credentials unavailable",
            TransportError::Closed => "dird closed the connection",
            TransportError::DeadlineExceeded => "dird deadline exceeded",
            TransportError::Io => "dird connection I/O failure",
            TransportError::Framing => "dird frame did not frame",
        })
    }
}

impl std::error::Error for TransportError {}

/// One open connection to dird's DNS socket.
/// Spec: docs/50 §3.1, §3.2, §3.6.
pub trait Connection {
    /// The uid of the process at the other end, from the transport's peer
    /// credentials — never from anything the peer sends.
    /// Spec: docs/50 R50-3, §3.2; docs/54 §4.6.
    fn peer_uid(&self) -> Result<u32, TransportError>;

    /// Write one whole frame (length prefix included) within `deadline`.
    /// Spec: docs/50 §3.6.
    fn send(&mut self, frame: &[u8], deadline: Duration) -> Result<(), TransportError>;

    /// Read exactly one frame and return its body: never more octets than
    /// the frame needs; its declared length checked against `limit` before
    /// the body is awaited; within `deadline`.
    /// Spec: docs/50 §3.3 (bound before allocation), §3.6.
    fn receive(
        &mut self,
        limit: FrameLimit,
        deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError>;

    /// Check, before this held connection is reused, that it is still usable
    /// — without blocking and without sending anything (end of stream, a
    /// pending error or a waiting octet ⇒ `Err`). **No default**: every
    /// connection decides.
    /// Spec: docs/50 §3.6, §3.7; docs/questions/Q-312 (A-82), Q-466 item 4
    /// (A-102).
    fn check_idle(&mut self) -> Result<(), TransportError>;
}

/// Opens connections to dird's DNS socket.
/// Spec: docs/50 §3.1, §3.7.
pub trait Connector {
    /// The connection type.
    type Connection: Connection;

    /// Open a new connection.
    fn connect(&mut self) -> Result<Self::Connection, TransportError>;
}

/// The client was configured with an unacceptable expectation.
/// Spec: docs/50 §3.2 ("uid 0 is never mapped").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientConfigError {
    /// dird's uid cannot be 0: dird never runs as root after its hardening
    /// (docs/50 §6), and accepting uid 0 would accept any root process.
    RootServerUid,
}

/// What dnsd expects of dird on every connection: its uid, and the zone it
/// must have assigned this process (module documentation).
/// Spec: docs/54 §4.6; docs/50 R50-3; docs/52 §3.12 (C12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedDird {
    uid: u32,
    zone: FrontZone,
}

impl ExpectedDird {
    /// Expect dird to run as `uid` and to name `zone` in its `Pong`.
    ///
    /// # Errors
    /// [`ClientConfigError::RootServerUid`].
    ///
    /// Spec: docs/54 §4.6; docs/50 §3.2.
    pub const fn new(uid: u32, zone: FrontZone) -> Result<ExpectedDird, ClientConfigError> {
        if uid == 0 {
            return Err(ClientConfigError::RootServerUid);
        }
        Ok(ExpectedDird { uid, zone })
    }

    /// dird's uid.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// The zone dird must name.
    #[must_use]
    pub const fn zone(&self) -> FrontZone {
        self.zone
    }
}

/// Why dird did not serve a call (module documentation).
/// Spec: docs/50 §3.7 (R50-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unserved {
    /// The transport failed.
    Transport(TransportError),
    /// The peer's uid is not dird's; nothing was sent.
    PeerMismatch,
    /// dird's `Pong` named another zone; only the `Ping` was sent.
    ZoneMismatch,
    /// dird answered with the shared transport refusal.
    Refused(Refused),
    /// A reply did not decode at the ipc layer.
    MalformedReply(ipc::Error),
    /// A reply decoded but does not answer the request.
    UnexpectedReply,
    /// The image did not reassemble into a valid zone.
    InvalidImage(ImageError),
    /// The request could not be encoded; nothing was sent.
    Unencodable,
}

/// The answer to [`DnsClient::fetch_zone_image`].
/// Spec: docs/54 §4.4, §4.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageFetch {
    /// The image dnsd has (`have`) is current — SERIAL confirmed.
    Unchanged(Serial),
    /// A new, validated image (its SERIAL differs from `have`).
    Image(Box<ZoneImage>),
}

/// The time left of a call's `deadline` that started at `start`.
/// Spec: docs/50 §3.6.
fn remaining(start: Instant, deadline: Duration) -> Result<Duration, Unserved> {
    match deadline.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(Unserved::Transport(TransportError::DeadlineExceeded)),
    }
}

/// Decode one reply body strictly; the shared refusal is an error.
/// Spec: docs/50 §3.3 (replies decoded with the same strictness); A-59.
fn decode_one(body: &[u8]) -> Result<DnsReply, Unserved> {
    match decode_reply::<DnsReply>(DNS_CHANNEL, body).map_err(Unserved::MalformedReply)? {
        ipc::Reply::Refused(refused) => Err(Unserved::Refused(refused)),
        ipc::Reply::Message(reply) => Ok(reply),
    }
}

/// Whether a reply frame ends the call, or more frames follow.
enum Step<T> {
    More,
    Done(T),
}

/// The `Pong` of `zone` answers a `Ping` of a client expecting `expected`.
/// Spec: docs/54 §4.6.
fn check_pong(reply: DnsReply, expected: FrontZone) -> Result<(), Unserved> {
    match reply {
        DnsReply::Pong { zone } if zone == expected => Ok(()),
        DnsReply::Pong { .. } => Err(Unserved::ZoneMismatch),
        _ => Err(Unserved::UnexpectedReply),
    }
}

/// A synchronous client of dird's DNS channel (module documentation).
/// Spec: docs/54 §4.6; docs/50 R50-3, R50-7, §3.6, §3.7.
pub struct DnsClient<C: Connector> {
    connector: C,
    expected: ExpectedDird,
    deadline: Duration,
    connection: Option<C::Connection>,
}

impl<C: Connector> fmt::Debug for DnsClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsClient")
            .field("expected", &self.expected)
            .field("deadline", &self.deadline)
            .field("connected", &self.connection.is_some())
            .finish()
    }
}

impl<C: Connector> DnsClient<C> {
    /// A client of the dird `expected` describes, with a per-call `deadline`
    /// ([`crate::DEFAULT_DEADLINE`] unless dnsd chooses another).
    /// Spec: docs/54 §4.6; docs/50 §3.6.
    #[must_use]
    pub fn new(connector: C, expected: ExpectedDird, deadline: Duration) -> DnsClient<C> {
        DnsClient {
            connector,
            expected,
            deadline,
            connection: None,
        }
    }

    /// What this client expects of dird.
    #[must_use]
    pub fn expected(&self) -> ExpectedDird {
        self.expected
    }

    /// Whether a verified connection is held.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    /// The connector.
    pub fn connector(&self) -> &C {
        &self.connector
    }

    /// The held connection if it is still usable, or a new one that passed
    /// both checks — dird's uid, then a `Pong` naming the expected zone —
    /// before anything else was sent on it.
    /// Spec: docs/54 §4.6; docs/50 R50-3; docs/questions/Q-312 (A-82).
    fn verified(&mut self, start: Instant) -> Result<&mut C::Connection, Unserved> {
        let stale = match self.connection.as_mut() {
            Some(held) => held.check_idle().is_err(),
            None => false,
        };
        if stale {
            self.connection = None;
        }
        if self.connection.is_none() {
            let mut connection = self.connector.connect().map_err(Unserved::Transport)?;
            let uid = connection.peer_uid().map_err(Unserved::Transport)?;
            if uid != self.expected.uid {
                // Dropped here: nothing was sent on it.
                return Err(Unserved::PeerMismatch);
            }
            let ping = encode_frame(DNS_CHANNEL, Direction::Request, &DnsRequest::Ping)
                .map_err(|_| Unserved::Unencodable)?;
            connection
                .send(ping.as_bytes(), remaining(start, self.deadline)?)
                .map_err(Unserved::Transport)?;
            let body = connection
                .receive(REPLY_LIMIT, remaining(start, self.deadline)?)
                .map_err(Unserved::Transport)?;
            // Dropped on any failure: only the `Ping` was sent on it.
            check_pong(decode_one(&body)?, self.expected.zone)?;
            self.connection = Some(connection);
        }
        self.connection
            .as_mut()
            .ok_or(Unserved::Transport(TransportError::Connect))
    }

    /// Perform one call: encode, send on a verified connection, then read
    /// reply frames until `accept` says the call is done — all within the
    /// deadline. Any failure drops the connection; the request is never sent
    /// twice.
    /// Spec: docs/54 §4.6; docs/50 §3.3, §3.6, §3.7, R50-7.
    fn call<T>(
        &mut self,
        request: &DnsRequest,
        mut accept: impl FnMut(DnsReply) -> Result<Step<T>, Unserved>,
    ) -> Result<T, Unserved> {
        let result = self.call_inner(request, &mut accept);
        if result.is_err() {
            self.connection = None;
        }
        result
    }

    fn call_inner<T>(
        &mut self,
        request: &DnsRequest,
        accept: &mut impl FnMut(DnsReply) -> Result<Step<T>, Unserved>,
    ) -> Result<T, Unserved> {
        let start = Instant::now();
        let frame = encode_frame(DNS_CHANNEL, Direction::Request, request)
            .map_err(|_| Unserved::Unencodable)?;
        let deadline = self.deadline;
        let connection = self.verified(start)?;
        connection
            .send(frame.as_bytes(), remaining(start, deadline)?)
            .map_err(Unserved::Transport)?;
        drop(frame);
        // Bounded: every reply but an image chunk ends the call, and the
        // assembly refuses chunks past the image bound; the deadline bounds
        // the time.
        loop {
            let body = connection
                .receive(REPLY_LIMIT, remaining(start, deadline)?)
                .map_err(Unserved::Transport)?;
            match accept(decode_one(&body)?)? {
                Step::More => continue,
                Step::Done(value) => return Ok(value),
            }
        }
    }

    /// The health check: `Ping` → a `Pong` naming the expected zone.
    ///
    /// # Errors
    /// [`Unserved`].
    ///
    /// Spec: docs/54 §4.6; docs/50 §7.5.
    pub fn ping(&mut self) -> Result<(), Unserved> {
        let zone = self.expected.zone;
        self.call(&DnsRequest::Ping, |reply| {
            check_pong(reply, zone).map(Step::Done)
        })
    }

    /// The zone's apex and SERIAL.
    ///
    /// # Errors
    /// [`Unserved`].
    ///
    /// Spec: docs/54 §4.6, §4.8.
    pub fn describe_zone(&mut self) -> Result<ZoneDescription, Unserved> {
        self.call(&DnsRequest::DescribeZone, |reply| match reply {
            DnsReply::ZoneDescription(description) => Ok(Step::Done(description)),
            _ => Err(Unserved::UnexpectedReply),
        })
    }

    /// The zone image, unless `have` (the SERIAL of the image dnsd answers
    /// from) is current. A new image is returned only whole and validated by
    /// `ZoneImage::new`; its SERIAL differs from `have`.
    ///
    /// # Errors
    /// [`Unserved`]; an `Unchanged` that does not confirm `have`, a chunk
    /// after `Unchanged`, or an image whose SERIAL equals `have` is
    /// [`Unserved::UnexpectedReply`].
    ///
    /// Spec: docs/54 §4.4 (refresh by SERIAL; atomic replacement), §4.6.
    pub fn fetch_zone_image(&mut self, have: Option<Serial>) -> Result<ImageFetch, Unserved> {
        let mut assembly = ImageAssembly::new();
        self.call(&DnsRequest::FetchZoneImage { have }, |reply| match reply {
            DnsReply::Unchanged { serial } if have == Some(serial) && !assembly.is_started() => {
                Ok(Step::Done(ImageFetch::Unchanged(serial)))
            }
            DnsReply::ImageChunk(chunk) => {
                match assembly.push(&chunk).map_err(Unserved::InvalidImage)? {
                    None => Ok(Step::More),
                    Some(image) if have.map(Serial::get) == Some(image.serial()) => {
                        Err(Unserved::UnexpectedReply)
                    }
                    Some(image) => Ok(Step::Done(ImageFetch::Image(Box::new(image)))),
                }
            }
            _ => Err(Unserved::UnexpectedReply),
        })
    }

    /// Hand one message to dird's PEP and return its answer.
    ///
    /// # Errors
    /// [`Unserved`]; dnsd answers the client SERVFAIL (docs/54 §6.6).
    ///
    /// Spec: docs/54 §4.5, §4.6; A-140; RFC 2136 §6.4.
    pub fn forward(&mut self, request: &ForwardRequest) -> Result<Forwarded, Unserved> {
        self.call(&DnsRequest::Forward(request.clone()), |reply| match reply {
            DnsReply::Forwarded(forwarded) => Ok(Step::Done(forwarded)),
            _ => Err(Unserved::UnexpectedReply),
        })
    }
}
