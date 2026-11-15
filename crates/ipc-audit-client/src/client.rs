//! The one audit client: a sender's link to auditd over `audit.sock` — the
//! single implementation for every daemon that sends events (keyd, the kdc,
//! dird, admind) and for ldap-front's start-up check (task R9b, docs/52
//! §3.12 C12, docs/questions/Q-512, Q-560). In crate ipc-audit-client, with
//! a non-optional tokio (task IB1, docs/questions/Q-851, A-144); auditd does
//! not link it.
//!
//! # The class it closes (docs/CLEAN-ROOM.md)
//!
//! * **C12 — "the peer's identity is verified by choice, or only in part".**
//!   Each daemon verified auditd's uid and a `Ping` → `Pong`, but the `Pong`
//!   carried nothing: a daemon could not tell an auditd whose `uid → source`
//!   map was cross-wired (this uid marked as another process). A-85's
//!   shape ↔ source binding refused most such events, but not a
//!   `WindowSummary` (accepted from any mapped source), and the failure read
//!   as "audit refused", not "auditd misconfigured" (Q-512 item 3).
//! * **Four copies of one mechanism.** keyd-daemon, kdc-daemon,
//!   directory-daemon and admin-daemon each had their own copy of this
//!   client (and ldap-front a fifth copy of its verification).
//!
//! # The peer is verified on every connection, by construction
//!
//! An [`AuditLink`] cannot be built without an [`ExpectedAuditd`]: auditd's
//! uid and the [`EventSource`] auditd must record **this** process's events
//! under. On every new connection — the first and every reconnection — the
//! link checks, **before anything else is sent on it**:
//!
//! 1. the peer uid is auditd's (docs/50 R50-3: "the client verifies the
//!    server's uid too") — a process that captured the socket path receives
//!    no request at all ([`AuditLinkError::PeerMismatch`]);
//! 2. auditd answers `Ping` with a `Pong` naming the expected source: the
//!    source auditd resolved for this connection's peer uid through its own
//!    map (docs/50 §3.2). Another source ⇒ the connection is dropped with no
//!    batch sent ([`AuditLinkError::SourceMismatch`]); an auditd that would
//!    record this process under another process's name never receives an
//!    event from it.
//!
//! Only an [`AuditConnection`] carries batches, and the only way to get one
//! is [`AuditLink::connect`], which made both checks. Every later `Pong`
//! (the heartbeat) must name the same source. There is no constructor
//! without the expectation and nothing to switch it off — the pattern of
//! task R9's `ExpectedPeer` (docs/questions/Q-510).
//!
//! While no verified connection exists the daemon's gate counts auditd as
//! unreachable, so gating operations are refused (A-57; A-67 item 2:
//! "auditd unreachable → every issuance is refused") — a cross-wired auditd
//! is, to the daemon, an unreachable one.
//!
//! # The client is the only source of the gate's evidence (task R15b)
//!
//! Whether auditd is reachable, and what auditd acknowledged, are the facts
//! an [`crate::AckedIntent`] rests on; their one owner is this client. The
//! gate's link side (reachability, the batch to send, the `Ack`, a lost
//! batch) is crate-private to ipc-audit-client, and only this module drives
//! it: a
//! daemon hands its gate and its verified start-up connection to
//! [`AuditLink::attach`] — which marks auditd reachable **because** that
//! connection was verified — and spawns [`AttachedLink::run`]. Nothing
//! else can open a gate or acknowledge (docs/questions/Q-630).
//!
//! # Delivery (as the four copies did)
//!
//! * **Strict request → reply.** One request in flight (docs/50 §3.6): an
//!   `Append` of the window's next batch, answered by `Ack` only after
//!   auditd synced it (§8.1); the reply is read
//!   with ipc's [`FrameReader`] under the reply bound and decoded with the
//!   same strictness as a request (§3.3).
//! * **The summary pace** (docs/questions/Q-989, A-165). A window that
//!   holds only counters leaves as a `WindowSummary` at most once per
//!   [`HEARTBEAT`] — the gate decides (`crate::gate`, "The summary pace"),
//!   and the link waits as long as the gate says; events are never held.
//!   So no sender's summaries follow auditd's acknowledgement rate.
//! * **Liveness.** When nothing is pending for [`HEARTBEAT`], a `Ping`; a
//!   connection that fails it, or any exchange, is dropped and auditd counts
//!   as unreachable until a verified connection is back (A-57;
//!   docs/questions/Q-260 item 2).
//! * **Reconnection** with a bounded, doubling backoff (docs/50 §3.7). The
//!   batch in flight goes back to the front of the window and is resent
//!   with the same sequence numbers (Q-252 item 7; auditd's resend check,
//!   A-101, recognises it).
//!
//! What stays each daemon's own ([`LinkedGate`]): its gate wrapper (the
//! shared [`AuditGate`] plus its event shapes — task R6), the tokio wake-up
//! its gate sends when an event was recorded, its operational notes, and the
//! source it expects.
//!
//! # Security
//!
//! No `unsafe`; no panic or `unwrap` on a network path; the reply's length
//! is checked against the channel's reply bound before any body octet is
//! read; no error or `Debug` output carries frame octets (docs/50 §8.2).
//!
//! # Provenance
//!
//! Moved from this repository's four daemon copies it replaces
//! (crates/keyd-daemon `audit_client.rs`, crates/kdc-daemon
//! `audit_client.rs`, crates/directory-daemon `audit_link.rs`,
//! crates/admin-daemon `audit_link.rs` — this project's code), with the
//! source check added, written only from docs/50 (R50-3, R50-16, R50-17,
//! §3.2, §3.3, §3.6, §3.7, §7.5, §8.1), docs/52 (§3.11, §3.12, §7 R9),
//! PENDING-OWNER (A-57, A-67, A-85, A-87, A-101, A-107, A-112),
//! docs/questions Q-218, Q-252, Q-260, Q-500, Q-502, Q-510, Q-512, and the
//! docs.rs API pages of tokio 1.54.1 (P-2): `net::UnixStream::{connect,
//! peer_cred}`, `net::unix::UCred::uid`, `time::{timeout, sleep}`,
//! `io::{AsyncReadExt::read, AsyncWriteExt::write_all}`. No other
//! implementation was consulted or recalled (docs/CLEAN-ROOM.md).
//!
//! Spec: docs/50 R50-3, R50-16, R50-17, §3.2, §3.3, §3.6, §3.7, §7.5, §8.1;
//! docs/52 §3.12 (C12); docs/questions/Q-218 (A-57), Q-252 (A-64), Q-260
//! (A-67), Q-512 (A-112), Q-560 (A-115), Q-570 §5 item a (A-118), Q-630,
//! Q-989 (A-165).

use crate::gate::{AuditGate, NextSend};
use core::fmt;
use core::future::Future;
use core::time::Duration;
use ipc::{Direction, FrameReader, Reply};
use ipc_audit::{
    decode_reply, encode_request, AuditReply, AuditRequest, EventSource, AUDIT_CHANNEL,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{sleep, timeout};

/// How long one exchange with auditd may take (connect, or write a request
/// and read its reply). auditd syncs each batch before it acknowledges, so
/// this is above the 2 s keyd client deadline. Project choice — docs/50 gives
/// no audit deadline (docs/questions/Q-260 item 4); the value of the four
/// copies this replaces.
pub const AUDIT_DEADLINE: Duration = Duration::from_secs(5);

/// Idle time after which the link checks auditd with a `Ping`. Project
/// choice (docs/questions/Q-260 item 4); the value of the four copies.
pub const HEARTBEAT: Duration = Duration::from_secs(1);

/// First and longest wait between reconnection attempts. Project choices
/// (docs/50 §3.7: "reconnection with bounded backoff").
const BACKOFF_MIN: Duration = Duration::from_millis(100);
const BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Octets read from the socket per read call at most. Project choice.
const READ_CHUNK: usize = 1024;

/// Where auditd listens and which uid it must run as — a daemon's
/// configuration (`audit_socket`, `auditd_uid`).
/// Spec: docs/50 R50-3, §2.4 (crates/config `Endpoint`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEndpoint {
    /// `audit_socket`.
    pub socket: PathBuf,
    /// `auditd_uid`.
    pub uid: u32,
}

/// Why auditd could not be verified or reached. Carries no octet of any
/// frame. Spec: docs/50 §3.7, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLinkError {
    /// The expected auditd uid is 0: auditd never runs as root after its
    /// hardening (docs/50 §6), and accepting uid 0 would accept any root
    /// process (as task R9's `ExpectedPeer`, docs/questions/Q-510 item 1).
    RootServerUid,
    /// The socket could not be connected.
    Connect,
    /// The peer credentials could not be read.
    PeerCredentials,
    /// The peer is not the configured auditd uid; nothing was sent.
    PeerMismatch,
    /// auditd records this process's events under another source than the
    /// expected one (its `uid → source` map is cross-wired); no batch was
    /// sent (task R9b, docs/questions/Q-512).
    SourceMismatch,
    /// The deadline passed.
    Deadline,
    /// auditd closed the connection.
    Closed,
    /// Another I/O failure.
    Io,
    /// The reply did not frame, did not decode, or did not answer the
    /// request.
    Protocol,
    /// auditd answered with the shared refusal.
    Refused,
}

impl fmt::Display for AuditLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AuditLinkError::RootServerUid => "auditd's uid cannot be 0",
            AuditLinkError::Connect => "audit socket could not be connected",
            AuditLinkError::PeerCredentials => "audit peer credentials unreadable",
            AuditLinkError::PeerMismatch => "audit peer is not the configured auditd uid",
            AuditLinkError::SourceMismatch => {
                "auditd records this process under another source; nothing was sent"
            }
            AuditLinkError::Deadline => "audit exchange deadline exceeded",
            AuditLinkError::Closed => "auditd closed the connection",
            AuditLinkError::Io => "audit connection I/O failure",
            AuditLinkError::Protocol => "audit reply refused",
            AuditLinkError::Refused => "auditd refused the request",
        })
    }
}

impl std::error::Error for AuditLinkError {}

/// The auditd an [`AuditLink`] expects at the other end of every
/// connection: auditd's uid, and the source auditd must record **this**
/// process's events under. The only input of [`AuditLink::new`] besides
/// the socket path: there is no link without it.
///
/// Spec: docs/50 R50-3, §3.2, §8.1; docs/52 §3.12; docs/questions/Q-510
/// item 1 (the pattern), Q-512 (A-112).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedAuditd {
    uid: u32,
    source: EventSource,
}

impl ExpectedAuditd {
    /// auditd runs as `auditd_uid` and records this process under `source`.
    ///
    /// # Errors
    /// [`AuditLinkError::RootServerUid`].
    ///
    /// Spec: docs/50 R50-3, §3.2 ("uid 0 is never mapped"); docs/questions/
    /// Q-510 item 1.
    pub fn new(auditd_uid: u32, source: EventSource) -> Result<ExpectedAuditd, AuditLinkError> {
        if auditd_uid == 0 {
            return Err(AuditLinkError::RootServerUid);
        }
        Ok(ExpectedAuditd {
            uid: auditd_uid,
            source,
        })
    }

    /// auditd's uid.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The source auditd must record this process under.
    #[must_use]
    pub fn source(&self) -> EventSource {
        self.source
    }
}

/// What a sending daemon gives its audit link ([`AuditLink::run`]): the
/// shared gate inside its own gate wrapper, the wake-up its wrapper sends
/// when an event was recorded, and its operational notes. Implemented by
/// each daemon's gate wrapper (task R6), which keeps its event shapes.
///
/// Spec: docs/52 §3.11 R6, §3.12; docs/questions/Q-500 item 1 (the wake-up
/// stays in the daemons), Q-560 item 4.
pub trait LinkedGate: Send + Sync {
    /// The shared gate (window, reachability, acknowledgements).
    fn audit_gate(&self) -> &AuditGate;

    /// Completes when an event was recorded into the window (or a stored
    /// wake-up is pending).
    fn recorded(&self) -> impl Future<Output = ()> + Send + '_;

    /// The link was verified again after a loss (the daemon's
    /// `AuditRestored` note).
    fn link_restored(&self);

    /// The verified connection was lost; auditd counts as unreachable (the
    /// daemon's `AuditLost` note).
    fn link_lost(&self);
}

/// The link to auditd: the socket and the expectation every connection is
/// verified against (module documentation).
///
/// Spec: docs/50 R50-3, R50-16, R50-17, §3.7, §8.1; docs/52 §3.12;
/// docs/questions/Q-512 (A-112).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLink {
    socket: PathBuf,
    expected: ExpectedAuditd,
}

/// A connection to auditd whose peer uid and reported source were verified
/// ([`AuditLink::connect`] — the only way to make one).
#[derive(Debug)]
pub struct AuditConnection {
    stream: UnixStream,
    expected: ExpectedAuditd,
}

/// The time left before `deadline` from `start`, or
/// [`AuditLinkError::Deadline`].
fn remaining(start: Instant, deadline: Duration) -> Result<Duration, AuditLinkError> {
    match deadline.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(AuditLinkError::Deadline),
    }
}

impl AuditLink {
    /// The link to auditd at `socket`, which must be `expected` on every
    /// connection. Nothing is connected until [`AuditLink::connect`].
    #[must_use]
    pub fn new(socket: PathBuf, expected: ExpectedAuditd) -> AuditLink {
        AuditLink { socket, expected }
    }

    /// The auditd this link expects.
    #[must_use]
    pub fn expected(&self) -> ExpectedAuditd {
        self.expected
    }

    /// auditd's socket.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Connect to auditd, check its uid, and check that it answers `Ping`
    /// with a `Pong` naming the expected source — before anything else is
    /// sent on the connection.
    ///
    /// # Errors
    /// [`AuditLinkError`]; a wrong uid or source sends nothing further and
    /// drops the connection.
    ///
    /// Spec: docs/50 R50-3 (server uid), R50-16 (auditd first), §3.2 (the
    /// source from the uid), §7.5 (`Ping`); docs/questions/Q-512, Q-560.
    pub async fn connect(&self) -> Result<AuditConnection, AuditLinkError> {
        let stream = timeout(AUDIT_DEADLINE, UnixStream::connect(&self.socket))
            .await
            .map_err(|_| AuditLinkError::Deadline)?
            .map_err(|_| AuditLinkError::Connect)?;
        let uid = stream
            .peer_cred()
            .map_err(|_| AuditLinkError::PeerCredentials)?
            .uid();
        if uid != self.expected.uid {
            // Dropped here: nothing was sent on it.
            return Err(AuditLinkError::PeerMismatch);
        }
        let mut connection = AuditConnection {
            stream,
            expected: self.expected,
        };
        // Dropped on any failure: no batch was sent on it.
        connection.check_source().await?;
        Ok(connection)
    }

    /// Verify auditd once (connect, uid, `Ping` → `Pong` naming the expected
    /// source) and close — the start-up check of a process that sends no
    /// events (ldap-front, docs/50 R50-16).
    ///
    /// # Errors
    /// [`AuditLinkError`].
    ///
    /// Spec: docs/50 R50-3, R50-16, §7.5; docs/questions/Q-560 item 5.
    pub async fn verify(&self) -> Result<(), AuditLinkError> {
        self.connect().await.map(drop)
    }

    /// Attach `first` — the connection [`AuditLink::connect`] verified at
    /// start — to the daemon's `gate`: from this call on the gate counts
    /// auditd as reachable, **because** that connection was verified (uid
    /// and source); [`AttachedLink::run`] then delivers over it and keeps
    /// the reachability true to the link from there on. This is how a
    /// daemon's start opens its gate — the gate's link side is crate-private
    /// to ipc-audit-client, so nothing else can (docs/questions/Q-630). A
    /// connection verified against another expectation does not open the
    /// gate and is never used.
    ///
    /// Spec: docs/50 R50-16 (auditd verified first), R50-17, §8.1; A-57,
    /// A-67 item 2; docs/questions/Q-560 (A-115), Q-570 §5 item a, Q-630.
    #[must_use = "the attached link must be run (spawned) to deliver the gate's events"]
    pub fn attach<G: LinkedGate>(self, gate: Arc<G>, first: AuditConnection) -> AttachedLink<G> {
        let first = (first.expected == self.expected).then_some(first);
        if first.is_some() {
            gate.audit_gate().set_reachable(true);
        }
        AttachedLink {
            link: self,
            gate,
            first,
        }
    }
}

/// A daemon's gate with the audit link attached ([`AuditLink::attach`]):
/// the gate counts auditd as reachable exactly while this link holds a
/// verified connection, and as unreachable once it is dropped (the daemon
/// aborted the task at stop, or never ran it).
///
/// Spec: docs/50 R50-17, §3.7, §8.1; A-57, A-67 item 2; docs/questions/
/// Q-630.
#[must_use = "the attached link must be run (spawned) to deliver the gate's events"]
pub struct AttachedLink<G: LinkedGate> {
    link: AuditLink,
    gate: Arc<G>,
    /// The verified start-up connection, until `run` takes it.
    first: Option<AuditConnection>,
}

impl<G: LinkedGate> fmt::Debug for AttachedLink<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachedLink")
            .field("link", &self.link)
            .finish_non_exhaustive()
    }
}

impl<G: LinkedGate> Drop for AttachedLink<G> {
    /// No link, no reachability: the gate's view of auditd ends with the
    /// link (fail closed, A-57).
    fn drop(&mut self) {
        self.gate.audit_gate().set_reachable(false);
    }
}

impl<G: LinkedGate> AttachedLink<G> {
    /// The audit client task: deliver the gate's events over the connection
    /// verified at start, then reconnect — and verify again — with backoff
    /// whenever it fails. Runs until the daemon aborts it at shutdown (the
    /// daemon's gate `close`, docs/questions/Q-502); the gate then counts
    /// auditd as unreachable.
    ///
    /// Spec: docs/50 R50-17, §3.7, §8.1; docs/questions/Q-218 (A-57),
    /// Q-512.
    pub async fn run(mut self) {
        let mut connection = self.first.take();
        let gate = Arc::clone(&self.gate);
        let mut backoff = BACKOFF_MIN;
        loop {
            let mut current = match connection.take() {
                Some(current) => current,
                None => match self.link.connect().await {
                    Ok(current) => {
                        gate.link_restored();
                        backoff = BACKOFF_MIN;
                        current
                    }
                    Err(_) => {
                        // Not verified (unreachable, another uid or another
                        // source): nothing was sent; auditd stays
                        // unreachable to the gate.
                        sleep(backoff).await;
                        backoff = backoff.saturating_mul(2).min(BACKOFF_MAX);
                        continue;
                    }
                },
            };
            let core = gate.audit_gate();
            core.set_reachable(true);
            let _failure = current.pump(&*gate).await;
            core.set_reachable(false);
            core.connection_lost();
            drop(current);
            gate.link_lost();
            sleep(backoff).await;
        }
    }
}

impl AuditConnection {
    /// `Ping` → a `Pong` that names the expected source.
    ///
    /// Spec: docs/50 §3.2, §7.5; docs/questions/Q-512, Q-560.
    async fn check_source(&mut self) -> Result<(), AuditLinkError> {
        match self.exchange(&AuditRequest::Ping).await? {
            AuditReply::Pong(source) if source == self.expected.source => Ok(()),
            AuditReply::Pong(_) => Err(AuditLinkError::SourceMismatch),
            AuditReply::Ack(_) => Err(AuditLinkError::Protocol),
        }
    }

    /// Send one request and read its one reply, within [`AUDIT_DEADLINE`].
    ///
    /// Spec: docs/50 §3.3 (bound before allocation; replies decoded
    /// strictly), §3.6 (strict request → reply), §8.1.
    async fn exchange(&mut self, request: &AuditRequest) -> Result<AuditReply, AuditLinkError> {
        let frame = encode_request(request).map_err(|_| AuditLinkError::Protocol)?;
        let start = Instant::now();
        timeout(
            remaining(start, AUDIT_DEADLINE)?,
            self.stream.write_all(frame.as_bytes()),
        )
        .await
        .map_err(|_| AuditLinkError::Deadline)?
        .map_err(|_| AuditLinkError::Io)?;
        drop(frame);
        let mut reader = FrameReader::new(AUDIT_CHANNEL.limit(Direction::Reply));
        let mut chunk = [0u8; READ_CHUNK];
        loop {
            if let Some(body) = reader.body() {
                return match decode_reply(body).map_err(|_| AuditLinkError::Protocol)? {
                    Reply::Message(reply) => Ok(reply),
                    Reply::Refused(_) => Err(AuditLinkError::Refused),
                };
            }
            let wanted = reader.wanted().min(READ_CHUNK);
            if wanted == 0 {
                return Err(AuditLinkError::Protocol);
            }
            let buffer = chunk.get_mut(..wanted).ok_or(AuditLinkError::Protocol)?;
            let read = timeout(remaining(start, AUDIT_DEADLINE)?, self.stream.read(buffer))
                .await
                .map_err(|_| AuditLinkError::Deadline)?
                .map_err(|_| AuditLinkError::Io)?;
            if read == 0 {
                return Err(AuditLinkError::Closed);
            }
            let received = buffer.get(..read).ok_or(AuditLinkError::Protocol)?;
            let taken = reader
                .push(received)
                .map_err(|_| AuditLinkError::Protocol)?;
            if taken != read {
                // Octets beyond the one reply: not a strict request → reply
                // peer (docs/50 §3.6).
                return Err(AuditLinkError::Protocol);
            }
        }
    }

    /// Deliver the window's batches until the connection fails; returns why.
    /// The gate says what is next (`AuditGate::next_send`): a batch is sent
    /// at once; counters held back by the summary pace are waited for —
    /// until the pace allows their summary, or an event is recorded — with
    /// no `Ping` (their summary's own exchange follows); idle for
    /// [`HEARTBEAT`] ⇒ a `Ping`, whose `Pong` must name the expected source
    /// too.
    ///
    /// Spec: docs/50 §8.1 (persistence acknowledgements), §7.5 (`Ping` as
    /// the health check); docs/questions/Q-218 (A-57), Q-560, Q-989 (A-165).
    async fn pump<G: LinkedGate + ?Sized>(&mut self, gate: &G) -> AuditLinkError {
        let core = gate.audit_gate();
        loop {
            match core.next_send() {
                NextSend::Batch(append) => {
                    match self.exchange(&AuditRequest::Append(append)).await {
                        Ok(AuditReply::Ack(ack)) => {
                            if core.acknowledge(&ack).is_err() {
                                return AuditLinkError::Protocol;
                            }
                        }
                        Ok(AuditReply::Pong(_)) => return AuditLinkError::Protocol,
                        Err(error) => return error,
                    }
                }
                NextSend::Paced(left) => {
                    // Woken by an event or at the end of the pace: either
                    // way the gate's next step decides.
                    let _ = timeout(left.min(HEARTBEAT), gate.recorded()).await;
                }
                NextSend::Idle => {
                    if timeout(HEARTBEAT, gate.recorded()).await.is_err() {
                        if let Err(error) = self.check_source().await {
                            return error;
                        }
                    }
                }
            }
        }
    }
}
