//! The client side: a synchronous keyd client over a connection trait, and
//! [`IpcKeyd`], the `KeyCustody` the kdc daemon builds its `Kdc` with.
//!
//! # Connections
//!
//! [`Connector`] opens a connection; [`Connection`] reports the peer's uid
//! (from the transport's peer credentials), carries one request frame and
//! its one reply frame within a deadline, and says — without blocking or
//! sending — whether a held connection is still usable. Tests use an
//! in-process loopback; the daemons a blocking Unix stream socket
//! ([`crate::unix`]).
//!
//! # The peer is verified on every connection, by construction (task R9)
//!
//! A [`KeydClient`] cannot be built without an [`ExpectedPeer`]: keyd's uid,
//! the role keyd must resolve for **this** process (its own role — Kdc,
//! Directory, Admin or Ldap), and, for the two roles that may call
//! `DescribeConfig`, optionally what keyd's description must say
//! ([`ExpectedDescription`]: the realm, or the exact description). On every
//! new connection — the first and every reconnection — the client checks,
//! **before** anything else is sent on it:
//!
//! 1. the peer uid is keyd's (R50-3: a process that captured the socket
//!    path receives no request and no password);
//! 2. keyd resolves this process's uid to the expected role: the connection
//!    carries one `Ping` — every role may ping, and the reply names the
//!    caller role keyd resolved (docs/questions/Q-403 option (c), Q-466
//!    item 2) — or, when a description is expected, one `DescribeConfig`,
//!    whose reply names the role too and must match the description
//!    (docs/questions/Q-311, Q-351).
//!
//! Anything else — another uid, another role, another realm or
//! description, keyd's refusal of the probe, any failure of it — drops the
//! connection, and the call is not served (`Unavailable`; the KDC's 29) and
//! **not sent** ([`RequestFate::NotSent`]): a keyd that maps this uid to
//! another role is never asked to run anything under it. There is no
//! constructor without the expectation, and nothing to switch it on or off
//! (it replaces the opt-in `require_description` / `require_caller_role` of
//! A-87 / A-90, docs/52 §3.12 C12). Then the connection is kept for the
//! following calls — one request in flight at a time, strict request →
//! reply (R50-7). Any failure drops it; the next call reconnects.
//!
//! # A held connection is checked before it is reused (Q-312)
//!
//! Before a call reuses the connection it holds, the client asks the
//! connection, without blocking and without sending, whether it is still
//! usable ([`Connection::check_idle`] — which every connection implements:
//! it has no default, docs/52 §2 row 19): end of stream or a pending error
//! means keyd went away (e.g. it was restarted while the connection was
//! idle), and an octet waiting on an idle strict request → reply channel is
//! a protocol error. Either way the connection is dropped and a fresh one
//! opened — and verified — **before** the request is sent, so the first
//! call after a keyd restart is served by the new keyd. A request is never
//! sent twice: once it was written, any failure ends the call `Unavailable`
//! and the next call starts over (a keyd operation may already have run — a
//! consumed one-time token cannot be presented again).
//!
//! # Keyd did not serve the call → `Unavailable`, never `Denied`
//!
//! | what happened | the caller sees | [`RequestFate`] ([`KeydClient::call_with_fate`]) |
//! |---|---|---|
//! | connect failed, peer credentials unreadable, peer uid not keyd's | `Unavailable` | not sent |
//! | the new connection's `Ping` / `DescribeConfig` failed, was refused, named another caller role, or described another realm / configuration | `Unavailable` (only the probe was sent) | not sent |
//! | the deadline passed before the request was written | `Unavailable` | not sent |
//! | the call could not be encoded | `Unavailable` | not sent |
//! | `Refused::Busy` / `Unavailable` / `Malformed` / `VersionMismatch` | `Unavailable` | not performed |
//! | after the request was handed to the connection: I/O error, peer closed, deadline exceeded, a reply that does not frame or decode, or belongs to another operation | `Unavailable` | **outcome unknown** |
//! | keyd's own answer | exactly keyd's answer (A-26 classes, keyd's `Unavailable`) | — (answered) |
//!
//! # State calls carry their fate, by type (Q-367, A-88; task R9)
//!
//! For an issuing or verifying call every row above is the same to the
//! caller: nothing was handed out, so the KDC answers 29 for each
//! (issuance is not a state change). A **state call** — a key-state change
//! (`set_secret`, `create_key`, `rotate_key`, `rotate_krbtgt`,
//! `retire_kvno`, `destroy_key_set`) or a call that loosens keyd
//! (`grant_set_secret`, `register_decision`) — is different: keyd-daemon
//! answers it with its shared `Refused` only when keyd did **not** perform
//! it (A-88), while a request that was written and whose reply was lost may
//! have been performed. So the client keeps the two apart by type:
//!
//! * [`KeydClient::call`], which reports only [`Unserved`], takes an
//!   [`IssuanceCall`] — made only from a call that is not a state call
//!   (keyd's one table, `keyd_types::authz::requires_acknowledged_intent`,
//!   the table keyd-daemon's own classification reads). A state call
//!   passed to it does not compile.
//! * [`KeydClient::call_with_fate`] sends any call and reports the fate
//!   ([`CallFailure`]): **not sent** (keyd cannot have run it), **not
//!   performed** (keyd refused it), **outcome unknown** (check before
//!   retrying — keyd's audit log holds the intent and the outcome).
//! * The typed methods of state calls return the fate too
//!   ([`StateOutcome`]); there is no typed state method that folds it into
//!   `Unavailable`.
//!
//! `Unavailable` is the `Unavailable` variant of the operation's own error
//! type (`AuthnError`, `IssueError`, `keyd_types::Error`), which the KDC answers
//! with KDC_ERR_SVC_UNAVAILABLE (code 29) over TCP and silence over UDP.
//! `Denied` would be reported to the user as a wrong password
//! (KDC_ERR_PREAUTH_FAILED) or a forged request — misleading for a refusal
//! that never reached keyd's checks (docs/50 §3.7). `Malformed` and
//! `VersionMismatch` mean the two processes disagree about the protocol (a
//! build or deployment mismatch), not that the request was judged; they too
//! are decided independent of any secret, so `Unavailable` reveals nothing
//! (A-26 concerns secret-dependent failures) — recorded in
//! docs/questions/Q-245 item 4.
//!
//! # `now`
//!
//! The `now` argument of the `KeyCustody` methods is **not sent**: keyd
//! takes `now` from its own clock (R50-5, A-56). The kdc keeps using its own
//! clock for its own checks.
//!
//! Spec: docs/50 §3.1-§3.7 (R50-3, R50-5, R50-7, R50-8), §7.5 step 4, §10
//! (`ipc-keyd`: "a synchronous client implementing `kdc::KeyCustody`" — the
//! trait is `keyd_types::KeyCustody` since D182 / A-63); docs/10 §2, §7א,
//! §9, §10; docs/52 §3.10 (c), §3.12 (C12), §7 R9; docs/questions/Q-217,
//! Q-222 (A-56), Q-240 item 8 (A-62), Q-311, Q-312 (A-82), Q-351 (A-87),
//! Q-365, Q-367 (A-88), Q-403 (A-94), Q-466 (A-102).

use crate::channel::{KEYD_CHANNEL, REPLY_LIMIT};
use crate::typed::{
    Answer, Call, ConversionError, DescribedConfig, IssuanceCall, Password, TgsFast,
};
use crate::wire::KeydReply;
use core::fmt;
use core::time::Duration;
use ipc::{decode_reply, encode_frame, Direction, FrameLimit, Refused, Reply};
use keyd_types::authz::{requires_acknowledged_intent, role_permits};
use keyd_types::{
    AccountKind, ArmorId, AsRepParts, AsTicketTemplate, AuthnError, AuthnProof,
    ChangePasswordContext, ChangePasswordCtxId, ConfigDescription, CtxId, DecidedOperation,
    DecisionId, DestructionPage, FastArmor, FastConversation, HostAddr, IssueError, KeyCustody,
    KeyHandle, Kvno, Operation, OperationDigest, OperationTicket, PrincipalBinding, PrincipalId,
    Role, SealedReply, ServiceContext, SetSecretTarget, TgsFastRequest, TgsRepParts,
    TgsTicketTemplate, TgtContext,
};
use krb_proto::{
    ApReq, EncryptedData, KerberosTime, KrbError, KrbFastArmoredReq, NonZeroResultCode, PaData,
    Realm,
};
use std::time::Instant;
use zeroize::Zeroizing;

/// The default per-call deadline of the keyd client: 2 seconds.
/// Spec: docs/50 §3.6 ("client deadline — keyd: 2 s; exceeded ⇒
/// `Unavailable` (§3.7) and the connection is dropped").
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(2);

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
    /// The deadline passed before the reply arrived.
    DeadlineExceeded,
    /// Another I/O failure.
    Io,
    /// The reply did not frame (bad length prefix, over the bound, or octets
    /// beyond the one reply).
    Framing,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TransportError::Connect => "keyd connection could not be opened",
            TransportError::PeerCredentials => "keyd peer credentials unavailable",
            TransportError::Closed => "keyd closed the connection",
            TransportError::DeadlineExceeded => "keyd deadline exceeded",
            TransportError::Io => "keyd connection I/O failure",
            TransportError::Framing => "keyd reply did not frame",
        })
    }
}

impl std::error::Error for TransportError {}

/// One open connection to keyd.
///
/// Spec: docs/50 §3.1 (Unix stream socket), §3.2 (peer credentials), §3.6
/// (deadline; strict request → reply).
pub trait Connection {
    /// The uid of the process at the other end, from the transport's peer
    /// credentials — never from anything the peer sends.
    /// Spec: docs/50 R50-3, §3.2.
    fn peer_uid(&self) -> Result<u32, TransportError>;

    /// Send one whole request frame (`frame`: length prefix included) and
    /// receive the one reply frame, returning its body (envelope and
    /// payload, without the prefix). The reply's declared length is checked
    /// against `reply_limit` before its body is awaited. The whole exchange
    /// must complete within `deadline`.
    /// Spec: docs/50 §3.3 (bound before allocation), §3.6, R50-7.
    fn exchange(
        &mut self,
        frame: &[u8],
        reply_limit: FrameLimit,
        deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError>;

    /// Check, before this held connection is reused for a request, that it
    /// is still usable — **without blocking and without sending anything**:
    /// the peer has not closed it, no error is pending on it, and no octet
    /// is waiting (nothing may arrive on an idle strict request → reply
    /// connection, so a waiting octet is a protocol error,
    /// [`TransportError::Framing`]). An `Err` makes the client drop the
    /// connection and open a fresh one before the request is sent; nothing
    /// is ever sent on a connection that failed this check.
    ///
    /// **No default** (task R9; docs/52 §2 row 19): every connection
    /// decides. A transport that truly cannot tell (an in-process loopback
    /// whose server lives as long as the connection) says so in its own
    /// implementation; the client runs the check before every reuse.
    ///
    /// Spec: docs/50 §3.6 ("an idle connection is allowed — clients hold a
    /// permanent connection"), §3.7, R50-7; docs/questions/Q-312 (A-82),
    /// Q-466 item 4 (A-102).
    fn check_idle(&mut self) -> Result<(), TransportError>;
}

/// Opens connections to keyd.
/// Spec: docs/50 §3.1, §3.7 ("reconnection with bounded backoff" — the
/// daemon's; this client reconnects at the next call).
pub trait Connector {
    /// The connection type.
    type Connection: Connection;

    /// Open a new connection.
    fn connect(&mut self) -> Result<Self::Connection, TransportError>;
}

/// Why keyd did not serve a call. Every case is reported to the caller as
/// the `Unavailable` variant of the operation's error type (module docs).
/// Whether the request was sent is not part of it: [`CallFailure`] adds
/// that ([`KeydClient::call_with_fate`]).
/// Spec: docs/50 §3.7 (R50-8); docs/questions/Q-245 item 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unserved {
    /// The transport failed.
    Transport(TransportError),
    /// The peer is not the keyd this client expects ([`ExpectedPeer`]): its
    /// uid is not keyd's (nothing was sent), or the new connection's probe
    /// — `Ping`, or `DescribeConfig` when a description is expected — was
    /// refused, named another caller role, or described another realm or
    /// configuration (nothing else was sent; docs/questions/Q-311, Q-351,
    /// Q-466).
    PeerMismatch,
    /// keyd answered with the shared transport refusal.
    Refused(Refused),
    /// The reply did not decode at the ipc layer.
    MalformedReply(ipc::Error),
    /// The reply decoded but its content did not (or it belongs to another
    /// operation).
    UnexpectedReply(ConversionError),
    /// The call could not be encoded; nothing was sent.
    Unencodable,
}

/// What the client knows about the fate of a request keyd did not answer
/// with a result (module documentation, "State calls carry their fate").
///
/// Spec: docs/questions/Q-367 (A-88: "a client-side deadline or transport
/// failure **after** the request was sent is reported as 'outcome unknown —
/// check before retrying', distinct from keyd's own `Unavailable` (= not
/// performed)"); docs/10 §10 (the audit order of a key-state change);
/// docs/50 §3.6, §3.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestFate {
    /// The request never left this process: it could not be encoded, the
    /// connection could not be opened, the peer is not the keyd expected
    /// (its uid, or the new connection's `Ping` / `DescribeConfig` probe —
    /// only that was sent), or the deadline passed before the request was
    /// written. keyd cannot have run it.
    NotSent,
    /// keyd answered the request with the shared transport refusal (`Busy`,
    /// `Unavailable`, `Malformed`, `VersionMismatch`). For a state call
    /// this means keyd did **not** perform it (A-88: keyd-daemon refuses one
    /// only before keyd runs it). For any other operation keyd delivered no
    /// result — nothing was issued (A-57) — though its bookkeeping (a
    /// throttle count, a consumed one-time token) may have moved.
    NotPerformed,
    /// The request was handed to the connection — written, or its writing
    /// began — and no usable reply came: the peer closed, the deadline
    /// passed, an I/O error, a reply that did not frame or decode, or one of
    /// another operation. keyd may or may not have performed it: **check
    /// before retrying** (keyd's audit log holds the intent and outcome of
    /// every state call; a blind retry of `create_key` is refused, of
    /// `set_secret` installs the next kvno, of `rotate_key` rotates once
    /// more).
    OutcomeUnknown,
}

impl fmt::Display for RequestFate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RequestFate::NotSent => "not sent",
            RequestFate::NotPerformed => "not performed",
            RequestFate::OutcomeUnknown => "outcome unknown - check before retrying",
        })
    }
}

/// A call that did not end in keyd's answer: why ([`Unserved`]) and what is
/// known of the request's fate ([`RequestFate`]). Carries no octet of the
/// request or the reply.
/// Spec: docs/questions/Q-367 (A-88); docs/50 §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallFailure {
    /// Why keyd did not serve the call.
    pub unserved: Unserved,
    /// Whether the request was sent, and if so whether keyd refused it.
    pub fate: RequestFate,
}

impl CallFailure {
    /// Nothing left this process. Spec: docs/questions/Q-367 (A-88).
    const fn not_sent(unserved: Unserved) -> CallFailure {
        CallFailure {
            unserved,
            fate: RequestFate::NotSent,
        }
    }

    /// Handed to the connection, no usable reply.
    /// Spec: docs/questions/Q-367 (A-88).
    const fn outcome_unknown(unserved: Unserved) -> CallFailure {
        CallFailure {
            unserved,
            fate: RequestFate::OutcomeUnknown,
        }
    }
}

/// The result of a state call through a typed method of [`KeydClient`]:
/// `Ok(result)` — keyd answered, and `result` is keyd's own answer (its
/// refusals included, exactly as keyd classified them); `Err(failure)` —
/// keyd did not serve the call, with the request's fate ([`CallFailure`]).
/// "Not performed" and "outcome unknown" are never folded into one
/// `Unavailable` (task R9).
/// Spec: docs/questions/Q-367 (A-88), Q-466 item 3 (A-102); docs/52 §3.10
/// (c).
pub type StateOutcome<T> = Result<Result<T, keyd_types::Error>, CallFailure>;

/// The client was configured with an unacceptable expectation of its peer.
/// Spec: docs/50 §3.2 ("uid 0 is never mapped"); docs/10 §2;
/// docs/questions/Q-245 item 5, Q-466 item 1 (A-102).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientConfigError {
    /// keyd's uid cannot be 0: keyd never runs as root after its hardening
    /// (docs/50 §6), and accepting uid 0 would accept any root process.
    RootServerUid,
    /// A description was expected of a role that may not call
    /// `DescribeConfig` (only Kdc and Ldap may, docs/10 §2): every new
    /// connection would be refused. Such a role is verified with `Ping`.
    DescriptionNotCallable,
}

/// What keyd's `DescribeConfig` must say on every new connection, beyond
/// the caller role: the realm only (a process that knows its realm from its
/// own configuration — dird), or the whole description (the kdc: the one it
/// started from, docs/50 §7.5 step 4, docs/questions/Q-350 item 1).
/// Spec: docs/50 §3.4 (`DescribeConfig`), §3.7, §7.5 step 4; docs/10 §7א;
/// docs/52 §3.12; docs/questions/Q-311 (A-82), Q-466 item 1 (A-102).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedDescription {
    /// keyd serves this realm.
    Realm(Realm),
    /// keyd's description is exactly this one.
    Exact(ConfigDescription),
}

impl ExpectedDescription {
    /// Whether `description` says what is expected.
    /// Spec: docs/questions/Q-311 (A-82), Q-350 item 1 (A-87).
    fn admits(&self, description: &ConfigDescription) -> bool {
        match self {
            ExpectedDescription::Realm(realm) => description.realm == *realm,
            ExpectedDescription::Exact(expected) => description == expected,
        }
    }
}

/// The keyd a [`KeydClient`] expects at the other end of every connection:
/// keyd's uid, the role keyd must resolve for **this** process from its peer
/// uid, and — only for the roles that may call `DescribeConfig` (Kdc, Ldap)
/// — optionally what keyd's description must say. The only input of
/// [`KeydClient::new`] besides the transport and the deadline: there is no
/// client without it (task R9; docs/52 §3.12 C12).
///
/// Spec: docs/50 R50-3, §3.2, §3.7; docs/10 §2, §7א; docs/52 §3.12, §7 R9;
/// docs/questions/Q-311, Q-351, Q-403 option (c), Q-466 items 1-2 (A-102).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedPeer {
    uid: u32,
    role: Role,
    description: Option<ExpectedDescription>,
}

// Every phase-1 role may ping (docs/10 §2), so the `Ping` probe verifies a
// client of any role. Checked at compile time.
const _: () = {
    assert!(role_permits(Role::Kdc, Operation::Ping));
    assert!(role_permits(Role::Directory, Operation::Ping));
    assert!(role_permits(Role::Admin, Operation::Ping));
    assert!(role_permits(Role::Ldap, Operation::Ping));
};

impl ExpectedPeer {
    /// keyd runs as `keyd_uid` and resolves this process to `role`.
    ///
    /// # Errors
    /// [`ClientConfigError::RootServerUid`].
    ///
    /// Spec: docs/50 R50-3, §3.2; docs/questions/Q-245 item 5, Q-466 item 1.
    pub fn new(keyd_uid: u32, role: Role) -> Result<ExpectedPeer, ClientConfigError> {
        if keyd_uid == 0 {
            return Err(ClientConfigError::RootServerUid);
        }
        Ok(ExpectedPeer {
            uid: keyd_uid,
            role,
            description: None,
        })
    }

    /// The same, and keyd's description must say `description` on every new
    /// connection.
    ///
    /// # Errors
    /// [`ClientConfigError::DescriptionNotCallable`]: the expected role may
    /// not call `DescribeConfig` (docs/10 §2).
    ///
    /// Spec: docs/10 §2, §7א; docs/questions/Q-311 (A-82), Q-466 item 1.
    pub fn with_description(
        self,
        description: ExpectedDescription,
    ) -> Result<ExpectedPeer, ClientConfigError> {
        if !role_permits(self.role, Operation::DescribeConfig) {
            return Err(ClientConfigError::DescriptionNotCallable);
        }
        Ok(ExpectedPeer {
            description: Some(description),
            ..self
        })
    }

    /// keyd's uid.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The role keyd must resolve for this process.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// What keyd's description must say, if anything.
    #[must_use]
    pub fn description(&self) -> Option<&ExpectedDescription> {
        self.description.as_ref()
    }
}

/// A connection whose peer uid, caller role and (when expected) description
/// were verified.
struct Verified<C> {
    connection: C,
}

/// The caller role [`IpcKeyd`] requires keyd to resolve for this process:
/// `IpcKeyd` is the `KeyCustody` of the kdc, whose operations are the Kdc
/// role's row of the capability table.
/// Spec: docs/10 §2 (Role `Kdc`); crates/keyd-types custody.rs
/// (`KeyCustody`: "the `Kdc`-role operations"); docs/questions/Q-351 (A-87:
/// "the kdc's client requires Role::Kdc").
const KDC_CALLER_ROLE: Role = Role::Kdc;

/// The time left of a call's `deadline` that started at `start`; none left
/// is [`TransportError::DeadlineExceeded`].
/// Spec: docs/50 §3.6 ("client deadline — keyd: 2 s"; one deadline per
/// call, the probe of a new connection included).
fn remaining(start: Instant, deadline: Duration) -> Result<Duration, TransportError> {
    match deadline.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(TransportError::DeadlineExceeded),
    }
}

/// One probe exchange (`Ping` or `DescribeConfig`) on a new connection that
/// carries nothing else yet: keyd's answer, or why there is none.
/// Spec: docs/50 §3.3, §3.4, §7.5 step 4; docs/questions/Q-311 (A-82),
/// Q-351 (A-87), Q-466 item 2 (A-102).
fn probe_on<K: Connection>(
    connection: &mut K,
    call: &Call,
    deadline: Duration,
) -> Result<Answer, Unserved> {
    let request = call.to_wire().map_err(|_| Unserved::Unencodable)?;
    let frame = encode_frame(KEYD_CHANNEL, Direction::Request, &request)
        .map_err(|_| Unserved::Unencodable)?;
    let body = connection
        .exchange(frame.as_bytes(), REPLY_LIMIT, deadline)
        .map_err(Unserved::Transport)?;
    match decode_reply::<KeydReply>(KEYD_CHANNEL, &body).map_err(Unserved::MalformedReply)? {
        Reply::Refused(refused) => Err(Unserved::Refused(refused)),
        Reply::Message(reply) => {
            Answer::from_wire(call.operation(), reply).map_err(Unserved::UnexpectedReply)
        }
    }
}

/// Verify the caller role (and, when expected, the description) keyd gives
/// this process on a new `connection`, before anything else is sent on it:
/// `DescribeConfig` when a description is expected (only Kdc and Ldap may
/// call it — [`ExpectedPeer::with_description`]), else `Ping` (every role).
/// keyd's own refusal of the probe, another role or another description is
/// [`Unserved::PeerMismatch`]; a failure of the exchange is that failure.
/// Spec: docs/50 R50-3, R50-8, §3.4, §3.7, §7.5 step 4; docs/10 §2, §7א;
/// docs/questions/Q-311 (A-82), Q-351 (A-87), Q-403 option (c), Q-466
/// items 1-2 (A-102).
fn verify_role_on<K: Connection>(
    connection: &mut K,
    peer: &ExpectedPeer,
    deadline: Duration,
) -> Result<(), Unserved> {
    let admitted = match peer.description.as_ref() {
        Some(expected) => match probe_on(connection, &Call::DescribeConfig, deadline)? {
            Answer::DescribeConfig(Ok(described)) => {
                described.caller_role == peer.role && expected.admits(&described.description)
            }
            _ => false,
        },
        None => match probe_on(connection, &Call::Ping, deadline)? {
            Answer::Ping(Ok(caller_role)) => caller_role == peer.role,
            _ => false,
        },
    };
    if admitted {
        Ok(())
    } else {
        Err(Unserved::PeerMismatch)
    }
}

/// A synchronous keyd client: every operation of the keyd channel, called
/// with the caller identity keyd derives from this process's credentials —
/// and verified, on every connection, to be that identity (module
/// documentation).
///
/// Spec: docs/50 §3.2 (R50-3), §3.6 (R50-7), §3.7 (R50-8), §10; docs/52
/// §3.12, §7 R9; docs/questions/Q-311, Q-312 (A-82), Q-351 (A-87), Q-367
/// (A-88), Q-466 (A-102).
pub struct KeydClient<C: Connector> {
    connector: C,
    peer: ExpectedPeer,
    deadline: Duration,
    connection: Option<Verified<C::Connection>>,
}

impl<C: Connector> fmt::Debug for KeydClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeydClient")
            .field("expected_uid", &self.peer.uid)
            .field("expected_role", &self.peer.role)
            .field("checks_description", &self.peer.description.is_some())
            .field("deadline", &self.deadline)
            .field("connected", &self.connection.is_some())
            .finish()
    }
}

// The typed methods of `KeydClient` and the one table agree: each issuing
// method's operation is not a state call (it goes through `call`), each
// state method's operation is one (it returns the fate). Checked at compile
// time against `keyd_types::authz::requires_acknowledged_intent`.
const _: () = {
    let issuance = [
        Operation::VerifyPreauth,
        Operation::IssueAsRep,
        Operation::OpenFastArmor,
        Operation::OpenAndVerifyTgt,
        Operation::IssueTgsRep,
        Operation::SealFastError,
        Operation::OpenAndVerifyServiceTicket,
        Operation::VerifyOperationTicket,
        Operation::DescribeConfig,
        Operation::Ping,
        Operation::SealCeremony,
        Operation::ListDestroyDecisions,
        // Task K4: the change-password request's opening and its error seal
        // change no key state (bookkeeping only).
        Operation::OpenChangePasswordRequest,
        Operation::SealChangePasswordError,
    ];
    let state = [
        Operation::SetSecret,
        Operation::CreateKey,
        Operation::RotateKey,
        Operation::RotateKrbtgt,
        Operation::RetireKvno,
        Operation::DestroyKeySet,
        Operation::GrantSetSecret,
        Operation::RegisterDecision,
        // Task K4: the completion installs a password (docs/52 §3.10 (c)).
        Operation::CompleteChangePassword,
    ];
    let mut i = 0;
    while i < issuance.len() {
        assert!(!requires_acknowledged_intent(issuance[i]));
        i += 1;
    }
    let mut j = 0;
    while j < state.len() {
        assert!(requires_acknowledged_intent(state[j]));
        j += 1;
    }
};

impl<C: Connector> KeydClient<C> {
    /// A client that talks to the keyd `peer` describes — every connection
    /// verified against it before anything else is sent on it (module
    /// documentation) — with a per-call `deadline` ([`DEFAULT_DEADLINE`] in
    /// the daemons). Nothing is sent until the first call.
    /// Spec: docs/50 R50-3 (the client verifies the server's uid), §3.6;
    /// docs/52 §3.12; docs/questions/Q-466 item 1 (A-102).
    #[must_use]
    pub fn new(connector: C, peer: ExpectedPeer, deadline: Duration) -> Self {
        KeydClient {
            connector,
            peer,
            deadline,
            connection: None,
        }
    }

    /// The keyd this client expects.
    #[must_use]
    pub fn expected_peer(&self) -> &ExpectedPeer {
        &self.peer
    }

    /// The connector (e.g. to inspect a test loopback).
    pub fn connector(&self) -> &C {
        &self.connector
    }

    /// Mutable access to the connector.
    pub fn connector_mut(&mut self) -> &mut C {
        &mut self.connector
    }

    /// Whether a verified connection is held.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    /// Narrow the expected description to exactly `description` (for
    /// [`IpcKeyd`], once it has the description it started from), if that
    /// does not contradict what is already expected; `false` (nothing
    /// changed) if it does. Crate-private: no user of the client can loosen
    /// or drop its expectation — only this crate's custody can make it
    /// stricter. The connection held now, if any, is kept: it was verified
    /// and already carried the call that returned `description`.
    /// Spec: docs/50 §7.5 step 4; docs/questions/Q-311 (A-82), Q-350 item 1
    /// (A-87), Q-466 item 1 (A-102).
    pub(crate) fn pin_description(&mut self, description: ConfigDescription) -> bool {
        if !role_permits(self.peer.role, Operation::DescribeConfig) {
            return false;
        }
        if let Some(expected) = self.peer.description.as_ref() {
            if !expected.admits(&description) {
                return false;
            }
        }
        self.peer.description = Some(ExpectedDescription::Exact(description));
        true
    }

    /// The held connection if it is still usable, or a new one — its peer
    /// uid keyd's, the caller role keyd gives this process the expected one,
    /// and the description (when expected) as expected — before anything
    /// else is sent on it. A held connection that fails its idle check is
    /// dropped here, before the request is sent (nothing was sent on it in
    /// this call).
    /// Spec: docs/50 R50-3, §3.2, §3.6, §3.7; docs/questions/Q-311, Q-312
    /// (A-82), Q-351 (A-87), Q-466 items 1, 2, 4 (A-102).
    fn verified(&mut self, start: Instant) -> Result<&mut C::Connection, Unserved> {
        // Q-312 / A-82: a held connection is checked before it is reused —
        // always (`check_idle` has no default, Q-466 item 4).
        let stale = match self.connection.as_mut() {
            Some(held) => held.connection.check_idle().is_err(),
            None => false,
        };
        if stale {
            self.connection = None;
        }
        if self.connection.is_none() {
            let mut connection = self.connector.connect().map_err(Unserved::Transport)?;
            let uid = connection.peer_uid().map_err(Unserved::Transport)?;
            if uid != self.peer.uid {
                // Dropped here: nothing was sent on it.
                return Err(Unserved::PeerMismatch);
            }
            // Q-466: the caller role (and the description, when expected)
            // on this connection before anything else is sent on it. On any
            // failure the connection is dropped here.
            let left = remaining(start, self.deadline).map_err(Unserved::Transport)?;
            verify_role_on(&mut connection, &self.peer, left)?;
            self.connection = Some(Verified { connection });
        }
        match self.connection.as_mut() {
            Some(verified) => Ok(&mut verified.connection),
            None => Err(Unserved::Transport(TransportError::Connect)),
        }
    }

    /// Perform one call that is not a state call ([`IssuanceCall`]): encode
    /// it, send it on a verified connection, receive and decode the reply
    /// strictly, and check that it belongs to the call's operation. Any
    /// failure drops the connection; the call is never sent a second time
    /// (Q-312: it may already have run in keyd).
    ///
    /// The failure does not say whether the request was sent — which is why
    /// a state call cannot be passed here (an [`IssuanceCall`] is never
    /// one); [`KeydClient::call_with_fate`] says it.
    ///
    /// Spec: docs/50 §3.3 (replies decoded with the same strictness), §3.6,
    /// §3.7, R50-7; docs/questions/Q-312 (A-82), Q-466 item 3 (A-102).
    pub fn call(&mut self, call: &IssuanceCall) -> Result<Answer, Unserved> {
        self.call_with_fate(call.call())
            .map_err(|failure| failure.unserved)
    }

    /// Perform one call — any call, and the only path of a state call —
    /// with the fate of a request keyd did not answer ([`CallFailure`]):
    /// **not sent** (nothing left this process), **not performed** (keyd
    /// refused it with the shared `Refused`), or **outcome unknown** (handed
    /// to the connection, no usable reply — check before retrying). keyd's
    /// own answer, its refusals included, is `Ok`. Any failure drops the
    /// connection; the call is never sent a second time.
    ///
    /// Spec: module documentation; docs/questions/Q-367 (A-88), Q-312
    /// (A-82), Q-466 item 3 (A-102); docs/10 §10; docs/50 §3.6, §3.7, R50-7.
    pub fn call_with_fate(&mut self, call: &Call) -> Result<Answer, CallFailure> {
        let result = self.call_inner(call);
        if result.is_err() {
            self.connection = None;
        }
        result
    }

    fn call_inner(&mut self, call: &Call) -> Result<Answer, CallFailure> {
        let start = Instant::now();
        let operation = call.operation();
        let request = call
            .to_wire()
            .map_err(|_| CallFailure::not_sent(Unserved::Unencodable))?;
        let frame = encode_frame(KEYD_CHANNEL, Direction::Request, &request)
            .map_err(|_| CallFailure::not_sent(Unserved::Unencodable))?;
        drop(request);
        let deadline = self.deadline;
        let connection = self.verified(start).map_err(CallFailure::not_sent)?;
        let left = remaining(start, deadline)
            .map_err(|error| CallFailure::not_sent(Unserved::Transport(error)))?;
        // Q-367: from here on the request is in the connection's hands — any
        // failure may come after keyd received it.
        let body = connection
            .exchange(frame.as_bytes(), REPLY_LIMIT, left)
            .map_err(|error| CallFailure::outcome_unknown(Unserved::Transport(error)))?;
        drop(frame);
        let reply = decode_reply::<KeydReply>(KEYD_CHANNEL, &body)
            .map_err(|error| CallFailure::outcome_unknown(Unserved::MalformedReply(error)))?;
        match reply {
            // A-88: keyd-daemon refuses a state call only before keyd runs
            // it.
            Reply::Refused(refused) => Err(CallFailure {
                unserved: Unserved::Refused(refused),
                fate: RequestFate::NotPerformed,
            }),
            Reply::Message(reply) => Answer::from_wire(operation, reply)
                .map_err(|error| CallFailure::outcome_unknown(Unserved::UnexpectedReply(error))),
        }
    }

    /// An issuing / verifying typed method: `call` through
    /// [`KeydClient::call`], keyd's answer picked by `pick`, every failure
    /// `unavailable`. A call that is a state call (cannot happen — the
    /// compile-time check above) is not sent.
    /// Spec: docs/50 §3.7 (R50-8); docs/questions/Q-466 item 3 (A-102).
    fn issuance<T, E>(
        &mut self,
        call: Call,
        pick: impl FnOnce(Answer) -> Option<Result<T, E>>,
        unavailable: E,
    ) -> Result<T, E> {
        let Some(issuance) = IssuanceCall::new(call) else {
            return Err(unavailable);
        };
        match self.call(&issuance) {
            Ok(answer) => pick(answer).unwrap_or(Err(unavailable)),
            Err(_) => Err(unavailable),
        }
    }

    /// A state call's typed method: `call` through
    /// [`KeydClient::call_with_fate`], keyd's answer picked by `pick`. An
    /// answer of another operation cannot arrive (the client checks it) and
    /// would say nothing of the request: outcome unknown.
    /// Spec: docs/questions/Q-367 (A-88), Q-466 item 3 (A-102).
    fn state<T>(
        &mut self,
        call: &Call,
        pick: impl FnOnce(Answer) -> Option<Result<T, keyd_types::Error>>,
    ) -> StateOutcome<T> {
        let answer = self.call_with_fate(call)?;
        pick(answer).ok_or(CallFailure::outcome_unknown(Unserved::UnexpectedReply(
            ConversionError::UnexpectedReply,
        )))
    }

    /// docs/10 §4 `verify_preauth`. Spec: docs/50 §3.4.
    pub fn verify_preauth(
        &mut self,
        client: &KeyHandle,
        padata: &PaData,
        armor: Option<ArmorId>,
    ) -> Result<AuthnProof, AuthnError> {
        let call = Call::VerifyPreauth {
            client: *client,
            padata: padata.clone(),
            armor,
        };
        self.issuance(
            call,
            |answer| match answer {
                Answer::VerifyPreauth(result) => Some(result),
                _ => None,
            },
            AuthnError::Unavailable,
        )
    }

    /// docs/10 §4 `issue_as_rep`. Spec: docs/50 §3.4.
    pub fn issue_as_rep(
        &mut self,
        client: &KeyHandle,
        krbtgt: &KeyHandle,
        proof: &AuthnProof,
        armor: Option<ArmorId>,
        template: &AsTicketTemplate,
    ) -> Result<AsRepParts, IssueError> {
        let call = Call::IssueAsRep {
            client: *client,
            krbtgt: *krbtgt,
            proof: proof.clone(),
            armor,
            template: template.clone(),
        };
        self.issuance(
            call,
            |answer| match answer {
                Answer::IssueAsRep(result) => Some(result),
                _ => None,
            },
            IssueError::Unavailable,
        )
    }

    /// docs/10 §5א `open_fast_armor`. Spec: docs/50 §3.4.
    pub fn open_fast_armor(
        &mut self,
        krbtgt: &KeyHandle,
        armored_req: &KrbFastArmoredReq,
        outer_req_body: &[u8],
    ) -> Result<FastArmor, AuthnError> {
        let call = Call::OpenFastArmor {
            krbtgt: *krbtgt,
            armored_req: armored_req.clone(),
            outer_req_body: outer_req_body.to_vec(),
        };
        self.issuance(
            call,
            |answer| match answer {
                Answer::OpenFastArmor(result) => Some(result),
                _ => None,
            },
            AuthnError::Unavailable,
        )
    }

    /// docs/10 §5 `open_and_verify_tgt`. Spec: docs/50 §3.4; A-17.
    pub fn open_and_verify_tgt(
        &mut self,
        krbtgt: &KeyHandle,
        ap_req: &ApReq,
        req_body: &[u8],
        fast: Option<TgsFastRequest<'_>>,
    ) -> Result<TgtContext, AuthnError> {
        let call = Call::OpenAndVerifyTgt {
            krbtgt: *krbtgt,
            ap_req: ap_req.clone(),
            req_body: req_body.to_vec(),
            fast: fast.map(|fast| TgsFast {
                ap_req_octets: fast.ap_req_octets.to_vec(),
                armored_req: fast.armored_req.clone(),
            }),
        };
        self.issuance(
            call,
            |answer| match answer {
                Answer::OpenAndVerifyTgt(result) => Some(result),
                _ => None,
            },
            AuthnError::Unavailable,
        )
    }

    /// docs/10 §5 `issue_tgs_rep`. Spec: docs/50 §3.4.
    pub fn issue_tgs_rep(
        &mut self,
        service: &KeyHandle,
        ctx: &CtxId,
        template: &TgsTicketTemplate,
    ) -> Result<TgsRepParts, IssueError> {
        let call = Call::IssueTgsRep {
            service: *service,
            ctx: *ctx,
            template: template.clone(),
        };
        self.issuance(
            call,
            |answer| match answer {
                Answer::IssueTgsRep(result) => Some(result),
                _ => None,
            },
            IssueError::Unavailable,
        )
    }

    /// docs/10 §5א `seal_fast_error`. Spec: docs/50 §3.4.
    pub fn seal_fast_error(
        &mut self,
        conversation: &FastConversation,
        error: &KrbError,
        padata: &[PaData],
    ) -> Result<EncryptedData, keyd_types::Error> {
        let call = Call::SealFastError {
            conversation: *conversation,
            error: error.clone(),
            padata: padata.to_vec(),
        };
        self.issuance(
            call,
            |answer| match answer {
                Answer::SealFastError(result) => Some(result),
                _ => None,
            },
            keyd_types::Error::Unavailable,
        )
    }

    /// docs/10 §5ב `open_and_verify_service_ticket` (Role::Ldap): an
    /// **unbound** service AP-REQ under the `Service` key set of `service`
    /// (the binding's purpose, R2); keyd keeps the session key under the
    /// answer's one-time context id.
    /// Spec: docs/50 §3.4; docs/52 §5 item 3; docs/questions/Q-523.
    pub fn open_and_verify_service_ticket(
        &mut self,
        service: &PrincipalId,
        ap_req_octets: &[u8],
    ) -> Result<ServiceContext, AuthnError> {
        let call = Call::OpenAndVerifyServiceTicket {
            service: *service,
            ap_req_octets: ap_req_octets.to_vec(),
        };
        self.issuance(
            call,
            |answer| match answer {
                Answer::OpenAndVerifyServiceTicket(result) => Some(result),
                _ => None,
            },
            AuthnError::Unavailable,
        )
    }

    /// docs/10 §5ב `verify_operation_ticket` (Role::Ldap): a service AP-REQ
    /// **bound to `operation`** under the `AdminService` key set of
    /// `service` (the binding's purpose, R2). The answer has no context id:
    /// keyd keeps nothing for it (Q-523).
    /// Spec: docs/50 §3.4; docs/52 §5 items 3-4; docs/questions/Q-523.
    pub fn verify_operation_ticket(
        &mut self,
        service: &PrincipalId,
        operation: &OperationDigest,
        ap_req_octets: &[u8],
    ) -> Result<OperationTicket, AuthnError> {
        let call = Call::VerifyOperationTicket {
            service: *service,
            operation: *operation,
            ap_req_octets: ap_req_octets.to_vec(),
        };
        self.issuance(
            call,
            |answer| match answer {
                Answer::VerifyOperationTicket(result) => Some(result),
                _ => None,
            },
            AuthnError::Unavailable,
        )
    }

    /// docs/10 §6 `set_secret` (Role::Directory) — a state call: the result
    /// carries the fate ([`StateOutcome`]). The password travels only in
    /// zeroizing buffers.
    /// Spec: docs/50 §3.3, §3.4; docs/10 I7, §10; docs/questions/Q-367
    /// (A-88), Q-466 item 3 (A-102).
    pub fn set_secret(
        &mut self,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
        password: Zeroizing<String>,
        salt: &str,
    ) -> StateOutcome<Kvno> {
        let call = Call::SetSecret {
            handle: *handle,
            binding: binding.clone(),
            password: Password::new(password),
            salt: salt.to_owned(),
        };
        self.state(&call, |answer| match answer {
            Answer::SetSecret(result) => Some(result),
            _ => None,
        })
    }

    /// docs/10 §7 `create_key` (Role::Admin; the provisioning ceremony only,
    /// A-102) — a state call ([`StateOutcome`]). Spec: docs/50 §3.4;
    /// docs/10 §10; docs/questions/Q-367 (A-88), Q-466 item 3.
    pub fn create_key(
        &mut self,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
    ) -> StateOutcome<Kvno> {
        let call = Call::CreateKey {
            handle: *handle,
            binding: binding.clone(),
        };
        self.state(&call, |answer| match answer {
            Answer::CreateKey(result) => Some(result),
            _ => None,
        })
    }

    /// docs/10 §7 `rotate_key` (Role::Admin): run dird's `RotateKey`
    /// decision `decision` (A-102) — a state call ([`StateOutcome`]).
    /// Spec: docs/50 §3.4; docs/10 §10; docs/52 §4.2.
    pub fn rotate_key(&mut self, decision: DecisionId) -> StateOutcome<Kvno> {
        self.state(&Call::RotateKey { decision }, |answer| match answer {
            Answer::RotateKey(result) => Some(result),
            _ => None,
        })
    }

    /// docs/10 §7 `rotate_krbtgt` (Role::Admin): run dird's `RotateKrbtgt`
    /// decision `decision` (A-102; keyd builds the dual-control token from
    /// the decision's approvers) — a state call ([`StateOutcome`]).
    /// Spec: docs/50 §3.4; docs/10 §10; docs/52 §4.2.
    pub fn rotate_krbtgt(&mut self, decision: DecisionId) -> StateOutcome<Kvno> {
        self.state(&Call::RotateKrbtgt { decision }, |answer| match answer {
            Answer::RotateKrbtgt(result) => Some(result),
            _ => None,
        })
    }

    /// docs/10 §7 `retire_kvno` (Role::Admin): run dird's `RetireKvno`
    /// decision `decision` (A-102) — a state call ([`StateOutcome`]).
    /// Spec: docs/50 §3.4; docs/10 §10; docs/52 §4.2.
    pub fn retire_kvno(&mut self, decision: DecisionId) -> StateOutcome<()> {
        self.state(&Call::RetireKvno { decision }, |answer| match answer {
            Answer::RetireKvno(result) => Some(result),
            _ => None,
        })
    }

    /// docs/10 §7 `destroy_key_set` (Role::Admin): run dird's
    /// `DestroyKeySet` decision `decision` (A-102) — a state call
    /// ([`StateOutcome`]). Spec: docs/50 §3.4; docs/10 §10; A-35; docs/52
    /// §4.2.
    pub fn destroy_key_set(&mut self, decision: DecisionId) -> StateOutcome<()> {
        self.state(&Call::DestroyKeySet { decision }, |answer| match answer {
            Answer::DestroyKeySet(result) => Some(result),
            _ => None,
        })
    }

    /// `seal_ceremony` (Role::Admin): end keyd's provisioning ceremony
    /// (A-102, docs/52 R3). Not a state call (it only makes keyd stricter —
    /// one record, docs/10 §10); a caller that reports its fate sends
    /// [`Call::SealCeremony`] with [`KeydClient::call_with_fate`].
    /// Spec: docs/52 §4.4.
    pub fn seal_ceremony(&mut self) -> Result<(), keyd_types::Error> {
        self.issuance(
            Call::SealCeremony,
            |answer| match answer {
                Answer::SealCeremony(result) => Some(result),
                _ => None,
            },
            keyd_types::Error::Unavailable,
        )
    }

    /// `list_destroy_decisions` (Role::Admin, Role::Ldap): one page of the
    /// pending destroy decisions dird registered, strictly after `after`
    /// (A-102). Spec: docs/52 §4.6.
    pub fn list_destroy_decisions(
        &mut self,
        after: Option<DecisionId>,
    ) -> Result<DestructionPage, keyd_types::Error> {
        self.issuance(
            Call::ListDestroyDecisions { after },
            |answer| match answer {
                Answer::ListDestroyDecisions(result) => Some(result),
                _ => None,
            },
            keyd_types::Error::Unavailable,
        )
    }

    /// `register_decision` (Role::Ldap — dird): record decision `id` to run
    /// `operation`, approved by `approvers`, live for `lifetime_secs` by
    /// keyd's clock (A-102, docs/52 R1). It loosens keyd — a state call:
    /// the result carries the fate ([`StateOutcome`]).
    /// Spec: docs/52 §4.2, §4.5; docs/questions/Q-460, Q-466 item 3.
    pub fn register_decision(
        &mut self,
        id: DecisionId,
        operation: &DecidedOperation,
        approvers: &[PrincipalId],
        lifetime_secs: u32,
    ) -> StateOutcome<()> {
        let call = Call::RegisterDecision {
            id,
            operation: operation.clone(),
            approvers: approvers.to_vec(),
            lifetime_secs,
        };
        self.state(&call, |answer| match answer {
            Answer::RegisterDecision(result) => Some(result),
            _ => None,
        })
    }

    /// docs/10 §7א `describe_config` (Kdc, Ldap): keyd's description (the
    /// caller role of the reply is left out — [`KeydClient::describe_config_with_role`]).
    /// Spec: docs/50 §3.4, §7.5.
    pub fn describe_config(&mut self) -> Result<ConfigDescription, keyd_types::Error> {
        self.describe_config_with_role()
            .map(|described| described.description)
    }

    /// docs/10 §7א `describe_config` (Kdc, Ldap): keyd's description and the
    /// caller role keyd resolved for this process from its peer uid.
    /// Spec: docs/50 §3.4, §7.5; docs/questions/Q-351 (A-87).
    pub fn describe_config_with_role(&mut self) -> Result<DescribedConfig, keyd_types::Error> {
        self.issuance(
            Call::DescribeConfig,
            |answer| match answer {
                Answer::DescribeConfig(result) => Some(result),
                _ => None,
            },
            keyd_types::Error::Unavailable,
        )
    }

    /// docs/10 §7א `ping` (every role): keyd's health, and the caller role
    /// keyd resolved for this process (on a verified connection, the
    /// expected one).
    /// Spec: docs/50 §3.4, §7.5; docs/questions/Q-466 item 2 (A-102).
    pub fn ping(&mut self) -> Result<Role, keyd_types::Error> {
        self.issuance(
            Call::Ping,
            |answer| match answer {
                Answer::Ping(result) => Some(result),
                _ => None,
            },
            keyd_types::Error::Unavailable,
        )
    }

    /// docs/53 §5.5 `open_change_password_request` (Role::Ldap — dird; task
    /// K4): an RFC 3244 request's AP-REQ and KRB-PRIV as received, and the
    /// connection's addresses as the front's kernel reported them. keyd
    /// verifies, decrypts and judges the request and answers a one-time
    /// request context with its verdict — the password never leaves keyd.
    /// Not a state call.
    /// Spec: docs/53 §5.3-§5.5; docs/50 §3.4; RFC 3244 §2.
    pub fn open_change_password_request(
        &mut self,
        service: &PrincipalId,
        ap_req_octets: &[u8],
        krb_priv_octets: &[u8],
        peer: &HostAddr,
        local: &HostAddr,
    ) -> Result<ChangePasswordContext, AuthnError> {
        let call = Call::OpenChangePasswordRequest {
            service: *service,
            ap_req_octets: ap_req_octets.to_vec(),
            krb_priv_octets: krb_priv_octets.to_vec(),
            peer: *peer,
            local: *local,
        };
        self.issuance(
            call,
            |answer| match answer {
                Answer::OpenChangePasswordRequest(result) => Some(result),
                _ => None,
            },
            AuthnError::Unavailable,
        )
    }

    /// docs/53 §5.5 `complete_change_password` (Role::Ldap — dird; task K4):
    /// install the password of request context `ctx` into `target` on the
    /// `ChangePassword` decision dird registered, and return the sealed
    /// success reply. It changes key state — a state call: the result
    /// carries the fate ([`StateOutcome`]: "not performed" and "outcome
    /// unknown" stay apart, docs/52 §3.10 (c)).
    /// Spec: docs/53 §5.5, §5.6 step 6; docs/50 §3.4; docs/questions/Q-367
    /// (A-88), Q-466 item 3.
    pub fn complete_change_password(
        &mut self,
        ctx: &ChangePasswordCtxId,
        target: &KeyHandle,
    ) -> StateOutcome<SealedReply> {
        let call = Call::CompleteChangePassword {
            ctx: *ctx,
            target: *target,
        };
        self.state(&call, |answer| match answer {
            Answer::CompleteChangePassword(result) => Some(result),
            _ => None,
        })
    }

    /// docs/53 §5.5 `seal_change_password_error` (Role::Ldap — dird; task
    /// K4): seal request context `ctx`'s error reply with `code` (never
    /// SUCCESS — the type cannot hold it). Not a state call.
    /// Spec: docs/53 §5.5, §5.7; docs/50 §3.4; RFC 3244 §2.
    pub fn seal_change_password_error(
        &mut self,
        ctx: &ChangePasswordCtxId,
        code: NonZeroResultCode,
    ) -> Result<SealedReply, keyd_types::Error> {
        self.issuance(
            Call::SealChangePasswordError { ctx: *ctx, code },
            |answer| match answer {
                Answer::SealChangePasswordError(result) => Some(result),
                _ => None,
            },
            keyd_types::Error::Unavailable,
        )
    }

    /// `grant_set_secret` (Role::Admin — keyadm's ceremony, before the seal;
    /// A-102): register a one-time grant, live for `lifetime_secs` by keyd's
    /// clock, that lets Role::Directory run one `set_secret` on each of
    /// `targets` with exactly its binding and salt. dird registers
    /// `SetSecret` decisions instead ([`KeydClient::register_decision`]).
    /// It loosens keyd — a state call: the result carries the fate
    /// ([`StateOutcome`]).
    ///
    /// Spec: docs/51 §5.8 option (b); docs/50 §3.4; docs/questions/Q-291
    /// (A-74), Q-450, Q-452, Q-466 item 3.
    pub fn grant_set_secret(
        &mut self,
        kind: AccountKind,
        targets: &[SetSecretTarget],
        lifetime_secs: u32,
    ) -> StateOutcome<()> {
        let call = Call::GrantSetSecret {
            kind,
            targets: targets.to_vec(),
            lifetime_secs,
        };
        self.state(&call, |answer| match answer {
            Answer::GrantSetSecret(result) => Some(result),
            _ => None,
        })
    }
}

/// The keyd custody of the kdc daemon: [`KeydClient`] behind
/// `KeyCustody`, with keyd's non-secret configuration fetched once
/// (`describe_config`) when it is built — and then expected, exactly, of
/// every new connection (so that [`KeyCustody::config`] stays the
/// description of the keyd that serves the calls, docs/questions/Q-311) —
/// over a client that expects the caller role `Kdc` on every connection
/// (docs/questions/Q-351, Q-466).
///
/// Spec: docs/50 §3.4, §7.5 step 4 ("`DescribeConfig` from keyd …
/// `KdcConfig::validate(&keyd_config)` — only then bind 88"), §10; docs/10
/// §2, §7א; docs/questions/Q-311 (A-82), Q-351 (A-87), Q-466 (A-102).
pub struct IpcKeyd<C: Connector> {
    client: KeydClient<C>,
    description: ConfigDescription,
}

impl<C: Connector> fmt::Debug for IpcKeyd<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpcKeyd")
            .field("client", &self.client)
            .field("realm", &self.description.realm)
            .finish()
    }
}

impl<C: Connector> IpcKeyd<C> {
    /// Ask keyd for its configuration and build the custody over `client`,
    /// which must expect the caller role `Kdc` (else `Unavailable`, nothing
    /// sent: the kdc's custody runs only the Kdc role's operations). Fails
    /// with keyd's error (or `Unavailable`) when keyd does not answer — the
    /// kdc daemon then does not start (fail closed, docs/50 §7.5). A keyd
    /// that maps this uid to another role is found by the client's probe of
    /// the first connection, before `DescribeConfig` is sent.
    ///
    /// The description is then expected, exactly, of every new connection
    /// the client opens (the connection that answered it is kept): a keyd
    /// that no longer gives it — or the role `Kdc` — serves no call
    /// (`Unavailable`) until it does again.
    ///
    /// Spec: docs/50 §7.5 step 4, §3.7; docs/10 §2; docs/questions/Q-311
    /// (A-82), Q-351 (A-87), Q-466 item 1 (A-102).
    pub fn connect(mut client: KeydClient<C>) -> Result<Self, keyd_types::Error> {
        if client.expected_peer().role() != KDC_CALLER_ROLE {
            return Err(keyd_types::Error::Unavailable);
        }
        let described = client.describe_config_with_role()?;
        if described.caller_role != KDC_CALLER_ROLE {
            // Q-351: keyd does not give this process the Kdc role (the
            // probe already found it; checked again on the answer itself).
            return Err(keyd_types::Error::Unavailable);
        }
        let description = described.description;
        if !client.pin_description(description.clone()) {
            // The answer contradicts the realm the client expected.
            return Err(keyd_types::Error::Unavailable);
        }
        Ok(IpcKeyd {
            client,
            description,
        })
    }

    /// The underlying client.
    pub fn client(&self) -> &KeydClient<C> {
        &self.client
    }

    /// Mutable access to the underlying client.
    pub fn client_mut(&mut self) -> &mut KeydClient<C> {
        &mut self.client
    }
}

/// Every method ignores its `now` argument: keyd reads its own clock (R50-5,
/// A-56); the wire has no field for it.
/// Spec: docs/50 R50-5, R50-8, §3.4, §3.5, §3.7; docs/questions/Q-217,
/// Q-222 (A-56).
impl<C: Connector> KeyCustody for IpcKeyd<C> {
    fn config(&self) -> &ConfigDescription {
        &self.description
    }

    fn verify_preauth(
        &mut self,
        client: &KeyHandle,
        padata: &PaData,
        armor: Option<ArmorId>,
        _now: &KerberosTime,
    ) -> Result<AuthnProof, AuthnError> {
        self.client.verify_preauth(client, padata, armor)
    }

    fn issue_as_rep(
        &mut self,
        client: &KeyHandle,
        krbtgt: &KeyHandle,
        proof: &AuthnProof,
        armor: Option<ArmorId>,
        template: &AsTicketTemplate,
        _now: &KerberosTime,
    ) -> Result<AsRepParts, IssueError> {
        self.client
            .issue_as_rep(client, krbtgt, proof, armor, template)
    }

    fn open_fast_armor(
        &mut self,
        krbtgt: &KeyHandle,
        armored_req: &KrbFastArmoredReq,
        outer_req_body: &[u8],
        _now: &KerberosTime,
    ) -> Result<FastArmor, AuthnError> {
        self.client
            .open_fast_armor(krbtgt, armored_req, outer_req_body)
    }

    fn open_and_verify_tgt(
        &mut self,
        krbtgt: &KeyHandle,
        ap_req: &ApReq,
        req_body: &[u8],
        fast: Option<TgsFastRequest<'_>>,
        _now: &KerberosTime,
    ) -> Result<TgtContext, AuthnError> {
        self.client
            .open_and_verify_tgt(krbtgt, ap_req, req_body, fast)
    }

    fn issue_tgs_rep(
        &mut self,
        service: &KeyHandle,
        ctx: &CtxId,
        template: &TgsTicketTemplate,
        _now: &KerberosTime,
    ) -> Result<TgsRepParts, IssueError> {
        self.client.issue_tgs_rep(service, ctx, template)
    }

    fn seal_fast_error(
        &mut self,
        conversation: &FastConversation,
        error: &KrbError,
        padata: &[PaData],
        _now: &KerberosTime,
    ) -> Result<EncryptedData, keyd_types::Error> {
        self.client.seal_fast_error(conversation, error, padata)
    }
}
