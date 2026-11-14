//! The client side: a synchronous keyd client over a connection trait, and
//! [`IpcKeyd`], the `KeyCustody` the kdc daemon builds its `Kdc` with.
//!
//! # Connections
//!
//! [`Connector`] opens a connection; [`Connection`] reports the peer's uid
//! (from the transport's peer credentials) and carries one request frame and
//! its one reply frame within a deadline. Tests use an in-process loopback;
//! the kdc daemon a blocking Unix stream socket ([`crate::unix`]).
//!
//! [`KeydClient`] checks the peer uid of every new connection against the
//! configured keyd uid **before** anything is sent on it (R50-3: "the client
//! also verifies the server's uid", so that a process that captured the
//! socket path receives no request and no password), then keeps it for the
//! following calls — one request in flight at a time, strict request → reply
//! (R50-7). Any failure drops the connection; the next call reconnects.
//!
//! # A held connection is checked before it is reused (Q-312)
//!
//! Before a call reuses the connection it holds, the client asks the
//! connection, without blocking and without sending, whether it is still
//! usable ([`Connection::check_idle`]): end of stream or a pending error
//! means keyd went away (e.g. it was restarted while the connection was
//! idle), and an octet waiting on an idle strict request → reply channel is
//! a protocol error. Either way the connection is dropped and a fresh one
//! opened — and checked — **before** the request is sent, so the first call
//! after a keyd restart is served by the new keyd. A request is never sent
//! twice: once it was written, any failure ends the call `Unavailable` and
//! the next call starts over (a keyd operation may already have run — a
//! consumed one-time token cannot be presented again).
//!
//! # Each new connection is checked with `DescribeConfig` (Q-311, Q-351)
//!
//! With [`KeydClient::require_description`] and
//! [`KeydClient::require_caller_role`] (both set by [`IpcKeyd::connect`]),
//! every new connection, after its peer uid and before any other request,
//! carries a `DescribeConfig` whose answer must be exactly the description
//! the client was built with **and** name the caller role the client
//! expects — the role keyd resolved for this process from its peer uid
//! ([`DescribedConfig`]). Only the Kdc and Ldap roles may call
//! `DescribeConfig` (docs/10 §2): a keyd restarted with this uid mapped to
//! Directory or Admin refuses it, one that maps it to the other of Kdc and
//! Ldap answers it with that role, and one serving another realm answers
//! another description — each is found here; the connection is dropped and
//! the call is not served (`Unavailable`, the KDC's 29), instead of reaching
//! an operation whose uniform `Denied` the KDC would report as a wrong
//! password (24).
//!
//! # Keyd did not serve the call → `Unavailable`, never `Denied`
//!
//! | what happened | the caller sees | [`RequestFate`] ([`KeydClient::call_with_fate`]) |
//! |---|---|---|
//! | connect failed, peer credentials unreadable, peer uid not keyd's | `Unavailable` | not sent |
//! | the new connection's `DescribeConfig` failed, refused, different, or of another caller role (when required) | `Unavailable` (only `DescribeConfig` was sent) | not sent |
//! | the deadline passed before the request was written | `Unavailable` | not sent |
//! | the call could not be encoded | `Unavailable` | not sent |
//! | `Refused::Busy` / `Unavailable` / `Malformed` / `VersionMismatch` | `Unavailable` | not performed |
//! | after the request was handed to the connection: I/O error, peer closed, deadline exceeded, a reply that does not frame or decode, or belongs to another operation | `Unavailable` | **outcome unknown** |
//! | keyd's own answer | exactly keyd's answer (A-26 classes, keyd's `Unavailable`) | — (answered) |
//!
//! # Not sent, not performed, outcome unknown (Q-367, A-88)
//!
//! For an issuing or verifying call every row above is the same to the
//! caller: nothing was handed out, so the KDC answers 29 for each
//! (issuance is not a state change). A key-state change (`set_secret`,
//! `create_key`, `rotate_key`, `rotate_krbtgt`, `retire_kvno`,
//! `destroy_key_set` — docs/10 §10) is different: keyd-daemon answers it
//! with its shared `Refused` only when keyd did **not** perform it (A-88:
//! the intent was not acknowledged in time, or auditd is away ⇒ `Busy`),
//! while a request that was written and whose reply was lost or came after
//! the client's own deadline may have been performed — inherent to request
//! → reply with a deadline. [`KeydClient::call_with_fate`] reports which
//! of the three it was ([`RequestFate`]): **not sent** (keyd cannot have
//! run it), **not performed** (keyd refused it), **outcome unknown** (check
//! before retrying — keyd's audit log holds the intent and the outcome).
//! [`KeydClient::call`] and the typed methods keep reporting every case as
//! before (`Unserved`, `Unavailable`).
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
//! trait is `keyd_types::KeyCustody` since D182 / A-63); docs/10 §2, §9,
//! §10; docs/questions/Q-217, Q-222 (A-56), Q-240 item 8 (A-62), Q-311,
//! Q-312 (A-82), Q-351 (A-87), Q-365, Q-367 (A-88).

use crate::channel::{KEYD_CHANNEL, REPLY_LIMIT};
use crate::typed::{Answer, Call, ConversionError, DescribedConfig, Password, TgsFast};
use crate::wire::KeydReply;
use core::fmt;
use core::time::Duration;
use ipc::{decode_reply, encode_frame, Direction, FrameLimit, Refused, Reply};
use keyd_types::{
    AccountKind, AppBinding, ArmorId, AsRepParts, AsTicketTemplate, AuthnError, AuthnProof,
    ConfigDescription, CtxId, DecidedOperation, DecisionId, DestructionPage, FastArmor,
    FastConversation, IssueError, KeyCustody, KeyHandle, Kvno, PrincipalBinding, PrincipalId, Role,
    ServiceContext, SetSecretTarget, TgsFastRequest, TgsRepParts, TgsTicketTemplate, TgtContext,
};
use krb_proto::{ApReq, EncryptedData, KerberosTime, KrbError, KrbFastArmoredReq, PaData};
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
    /// The default reports the connection usable — for a transport that
    /// cannot tell (an in-process loopback): a dead connection is then found
    /// by the exchange itself, as before.
    ///
    /// Spec: docs/50 §3.6 ("an idle connection is allowed — clients hold a
    /// permanent connection"), §3.7, R50-7; docs/questions/Q-312 (A-82).
    fn check_idle(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
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
    /// The peer is not the keyd this client was configured for: its uid is
    /// not keyd's (nothing was sent), or — when the client requires a
    /// description ([`KeydClient::require_description`]) or its caller role
    /// ([`KeydClient::require_caller_role`]) — the new connection's
    /// `DescribeConfig` was refused, answered another description, or named
    /// another caller role (nothing else was sent; docs/questions/Q-311,
    /// Q-351).
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
/// with a result (module documentation, "Not sent, not performed, outcome
/// unknown").
///
/// Spec: docs/questions/Q-367 (A-88: "a client-side deadline or transport
/// failure **after** the request was sent is reported as 'outcome unknown —
/// check before retrying', distinct from keyd's own `Unavailable` (= not
/// performed)"); docs/10 §10 (the audit order of a key-state change);
/// docs/50 §3.6, §3.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestFate {
    /// The request never left this process: it could not be encoded, the
    /// connection could not be opened, the peer is not the keyd configured
    /// (its uid, or its `DescribeConfig` when required — only that was
    /// sent), or the deadline passed before the request was written. keyd
    /// cannot have run it.
    NotSent,
    /// keyd answered the request with the shared transport refusal (`Busy`,
    /// `Unavailable`, `Malformed`, `VersionMismatch`). For a key-state change
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
    /// every key-state change; a blind retry of `create_key` is refused, of
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

/// A call that did not end in keyd's answer: why ([`Unserved`], as
/// [`KeydClient::call`] reports it) and what is known of the request's fate
/// ([`RequestFate`]). Carries no octet of the request or the reply.
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

/// The client was configured with an unacceptable keyd uid.
/// Spec: docs/50 §3.2 ("uid 0 is never mapped"); docs/questions/Q-245
/// item 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientConfigError {
    /// keyd's uid cannot be 0: keyd never runs as root after its hardening
    /// (docs/50 §6), and accepting uid 0 would accept any root process.
    RootServerUid,
}

/// A connection whose peer uid was checked against keyd's (and, when the
/// client requires a description or a caller role, whose `DescribeConfig`
/// answer matched).
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
/// call, the `DescribeConfig` of a new connection included).
fn remaining(start: Instant, deadline: Duration) -> Result<Duration, TransportError> {
    match deadline.checked_sub(start.elapsed()) {
        Some(left) if !left.is_zero() => Ok(left),
        _ => Err(TransportError::DeadlineExceeded),
    }
}

/// One `DescribeConfig` exchange on a new connection that carries nothing
/// else yet: keyd's description and the caller role it resolved, or why
/// they were not given. keyd's own refusal (`Denied` for a role that may
/// not call it, docs/10 §2) is [`Unserved::PeerMismatch`].
/// Spec: docs/50 §3.3, §3.4 (`DescribeConfig` — Kdc, Ldap), §7.5 step 4;
/// docs/questions/Q-311 (A-82), Q-351 (A-87).
fn describe_on<K: Connection>(
    connection: &mut K,
    deadline: Duration,
) -> Result<DescribedConfig, Unserved> {
    let call = Call::DescribeConfig;
    let request = call.to_wire().map_err(|_| Unserved::Unencodable)?;
    let frame = encode_frame(KEYD_CHANNEL, Direction::Request, &request)
        .map_err(|_| Unserved::Unencodable)?;
    let body = connection
        .exchange(frame.as_bytes(), REPLY_LIMIT, deadline)
        .map_err(Unserved::Transport)?;
    match decode_reply::<KeydReply>(KEYD_CHANNEL, &body).map_err(Unserved::MalformedReply)? {
        Reply::Refused(refused) => Err(Unserved::Refused(refused)),
        Reply::Message(reply) => match Answer::from_wire(call.operation(), reply) {
            Ok(Answer::DescribeConfig(Ok(described))) => Ok(described),
            Ok(Answer::DescribeConfig(Err(_))) => Err(Unserved::PeerMismatch),
            Ok(_) => Err(Unserved::UnexpectedReply(ConversionError::UnexpectedReply)),
            Err(error) => Err(Unserved::UnexpectedReply(error)),
        },
    }
}

/// A synchronous keyd client: every operation of the keyd channel, called
/// with the caller identity keyd derives from this process's credentials.
///
/// Spec: docs/50 §3.2 (R50-3), §3.6 (R50-7), §3.7 (R50-8), §10;
/// docs/questions/Q-311, Q-312 (A-82), Q-351 (A-87), Q-367 (A-88).
pub struct KeydClient<C: Connector> {
    connector: C,
    expected_uid: u32,
    deadline: Duration,
    connection: Option<Verified<C::Connection>>,
    /// When set, every new connection's `DescribeConfig` must answer
    /// exactly this (Q-311).
    description: Option<ConfigDescription>,
    /// When set, every new connection's `DescribeConfig` must name this
    /// caller role (Q-351).
    caller_role: Option<Role>,
}

impl<C: Connector> fmt::Debug for KeydClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeydClient")
            .field("expected_uid", &self.expected_uid)
            .field("deadline", &self.deadline)
            .field("connected", &self.connection.is_some())
            .field("checks_description", &self.description.is_some())
            .field("checks_caller_role", &self.caller_role)
            .finish()
    }
}

impl<C: Connector> KeydClient<C> {
    /// A client that talks to the keyd process running as `expected_uid`,
    /// with a per-call `deadline` ([`DEFAULT_DEADLINE`] in the daemons).
    /// Spec: docs/50 R50-3 (the client verifies the server's uid), §3.6.
    pub fn new(
        connector: C,
        expected_uid: u32,
        deadline: Duration,
    ) -> Result<Self, ClientConfigError> {
        if expected_uid == 0 {
            return Err(ClientConfigError::RootServerUid);
        }
        Ok(KeydClient {
            connector,
            expected_uid,
            deadline,
            connection: None,
            description: None,
            caller_role: None,
        })
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

    /// Require every **new** connection — after its peer uid, before any
    /// other request is sent on it — to answer `DescribeConfig` with exactly
    /// `description` (the one this client's user validated itself against,
    /// docs/50 §7.5 step 4). keyd's refusal (a role that may not call it,
    /// docs/10 §2), another description, or any failure of that exchange
    /// drops the connection, and the call is not served
    /// ([`Unserved::PeerMismatch`] or the failure; the caller sees
    /// `Unavailable`). The connection held now, if any, is kept: it already
    /// carried a call.
    ///
    /// Only the Kdc and Ldap roles may call `DescribeConfig`; a client of
    /// another role must not require a description. A client that requires
    /// a description also requires its own caller role
    /// ([`KeydClient::require_caller_role`]): the description alone does not
    /// tell the Kdc role from the Ldap role (docs/questions/Q-351).
    ///
    /// Spec: docs/50 R50-3, R50-8, §3.4, §7.5 step 4; docs/questions/Q-311
    /// (A-82), Q-351 (A-87).
    pub fn require_description(&mut self, description: ConfigDescription) {
        self.description = Some(description);
    }

    /// The description every new connection must answer, if required.
    /// Spec: docs/questions/Q-311 (A-82).
    #[must_use]
    pub fn required_description(&self) -> Option<&ConfigDescription> {
        self.description.as_ref()
    }

    /// Require every **new** connection — after its peer uid, before any
    /// other request is sent on it — to answer `DescribeConfig` naming
    /// `role` as the caller role keyd resolved for this process from its
    /// peer uid ([`DescribedConfig::caller_role`]). Another role, keyd's
    /// refusal, or any failure of that exchange drops the connection and the
    /// call is not served ([`Unserved::PeerMismatch`] or the failure; the
    /// caller sees `Unavailable`), exactly as for
    /// [`KeydClient::require_description`], with which it shares the one
    /// `DescribeConfig` of a new connection. The connection held now, if
    /// any, is kept: it already carried a call.
    ///
    /// Only the Kdc and Ldap roles may call `DescribeConfig` (docs/10 §2):
    /// requiring `Directory` or `Admin` would leave every new connection
    /// refused, so a client of those roles requires no caller role.
    ///
    /// Spec: docs/50 R50-3, R50-8, §3.2, §3.4, §3.7; docs/10 §2;
    /// docs/questions/Q-351 (A-87).
    pub fn require_caller_role(&mut self, role: Role) {
        self.caller_role = Some(role);
    }

    /// The caller role every new connection's `DescribeConfig` must name,
    /// if required. Spec: docs/questions/Q-351 (A-87).
    #[must_use]
    pub fn required_caller_role(&self) -> Option<Role> {
        self.caller_role
    }

    /// The held connection if it is still usable, or a new one — its peer
    /// uid keyd's and, when required, its `DescribeConfig` answer the
    /// expected description and caller role — before anything else is sent
    /// on it. A held connection that fails its idle check is dropped here,
    /// before the request is sent (nothing was sent on it in this call).
    /// Spec: docs/50 R50-3, §3.2, §3.6, §3.7; docs/questions/Q-311, Q-312
    /// (A-82), Q-351 (A-87).
    fn verified(&mut self, start: Instant) -> Result<&mut C::Connection, Unserved> {
        // Q-312: a held connection is checked before it is reused.
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
            if uid != self.expected_uid {
                // Dropped here: nothing was sent on it.
                return Err(Unserved::PeerMismatch);
            }
            if self.description.is_some() || self.caller_role.is_some() {
                // Q-311 / Q-351: the start-time check, repeated on this
                // connection before anything else is sent on it. On any
                // failure the connection is dropped here.
                let left = remaining(start, self.deadline).map_err(Unserved::Transport)?;
                let described = describe_on(&mut connection, left)?;
                let description_matches = self
                    .description
                    .as_ref()
                    .is_none_or(|expected| described.description == *expected);
                let role_matches = self
                    .caller_role
                    .is_none_or(|expected| described.caller_role == expected);
                if !(description_matches && role_matches) {
                    return Err(Unserved::PeerMismatch);
                }
            }
            self.connection = Some(Verified { connection });
        }
        match self.connection.as_mut() {
            Some(verified) => Ok(&mut verified.connection),
            None => Err(Unserved::Transport(TransportError::Connect)),
        }
    }

    /// Perform one call: encode it, send it on a verified connection,
    /// receive and decode the reply strictly, and check that it belongs to
    /// the call's operation. Any failure drops the connection; the call is
    /// never sent a second time (Q-312: it may already have run in keyd).
    ///
    /// The failure does not say whether the request was sent; a caller that
    /// must know — a key-state change — uses [`KeydClient::call_with_fate`].
    ///
    /// Spec: docs/50 §3.3 (replies decoded with the same strictness), §3.6,
    /// §3.7, R50-7; docs/questions/Q-312 (A-82).
    pub fn call(&mut self, call: &Call) -> Result<Answer, Unserved> {
        self.call_with_fate(call)
            .map_err(|failure| failure.unserved)
    }

    /// [`KeydClient::call`], with the fate of a request keyd did not answer
    /// ([`CallFailure`]): **not sent** (nothing left this process),
    /// **not performed** (keyd refused it with the shared `Refused`), or
    /// **outcome unknown** (handed to the connection, no usable reply —
    /// check before retrying). keyd's own answer, its refusals included, is
    /// `Ok` exactly as from `call`. Any failure drops the connection; the
    /// call is never sent a second time.
    ///
    /// Spec: module documentation; docs/questions/Q-367 (A-88), Q-312
    /// (A-82); docs/10 §10; docs/50 §3.6, §3.7, R50-7.
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
            // A-88: keyd-daemon refuses a key-state change only before keyd
            // runs it.
            Reply::Refused(refused) => Err(CallFailure {
                unserved: Unserved::Refused(refused),
                fate: RequestFate::NotPerformed,
            }),
            Reply::Message(reply) => Answer::from_wire(operation, reply)
                .map_err(|error| CallFailure::outcome_unknown(Unserved::UnexpectedReply(error))),
        }
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
        match self.call(&call) {
            Ok(Answer::VerifyPreauth(result)) => result,
            _ => Err(AuthnError::Unavailable),
        }
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
        match self.call(&call) {
            Ok(Answer::IssueAsRep(result)) => result,
            _ => Err(IssueError::Unavailable),
        }
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
        match self.call(&call) {
            Ok(Answer::OpenFastArmor(result)) => result,
            _ => Err(AuthnError::Unavailable),
        }
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
        match self.call(&call) {
            Ok(Answer::OpenAndVerifyTgt(result)) => result,
            _ => Err(AuthnError::Unavailable),
        }
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
        match self.call(&call) {
            Ok(Answer::IssueTgsRep(result)) => result,
            _ => Err(IssueError::Unavailable),
        }
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
        match self.call(&call) {
            Ok(Answer::SealFastError(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// docs/10 §5ב `open_and_verify_service_ticket` (Role::Ldap): the
    /// service key set's principal and the binding, whose purpose the key
    /// set is (R2).
    /// Spec: docs/50 §3.4; docs/52 §5 item 3.
    pub fn open_and_verify_service_ticket(
        &mut self,
        service: &PrincipalId,
        binding: &AppBinding,
        ap_req_octets: &[u8],
    ) -> Result<ServiceContext, AuthnError> {
        let call = Call::OpenAndVerifyServiceTicket {
            service: *service,
            binding: *binding,
            ap_req_octets: ap_req_octets.to_vec(),
        };
        match self.call(&call) {
            Ok(Answer::OpenAndVerifyServiceTicket(result)) => result,
            _ => Err(AuthnError::Unavailable),
        }
    }

    /// docs/10 §6 `set_secret` (Role::Directory). The password travels only
    /// in zeroizing buffers.
    ///
    /// A key-state change (docs/10 §10): `Err(Unavailable)` here is keyd's
    /// own answer **or** any failure of the call, a lost reply included; a
    /// caller that must tell "not performed" from "outcome unknown" sends
    /// [`Call::SetSecret`] with [`KeydClient::call_with_fate`] (Q-367,
    /// A-88). The same holds for `create_key`, `rotate_key`,
    /// `rotate_krbtgt`, `retire_kvno` and `destroy_key_set`.
    ///
    /// Spec: docs/50 §3.3, §3.4; docs/10 I7, §10; docs/questions/Q-367
    /// (A-88).
    pub fn set_secret(
        &mut self,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
        password: Zeroizing<String>,
        salt: &str,
    ) -> Result<Kvno, keyd_types::Error> {
        let call = Call::SetSecret {
            handle: *handle,
            binding: binding.clone(),
            password: Password::new(password),
            salt: salt.to_owned(),
        };
        match self.call(&call) {
            Ok(Answer::SetSecret(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// docs/10 §7 `create_key` (Role::Admin; the provisioning ceremony only,
    /// A-102). A key-state change: see [`KeydClient::set_secret`] on
    /// `Unavailable` and [`KeydClient::call_with_fate`]. Spec: docs/50 §3.4;
    /// docs/10 §10; docs/questions/Q-367 (A-88).
    pub fn create_key(
        &mut self,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
    ) -> Result<Kvno, keyd_types::Error> {
        let call = Call::CreateKey {
            handle: *handle,
            binding: binding.clone(),
        };
        match self.call(&call) {
            Ok(Answer::CreateKey(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// docs/10 §7 `rotate_key` (Role::Admin): run dird's `RotateKey`
    /// decision `decision` (A-102). A key-state change: see
    /// [`KeydClient::set_secret`]. Spec: docs/50 §3.4; docs/10 §10; docs/52
    /// §4.2.
    pub fn rotate_key(&mut self, decision: DecisionId) -> Result<Kvno, keyd_types::Error> {
        match self.call(&Call::RotateKey { decision }) {
            Ok(Answer::RotateKey(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// docs/10 §7 `rotate_krbtgt` (Role::Admin): run dird's `RotateKrbtgt`
    /// decision `decision` (A-102; keyd builds the dual-control token from
    /// the decision's approvers). A key-state change: see
    /// [`KeydClient::set_secret`]. Spec: docs/50 §3.4; docs/10 §10; docs/52
    /// §4.2.
    pub fn rotate_krbtgt(&mut self, decision: DecisionId) -> Result<Kvno, keyd_types::Error> {
        match self.call(&Call::RotateKrbtgt { decision }) {
            Ok(Answer::RotateKrbtgt(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// docs/10 §7 `retire_kvno` (Role::Admin): run dird's `RetireKvno`
    /// decision `decision` (A-102). A key-state change: see
    /// [`KeydClient::set_secret`]. Spec: docs/50 §3.4; docs/10 §10; docs/52
    /// §4.2.
    pub fn retire_kvno(&mut self, decision: DecisionId) -> Result<(), keyd_types::Error> {
        match self.call(&Call::RetireKvno { decision }) {
            Ok(Answer::RetireKvno(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// docs/10 §7 `destroy_key_set` (Role::Admin): run dird's
    /// `DestroyKeySet` decision `decision` (A-102). A key-state change: see
    /// [`KeydClient::set_secret`]. Spec: docs/50 §3.4; docs/10 §10; A-35;
    /// docs/52 §4.2.
    pub fn destroy_key_set(&mut self, decision: DecisionId) -> Result<(), keyd_types::Error> {
        match self.call(&Call::DestroyKeySet { decision }) {
            Ok(Answer::DestroyKeySet(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// `seal_ceremony` (Role::Admin): end keyd's provisioning ceremony
    /// (A-102, docs/52 R3). Spec: docs/52 §4.4.
    pub fn seal_ceremony(&mut self) -> Result<(), keyd_types::Error> {
        match self.call(&Call::SealCeremony) {
            Ok(Answer::SealCeremony(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// `list_destroy_decisions` (Role::Admin): one page of the pending
    /// destroy decisions dird registered, strictly after `after` (A-102).
    /// Spec: docs/52 §4.6.
    pub fn list_destroy_decisions(
        &mut self,
        after: Option<DecisionId>,
    ) -> Result<DestructionPage, keyd_types::Error> {
        match self.call(&Call::ListDestroyDecisions { after }) {
            Ok(Answer::ListDestroyDecisions(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// `register_decision` (Role::Ldap — dird): record decision `id` to run
    /// `operation`, approved by `approvers`, live for `lifetime_secs` by
    /// keyd's clock (A-102, docs/52 R1). It loosens keyd, so keyd-daemon has
    /// its intent acknowledged by auditd first: `Err(Unavailable)` here is
    /// keyd's own answer **or** any failure of the call; a caller that must
    /// tell "not registered" from "outcome unknown" sends
    /// [`Call::RegisterDecision`] with [`KeydClient::call_with_fate`].
    /// Spec: docs/52 §4.2, §4.5; docs/questions/Q-460.
    pub fn register_decision(
        &mut self,
        id: DecisionId,
        operation: &DecidedOperation,
        approvers: &[PrincipalId],
        lifetime_secs: u32,
    ) -> Result<(), keyd_types::Error> {
        let call = Call::RegisterDecision {
            id,
            operation: operation.clone(),
            approvers: approvers.to_vec(),
            lifetime_secs,
        };
        match self.call(&call) {
            Ok(Answer::RegisterDecision(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
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
        match self.call(&Call::DescribeConfig) {
            Ok(Answer::DescribeConfig(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// docs/10 §7א `ping` (every role). Spec: docs/50 §3.4, §7.5.
    pub fn ping(&mut self) -> Result<(), keyd_types::Error> {
        match self.call(&Call::Ping) {
            Ok(Answer::Ping(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// `grant_set_secret` (Role::Admin — keyadm's ceremony, before the seal;
    /// A-102): register a one-time grant, live for `lifetime_secs` by keyd's
    /// clock, that lets Role::Directory run one `set_secret` on each of
    /// `targets` with exactly its binding and salt. dird registers
    /// `SetSecret` decisions instead ([`KeydClient::register_decision`]).
    ///
    /// It loosens keyd, so keyd-daemon has its intent acknowledged by auditd
    /// before keyd registers it (as for a key-state change, A-88):
    /// `Err(Unavailable)` here is keyd's own answer **or** any failure of the
    /// call; a caller that must tell "not registered" from "outcome unknown"
    /// sends [`Call::GrantSetSecret`] with [`KeydClient::call_with_fate`].
    /// Added by task A15a; every existing method is unchanged.
    ///
    /// Spec: docs/51 §5.8 option (b); docs/50 §3.4; docs/questions/Q-291
    /// (A-74), Q-450, Q-452.
    pub fn grant_set_secret(
        &mut self,
        kind: AccountKind,
        targets: &[SetSecretTarget],
        lifetime_secs: u32,
    ) -> Result<(), keyd_types::Error> {
        let call = Call::GrantSetSecret {
            kind,
            targets: targets.to_vec(),
            lifetime_secs,
        };
        match self.call(&call) {
            Ok(Answer::GrantSetSecret(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }
}

/// The keyd custody of the kdc daemon: [`KeydClient`] behind
/// `KeyCustody`, with keyd's non-secret configuration fetched once
/// (`describe_config`) when it is built — and required of every new
/// connection afterwards ([`KeydClient::require_description`]), so that
/// [`KeyCustody::config`] stays the description of the keyd that serves the
/// calls (docs/questions/Q-311) — and with the caller role `Kdc` required
/// of that first answer and of every new connection
/// ([`KeydClient::require_caller_role`]; docs/questions/Q-351).
///
/// Spec: docs/50 §3.4, §7.5 step 4 ("`DescribeConfig` from keyd …
/// `KdcConfig::validate(&keyd_config)` — only then bind 88"), §10; docs/10
/// §2, §7א; docs/questions/Q-311 (A-82), Q-351 (A-87).
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
    /// Ask keyd for its configuration and build the custody. Fails with
    /// keyd's error (or `Unavailable`) when keyd does not answer it — the
    /// kdc daemon then does not start (fail closed, docs/50 §7.5). Fails
    /// with `Unavailable` when keyd answers it for a caller role other than
    /// `Kdc` (this uid mapped to Ldap): the client and the connection that
    /// answered are dropped, nothing else was sent (docs/questions/Q-351).
    ///
    /// The description and the caller role `Kdc` are then required of every
    /// new connection the client opens (the connection that answered them is
    /// kept): a keyd that no longer gives them — restarted with this uid
    /// mapped to another role, or with another configuration — serves no
    /// call (`Unavailable`) until it does again.
    ///
    /// Spec: docs/50 §7.5 step 4, §3.7; docs/10 §2; docs/questions/Q-311
    /// (A-82), Q-351 (A-87).
    pub fn connect(mut client: KeydClient<C>) -> Result<Self, keyd_types::Error> {
        let described = client.describe_config_with_role()?;
        if described.caller_role != KDC_CALLER_ROLE {
            // Q-351: keyd does not give this process the Kdc role; the
            // connection that answered goes with the client.
            return Err(keyd_types::Error::Unavailable);
        }
        let description = described.description;
        client.require_description(description.clone());
        client.require_caller_role(KDC_CALLER_ROLE);
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
