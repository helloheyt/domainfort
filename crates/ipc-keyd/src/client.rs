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
//! # Each new connection is checked with `DescribeConfig` (Q-311)
//!
//! With [`KeydClient::require_description`] (set by [`IpcKeyd::connect`]),
//! every new connection, after its peer uid and before any other request,
//! carries a `DescribeConfig` whose answer must be exactly the description
//! the client was built with. Only the Kdc and Ldap roles may call it
//! (docs/10 §2), so a keyd restarted with this uid mapped to another role —
//! or serving another realm — is found here; the connection is dropped and
//! the call is not served (`Unavailable`, the KDC's 29), instead of reaching
//! an operation whose uniform `Denied` the KDC would report as a wrong
//! password (24). Residual: Kdc and Ldap are not told apart this way
//! (docs/questions/Q-351).
//!
//! # Keyd did not serve the call → `Unavailable`, never `Denied`
//!
//! | what happened | the caller sees |
//! |---|---|
//! | connect failed, I/O error, peer closed, deadline exceeded | `Unavailable` |
//! | peer uid unreadable or not keyd's | `Unavailable` (nothing was sent) |
//! | the new connection's `DescribeConfig` refused or different (when required) | `Unavailable` (only `DescribeConfig` was sent) |
//! | `Refused::Busy` / `Refused::Unavailable` | `Unavailable` |
//! | `Refused::Malformed` / `Refused::VersionMismatch` | `Unavailable` |
//! | a reply that does not decode, or belongs to another operation | `Unavailable` |
//! | the call could not be encoded | `Unavailable` (nothing was sent) |
//! | keyd's own answer | exactly keyd's answer (A-26 classes, keyd's `Unavailable`) |
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
//! trait is `keyd_types::KeyCustody` since D182 / A-63); docs/10 §2, §9;
//! docs/questions/Q-217, Q-222 (A-56), Q-240 item 8 (A-62), Q-311, Q-312
//! (A-82).

use crate::channel::{KEYD_CHANNEL, REPLY_LIMIT};
use crate::typed::{Answer, Call, ConversionError, Password, TgsFast};
use crate::wire::KeydReply;
use core::fmt;
use core::time::Duration;
use ipc::{decode_reply, encode_frame, Direction, FrameLimit, Refused, Reply};
use keyd_types::{
    ArmorId, AsRepParts, AsTicketTemplate, AuthnError, AuthnProof, ConfigDescription, CtxId,
    DualControlToken, FastArmor, FastConversation, IssueError, KeyCustody, KeyHandle, Kvno,
    PrincipalBinding, ServiceContext, TgsFastRequest, TgsRepParts, TgsTicketTemplate, TgtContext,
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
/// Spec: docs/50 §3.7 (R50-8); docs/questions/Q-245 item 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unserved {
    /// The transport failed.
    Transport(TransportError),
    /// The peer is not the keyd this client was configured for: its uid is
    /// not keyd's (nothing was sent), or — when the client requires a
    /// description ([`KeydClient::require_description`]) — the new
    /// connection's `DescribeConfig` was refused or answered another
    /// description (nothing else was sent; docs/questions/Q-311).
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
/// client requires one, whose `DescribeConfig` answer matched).
struct Verified<C> {
    connection: C,
}

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
/// else yet: keyd's description, or why it was not given. keyd's own
/// refusal (`Denied` for a role that may not call it, docs/10 §2) is
/// [`Unserved::PeerMismatch`].
/// Spec: docs/50 §3.3, §3.4 (`DescribeConfig` — Kdc, Ldap), §7.5 step 4;
/// docs/questions/Q-311 (A-82).
fn describe_on<K: Connection>(
    connection: &mut K,
    deadline: Duration,
) -> Result<ConfigDescription, Unserved> {
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
            Ok(Answer::DescribeConfig(Ok(description))) => Ok(description),
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
/// docs/questions/Q-311, Q-312 (A-82).
pub struct KeydClient<C: Connector> {
    connector: C,
    expected_uid: u32,
    deadline: Duration,
    connection: Option<Verified<C::Connection>>,
    /// When set, every new connection's `DescribeConfig` must answer
    /// exactly this (Q-311).
    description: Option<ConfigDescription>,
}

impl<C: Connector> fmt::Debug for KeydClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeydClient")
            .field("expected_uid", &self.expected_uid)
            .field("deadline", &self.deadline)
            .field("connected", &self.connection.is_some())
            .field("checks_description", &self.description.is_some())
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
    /// another role must not require a description.
    ///
    /// Spec: docs/50 R50-3, R50-8, §3.4, §7.5 step 4; docs/questions/Q-311
    /// (A-82).
    pub fn require_description(&mut self, description: ConfigDescription) {
        self.description = Some(description);
    }

    /// The description every new connection must answer, if required.
    /// Spec: docs/questions/Q-311 (A-82).
    #[must_use]
    pub fn required_description(&self) -> Option<&ConfigDescription> {
        self.description.as_ref()
    }

    /// The held connection if it is still usable, or a new one — its peer
    /// uid keyd's and, when required, its `DescribeConfig` answer the
    /// expected description — before anything else is sent on it. A held
    /// connection that fails its idle check is dropped here, before the
    /// request is sent (nothing was sent on it in this call).
    /// Spec: docs/50 R50-3, §3.2, §3.6, §3.7; docs/questions/Q-311, Q-312
    /// (A-82).
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
            if let Some(expected) = self.description.as_ref() {
                // Q-311: the start-time check, repeated on this connection
                // before anything else is sent on it. On any failure the
                // connection is dropped here.
                let left = remaining(start, self.deadline).map_err(Unserved::Transport)?;
                if describe_on(&mut connection, left)? != *expected {
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
    /// Spec: docs/50 §3.3 (replies decoded with the same strictness), §3.6,
    /// §3.7, R50-7; docs/questions/Q-312 (A-82).
    pub fn call(&mut self, call: &Call) -> Result<Answer, Unserved> {
        let result = self.call_inner(call);
        if result.is_err() {
            self.connection = None;
        }
        result
    }

    fn call_inner(&mut self, call: &Call) -> Result<Answer, Unserved> {
        let start = Instant::now();
        let operation = call.operation();
        let request = call.to_wire().map_err(|_| Unserved::Unencodable)?;
        let frame = encode_frame(KEYD_CHANNEL, Direction::Request, &request)
            .map_err(|_| Unserved::Unencodable)?;
        drop(request);
        let deadline = self.deadline;
        let connection = self.verified(start)?;
        let left = remaining(start, deadline).map_err(Unserved::Transport)?;
        let body = connection
            .exchange(frame.as_bytes(), REPLY_LIMIT, left)
            .map_err(Unserved::Transport)?;
        drop(frame);
        match decode_reply::<KeydReply>(KEYD_CHANNEL, &body).map_err(Unserved::MalformedReply)? {
            Reply::Refused(refused) => Err(Unserved::Refused(refused)),
            Reply::Message(reply) => {
                Answer::from_wire(operation, reply).map_err(Unserved::UnexpectedReply)
            }
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

    /// docs/10 §5ב `open_and_verify_service_ticket` (Role::Ldap).
    /// Spec: docs/50 §3.4.
    pub fn open_and_verify_service_ticket(
        &mut self,
        service: &KeyHandle,
        ap_req_octets: &[u8],
    ) -> Result<ServiceContext, AuthnError> {
        let call = Call::OpenAndVerifyServiceTicket {
            service: *service,
            ap_req_octets: ap_req_octets.to_vec(),
        };
        match self.call(&call) {
            Ok(Answer::OpenAndVerifyServiceTicket(result)) => result,
            _ => Err(AuthnError::Unavailable),
        }
    }

    /// docs/10 §6 `set_secret` (Role::Directory). The password travels only
    /// in zeroizing buffers. Spec: docs/50 §3.3, §3.4; docs/10 I7.
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

    /// docs/10 §6 `verify_secret` (Role::Directory). Spec: docs/50 §3.3,
    /// §3.4; docs/10 I6, I7.
    pub fn verify_secret(
        &mut self,
        handle: &KeyHandle,
        candidate: Zeroizing<String>,
    ) -> Result<(), keyd_types::Error> {
        let call = Call::VerifySecret {
            handle: *handle,
            candidate: Password::new(candidate),
        };
        match self.call(&call) {
            Ok(Answer::VerifySecret(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// docs/10 §7 `create_key` (Role::Admin). Spec: docs/50 §3.4.
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

    /// docs/10 §7 `rotate_key` (Role::Admin). Spec: docs/50 §3.4.
    pub fn rotate_key(&mut self, handle: &KeyHandle) -> Result<Kvno, keyd_types::Error> {
        match self.call(&Call::RotateKey { handle: *handle }) {
            Ok(Answer::RotateKey(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// docs/10 §7 `rotate_krbtgt` (Role::Admin). Spec: docs/50 §3.4.
    pub fn rotate_krbtgt(
        &mut self,
        krbtgt: &KeyHandle,
        approval: &DualControlToken,
    ) -> Result<Kvno, keyd_types::Error> {
        let call = Call::RotateKrbtgt {
            krbtgt: *krbtgt,
            approval: *approval,
        };
        match self.call(&call) {
            Ok(Answer::RotateKrbtgt(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// docs/10 §7 `retire_kvno` (Role::Admin). Spec: docs/50 §3.4.
    pub fn retire_kvno(&mut self, handle: &KeyHandle, kvno: Kvno) -> Result<(), keyd_types::Error> {
        let call = Call::RetireKvno {
            handle: *handle,
            kvno,
        };
        match self.call(&call) {
            Ok(Answer::RetireKvno(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// docs/10 §7 `destroy_key_set` (Role::Admin). Spec: docs/50 §3.4; A-35.
    pub fn destroy_key_set(&mut self, handle: &KeyHandle) -> Result<(), keyd_types::Error> {
        match self.call(&Call::DestroyKeySet { handle: *handle }) {
            Ok(Answer::DestroyKeySet(result)) => result,
            _ => Err(keyd_types::Error::Unavailable),
        }
    }

    /// docs/10 §7א `describe_config` (Kdc, Ldap). Spec: docs/50 §3.4, §7.5.
    pub fn describe_config(&mut self) -> Result<ConfigDescription, keyd_types::Error> {
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
}

/// The keyd custody of the kdc daemon: [`KeydClient`] behind
/// `KeyCustody`, with keyd's non-secret configuration fetched once
/// (`describe_config`) when it is built — and required of every new
/// connection afterwards ([`KeydClient::require_description`]), so that
/// [`KeyCustody::config`] stays the description of the keyd that serves the
/// calls (docs/questions/Q-311).
///
/// Spec: docs/50 §3.4, §7.5 step 4 ("`DescribeConfig` from keyd …
/// `KdcConfig::validate(&keyd_config)` — only then bind 88"), §10; docs/10
/// §7א; docs/questions/Q-311 (A-82).
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
    /// kdc daemon then does not start (fail closed, docs/50 §7.5).
    ///
    /// The description is then required of every new connection the client
    /// opens (the connection that answered it is kept): a keyd that no
    /// longer gives it — restarted with this uid mapped to another role, or
    /// with another configuration — serves no call (`Unavailable`) until it
    /// does again.
    ///
    /// Spec: docs/50 §7.5 step 4; docs/questions/Q-311 (A-82).
    pub fn connect(mut client: KeydClient<C>) -> Result<Self, keyd_types::Error> {
        let description = client.describe_config()?;
        client.require_description(description.clone());
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
