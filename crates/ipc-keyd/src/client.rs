//! The client side: a synchronous keyd client over a connection trait, and
//! [`IpcKeyd`], the `kdc::KeyCustody` the kdc daemon builds its `Kdc` with.
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
//! # Keyd did not serve the call → `Unavailable`, never `Denied`
//!
//! | what happened | the caller sees |
//! |---|---|
//! | connect failed, I/O error, peer closed, deadline exceeded | `Unavailable` |
//! | peer uid unreadable or not keyd's | `Unavailable` (nothing was sent) |
//! | `Refused::Busy` / `Refused::Unavailable` | `Unavailable` |
//! | `Refused::Malformed` / `Refused::VersionMismatch` | `Unavailable` |
//! | a reply that does not decode, or belongs to another operation | `Unavailable` |
//! | the call could not be encoded | `Unavailable` (nothing was sent) |
//! | keyd's own answer | exactly keyd's answer (A-26 classes, keyd's `Unavailable`) |
//!
//! `Unavailable` is the `Unavailable` variant of the operation's own error
//! type (`AuthnError`, `IssueError`, `keyd::Error`), which the KDC answers
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
//! Spec: docs/50 §3.1-§3.7 (R50-3, R50-5, R50-7, R50-8), §10 (`ipc-keyd`:
//! "a synchronous client implementing `kdc::KeyCustody`"); docs/10 §9;
//! docs/questions/Q-217, Q-222 (A-56), Q-240 item 8 (A-62).

use crate::channel::{KEYD_CHANNEL, REPLY_LIMIT};
use crate::typed::{Answer, Call, ConversionError, Password, TgsFast};
use crate::wire::KeydReply;
use core::fmt;
use core::time::Duration;
use ipc::{decode_reply, encode_frame, Direction, FrameLimit, Refused, Reply};
use kdc::KeyCustody;
use keyd::{
    ArmorId, AsRepParts, AsTicketTemplate, AuthnError, AuthnProof, ConfigDescription, CtxId,
    DualControlToken, FastArmor, FastConversation, IssueError, KeyHandle, Kvno, PrincipalBinding,
    ServiceContext, TgsFastRequest, TgsRepParts, TgsTicketTemplate, TgtContext,
};
use krb_proto::{ApReq, EncryptedData, KerberosTime, KrbError, KrbFastArmoredReq, PaData};
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
    /// The peer is not the configured keyd uid; nothing was sent.
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

/// A connection whose peer uid was checked against keyd's.
struct Verified<C> {
    connection: C,
}

/// A synchronous keyd client: every operation of the keyd channel, called
/// with the caller identity keyd derives from this process's credentials.
///
/// Spec: docs/50 §3.2 (R50-3), §3.6 (R50-7), §3.7 (R50-8), §10.
pub struct KeydClient<C: Connector> {
    connector: C,
    expected_uid: u32,
    deadline: Duration,
    connection: Option<Verified<C::Connection>>,
}

impl<C: Connector> fmt::Debug for KeydClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeydClient")
            .field("expected_uid", &self.expected_uid)
            .field("deadline", &self.deadline)
            .field("connected", &self.connection.is_some())
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

    /// The open connection, opening and verifying a new one if needed: its
    /// peer uid must be keyd's before it is used at all.
    /// Spec: docs/50 R50-3, §3.2.
    fn verified(&mut self) -> Result<&mut C::Connection, Unserved> {
        if self.connection.is_none() {
            let connection = self.connector.connect().map_err(Unserved::Transport)?;
            let uid = connection.peer_uid().map_err(Unserved::Transport)?;
            if uid != self.expected_uid {
                // Dropped here: nothing was sent on it.
                return Err(Unserved::PeerMismatch);
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
    /// the call's operation. Any failure drops the connection.
    ///
    /// Spec: docs/50 §3.3 (replies decoded with the same strictness), §3.6,
    /// §3.7, R50-7.
    pub fn call(&mut self, call: &Call) -> Result<Answer, Unserved> {
        let result = self.call_inner(call);
        if result.is_err() {
            self.connection = None;
        }
        result
    }

    fn call_inner(&mut self, call: &Call) -> Result<Answer, Unserved> {
        let operation = call.operation();
        let request = call.to_wire().map_err(|_| Unserved::Unencodable)?;
        let frame = encode_frame(KEYD_CHANNEL, Direction::Request, &request)
            .map_err(|_| Unserved::Unencodable)?;
        drop(request);
        let deadline = self.deadline;
        let connection = self.verified()?;
        let body = connection
            .exchange(frame.as_bytes(), REPLY_LIMIT, deadline)
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
    ) -> Result<EncryptedData, keyd::Error> {
        let call = Call::SealFastError {
            conversation: *conversation,
            error: error.clone(),
            padata: padata.to_vec(),
        };
        match self.call(&call) {
            Ok(Answer::SealFastError(result)) => result,
            _ => Err(keyd::Error::Unavailable),
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
    ) -> Result<Kvno, keyd::Error> {
        let call = Call::SetSecret {
            handle: *handle,
            binding: binding.clone(),
            password: Password::new(password),
            salt: salt.to_owned(),
        };
        match self.call(&call) {
            Ok(Answer::SetSecret(result)) => result,
            _ => Err(keyd::Error::Unavailable),
        }
    }

    /// docs/10 §6 `verify_secret` (Role::Directory). Spec: docs/50 §3.3,
    /// §3.4; docs/10 I6, I7.
    pub fn verify_secret(
        &mut self,
        handle: &KeyHandle,
        candidate: Zeroizing<String>,
    ) -> Result<(), keyd::Error> {
        let call = Call::VerifySecret {
            handle: *handle,
            candidate: Password::new(candidate),
        };
        match self.call(&call) {
            Ok(Answer::VerifySecret(result)) => result,
            _ => Err(keyd::Error::Unavailable),
        }
    }

    /// docs/10 §7 `create_key` (Role::Admin). Spec: docs/50 §3.4.
    pub fn create_key(
        &mut self,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
    ) -> Result<Kvno, keyd::Error> {
        let call = Call::CreateKey {
            handle: *handle,
            binding: binding.clone(),
        };
        match self.call(&call) {
            Ok(Answer::CreateKey(result)) => result,
            _ => Err(keyd::Error::Unavailable),
        }
    }

    /// docs/10 §7 `rotate_key` (Role::Admin). Spec: docs/50 §3.4.
    pub fn rotate_key(&mut self, handle: &KeyHandle) -> Result<Kvno, keyd::Error> {
        match self.call(&Call::RotateKey { handle: *handle }) {
            Ok(Answer::RotateKey(result)) => result,
            _ => Err(keyd::Error::Unavailable),
        }
    }

    /// docs/10 §7 `rotate_krbtgt` (Role::Admin). Spec: docs/50 §3.4.
    pub fn rotate_krbtgt(
        &mut self,
        krbtgt: &KeyHandle,
        approval: &DualControlToken,
    ) -> Result<Kvno, keyd::Error> {
        let call = Call::RotateKrbtgt {
            krbtgt: *krbtgt,
            approval: *approval,
        };
        match self.call(&call) {
            Ok(Answer::RotateKrbtgt(result)) => result,
            _ => Err(keyd::Error::Unavailable),
        }
    }

    /// docs/10 §7 `retire_kvno` (Role::Admin). Spec: docs/50 §3.4.
    pub fn retire_kvno(&mut self, handle: &KeyHandle, kvno: Kvno) -> Result<(), keyd::Error> {
        let call = Call::RetireKvno {
            handle: *handle,
            kvno,
        };
        match self.call(&call) {
            Ok(Answer::RetireKvno(result)) => result,
            _ => Err(keyd::Error::Unavailable),
        }
    }

    /// docs/10 §7 `destroy_key_set` (Role::Admin). Spec: docs/50 §3.4; A-35.
    pub fn destroy_key_set(&mut self, handle: &KeyHandle) -> Result<(), keyd::Error> {
        match self.call(&Call::DestroyKeySet { handle: *handle }) {
            Ok(Answer::DestroyKeySet(result)) => result,
            _ => Err(keyd::Error::Unavailable),
        }
    }

    /// docs/10 §7א `describe_config` (Kdc, Ldap). Spec: docs/50 §3.4, §7.5.
    pub fn describe_config(&mut self) -> Result<ConfigDescription, keyd::Error> {
        match self.call(&Call::DescribeConfig) {
            Ok(Answer::DescribeConfig(result)) => result,
            _ => Err(keyd::Error::Unavailable),
        }
    }

    /// docs/10 §7א `ping` (every role). Spec: docs/50 §3.4, §7.5.
    pub fn ping(&mut self) -> Result<(), keyd::Error> {
        match self.call(&Call::Ping) {
            Ok(Answer::Ping(result)) => result,
            _ => Err(keyd::Error::Unavailable),
        }
    }
}

/// The keyd custody of the kdc daemon: [`KeydClient`] behind
/// `kdc::KeyCustody`, with keyd's non-secret configuration fetched once
/// (`describe_config`) when it is built.
///
/// Spec: docs/50 §3.4, §7.5 step 4 ("`DescribeConfig` from keyd …
/// `KdcConfig::validate(&keyd_config)` — only then bind 88"), §10; docs/10
/// §7א.
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
    /// Spec: docs/50 §7.5 step 4.
    pub fn connect(mut client: KeydClient<C>) -> Result<Self, keyd::Error> {
        let description = client.describe_config()?;
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
    ) -> Result<EncryptedData, keyd::Error> {
        self.client.seal_fast_error(conversation, error, padata)
    }
}
