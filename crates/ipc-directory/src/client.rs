//! The kdc's side: a synchronous client of the directory-view channel, and
//! [`RemoteView`] — the per-request view, pinned to one dird snapshot, that
//! the kdc hands to `Kdc::handle` both as its `AccountSource` and as the PIP
//! of its `PolicyInputs` (docs/47 §8.1, R47-14; docs/50 R50-2).
//!
//! # Connections
//!
//! [`Connector`] opens a connection; [`Connection`] reports the peer's uid
//! (from the transport's peer credentials) and carries one request frame and
//! its one reply frame within a deadline. Tests use an in-process loopback;
//! the kdc daemon a blocking Unix stream socket (`crate::unix`).
//!
//! [`DirectoryClient`] checks the peer uid of every new connection against
//! dird's configured uid **before** anything is sent on it (R50-3), keeps it
//! for the following calls — one request in flight, strict request → reply
//! (R50-7) — and drops it on any failure; the next call reconnects. dird
//! releases a connection's view when the connection ends (docs/50 §3.4).
//!
//! # The view and the policy version (R50-2)
//!
//! [`DirectoryClient::begin_view`] asks dird to pin one snapshot (and its
//! tier map) to the connection. dird answers the view id and the version of
//! its policy; if that version is not the kdc's own (the version of the
//! `PolicySnapshot` the kdc loaded, given to [`DirectoryClient::new`]), the
//! view is refused locally — [`Unserved::PolicyVersionMismatch`] — so the
//! request fails closed and the kdc daemon reloads its policy (docs/50 §3.4:
//! "if the `policy_version` dird returned ≠ the version of the kdc's
//! `PolicySnapshot` ⇒ the request fails closed and the kdc reloads"; docs/11
//! §9, D39). The kdc daemon answers such a request without a view through
//! [`UnavailableDirectory`].
//!
//! # dird did not serve → `Unavailable`, never `Failed`
//!
//! | what happened | `AccountSource` sees | `Pip` sees |
//! |---|---|---|
//! | connect failed, I/O error, peer closed, deadline exceeded | `Unavailable` | `PipError::Unavailable` |
//! | peer uid unreadable or not dird's (nothing sent) | `Unavailable` | `PipError::Unavailable` |
//! | `Refused::{Busy, Unavailable, Malformed, VersionMismatch}` | `Unavailable` | `PipError::Unavailable` |
//! | a reply that does not decode, or answers another request | `Unavailable` | `PipError::Unavailable` |
//! | the view protocol refused (unknown, expired, bound reached, no snapshot) | `Unavailable` | `PipError::Unavailable` |
//! | the view broke earlier in this request | `Unavailable` | `PipError::Unavailable` |
//! | the view's own answer | exactly the view's answer (`Ok`, `Failed`) | exactly the view's answer |
//!
//! `AccountSourceError::Unavailable` reaches the client as
//! KDC_ERR_SVC_UNAVAILABLE (29) over TCP, nothing over UDP; `Failed` would be
//! KRB_ERR_GENERIC — kept for the directory's own "cannot tell", exactly as
//! the in-process `DirectoryView` answers it (docs/50 §3.7, R50-8; A-56;
//! docs/questions/Q-245 item 4 for the keyd channel's equivalent).
//!
//! # The `Pip` subset
//!
//! Only `expand_groups` and `tier_of` go to dird: the KDC's PEP needs no
//! other (docs/47 §8.2: "for the KDC alone `expand_groups` and `tier_of` are
//! needed"; the KDC does not write, so `object_tier` is not asked). Every
//! other method answers `PipError::Unavailable` locally without asking ⇒ the
//! PDP denies (D40; docs/50 §3.4).
//!
//! Spec: docs/50 R50-2, R50-3, R50-7, R50-8, §3.1-§3.7, §7.5, §10; docs/47
//! §8.1, §8.2; docs/11 §6, §9; D40; A-56.

use crate::channel::{ViewFailure, DIRECTORY_CHANNEL, REPLY_LIMIT};
use crate::typed::{ConversionError, DomainDescription, Query, Request};
use crate::wire::DirectoryReply;
use core::cell::{Cell, RefCell};
use core::fmt;
use core::time::Duration;
use dtyp::{SecurityDescriptor, Sid};
use ipc::{decode_reply, encode_frame, Direction, FrameLimit, Refused, Reply};
use kdc::{AccountSource, AccountSourceError, ClientAccount, ServiceAccount};
use krb_proto::{PrincipalName, Realm};
use pdp::{
    AttrClass, AttrId, Dn, ObjClassChain, Pip, PipError, PolicyVersion, PropertySet, Resource, Tier,
};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

/// The default per-call deadline of the directory client: 2 seconds.
/// Spec: docs/50 §3.6 ("client deadline — … dird-kdc: 2 s; exceeded ⇒
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
            TransportError::Connect => "dird connection could not be opened",
            TransportError::PeerCredentials => "dird peer credentials unavailable",
            TransportError::Closed => "dird closed the connection",
            TransportError::DeadlineExceeded => "dird deadline exceeded",
            TransportError::Io => "dird connection I/O failure",
            TransportError::Framing => "dird reply did not frame",
        })
    }
}

impl std::error::Error for TransportError {}

/// One open connection to dird.
/// Spec: docs/50 §3.1 (Unix stream socket), §3.2 (peer credentials), §3.6
/// (deadline; strict request → reply).
pub trait Connection {
    /// The uid of the process at the other end, from the transport's peer
    /// credentials — never from anything the peer sends.
    /// Spec: docs/50 R50-3, §3.2.
    fn peer_uid(&self) -> Result<u32, TransportError>;

    /// Send one whole request frame (length prefix included) and receive the
    /// one reply frame, returning its body. The reply's declared length is
    /// checked against `reply_limit` before its body is awaited; the whole
    /// exchange completes within `deadline`.
    /// Spec: docs/50 §3.3 (bound before allocation), §3.6, R50-7.
    fn exchange(
        &mut self,
        frame: &[u8],
        reply_limit: FrameLimit,
        deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError>;
}

/// Opens connections to dird.
/// Spec: docs/50 §3.1, §3.7 ("reconnection with bounded backoff" — the
/// daemon's; this client reconnects at the next call).
pub trait Connector {
    /// The connection type.
    type Connection: Connection;

    /// Open a new connection.
    fn connect(&mut self) -> Result<Self::Connection, TransportError>;
}

/// Why dird did not serve a call. Every case reaches the KDC as
/// `Unavailable` (module docs).
/// Spec: docs/50 §3.7 (R50-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unserved {
    /// The transport failed.
    Transport(TransportError),
    /// The peer is not the configured dird uid; nothing was sent.
    PeerMismatch,
    /// dird answered with the shared transport refusal.
    Refused(Refused),
    /// The reply did not decode at the ipc layer.
    MalformedReply(ipc::Error),
    /// The reply decoded but a value did not, or it answers another request.
    UnexpectedReply(ConversionError),
    /// The request could not be encoded; nothing was sent.
    Unencodable,
    /// The view protocol refused the request.
    View(ViewFailure),
    /// dird's policy version is not the kdc's (R50-2): the kdc reloads.
    PolicyVersionMismatch {
        /// The version dird's view carries.
        dird: PolicyVersion,
    },
    /// The view failed earlier, was ended, or the client is busy with
    /// another call.
    ViewClosed,
}

impl fmt::Display for Unserved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unserved::Transport(error) => write!(f, "{error}"),
            Unserved::PeerMismatch => f.write_str("dird peer is not the configured uid"),
            Unserved::Refused(refused) => write!(f, "dird refused: {refused:?}"),
            Unserved::MalformedReply(error) => write!(f, "dird reply malformed: {error}"),
            Unserved::UnexpectedReply(error) => write!(f, "dird reply refused: {error}"),
            Unserved::Unencodable => f.write_str("request could not be encoded"),
            Unserved::View(failure) => write!(f, "dird refused the view: {failure:?}"),
            Unserved::PolicyVersionMismatch { dird } => {
                write!(f, "dird policy version {} is not the kdc's", dird.0)
            }
            Unserved::ViewClosed => f.write_str("view is closed"),
        }
    }
}

impl std::error::Error for Unserved {}

/// The client was configured with an unacceptable dird uid.
/// Spec: docs/50 §3.2 ("uid 0 is never mapped" — applied to the server's
/// identity as for keyd, docs/questions/Q-245 item 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientConfigError {
    /// dird's uid cannot be 0: dird never runs as root after its hardening
    /// (docs/50 §6), and accepting uid 0 would accept any root process.
    RootServerUid,
}

/// A synchronous client of the directory-view channel.
/// Spec: docs/50 R50-2, R50-3, R50-7, R50-8, §3.4, §3.6, §10.
pub struct DirectoryClient<C: Connector> {
    connector: C,
    expected_uid: u32,
    deadline: Duration,
    policy_version: PolicyVersion,
    connection: Option<C::Connection>,
}

impl<C: Connector> fmt::Debug for DirectoryClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectoryClient")
            .field("expected_uid", &self.expected_uid)
            .field("deadline", &self.deadline)
            .field("policy_version", &self.policy_version)
            .field("connected", &self.connection.is_some())
            .finish()
    }
}

impl<C: Connector> DirectoryClient<C> {
    /// A client of the dird process running as `expected_uid`, with a
    /// per-call `deadline` ([`DEFAULT_DEADLINE`] in the kdc daemon), for a
    /// kdc whose loaded policy has version `policy_version` (R50-2).
    ///
    /// # Errors
    /// [`ClientConfigError::RootServerUid`].
    ///
    /// Spec: docs/50 R50-2, R50-3, §3.6.
    pub fn new(
        connector: C,
        expected_uid: u32,
        deadline: Duration,
        policy_version: PolicyVersion,
    ) -> Result<Self, ClientConfigError> {
        if expected_uid == 0 {
            return Err(ClientConfigError::RootServerUid);
        }
        Ok(DirectoryClient {
            connector,
            expected_uid,
            deadline,
            policy_version,
            connection: None,
        })
    }

    /// The policy version views must carry.
    #[must_use]
    pub fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    /// Set the policy version views must carry (after the kdc reloaded its
    /// policy). Spec: docs/50 §3.4 ("the kdc reloads").
    pub fn set_policy_version(&mut self, version: PolicyVersion) {
        self.policy_version = version;
    }

    /// The connector (e.g. to inspect a test loopback).
    pub fn connector(&self) -> &C {
        &self.connector
    }

    /// Mutable access to the connector.
    pub fn connector_mut(&mut self) -> &mut C {
        &mut self.connector
    }

    /// Whether a verified connection is open.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connection.is_some()
    }

    /// The open connection, opening and verifying a new one if needed: its
    /// peer uid must be dird's before it is used at all.
    /// Spec: docs/50 R50-3, §3.2.
    fn verified(&mut self) -> Result<&mut C::Connection, Unserved> {
        if self.connection.is_none() {
            let connection = self.connector.connect().map_err(Unserved::Transport)?;
            let uid = connection.peer_uid().map_err(Unserved::Transport)?;
            if uid != self.expected_uid {
                // Dropped here: nothing was sent on it.
                return Err(Unserved::PeerMismatch);
            }
            self.connection = Some(connection);
        }
        self.connection
            .as_mut()
            .ok_or(Unserved::Transport(TransportError::Connect))
    }

    /// One exchange: encode, send on a verified connection, receive and
    /// decode the reply strictly. Any failure drops the connection (dird
    /// then releases the connection's view).
    /// Spec: docs/50 §3.3 (replies decoded with the same strictness), §3.6,
    /// §3.7, R50-7.
    fn call(&mut self, request: &Request) -> Result<DirectoryReply, Unserved> {
        let result = self.call_inner(request);
        if result.is_err() {
            self.connection = None;
        }
        result
    }

    fn call_inner(&mut self, request: &Request) -> Result<DirectoryReply, Unserved> {
        let wire = request.to_wire().map_err(|_| Unserved::Unencodable)?;
        let frame = encode_frame(DIRECTORY_CHANNEL, Direction::Request, &wire)
            .map_err(|_| Unserved::Unencodable)?;
        drop(wire);
        let deadline = self.deadline;
        let connection = self.verified()?;
        let body = connection
            .exchange(frame.as_bytes(), REPLY_LIMIT, deadline)
            .map_err(Unserved::Transport)?;
        match decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, &body)
            .map_err(Unserved::MalformedReply)?
        {
            Reply::Refused(refused) => Err(Unserved::Refused(refused)),
            Reply::Message(DirectoryReply::ViewFailure(failure)) => Err(Unserved::View(failure)),
            Reply::Message(reply) => Ok(reply),
        }
    }

    /// The domain description (once at the kdc's start: `KdcConfig::new(
    /// realm, krbtgt)`). The policy version is reported, not checked here.
    ///
    /// # Errors
    /// [`Unserved`].
    ///
    /// Spec: docs/50 §3.4, §7.5 step 4.
    pub fn describe_domain(&mut self) -> Result<DomainDescription, Unserved> {
        let reply = self.call(&Request::DescribeDomain)?;
        reply.into_domain().map_err(|error| {
            self.connection = None;
            Unserved::UnexpectedReply(error)
        })
    }

    /// Health check. Spec: docs/50 §7.5.
    ///
    /// # Errors
    /// [`Unserved`].
    pub fn ping(&mut self) -> Result<(), Unserved> {
        match self.call(&Request::Ping)? {
            DirectoryReply::Pong => Ok(()),
            _ => {
                self.connection = None;
                Err(Unserved::UnexpectedReply(ConversionError::UnexpectedReply))
            }
        }
    }

    /// Pin a view (module docs). The view carries dird's policy version,
    /// which must be the kdc's own (R50-2).
    ///
    /// # Errors
    /// [`Unserved`] — the kdc answers the request through
    /// [`UnavailableDirectory`] (29 over TCP); on
    /// [`Unserved::PolicyVersionMismatch`] it also reloads its policy.
    ///
    /// Spec: docs/50 R50-2, §3.4; docs/11 §9; D39.
    pub fn begin_view(&mut self) -> Result<RemoteView<'_, C>, Unserved> {
        let reply = self.call(&Request::BeginView)?;
        let (view, version) = match reply.into_view_begun() {
            Ok(Ok(begun)) => begun,
            Ok(Err(failure)) => {
                self.connection = None;
                return Err(Unserved::View(failure));
            }
            Err(error) => {
                self.connection = None;
                return Err(Unserved::UnexpectedReply(error));
            }
        };
        if version != self.policy_version {
            // Dropping the connection releases the view in dird.
            self.connection = None;
            return Err(Unserved::PolicyVersionMismatch { dird: version });
        }
        Ok(RemoteView {
            client: RefCell::new(self),
            view,
            state: Cell::new(ViewState::Open),
        })
    }
}

/// Where a [`RemoteView`] stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewState {
    /// Queries go to dird.
    Open,
    /// A query failed; every later one is `Unavailable` without asking (the
    /// connection was dropped, so dird released the view).
    Broken,
    /// `EndView` was sent.
    Ended,
}

/// One request's view of the directory, pinned in dird to one snapshot and
/// one policy version (module docs). Implements `kdc::AccountSource` and
/// `pdp::Pip` over the same pinned view, so the account records the KDC reads
/// and the answers its PDP gets come from one consistent picture (docs/47
/// §8.1; docs/11 §6, P9). Dropping it ends the view.
///
/// Spec: docs/50 R50-2, §3.4; docs/47 §8.1, §8.2.
pub struct RemoteView<'c, C: Connector> {
    client: RefCell<&'c mut DirectoryClient<C>>,
    view: u64,
    state: Cell<ViewState>,
}

impl<C: Connector> fmt::Debug for RemoteView<'_, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteView")
            .field("view", &self.view)
            .field("state", &self.state.get())
            .finish()
    }
}

impl<C: Connector> RemoteView<'_, C> {
    /// The view id dird assigned.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.view
    }

    /// Whether every query so far was served.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.state.get() == ViewState::Open
    }

    /// Ask one question over the view. A failure marks the view broken.
    /// Spec: docs/50 §3.4, §3.7.
    fn ask(&self, query: Query) -> Result<DirectoryReply, Unserved> {
        if self.state.get() != ViewState::Open {
            return Err(Unserved::ViewClosed);
        }
        let Ok(mut client) = self.client.try_borrow_mut() else {
            return Err(Unserved::ViewClosed);
        };
        let request = Request::Query {
            view: self.view,
            query,
        };
        let result = client.call(&request);
        if result.is_err() {
            self.state.set(ViewState::Broken);
        }
        result
    }

    /// A reply whose content did not decode: the view is broken and the
    /// connection dropped (fail closed).
    fn refuse_reply(&self) {
        self.state.set(ViewState::Broken);
        if let Ok(mut client) = self.client.try_borrow_mut() {
            client.connection = None;
        }
    }

    /// End the view now (dropping the view does the same, ignoring the
    /// result).
    ///
    /// # Errors
    /// [`Unserved`] (the connection is then dropped, which also releases the
    /// view in dird).
    ///
    /// Spec: docs/50 §3.4 (`EndView` releases the snapshot).
    pub fn end(self) -> Result<(), Unserved> {
        self.end_inner()
    }

    fn end_inner(&self) -> Result<(), Unserved> {
        if self.state.get() != ViewState::Open {
            return Ok(());
        }
        self.state.set(ViewState::Ended);
        let Ok(mut client) = self.client.try_borrow_mut() else {
            return Err(Unserved::ViewClosed);
        };
        match client.call(&Request::EndView { view: self.view })? {
            DirectoryReply::ViewEnded => Ok(()),
            _ => {
                client.connection = None;
                Err(Unserved::UnexpectedReply(ConversionError::UnexpectedReply))
            }
        }
    }
}

impl<C: Connector> Drop for RemoteView<'_, C> {
    fn drop(&mut self) {
        let _ = self.end_inner();
    }
}

impl<C: Connector> AccountSource for RemoteView<'_, C> {
    /// Spec: docs/50 §3.4 (`Client`), §3.7; crates/kdc accounts.rs.
    fn client(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ClientAccount>, AccountSourceError> {
        let query = Query::Client {
            realm: realm.clone(),
            name: name.clone(),
        };
        let reply = self
            .ask(query)
            .map_err(|_| AccountSourceError::Unavailable)?;
        reply.into_client().unwrap_or_else(|_| {
            self.refuse_reply();
            Err(AccountSourceError::Unavailable)
        })
    }

    /// Spec: docs/50 §3.4 (`Service`), §3.7; crates/kdc accounts.rs.
    fn service(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ServiceAccount>, AccountSourceError> {
        let query = Query::Service {
            realm: realm.clone(),
            name: name.clone(),
        };
        let reply = self
            .ask(query)
            .map_err(|_| AccountSourceError::Unavailable)?;
        reply.into_service().unwrap_or_else(|_| {
            self.refuse_reply();
            Err(AccountSourceError::Unavailable)
        })
    }
}

impl<C: Connector> Pip for RemoteView<'_, C> {
    /// Spec: docs/50 §3.4 (`ExpandGroups`); docs/47 §8.2.
    fn expand_groups(&self, p: &Sid) -> Result<BTreeSet<Sid>, PipError> {
        let reply = self
            .ask(Query::ExpandGroups { sid: *p })
            .map_err(|_| PipError::Unavailable)?;
        reply.into_groups().unwrap_or_else(|_| {
            self.refuse_reply();
            Err(PipError::Unavailable)
        })
    }

    /// Spec: docs/50 §3.4 (`TierOf`: "decide requires it to equal
    /// `Subject.tier`, P3"); docs/47 §8.2.
    fn tier_of(&self, p: &Sid, g: &BTreeSet<Sid>) -> Result<Tier, PipError> {
        let query = Query::TierOf {
            sid: *p,
            groups: g.clone(),
        };
        let reply = self.ask(query).map_err(|_| PipError::Unavailable)?;
        reply.into_tier().unwrap_or_else(|_| {
            self.refuse_reply();
            Err(PipError::Unavailable)
        })
    }

    /// Not asked: the KDC does not write (docs/47 §8.2). Local
    /// `Unavailable` ⇒ Deny (D40; docs/50 §3.4).
    fn object_tier(&self, _r: &Resource) -> Result<Tier, PipError> {
        Err(PipError::Unavailable)
    }

    /// Not asked by the KDC. Spec: docs/50 §3.4; D40.
    fn security_descriptor(&self, _dn: &Dn) -> Result<SecurityDescriptor, PipError> {
        Err(PipError::Unavailable)
    }

    /// Not asked by the KDC. Spec: docs/50 §3.4; D40.
    fn attr_class(&self, _a: &AttrId) -> Result<AttrClass, PipError> {
        Err(PipError::Unavailable)
    }

    /// Not asked by the KDC. Spec: docs/50 §3.4; D40.
    fn object_classes(&self, _dn: &Dn) -> Result<ObjClassChain, PipError> {
        Err(PipError::Unavailable)
    }

    /// Not asked by the KDC. Spec: docs/50 §3.4; D40.
    fn object_sid(&self, _dn: &Dn) -> Result<Option<Sid>, PipError> {
        Err(PipError::Unavailable)
    }

    /// Not asked by the KDC. Spec: docs/50 §3.4; D40.
    fn property_set(&self, _a: &AttrId) -> Result<Option<PropertySet>, PipError> {
        Err(PipError::Unavailable)
    }
}

/// The directory when no view could be pinned (dird down, deadline, Busy,
/// policy version mismatch): every account lookup is
/// `AccountSourceError::Unavailable` (KDC_ERR_SVC_UNAVAILABLE, 29, over TCP)
/// and every PIP question `PipError::Unavailable` (Deny). No fallback, no
/// cached answer (docs/50 §3.7: "no fallback … no 'disconnected mode'").
///
/// Spec: docs/50 R50-8, §3.7; A-56; D40.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnavailableDirectory;

impl AccountSource for UnavailableDirectory {
    /// Spec: docs/50 §3.7.
    fn client(
        &self,
        _realm: &Realm,
        _name: &PrincipalName,
    ) -> Result<Option<ClientAccount>, AccountSourceError> {
        Err(AccountSourceError::Unavailable)
    }

    /// Spec: docs/50 §3.7.
    fn service(
        &self,
        _realm: &Realm,
        _name: &PrincipalName,
    ) -> Result<Option<ServiceAccount>, AccountSourceError> {
        Err(AccountSourceError::Unavailable)
    }
}

impl Pip for UnavailableDirectory {
    /// Spec: docs/50 §3.7; D40.
    fn expand_groups(&self, _p: &Sid) -> Result<BTreeSet<Sid>, PipError> {
        Err(PipError::Unavailable)
    }

    /// Spec: docs/50 §3.7; D40.
    fn tier_of(&self, _p: &Sid, _g: &BTreeSet<Sid>) -> Result<Tier, PipError> {
        Err(PipError::Unavailable)
    }

    /// Spec: docs/50 §3.7; D40.
    fn object_tier(&self, _r: &Resource) -> Result<Tier, PipError> {
        Err(PipError::Unavailable)
    }

    /// Spec: docs/50 §3.7; D40.
    fn security_descriptor(&self, _dn: &Dn) -> Result<SecurityDescriptor, PipError> {
        Err(PipError::Unavailable)
    }

    /// Spec: docs/50 §3.7; D40.
    fn attr_class(&self, _a: &AttrId) -> Result<AttrClass, PipError> {
        Err(PipError::Unavailable)
    }

    /// Spec: docs/50 §3.7; D40.
    fn object_classes(&self, _dn: &Dn) -> Result<ObjClassChain, PipError> {
        Err(PipError::Unavailable)
    }

    /// Spec: docs/50 §3.7; D40.
    fn object_sid(&self, _dn: &Dn) -> Result<Option<Sid>, PipError> {
        Err(PipError::Unavailable)
    }

    /// Spec: docs/50 §3.7; D40.
    fn property_set(&self, _a: &AttrId) -> Result<Option<PropertySet>, PipError> {
        Err(PipError::Unavailable)
    }
}
