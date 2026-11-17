#![forbid(unsafe_code)]
//! `ipc-directory-server`: dird's side of the directory-view channel
//! (docs/50 R50-2, §3.4, §10 task P8; decision A-58).
//!
//! [`DirectoryServer`] decodes one request body, answers it from the
//! `directory_pip::DirectoryView` pinned to the requesting connection, and
//! encodes the reply — the same disposition rules as ipc's refusal table
//! (bad prefix, wrong magic or unknown kind ⇒ close without a reply; wrong
//! version ⇒ `Refused::VersionMismatch` + close; malformed ⇒
//! `Refused::Malformed` + close). It holds no socket, no thread and reads no
//! clock: the caller (dird's engine thread) passes the connection id it
//! assigned and a monotonic `now`, and tells the server when a connection
//! ends.
//!
//! # Views (docs/50 §3.4)
//!
//! * `BeginView` pins **one** dirstore snapshot, with the tier map of dird's
//!   policy version, to the connection and answers a fresh view id and that
//!   policy version. One view per connection: a second `BeginView` while one
//!   is open is refused (`ViewOpen`).
//! * Every query names the view id; a different id, or no view, is
//!   `UnknownView`. A write committed after `BeginView` is invisible to the
//!   view (dirstore snapshots, D39) until the client takes a new one.
//! * A view lives at most the configured lifetime (`view_lifetime`, ≤ 5 s):
//!   an older one is released and answered `Expired`; [`DirectoryServer::
//!   expire`] releases old views even with no request.
//! * At most `max_views` views are open at once (`ViewLimit` beyond).
//! * `EndView` or the end of the connection ([`DirectoryServer::release`])
//!   releases the view.
//!
//! # Answers
//!
//! `Client` / `Service` / `ExpandGroups` / `TierOf` are answered by the
//! view's own `AccountSource` / `Pip` methods, unchanged — including their
//! errors (`AccountSourceError::Failed`, `PipError`). `DescribeDomain`
//! answers the description computed once when the server was built: the
//! realm, the naming context (A-53), keyd's krbtgt handle
//! (`DirectoryView::krbtgt_handle` over the domain SID, the objectSid of the
//! naming context's root, docs/47 R47-2) and the policy version. A server
//! that cannot compute it is not built ([`StartError`]): dird does not start
//! on a directory without its domain root and krbtgt account (fail closed).
//!
//! # The resolution a record carries (task PN10)
//!
//! A `Client` / `Service` record carries dird's attested resolution of the
//! name it was looked up by (docs/59 §7.5): the view's own account source
//! builds it with the signer of its context, which dird builds from this
//! crate's [`ResolutionSigner`] — dird's attestation key and clock (module
//! `attest`; docs/59 §7.1, §7.4). The server adds nothing to the record and
//! reads nothing of it; a context without a signer answers every record
//! `AccountSourceError::Failed` (fail closed).
//!
//! Spec: docs/50 R50-2, §3.3, §3.4, §3.7, §7.5; docs/47 §1.4 (R47-2), §8;
//! docs/11 §6 (snapshot semantics); D39; A-53; A-59; docs/59 §7.1, §7.4,
//! §7.5.
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session
//! (docs/50, docs/47 §8, docs/questions Q-213, Q-225, Q-245, Q-255, Q-270,
//! PENDING-OWNER) and the public API of this project's crates ipc,
//! ipc-directory, directory-pip, dirstore, kdc and pdp (ipc-keyd-server as
//! the pattern). No other implementation, directory server or RPC framework
//! was consulted or recalled (docs/CLEAN-ROOM.md).

mod attest;

pub use attest::{IssueClock, ResolutionSigner, SharedAttestationKey};
// The attestation key's length and refusal, for the reader of dird's key
// file (crates/directory-daemon `startup`) — the key's type itself stays
// inside `SharedAttestationKey` (task PN10; docs/59 §7.4).
pub use name_attestation::{KeyRefused, ATTESTATION_KEY_LEN};

use core::fmt;
use core::time::Duration;
use directory_pip::{DirectoryContext, DirectoryView, TierMap};
use dirstore::Store;
use ipc::{decode_body, encode_frame, encode_refused, Direction, EncodedFrame, Refused};
use ipc_directory::typed::{DomainDescription, Query, Request};
use ipc_directory::wire::{DirectoryReply, DirectoryRequest};
use ipc_directory::{ViewFailure, DIRECTORY_CHANNEL, MAX_GROUPS};
use kdc::AccountSource;
use pdp::{Pip, PolicyVersion};
use std::collections::BTreeMap;
use std::time::Instant;

// The channel's group bound is the directory's expansion bound, so every
// expanded group set the view produces fits a reply. Checked at compile time.
// Spec: docs/47 §5.3 (R47-8); docs/50 §3.4.
const _: () = assert!(MAX_GROUPS as usize == directory_pip::MAX_EXPANDED_GROUPS);
// The naming-context labels of `DescribeDomain` fit their bound.
const _: () =
    assert!(ipc_directory::channel::MAX_NC_LABELS as usize == directory_pip::MAX_NC_LABELS);

/// The connection a request came on, as dird's engine numbers them (never
/// anything the peer sent).
/// Spec: docs/50 §3.2, §3.4 ("a view pinned to the connection").
pub type ConnectionId = u64;

/// What to do with the connection after a request.
///
/// Spec: docs/50 §3.3 (bad prefix, wrong magic, unknown kind ⇒ close without
/// a reply; wrong version ⇒ `Refused{VersionMismatch}` + close; malformed ⇒
/// `Malformed` + close).
pub enum Dispatch {
    /// Send the reply; the connection stays open.
    Reply(EncodedFrame),
    /// Send the reply (a transport refusal), then close the connection.
    ReplyAndClose(EncodedFrame),
    /// Close the connection without a reply.
    Close,
}

impl fmt::Debug for Dispatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dispatch::Reply(frame) => f.debug_tuple("Reply").field(&frame.len()).finish(),
            Dispatch::ReplyAndClose(frame) => {
                f.debug_tuple("ReplyAndClose").field(&frame.len()).finish()
            }
            Dispatch::Close => f.write_str("Close"),
        }
    }
}

/// A shared refusal frame, then close; a refusal that cannot be encoded
/// (never, given ipc's minimum body bound) closes without a reply.
/// Spec: docs/50 §3.3; A-59.
#[must_use]
pub fn refuse(refused: Refused) -> Dispatch {
    match encode_refused(DIRECTORY_CHANNEL, refused) {
        Ok(frame) => Dispatch::ReplyAndClose(frame),
        Err(_) => Dispatch::Close,
    }
}

/// A shared refusal frame; the connection stays open (`Busy`: try again).
/// Spec: docs/50 §3.6 ("immediate `Busy`").
#[must_use]
pub fn refuse_and_stay(refused: Refused) -> Dispatch {
    match encode_refused(DIRECTORY_CHANNEL, refused) {
        Ok(frame) => Dispatch::Reply(frame),
        Err(_) => Dispatch::Close,
    }
}

/// The bounds of the view table.
/// Spec: docs/50 §3.4 ("one view open per connection, expires after ≤ 5 s
/// (project choice)").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewLimits {
    /// Views open at once, over all connections (at least 1).
    pub max_views: usize,
    /// How long a view stays pinned (greater than zero).
    pub lifetime: Duration,
}

/// Why the server was not built. dird does not start (docs/50 §7.5: every
/// daemon exits on any start-up failure).
/// Spec: docs/50 §7.5; docs/47 §1.4 (R47-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    /// `max_views` is 0 or the lifetime is zero.
    Limits,
    /// No snapshot could be taken (also: the store's schema is not the
    /// context's).
    Snapshot,
    /// The naming context's root object was not found, or could not be read
    /// (A-53).
    NamingContextRoot,
    /// The naming context's root has no objectSid (no domain SID).
    DomainSid,
    /// The krbtgt account (domain SID ‖ 502, sAMAccountName "krbtgt") was not
    /// found or is inconsistent (docs/47 R47-2).
    Krbtgt,
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StartError::Limits => "view limits out of range",
            StartError::Snapshot => "directory snapshot failed",
            StartError::NamingContextRoot => "naming context root not found",
            StartError::DomainSid => "naming context root has no objectSid",
            StartError::Krbtgt => "krbtgt account not found or inconsistent",
        })
    }
}

impl std::error::Error for StartError {}

/// The domain description of a directory: realm, naming context, keyd's
/// krbtgt handle from the domain SID (the objectSid of the naming context's
/// root), and `policy_version`.
///
/// # Errors
/// [`StartError`].
///
/// Spec: docs/50 §3.4 (`DescribeDomain`), §7.5; docs/47 §1.4 (R47-2); A-53.
pub fn describe(
    ctx: &DirectoryContext,
    store: &Store,
    tiers: &TierMap,
    policy_version: PolicyVersion,
) -> Result<DomainDescription, StartError> {
    let view = ctx.view(store, tiers).map_err(|_| StartError::Snapshot)?;
    let domain_sid = view
        .object_sid(ctx.naming_context().dn())
        .map_err(|_| StartError::NamingContextRoot)?
        .ok_or(StartError::DomainSid)?;
    let krbtgt = view
        .krbtgt_handle(&domain_sid)
        .map_err(|_| StartError::Krbtgt)?;
    Ok(DomainDescription {
        realm: ctx.realm().clone(),
        naming_context: ctx.naming_context().labels().to_vec(),
        krbtgt,
        policy_version,
    })
}

/// The reply to one query, from `view`'s own `AccountSource` / `Pip`
/// methods, unchanged (errors included).
/// Spec: docs/50 §3.4; docs/47 §8.2.
#[must_use]
pub fn answer(view: &DirectoryView<'_>, query: &Query) -> DirectoryReply {
    match query {
        Query::Client { realm, name } => DirectoryReply::from_client(&view.client(realm, name)),
        Query::Service { realm, name } => DirectoryReply::from_service(&view.service(realm, name)),
        Query::ExpandGroups { sid } => DirectoryReply::from_groups(&view.expand_groups(sid)),
        Query::TierOf { sid, groups } => DirectoryReply::from_tier(&view.tier_of(sid, groups)),
    }
}

/// One pinned view.
struct Pinned<'a> {
    id: u64,
    view: DirectoryView<'a>,
    opened: Instant,
}

/// dird's side of the channel (module docs).
/// Spec: docs/50 R50-2, §3.4.
pub struct DirectoryServer<'a> {
    ctx: &'a DirectoryContext,
    store: &'a Store,
    tiers: &'a TierMap,
    domain: DomainDescription,
    limits: ViewLimits,
    views: BTreeMap<ConnectionId, Pinned<'a>>,
    last_view: u64,
}

impl fmt::Debug for DirectoryServer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectoryServer")
            .field("policy_version", &self.domain.policy_version)
            .field("limits", &self.limits)
            .field("open_views", &self.views.len())
            .finish()
    }
}

impl<'a> DirectoryServer<'a> {
    /// A server over `store` (opened with `ctx`'s schema) and the tier map of
    /// policy version `policy_version`.
    ///
    /// # Errors
    /// [`StartError`] — the limits are out of range, or the directory has no
    /// usable domain root / krbtgt account ([`describe`]).
    ///
    /// Spec: docs/50 R50-2, §3.4, §7.5.
    pub fn new(
        ctx: &'a DirectoryContext,
        store: &'a Store,
        tiers: &'a TierMap,
        policy_version: PolicyVersion,
        limits: ViewLimits,
    ) -> Result<DirectoryServer<'a>, StartError> {
        if limits.max_views == 0 || limits.lifetime.is_zero() {
            return Err(StartError::Limits);
        }
        let domain = describe(ctx, store, tiers, policy_version)?;
        Ok(DirectoryServer {
            ctx,
            store,
            tiers,
            domain,
            limits,
            views: BTreeMap::new(),
            last_view: 0,
        })
    }

    /// The domain description `DescribeDomain` answers.
    #[must_use]
    pub fn domain(&self) -> &DomainDescription {
        &self.domain
    }

    /// Views open now.
    #[must_use]
    pub fn open_views(&self) -> usize {
        self.views.len()
    }

    /// Release the view of a connection that ended; `true` if it had one.
    /// Spec: docs/50 §3.4 ("released on EndView or disconnect").
    pub fn release(&mut self, connection: ConnectionId) -> bool {
        self.views.remove(&connection).is_some()
    }

    /// Release every view older than the lifetime at `now`; the number
    /// released.
    /// Spec: docs/50 §3.4 ("expires after ≤ 5 s").
    pub fn expire(&mut self, now: Instant) -> usize {
        self.expire_except(None, now)
    }

    /// [`DirectoryServer::expire`], keeping `kept`'s view for the request in
    /// hand, which then reports its own expiry (`Expired`).
    fn expire_except(&mut self, kept: Option<ConnectionId>, now: Instant) -> usize {
        let lifetime = self.limits.lifetime;
        let before = self.views.len();
        self.views.retain(|connection, pinned| {
            Some(*connection) == kept || now.saturating_duration_since(pinned.opened) < lifetime
        });
        before - self.views.len()
    }

    /// Answer one request body that arrived on `connection` at the monotonic
    /// instant `now` (module docs).
    /// Spec: docs/50 §3.3, §3.4; A-59.
    pub fn handle(&mut self, connection: ConnectionId, body: &[u8], now: Instant) -> Dispatch {
        self.expire_except(Some(connection), now);
        let wire =
            match decode_body::<DirectoryRequest>(DIRECTORY_CHANNEL, Direction::Request, body) {
                Ok(wire) => wire,
                Err(error) => {
                    return match error.refusal() {
                        Some(refused) => refuse(refused),
                        None => Dispatch::Close,
                    }
                }
            };
        let Ok(request) = Request::from_wire(&wire) else {
            return refuse(Refused::Malformed);
        };
        drop(wire);
        let reply = match request {
            Request::BeginView => self.begin(connection, now),
            Request::Query { view, query } => self.query(connection, view, &query, now),
            Request::EndView { view } => self.end(connection, view),
            Request::DescribeDomain => DirectoryReply::from_domain(&self.domain),
            Request::Ping => DirectoryReply::Pong,
        };
        match encode_frame(DIRECTORY_CHANNEL, Direction::Reply, &reply) {
            Ok(frame) => Dispatch::Reply(frame),
            // A reply over the channel's bounds: not served (fail closed).
            Err(_) => refuse(Refused::Unavailable),
        }
    }

    /// `BeginView`: pin a snapshot to `connection`.
    /// Spec: docs/50 §3.4.
    fn begin(&mut self, connection: ConnectionId, now: Instant) -> DirectoryReply {
        if let Some(pinned) = self.views.get(&connection) {
            if now.saturating_duration_since(pinned.opened) < self.limits.lifetime {
                return DirectoryReply::ViewFailure(ViewFailure::ViewOpen);
            }
            // The old view outlived its lifetime: released, a new one may
            // be pinned.
            self.views.remove(&connection);
        }
        if self.views.len() >= self.limits.max_views {
            return DirectoryReply::ViewFailure(ViewFailure::ViewLimit);
        }
        let Some(id) = self.last_view.checked_add(1) else {
            return DirectoryReply::ViewFailure(ViewFailure::ViewLimit);
        };
        let Ok(view) = self.ctx.view(self.store, self.tiers) else {
            return DirectoryReply::ViewFailure(ViewFailure::Snapshot);
        };
        self.last_view = id;
        self.views.insert(
            connection,
            Pinned {
                id,
                view,
                opened: now,
            },
        );
        DirectoryReply::ViewBegun {
            view: id,
            policy_version: self.domain.policy_version.0,
        }
    }

    /// A query over the connection's view `id`.
    /// Spec: docs/50 §3.4.
    fn query(
        &mut self,
        connection: ConnectionId,
        id: u64,
        query: &Query,
        now: Instant,
    ) -> DirectoryReply {
        let lifetime = self.limits.lifetime;
        let Some(pinned) = self.views.get(&connection) else {
            return DirectoryReply::ViewFailure(ViewFailure::UnknownView);
        };
        if pinned.id != id {
            return DirectoryReply::ViewFailure(ViewFailure::UnknownView);
        }
        if now.saturating_duration_since(pinned.opened) >= lifetime {
            self.views.remove(&connection);
            return DirectoryReply::ViewFailure(ViewFailure::Expired);
        }
        answer(&pinned.view, query)
    }

    /// `EndView`: release the connection's view `id`.
    /// Spec: docs/50 §3.4.
    fn end(&mut self, connection: ConnectionId, id: u64) -> DirectoryReply {
        match self.views.get(&connection) {
            Some(pinned) if pinned.id == id => {
                self.views.remove(&connection);
                DirectoryReply::ViewEnded
            }
            _ => DirectoryReply::ViewFailure(ViewFailure::UnknownView),
        }
    }
}
