//! dird's kpasswd service (task K7, dird side; docs/53 §4.3, §5.6): its
//! parameters, its keyd client, how it finds the change-password service's
//! key set, and the conversions between keyd's types and the
//! `dird-kpasswd.sock` channel's (crate ipc-kpasswd).
//!
//! # Where the password is, and where it is not (docs/53 R53-4, R53-8)
//!
//! kpasswd-front hands dird the client's AP-REQ and KRB-PRIV **as opaque
//! octets** (crate ipc-kpasswd: no field can hold a cleartext password).
//! dird hands them to keyd (`open_change_password_request`, Role::Ldap);
//! **only keyd decrypts the new password**, and it never leaves keyd: dird
//! gets a one-time request context and keyd's verdict, decides
//! (crate directory-admin `prepare_change_password`), writes `pwdLastSet`,
//! registers the `ChangePassword` decision, and asks keyd to complete and
//! seal (`complete_change_password`) — or to seal an error
//! (`seal_change_password_error`). dird links no krb-crypto (its own guard,
//! `tests/no_crypto_dependency.rs`): it cannot decrypt anything it relays.
//!
//! # The change-password service's key set
//!
//! At start, dird resolves `kadmin/changepw` (RFC 3244 §2) exactly as the
//! KDC resolves it for the AS (crate kdc `as_exchange.rs` A8a:
//! `AccountSource::service`, the unique servicePrincipalName index, the
//! stored value compared octet for octet, a computer object): its key set
//! must be `(objectGUID, ChangePasswordService)` — the purpose the one
//! derivation gives the name (`KeyPurpose::of_service_name`, docs/52 R2b).
//! Absent, of another purpose, or unreadable ⇒ the kpasswd service does not
//! start; dird's other services run. keyd checks the binding again on every
//! request (A-19: the key set opens only tickets for `kadmin/changepw`).
//! The provisioning manifest does not name this object yet (task K9 —
//! docs/questions/Q-964 item 2).
//!
//! # Parameters
//!
//! `dird_kpasswd_socket` and `kpasswd_front_uid` (crate config, dird's file;
//! docs/questions/Q-955 item 13). The service runs only with the admin
//! service: it shares the admin service's ticket-age threshold (R51-10 —
//! one rule, docs/53 §5.6 step 4), its protected objects (the manifest), its
//! node-id, its keyd endpoint and its decision-acknowledgement wait.
//!
//! Spec: docs/53 §3.3, §4.3, §5.2, §5.5–§5.7, §9; docs/50 R50-3, R50-7, §3.2,
//! §3.6; docs/52 R2b; RFC 3244 §2; RFC 4120 §7.1; A-117, A-126, A-158.
//!
//! Written only from this project's decided design and the allowed
//! specifications, opened in this session: AGENT-ONBOARDING, AGENTS; docs/53
//! (whole); PENDING-OWNER (A-117, A-121, A-126, A-142, A-151, A-153, A-156,
//! A-158, A-159); docs/questions Q-600..Q-609, Q-660..Q-664, Q-945, Q-955;
//! docs/research/r3-e (§1-§3); the pinned RFC 3244 §2 and RFC 4120 §3.2.3;
//! and this repository's own code (crates ipc-kpasswd, ipc-keyd, keyd-types,
//! directory-admin, directory-pip, kdc and this crate's admin service as the
//! pattern). No other implementation was consulted or recalled (AGENTS.md
//! §1-3).

use crate::registration::DecisionRegistration;
use core::fmt;
use core::net::IpAddr;
use core::time::Duration;
use directory_pip::DirectoryView;
use ipc_kpasswd::{
    ApRepOctets, ChangePasswordRequest, KrbPrivOctets, ObservedAddress, SealedReply,
};
use kdc::AccountSource;
use keyd_types::{
    AuthnError, ChangePasswordContext, ChangePasswordCtxId, HostAddr, KeyHandle, KeyPurpose,
    PrincipalId,
};
use krb_proto::constants::KRB_NT_SRV_INST;
use krb_proto::{
    KerberosString, NonZeroResultCode, PrincipalName, Realm, CHANGE_PASSWORD_SERVICE_NAME,
};
use provision_manifest::Manifest;
use std::path::PathBuf;
use std::sync::Arc;

/// Connections kpasswd-front may hold open at once on `dird-kpasswd.sock`:
/// the front's own bound (crate ipc-kpasswd `MAX_FRONT_CONNECTIONS`), so a
/// front within its bound never meets dird's.
/// Spec: docs/53 §5.6 step 1; docs/questions/Q-955 item 3.
pub const MAX_KPASSWD_CONNECTIONS: usize = ipc_kpasswd::MAX_FRONT_CONNECTIONS;

/// Requests the kpasswd thread's queue holds before a request is answered
/// `Busy`: one — with the one request in flight, a request waits behind at
/// most one other (docs/53 §5.6 step 1: "a bounded queue and one request in
/// flight"), which is what the front's deadline is sized for
/// ([`MAX_KPASSWD_CALL_SECS`]). A flood on TCP 464 fills this queue, never
/// the LDAP engine's or the admin thread's (docs/07 §1, "a separate
/// pool"). Project choice (docs/questions/Q-964 item 4).
pub const KPASSWD_QUEUE_CAPACITY: usize = 1;

/// Largest kpasswd queue accepted. Project bound (AGENTS.md §6).
pub const MAX_KPASSWD_QUEUE_CAPACITY: usize = 16;

/// The keyd calls one change request may make: `open_change_password_request`,
/// `register_decision`, `complete_change_password` and — when the completion
/// was refused or not performed — `seal_change_password_error` (docs/53
/// §5.6 steps 2, 5, 6).
const MAX_KEYD_CALLS_PER_CHANGE: u32 = 4;

/// The worst case of one change request in dird, in seconds: its keyd calls
/// at keyd's client deadline (docs/50 §3.6) and the decision-acknowledgement
/// wait at its ceiling (`MAX_DECISION_ACK_DEADLINE`).
pub const MAX_KPASSWD_CALL_SECS: u64 = MAX_KEYD_CALLS_PER_CHANGE as u64
    * ipc_keyd::DEFAULT_DEADLINE.as_secs()
    + crate::admin_service::MAX_DECISION_ACK_DEADLINE.as_secs();

// The front's deadline covers dird's worst case for a request queued behind
// one other (docs/questions/Q-955 item 3 — pinned here against dird's real
// path): 2 × (4 × 2 s + 4 s) = 24 s ≤ 25 s.
const _: () = assert!(
    (KPASSWD_QUEUE_CAPACITY as u64 + 1) * MAX_KPASSWD_CALL_SECS
        <= ipc_kpasswd::DEFAULT_DEADLINE.as_secs()
);
// keyd's request context outlives dird's worst case (keyd-types
// `token_lifetime_secs` default 30 s, docs/53 §5.5): a context opened at
// step 2 is still there for the completion or the error seal.
const _: () = assert!(MAX_KPASSWD_CALL_SECS < 30);

/// How long a `ChangePassword` decision dird registers stays live: keyd's
/// ceiling for the set-secret family (`keyd_types::MAX_SET_SECRET_GRANT_SECS`,
/// 30 s) — dird completes at once, within keyd's 2 s client deadline.
/// Spec: docs/53 §5.6 steps 5-6; docs/52 §4.2; docs/questions/Q-662.
pub const CHANGE_PASSWORD_DECISION_LIFETIME_SECS: u32 = keyd_types::MAX_SET_SECRET_GRANT_SECS;

/// The change-password service's name, `kadmin/changepw` (RFC 3244 §2: "the
/// service principal kadmin/changepw@REALM"), as dird resolves it in its
/// directory: the components of the project's one definition,
/// `krb_proto::CHANGE_PASSWORD_SERVICE_NAME` — the name keyd binds the key
/// set to and the kdc classifies by (this function spelled the components
/// as literals until docs/questions/Q-987 item 5 / A-165 folded them —
/// Q-995). The name-type is a hint only (RFC 4120 §6.2: "not significant
/// when checking for equivalence"; the directory resolves the components);
/// NT-SRV-INST ("Service and other unique instance") as the KDC fixtures
/// use.
/// Spec: RFC 3244 §2; RFC 4120 §6.2; docs/53 §5.2.
fn change_password_service_name() -> Option<PrincipalName> {
    Some(PrincipalName {
        name_type: KRB_NT_SRV_INST,
        name_string: CHANGE_PASSWORD_SERVICE_NAME
            .iter()
            .map(|component| KerberosString::new(component).ok())
            .collect::<Option<Vec<_>>>()?,
    })
}

/// Why the kpasswd service did not start (dird's other services run).
/// Spec: docs/53 §5.6; docs/51 §4.6 (the admin service's precedent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KpasswdNotStarted {
    /// The admin service did not start: the kpasswd service needs its
    /// settings (module documentation).
    NoAdminService,
    /// No keyd endpoint is configured, or the keyd client could not be
    /// built.
    NoKeyd,
    /// No object holds `kadmin/changepw`, or its key set is not a
    /// `ChangePasswordService` one.
    ServiceAbsent,
    /// The directory could not answer.
    DirectoryUnreadable,
    /// The write PEP refused its configuration or the schema.
    Configuration,
    /// The socket could not be bound, or its path is occupied.
    Bind,
    /// The kpasswd thread could not be started.
    Spawn,
}

impl KpasswdNotStarted {
    /// A numeric code for the fixed log note (docs/50 §8.2).
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            KpasswdNotStarted::NoAdminService => 1,
            KpasswdNotStarted::NoKeyd => 2,
            KpasswdNotStarted::ServiceAbsent => 3,
            KpasswdNotStarted::DirectoryUnreadable => 4,
            KpasswdNotStarted::Configuration => 5,
            KpasswdNotStarted::Bind => 6,
            KpasswdNotStarted::Spawn => 7,
        }
    }
}

/// The change-password service's key set: `kadmin/changepw` resolved as the
/// KDC resolves it, which must give a `ChangePasswordService` key set **and**
/// be exactly the manifest's change-password service handle (A-163;
/// docs/questions/Q-964 item 4) — the same check the admin service's handle
/// gets (`admin_service_handle`). Anything else ⇒ the service does not start
/// (fail closed).
/// Spec: RFC 3244 §2; docs/53 §5.2; crate kdc `as_exchange.rs` A8a; docs/52
/// R2b; docs/questions/Q-964 item 4, Q-975.
pub(crate) fn change_password_service_handle(
    view: &DirectoryView<'_>,
    realm: &Realm,
    manifest: &Manifest,
) -> Result<KeyHandle, KpasswdNotStarted> {
    let name = change_password_service_name().ok_or(KpasswdNotStarted::Configuration)?;
    match view.service(realm, &name) {
        Ok(Some(account))
            if account.key.purpose == KeyPurpose::ChangePasswordService
                && account.key.purpose == KeyPurpose::of_service_name(&name)
                && account.key == manifest.change_password_service().handle =>
        {
            Ok(account.key)
        }
        Ok(_) => Err(KpasswdNotStarted::ServiceAbsent),
        Err(_) => Err(KpasswdNotStarted::DirectoryUnreadable),
    }
}

/// What dird's configuration sets for the kpasswd service — **and nothing
/// else** (docs/52 C18): `dird_kpasswd_socket` and `kpasswd_front_uid`. Its
/// keyd client, its connection and queue bounds come from the admin
/// service's parameters and the daemon's constants
/// (`serve_with_services`).
/// Spec: docs/53 §5.6; docs/questions/Q-955 item 13.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KpasswdParams {
    /// `dird_kpasswd_socket`.
    pub socket: PathBuf,
    /// `kpasswd_front_uid`: the only peer admitted (docs/53 §5.6 step 1;
    /// docs/50 R50-3).
    pub front_uid: u32,
}

/// dird's keyd client for the kpasswd service (Role::Ldap): the three
/// change-password operations and the registration of the `ChangePassword`
/// decision (docs/53 §5.5, §5.6).
/// Spec: docs/53 §5.5, §5.6 steps 2, 5, 6; docs/52 §4.2, §3.10 (c); A-126.
pub trait KpasswdKeyd: Send {
    /// keyd's `open_change_password_request` for the change-password key
    /// set of `service`, with the request's two messages and the addresses
    /// the front's kernel reported. keyd not reachable, not the configured
    /// keyd, or in its start-up hold-down ⇒ `AuthnError::Unavailable`; every
    /// other error is keyd's own uniform refusal (A-26).
    fn open(
        &mut self,
        service: &PrincipalId,
        ap_req: &[u8],
        krb_priv: &[u8],
        peer: &HostAddr,
        local: &HostAddr,
    ) -> Result<ChangePasswordContext, AuthnError>;

    /// Register dird's `ChangePassword` decision (built only from a
    /// committed `ChangePassword`, crate::registration) — through
    /// `call_with_fate`, as every decision (A-90).
    ///
    /// # Errors
    /// [`crate::RegistrationFailure`].
    fn register_decision(
        &mut self,
        decision: DecisionRegistration,
    ) -> Result<(), crate::RegistrationFailure>;

    /// keyd's `complete_change_password` of `ctx` into `target` — a state
    /// call with its fate (R9).
    fn complete(&mut self, ctx: &ChangePasswordCtxId, target: &KeyHandle) -> CompletionOutcome;

    /// keyd's `seal_change_password_error` of `ctx` with `code`; `None` if
    /// keyd did not seal it.
    fn seal_error(
        &mut self,
        ctx: &ChangePasswordCtxId,
        code: NonZeroResultCode,
    ) -> Option<keyd_types::SealedReply>;
}

/// How keyd's `complete_change_password` ended, as dird acts on it.
/// Spec: docs/53 §5.6 step 6; docs/questions/Q-367 (A-88: the three fates),
/// Q-663 item 1 (a refusal keeps the context for the error seal).
#[derive(Debug)]
pub enum CompletionOutcome {
    /// keyd installed the password and sealed the success reply.
    Completed(keyd_types::SealedReply),
    /// keyd answered and refused, or did not perform the call: nothing was
    /// installed and the context is still there for an error seal.
    NotInstalled,
    /// Sent, and no usable answer came back: keyd may have installed it.
    OutcomeUnknown,
}

/// The production client: ipc-keyd's `KeydClient` expecting Role::Ldap and
/// dird's realm on every connection (task R9; the admin service's
/// `KeydTicketVerifier` as the pattern).
/// Spec: docs/10 §2 (Role `Ldap`), §7א; docs/50 R50-3, §3.7; A-73;
/// docs/questions/Q-466 item 1 (A-102).
pub struct KeydKpasswdClient<C: ipc_keyd::Connector> {
    client: ipc_keyd::KeydClient<C>,
}

impl<C: ipc_keyd::Connector> KeydKpasswdClient<C> {
    /// A client talking to keyd through `connector`: keyd runs as
    /// `keyd_uid`, gives dird the role Ldap and serves `realm` — checked on
    /// every connection before anything else is sent — with a per-call
    /// `deadline` (`ipc_keyd::DEFAULT_DEADLINE` in dird).
    ///
    /// # Errors
    /// `ipc_keyd::ClientConfigError` (a keyd uid of 0).
    ///
    /// Spec: docs/10 §2, §7א; docs/50 R50-3, §3.7; A-73; docs/questions/Q-466.
    pub fn new(
        connector: C,
        keyd_uid: u32,
        realm: Realm,
        deadline: Duration,
    ) -> Result<KeydKpasswdClient<C>, ipc_keyd::ClientConfigError> {
        let peer = ipc_keyd::ExpectedPeer::new(keyd_uid, keyd_types::Role::Ldap)?
            .with_description(ipc_keyd::ExpectedDescription::Realm(realm))?;
        Ok(KeydKpasswdClient {
            client: ipc_keyd::KeydClient::new(connector, peer, deadline),
        })
    }
}

impl<C: ipc_keyd::Connector> fmt::Debug for KeydKpasswdClient<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeydKpasswdClient")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl<C> KpasswdKeyd for KeydKpasswdClient<C>
where
    C: ipc_keyd::Connector + Send,
    C::Connection: Send,
{
    /// Spec: docs/53 §5.5, §5.6 step 2; docs/50 §3.4.
    fn open(
        &mut self,
        service: &PrincipalId,
        ap_req: &[u8],
        krb_priv: &[u8],
        peer: &HostAddr,
        local: &HostAddr,
    ) -> Result<ChangePasswordContext, AuthnError> {
        self.client
            .open_change_password_request(service, ap_req, krb_priv, peer, local)
    }

    /// Spec: docs/52 §4.2, §4.3; docs/questions/Q-367 (A-88), Q-662.
    fn register_decision(
        &mut self,
        decision: DecisionRegistration,
    ) -> Result<(), crate::RegistrationFailure> {
        crate::admin_service::register_with_fate(&mut self.client, &decision)
    }

    /// Spec: docs/53 §5.6 step 6; docs/52 §3.10 (c), R9; docs/questions/
    /// Q-367 (A-88), Q-663 item 1.
    fn complete(&mut self, ctx: &ChangePasswordCtxId, target: &KeyHandle) -> CompletionOutcome {
        match self.client.complete_change_password(ctx, target) {
            Ok(Ok(sealed)) => CompletionOutcome::Completed(sealed),
            // keyd's own refusal: decided before (or at) the install, which
            // then did not happen — the context stays (Q-663 item 1).
            Ok(Err(_)) => CompletionOutcome::NotInstalled,
            Err(failure) => match failure.fate {
                ipc_keyd::RequestFate::NotSent | ipc_keyd::RequestFate::NotPerformed => {
                    CompletionOutcome::NotInstalled
                }
                ipc_keyd::RequestFate::OutcomeUnknown => CompletionOutcome::OutcomeUnknown,
            },
        }
    }

    /// Spec: docs/53 §5.5, §5.7; RFC 3244 §2.
    fn seal_error(
        &mut self,
        ctx: &ChangePasswordCtxId,
        code: NonZeroResultCode,
    ) -> Option<keyd_types::SealedReply> {
        self.client.seal_change_password_error(ctx, code).ok()
    }
}

/// Builds the kpasswd thread's keyd client when the service starts; `None`
/// ⇒ the service does not start. A product dird builds only the production
/// one; any other is a test seam (docs/52 C18).
pub type KpasswdKeydFactory = Arc<dyn Fn() -> Option<Box<dyn KpasswdKeyd>> + Send + Sync>;

/// Everything the kpasswd service runs with: the product [`KpasswdParams`]
/// plus the seams. Built for a product dird only by
/// [`KpasswdServeParams::production`].
/// Spec: docs/53 §5.6; docs/52 C18.
#[derive(Clone)]
pub(crate) struct KpasswdServeParams {
    /// `dird_kpasswd_socket`.
    pub socket: PathBuf,
    /// `kpasswd_front_uid`.
    pub front_uid: u32,
    /// The kpasswd thread's keyd client; `None` ⇒ the service does not start.
    pub keyd: Option<KpasswdKeydFactory>,
    /// Connections the front may hold ([`MAX_KPASSWD_CONNECTIONS`]).
    pub max_connections: usize,
    /// The kpasswd queue ([`KPASSWD_QUEUE_CAPACITY`]).
    pub queue_capacity: usize,
}

impl KpasswdServeParams {
    /// The product parameters with the production keyd client — a fresh
    /// `KeydKpasswdClient` over `ipc_keyd::UnixConnector` to the admin
    /// service's keyd (`keyd`), expecting its uid, Role::Ldap and dird's
    /// `realm`, with the keyd channel's 2 s deadline — and the daemon's
    /// constants.
    /// Spec: docs/53 §5.6; docs/50 §3.6; A-73; docs/questions/Q-466.
    pub(crate) fn production(
        kpasswd: KpasswdParams,
        keyd: Option<&crate::KeydEndpoint>,
        realm: &Realm,
    ) -> KpasswdServeParams {
        let realm = realm.clone();
        let keyd: Option<KpasswdKeydFactory> = keyd.cloned().map(|endpoint| {
            let factory: KpasswdKeydFactory = Arc::new(move || {
                let client: Box<dyn KpasswdKeyd> = Box::new(
                    KeydKpasswdClient::new(
                        ipc_keyd::UnixConnector::new(endpoint.socket.clone()),
                        endpoint.uid,
                        realm.clone(),
                        ipc_keyd::DEFAULT_DEADLINE,
                    )
                    .ok()?,
                );
                Some(client)
            });
            factory
        });
        KpasswdServeParams {
            socket: kpasswd.socket,
            front_uid: kpasswd.front_uid,
            keyd,
            max_connections: MAX_KPASSWD_CONNECTIONS,
            queue_capacity: KPASSWD_QUEUE_CAPACITY,
        }
    }
}

impl fmt::Debug for KpasswdServeParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KpasswdServeParams")
            .field("socket", &self.socket)
            .field("front_uid", &self.front_uid)
            .field("keyd", &self.keyd.is_some())
            .field("max_connections", &self.max_connections)
            .field("queue_capacity", &self.queue_capacity)
            .finish()
    }
}

/// keyd's address type of an address the front's kernel reported: IPv4, or
/// IPv6 (an IPv4-mapped one held as IPv4 by both types — RFC 4120 §7.1).
/// Spec: RFC 4120 §7.1; docs/53 §5.4 item 3; docs/questions/Q-955 item 13
/// ("same family codes as keyd's `HostAddr`").
pub(crate) fn host_addr(observed: ObservedAddress) -> HostAddr {
    match observed.address() {
        IpAddr::V4(v4) => HostAddr::ipv4(v4.octets()),
        IpAddr::V6(v6) => HostAddr::ipv6(v6.octets()),
    }
}

/// The channel's form of a reply keyd sealed: the AP-REP and the KRB-PRIV as
/// DER octets (crate krb-proto's canonical encoding), within the channel's
/// bounds; `None` if either does not encode or the pair does not fit (the
/// caller then answers HARDERROR, docs/53 §5.7).
/// Spec: docs/53 §5.5 (`SealedReply { ap_rep, krb_priv }` — "DER; the front
/// frames it"), §5.9; RFC 3244 §2 (reply message); RFC 4120 §5.5.2, §5.7.1.
pub(crate) fn sealed_for_front(sealed: &keyd_types::SealedReply) -> Option<SealedReply> {
    let ap_rep = sealed.ap_rep.encode().ok()?;
    let krb_priv = sealed.krb_priv.encode().ok()?;
    SealedReply::new(ApRepOctets::new(&ap_rep)?, KrbPrivOctets::new(&krb_priv)?)
}

/// The front's request as keyd's `open_change_password_request` takes it:
/// the two messages, exactly as received, and the two addresses.
/// Spec: docs/53 §5.5 (`ap_req_octets`, `krb_priv_octets`, `peer`, `local`).
pub(crate) struct OpenArguments<'r> {
    pub(crate) ap_req: &'r [u8],
    pub(crate) krb_priv: &'r [u8],
    pub(crate) peer: HostAddr,
    pub(crate) local: HostAddr,
}

impl<'r> OpenArguments<'r> {
    /// Spec: docs/53 §5.5; RFC 4120 §7.1.
    pub(crate) fn of(request: &'r ChangePasswordRequest) -> OpenArguments<'r> {
        OpenArguments {
            ap_req: request.ap_req().as_bytes(),
            krb_priv: request.krb_priv().as_bytes(),
            peer: host_addr(request.peer()),
            local: host_addr(request.local()),
        }
    }
}

// The front's AP-REQ / KRB-PRIV bound fits keyd's channel (docs/53 §5.9:
// "the keyd codec … ≤ 80 KiB"; crate ipc-keyd: each message within
// `MAX_REQUEST_FIELD`, the whole body within `MAX_REQUEST_BODY`): a request
// the front forwards is never refused by dird's keyd client for its size.
const _: () = assert!(
    ipc_kpasswd::MAX_REQUEST_FIELD <= ipc_keyd::channel::MAX_REQUEST_FIELD
        && ipc_kpasswd::MAX_REQUEST_MESSAGES + 256 <= ipc_keyd::channel::MAX_REQUEST_BODY
);
