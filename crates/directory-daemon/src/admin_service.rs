//! dird's admin service (docs/51 §7, task A8): its parameters, its keyd
//! client, how it finds the admin service's key set and the protected
//! objects, and the mapping between the admin channel's typed messages
//! (crate ipc-dird-admin) and the write PEP's (crate directory-admin).
//!
//! # Ticket verification through keyd (A-73)
//!
//! dird verifies every AP-REQ of an admin request through keyd
//! `open_and_verify_service_ticket` under **Role::Ldap** (keyd's `uid_roles`
//! maps dird's uid to `Ldap`), naming the admin service's key set — the
//! admin service object's objectGUID with purpose `Service`. keyd runs RFC
//! 4120 §3.2.3 under that key, which never leaves keyd, and answers the
//! ticket's non-secret facts (crealm, cname, authtime); the write PEP builds
//! the Subject from them through the directory (docs/51 §5.3, option D).
//!
//! [`KeydTicketVerifier`] wraps ipc-keyd's `KeydClient` with F1's
//! connection rules (A-87): a held connection is checked before reuse
//! (inside `KeydClient`), and every new connection must answer
//! `DescribeConfig` (Kdc and Ldap may call it, docs/10 §2) with the
//! description the first connection gave — so a keyd restarted with dird's
//! uid mapped to another role, or serving another realm, serves nothing
//! (`Unavailable`) instead of answering every ticket with a uniform
//! `Denied` that would read as "bad ticket". The first description is taken
//! lazily, at the first request (keyd may still be in its start-up
//! hold-down, or down, when dird starts); its realm must be dird's. Only
//! ipc-keyd's public API is used, and the description is compared as a
//! whole value, so a field added to it later (F3: the caller's role) is
//! compared too (docs/questions/Q-387 item 2).
//!
//! # The set_secret grant (task A15a; docs/51 §5.8 option (b))
//!
//! keyd refuses admind's `set_secret` (Role::Directory) unless a live,
//! one-time grant names the key set. After a `BeginPasswordSet` is decided,
//! acknowledged and committed, dird registers that grant through the same
//! client (Role::Ldap, `grant_set_secret`) for exactly the key targets its
//! reply hands admind, live [`SET_SECRET_GRANT_LIFETIME_SECS`]; any failure
//! answers the `BeginPasswordSet` `Unavailable` (crate admin_engine, step 8a;
//! docs/questions/Q-453 item 1).
//!
//! # The admin service's key set (A-73)
//!
//! At start, dird resolves the SPN `admind/<dc-fqdn>` — the binding the
//! provisioning manifest records for the admin service object — exactly as
//! the KDC resolves a service principal (`AccountSource::service`, docs/47
//! §1.3: the unique servicePrincipalName index, the single stored value
//! compared octet for octet, a computer object): the handle is
//! `(objectGUID, Service)`. Absent, multi-valued, or naming another object
//! than the manifest's admin service ⇒ the admin service does not start;
//! dird's other services run (docs/questions/Q-386 item 3).
//!
//! # Protected objects
//!
//! `directory_admin::ProtectedObjects`: the service objects are the LDAP
//! and admin service objects of the manifest (their objectGUIDs); the
//! policy principals are the loaded policy's FAST bootstrap group (the tier
//! map's principals and subtrees are recognised by the PEP itself).
//! docs/questions/Q-386.
//!
//! Spec: docs/51 §5.2 row 9, §5.3, §7, §12 (A8); docs/10 §2, §5ב, §7א;
//! docs/50 §3.4, §3.6, §3.7; A-56; A-73; A-87; A-89.

use crate::policy::DevelopmentPolicy;
use core::fmt;
use core::time::Duration;
use directory_admin::{
    CompletePasswordSet, CreateComputer, CreateContainerLike, CreateGroup, CreateUser,
    KeyAdminOperation, KeyOperation as PepKeyOperation, KeyOperationOutcome as PepKeyOutcome,
    KeyRef as PepKeyRef, KeyReply, KeyTargets, LookupKey as PepLookupKey, Membership,
    Operation as PepOperation, PasswordSetOutcome as PepOutcome, ProtectedObjects,
    RefusalStatus as PepStatus, Reply as PepReply, SetAccountExpires, SetEnabled,
};
use directory_pip::{AccountKind as PipKind, DirectoryView};
use dirstore::NodeId;
use dtyp::Guid;
use ipc_audit::AccountExpiresValue;
use ipc_dird_admin::{
    AccountExpires, AccountKind, ApprovedKeyOperation, DestructionEntry, DestructionPage, Found,
    KeyOperation, KeyOperationOutcome, KeyRef, KeyRequestState, KeyTarget, KeyadmRequest,
    LookupKey, Operation, PasswordSet, PasswordSetOutcome, RefusalStatus, Reply,
};
use kdc::AccountSource;
use keyd_types::{
    AccountKind as GrantKind, AuthnError, KeyHandle, ServiceContext, SetSecretTarget,
};
use krb_proto::Realm;
use pdp::Dn;
use provision_manifest::Manifest;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

/// Connections admind may hold open at once on `dird-admin.sock`.
/// Spec: docs/51 §7.5 ("≤ 2 connections from admind").
pub const MAX_ADMIN_CONNECTIONS: usize = 2;

/// Requests the admin thread's queue holds before a request is answered
/// `Busy`. One: with one request in flight per connection and ≤ 2
/// connections, a request waits behind at most one other (docs/51 §7.5:
/// "an admin thread in dird with a bounded queue (full ⇒ `Busy`); writes
/// serialized"). Project choice.
pub const ADMIN_QUEUE_CAPACITY: usize = 1;

/// Largest admin queue accepted. Project bound (AGENTS.md §6).
pub const MAX_ADMIN_QUEUE_CAPACITY: usize = 16;

/// How long the admin thread waits for auditd's acknowledgement of a
/// decision event before it gives up and refuses the operation
/// `Unavailable` (nothing committed): 2 s, the keyd channel's client
/// deadline (docs/50 §3.6). Project choice (docs/questions/Q-388 item 3).
/// Every production dird uses it ([`DecisionAckDeadline::PRODUCTION`];
/// `startup::admin_params`) — there is no configuration key.
/// Spec: docs/51 §5.7 item 2; A-85.
pub const DECISION_ACK_DEADLINE: Duration = Duration::from_secs(2);

/// The AP-REQs one admin request may carry: the requester's and at most
/// [`ipc_dird_admin::channel::MAX_APPROVALS`] approvals' — each verified through keyd
/// before the decision event (docs/51 §7.4 steps 1-2, §7.2).
const MAX_VERIFICATIONS_PER_REQUEST: u32 = 1 + ipc_dird_admin::channel::MAX_APPROVALS;

/// The keyd calls one admin request may make: its AP-REQ verifications plus
/// the set_secret grant a `BeginPasswordSet` registers after its commit
/// (task A15a; docs/51 §5.8 option (b)).
const MAX_KEYD_CALLS_PER_REQUEST: u32 = MAX_VERIFICATIONS_PER_REQUEST + 1;

/// The ceiling of any dird's decision-acknowledgement wait: 4 s.
///
/// admind waits [`ipc_dird_admin::DEFAULT_DEADLINE`] (24 s, A-91, A-100) for each
/// answer on `dird-admin.sock`, and that deadline covers dird's worst case
/// for one request queued behind one other ([`MAX_ADMIN_CONNECTIONS`]
/// connections, one request in flight on each, docs/51 §7.5): for each,
/// [`MAX_KEYD_CALLS_PER_REQUEST`] keyd calls (the AP-REQ verifications and
/// the set_secret grant) at keyd's client deadline
/// ([`ipc_keyd::DEFAULT_DEADLINE`], 2 s, docs/50 §3.6) and one
/// decision-acknowledgement wait. 2 × (4 × 2 s + 4 s) = 24 s: a longer wait
/// could let dird decide — and commit — an operation after admind gave up
/// on it and reported it unavailable (the ambiguity A-86 / A-90 avoid), and
/// would hold the request queued behind it past admind's deadline as well.
/// Production stays at [`DECISION_ACK_DEADLINE`]; a wait between the two
/// exists only for tests on a loaded machine, whose fake auditd may be slow
/// (the A-95 treatment of keyd's intent budget, Q-417 item 3). Project
/// choice (docs/questions/Q-441).
pub const MAX_DECISION_ACK_DEADLINE: Duration = Duration::from_secs(4);

// The production wait is within the ceiling (docs/questions/Q-441).
const _: () = assert!(DECISION_ACK_DEADLINE.as_nanos() <= MAX_DECISION_ACK_DEADLINE.as_nanos());
// The ceiling keeps admind's deadline above dird's worst case for a request
// queued behind another (docs/51 §7.5; A-91; docs/questions/Q-441).
const _: () = assert!(
    (MAX_ADMIN_CONNECTIONS as u128)
        * (MAX_KEYD_CALLS_PER_REQUEST as u128 * ipc_keyd::DEFAULT_DEADLINE.as_nanos()
            + MAX_DECISION_ACK_DEADLINE.as_nanos())
        <= ipc_dird_admin::DEFAULT_DEADLINE.as_nanos()
);

/// The decision-acknowledgement wait of one dird: more than zero and at
/// most [`MAX_DECISION_ACK_DEADLINE`]. The range is checked when the value
/// is built ([`DecisionAckDeadline::new`]), so an [`AdminParams`] can only
/// carry a wait within the ceiling. There is no configuration key for it:
/// the parameters from dird's file always hold
/// [`DecisionAckDeadline::PRODUCTION`].
/// Spec: docs/51 §5.7 item 2; docs/questions/Q-388 item 3, Q-417 item 3,
/// Q-441; A-95 (follow-up).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionAckDeadline(Duration);

/// A decision-acknowledgement wait of zero or above
/// [`MAX_DECISION_ACK_DEADLINE`] was refused.
/// Spec: docs/questions/Q-441.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionAckDeadlineOutOfRange;

impl fmt::Display for DecisionAckDeadlineOutOfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("decision acknowledgement deadline out of range")
    }
}

impl std::error::Error for DecisionAckDeadlineOutOfRange {}

impl DecisionAckDeadline {
    /// [`DECISION_ACK_DEADLINE`], the wait of every production dird.
    pub const PRODUCTION: DecisionAckDeadline = DecisionAckDeadline(DECISION_ACK_DEADLINE);

    /// `deadline`, if it is more than zero and at most
    /// [`MAX_DECISION_ACK_DEADLINE`].
    ///
    /// # Errors
    /// [`DecisionAckDeadlineOutOfRange`]: zero (every write would be refused
    /// — a fault, not a setting) or above the ceiling.
    ///
    /// Spec: docs/questions/Q-441.
    pub const fn new(
        deadline: Duration,
    ) -> Result<DecisionAckDeadline, DecisionAckDeadlineOutOfRange> {
        if deadline.is_zero() || deadline.as_nanos() > MAX_DECISION_ACK_DEADLINE.as_nanos() {
            Err(DecisionAckDeadlineOutOfRange)
        } else {
            Ok(DecisionAckDeadline(deadline))
        }
    }

    /// The wait.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }
}

/// How long a set_secret grant dird registers stays live: keyd's ceiling for
/// Role::Ldap (`keyd_types::MAX_SET_SECRET_GRANT_SECS`, 30 s). dird registers
/// it right before it answers `BeginPasswordSet`; admind's two `set_secret`
/// calls follow at once, each within the keyd client's 2 s deadline.
/// Spec: docs/51 §5.8 option (b); docs/50 §3.6; docs/questions/Q-450 item 3.
pub const SET_SECRET_GRANT_LIFETIME_SECS: u32 = keyd_types::MAX_SET_SECRET_GRANT_SECS;

// More than the two keyd deadlines of admind's set_secret calls (docs/50
// §3.6: 2 s each), with margin.
const _: () = assert!(
    SET_SECRET_GRANT_LIFETIME_SECS as u64 > 4 * ipc_keyd::DEFAULT_DEADLINE.as_secs()
        && SET_SECRET_GRANT_LIFETIME_SECS <= keyd_types::MAX_SET_SECRET_GRANT_SECS
);

/// Why dird's set_secret grant was not registered (task A15a). Every case
/// answers the `BeginPasswordSet` `Unavailable`; the class only goes to
/// dird's log note.
/// Spec: docs/51 §5.8 option (b); docs/questions/Q-367 (A-88, A-90: the
/// three fates), Q-453 item 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantFailure {
    /// keyd answered and refused it (its own `Denied`, `Unavailable` — a
    /// full grant table — or `RateLimited`).
    Refused(keyd_types::Error),
    /// keyd did not register it: nothing was sent, or keyd-daemon refused it
    /// before keyd ran it (A-88), or keyd is not the keyd dird was
    /// configured for.
    NotPerformed,
    /// Sent, and no usable answer came back: keyd may hold the grant — it
    /// expires by itself within [`SET_SECRET_GRANT_LIFETIME_SECS`].
    OutcomeUnknown,
}

impl GrantFailure {
    /// The class number of the log note (docs/50 §8.2: a code, no content).
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            GrantFailure::Refused(_) => 1,
            GrantFailure::NotPerformed => 2,
            GrantFailure::OutcomeUnknown => 3,
        }
    }
}

/// dird's keyd client (Role::Ldap): one AP-REQ's verification — keyd's
/// `open_and_verify_service_ticket` for the admin service's key set — and
/// the set_secret grant after a `BeginPasswordSet` (task A15a).
/// Spec: docs/10 §5ב; docs/51 §5.8 option (b), §7.4 step 1; A-73.
pub trait TicketVerifier: Send {
    /// Verify `ap_req` (the raw `KRB_AP_REQ` DER admind forwarded) under
    /// `service`. keyd not reachable, not the configured keyd, or in its
    /// start-up hold-down ⇒ `AuthnError::Unavailable` (A-56); every other
    /// error is keyd's own answer.
    fn verify(&mut self, service: &KeyHandle, ap_req: &[u8]) -> Result<ServiceContext, AuthnError>;

    /// Register in keyd the one-time grant that lets admind's `set_secret`
    /// run on exactly `targets` (keyd's `grant_set_secret`, live for
    /// `lifetime_secs` by keyd's clock).
    /// Spec: docs/51 §5.8 option (b); docs/questions/Q-291 (A-74), Q-450.
    fn grant_set_secret(
        &mut self,
        kind: GrantKind,
        targets: &[SetSecretTarget],
        lifetime_secs: u32,
    ) -> Result<(), GrantFailure>;
}

/// The production verifier: ipc-keyd's client under Role::Ldap with F1's
/// per-connection description check (module documentation).
/// Spec: docs/51 §7.4 step 1; A-73; A-87.
pub struct KeydTicketVerifier<C: ipc_keyd::Connector> {
    client: ipc_keyd::KeydClient<C>,
    realm: Realm,
}

impl<C: ipc_keyd::Connector> KeydTicketVerifier<C> {
    /// A verifier over `client` for dird's `realm`.
    #[must_use]
    pub fn new(client: ipc_keyd::KeydClient<C>, realm: Realm) -> KeydTicketVerifier<C> {
        KeydTicketVerifier { client, realm }
    }
}

impl<C: ipc_keyd::Connector> fmt::Debug for KeydTicketVerifier<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeydTicketVerifier")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl<C: ipc_keyd::Connector> KeydTicketVerifier<C> {
    /// The first time: keyd's description must be of dird's realm and name
    /// dird's role Ldap; from then on both are required of every new
    /// connection (inside `KeydClient`). `false` ⇒ not the keyd dird was
    /// configured for, or keyd unreachable.
    /// Spec: docs/10 §7א; docs/50 §3.7, §7.5 step 4; A-73; A-87; A-90
    /// (docs/questions/Q-311, Q-351).
    fn keyd_identified(&mut self) -> bool {
        if self.client.required_description().is_some() {
            return true;
        }
        let Ok(described) = self.client.describe_config_with_role() else {
            return false;
        };
        // Another realm's keyd, or dird's uid mapped to another role than
        // Ldap: a cross-wiring ⇒ unavailable.
        if described.description.realm.as_bytes() != self.realm.as_bytes()
            || described.caller_role != keyd_types::Role::Ldap
        {
            return false;
        }
        self.client.require_caller_role(keyd_types::Role::Ldap);
        self.client.require_description(described.description);
        true
    }
}

impl<C> TicketVerifier for KeydTicketVerifier<C>
where
    C: ipc_keyd::Connector + Send,
    C::Connection: Send,
{
    /// Spec: docs/10 §5ב, §7א; docs/50 §3.7, §7.5 step 4; A-56; A-87
    /// (docs/questions/Q-311: the description required of every new
    /// connection).
    fn verify(&mut self, service: &KeyHandle, ap_req: &[u8]) -> Result<ServiceContext, AuthnError> {
        if !self.keyd_identified() {
            return Err(AuthnError::Unavailable);
        }
        self.client.open_and_verify_service_ticket(service, ap_req)
    }

    /// Through `call_with_fate` (A-90): the grant loosens keyd, so whether a
    /// failed call may still have registered it is told apart.
    /// Spec: docs/51 §5.8 option (b); docs/questions/Q-367 (A-88), Q-450,
    /// Q-453 item 1.
    fn grant_set_secret(
        &mut self,
        kind: GrantKind,
        targets: &[SetSecretTarget],
        lifetime_secs: u32,
    ) -> Result<(), GrantFailure> {
        if !self.keyd_identified() {
            return Err(GrantFailure::NotPerformed);
        }
        let call = ipc_keyd::Call::GrantSetSecret {
            kind,
            targets: targets.to_vec(),
            lifetime_secs,
        };
        match self.client.call_with_fate(&call) {
            Ok(ipc_keyd::Answer::GrantSetSecret(Ok(()))) => Ok(()),
            Ok(ipc_keyd::Answer::GrantSetSecret(Err(error))) => Err(GrantFailure::Refused(error)),
            // The client checks that a reply answers its call; anything
            // else cannot arrive — and would say nothing of the grant.
            Ok(_) => Err(GrantFailure::OutcomeUnknown),
            Err(failure) => Err(match failure.fate {
                ipc_keyd::RequestFate::NotSent | ipc_keyd::RequestFate::NotPerformed => {
                    GrantFailure::NotPerformed
                }
                ipc_keyd::RequestFate::OutcomeUnknown => GrantFailure::OutcomeUnknown,
            }),
        }
    }
}

/// Builds the admin thread's verifier when the admin service starts; `None`
/// ⇒ the admin service does not start.
pub type VerifierFactory = Arc<dyn Fn() -> Option<Box<dyn TicketVerifier>> + Send + Sync>;

/// What dird's admin service needs (from dird's configuration and the
/// provisioning manifest).
/// Spec: docs/51 §4.6, §5.5, §5.6, §7.1, §7.5; A-73; P-22.
#[derive(Clone)]
pub struct AdminParams {
    /// `dird_admin_socket`.
    pub socket: PathBuf,
    /// `admind_uid`: the only peer admitted (docs/51 §7.1).
    pub admind_uid: u32,
    /// keyd (`keyd_socket` + `keyd_uid`); `None` ⇒ the admin service does
    /// not start, the rest of dird runs (docs/51 §4.6).
    pub keyd: Option<VerifierFactory>,
    /// `admin_ticket_age_max` (R51-10).
    pub ticket_age_max: Duration,
    /// `admin_quorum` (P-22).
    pub quorum: usize,
    /// `node_id` (docs/51 §4.6).
    pub node_id: NodeId,
    /// The provisioning manifest (docs/51 §4.3 step 8).
    pub manifest: Manifest,
    /// Connections admind may hold ([`MAX_ADMIN_CONNECTIONS`]).
    pub max_connections: usize,
    /// The admin queue ([`ADMIN_QUEUE_CAPACITY`]).
    pub queue_capacity: usize,
    /// The decision-acknowledgement wait ([`DecisionAckDeadline::PRODUCTION`]
    /// in every production dird; at most [`MAX_DECISION_ACK_DEADLINE`]).
    pub ack_deadline: DecisionAckDeadline,
    /// The lifetime of a pending key-operation request
    /// (`directory_admin::KEY_REQUEST_LIFETIME`; docs/51 §5.6, task A10).
    pub key_request_lifetime: Duration,
}

impl fmt::Debug for AdminParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminParams")
            .field("socket", &self.socket)
            .field("admind_uid", &self.admind_uid)
            .field("keyd", &self.keyd.is_some())
            .field("ticket_age_max", &self.ticket_age_max)
            .field("quorum", &self.quorum)
            .field("max_connections", &self.max_connections)
            .field("queue_capacity", &self.queue_capacity)
            .field("ack_deadline", &self.ack_deadline)
            .field("key_request_lifetime", &self.key_request_lifetime)
            .finish_non_exhaustive()
    }
}

/// Why the admin service did not start (dird's other services run).
/// Spec: docs/51 §4.6, §7; A-73; docs/questions/Q-386 item 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotStarted {
    /// No keyd endpoint is configured.
    NoKeyd,
    /// The manifest is not of dird's realm or naming context, or does not
    /// name dird's DNS host.
    ManifestMismatch,
    /// No object holds the admin service's SPN (or it is not a computer).
    AdminServiceAbsent,
    /// The admin service's SPN is held by another object than the
    /// manifest's admin service object.
    AdminServiceMismatch,
    /// The directory could not answer (a multi-valued SPN included).
    DirectoryUnreadable,
    /// The write PEP refused its configuration or the schema.
    Configuration,
    /// The socket could not be bound, or its path is occupied.
    Bind,
    /// The admin thread could not be started.
    Spawn,
}

impl NotStarted {
    /// A numeric code for the fixed log note (docs/50 §8.2).
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            NotStarted::NoKeyd => 1,
            NotStarted::ManifestMismatch => 2,
            NotStarted::AdminServiceAbsent => 3,
            NotStarted::AdminServiceMismatch => 4,
            NotStarted::DirectoryUnreadable => 5,
            NotStarted::Configuration => 6,
            NotStarted::Bind => 7,
            NotStarted::Spawn => 8,
        }
    }
}

/// The objectGUID a manifest key set's handle names.
fn guid_of(handle: &KeyHandle) -> Guid {
    Guid::from_packet(handle.principal.as_bytes())
}

/// The manifest must describe dird's own domain and host (fail closed on
/// mismatched files).
/// Spec: docs/51 §4.3 step 8; A-53; docs/questions/Q-386 item 2.
pub(crate) fn check_manifest(
    manifest: &Manifest,
    realm: &Realm,
    naming_context: &directory_pip::NamingContext,
    dns_host_name: &str,
) -> Result<(), NotStarted> {
    let same_nc = manifest.naming_context_labels().len() == naming_context.labels().len()
        && manifest
            .naming_context_labels()
            .iter()
            .zip(naming_context.labels())
            .all(|(a, b)| a.eq_ignore_ascii_case(b));
    if manifest.realm().as_bytes() != realm.as_bytes()
        || !same_nc
        || !manifest.dc_fqdn().eq_ignore_ascii_case(dns_host_name)
    {
        return Err(NotStarted::ManifestMismatch);
    }
    Ok(())
}

/// The admin service's key set: the manifest's admin-service binding
/// resolved as the KDC resolves a service principal, and the result must be
/// the manifest's handle (module documentation).
/// Spec: docs/47 §1.3 (`AccountSource::service`); docs/51 §5.3; A-73;
/// docs/questions/Q-386 item 3.
pub(crate) fn admin_service_handle(
    view: &DirectoryView<'_>,
    manifest: &Manifest,
) -> Result<KeyHandle, NotStarted> {
    let expected = manifest.admin_service();
    match view.service(&expected.binding.realm, &expected.binding.name) {
        Ok(Some(account)) if account.key == expected.handle => Ok(account.key),
        Ok(Some(_)) => Err(NotStarted::AdminServiceMismatch),
        Ok(None) => Err(NotStarted::AdminServiceAbsent),
        Err(_) => Err(NotStarted::DirectoryUnreadable),
    }
}

/// The key sets a key-operation request may name: the manifest's krbtgt
/// account and its two service objects (the randomized `Service` key sets
/// of the ceremony, docs/51 §4.3 step 11).
/// Spec: docs/51 §4.3 steps 8, 11, §6; docs/questions/Q-420.
#[must_use]
pub fn key_targets(manifest: &Manifest) -> KeyTargets {
    KeyTargets {
        krbtgt: guid_of(&manifest.krbtgt().handle),
        services: BTreeSet::from([
            guid_of(&manifest.ldap_service().handle),
            guid_of(&manifest.admin_service().handle),
        ]),
    }
}

/// The protected objects (module documentation).
/// Spec: docs/51 §5.2 row 9, §4.3 step 5; A-39; A-44; docs/questions/Q-356
/// item 2, Q-386 item 1.
#[must_use]
pub fn protected_objects(manifest: &Manifest, policy: &DevelopmentPolicy) -> ProtectedObjects {
    ProtectedObjects {
        service_objects: BTreeSet::from([
            guid_of(&manifest.ldap_service().handle),
            guid_of(&manifest.admin_service().handle),
        ]),
        policy_principals: BTreeSet::from([policy.mandatory_fast.bootstrap_group]),
    }
}

// ---------------------------------------------------------------------------
// The channel's typed messages ↔ the write PEP's.
// ---------------------------------------------------------------------------

/// The PEP's key operation of a typed one (field for field).
/// Spec: docs/51 §6, §7.3; crate directory-admin `KeyOperation`.
fn pep_key_operation(operation: &KeyOperation) -> PepKeyOperation {
    match operation {
        KeyOperation::RotateKrbtgt => PepKeyOperation::RotateKrbtgt,
        KeyOperation::RotateKey { service } => PepKeyOperation::RotateKey { service: *service },
        KeyOperation::RetireKvno { key, kvno } => PepKeyOperation::RetireKvno {
            key: match key {
                KeyRef::Krbtgt => PepKeyRef::Krbtgt,
                KeyRef::Service(service) => PepKeyRef::Service(*service),
            },
            kvno: *kvno,
        },
    }
}

/// The typed key operation of the PEP's (field for field).
fn wire_key_operation(operation: &PepKeyOperation) -> KeyOperation {
    match operation {
        PepKeyOperation::RotateKrbtgt => KeyOperation::RotateKrbtgt,
        PepKeyOperation::RotateKey { service } => KeyOperation::RotateKey { service: *service },
        PepKeyOperation::RetireKvno { key, kvno } => KeyOperation::RetireKvno {
            key: match key {
                PepKeyRef::Krbtgt => KeyRef::Krbtgt,
                PepKeyRef::Service(service) => KeyRef::Service(*service),
            },
            kvno: *kvno,
        },
    }
}

/// The PEP's key-plane request of a typed operation, if it is one
/// (`RequestKeyOperation`, `Approve`).
/// Spec: docs/51 §5.6, §6, §7.3.
#[must_use]
pub fn key_request_of(operation: &Operation) -> Option<KeyAdminOperation> {
    match operation {
        Operation::RequestKeyOperation { operation } => {
            Some(KeyAdminOperation::RequestKeyOperation {
                operation: pep_key_operation(operation),
            })
        }
        Operation::Approve { id, operation } => Some(KeyAdminOperation::Approve {
            id: *id,
            operation: pep_key_operation(operation),
        }),
        _ => None,
    }
}

/// The PEP's key-plane request of a keyadm request.
/// Spec: docs/51 §6, §7.3.
#[must_use]
pub fn keyadm_request(request: &KeyadmRequest) -> KeyAdminOperation {
    match request {
        KeyadmRequest::FetchApproved { id } => KeyAdminOperation::FetchApproved { id: *id },
        KeyadmRequest::Complete { id, outcome } => KeyAdminOperation::Complete {
            id: *id,
            outcome: match outcome {
                KeyOperationOutcome::Performed { kvno } => PepKeyOutcome::Performed { kvno: *kvno },
                KeyOperationOutcome::Refused => PepKeyOutcome::Refused,
                KeyOperationOutcome::NotPerformed => PepKeyOutcome::NotPerformed,
                KeyOperationOutcome::OutcomeUnknown => PepKeyOutcome::OutcomeUnknown,
            },
        },
        KeyadmRequest::ListPendingDestruction { cursor } => {
            KeyAdminOperation::ListPendingDestruction { cursor: *cursor }
        }
    }
}

/// The typed reply of a key-plane step. A count that cannot be one octet
/// (never: at most two approvals, a quorum of at most three) is answered
/// `Unavailable`.
/// Spec: docs/51 §6, §7.3.
#[must_use]
pub fn wire_key_reply(reply: &KeyReply) -> Reply {
    match reply {
        KeyReply::Request(view) => {
            match (u8::try_from(view.approvals), u8::try_from(view.quorum)) {
                (Ok(approvals), Ok(quorum)) => Reply::KeyRequest(KeyRequestState {
                    id: view.id,
                    digest: view.digest,
                    operation: wire_key_operation(&view.operation),
                    approvals,
                    quorum,
                }),
                _ => Reply::Refused(RefusalStatus::Unavailable),
            }
        }
        KeyReply::Approved(approved) => Reply::Approved(ApprovedKeyOperation {
            id: approved.id,
            digest: approved.digest,
            operation: wire_key_operation(&approved.operation),
            principal: guid_of(&approved.handle),
            requester: approved.requester,
            approvers: approved.approvers.clone(),
        }),
        KeyReply::Done => Reply::Done,
        KeyReply::Page(page) => Reply::PendingDestruction(DestructionPage {
            entries: page
                .entries
                .iter()
                .map(|e| DestructionEntry {
                    guid: e.guid,
                    kind: match e.kind {
                        PipKind::User => AccountKind::User,
                        PipKind::Computer => AccountKind::Computer,
                    },
                })
                .collect(),
            next: page.next,
        }),
    }
}

/// The PEP's operation of a typed request (field for field; no rule is
/// applied here — the PEP checks every value and audits a refusal); `None`
/// for a key-plane request ([`key_request_of`]).
/// Spec: docs/51 §7.3; crate directory-admin `Operation`.
#[must_use]
pub fn pep_operation(operation: &Operation) -> Option<PepOperation> {
    Some(match operation {
        Operation::CreateUser {
            parent,
            sam,
            upn,
            description,
        } => PepOperation::CreateUser(CreateUser {
            parent: *parent,
            sam: sam.clone(),
            upn: upn.clone(),
            description: description.clone(),
        }),
        Operation::CreateComputer {
            parent,
            name,
            dns_host_name,
            spn,
        } => PepOperation::CreateComputer(CreateComputer {
            parent: *parent,
            name: name.clone(),
            dns_host_name: dns_host_name.clone(),
            spn: spn.clone(),
        }),
        Operation::CreateGroup {
            parent,
            sam,
            group_type,
        } => PepOperation::CreateGroup(CreateGroup {
            parent: *parent,
            sam: sam.clone(),
            group_type: *group_type,
        }),
        Operation::CreateOu { parent, name } => PepOperation::CreateOu(CreateContainerLike {
            parent: *parent,
            name: name.clone(),
        }),
        Operation::CreateContainer { parent, name } => {
            PepOperation::CreateContainer(CreateContainerLike {
                parent: *parent,
                name: name.clone(),
            })
        }
        Operation::BeginPasswordSet { target } => {
            PepOperation::BeginPasswordSet { target: *target }
        }
        Operation::CompletePasswordSet {
            target,
            outcome,
            kvnos,
        } => PepOperation::CompletePasswordSet(CompletePasswordSet {
            target: *target,
            outcome: match outcome {
                PasswordSetOutcome::Completed => PepOutcome::Completed,
                PasswordSetOutcome::Failed => PepOutcome::Failed,
            },
            kvnos: kvnos.clone(),
        }),
        Operation::SetEnabled { target, enabled } => PepOperation::SetEnabled(SetEnabled {
            target: *target,
            enabled: *enabled,
        }),
        Operation::SetAccountExpires { target, value } => {
            PepOperation::SetAccountExpires(SetAccountExpires {
                target: *target,
                value: match value {
                    AccountExpires::Never => AccountExpiresValue::NEVER,
                    AccountExpires::At(at) => AccountExpiresValue::at(*at),
                },
            })
        }
        Operation::AddMember { group, member } => PepOperation::AddMember(Membership {
            group: *group,
            member: *member,
        }),
        Operation::RemoveMember { group, member } => PepOperation::RemoveMember(Membership {
            group: *group,
            member: *member,
        }),
        Operation::Delete { target } => PepOperation::Delete { target: *target },
        Operation::Lookup(key) => PepOperation::Lookup(match key {
            LookupKey::SamAccountName(sam) => PepLookupKey::SamAccountName(sam.clone()),
            LookupKey::ServicePrincipalName(spn) => PepLookupKey::ServicePrincipalName(spn.clone()),
            LookupKey::Dn(dn) => PepLookupKey::Dn(Dn::new(dn.clone())),
        }),
        Operation::RequestKeyOperation { .. } | Operation::Approve { .. } => return None,
    })
}

/// The wire status of the PEP's status (the same six values by name).
/// Spec: A-26; A-55; A-56; crate directory-admin `RefusalStatus`.
#[must_use]
pub fn wire_status(status: PepStatus) -> RefusalStatus {
    match status {
        PepStatus::Denied => RefusalStatus::Denied,
        PepStatus::ApprovalRequired => RefusalStatus::ApprovalRequired,
        PepStatus::NotFound => RefusalStatus::NotFound,
        PepStatus::Invalid => RefusalStatus::Invalid,
        PepStatus::Conflict => RefusalStatus::Conflict,
        PepStatus::Unavailable => RefusalStatus::Unavailable,
    }
}

/// The set_secret grant a committed `BeginPasswordSet` asks keyd for: the
/// account kind and exactly the key targets — handles and bindings — the
/// reply hands admind (task A15a). `None` for any other reply.
/// Spec: docs/51 §5.2 row 5, §5.8 option (b), §7.3; docs/47 §9.1;
/// docs/questions/Q-450 item 2.
#[must_use]
pub fn grant_of(reply: &PepReply) -> Option<(GrantKind, Vec<SetSecretTarget>)> {
    let PepReply::PasswordSet(set) = reply else {
        return None;
    };
    let kind = match set.kind {
        PipKind::User => GrantKind::User,
        PipKind::Computer => GrantKind::Computer,
    };
    let targets = set
        .keys
        .iter()
        .map(|k| SetSecretTarget {
            handle: k.handle,
            binding: k.binding.clone(),
        })
        .collect();
    Some((kind, targets))
}

/// The typed reply of the PEP's reply.
/// Spec: docs/51 §7.3 (the reply column).
#[must_use]
pub fn wire_reply(reply: &PepReply) -> Reply {
    match reply {
        PepReply::Created { guid, sid } => Reply::Created {
            guid: *guid,
            sid: *sid,
        },
        PepReply::PasswordSet(set) => Reply::PasswordSet(PasswordSet {
            kind: match set.kind {
                PipKind::User => AccountKind::User,
                PipKind::Computer => AccountKind::Computer,
            },
            keys: set
                .keys
                .iter()
                .map(|k| KeyTarget {
                    handle: k.handle,
                    binding: k.binding.clone(),
                })
                .collect(),
            salt: set.salt.clone(),
        }),
        PepReply::Done => Reply::Done,
        PepReply::Found(found) => Reply::Found(Found {
            guid: found.guid,
            dn: found.dn.rdns().to_vec(),
            class: found.class.to_owned(),
            sid: found.sid,
        }),
    }
}

// The channel's field bounds hold every value the PEP accepts, and its DN
// bound is directory-pip's (this crate links both; ipc-dird-admin links
// neither). Checked at compile time.
const _: () =
    assert!(ipc_dird_admin::channel::MAX_NAME as usize >= directory_admin::MAX_GROUP_SAM_CHARS);
const _: () =
    assert!(ipc_dird_admin::channel::MAX_NAME as usize >= directory_admin::MAX_ACCOUNT_SAM_CHARS);
const _: () =
    assert!(ipc_dird_admin::channel::MAX_NAME as usize >= directory_admin::MAX_RDN_VALUE_CHARS);
const _: () = assert!(
    ipc_dird_admin::channel::MAX_PRINCIPAL_NAME as usize
        >= directory_admin::MAX_PRINCIPAL_NAME_CHARS
);
const _: () = assert!(
    ipc_dird_admin::channel::MAX_DNS_HOST_NAME as usize >= directory_admin::MAX_DNS_HOST_NAME_CHARS
);
const _: () = assert!(
    ipc_dird_admin::channel::MAX_DESCRIPTION as usize >= 3 * directory_admin::MAX_DESCRIPTION_UNITS
);
const _: () =
    assert!(ipc_dird_admin::channel::MAX_DN_COMPONENTS as usize == directory_pip::MAX_DN_DEPTH);
const _: () = assert!(ipc_dird_admin::channel::MAX_APPROVALS as usize == ipc_audit::MAX_APPROVERS);
const _: () = assert!(ipc_dird_admin::channel::MAX_KVNOS as usize == ipc_audit::MAX_REPORTED_KVNOS);
const _: () = assert!(
    ipc_dird_admin::channel::MAX_DESTRUCTION_ENTRIES as usize
        == directory_admin::MAX_DESTRUCTION_PAGE
);
const _: () = assert!(ipc_dird_admin::channel::DIGEST_LEN == directory_admin::DIGEST_LEN);
const _: () = assert!(directory_admin::MAX_QUORUM <= u8::MAX as usize);
