//! dird's admin service (docs/51 §7, task A8): its parameters, its keyd
//! client, how it finds the admin service's key set and the protected
//! objects, and the mapping between the admin channel's typed messages
//! (crate ipc-dird-admin) and the write PEP's (crate directory-admin).
//!
//! # Ticket verification through keyd (A-73)
//!
//! dird verifies every AP-REQ of an admin request through keyd
//! `open_and_verify_service_ticket` under **Role::Ldap** (keyd's `uid_roles`
//! maps dird's uid to `Ldap`), naming the admin service's principal — the
//! admin service object's objectGUID — and **the operation digest** of the
//! request (R2 below): keyd opens the ticket only under the admin service's
//! own key set (purpose `AdminService`, which follows from the binding).
//! keyd runs RFC 4120 §3.2.3 under that key, which never leaves keyd, and
//! answers the ticket's non-secret facts (crealm, cname, authtime) and the
//! digest it verified; the write PEP builds the Subject from them through
//! the directory (docs/51 §5.3, option D).
//!
//! # Every AP-REQ is bound to its operation (R2; docs/52 §3.2, §5; A-102)
//!
//! Class C2 (confused deputy): an AP-REQ says who asks, not what — so a
//! compromised admind could attach an administrator's AP-REQ to another
//! operation. The client puts the session key's MIC over the request's
//! operation digest into the Authenticator's `cksum` (RFC 4120 §5.5.1, key
//! usage 10; crate ipc-dird-admin `operation_digest`: SHA-256 over a label,
//! the channel header and the payload after `auth`). dird computes the
//! digest from the request **it decoded** and passes it with the request's
//! one AP-REQ ([`TicketVerifier::verify`] takes a digest — dird cannot ask
//! for an unbound admin verification). keyd verifies the `cksum` while it
//! opens the ticket; a mismatch is the uniform `Denied`. The PEP reports
//! `channel_bound` to the PDP only for a request whose ticket carries that
//! digest (docs/11 §4: a write needs it — no exemption). A request carries
//! exactly one AP-REQ — the requester's, or the approver's of an `Approve`:
//! the in-request approvals are retired (docs/questions/Q-882, A-148).
//!
//! [`KeydTicketVerifier`] owns ipc-keyd's `KeydClient`, built only with
//! the keyd dird expects (task R9, docs/questions/Q-466): keyd's uid, the
//! caller role **Ldap** and dird's **realm**. On every new connection —
//! inside `KeydClient`, before anything else is sent — keyd's uid is
//! checked and keyd must answer `DescribeConfig` (Kdc and Ldap may call it,
//! docs/10 §2) naming the role Ldap and dird's realm; a held connection is
//! checked before reuse (A-87). So a keyd restarted with dird's uid mapped
//! to another role, or serving another realm, serves nothing
//! (`Unavailable`) instead of answering every ticket with a uniform
//! `Denied` that would read as "bad ticket", and no decision is registered
//! with it. There is no lazy first check to forget: the expectation exists
//! from construction (it replaced the opt-in `require_description` /
//! `require_caller_role` of A-87 / A-90, docs/52 §3.12 C12).
//!
//! # dird's decisions in keyd (task A15a; A-102, docs/52 R1, §4.3)
//!
//! keyd performs no Directory / Admin state change without a decision dird
//! registered (Role::Ldap, `register_decision`, through
//! [`TicketVerifier::register_decision`]). dird registers three kinds
//! (crate admin_engine):
//!
//! * after a `BeginPasswordSet` is decided, acknowledged and committed — a
//!   `SetSecret` decision for exactly the key targets **and salt** its reply
//!   hands admind ([`secret_decision_of`]), live
//!   [`SET_SECRET_GRANT_LIFETIME_SECS`]; any failure answers the
//!   `BeginPasswordSet` `Unavailable` (step 8a; docs/questions/Q-453 item 1);
//! * at the `Approve` that completes a key request's quorum — the request's
//!   decision (`RotateKrbtgt` / `RotateKey` / `RetireKvno`, the approvers,
//!   the request's remaining lifetime), after the step's decision event was
//!   acknowledged; any failure reverts the approval and answers
//!   `Unavailable`;
//! * after a `Delete` of a user or computer committed — a `DestroyKeySet`
//!   decision for its tombstone, live `keyd_types::MAX_DESTROY_DECISION_SECS`;
//!   a failure is noted (`AdminDestroyNotRegistered`) and the `Delete` still
//!   answers its success: the account is deleted and its key sets are
//!   unreachable (no object ⇒ no handle, docs/51 §9 — fail closed);
//! * again, for every tombstoned user or computer whose destruction is not
//!   known complete — at the admin service's start and every
//!   [`DESTROY_RECONCILE_INTERVAL`] — so that a destroy decision
//!   lost by a keyd restart or a failed registration is registered again
//!   (A-105; crate::reconcile).
//!
//! Each registration is a [`crate::DecisionRegistration`], which dird builds
//! only from its evidence — an acknowledged decision event, an applied write,
//! or a tombstone (docs/52 §3.11 R6; crate::registration).
//!
//! # The admin service's key set (A-73)
//!
//! At start, dird resolves the SPN `admind/<dc-fqdn>` — the binding the
//! provisioning manifest records for the admin service object — exactly as
//! the KDC resolves a service principal (`AccountSource::service`, docs/47
//! §1.3: the unique servicePrincipalName index, the single stored value
//! compared octet for octet, a computer object): the handle is
//! `(objectGUID, AdminService)` (R2: the admin service's own purpose,
//! `KeyPurpose::of_service_name`). Absent, multi-valued, or naming another object
//! than the manifest's admin service ⇒ the admin service does not start;
//! dird's other services run (docs/questions/Q-386 item 3).
//!
//! # The request queue (task D2-c; docs/questions/Q-882, A-148)
//!
//! `Propose` maps onto the PEP's [`ProposedOperation`] ([`proposal_of`]):
//! a proposable directory write field for field, a `ChangePolicy` onto the
//! tier-map vocabulary, a `KeyOperation` onto the PEP's key operation; its
//! fingerprint is the proposed operation's own digest
//! (`ipc_dird_admin::operation_digest`). `Approve` / `Reject` / `Withdraw`
//! / `ListRequests` / `ShowRequest` map onto [`RequestStep`]s
//! ([`step_of`]); a `ShowRequest`'s operation is rendered back from the
//! request's own fields ([`wire_proposed`] — never requester text).
//!
//! # The policy change (task A16; docs/51 §5.10)
//!
//! `ChangePolicy` maps field for field onto crate policy-store's tier-map
//! vocabulary ([`policy_change_of`]) — the one edit `provision policy` uses
//! offline; the PEP decides it (`prepare_policy_change`) and dird writes the
//! acknowledged candidate as `policy.next` ([`AdminParams::policy_next`],
//! crate::policy_next). The channel's bounds are pinned against the PEP's
//! and the policy file's below.
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
//! docs/50 §3.4, §3.6, §3.7; docs/52 §3.2, §5 (R2); RFC 4120 §5.5.1, §7.5.1;
//! A-56; A-73; A-87; A-89; A-102.

use crate::policy::DevelopmentPolicy;
use crate::policy_next::PolicyNextFile;
use crate::registration::DecisionRegistration;
use core::fmt;
use core::time::Duration;
use directory_admin::{
    CompletePasswordSet, CreateComputer, CreateContainerLike, CreateGroup, CreateUser,
    KeyOperation as PepKeyOperation, KeyRef as PepKeyRef, KeyTargets, ListScope as PepListScope,
    LookupKey as PepLookupKey, Membership, Operation as PepOperation,
    PasswordSetOutcome as PepOutcome, ProposedOperation, ProtectedObjects,
    RefusalStatus as PepStatus, Reply as PepReply, RequestDetail, RequestFact,
    RequestState as PepState, RequestStep, RequestSummary as PepSummary, RequestView,
    SetAccountExpires, SetEnabled, StepReply,
};
use directory_pip::{AccountKind as PipKind, DirectoryView};
use dirstore::NodeId;
use dtyp::Guid;
use ipc_audit::AccountExpiresValue;
use ipc_dird_admin::{
    AccountExpires, AccountKind, Fact, FactTier, Found, KeyOperation, KeyRef, KeyTarget, ListScope,
    LookupKey, Operation, PasswordSet, PasswordSetOutcome, PendingRequestState, PolicyChange,
    PolicyTier, RefusalStatus, Reply, RequestShown, RequestState, RequestSummary,
};
use kdc::AccountSource;
use keyd_types::{
    AccountKind as GrantKind, AuthnError, DecidedOperation, DecisionId, DestructionPage, KeyHandle,
    OperationDigest, OperationTicket, PrincipalId, ServiceKeyHandle, SetSecretTarget,
};
use krb_proto::Realm;
use pdp::Dn;
use pdp::Tier;
use policy_store::TierChange;
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

/// The AP-REQs one admin request carries: one — the requester's (or the
/// approver's of an `Approve` / `Reject`), verified through keyd before the
/// decision event (docs/51 §7.4 steps 1-2, §7.2). The in-request approvals
/// are retired (docs/questions/Q-882).
const MAX_VERIFICATIONS_PER_REQUEST: u32 = 1;

/// The keyd calls one admin request may make: its AP-REQ verifications plus
/// the one decision it may register after its commit or its acknowledged
/// decision event (task A15a; A-102: a `BeginPasswordSet`'s `SetSecret`, an
/// `Approve`'s key decision — one verification —, a `Delete`'s
/// `DestroyKeySet`).
const MAX_KEYD_CALLS_PER_REQUEST: u32 = MAX_VERIFICATIONS_PER_REQUEST + 1;

/// The ceiling of any dird's decision-acknowledgement wait: 4 s.
///
/// admind waits [`ipc_dird_admin::DEFAULT_DEADLINE`] (24 s, A-91, A-100) for each
/// answer on `dird-admin.sock`, and that deadline covers dird's worst case
/// for one request queued behind one other ([`MAX_ADMIN_CONNECTIONS`]
/// connections, one request in flight on each, docs/51 §7.5): for each,
/// [`MAX_KEYD_CALLS_PER_REQUEST`] keyd calls (the AP-REQ verification and
/// the decision's registration) at keyd's client deadline
/// ([`ipc_keyd::DEFAULT_DEADLINE`], 2 s, docs/50 §3.6) and one
/// decision-acknowledgement wait. 2 × (2 × 2 s + 4 s) = 16 s ≤ 24 s (it was
/// 2 × (4 × 2 s + 4 s) with in-request approvals): a longer wait
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
/// is built ([`DecisionAckDeadline::new`]), so an `AdminServeParams` can only
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

/// How long a `SetSecret` decision dird registers stays live: keyd's ceiling
/// for the set-secret family (`keyd_types::MAX_SET_SECRET_GRANT_SECS`,
/// 30 s). dird registers it right before it answers `BeginPasswordSet`;
/// admind's two `set_secret` calls follow at once, each within the keyd
/// client's 2 s deadline.
/// Spec: docs/51 §5.8 option (b); docs/50 §3.6; docs/questions/Q-450
/// item 3; docs/52 §4.3 (A-102).
pub const SET_SECRET_GRANT_LIFETIME_SECS: u32 = keyd_types::MAX_SET_SECRET_GRANT_SECS;

// More than the two keyd deadlines of admind's set_secret calls (docs/50
// §3.6: 2 s each), with margin.
const _: () = assert!(
    SET_SECRET_GRANT_LIFETIME_SECS as u64 > 4 * ipc_keyd::DEFAULT_DEADLINE.as_secs()
        && SET_SECRET_GRANT_LIFETIME_SECS <= keyd_types::MAX_SET_SECRET_GRANT_SECS
);

/// Why a decision dird registers in keyd was not registered (task A15a;
/// A-102). The class goes to dird's log note (and, for an `Approve`'s
/// decision, to its `Outcome` event).
/// Spec: docs/51 §5.8 option (b); docs/questions/Q-367 (A-88, A-90: the
/// three fates), Q-453 item 1; docs/52 §4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationFailure {
    /// keyd answered and refused it (its own `Denied`, `Unavailable` — a
    /// full decision family — or `RateLimited`).
    Refused(keyd_types::Error),
    /// keyd did not register it: nothing was sent, or keyd-daemon refused it
    /// before keyd ran it (A-88), or keyd is not the keyd dird was
    /// configured for.
    NotPerformed,
    /// Sent, and no usable answer came back: keyd may hold the decision —
    /// it expires by itself, and an identical re-registration is accepted
    /// unchanged.
    OutcomeUnknown,
}

impl RegistrationFailure {
    /// The class number of the log note (docs/50 §8.2: a code, no content).
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            RegistrationFailure::Refused(_) => 1,
            RegistrationFailure::NotPerformed => 2,
            RegistrationFailure::OutcomeUnknown => 3,
        }
    }
}

/// dird's keyd client (Role::Ldap): one AP-REQ's verification — keyd's
/// `verify_operation_ticket` for the admin service's key set, bound to an
/// operation digest, which leaves no service context in keyd (Q-523) — and
/// the registration of dird's decisions (task A15a; A-102).
/// Spec: docs/10 §5ב; docs/51 §5.8 option (b), §7.4 step 1; A-73; docs/52
/// §4.2, §4.3, §5 items 3-4.
pub trait TicketVerifier: Send {
    /// Verify `ap_req` (the raw `KRB_AP_REQ` DER admind forwarded) under the
    /// admin service key set of `service`, bound to `operation` — the
    /// operation digest dird computed from the request it decoded (R2: the
    /// Authenticator's `cksum`, RFC 4120 §5.5.1). There is no unbound form:
    /// an admin ticket is verified against an operation or not at all. keyd
    /// not reachable, not the configured keyd, or in its start-up hold-down
    /// ⇒ `AuthnError::Unavailable` (A-56); every other error is keyd's own
    /// answer. The answer carries no context id: dird has no use for one,
    /// and keyd keeps none (docs/questions/Q-523).
    fn verify(
        &mut self,
        service: &PrincipalId,
        operation: &OperationDigest,
        ap_req: &[u8],
    ) -> Result<OperationTicket, AuthnError>;

    /// Register in keyd dird's `decision` (keyd's `register_decision`,
    /// Role::Ldap): its id, operation, approvers and lifetime. A
    /// [`DecisionRegistration`] is built only from its evidence (an
    /// acknowledged decision event, an applied write, a tombstone —
    /// crate::registration), so this cannot be reached for a decision auditd
    /// has not durably recorded.
    /// Spec: docs/52 §4.2, §4.3 (A-102), §3.11 R6 (a); docs/51 §5.8 option
    /// (b); docs/questions/Q-291 (A-74), Q-450, Q-460.
    fn register_decision(
        &mut self,
        decision: DecisionRegistration,
    ) -> Result<(), RegistrationFailure>;

    /// One page of keyd's pending destroy decisions strictly after `after`
    /// (keyd's `list_destroy_decisions`, Role::Ldap since task R6), for the
    /// re-registration of lost ones (crate::reconcile); `None` when keyd
    /// did not answer with a page. Reads only. The default answers `None`
    /// (a verifier that cannot list: nothing is re-registered).
    /// Spec: docs/52 §4.3, §4.6; docs/questions/Q-470 (A-105), Q-501, Q-503.
    fn list_destroy_decisions(&mut self, after: Option<DecisionId>) -> Option<DestructionPage> {
        let _ = after;
        None
    }
}

/// The production verifier: ipc-keyd's client expecting Role::Ldap and
/// dird's realm on every connection (module documentation).
/// Spec: docs/51 §7.4 step 1; A-73; A-87; docs/52 §3.12; docs/questions/
/// Q-466 item 1 (A-102).
pub struct KeydTicketVerifier<C: ipc_keyd::Connector> {
    client: ipc_keyd::KeydClient<C>,
}

impl<C: ipc_keyd::Connector> KeydTicketVerifier<C> {
    /// A verifier talking to keyd through `connector`: keyd runs as
    /// `keyd_uid`, gives dird the role Ldap and serves `realm` — checked on
    /// every connection before anything else is sent — with a per-call
    /// `deadline` (`ipc_keyd::DEFAULT_DEADLINE` in dird).
    ///
    /// # Errors
    /// `ipc_keyd::ClientConfigError` (a keyd uid of 0).
    ///
    /// Spec: docs/10 §2 (Role `Ldap`), §7א; docs/50 R50-3, §3.7, §7.5 step
    /// 4; A-73; docs/questions/Q-311, Q-351, Q-466 item 1 (A-102).
    pub fn new(
        connector: C,
        keyd_uid: u32,
        realm: Realm,
        deadline: Duration,
    ) -> Result<KeydTicketVerifier<C>, ipc_keyd::ClientConfigError> {
        let peer = ipc_keyd::ExpectedPeer::new(keyd_uid, keyd_types::Role::Ldap)?
            .with_description(ipc_keyd::ExpectedDescription::Realm(realm))?;
        Ok(KeydTicketVerifier {
            client: ipc_keyd::KeydClient::new(connector, peer, deadline),
        })
    }
}

impl<C: ipc_keyd::Connector> fmt::Debug for KeydTicketVerifier<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeydTicketVerifier")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl<C> TicketVerifier for KeydTicketVerifier<C>
where
    C: ipc_keyd::Connector + Send,
    C::Connection: Send,
{
    /// Spec: docs/10 §5ב, §7א; docs/50 §3.7, §7.5 step 4; docs/52 §5 item 3;
    /// A-56; A-87 (docs/questions/Q-311); docs/questions/Q-466 (the role and
    /// realm expected of every new connection), Q-523 (no service context).
    fn verify(
        &mut self,
        service: &PrincipalId,
        operation: &OperationDigest,
        ap_req: &[u8],
    ) -> Result<OperationTicket, AuthnError> {
        // The client verifies keyd's uid, role and realm on every new
        // connection before this is sent (task R9).
        self.client
            .verify_operation_ticket(service, operation, ap_req)
    }

    /// Through `call_with_fate` (A-90): a decision loosens keyd, so whether
    /// a failed call may still have registered it is told apart.
    /// Spec: docs/52 §4.2, §4.3; docs/51 §5.8 option (b);
    /// docs/questions/Q-367 (A-88), Q-450, Q-453 item 1, Q-460.
    fn register_decision(
        &mut self,
        decision: DecisionRegistration,
    ) -> Result<(), RegistrationFailure> {
        let call = ipc_keyd::Call::RegisterDecision {
            id: decision.id(),
            operation: decision.operation().clone(),
            approvers: decision.approvers().to_vec(),
            lifetime_secs: decision.lifetime_secs(),
        };
        match self.client.call_with_fate(&call) {
            Ok(ipc_keyd::Answer::RegisterDecision(Ok(()))) => Ok(()),
            Ok(ipc_keyd::Answer::RegisterDecision(Err(error))) => {
                Err(RegistrationFailure::Refused(error))
            }
            // The client checks that a reply answers its call; anything
            // else cannot arrive — and would say nothing of the decision.
            Ok(_) => Err(RegistrationFailure::OutcomeUnknown),
            Err(failure) => Err(match failure.fate {
                ipc_keyd::RequestFate::NotSent | ipc_keyd::RequestFate::NotPerformed => {
                    RegistrationFailure::NotPerformed
                }
                ipc_keyd::RequestFate::OutcomeUnknown => RegistrationFailure::OutcomeUnknown,
            }),
        }
    }

    /// A read: `call` (the fate is not needed — nothing changes either way).
    /// Spec: docs/52 §4.6; docs/questions/Q-470 (A-105), Q-501, Q-503.
    fn list_destroy_decisions(&mut self, after: Option<DecisionId>) -> Option<DestructionPage> {
        self.client.list_destroy_decisions(after).ok()
    }
}

/// Builds the admin thread's verifier when the admin service starts; `None`
/// ⇒ the admin service does not start. A product dird builds only the
/// production one ([`AdminServeParams::production`]); any other is a test
/// seam (docs/52 C18, task R15).
pub type VerifierFactory = Arc<dyn Fn() -> Option<Box<dyn TicketVerifier>> + Send + Sync>;

/// keyd's socket and uid, as dird's configuration names them (`keyd_socket`,
/// `keyd_uid`; docs/51 §4.6).
/// Spec: docs/51 §4.6; docs/50 §3.2; A-73.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeydEndpoint {
    /// `keyd_socket`.
    pub socket: PathBuf,
    /// `keyd_uid`: the only keyd dird accepts (task R9).
    pub uid: u32,
}

/// What dird's configuration and the provisioning manifest set for the admin
/// service — **and nothing else** (docs/52 C18, task R15): the product
/// parameters. Its keyd client, its connection and queue bounds, the
/// decision-acknowledgement wait, the pending requests' lifetime and
/// per-requester cap, and the re-registration interval are the daemon's
/// production values, supplied by
/// `serve_with_admin` ([`AdminServeParams::production`]); they are not fields
/// here.
/// Spec: docs/51 §4.6, §5.5, §5.6, §7.1, §7.5; A-73; P-22; docs/52 §3.18.
#[derive(Debug, Clone)]
pub struct AdminParams {
    /// `dird_admin_socket`.
    pub socket: PathBuf,
    /// `admind_uid`: the only peer admitted (docs/51 §7.1).
    pub admind_uid: u32,
    /// keyd (`keyd_socket` + `keyd_uid`); `None` ⇒ the admin service does
    /// not start, the rest of dird runs (docs/51 §4.6).
    pub keyd: Option<KeydEndpoint>,
    /// `admin_ticket_age_max` (R51-10).
    pub ticket_age_max: Duration,
    /// `admin_quorum` (P-22).
    pub quorum: usize,
    /// `node_id` (docs/51 §4.6).
    pub node_id: NodeId,
    /// The provisioning manifest (docs/51 §4.3 step 8).
    pub manifest: Manifest,
    /// `policy_next_path` with dird's own account (`run_as_uid`) as the
    /// file's owner — where an approved tier-map change is written as
    /// `policy.next` for root to activate (task A16, docs/51 §5.10); `None`
    /// ⇒ `ChangePolicy` is answered `Unavailable` (policy changes offline
    /// only). A configured value, not a seam.
    pub policy_next: Option<PolicyNextFile>,
}

/// Everything the admin service runs with: the product [`AdminParams`] plus
/// the test seams. Built for a product dird only by
/// [`AdminServeParams::production`]; outside this crate only through
/// `test_seams::AdminParams` (docs/52 C18, task R15).
/// Spec: docs/51 §4.6, §5.5, §5.6, §7.1, §7.5; A-73; P-22.
#[derive(Clone)]
pub(crate) struct AdminServeParams {
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
    /// The lifetime of a pending request (`directory_admin::REQUEST_LIFETIME`;
    /// docs/51 §5.6; docs/questions/Q-939).
    pub request_lifetime: Duration,
    /// The open pending requests one requester may hold
    /// (`directory_admin::REQUESTS_PER_REQUESTER`, interim while P-78 is
    /// open; docs/questions/Q-940).
    pub requests_per_requester: usize,
    /// How often the admin thread re-registers lost destroy decisions
    /// ([`DESTROY_RECONCILE_INTERVAL`] in every production dird; kept
    /// within [`MIN_DESTROY_RECONCILE_INTERVAL`] ..=
    /// [`MAX_DESTROY_RECONCILE_INTERVAL`]); it also does so once at start
    /// (A-105, crate::reconcile).
    pub destroy_reconcile_interval: Duration,
    /// Where an approved tier-map change is written as `policy.next` for
    /// root to activate (`policy_next_path`, owned by dird's account — task
    /// A16, docs/51 §5.10); `None` ⇒ `ChangePolicy` is answered
    /// `Unavailable` (policy changes are offline only).
    pub policy_next: Option<PolicyNextFile>,
}

/// How often dird re-registers the destroy decisions keyd lost (A-105):
/// every 10 minutes, and once at the admin service's start. A lost decision
/// costs hygiene only — the key sets of a deleted account are unreachable
/// (docs/51 §9) — and `destroy-sweep` runs by hand, so minutes are enough;
/// each run is bounded (crate::reconcile). Project choice
/// (docs/questions/Q-501).
pub const DESTROY_RECONCILE_INTERVAL: Duration = Duration::from_secs(600);

/// The shortest re-registration interval dird accepts (a shorter one is
/// raised to it): the bound on how much of the admin thread the
/// re-registration may take. Project choice (docs/questions/Q-501).
pub const MIN_DESTROY_RECONCILE_INTERVAL: Duration = Duration::from_millis(100);

/// The longest re-registration interval dird accepts (a longer one is
/// lowered to it): a lost decision waits at most a day. Project choice
/// (docs/questions/Q-501).
pub const MAX_DESTROY_RECONCILE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

impl AdminServeParams {
    /// The product admin parameters with the production keyd client — a
    /// fresh `KeydTicketVerifier` over `ipc_keyd::UnixConnector` to the
    /// configured keyd, expecting its uid, Role::Ldap and dird's `realm`
    /// (task R9; A-73), with the keyd channel's 2 s deadline — and the
    /// daemon's constants: [`MAX_ADMIN_CONNECTIONS`],
    /// [`ADMIN_QUEUE_CAPACITY`], [`DecisionAckDeadline::PRODUCTION`],
    /// `directory_admin::REQUEST_LIFETIME`,
    /// `directory_admin::REQUESTS_PER_REQUESTER` and
    /// [`DESTROY_RECONCILE_INTERVAL`] (docs/52 C18, task R15; task D2-c).
    /// Spec: docs/51 §4.6, §5.5, §5.6, §7.1, §7.5; A-73; docs/questions/Q-385,
    /// Q-466 (A-102), Q-501.
    pub(crate) fn production(admin: AdminParams, realm: &Realm) -> AdminServeParams {
        let realm = realm.clone();
        let keyd: Option<VerifierFactory> = admin.keyd.map(|endpoint| {
            let factory: VerifierFactory = Arc::new(move || {
                // Task R9: keyd's uid, the role Ldap and dird's realm,
                // expected of every keyd connection.
                let verifier: Box<dyn TicketVerifier> = Box::new(
                    KeydTicketVerifier::new(
                        ipc_keyd::UnixConnector::new(endpoint.socket.clone()),
                        endpoint.uid,
                        realm.clone(),
                        ipc_keyd::DEFAULT_DEADLINE,
                    )
                    .ok()?,
                );
                Some(verifier)
            });
            factory
        });
        AdminServeParams {
            socket: admin.socket,
            admind_uid: admin.admind_uid,
            keyd,
            ticket_age_max: admin.ticket_age_max,
            quorum: admin.quorum,
            node_id: admin.node_id,
            manifest: admin.manifest,
            max_connections: MAX_ADMIN_CONNECTIONS,
            queue_capacity: ADMIN_QUEUE_CAPACITY,
            ack_deadline: DecisionAckDeadline::PRODUCTION,
            request_lifetime: directory_admin::REQUEST_LIFETIME,
            requests_per_requester: directory_admin::REQUESTS_PER_REQUESTER,
            destroy_reconcile_interval: DESTROY_RECONCILE_INTERVAL,
            // Task A16: configured, passed through.
            policy_next: admin.policy_next,
        }
    }
}

impl fmt::Debug for AdminServeParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminServeParams")
            .field("socket", &self.socket)
            .field("admind_uid", &self.admind_uid)
            .field("keyd", &self.keyd.is_some())
            .field("ticket_age_max", &self.ticket_age_max)
            .field("quorum", &self.quorum)
            .field("max_connections", &self.max_connections)
            .field("queue_capacity", &self.queue_capacity)
            .field("ack_deadline", &self.ack_deadline)
            .field("request_lifetime", &self.request_lifetime)
            .field("requests_per_requester", &self.requests_per_requester)
            .field(
                "destroy_reconcile_interval",
                &self.destroy_reconcile_interval,
            )
            .field("policy_next", &self.policy_next.is_some())
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
/// the manifest's handle — `(objectGUID, AdminService)` (module
/// documentation).
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
/// account and its two service objects (the randomized key sets of the
/// ceremony, docs/51 §4.3 step 11) — each service object's key set derived
/// from its binding's name (`Service` for the LDAP service, `AdminService`
/// for the admin service), the one derivation the KDC uses (docs/52 R2b;
/// docs/questions/Q-493 item 1).
/// Spec: docs/51 §4.3 steps 8, 11, §6; docs/questions/Q-420; docs/47 §1.3.
#[must_use]
pub fn key_targets(manifest: &Manifest) -> KeyTargets {
    let service = |set: &provision_manifest::KeySet| {
        ServiceKeyHandle::of_service(set.handle.principal, &set.binding.name)
    };
    KeyTargets {
        krbtgt: guid_of(&manifest.krbtgt().handle),
        services: BTreeSet::from([
            service(manifest.ldap_service()),
            service(manifest.admin_service()),
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

/// The PEP's operation of the operation a `Propose` carries (task D2-c):
/// a directory write field for field, a `ChangePolicy` in the tier-map
/// vocabulary, a key operation; `None` for anything else (the codec admits
/// only `request_kind::PROPOSABLE`; the PEP refuses a read or an audit-only
/// report itself).
/// Spec: docs/questions/Q-882 item 1; crate directory-admin
/// `ProposedOperation`.
#[must_use]
pub fn proposal_of(operation: &Operation) -> Option<ProposedOperation> {
    match operation {
        Operation::ChangePolicy { changes } => {
            Some(ProposedOperation::Policy(tier_changes(changes)))
        }
        Operation::KeyOperation(operation) => {
            Some(ProposedOperation::Key(pep_key_operation(operation)))
        }
        other => pep_operation(other).map(ProposedOperation::Directory),
    }
}

/// The PEP's step of a request-queue operation, if it is one (task D2-c).
/// Spec: docs/questions/Q-882 item 1; r5-a §11 MA5.
#[must_use]
pub fn step_of(operation: &Operation) -> Option<RequestStep> {
    Some(match operation {
        Operation::Approve { id, digest } => RequestStep::Approve {
            id: *id,
            digest: OperationDigest::new(*digest),
        },
        Operation::Reject { id, digest } => RequestStep::Reject {
            id: *id,
            digest: OperationDigest::new(*digest),
        },
        Operation::Withdraw { id } => RequestStep::Withdraw { id: *id },
        Operation::ListRequests(scope) => RequestStep::List(match scope {
            ListScope::Mine => PepListScope::Mine,
            ListScope::AwaitingMe => PepListScope::AwaitingMe,
        }),
        Operation::ShowRequest { id } => RequestStep::Show { id: *id },
        _ => return None,
    })
}

/// The typed operation of the PEP's (field for field — the inverse of
/// [`pep_operation`]).
/// Spec: docs/51 §7.3; crate directory-admin `Operation`.
fn wire_operation(operation: &PepOperation) -> Operation {
    match operation {
        PepOperation::CreateUser(c) => Operation::CreateUser {
            parent: c.parent,
            sam: c.sam.clone(),
            upn: c.upn.clone(),
            description: c.description.clone(),
        },
        PepOperation::CreateComputer(c) => Operation::CreateComputer {
            parent: c.parent,
            name: c.name.clone(),
            dns_host_name: c.dns_host_name.clone(),
            spn: c.spn.clone(),
        },
        PepOperation::CreateGroup(c) => Operation::CreateGroup {
            parent: c.parent,
            sam: c.sam.clone(),
            group_type: c.group_type,
        },
        PepOperation::CreateOu(c) => Operation::CreateOu {
            parent: c.parent,
            name: c.name.clone(),
        },
        PepOperation::CreateContainer(c) => Operation::CreateContainer {
            parent: c.parent,
            name: c.name.clone(),
        },
        PepOperation::BeginPasswordSet { target } => {
            Operation::BeginPasswordSet { target: *target }
        }
        PepOperation::CompletePasswordSet(c) => Operation::CompletePasswordSet {
            target: c.target,
            outcome: match c.outcome {
                PepOutcome::Completed => PasswordSetOutcome::Completed,
                PepOutcome::Failed => PasswordSetOutcome::Failed,
            },
            kvnos: c.kvnos.clone(),
        },
        PepOperation::SetEnabled(s) => Operation::SetEnabled {
            target: s.target,
            enabled: s.enabled,
        },
        PepOperation::SetAccountExpires(s) => Operation::SetAccountExpires {
            target: s.target,
            value: match s.value.filetime() {
                None => AccountExpires::Never,
                Some(at) => AccountExpires::At(at),
            },
        },
        PepOperation::AddMember(m) => Operation::AddMember {
            group: m.group,
            member: m.member,
        },
        PepOperation::RemoveMember(m) => Operation::RemoveMember {
            group: m.group,
            member: m.member,
        },
        PepOperation::Delete { target } => Operation::Delete { target: *target },
        PepOperation::Lookup(key) => Operation::Lookup(match key {
            PepLookupKey::SamAccountName(sam) => LookupKey::SamAccountName(sam.clone()),
            PepLookupKey::ServicePrincipalName(spn) => LookupKey::ServicePrincipalName(spn.clone()),
            PepLookupKey::Dn(dn) => LookupKey::Dn(dn.rdns().to_vec()),
        }),
    }
}

/// The typed operation of a pending request's own fields — what a
/// `ShowRequest` renders (never requester text: class C44); `None` if a
/// policy change holds a tier the channel cannot carry (cannot happen: it
/// came from the channel).
/// Spec: docs/questions/Q-882 item 1; docs/research/r5-b-cli.md §7.4
/// rule 1.
#[must_use]
pub fn wire_proposed(operation: &ProposedOperation) -> Option<Operation> {
    Some(match operation {
        ProposedOperation::Directory(op) => wire_operation(op),
        ProposedOperation::Policy(changes) => Operation::ChangePolicy {
            changes: policy_changes(changes)?,
        },
        ProposedOperation::Key(op) => Operation::KeyOperation(wire_key_operation(op)),
    })
}

/// The channel's state of the PEP's.
fn wire_state(state: PepState) -> RequestState {
    match state {
        PepState::Pending => RequestState::Pending,
        PepState::Approved => RequestState::Approved,
    }
}

/// The typed reply of a request's state (the answer to `Propose` and
/// `Approve`). A count that cannot be one octet (never: a quorum of at most
/// three) is answered `Unavailable`.
/// Spec: docs/questions/Q-882 item 1.
#[must_use]
pub fn wire_request_view(view: &RequestView) -> Reply {
    match (u8::try_from(view.approvals), u8::try_from(view.quorum)) {
        (Ok(approvals), Ok(quorum)) => Reply::PendingRequest(PendingRequestState {
            id: view.id,
            digest: *view.digest.as_bytes(),
            state: wire_state(view.state),
            approvals,
            quorum,
            expires: view.expires,
        }),
        _ => Reply::Refused(RefusalStatus::Unavailable),
    }
}

/// One `ListRequests` entry; `None` if a count does not fit or the
/// operation has no wire form (neither happens).
fn wire_summary(summary: &PepSummary) -> Option<RequestSummary> {
    let kind = wire_proposed(&summary.operation)?.to_wire().ok()?.kind();
    Some(RequestSummary {
        id: summary.id,
        digest: *summary.digest.as_bytes(),
        state: wire_state(summary.state),
        operation: kind,
        requester: summary.requester,
        approvals: u8::try_from(summary.approvals).ok()?,
        quorum: u8::try_from(summary.quorum).ok()?,
        expires: summary.expires,
    })
}

/// One fact on the channel.
fn wire_fact(fact: &RequestFact) -> Fact {
    Fact {
        guid: fact.guid,
        dn: fact.dn.rdns().to_vec(),
        class: fact.class.to_owned(),
        sid: fact.sid,
        tier: match fact.tier {
            Some(Tier::Tier0) => FactTier::Tier0,
            Some(Tier::Tier1) => FactTier::Tier1,
            Some(Tier::Tier2) => FactTier::Tier2,
            Some(Tier::Untiered) | None => FactTier::Unclassified,
        },
    }
}

/// A `ShowRequest` answer; `None` if a count does not fit or the operation
/// has no wire form (neither happens).
fn wire_detail(detail: &RequestDetail) -> Option<RequestShown> {
    Some(RequestShown {
        id: detail.id,
        digest: *detail.digest.as_bytes(),
        state: wire_state(detail.state),
        requester: detail.requester,
        approvers: detail.approvers.clone(),
        quorum: u8::try_from(detail.quorum).ok()?,
        expires: detail.expires,
        reason_ref: detail.reason_ref.clone(),
        operation: wire_proposed(&detail.operation)?,
        facts: detail.facts.iter().map(wire_fact).collect(),
    })
}

/// The typed reply of a request-queue step. Anything that cannot be
/// rendered (never) is answered `Unavailable`.
/// Spec: docs/questions/Q-882 item 1; r5-a §11 MA5.
#[must_use]
pub fn wire_step_reply(reply: &StepReply) -> Reply {
    let unavailable = Reply::Refused(RefusalStatus::Unavailable);
    match reply {
        StepReply::Request(view) => wire_request_view(view),
        StepReply::Done => Reply::Done,
        StepReply::List(entries) => entries
            .iter()
            .map(wire_summary)
            .collect::<Option<Vec<_>>>()
            .map_or(unavailable, Reply::RequestList),
        StepReply::Shown(detail) => {
            wire_detail(detail).map_or(unavailable, |shown| Reply::RequestShown(Box::new(shown)))
        }
    }
}

/// The PEP's operation of a typed request (field for field; no rule is
/// applied here — the PEP checks every value and audits a refusal); `None`
/// for a request-queue step ([`proposal_of`], [`step_of`]) and a policy
/// change ([`policy_change_of`]).
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
        Operation::ChangePolicy { .. }
        | Operation::KeyOperation(_)
        | Operation::Propose { .. }
        | Operation::Approve { .. }
        | Operation::Reject { .. }
        | Operation::Withdraw { .. }
        | Operation::ListRequests(_)
        | Operation::ShowRequest { .. } => return None,
    })
}

/// The tier-map edit's vocabulary of a typed `ChangePolicy` (task A16), if
/// it is one: each change field for field (`Dn` of its components, the
/// tier by name); no rule is applied here — the one tier-map edit (crate
/// policy-store) checks every value and the PEP audits a refusal.
/// Spec: docs/51 §5.10; crate policy-store `TierChange`; docs/questions/
/// Q-590, Q-592.
#[must_use]
pub fn policy_change_of(operation: &Operation) -> Option<Vec<TierChange>> {
    let Operation::ChangePolicy { changes } = operation else {
        return None;
    };
    Some(tier_changes(changes))
}

/// The tier-map vocabulary of a `ChangePolicy`'s changes (field for field).
/// Spec: docs/51 §5.10; crate policy-store `TierChange`.
fn tier_changes(changes: &[PolicyChange]) -> Vec<TierChange> {
    let tier = |tier: &PolicyTier| match tier {
        PolicyTier::Tier0 => Tier::Tier0,
        PolicyTier::Tier1 => Tier::Tier1,
        PolicyTier::Tier2 => Tier::Tier2,
    };
    changes
        .iter()
        .map(|change| match change {
            PolicyChange::AddPrincipal(sid, t) => TierChange::AddPrincipal(*sid, tier(t)),
            PolicyChange::RemovePrincipal(sid) => TierChange::RemovePrincipal(*sid),
            PolicyChange::AddSubtree(dn, t) => TierChange::AddSubtree(Dn::new(dn.clone()), tier(t)),
            PolicyChange::RemoveSubtree(dn) => TierChange::RemoveSubtree(Dn::new(dn.clone())),
        })
        .collect()
}

/// The channel's changes of a tier-map vocabulary list (the inverse of
/// [`tier_changes`]); `None` for a tier the channel cannot carry
/// (`Untiered` is never a map row, A-36).
/// Spec: docs/51 §5.10; A-36.
fn policy_changes(changes: &[TierChange]) -> Option<Vec<PolicyChange>> {
    let tier = |tier: &Tier| match tier {
        Tier::Tier0 => Some(PolicyTier::Tier0),
        Tier::Tier1 => Some(PolicyTier::Tier1),
        Tier::Tier2 => Some(PolicyTier::Tier2),
        _ => None,
    };
    changes
        .iter()
        .map(|change| {
            Some(match change {
                TierChange::AddPrincipal(sid, t) => PolicyChange::AddPrincipal(*sid, tier(t)?),
                TierChange::RemovePrincipal(sid) => PolicyChange::RemovePrincipal(*sid),
                TierChange::AddSubtree(dn, t) => {
                    PolicyChange::AddSubtree(dn.rdns().to_vec(), tier(t)?)
                }
                TierChange::RemoveSubtree(dn) => PolicyChange::RemoveSubtree(dn.rdns().to_vec()),
            })
        })
        .collect()
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

/// The `SetSecret` decision a committed `BeginPasswordSet` registers in
/// keyd: the account kind and exactly the key targets — handles, bindings
/// **and the salt** — the reply hands admind (task A15a; N4, A-102). `None`
/// for any other reply.
/// Spec: docs/51 §5.2 row 5, §5.8 option (b), §7.3; docs/47 §9.1;
/// docs/questions/Q-450 item 2; docs/52 §4.2 (`SetSecret { kind, targets:
/// [(handle, binding, salt)] }`).
#[must_use]
pub fn secret_decision_of(reply: &PepReply) -> Option<DecidedOperation> {
    let PepReply::PasswordSet(set) = reply else {
        return None;
    };
    let kind = match set.kind {
        PipKind::User => GrantKind::User,
        PipKind::Computer => GrantKind::Computer,
    };
    let salt = set.salt.as_str().to_owned();
    let targets = set
        .keys
        .iter()
        .map(|k| SetSecretTarget {
            handle: k.handle,
            binding: k.binding.clone(),
            salt: salt.clone(),
        })
        .collect();
    Some(DecidedOperation::SetSecret { kind, targets })
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
// Task D2-c: the request queue's bounds on the channel are the PEP's.
const _: () = assert!(
    ipc_dird_admin::channel::MAX_SHOWN_APPROVERS as usize == directory_admin::MAX_QUORUM - 1
);
const _: () = assert!(
    ipc_dird_admin::channel::MAX_LISTED_REQUESTS as usize == directory_admin::MAX_PENDING_REQUESTS
);
const _: () = assert!(ipc_dird_admin::channel::MAX_FACTS as usize == directory_admin::MAX_FACTS);
const _: () = assert!(
    ipc_dird_admin::channel::MAX_REASON_REF as usize == directory_admin::MAX_REASON_REF_CHARS
);
const _: () = assert!(directory_admin::MAX_PENDING_REQUESTS <= u8::MAX as usize);
const _: () = assert!(ipc_dird_admin::channel::RETIRED_APPROVALS == 0);
const _: () = assert!(ipc_dird_admin::channel::MAX_KVNOS as usize == ipc_audit::MAX_REPORTED_KVNOS);
const _: () = assert!(ipc_dird_admin::channel::DIGEST_LEN == directory_admin::DIGEST_LEN);
const _: () = assert!(directory_admin::MAX_QUORUM <= u8::MAX as usize);
// Task A16: every change of a `ChangePolicy` the channel can carry is named
// in its audit events, and the policy file can hold every subtree the
// channel can carry.
const _: () = assert!(
    ipc_dird_admin::channel::MAX_POLICY_CHANGES as usize == directory_admin::MAX_POLICY_CHANGES
);
const _: () = assert!(directory_admin::MAX_POLICY_CHANGES == ipc_audit::MAX_TARGET_NAMES);
const _: () =
    assert!(ipc_dird_admin::channel::MAX_POLICY_DN_COMPONENTS <= policy_store::MAX_DN_COMPONENTS);
const _: () = assert!(ipc_dird_admin::channel::MAX_DN_COMPONENT <= policy_store::MAX_COMPONENT);
const _: () = assert!(ipc_dird_admin::channel::MAX_SID == policy_store::MAX_SID);
