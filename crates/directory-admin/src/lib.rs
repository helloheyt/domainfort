#![forbid(unsafe_code)]
//! `directory-admin`: the admin plane's write PEP (docs/51 §12, task A3) —
//! a library, with no socket, no thread and no clock.
//!
//! # The two phases (A-85: decision acknowledged ⇒ commit ⇒ outcome)
//!
//! dird's admin service (task A8) verifies every AP-REQ of a request
//! through keyd (`open_and_verify_service_ticket`, Role::Ldap — A-73) and
//! then:
//!
//! 1. calls [`DirectoryAdmin::prepare`] with the verified tickets, ONE
//!    [`directory_pip::DirectoryView`] (taken after it began its
//!    `WriteTxn`, for a write) and the policy snapshot of the same version.
//!    `prepare` builds the requester's Subject from the directory
//!    ([`AdminSubject::from_verified_ticket`]), runs `decide`, the semantic
//!    checks of docs/51 §11, the self-lockout guard and the dual-control
//!    classification — consuming, when the operation needs an approver, the
//!    approved pending request held for it ([`PendingRequests`]) — and
//!    returns a [`Prepared`] carrying the `Decision` event — or a
//!    [`Refusal`] whose event records why;
//! 2. sends the decision event and waits for auditd's acknowledgement
//!    (auditd unavailable ⇒ the operation is refused before the commit,
//!    docs/51 §5.7 item 2);
//! 3. calls [`DirectoryAdmin::apply`] inside the `WriteTxn`: GUID from the
//!    CSPRNG, RID and change-seq from the counters, the security descriptor
//!    of the new object, the write; `apply` re-verifies what could have
//!    changed (module `apply`);
//! 4. commits, and sends the `Outcome` event ([`Applied::outcome_event`]);
//!    on any `apply` error it aborts the transaction and sends the
//!    refusal's event instead.
//!
//! `Lookup` and `CompletePasswordSet` commit nothing: their decision event
//! is the only one, and their reply is [`Prepared::reply`].
//!
//! # One dual-control mechanism (task D2-c; docs/questions/Q-882, A-148)
//!
//! Every dual-controlled operation — a directory write whose rule needs an
//! approver (P-22), a `ChangePolicy`, a key operation — goes through a
//! pending request dird holds in memory ([`PendingRequests`], module
//! `requests`): [`DirectoryAdmin::propose`] (the operation's checks as a dry
//! run; its exact fields and its operation digest held), then
//! [`DirectoryAdmin::step`] — `Approve {id, digest}` (everything the
//! request was judged on evaluated again — class C43), `Reject`,
//! `Withdraw`, `ListRequests`, `ShowRequest` (r5-a MA5). At the quorum a
//! directory or policy operation is executed by its requester (`prepare` /
//! `prepare_policy_change` consume the approved request); a key
//! operation's `Approve` yields the [`KeyDecision`] dird registers in keyd
//! (A-102, docs/52 §4.3) — as a [`QuorumStep`], whose `Decision` event
//! auditd must acknowledge first (an `ipc_audit_client::AckedIntent<QuorumStep>`,
//! docs/52 R6). The in-request approvals of docs/51 §7.2 and the key-only
//! `RequestKeyOperation` / `Approve` (task A10) have no code path.
//! [`DirectoryAdmin::destruction_target`] and
//! [`DirectoryAdmin::destruction_targets`] name the key sets a committed
//! `Delete` leaves to destroy, as [`TombstonedPrincipal`]s — the only input
//! of a destroy decision (module `key_requests`; docs/51 §5.6, §6; A-105).
//!
//! # `PolicyAdmin` online (task A16; docs/51 §5.10, R51-21; A-80)
//!
//! [`DirectoryAdmin::prepare_policy_change`] decides a `ChangePolicy`
//! request — a tier-map edit in the vocabulary of `provision policy` — with
//! the PEP's own `authorize` (`PolicyAdmin` on the scope
//! [`POLICY_CHANGE_SCOPE`]) and the one dual-control mechanism, always
//! required (an approved pending request for exactly these changes);
//! refuses while a `policy.next` waits for root ([`PendingPolicy`]); and
//! builds the candidate with crate policy-store's one tier-map edit (the
//! next version), decoded again by the format's own decoder before anything
//! is written. The candidate leaves [`PreparedPolicyChange`] only as a
//! [`PolicyCandidate`], made from the `ipc_audit_client::AckedIntent` of its
//! decision event (module `policy_change`; docs/questions/Q-590..Q-593).
//!
//! # The proof of an acknowledged decision (docs/52 §3.11 R6, A-102)
//!
//! [`Prepared`] is not `Clone` and is its own `ipc_audit_client::IntentRecord`
//! (its `Decision` event); [`DirectoryAdmin::apply`] takes it only as an
//! `ipc_audit_client::AckedIntent<Prepared>`, which only the caller's
//! `ipc_audit_client::AuditGate` produces after auditd acknowledged that event. The
//! "decision acknowledged ⇒ commit" rule of A-85 is a type, not a comment.
//!
//! # The operations (docs/51 §5.2, §7.3)
//!
//! | operation | PDP Action on Resource | dual control (P-22) |
//! |---|---|---|
//! | `CreateUser` / `CreateComputer` / `CreateGroup` / `CreateOu` / `CreateContainer` | `DirAddChild(class)` on the parent | parent inside a tier-map subtree that is Tier0 |
//! | `BeginPasswordSet` | `DirControlRight(User-Force-Change-Password)` on the account | account explicitly Tier0 |
//! | `CompletePasswordSet` | the same (audit only) | never |
//! | `SetEnabled` | `DirWrite(userAccountControl)` | account explicitly Tier0 |
//! | `SetAccountExpires` | `DirWrite(accountExpires)` | account explicitly Tier0 |
//! | `AddMember` / `RemoveMember` | `DirWrite(member)` on the group | group explicitly Tier0 |
//! | `Delete` | `DirDelete` on the object | object explicitly Tier0 |
//! | `Lookup` | `DirRead` on the object | never |
//! | `ChangePassword` (kpasswd, task K6) | `DirControlRight(User-Change-Password)` on the requester's own account | account explicitly Tier0 ⇒ refused (no approver on kpasswd) |
//!
//! Before any of these, every object the request names must be visible to
//! the requester through `directory_pip::VisibilityGate`, rule
//! `ListAndRead`: `DirList` on its parent ([MS-ADTS] 5.1.3.3.6, the LDAP
//! search's rule) and `DirRead` on the object; otherwise it is answered
//! exactly like an absent object (A-55; docs/52 R10; docs/questions/Q-485).
//!
//! "Explicitly Tier0" = classified Tier0 by a tier-map subtree, a tier-map
//! entry of its SID or groups, or a structural rule (NC root, krbtgt, DC
//! account) — not merely unclassified (A-36 makes unclassified Tier0 for
//! writes; P-22: such a write needs no approver).
//!
//! # Provenance
//!
//! Written only from, opened in this session: docs/51 (whole; decided
//! A-72), docs/47 (§1.3, §3, §4, §5, §6, §9), docs/46 (§2.3, §4, §5, §8),
//! docs/11 (§2, §4), docs/32 (§6, §7), AGENT-ONBOARDING, AGENTS, the
//! decisions A-18, A-19, A-35, A-55, A-72..A-79, A-83..A-85, P-22 and the
//! questions Q-290, Q-292..Q-295, Q-298, Q-330, Q-335, Q-336; the pinned
//! specifications from `tools/spec-pin/cache/` (SHA-256 verified against
//! `tools/spec-pin/manifest.json`): [MS-SAMR] v20260427 (083fe00a…8a4e)
//! 2.2.1.14, 3.1.1.6, 3.1.1.7.2, 3.1.1.8.1, 3.1.1.8.4, 3.1.1.8.9,
//! 3.1.1.8.10, 3.1.1.9.2, 3.1.1.9.2.1, 3.1.1.9.2.2; [MS-ADTS] v20261026
//! (55b59eb1…b2b1) 3.1.1.5.2.4, 6.1.1.2.7.53, 6.1.3, 6.1.3.1, 6.1.3.7,
//! 6.1.3.8; [MS-DTYP] v20241119 (0f4a3744…83b3) 2.3.4.2, 2.4.2.2,
//! 2.4.2.4, 2.4.4.1, 2.4.4.2, 2.4.6; [MS-KILE] v20260928 (8d172e6f…7a01)
//! 3.1.1.2; RFC 4120 (368d3cd1…f75b) §5.5.1 (`cksum`), §6.2, §6.2.1, §7.3.
//! The
//! public APIs of this workspace's crates dirstore, ad-schema, dtyp, pdp,
//! directory-pip, kdc, keyd-types, krb-proto, ipc-audit and keyd (its
//! entropy source, as the pattern A-15 names) were read. No other
//! implementation was consulted or recalled (AGENTS.md §1-3).
//!
//! The closure-size refusal of `AddMember` (the A-89 residual, task F5)
//! was written only from docs/47 §5.3, PENDING-OWNER A-89, docs/questions
//! Q-356 and Q-357, and this repository's crate directory-pip
//! (`MAX_EXPANDED_GROUPS`, `groups.rs`).
//!
//! # One checker for every write path (docs/52 R13, A-102)
//!
//! Module `invariants` holds the rules every directory write must keep —
//! the [MS-SAMR] constraints and name rules (A-79), the membership rules,
//! the cycle refusal and the expansion bounds (A-89, A-95) — and the only
//! code in the workspace that calls dirstore's mutating API: `apply`
//! commits a `CheckedWrite` of it, and `provision domain` writes the new
//! domain through its [`Provisioning`] session, the one place the named
//! provisioning exceptions (NC root, krbtgt, DC account, service objects)
//! exist. Pinned by `tests/single_write_path.rs`. Written only from
//! docs/52 (§3.14, §7), docs/51 (§4.3, §11), docs/46 (§4-§5, §8), docs/47
//! (§5.3), the decisions A-79, A-83, A-89, A-92, A-95, A-102, the questions
//! Q-298, Q-355..Q-358, Q-376, Q-416, the pinned [MS-SAMR] v20260427
//! (083fe00a…8a4e) 2.2.1.14, 3.1.1.6, 3.1.1.8.9, 3.1.1.9.2 and this
//! repository's code; interpretations in docs/questions/Q-505..Q-507.
//!
//! The shared gate, the proof of an acknowledged intent and the one stop
//! flush (task R6, decision A-102) were written only from docs/52 (§2,
//! §3.10, §3.11, §4.3, §7 R6), docs/50 §3.6 / §8.1, docs/51 §5.7,
//! PENDING-OWNER (A-85, A-87, A-88, A-93, A-102, A-105), docs/questions
//! Q-313, Q-350, Q-365, Q-470, Q-471 and this repository's own code
//! (docs/questions/Q-500..Q-503). No other implementation was consulted
//! or recalled (AGENTS.md §1-3).
//!
//! Interpretations and gaps: docs/questions/Q-355 (names and values),
//! Q-356 (membership and protected objects), Q-357 (dual control and the
//! self-lockout guard), Q-358 (two-phase contract and re-verification),
//! Q-416 (the closure-size refusal).
//!
//! The one dual-control mechanism (task D2-c) was written only from, opened
//! in this session: docs/research/r5-b-cli.md (§6, §7, §12-§15),
//! docs/research/r5-a-admin-model.md (§5, §8.2, §11 MA5), docs/questions
//! Q-882, Q-888, Q-887, Q-878, Q-874, docs/51 (§5.5-§5.7, §7), docs/52
//! (§2 classes C14, C43, C44, C46, C47; §3.11), PENDING-OWNER (A-102,
//! A-108, A-110, A-111, A-120, A-146..A-148, P-22, P-30, P-78) and this
//! repository's own code; interpretations in docs/questions/Q-935..Q-941.
//! No other implementation was consulted or recalled (AGENTS.md §1-3).
//!
//! # Plan → Commit (tasks MA2 + MA3; docs/research/r5-a-admin-model.md
//! §3.3, §11; PENDING-OWNER A-147)
//!
//! An operation that requires an effect plan (`Operation::requires_plan`,
//! `ProposedOperation::requires_plan` — membership changes, an account's
//! enable / expiry / delete / password set, the policy change, the key
//! operations; docs/questions/Q-982) is first planned —
//! [`DirectoryAdmin::plan`]: its every check as a dry run, then its effect
//! plan built by module `effects` from that evaluation over directory-pip's
//! enforcing functions — and then executed or proposed only with the digest
//! of that plan (`Request::plan`, `ProposeRequest::plan`,
//! `PolicyChangeRequest::plan`), which is inside the operation digest the
//! AP-REQs bind. The plan is recomputed at every `Propose`, `Approve` and
//! execution; any difference refuses (`PlanChanged`); a principal the
//! requester or approver may not see refuses (`PlanNotVisible`); a closure
//! too large to show refuses (`PlanTooLarge`). Class C46 ("the approved
//! effect is smaller than the executed one") has no path left
//! (docs/questions/Q-980..Q-984).
//!
//! Written only from, opened in this session: docs/research/
//! r5-a-admin-model.md (whole), docs/questions/Q-874, Q-117, Q-935..Q-941,
//! PENDING-OWNER (A-36, A-102, A-108, A-147, A-159), docs/52 (C14, C43, C46,
//! C47), docs/51 §5-§7, docs/57 and this repository's own code. No other
//! implementation was consulted or recalled (AGENTS.md §1-3).
//!
//! `ChangePassword` (task K6, module `change_password`) was written only
//! from, opened in this session: docs/53 (whole), PENDING-OWNER (A-117,
//! A-121, A-126, A-142, A-151, A-153, A-156, A-158, A-159), docs/questions
//! Q-600..Q-609, Q-660..Q-664, Q-945, Q-955, docs/research/r3-e (§1-§3), the
//! pinned RFC 3244 §2, RFC 4120 §3.2.3 and [MS-ADTS] v20261026
//! 3.1.1.3.1.5.1, 6.1.1.2.7.52, and this repository's own code;
//! interpretations in docs/questions/Q-963. No other implementation was
//! consulted or recalled (AGENTS.md §1-3).

mod admin;
mod apply;
mod audit;
mod change_password;
mod checks;
mod config;
mod descriptor;
mod effects;
mod ids;
mod invariants;
mod key_requests;
mod names;
mod operation;
mod policy_change;
mod random;
mod record;
mod reply;
mod requests;
mod subject;
mod time;

pub use admin::{
    DirectoryAdmin, Prepared, Request, VerificationFailure, ACCOUNT_EXPIRES_NEVER,
    USER_FORCE_CHANGE_PASSWORD,
};
pub use apply::Applied;
pub use audit::{Refusal, RefusalStatus};
// A user's change of its own password through kpasswd (task K6; docs/53
// §4.4, §5.6 step 4): the one write path, User-Change-Password on itself.
pub use change_password::{
    change_password_result, ChangePasswordRequest, ChangePasswordTicket, NO_OPERATION_DIGEST,
    USER_CHANGE_PASSWORD,
};
pub use config::{
    AdminConfig, ConfigError, ProtectedObjects, CHANGE_SEQ_COUNTER, CHANGE_SEQ_END_EXCLUSIVE,
    CHANGE_SEQ_FIRST, MAX_QUORUM, MIN_QUORUM, RID_COUNTER, RID_END_EXCLUSIVE, RID_FIRST,
};
pub use descriptor::{new_object_descriptor, DescriptorError};
// The write invariants' provisioning session (docs/52 R13): the only way
// `provision domain` writes the new domain, and the only place the named
// provisioning exceptions exist.
pub use invariants::{InvariantViolation, Provisioning, ProvisioningError, ProvisioningRole};
// Key operations (task A10, docs/51 §5.6, §6): their key sets, the decision
// registered in keyd, the tombstones to destroy.
pub use key_requests::{
    DestructionTargets, KeyDecision, KeyOperation, KeyRef, KeyTargets, RegistrationOutcome,
    TombstonedPrincipal, KEY_POLICY_SCOPE,
};
// The one dual-control mechanism (task D2-c; docs/questions/Q-882).
pub use requests::{
    ApproverSignature, ListScope, PendingRequests, PlanRequest, Planned, PolicyFile,
    ProposeRequest, Proposed, ProposedOperation, QuorumStep, RequestDetail, RequestFact,
    RequestState, RequestStep, RequestSummary, RequestView, RevocationFailure, RevocationStep,
    StepReply, StepRequest, Stepped, MAX_FACTS, MAX_PENDING_REQUESTS, MAX_REASON_REF_CHARS,
    MAX_REQUESTS_PER_REQUESTER, MAX_REQUEST_LIFETIME, REQUESTS_PER_REQUESTER, REQUEST_LIFETIME,
};

/// Octets of an operation digest (SHA-256). Spec: FIPS 180-4 §6.2; crate
/// ipc-dird-admin `DIGEST_LEN` (pinned in crates/directory-daemon).
pub const DIGEST_LEN: usize = 32;
// The name and value rules, public for `provision domain` (task A4), which
// must apply exactly these rules to the names it is given (A-79).
pub use names::{
    admin_service_spn_ok, computer_name_ok, computer_sam, dns_host_name_ok, group_sam_ok,
    rdn_value_ok, spn_ok, user_sam_ok, MAX_ACCOUNT_SAM_CHARS, MAX_DESCRIPTION_UNITS,
    MAX_DNS_HOST_NAME_CHARS, MAX_GROUP_SAM_CHARS, MAX_PRINCIPAL_NAME_CHARS, MAX_RDN_VALUE_CHARS,
};
pub use operation::{
    CompletePasswordSet, CreateComputer, CreateContainerLike, CreateGroup, CreateUser, LookupKey,
    Membership, Operation, PasswordSetOutcome, SetAccountExpires, SetEnabled,
};
// `PolicyAdmin` online (task A16, docs/51 §5.10): the decided tier-map change
// and the candidate `policy.next`, released only by auditd's acknowledgement.
pub use policy_change::{
    PendingPolicy, PolicyCandidate, PolicyChangeRequest, PreparedPolicyChange, MAX_POLICY_CHANGES,
    POLICY_CHANGE_SCOPE,
};
pub use random::{OsRandom, RandomError, RandomSource};
pub use reply::{KeyTarget, LookupResult, PasswordChangeTarget, PasswordSetReply, Reply};
pub use subject::{AdminSubject, SubjectError, VerifiedTicket};
pub use time::{filetime, wall_clock};
