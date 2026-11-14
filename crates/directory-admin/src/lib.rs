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
//!    ([`AdminSubject::from_verified_ticket`]), runs `decide`, the
//!    dual-control classification and the approvers' checks, the semantic
//!    checks of docs/51 §11 and the self-lockout guard, and returns a
//!    [`Prepared`] carrying the `Decision` event — or a [`Refusal`] whose
//!    event records why;
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
//! # Dual-controlled key operations (task A10)
//!
//! [`DirectoryAdmin::key_step`] serves `RequestKeyOperation`, `Approve`,
//! `FetchApproved`, `Complete` and `ListPendingDestruction` over the
//! pending requests dird holds in memory ([`KeyRequests`]): `PolicyAdmin`
//! on the policy scope `keys` for the requester and every approver, the
//! approval bound to the request's operation digest, one fetch per approved
//! request (module `key_requests`; docs/51 §5.6, §6).
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
//! Interpretations and gaps: docs/questions/Q-355 (names and values),
//! Q-356 (membership and protected objects), Q-357 (dual control and the
//! self-lockout guard), Q-358 (two-phase contract and re-verification),
//! Q-416 (the closure-size refusal).

mod admin;
mod apply;
mod audit;
mod checks;
mod config;
mod descriptor;
mod ids;
mod key_requests;
mod names;
mod operation;
mod random;
mod record;
mod reply;
mod subject;
mod time;

pub use admin::{
    DirectoryAdmin, Prepared, Request, VerificationFailure, ACCOUNT_EXPIRES_NEVER,
    USER_FORCE_CHANGE_PASSWORD,
};
pub use apply::Applied;
pub use audit::{Refusal, RefusalStatus};
pub use config::{
    AdminConfig, ConfigError, ProtectedObjects, CHANGE_SEQ_COUNTER, MAX_QUORUM, MIN_QUORUM,
    RID_COUNTER, RID_END_EXCLUSIVE, RID_FIRST,
};
pub use descriptor::{new_object_descriptor, DescriptorError};
// Dual-controlled key operations (task A10, docs/51 §5.6, §6).
pub use key_requests::{
    operation_digest, ApprovedKeyOperation, DestructionEntry, DestructionPage, KeyAdminOperation,
    KeyOperation, KeyOperationOutcome, KeyRef, KeyReply, KeyRequestView, KeyRequests, KeyStep,
    KeyTargets, DIGEST_LEN, KEY_POLICY_SCOPE, KEY_REQUEST_LIFETIME, MAX_DESTRUCTION_PAGE,
    MAX_KEY_REQUEST_LIFETIME, MAX_PENDING_KEY_REQUESTS,
};
// The name and value rules, public for `provision domain` (task A4), which
// must apply exactly these rules to the names it is given (A-79).
pub use names::{
    computer_name_ok, computer_sam, dns_host_name_ok, group_sam_ok, rdn_value_ok, spn_ok,
    user_sam_ok, MAX_ACCOUNT_SAM_CHARS, MAX_DESCRIPTION_UNITS, MAX_DNS_HOST_NAME_CHARS,
    MAX_GROUP_SAM_CHARS, MAX_PRINCIPAL_NAME_CHARS, MAX_RDN_VALUE_CHARS,
};
pub use operation::{
    CompletePasswordSet, CreateComputer, CreateContainerLike, CreateGroup, CreateUser, LookupKey,
    Membership, Operation, PasswordSetOutcome, SetAccountExpires, SetEnabled,
};
pub use random::{OsRandom, RandomError, RandomSource};
pub use reply::{KeyTarget, LookupResult, PasswordSetReply, Reply};
pub use subject::{AdminSubject, SubjectError, VerifiedTicket};
pub use time::{filetime, wall_clock};
