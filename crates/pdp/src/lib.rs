#![forbid(unsafe_code)]
//! `pdp`: the central Policy Decision Point — every access decision of the
//! domain controller goes through [`decide`].
//!
//! # What it is
//!
//! A pure library implementing docs/11-pdp-interface.md (conceptual model in
//! docs/06, principles in docs/05 and docs/25 §5.1):
//!
//! - the request / decision model of docs/11 §1 and §1b ([`model`]);
//! - the rule model of docs/11 §3 and the versioned [`PolicySnapshot`]
//!   ([`policy`]) — explicit Deny wins, no matching Allow ⇒ Deny;
//! - [`decide`], exactly the five layers of docs/11 §4 — authn, transport
//!   floor (`required_sec`, on every transport alike — [`required_sec_on`];
//!   the `LocalIpc` exemption of A-74 was removed by R2, A-102), coarse
//!   global rules, the Tier-0
//!   write invariant *before* the ACL, then the object ACL and the attribute
//!   class — each deny-by-default, an explicit Deny at any layer stopping
//!   immediately;
//! - [`acl_grants`] (docs/11 §5), the [MS-DTYP] 2.5.3.2 access check over
//!   `dtyp` types combined with the [MS-ADTS] 5.1.3.3.x directory-object
//!   rules (object-type GUIDs, property sets and properties, control access
//!   rights), fail closed where the two texts differ ([`access_check`]);
//! - the [`Pip`] trait of docs/11 §6 — any PIP failure or absence ⇒ Deny
//!   (D40);
//! - [`decide_visibility`] of docs/11 §7 — search results are filtered,
//!   never refused with an error.
//!
//! # LDAP extensions (docs/49 §5.2, R49-10; Q-164 items 1-3, A-48)
//!
//! - [`Resource::RootDse`] / [`ResourceMatch::RootDse`]: the rootDSE is not
//!   a directory object ([MS-ADTS] 3.1.1.3); only `DirRead` is well formed
//!   on it, and it has no layer 5. A directory object never has the empty
//!   DN.
//! - A rule's DN subtree is a [`SubtreeBase`], never empty — the empty base
//!   matched every object (a bug found in merged code, Q-164 item 2).
//! - An [`AnonymousGrant`] names the source network it admits, which can
//!   only be the internal one (docs/15 §6; A-51, Q-170 item 3: External is
//!   forbidden), and never every resource; these refusals are
//!   [`RuleError`]s at construction.
//! - Reading nTSecurityDescriptor asks the rights of [MS-ADTS] 3.1.1.4.4
//!   (ACCESS_SYSTEM_SECURITY and RIGHT_READ_CONTROL), which a `Subject`
//!   without privileges never holds (a bug found in merged code, A-48).
//!
//! Each of these only narrows: a decision that changes goes from Allow to
//! Deny, and the new resource changes no other decision (`tests/properties.rs`,
//! section "LDAP extensions: never widen"; `tests/ldap_extensions.rs`).
//!
//! # Project rules stricter than the specifications (docs/11 §5, D37)
//!
//! Each is a deliberate deviation, marked `DELIBERATE` at its `// Spec:`
//! comment:
//!
//! - 5a — an absent DACL ⇒ DENY ([MS-DTYP] 2.5.3.2 and [MS-ADTS] 5.1.3.3.1
//!   grant all access); an empty DACL ⇒ deny (as the specs say — only the
//!   owner's implied right remains);
//! - owner implicit rights (A-21, Q-050) — READ_CONTROL only: never
//!   WRITE_DAC (the BlockOwnerImplicitRights mode of [MS-ADTS] 5.1.3.3.1 /
//!   6.1.3.4, hard-wired for every requester) and never WRITE_OWNER;
//! - 5b — any `Ace::Unsupported` (callback, conditional, mandatory label,
//!   resource attribute, scoped policy, alarm, ...) or other non-access ACE
//!   in the DACL ⇒ DENY the request, instead of evaluating or skipping it;
//! - 5c — attribute class Secret ⇒ Deny (`NoSuchPath`, unreachable — P6);
//!   Sensitive ⇒ also requires its control access right;
//! - 5d — Tier-0 objects are writable only by Tier-0 subjects, checked in
//!   layer 4, before and independently of the ACL (P5).
//!
//! # Guarantees (docs/11 §10)
//!
//! Deterministic and total: no clock reads (only `Context.time`, P9), no
//! randomness, no global state; never panics; every internal error ⇒ Deny
//! (P1, D40); every decision carries exactly one `Audit` obligation (P7);
//! reason codes are internal, for audit only (docs/11 §1b, §8).
//!
//! # Out of scope
//!
//! - The decision / group-expansion cache and its invalidation (docs/11 §9,
//!   D41): this core is stateless; a caching layer is future work.
//! - MAXIMUM_ALLOWED mode, privileges, mandatory integrity ([MS-DTYP]
//!   2.5.3.3, optional per 2.5.2), central access policies ([MS-DTYP]
//!   2.5.3.1.4 — none configured), validated writes ([MS-ADTS] 5.1.3.3.5),
//!   "List Object" mode ([MS-ADTS] 5.1.3.3.6), and the "RIGHT_DS_DELETE_CHILD
//!   on the parent" alternative for deletes ([MS-ADTS] 3.1.1.5.5.4). Each
//!   omission can only remove grants, never add them.
//!
//! # Mandatory FAST (D126) — in the rule language, not in `decide`
//!
//! `decide` never reads `AuthContext.armored` itself. A rule can require it:
//! [`Match`]`.auth` ([`AuthMatch`]) on the Allow side, and the negated
//! subject predicate [`SubjectMatch::NotMemberOf`] for an explicit Deny,
//! which takes effect in Deny rules only ([`Rule::applies`]). The default
//! rule set of the Q-127 interim decision (owner item P-10) is
//! [`mandatory_fast_rules`] — policy data, with the bootstrap-allowed group
//! SID supplied by the caller (docs/48 §7). Beside it,
//! [`change_password_as_rules`] (task K5) denies the AS for the
//! change-password service ([`KerbResKind::ChangePassword`]) when unarmored
//! and to the computer group — policy data too (docs/53 §5.2; A-142).
//!
//! # Provenance
//!
//! Written only from, opened in this session:
//! - [MS-DTYP] v20241119 (protocol revision 42.0; pinned PDF sha256
//!   0f4a3744…83b3): 2.3.4, 2.3.9, 2.4.2.4, 2.4.3, 2.4.4.1, 2.4.4.3,
//!   2.4.4.5, 2.4.5, 2.4.6, 2.5.2, 2.5.3, 2.5.3.1.1, 2.5.3.1.3, 2.5.3.1.4,
//!   2.5.3.2;
//! - [MS-ADTS] v20261026 (protocol revision 70.0; pinned PDF sha256
//!   55b59eb1…b2b1): 3.1.1.2.3.3, 3.1.1.2.4.3, 3.1.1.3 (introduction: the
//!   rootDSE), 3.1.1.3.2 (introduction: rootDSE attributes read-only, not in
//!   the schema), 3.1.1.3.4.1.11 (SD_FLAGS: the default covers every part),
//!   3.1.1.4.1-3.1.1.4.4, 3.1.1.5.2.1, 3.1.1.5.5.4, 5.1.3, 5.1.3.1, 5.1.3.2,
//!   5.1.3.2.1, 5.1.3.2.2, 5.1.3.3, 5.1.3.3.1-5.1.3.3.6, 6.1.3, 6.1.3.4,
//!   6.1.1.2.4.1.2 (BlockOwnerImplicitRights row), 6.1.1.2.6.18;
//! - [MS-ADA1] v20180912 (pinned PDF sha256 3885c568…6a50): 2.185
//!   (dNSHostName: schemaIdGuid = attributeSecurityGuid, Q-081);
//! - [MS-ADA3] v20180912 (pinned PDF sha256 f8eca4bf…5a49): 2.37
//!   (nTSecurityDescriptor: schemaIdGuid);
//! - this project's docs/05, docs/06, docs/11, docs/15 §6, docs/25 §5.1,
//!   docs/45 §5-7, docs/48 §4.2, §7 (and its closing decision), docs/49 §5.2,
//!   §6.5, §12 (L2) and its closing decision, docs/questions/Q-127 (interim
//!   decision, owner item P-10), Q-164 (A-48), A-31 (GUID string form);
//! - for the change-password AS rules (task K5): docs/53 R53-1, R53-6, §5.2;
//!   PENDING-OWNER A-117, A-139, A-142; RFC 3244 (pinned copy, sha256
//!   45b9130f…c378) §2 (the service principal `kadmin/changepw`).
//!
//! No other implementation was consulted or recalled (docs/CLEAN-ROOM.md).
//! Spec gaps, conflicts and design decisions: docs/questions/Q-050 (resolved,
//! A-21), Q-051 (deferred: owner item P-8 + lab recording), Q-052 (resolved,
//! A-22), Q-081 (resolved, A-28: the object type tree's class and duplicate
//! GUIDs — see [`access_check`]), Q-127 (deferred: owner item P-10; built
//! per the interim decision), Q-130 (open: the mandatory-FAST rule-language
//! interpretations and the bootstrap SID), Q-164 (resolved, A-48: items 1-3
//! built here), Q-170 (open: the interpretations of that build).

pub mod access_check;
pub mod change_password;
mod decide;
pub mod mandatory_fast;
pub mod model;
pub mod pip;
pub mod policy;
mod visibility;

pub use access_check::{acl_grants, dacl_preconditions, DaclRefusal, DirObjectContext, Right};
pub use change_password::{change_password_as_rules, CHANGE_PASSWORD_AS_RULE_COUNT};
pub use decide::{decide, is_write, required_sec, required_sec_on};
pub use mandatory_fast::{mandatory_fast_rules, MANDATORY_FAST_RULE_COUNT};
pub use model::{
    AccessRequest, Action, ActionClass, AttrId, AuthContext, AuthStrength, ClaimId, ClaimValue,
    Constraint, Context, ControlRightId, Decision, Dn, Effect, FilePath, Instant, IpScope,
    KerbResKind, ObjClass, ObjClassChain, Obligation, PolicyScope, PrincipalId, PropertySet,
    ReasonCode, RecordKey, Resource, RlKey, RuleId, ShareId, Spn, Subject, Tier, Transport,
    TransportSec, Uuid, ZoneId,
};
pub use pip::{AttrClass, Pip, PipError};
pub use policy::{
    ActionMatch, AnonymousGrant, AuthMatch, ContextMatch, Match, PolicySnapshot, PolicyVersion,
    ResourceMatch, Rule, RuleError, SubjectMatch, SubtreeBase, TimeWindow,
};
pub use visibility::{decide_visibility, DirObjectRef, Visible};
