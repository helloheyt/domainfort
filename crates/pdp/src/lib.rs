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
//!   floor (`required_sec`), coarse global rules, the Tier-0 write invariant
//!   *before* the ACL, then the object ACL and the attribute class — each
//!   deny-by-default, an explicit Deny at any layer stopping immediately;
//! - [`acl_grants`] (docs/11 §5), the [MS-DTYP] 2.5.3.2 access check over
//!   `dtyp` types combined with the [MS-ADTS] 5.1.3.3.x directory-object
//!   rules (object-type GUIDs, property sets and properties, control access
//!   rights), fail closed where the two texts differ ([`access_check`]);
//! - the [`Pip`] trait of docs/11 §6 — any PIP failure or absence ⇒ Deny
//!   (D40);
//! - [`decide_visibility`] of docs/11 §7 — search results are filtered,
//!   never refused with an error.
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
//! - FAST as a mandatory input for KDC actions (D126, docs/30 §5): a
//!   follow-up; `AuthContext.armored` is carried but not yet required.
//!
//! # Provenance
//!
//! Written only from, opened in this session:
//! - [MS-DTYP] v20241119 (protocol revision 42.0; pinned PDF sha256
//!   0f4a3744…83b3): 2.3.4, 2.3.9, 2.4.2.4, 2.4.3, 2.4.4.1, 2.4.4.3,
//!   2.4.4.5, 2.4.5, 2.4.6, 2.5.2, 2.5.3, 2.5.3.1.1, 2.5.3.1.3, 2.5.3.1.4,
//!   2.5.3.2;
//! - [MS-ADTS] v20261026 (protocol revision 70.0; pinned PDF sha256
//!   55b59eb1…b2b1): 3.1.1.2.3.3, 3.1.1.2.4.3, 3.1.1.4.3, 3.1.1.4.4,
//!   3.1.1.5.2.1, 3.1.1.5.5.4, 5.1.3, 5.1.3.1, 5.1.3.2, 5.1.3.2.1, 5.1.3.2.2,
//!   5.1.3.3, 5.1.3.3.1-5.1.3.3.6, 6.1.3, 6.1.3.4, 6.1.1.2.4.1.2
//!   (BlockOwnerImplicitRights row), 6.1.1.2.6.18;
//! - [MS-ADA1] v20180912 (pinned PDF sha256 3885c568…6a50): 2.185
//!   (dNSHostName: schemaIdGuid = attributeSecurityGuid, Q-081);
//! - this project's docs/05, docs/06, docs/11, docs/25 §5.1, docs/45 §5-7.
//!
//! No other implementation was consulted or recalled (AGENTS.md §1-3).
//! Spec gaps, conflicts and design decisions: docs/questions/Q-050 (resolved,
//! A-21), Q-051 (deferred: owner item P-8 + lab recording), Q-052 (resolved,
//! A-22), Q-081 (resolved, A-28: the object type tree's class and duplicate
//! GUIDs — see [`access_check`]).

pub mod access_check;
mod decide;
pub mod model;
pub mod pip;
pub mod policy;
mod visibility;

pub use access_check::{acl_grants, dacl_preconditions, DaclRefusal, DirObjectContext, Right};
pub use decide::{decide, is_write, required_sec};
pub use model::{
    AccessRequest, Action, ActionClass, AttrId, AuthContext, AuthStrength, ClaimId, ClaimValue,
    Constraint, Context, ControlRightId, Decision, Dn, Effect, FilePath, Instant, IpScope,
    KerbResKind, ObjClass, ObjClassChain, Obligation, PolicyScope, PrincipalId, PropertySet,
    ReasonCode, RecordKey, Resource, RlKey, RuleId, ShareId, Spn, Subject, Tier, Transport,
    TransportSec, Uuid, ZoneId,
};
pub use pip::{AttrClass, Pip, PipError};
pub use policy::{
    ActionMatch, AnonymousGrant, ContextMatch, Match, PolicySnapshot, PolicyVersion, ResourceMatch,
    Rule, SubjectMatch, TimeWindow,
};
pub use visibility::{decide_visibility, DirObjectRef, Visible};
