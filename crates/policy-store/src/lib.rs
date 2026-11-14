#![forbid(unsafe_code)]
//! `policy-store`: the policy file dird and the kdc load at start — for now
//! ONLY the clearly marked, UNSIGNED development format (decision A-68;
//! docs/questions/Q-270 item 2).
//!
//! docs/50 §7.2: "kdc and dird load the **same** file at start; an invalid
//! signature / a version older than the current one ⇒ they do not start;
//! the policy version is compared in every view (§3.4)". The signed store
//! is decided in principle (Q-219 → A-57: "a hand-defined format with the
//! same discipline as the IPC codec + fuzz target; signature with a tier-0
//! key"), but its signature algorithm, key custody, rollback protection and
//! reload are not defined anywhere yet. Until they are, the file **says**
//! what it is — its first octets are [`MARKER`] — and is accepted only when
//! the daemon's configuration names the format explicitly
//! (`policy_store_format = unsigned-development`, crates/config); both
//! daemons print [`UNSIGNED_DEVELOPMENT_WARNING`] at every start. No
//! signature is verified and nothing here may be trusted in production.
//!
//! # History
//!
//! Format 1 was dird's own file (crates/directory-daemon, task P8): the
//! tier map only. A-68 moved its decoder and encoder here unchanged for the
//! tier map, and format 2 adds what the kdc needs from the same file: the
//! PDP rule set, the anonymous allowlist and the bootstrap group of the
//! mandatory-FAST rules. A format-1 file is **refused, not migrated**
//! ([`PolicyError::Superseded`]): it holds no rule set, and a migration
//! would have to invent one (docs/questions/Q-275 item 1).
//!
//! # Format 2 (the discipline of the IPC codec, docs/50 §3.3; A-57)
//!
//! ```text
//! file       := marker[24] ‖ format:u8 (= 2) ‖ policy_version:u64
//!               ‖ principals: seq<principal, 4096> ‖ subtrees: seq<subtree, 256>
//!               ‖ fast: bootstrap_group: sid ‖ first_rule_id: u32
//!               ‖ rules: seq<rule, 1024> ‖ anonymous: seq<grant, 64>
//! principal  := sid ‖ tier                       ; strictly ascending SID order
//! subtree    := dn ‖ tier                        ; RDN components leaf first
//! sid        := bytes<68>                        ; [MS-DTYP] 2.4.2.2 packet
//! dn         := seq<bytes<255>, 64>              ; printable "att=value" each
//! tier       := 0 Tier0 | 1 Tier1 | 2 Tier2 | 3 Untiered (refused in the tier map)
//! rule       := id:u32 ‖ effect ‖ match ‖ obligations: seq<obligation, 8>
//! effect     := 0 Allow | 1 Deny
//! match      := action_match ‖ resource_match ‖ subject_match ‖ context_match ‖ auth_match
//! grant      := action_match ‖ resource_match ‖ min_transport ‖ src_net
//! ```
//!
//! The pieces of a rule and their closed code tables are in [`codes`]
//! (one table per `pdp` enumeration, variant for variant); the reading and
//! writing of each piece is `wire`. Every primitive is ipc's (fixed-width
//! big-endian integers, `u32`-counted sequences and byte strings under a
//! bound, `Option` as `00` | `01 T`, no trailing octet); the file is at most
//! [`MAX_POLICY_FILE`] octets and is bounded before it is read whole.
//!
//! # Content rules (fail closed: anything else refuses the whole file)
//!
//! - tier map (as format 1): each SID decodes strictly and appears once, in
//!   ascending order; each subtree DN has at least one component, each
//!   component printable ASCII `att=value`, no DN twice; no entry is
//!   Untiered;
//! - mandatory FAST: the bootstrap group SID decodes; the
//!   [`pdp::MANDATORY_FAST_RULE_COUNT`] rule ids from `first_rule_id` fit in
//!   `u32` (docs/48 §7; A-39; P-10 interim);
//! - rules: every id is unique and outside the mandatory-FAST range; every
//!   SID decodes; every text (share, zone, SPN, policy scope, claim) is
//!   1 ..= [`MAX_TEXT`] octets of printable ASCII; every DN component as in
//!   the tier map; a time window is not reversed (`pdp::TimeWindow::new`);
//! - **construction refusals** (A-51; crates/pdp policy.rs): a rule subtree
//!   whose base DN has no component ([`pdp::RuleError::EmptySubtreeBase`]),
//!   an anonymous grant for a network other than Internal
//!   ([`pdp::RuleError::AnonymousExternalNetwork`]) or over every resource
//!   ([`pdp::RuleError::UnboundedAnonymousResource`]) — each refuses the
//!   whole load: "a loader that met a `RuleError` builds no snapshot at all"
//!   (crates/pdp policy.rs; dropping only the refused item could widen).
//!
//! # The snapshot
//!
//! [`DevelopmentPolicy::snapshot`] builds the `pdp::PolicySnapshot` the kdc
//! decides with: the mandatory-FAST rule set of the bootstrap group first
//! (`pdp::mandatory_fast_rules`, policy data — the PDP layer of D126,
//! docs/48 §7.2), then the file's rules in file order, and the anonymous
//! allowlist (internal-only, A-51), all under the file's policy version.
//! The rule order only decides which Deny id an audit record names (crates/
//! pdp policy.rs), never an effect. dird builds its tier map from
//! [`DevelopmentPolicy::principals`] / [`DevelopmentPolicy::subtrees`]
//! itself (this crate links no directory code).
//!
//! # The tier-map edit (task A16)
//!
//! [`edit`] holds the one implementation of the tier-map edit both
//! policy-change paths use — `provision policy` offline and dird's online
//! `PolicyAdmin` path, which writes the result as `policy.next` for root to
//! activate (docs/51 §5.10; A-80) — and the rule a `policy.next` must meet to
//! be activated ([`check_tier_map_successor`]).
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside tests
//! and const evaluation; no indexing on a decode path. No error carries file
//! content (docs/50 §8.2). The decoder never allocates from a length it has
//! not bounded (ipc's reader).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! AGENT-ONBOARDING, AGENTS, docs/50 (§3.3, §3.4, §7.2, §9, §10 P8/P9),
//! docs/questions Q-127 / Q-130 (A-39), Q-219 (A-57), Q-270 (A-68),
//! PENDING-OWNER (A-36, A-39, A-48, A-51, A-57, A-68, P-1, P-10); the code
//! of this project's crates directory-daemon (`policy.rs`, moved here), pdp
//! (`policy.rs`, `mandatory_fast.rs`, `model.rs`), ipc and dtyp. The code
//! values of the tier table are format 1's (the directory channel's,
//! crates/ipc-directory); every other table is this project's choice. No
//! other implementation, policy language or serializer was consulted or
//! recalled (AGENTS.md §1-3).
//!
//! Spec: docs/50 §3.3, §7.2, §9; docs/06 §9; docs/11 §3, §6; docs/48 §7;
//! A-36; A-39; A-51; A-57; A-68.

pub mod codes;
pub mod edit;
mod file;
mod policy;
mod wire;

pub use edit::{
    check_tier_map_successor, edit_tier_map, tier_map_difference, EditError, SuccessorError,
    TierChange,
};
pub use file::{read_file, LoadError};
pub use policy::{
    DevelopmentPolicy, MandatoryFast, PolicyError, FORMAT, MARKER, MAX_ACTIONS,
    MAX_ANONYMOUS_GRANTS, MAX_COMPONENT, MAX_DN_COMPONENTS, MAX_OBLIGATIONS, MAX_POLICY_FILE,
    MAX_PRINCIPALS, MAX_RULES, MAX_SID, MAX_SUBTREES, MAX_TEXT, SUPERSEDED_FORMAT,
    UNSIGNED_DEVELOPMENT_WARNING,
};
