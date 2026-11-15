//! The policy of a new domain (docs/51 §4.3 step 6) and the offline
//! tier-map edit of `provision policy` (R51-21, A-80) — both pure.
//!
//! # The policy of a new domain (`policy_version` = 1, format 2)
//!
//! - tier map: the Tier-0 group's SID → Tier0; the Tier-0 OU's subtree →
//!   Tier0 (docs/47 §6.3; A-36);
//! - `fast.bootstrap_group` = the bootstrap group's SID, the
//!   mandatory-FAST rule ids from [`MANDATORY_FAST_FIRST_RULE_ID`] (A-39,
//!   A-44; crates/pdp mandatory_fast.rs);
//! - rules, in this order:
//!
//! | id | effect | action | resource | subject | context | source |
//! |---|---|---|---|---|---|---|
//! | 1 | Allow | `AnyOf[KdcAs, KdcTgs]` | every Kerberos resource | any | any | the phase-1 KDC's PDP questions (below) |
//! | 2 | Allow | `DirRead` | rootDSE | any | any | the existing base (e2e `root_dse_rule`; docs/49 §5.2) |
//! | 3 | Allow | the A3 directory actions (below) | `DirSubtree(NC root)` | `MemberOf(Tier-0 group)` | `{encrypted, sealed}` floor, internal network | docs/51 §4.3 step 6, §5.2 |
//! | 4 | Allow | `PolicyAdmin` | every policy scope | `MemberOf(Tier-0 group)` | as 3 | docs/51 §4.3 step 6, §5.10; docs/06 §9 |
//! | 5 | Allow | `DirControlRight(User-Change-Password)` | `DirSubtree(NC root)` | any | `{encrypted, sealed, channel_bound}` floor, internal network | task K9: docs/53 §5.6 step 4 |
//!
//!   **Rule 5** (task K9) is the coarse grant of kpasswd's self change:
//!   dird asks `DirControlRight(User-Change-Password)` on the account's own
//!   object, the Subject being that account, on transport `Kpasswd` with
//!   `{encrypted, sealed, channel_bound}` from the internal network
//!   (crates/directory-admin `prepare_change_password`, A-161). The rule
//!   names no subject — layer 5 decides who: the root's PRINCIPAL_SELF ACE
//!   grants the right only on an account's own object ([MS-ADTS]
//!   3.1.1.3.1.5.1 "on itself"; module `descriptor`, row 11), and layer 4
//!   (tier) applies without exception (docs/53 R53-13; Q-608 item 2, A-117).
//!   The change-password service's AS needs no rule here: rule 1 grants
//!   `KdcAs` on every Kerberos resource and the policy's reserved set narrows
//!   it (pdp `change_password_as_rules`: armored only, the computer group
//!   denied — A-151).
//!
//!   **Rule 1** grants exactly the Kerberos actions the phase-1 KDC asks
//!   the PDP for — `KdcAs` on `Kerberos{Tgt}` (crates/kdc as_exchange.rs,
//!   the PDP step of the AS exchange: `enforce(Question { action:
//!   Action::KdcAs, resource: Resource::Kerberos { kind: KerbResKind::Tgt }
//!   … })`) and `KdcTgs` on `Kerberos{Service(spn)}` (crates/kdc
//!   tgs_exchange.rs, step 10: `enforce(Question { action: Action::KdcTgs,
//!   resource: Resource::Kerberos { kind: KerbResKind::Service(Spn(spn)) }
//!   … })`); crates/kdc gate.rs: "The request: `Action::KdcAs` /
//!   `Action::KdcTgs`". The KDC asks nothing else, so `KdcS4u2Self` /
//!   `KdcS4u2Proxy` (pdp `Action`, `ActionClass::Kerberos`) have no grant
//!   (deny by default, docs/11 §3). This replaces the shared test base
//!   `allow_kerberos` (`Class(Kerberos)` on any resource), which stays as it
//!   is for the other crates' tests (Q-377, decided by the main session:
//!   the generated production policy grants no wider than phase 1 needs).
//!   Mandatory FAST still applies on top (the set's Deny rules for unarmored
//!   requests, docs/48 §7.2).
//!
//!   The `KdcTgs` grant for the admin service's SPN `admind/<fqdn>` that
//!   docs/51 §4.3 step 6 lists is **covered by rule 1** (every service, any
//!   subject — delegated administrators need admin-service tickets too,
//!   docs/51 §10; dird's PDP decides each operation), so no separate rule
//!   is written (Q-377).
//!
//!   The A3 directory actions are exactly what crates/directory-admin
//!   asks the PDP (docs/51 §5.2): `DirRead` (visibility, `Lookup`),
//!   `DirList`, `DirWrite` (userAccountControl, accountExpires, member),
//!   `DirDelete`, `DirAddChild` of user / computer / group /
//!   organizationalUnit / container, and `DirControlRight(User-Force-
//!   Change-Password)` — no other `DirAddChild` class and no other control
//!   right. Layer 5 (the root's ACEs, module `descriptor`) narrows
//!   `DirWrite` to its three attributes.
//! - the anonymous allowlist: `DirRead` of the rootDSE from the internal
//!   network, no transport floor (the existing base; A-51).
//!
//! # The tier-map edit
//!
//! Decode, add / remove `SID → tier` and `subtree → tier` rows, bump
//! `policy_version` by one, encode (policy-store re-validates). Refused: an
//! add of a row already present, a remove of a row absent, an edit that
//! leaves no Tier0 principal (docs/questions/Q-379), a version overflow.
//! The edit itself is crate policy-store's `edit` module since task A16 —
//! one implementation for the offline path and dird's online path
//! (docs/questions/Q-590).
//!
//! Spec: docs/51 §4.3 step 6, §5.2, §5.10; docs/47 §6.3; docs/06 §9;
//! docs/11 §3; docs/53 §5.6 step 4, §10 (K9); [MS-ADTS] 3.1.1.3.1.5.1,
//! 6.1.1.2.7.52; A-36; A-39; A-51; A-68; A-69; A-73; A-80; A-117; A-151;
//! A-161; crates/pdp policy.rs (the rule language), decide.rs
//! (`desired_right`); docs/questions/Q-964 item 13.

use std::collections::BTreeMap;

use directory_admin::{USER_CHANGE_PASSWORD, USER_FORCE_CHANGE_PASSWORD};
use dtyp::{Guid, Sid};
use pdp::{
    Action, ActionMatch, AnonymousGrant, AuthMatch, ContextMatch, ControlRightId, Dn, Effect,
    IpScope, Match, ObjClass, PolicyVersion, ResourceMatch, Rule, RuleError, RuleId, SubjectMatch,
    SubtreeBase, Tier, TransportSec,
};
use policy_store::{DevelopmentPolicy, MandatoryFast};

/// The version of a new domain's policy. Spec: docs/51 §4.3 step 6
/// ("`policy_version` = 1").
pub const FIRST_POLICY_VERSION: u64 = 1;

/// The first of the mandatory-FAST rule ids (the set takes
/// `pdp::MANDATORY_FAST_RULE_COUNT` consecutive ids). Project choice, the
/// value the existing fixtures use (crates/kdc-daemon tests
/// `shared_policy`), clear of rules 1-4.
pub const MANDATORY_FAST_FIRST_RULE_ID: u32 = 100;

/// Rule id of the Kerberos rule (`AnyOf[KdcAs, KdcTgs]`). Spec: crates/kdc
/// as_exchange.rs, tgs_exchange.rs (the PDP questions); docs/11 §3.
pub const RULE_KERBEROS: u32 = 1;
/// Rule id of the rootDSE read rule. Spec: docs/49 §5.2; e2e
/// `root_dse_rule`.
pub const RULE_ROOT_DSE: u32 = 2;
/// Rule id of the Tier-0 directory-administration rule. Spec: docs/51
/// §4.3 step 6, §5.2.
pub const RULE_TIER0_DIRECTORY: u32 = 3;
/// Rule id of the Tier-0 policy-administration rule. Spec: docs/51 §4.3
/// step 6, §5.10.
pub const RULE_TIER0_POLICY: u32 = 4;
/// Rule id of the change-password rule (task K9). Spec: docs/53 §5.6 step
/// 4.
pub const RULE_CHANGE_PASSWORD: u32 = 5;

/// The Kerberos actions the phase-1 KDC asks the PDP for: `KdcAs` (the AS
/// exchange, on `Kerberos{Tgt}`) and `KdcTgs` (the TGS exchange, on
/// `Kerberos{Service(spn)}`) — and nothing else (no S4U).
/// Spec: crates/kdc as_exchange.rs (`Action::KdcAs`), tgs_exchange.rs step
/// 10 (`Action::KdcTgs`), gate.rs; docs/11 §1, §3; Q-377 (main-session
/// decision: no wider than phase 1 needs).
#[must_use]
pub fn phase1_kerberos_actions() -> Vec<Action> {
    vec![Action::KdcAs, Action::KdcTgs]
}

/// The transport floor of the administration rules: what the local admin
/// channel reports (`{encrypted, sealed}`, A-74; crates/pdp
/// `Transport::LocalIpc`). `decide` applies its own floor first (layer 2);
/// this keeps the grant from matching a weaker transport.
/// Spec: docs/51 §5.4 (R51-9); A-74; docs/11 §3 ("transport_sec floor").
const ADMIN_FLOOR: TransportSec = TransportSec {
    encrypted: true,
    sealed: true,
    channel_bound: false,
};

/// The context of the administration rules: the floor above, the internal
/// network (the DC host itself, docs/51 §5.1: "admind = local socket
/// only"; crates/directory-admin reports `src_net = Internal`, Q-358 item
/// 11).
/// Spec: docs/11 §3; docs/51 §5.1, §5.4.
const ADMIN_CONTEXT: ContextMatch = ContextMatch {
    min_transport: ADMIN_FLOOR,
    src_net: Some(IpScope::Internal),
    time_window: None,
};

/// The transport floor of the change-password rule: what dird's kpasswd PEP
/// reports for a request whose KRB-PRIV keyd decrypted under that request's
/// AP-REQ subkey — `{encrypted, sealed, channel_bound}` (crates/pdp
/// `Transport::Kpasswd`; crates/directory-admin `KPASSWD_SECURITY`).
/// Spec: docs/53 §5.4 item 1, §5.6 step 4; docs/questions/Q-601 item 7
/// (A-117).
const KPASSWD_FLOOR: TransportSec = TransportSec {
    encrypted: true,
    sealed: true,
    channel_bound: true,
};

/// The context of the change-password rule: the floor above, the internal
/// network (the front serves internal sources only and dird reports
/// `src_net = Internal` for every kpasswd request — docs/53 §3.3; crates/
/// directory-admin checks.rs).
/// Spec: docs/53 §3.3, §5.6 step 4; docs/11 §3.
const KPASSWD_CONTEXT: ContextMatch = ContextMatch {
    min_transport: KPASSWD_FLOOR,
    src_net: Some(IpScope::Internal),
    time_window: None,
};

/// The class GUIDs the Tier-0 administrators may create children of (the
/// classes of docs/51 §5.2 rows 1-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CreatableClasses {
    pub(crate) user: Guid,
    pub(crate) computer: Guid,
    pub(crate) group: Guid,
    pub(crate) organizational_unit: Guid,
    pub(crate) container: Guid,
}

/// What the domain policy names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DomainPolicyInput {
    pub(crate) tier0_group: Sid,
    pub(crate) bootstrap_group: Sid,
    /// The NC root's DN (leaf first, `dc=…` components).
    pub(crate) nc_root: Dn,
    /// The Tier-0 OU's DN.
    pub(crate) tier0_ou: Dn,
    pub(crate) classes: CreatableClasses,
}

/// The directory actions crates/directory-admin asks the PDP for (docs/51
/// §5.2; crates/directory-admin lib.rs table).
/// Spec: docs/51 §5.2 rows 1-10; [MS-ADTS] 6.1.1.2.7.53.
pub(crate) fn admin_directory_actions(classes: &CreatableClasses) -> Vec<Action> {
    vec![
        Action::DirRead,
        Action::DirList,
        Action::DirWrite,
        Action::DirDelete,
        Action::DirAddChild(ObjClass(classes.user)),
        Action::DirAddChild(ObjClass(classes.computer)),
        Action::DirAddChild(ObjClass(classes.group)),
        Action::DirAddChild(ObjClass(classes.organizational_unit)),
        Action::DirAddChild(ObjClass(classes.container)),
        Action::DirControlRight(ControlRightId(USER_FORCE_CHANGE_PASSWORD)),
    ]
}

/// One Allow rule.
fn allow(
    id: u32,
    action: ActionMatch,
    resource: ResourceMatch,
    subject: SubjectMatch,
    context: ContextMatch,
) -> Rule {
    Rule {
        id: RuleId(id),
        effect: Effect::Allow,
        when: Match {
            action,
            resource,
            subject,
            context,
            auth: AuthMatch::ANY,
        },
        obligations: Vec::new(),
    }
}

/// The policy of a new domain (module documentation).
///
/// # Errors
/// [`RuleError`] if the NC root's DN is empty or the anonymous grant is
/// refused (neither can happen for a checked input) — the caller fails
/// closed.
///
/// Spec: docs/51 §4.3 step 6; module documentation.
pub(crate) fn domain_policy(input: &DomainPolicyInput) -> Result<DevelopmentPolicy, RuleError> {
    let rules = vec![
        allow(
            RULE_KERBEROS,
            ActionMatch::AnyOf(phase1_kerberos_actions()),
            ResourceMatch::Kerberos { kind: None },
            SubjectMatch::Any,
            ContextMatch::ANY,
        ),
        allow(
            RULE_ROOT_DSE,
            ActionMatch::Exact(Action::DirRead),
            ResourceMatch::RootDse,
            SubjectMatch::Any,
            ContextMatch::ANY,
        ),
        allow(
            RULE_TIER0_DIRECTORY,
            ActionMatch::AnyOf(admin_directory_actions(&input.classes)),
            ResourceMatch::DirSubtree {
                base: SubtreeBase::new(input.nc_root.clone())?,
            },
            SubjectMatch::MemberOf(input.tier0_group),
            ADMIN_CONTEXT,
        ),
        allow(
            RULE_TIER0_POLICY,
            ActionMatch::Exact(Action::PolicyAdmin),
            ResourceMatch::Policy { scope: None },
            SubjectMatch::MemberOf(input.tier0_group),
            ADMIN_CONTEXT,
        ),
        // Task K9 (module documentation, rule 5): the coarse grant of the
        // self change; the root's PRINCIPAL_SELF ACE (layer 5) and the tier
        // invariant (layer 4) decide.
        allow(
            RULE_CHANGE_PASSWORD,
            ActionMatch::Exact(Action::DirControlRight(ControlRightId(
                USER_CHANGE_PASSWORD,
            ))),
            ResourceMatch::DirSubtree {
                base: SubtreeBase::new(input.nc_root.clone())?,
            },
            SubjectMatch::Any,
            KPASSWD_CONTEXT,
        ),
    ];
    let anonymous = vec![AnonymousGrant::new(
        ActionMatch::Exact(Action::DirRead),
        ResourceMatch::RootDse,
        TransportSec::NONE,
        IpScope::Internal,
    )?];
    Ok(DevelopmentPolicy {
        version: PolicyVersion(FIRST_POLICY_VERSION),
        principals: BTreeMap::from([(input.tier0_group, Tier::Tier0)]),
        subtrees: vec![(input.tier0_ou.clone(), Tier::Tier0)],
        mandatory_fast: MandatoryFast {
            bootstrap_group: input.bootstrap_group,
            first_rule_id: RuleId(MANDATORY_FAST_FIRST_RULE_ID),
        },
        rules,
        anonymous,
    })
}

// The tier-map edit of `provision policy` (R51-21, A-80) is crate
// policy-store's (module `edit`, task A16): the one implementation both the
// offline path here and dird's online `PolicyAdmin` path use, so the two
// cannot diverge (docs/52 C14 — the lesson of R13). Re-exported under its
// former path for this crate's callers.
// Spec: docs/51 §5.10; A-80; docs/questions/Q-590.
pub use policy_store::edit::{edit_tier_map, EditError, TierChange};
