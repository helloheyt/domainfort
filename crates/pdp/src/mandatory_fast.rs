//! The mandatory-FAST rule set: policy data for layer 3 of `decide`, not a
//! check built into it.
//!
//! Spec: docs/48 §7.1 (phase 1: FAST is required for every principal and
//! every exchange, with one exception), §7.2 (enforced in two layers; layer
//! 2 is a PDP rule on `armored`, option (ii): an explicit Deny with a
//! negated subject predicate plus `AuthMatch`), §7.3 (the bootstrap
//! exception (א): an unarmored AS only for a computer account, TGT only);
//! the closing decision of docs/48 (Q-127 → owner item P-10; build per the
//! proposal meanwhile); Q-127 interim decision ((1)–(5), (ג) = (ii));
//! docs/11 §3 (rules; explicit Deny wins; no matching Allow → Deny), §4
//! (layer 3), §10 (P2, P4); D126 (docs/30 §5).
//!
//! # The rules
//!
//! [`mandatory_fast_rules`] returns, for a bootstrap-allowed group SID `B`
//! taken from policy data:
//!
//! | id | effect | action | resource | subject | auth |
//! |---|---|---|---|---|---|
//! | first + 0 | Deny | every Kerberos action | any | `NotMemberOf(B)` | unarmored |
//! | first + 1 | Deny | `KdcTgs`, `KdcS4u2Self`, `KdcS4u2Proxy` | any | any | unarmored |
//! | first + 2 | Allow | `KdcAs`, `KdcTgs` | any Kerberos target | any | armored |
//! | first + 3 | Allow | `KdcAs` | the TGT | `MemberOf(B)` | unarmored |
//!
//! - The two Deny rules are option (ii): an unarmored Kerberos request is
//!   denied unless it is an AS by a member of `B`. An explicit Deny wins
//!   (P4), so a broader Allow elsewhere in the policy cannot reopen the
//!   downgrade (docs/48 §7.2: the weakness of option (i) alone).
//! - The two Allow rules are option (i): every grant carries an `auth`
//!   constraint; deny-by-default refuses everything else (P2).
//! - `KdcS4u2Self` / `KdcS4u2Proxy` are not granted (docs/48 §7.2 (i) names
//!   only `KdcAs` / `KdcTgs`); unarmored, they are denied.
//!
//! # Bounds of this layer (documented residuals)
//!
//! - It is defence in depth. The first downgrade defence is the KDC's PEP
//!   gate before keyd (docs/48 §7.2 layer 1; build task T5), because the PDP
//!   is asked only after pre-authentication.
//! - The PDP sees SIDs, not the account's `kind`: the bootstrap set is a
//!   group SID chosen in policy data, and the KDC's layer 1 derives
//!   `armor_policy` from objectClass computer (Q-127 interim (ב)). Both
//!   layers must pass, so a mismatch can only refuse more. Which SID a
//!   deployment names: Q-130.
//! - "TGT only" is enforced by the KDC (the phase-1 AS issues TGTs only,
//!   docs/48 §7.3). Here the bootstrap Allow names the TGT as well, but no
//!   Deny names a non-TGT AS target (the resource matcher has no negation),
//!   so a broader Allow could grant one. For the one non-TGT AS target the
//!   KDC serves — the change-password service — the explicit Deny is
//!   [`crate::change_password_as_rules`] (task K5; docs/53 §5.2, A-142).
//! - That `armored` is true only after keyd verified the armor is the PEP's
//!   contract (docs/48 §4.2, R48-10; docs/11 P3).

use crate::model::{Action, ActionClass, Effect, KerbResKind, PrincipalId, RuleId};
use crate::policy::{
    ActionMatch, AuthMatch, ContextMatch, Match, ResourceMatch, Rule, SubjectMatch,
};

/// The number of rules [`mandatory_fast_rules`] returns (and of consecutive
/// rule ids it uses, starting at `first_id`).
pub const MANDATORY_FAST_RULE_COUNT: u32 = 4;

/// The mandatory-FAST rule set for the bootstrap-allowed group
/// `bootstrap_allowed`, with rule ids `first_id` to `first_id + 3` (see the
/// table in the module documentation).
///
/// `bootstrap_allowed` is policy data: a group SID whose expanded members
/// (docs/11 §1 `groups`) may make an unarmored AS request for a TGT. Nothing
/// in `decide` knows this SID; a snapshot without these rules imposes no
/// FAST requirement and grants no Kerberos action (P2).
///
/// Returns `None` if the ids would overflow `u32` (no partial set).
///
/// Spec: docs/48 §7.1-§7.3; Q-127 interim decision (P-10); docs/11 §3, P4.
#[must_use]
pub fn mandatory_fast_rules(bootstrap_allowed: PrincipalId, first_id: RuleId) -> Option<Vec<Rule>> {
    let id = |offset: u32| first_id.0.checked_add(offset).map(RuleId);
    Some(vec![
        // docs/48 §7.2 (ii), §7.3: an unarmored Kerberos request by a
        // subject outside the bootstrap set is denied.
        Rule {
            id: id(0)?,
            effect: Effect::Deny,
            when: Match {
                action: ActionMatch::Class(ActionClass::Kerberos),
                resource: ResourceMatch::Any,
                subject: SubjectMatch::NotMemberOf(bootstrap_allowed),
                context: ContextMatch::ANY,
                auth: AuthMatch::UNARMORED,
            },
            obligations: Vec::new(),
        },
        // docs/48 §7.1, §7.3 ("TGS is always armored"); Q-127 (2), (4): no
        // Kerberos exchange other than the AS has an unarmored exception.
        Rule {
            id: id(1)?,
            effect: Effect::Deny,
            when: Match {
                action: ActionMatch::AnyOf(vec![
                    Action::KdcTgs,
                    Action::KdcS4u2Self,
                    Action::KdcS4u2Proxy,
                ]),
                resource: ResourceMatch::Any,
                subject: SubjectMatch::Any,
                context: ContextMatch::ANY,
                auth: AuthMatch::UNARMORED,
            },
            obligations: Vec::new(),
        },
        // docs/48 §7.2 (i): "every Allow for KdcAs/KdcTgs requires armored:
        // Some(true)".
        Rule {
            id: id(2)?,
            effect: Effect::Allow,
            when: Match {
                action: ActionMatch::AnyOf(vec![Action::KdcAs, Action::KdcTgs]),
                resource: ResourceMatch::Kerberos { kind: None },
                subject: SubjectMatch::Any,
                context: ContextMatch::ANY,
                auth: AuthMatch::ARMORED,
            },
            obligations: Vec::new(),
        },
        // docs/48 §7.2 (i) ("except one Allow KdcAs for MemberOf(computer
        // group)"), §7.3 (א) (unarmored AS, TGT only); Q-127 (4).
        Rule {
            id: id(3)?,
            effect: Effect::Allow,
            when: Match {
                action: ActionMatch::Exact(Action::KdcAs),
                resource: ResourceMatch::Kerberos {
                    kind: Some(KerbResKind::Tgt),
                },
                subject: SubjectMatch::MemberOf(bootstrap_allowed),
                context: ContextMatch::ANY,
                auth: AuthMatch::UNARMORED,
            },
            obligations: Vec::new(),
        },
    ])
}
