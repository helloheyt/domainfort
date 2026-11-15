//! The change-password service's AS rule set: policy data for layer 3 of
//! `decide`, beside the mandatory-FAST set ([`crate::mandatory_fast`]).
//!
//! Spec: docs/53 R53-1 (users only), R53-6, §5.2 (a ticket for
//! `kadmin/changepw` only from an armored AS; "the PDP: `KdcAs` on this
//! service's resource, `armored` required (A-39), users only (a data
//! rule)"); A-117; A-142 (no FAST exception for the AS to
//! `kadmin/changepw`, in any version); docs/48 §7.2 (layer 2: an explicit
//! Deny, which a broader Allow cannot reopen), (i) ("the computer group");
//! docs/11 §3 (explicit Deny wins; no matching Allow → Deny), §10 (P2, P4).
//!
//! # The rules
//!
//! [`change_password_as_rules`] returns, for the computer group `C` taken
//! from policy data (the bootstrap group of the mandatory-FAST set — the
//! role docs/48 §7.2 (i) gives "the computer group"):
//!
//! | id | effect | action | resource | subject | auth |
//! |---|---|---|---|---|---|
//! | first + 0 | Deny | `KdcAs` | `Kerberos { ChangePassword }` | any | unarmored |
//! | first + 1 | Deny | `KdcAs` | `Kerberos { ChangePassword }` | `MemberOf(C)` | any |
//!
//! - first + 0 closes, at the PDP, the gap the mandatory-FAST set leaves
//!   open by design ("no Deny names a non-TGT AS target ..., so a broader
//!   Allow could grant one", crates/pdp mandatory_fast.rs): the
//!   mandatory-FAST Deny covers subjects outside the bootstrap set only, and
//!   a broad Allow with `AuthMatch::ANY` (provision's Kerberos rule) would
//!   otherwise grant a bootstrap-set member an unarmored AS for this
//!   service. A-142: that AS is never unarmored, for anyone.
//! - first + 1 is "users only" as policy data: the PDP sees SIDs, not the
//!   account's kind, so the one computer group the policy names is denied.
//! - There is no Allow here: the armored grant is the mandatory-FAST set's
//!   (`KdcAs` / `KdcTgs`, any Kerberos target, armored). Both rules only
//!   narrow.
//!
//! # Bounds of this layer (documented residuals)
//!
//! - It is defence in depth. The first defence is the KDC (crates/kdc
//!   `as_exchange.rs`, task K5): its unarmored path has no value that can
//!   name the change-password service, and it refuses a client whose
//!   account is not a user (`AccountKind::User`, from objectClass) before
//!   keyd is asked. Both layers must pass, so a mismatch can only refuse
//!   more.
//! - A computer outside the named group is denied by the KDC only: a
//!   positive "users" group would need a users-group SID in the policy file,
//!   which format 2 does not carry (docs/questions/Q-916).
//! - The TGS never asks about this resource: the KDC refuses the name before
//!   the PDP (docs/53 §5.2), and keyd's `issue_tgs_rep` refuses the key set.

use crate::model::{Action, Effect, KerbResKind, PrincipalId, RuleId};
use crate::policy::{
    ActionMatch, AuthMatch, ContextMatch, Match, ResourceMatch, Rule, SubjectMatch,
};

/// The number of rules [`change_password_as_rules`] returns (and of
/// consecutive rule ids it uses, starting at `first_id`).
pub const CHANGE_PASSWORD_AS_RULE_COUNT: u32 = 2;

/// The change-password service's AS rule set for the computer group
/// `computer_group`, with rule ids `first_id` and `first_id + 1` (see the
/// table in the module documentation).
///
/// `computer_group` is policy data (the mandatory-FAST set's bootstrap
/// group, docs/48 §7.2 (i)). Returns `None` if the ids would overflow `u32`
/// (no partial set).
///
/// Spec: docs/53 R53-1, §5.2; A-117; A-142; docs/48 §7.2; docs/11 §3, P4.
#[must_use]
pub fn change_password_as_rules(
    computer_group: PrincipalId,
    first_id: RuleId,
) -> Option<Vec<Rule>> {
    let id = |offset: u32| first_id.0.checked_add(offset).map(RuleId);
    let resource = || ResourceMatch::Kerberos {
        kind: Some(KerbResKind::ChangePassword),
    };
    Some(vec![
        // A-142; docs/53 §5.2 ("an unarmored AS to `kadmin/changepw` is
        // refused for every principal").
        Rule {
            id: id(0)?,
            effect: Effect::Deny,
            when: Match {
                action: ActionMatch::Exact(Action::KdcAs),
                resource: resource(),
                subject: SubjectMatch::Any,
                context: ContextMatch::ANY,
                auth: AuthMatch::UNARMORED,
            },
            obligations: Vec::new(),
        },
        // docs/53 R53-1 ("users only — a computer account is refused"),
        // §5.2 ("users only (a data rule)").
        Rule {
            id: id(1)?,
            effect: Effect::Deny,
            when: Match {
                action: ActionMatch::Exact(Action::KdcAs),
                resource: resource(),
                subject: SubjectMatch::MemberOf(computer_group),
                context: ContextMatch::ANY,
                auth: AuthMatch::ANY,
            },
            obligations: Vec::new(),
        },
    ])
}
