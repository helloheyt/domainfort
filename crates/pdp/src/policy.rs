//! The rule model and the versioned policy snapshot.
//!
//! Spec: docs/11 §3 (`Rule`, `Match`; "explicit Deny wins; no matching Allow →
//! Deny"), §4 (`eval_rules`: "matches rules by the `Match`; collects
//! Allow/Deny; does nothing beyond that"), §6 (snapshot semantics, P9), D39;
//! docs/06 §5, §9 (global rules live in a separate, signed, versioned store —
//! D17).
//!
//! Matching is exact and non-recursive: no pattern language, no regular
//! expressions, no DN parsing (DNs are compared component-wise, see
//! [`Dn::is_within`]). Every matcher is a total function.

use crate::model::{
    AccessRequest, Action, ActionClass, ClaimId, ClaimValue, Dn, Effect, Instant, IpScope,
    KerbResKind, Obligation, PolicyScope, PrincipalId, Resource, RuleId, ShareId, Subject, Tier,
    TransportSec, Uuid, ZoneId,
};

/// A global rule. Spec: docs/11 §3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Identifier, reported in the audit reason of a coarse deny.
    pub id: RuleId,
    /// Allow or Deny.
    pub effect: Effect,
    /// When the rule applies: all four matchers must hold.
    pub when: Match,
    /// Obligations attached when an Allow rule applies. An `Audit` here is
    /// redundant and is dropped: the decision always carries exactly one
    /// (P7, docs/11 §8).
    pub obligations: Vec<Obligation>,
}

/// The applicability condition of a rule. Spec: docs/11 §3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// Which actions. Spec: docs/11 §3 ("Exact | AnyOf | Class").
    pub action: ActionMatch,
    /// Which resources. Spec: docs/11 §3 ("kind + pattern: DN subtree,
    /// iface/opnum, share, zone, SPN").
    pub resource: ResourceMatch,
    /// Which subjects. Spec: docs/11 §3 ("predicate on
    /// principal/group/tier/claim").
    pub subject: SubjectMatch,
    /// Which contexts. Spec: docs/11 §3 ("transport_sec floor, source zone,
    /// time window").
    pub context: ContextMatch,
}

/// Action matcher. Spec: docs/11 §3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionMatch {
    /// Every action.
    Any,
    /// Exactly this action (including its GUID payload, if any).
    Exact(Action),
    /// Any of these actions (an empty list matches nothing).
    AnyOf(Vec<Action>),
    /// Every action of this protocol family.
    Class(ActionClass),
}

impl ActionMatch {
    /// `true` if `action` is matched. Spec: docs/11 §3.
    #[must_use]
    pub fn matches(&self, action: &Action) -> bool {
        match self {
            ActionMatch::Any => true,
            ActionMatch::Exact(a) => a == action,
            ActionMatch::AnyOf(list) => list.contains(action),
            ActionMatch::Class(class) => action.class() == *class,
        }
    }
}

/// Resource matcher: a kind plus an exact pattern. Spec: docs/11 §3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceMatch {
    /// Every resource.
    Any,
    /// A directory object equal to `base` or below it (any attribute).
    DirSubtree {
        /// The subtree root.
        base: Dn,
    },
    /// An RPC method of this interface; `opnum: None` matches every opnum.
    RpcMethod {
        /// Interface UUID.
        iface: Uuid,
        /// Operation number, or every operation.
        opnum: Option<u16>,
    },
    /// Any file in this share.
    File {
        /// The share.
        share: ShareId,
    },
    /// This DNS zone (any record).
    Dns {
        /// The zone.
        zone: ZoneId,
    },
    /// A Kerberos target; `kind: None` matches every Kerberos resource.
    Kerberos {
        /// The exact target, or every target.
        kind: Option<KerbResKind>,
    },
    /// A policy scope; `scope: None` matches every scope.
    Policy {
        /// The exact scope, or every scope.
        scope: Option<PolicyScope>,
    },
}

impl ResourceMatch {
    /// `true` if `resource` is matched. Spec: docs/11 §3.
    #[must_use]
    pub fn matches(&self, resource: &Resource) -> bool {
        match (self, resource) {
            (ResourceMatch::Any, _) => true,
            (ResourceMatch::DirSubtree { base }, Resource::DirObject { dn, .. }) => {
                dn.is_within(base)
            }
            (
                ResourceMatch::RpcMethod {
                    iface: want_iface,
                    opnum: want_opnum,
                },
                Resource::RpcMethod { iface, opnum },
            ) => want_iface == iface && want_opnum.is_none_or(|o| o == *opnum),
            (ResourceMatch::File { share: want }, Resource::File { share, .. }) => want == share,
            (ResourceMatch::Dns { zone: want }, Resource::Dns { zone, .. }) => want == zone,
            (ResourceMatch::Kerberos { kind: want }, Resource::Kerberos { kind }) => {
                want.as_ref().is_none_or(|w| w == kind)
            }
            (ResourceMatch::Policy { scope: want }, Resource::Policy { scope }) => {
                want.as_ref().is_none_or(|w| w == scope)
            }
            _ => false,
        }
    }
}

/// Subject predicate. Spec: docs/11 §3 ("predicate on
/// principal/group/tier/claim").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectMatch {
    /// Every subject.
    Any,
    /// The principal is exactly this SID.
    Principal(PrincipalId),
    /// The principal is this SID or the (expanded) groups contain it.
    MemberOf(PrincipalId),
    /// The subject's (PIP-verified) tier is exactly this one.
    Tier(Tier),
    /// The subject carries this claim with exactly this value.
    Claim(ClaimId, ClaimValue),
}

impl SubjectMatch {
    /// `true` if `subject` is matched. Spec: docs/11 §3.
    #[must_use]
    pub fn matches(&self, subject: &Subject) -> bool {
        match self {
            SubjectMatch::Any => true,
            SubjectMatch::Principal(sid) => subject.principal == *sid,
            SubjectMatch::MemberOf(sid) => {
                subject.principal == *sid || subject.groups.contains(sid)
            }
            SubjectMatch::Tier(tier) => subject.tier == *tier,
            SubjectMatch::Claim(id, value) => subject.claims.get(id) == Some(value),
        }
    }
}

/// An inclusive window of explicit time. Constructed only through
/// [`TimeWindow::new`], so `not_before <= not_after` always holds (a rule can
/// never carry a malformed window). Spec: docs/11 §3 ("time window"), §10 P9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeWindow {
    not_before: Instant,
    not_after: Instant,
}

impl TimeWindow {
    /// An inclusive window; `None` if `not_before > not_after`.
    #[must_use]
    pub fn new(not_before: Instant, not_after: Instant) -> Option<TimeWindow> {
        if not_before <= not_after {
            Some(TimeWindow {
                not_before,
                not_after,
            })
        } else {
            None
        }
    }

    /// `true` if `t` lies in the window (inclusive). Uses only the explicit
    /// `Context.time` (P9).
    #[must_use]
    pub fn contains(&self, t: Instant) -> bool {
        self.not_before <= t && t <= self.not_after
    }
}

/// Context matcher. Spec: docs/11 §3 ("transport_sec floor, source zone, time
/// window").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextMatch {
    /// The transport must meet this floor.
    pub min_transport: TransportSec,
    /// The source must be in this zone, if set.
    pub src_net: Option<IpScope>,
    /// `Context.time` must lie in this window, if set.
    pub time_window: Option<TimeWindow>,
}

impl ContextMatch {
    /// Matches every context.
    pub const ANY: ContextMatch = ContextMatch {
        min_transport: TransportSec::NONE,
        src_net: None,
        time_window: None,
    };

    /// `true` if `context` is matched. Spec: docs/11 §3.
    #[must_use]
    pub fn matches(&self, context: &crate::model::Context) -> bool {
        context.transport_sec.meets(self.min_transport)
            && self.src_net.is_none_or(|z| z == context.src_net)
            && self.time_window.is_none_or(|w| w.contains(context.time))
    }
}

impl Match {
    /// `true` if all four matchers hold. Spec: docs/11 §3, §4 (`eval_rules`).
    #[must_use]
    pub fn matches(&self, req: &AccessRequest) -> bool {
        self.action.matches(&req.action)
            && self.resource.matches(&req.resource)
            && self.subject.matches(&req.subject)
            && self.context.matches(&req.context)
    }
}

/// One entry of the anonymous allowlist (layer 1): which unauthenticated
/// requests may proceed to the later layers, and the transport floor that
/// replaces `required_sec` for them. Spec: docs/11 §4 (`anon_allowlist`;
/// "anonymous allowlist (rootDSE, CLDAP ping) → configured minimum"); docs/06
/// §5.1; docs/05 §3 (CLDAP / anonymous: rootDSE only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymousGrant {
    /// Which actions.
    pub action: ActionMatch,
    /// Which resources.
    pub resource: ResourceMatch,
    /// The configured transport minimum for these requests.
    pub min_transport: TransportSec,
}

/// The version of a policy snapshot. Spec: docs/11 §6, §9 (the cache key
/// includes the policy version), D39.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion(pub u64);

/// A consistent, versioned set of global rules plus the anonymous allowlist.
/// Every decision is evaluated against one snapshot, so it is reproducible
/// (P9, D39). Spec: docs/11 §3, §6; docs/06 §9 (D17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySnapshot {
    version: PolicyVersion,
    rules: Vec<Rule>,
    anonymous_allowlist: Vec<AnonymousGrant>,
}

impl PolicySnapshot {
    /// Build a snapshot. Rule order is kept; it only affects which rule id a
    /// coarse deny reports (the first matching Deny), never the effect.
    #[must_use]
    pub fn new(
        version: PolicyVersion,
        rules: Vec<Rule>,
        anonymous_allowlist: Vec<AnonymousGrant>,
    ) -> PolicySnapshot {
        PolicySnapshot {
            version,
            rules,
            anonymous_allowlist,
        }
    }

    /// The snapshot version.
    #[must_use]
    pub fn version(&self) -> PolicyVersion {
        self.version
    }

    /// The global rules, in order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The anonymous allowlist.
    #[must_use]
    pub fn anonymous_allowlist(&self) -> &[AnonymousGrant] {
        &self.anonymous_allowlist
    }
}

/// The result of evaluating the global rules against a request.
/// Spec: docs/11 §4 (`coarse.has_deny()`, `coarse.has_allow()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoarseResult {
    /// The first matching Deny rule, if any.
    pub(crate) denied_by: Option<RuleId>,
    /// At least one Allow rule matched.
    pub(crate) allowed: bool,
    /// Obligations of the matching Allow rules, in rule order, without
    /// `Audit` (P7).
    pub(crate) obligations: Vec<Obligation>,
}

/// Collect the matching rules. Does nothing beyond matching and collecting.
/// Spec: docs/11 §4 (`eval_rules`).
pub(crate) fn eval_rules(req: &AccessRequest, pol: &PolicySnapshot) -> CoarseResult {
    let mut result = CoarseResult {
        denied_by: None,
        allowed: false,
        obligations: Vec::new(),
    };
    for rule in pol.rules() {
        if !rule.when.matches(req) {
            continue;
        }
        match rule.effect {
            Effect::Deny => {
                if result.denied_by.is_none() {
                    result.denied_by = Some(rule.id);
                }
            }
            Effect::Allow => {
                result.allowed = true;
                result.obligations.extend(
                    rule.obligations
                        .iter()
                        .filter(|o| !matches!(o, Obligation::Audit))
                        .cloned(),
                );
            }
        }
    }
    result
}
