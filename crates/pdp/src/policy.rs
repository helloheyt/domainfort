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
//!
//! Mandatory FAST (D126) is expressed in the rule language, not hard-wired
//! in `decide`. Spec: docs/48 §7.2 layer 2 — option (i) `Match.auth:
//! AuthMatch { armored: Option<bool> }` on the Allow side, and option (ii) a
//! negated subject predicate (`SubjectMatch::NotMemberOf`) so that an
//! explicit Deny can be written ("explicit Deny wins", docs/11 §3, P4);
//! Q-127 interim decision (owner item P-10): (ג) = (ii). Neither extension
//! widens an existing rule's grants:
//! - a rule whose `auth` is [`AuthMatch::ANY`] matches exactly what it
//!   matched before `auth` existed (the conjunction gains a `true` term);
//! - an `auth` constraint only removes requests from a rule's match set;
//! - a negated subject predicate takes effect in Deny rules only; in an
//!   Allow rule it matches nothing ([`Rule::applies`]) — DELIBERATE, fail
//!   closed, see Q-130.
//!
//! # Construction refusals (Q-164 items 2-3, A-48; Q-170 item 3, A-51)
//!
//! Two pieces of policy data are checked when they are built, and a value
//! that fails the check cannot exist:
//! - a DN subtree ([`SubtreeBase`]) is never empty: an empty base is a
//!   suffix of every DN ([`Dn::is_within`]), so a rule over it would match
//!   every directory object — in an anonymous-allowlist entry, the whole
//!   directory. Refused for every rule, Allow or Deny, and for the
//!   allowlist. A rule over every resource is written explicitly as
//!   [`ResourceMatch::Any`] (for a Deny, together with an action matcher
//!   such as `ActionMatch::Class(ActionClass::Directory)`);
//! - an anonymous-allowlist entry ([`AnonymousGrant`]) admits the internal
//!   network only (docs/15 §6, "only these, from the internal network";
//!   A-51: External is forbidden outright): its source network is a
//!   required field, there is no "any network" form, and every value other
//!   than [`IpScope::Internal`] is refused. It never names every resource.
//!
//! A refusal is a [`RuleError`]. Whoever loads a policy must treat it as a
//! failure of the whole load (no snapshot, so every decision is Deny), never
//! skip the refused item: dropping a Deny rule, or an allowlist entry whose
//! transport minimum joins another entry's, would widen.

use crate::model::{
    AccessRequest, Action, ActionClass, AuthContext, ClaimId, ClaimValue, Dn, Effect, Instant,
    IpScope, KerbResKind, Obligation, PolicyScope, PrincipalId, Resource, RuleId, ShareId, Subject,
    Tier, TransportSec, Uuid, ZoneId,
};

/// Why a piece of policy data was refused when it was built. Spec: Q-164
/// items 2-3 (A-48); Q-170 item 3 (A-51); docs/15 §6; the module
/// documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleError {
    /// A DN subtree with no RDN component: it would contain every directory
    /// object (Q-164 item 2).
    EmptySubtreeBase,
    /// An anonymous-allowlist entry over every resource
    /// ([`ResourceMatch::Any`]): docs/15 §6 lists the only resources
    /// anonymous requests may reach.
    UnboundedAnonymousResource,
    /// An anonymous-allowlist entry for a source network other than
    /// [`IpScope::Internal`]: docs/15 §6 admits anonymous requests "from the
    /// internal network" only, and A-51 (Q-170 item 3) forbids External in
    /// the allowlist outright.
    AnonymousExternalNetwork,
}

/// The root of a DN subtree in a rule: a [`Dn`] with at least one RDN
/// component. Constructed only through [`SubtreeBase::new`], so a rule can
/// never carry the empty base that would contain every object.
///
/// Spec: docs/11 §3 (`ResourceMatch`: "subtree of DN"); Q-164 item 2 (A-48:
/// "`DirSubtree` with an empty base matched every object"); [MS-ADTS]
/// 3.1.1.3 (the empty DN is the rootDSE, not an object — expressed as
/// [`ResourceMatch::RootDse`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubtreeBase {
    dn: Dn,
}

impl SubtreeBase {
    /// The subtree rooted at `dn`; [`RuleError::EmptySubtreeBase`] if `dn`
    /// has no RDN component. Spec: Q-164 item 2.
    pub fn new(dn: Dn) -> Result<SubtreeBase, RuleError> {
        if dn.rdns().is_empty() {
            Err(RuleError::EmptySubtreeBase)
        } else {
            Ok(SubtreeBase { dn })
        }
    }

    /// The root DN (never empty).
    #[must_use]
    pub fn dn(&self) -> &Dn {
        &self.dn
    }
}

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

impl Rule {
    /// `true` if this rule takes part in the decision for `req`.
    ///
    /// A Deny rule applies when its [`Match`] holds. An Allow rule applies
    /// when its `Match` holds AND its subject predicate is not negated: an
    /// Allow with [`SubjectMatch::NotMemberOf`] matches nothing.
    ///
    /// DELIBERATE (fail closed, AGENTS.md §6; Q-130): the negated predicate
    /// exists to write an explicit Deny (docs/48 §7.2 option (ii); Q-127
    /// (ג) = (ii)). In a grant it would hold for every subject whose
    /// membership is absent from the request — a grant on missing data. A
    /// negation can therefore only remove grants (through a Deny, P4), never
    /// add one. Spec: docs/11 §3 ("explicit Deny wins; without a matching
    /// Allow → Deny"), §4 (`eval_rules`), §10 P2, P4.
    #[must_use]
    pub fn applies(&self, req: &AccessRequest) -> bool {
        match self.effect {
            Effect::Deny => self.when.matches(req),
            Effect::Allow => !self.when.subject.is_negated() && self.when.matches(req),
        }
    }
}

/// The applicability condition of a rule. Spec: docs/11 §3; docs/48 §7.2
/// (`auth`).
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
    /// Which authentication contexts. [`AuthMatch::ANY`] keeps the rule
    /// exactly as it was without this field. Spec: docs/48 §7.2 option (i)
    /// (`Match.auth: AuthMatch { armored: Option<bool> }`); Q-127 interim
    /// decision (P-10); docs/11 §1 (`AuthContext`).
    pub auth: AuthMatch,
}

/// Matcher on the request's authentication context (`Subject.auth`).
///
/// `armored: None` — any request; `Some(true)` — only a request whose
/// `AuthContext.armored` is `true` (FAST was used); `Some(false)` — only a
/// request that was not armored. An `Allow` rule with `Some(true)` is the
/// Allow-side half of mandatory FAST; deny-by-default does the rest (no
/// matching Allow → Deny). Spec: docs/48 §7.2 option (i), §4.2 (when the
/// PEP reports `armored = true`: only after keyd verified the armor —
/// R48-10); Q-127 interim decision (P-10); docs/11 §1 (`armored: bool //
/// FAST`), §3, P3 (the field is set by the PEP from the verified exchange,
/// never claimed by the client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthMatch {
    /// The required value of `AuthContext.armored`, or `None` for any.
    pub armored: Option<bool>,
}

impl AuthMatch {
    /// Matches every authentication context (the behaviour of a rule before
    /// `auth` existed).
    pub const ANY: AuthMatch = AuthMatch { armored: None };

    /// Matches only FAST-armored requests. Spec: docs/48 §7.2 option (i).
    pub const ARMORED: AuthMatch = AuthMatch {
        armored: Some(true),
    };

    /// Matches only requests that were not armored. Spec: docs/48 §7.2
    /// option (ii) (the Deny side), §7.3 (the bootstrap Allow).
    pub const UNARMORED: AuthMatch = AuthMatch {
        armored: Some(false),
    };

    /// `true` if `auth` is matched. Spec: docs/48 §7.2; docs/11 §1, §3.
    #[must_use]
    pub fn matches(&self, auth: &AuthContext) -> bool {
        self.armored.is_none_or(|want| want == auth.armored)
    }
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
    /// A directory object equal to `base` or below it (any attribute). Never
    /// the rootDSE, which is not a directory object.
    DirSubtree {
        /// The subtree root (never empty, [`SubtreeBase`]).
        base: SubtreeBase,
    },
    /// The rootDSE ([`Resource::RootDse`]), and nothing else. Spec: docs/49
    /// §5.2 (R49-10); Q-164 item 1.
    RootDse,
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
                dn.is_within(base.dn())
            }
            (ResourceMatch::RootDse, Resource::RootDse) => true,
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
    /// The exact complement of [`SubjectMatch::MemberOf`]: neither the
    /// principal nor the (expanded) groups are this SID.
    ///
    /// Takes effect in a Deny rule only; in an Allow rule it matches nothing
    /// ([`Rule::applies`], fail closed). A set of principals is named by one
    /// group SID: `Subject.groups` is the expanded, nested membership from
    /// authoritative data (docs/11 §1). Spec: docs/48 §7.2 option (ii)
    /// ("explicit Deny with a negative predicate
    /// (`SubjectMatch::NotMemberOf`)"); Q-127 interim decision (P-10), (ג) =
    /// (ii); docs/11 §3 (subject predicate; explicit Deny wins), P4.
    NotMemberOf(PrincipalId),
    /// The subject's (PIP-verified) tier is exactly this one.
    Tier(Tier),
    /// The subject carries this claim with exactly this value.
    Claim(ClaimId, ClaimValue),
}

impl SubjectMatch {
    /// `true` if `subject` is matched. Spec: docs/11 §3; docs/48 §7.2
    /// (`NotMemberOf`).
    #[must_use]
    pub fn matches(&self, subject: &Subject) -> bool {
        match self {
            SubjectMatch::Any => true,
            SubjectMatch::Principal(sid) => subject.principal == *sid,
            SubjectMatch::MemberOf(sid) => is_member(subject, sid),
            SubjectMatch::NotMemberOf(sid) => !is_member(subject, sid),
            SubjectMatch::Tier(tier) => subject.tier == *tier,
            SubjectMatch::Claim(id, value) => subject.claims.get(id) == Some(value),
        }
    }

    /// `true` for a negated predicate, which [`Rule::applies`] admits in Deny
    /// rules only. Spec: docs/48 §7.2 option (ii); Q-130.
    #[must_use]
    pub fn is_negated(&self) -> bool {
        match self {
            SubjectMatch::NotMemberOf(_) => true,
            SubjectMatch::Any
            | SubjectMatch::Principal(_)
            | SubjectMatch::MemberOf(_)
            | SubjectMatch::Tier(_)
            | SubjectMatch::Claim(..) => false,
        }
    }
}

/// The principal is `sid`, or the expanded groups contain it. The single
/// definition behind `MemberOf` and its complement `NotMemberOf`, so the two
/// can never drift apart. Spec: docs/11 §1 (`groups`: expanded, nested),
/// §3.
fn is_member(subject: &Subject, sid: &PrincipalId) -> bool {
    subject.principal == *sid || subject.groups.contains(sid)
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

    /// The first instant of the window (for the policy store's encoder,
    /// A-68; reading it changes no decision).
    #[must_use]
    pub fn not_before(&self) -> Instant {
        self.not_before
    }

    /// The last instant of the window (for the policy store's encoder,
    /// A-68).
    #[must_use]
    pub fn not_after(&self) -> Instant {
        self.not_after
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
    /// `true` if all five matchers hold. Spec: docs/11 §3, §4 (`eval_rules`);
    /// docs/48 §7.2 (`auth`).
    #[must_use]
    pub fn matches(&self, req: &AccessRequest) -> bool {
        self.action.matches(&req.action)
            && self.resource.matches(&req.resource)
            && self.subject.matches(&req.subject)
            && self.context.matches(&req.context)
            && self.auth.matches(&req.subject.auth)
    }
}

/// One entry of the anonymous allowlist (layer 1): which unauthenticated
/// requests, from which source network, may proceed to the later layers, and
/// the transport floor that replaces `required_sec` for them. It is not an
/// Allow by itself: layers 3-5 still apply.
///
/// Constructed only through [`AnonymousGrant::new`], which enforces the
/// module's construction refusals: the entry names its source network
/// (there is no "any network" form — the stricter option of Q-164 item 3),
/// that network is [`IpScope::Internal`] and nothing else, and the entry
/// never names every resource. docs/15 §6 lists the anonymous allowlist as
/// "only these, from the internal network"; A-51 (Q-170 item 3) decided
/// that an entry for [`IpScope::External`] cannot exist, so no allowlist
/// admits an anonymous request from the external network.
///
/// Spec: docs/11 §4 (`anon_allowlist`; "anonymous allowlist (rootDSE, CLDAP
/// ping) → configured minimum"); docs/15 §6; docs/06 §5.1; docs/05 §3
/// (CLDAP / anonymous: rootDSE only); [MS-ADTS] 5.1.3 (with
/// fLDAPBlockAnonOps "anonymous (unauthenticated) users are limited to
/// performing rootDSE searches and binds"); Q-164 items 2-3 (A-48); Q-170
/// item 3 (A-51).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymousGrant {
    action: ActionMatch,
    resource: ResourceMatch,
    min_transport: TransportSec,
    src_net: IpScope,
}

impl AnonymousGrant {
    /// An allowlist entry for `action` on `resource` from `src_net`, with
    /// the transport minimum `min_transport`.
    ///
    /// [`RuleError::UnboundedAnonymousResource`] if `resource` is
    /// [`ResourceMatch::Any`] — DELIBERATE, stricter than Q-164 asked (it
    /// named the empty subtree; `Any` is the same "every object" match in
    /// explicit form, and docs/15 §6 admits only the listed resources). An
    /// empty subtree cannot reach here at all ([`SubtreeBase`]).
    ///
    /// [`RuleError::AnonymousExternalNetwork`] if `src_net` is anything but
    /// [`IpScope::Internal`] (docs/15 §6: "from the internal network"; A-51,
    /// Q-170 item 3). The resource is checked first, so an entry refused on
    /// both counts reports `UnboundedAnonymousResource`.
    /// Spec: docs/15 §6; Q-164 items 2-3 (A-48); Q-170 item 3 (A-51).
    pub fn new(
        action: ActionMatch,
        resource: ResourceMatch,
        min_transport: TransportSec,
        src_net: IpScope,
    ) -> Result<AnonymousGrant, RuleError> {
        if matches!(resource, ResourceMatch::Any) {
            return Err(RuleError::UnboundedAnonymousResource);
        }
        // Spec: docs/15 §6 ("only these, from the internal network"); A-51
        // (Q-170 item 3): External is forbidden in the allowlist. Written as
        // "anything but Internal", so a network value added to `IpScope`
        // later is refused here too (fail closed) rather than admitted.
        if !matches!(src_net, IpScope::Internal) {
            return Err(RuleError::AnonymousExternalNetwork);
        }
        Ok(AnonymousGrant {
            action,
            resource,
            min_transport,
            src_net,
        })
    }

    /// Which actions.
    #[must_use]
    pub fn action(&self) -> &ActionMatch {
        &self.action
    }

    /// Which resources (never [`ResourceMatch::Any`]).
    #[must_use]
    pub fn resource(&self) -> &ResourceMatch {
        &self.resource
    }

    /// The configured transport minimum for these requests.
    #[must_use]
    pub fn min_transport(&self) -> TransportSec {
        self.min_transport
    }

    /// The only source network this entry admits — always
    /// [`IpScope::Internal`] ([`AnonymousGrant::new`]; docs/15 §6, A-51).
    #[must_use]
    pub fn src_net(&self) -> IpScope {
        self.src_net
    }

    /// `true` if the entry admits `req`: its action, its resource and its
    /// source network (`Context.src_net`, which must be the internal one)
    /// all match. Spec: docs/11 §4 (`anon_allowlist(req)`); docs/15 §6
    /// ("from the internal network"); A-51 (Q-170 item 3).
    #[must_use]
    pub fn matches(&self, req: &AccessRequest) -> bool {
        self.action.matches(&req.action)
            && self.resource.matches(&req.resource)
            && self.src_net == req.context.src_net
    }
}

/// The version of a policy snapshot. Spec: docs/11 §6, §9 (the cache key
/// includes the policy version), D39.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion(pub u64);

/// A consistent, versioned set of global rules plus the anonymous allowlist.
/// Every decision is evaluated against one snapshot, so it is reproducible
/// (P9, D39). Every rule and allowlist entry passed in has already passed
/// its construction checks ([`SubtreeBase::new`], [`AnonymousGrant::new`]);
/// a loader that met a [`RuleError`] builds no snapshot at all (module
/// documentation). Spec: docs/11 §3, §6; docs/06 §9 (D17).
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

/// Collect the applying rules ([`Rule::applies`]). Does nothing beyond
/// matching and collecting. Spec: docs/11 §4 (`eval_rules`).
pub(crate) fn eval_rules(req: &AccessRequest, pol: &PolicySnapshot) -> CoarseResult {
    let mut result = CoarseResult {
        denied_by: None,
        allowed: false,
        obligations: Vec::new(),
    };
    for rule in pol.rules() {
        if !rule.applies(req) {
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
