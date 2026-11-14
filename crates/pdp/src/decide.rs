//! The decision algorithm.
//!
//! Spec: docs/11 §4 (`decide`: five layers, each deny-by-default; an explicit
//! Deny at any layer stops immediately), §8 (obligations), §10 (P1-P9),
//! D37-D40; docs/06 §5-§6; docs/05 §2.
//!
//! `decide` is a pure, total function of (request, policy snapshot, PIP):
//! - no clock is read — only `Context.time` (P9); no randomness; no global
//!   or hidden state; no I/O except through the `Pip` passed in;
//! - it never panics, and every internal failure (malformed request, PIP
//!   error or absence) is a Deny (P1, D40);
//! - every decision carries exactly one `Obligation::Audit` (P7).
//!
//! Before the five layers, the request is checked for well-formedness (the
//! action and the resource must belong together); a malformed request is
//! denied (P1, D40). Between layers 2 and 3, `Subject.tier` is checked against
//! `Pip::tier_of` (P3: the tier is "derived by the PIP — not claimed").
//!
//! Out of scope (documented, not implemented): the decision and
//! group-expansion cache with invalidation of docs/11 §9 (D41). This core is
//! stateless, so every decision reflects exactly the snapshot it is given and
//! a deny-widening change is visible on the next call (P8).

use crate::access_check::rights::{
    ACCESS_SYSTEM_SECURITY, RIGHT_DELETE, RIGHT_DS_LIST_CONTENTS, RIGHT_DS_READ_PROPERTY,
    RIGHT_DS_WRITE_PROPERTY, RIGHT_READ_CONTROL,
};
use crate::access_check::{acl_grants, DirObjectContext, Right};
use crate::model::{
    AccessRequest, Action, AttrId, AuthContext, AuthStrength, Decision, Effect, Obligation,
    ReasonCode, Resource, RlKey, Tier, Transport, TransportSec,
};
use crate::pip::{AttrClass, Pip, PipError};
use crate::policy::{eval_rules, PolicySnapshot};

/// Decide an access request. Spec: docs/11 §4.
#[must_use]
pub fn decide<P: Pip + ?Sized>(req: &AccessRequest, pol: &PolicySnapshot, pip: &P) -> Decision {
    match evaluate(req, pol, pip) {
        Ok(obligations) => Decision {
            effect: Effect::Allow,
            obligations,
            reason: ReasonCode::Allowed,
        },
        // Every deny carries exactly one Audit obligation (P7).
        Err(reason) => Decision {
            effect: Effect::Deny,
            obligations: vec![Obligation::Audit],
            reason,
        },
    }
}

/// A PIP failure or absence is a Deny. Spec: D40; docs/06 §6 ("missing
/// information or a PIP timeout → DENY").
fn from_pip<T>(result: Result<T, PipError>) -> Result<T, ReasonCode> {
    result.map_err(|_| ReasonCode::PipFailure)
}

/// The five layers. `Ok` carries the Allow obligations; `Err` the deny
/// reason. Spec: docs/11 §4.
fn evaluate<P: Pip + ?Sized>(
    req: &AccessRequest,
    pol: &PolicySnapshot,
    pip: &P,
) -> Result<Vec<Obligation>, ReasonCode> {
    // Well-formedness (P1, D40).
    if !well_formed(&req.action, &req.resource) {
        return Err(ReasonCode::InvalidRequest);
    }

    // Layer 1 — Authn. "if req.subject.auth.strength == Unauth &&
    // !anon_allowlist(req) { return Deny(Unauthenticated) }". An identity not
    // established from a verified ticket counts as unauthenticated (docs/11
    // §1 `ticket_verified`; fail closed). Some actions are never admitted
    // anonymously, whatever the allowlist says (`never_anonymous`, A-22).
    let authenticated = is_authenticated(&req.subject.auth);
    let required = if authenticated {
        required_sec_on(&req.action, req.context.transport)
    } else if never_anonymous(&req.action) {
        return Err(ReasonCode::Unauthenticated);
    } else {
        match anonymous_floor(req, pol) {
            Some(floor) => floor,
            None => return Err(ReasonCode::Unauthenticated),
        }
    };

    // Layer 2 — Transport. "if !meets(req.context.transport_sec,
    // required_sec(req.action)) { return Deny(WeakTransport) }" — on every
    // transport alike: the `LocalIpc` write exemption of A-74 is gone (R2,
    // A-102: the admin channel's PEP reports `channel_bound` only once keyd
    // verified each AP-REQ's operation binding).
    if !req.context.transport_sec.meets(required) {
        return Err(ReasonCode::WeakTransport);
    }

    // P3: the tier is derived by the PIP, never claimed. The request's tier
    // must equal the PIP's answer; otherwise the Subject is not
    // authoritative.
    let pip_tier = from_pip(pip.tier_of(&req.subject.principal, &req.subject.groups))?;
    if pip_tier != req.subject.tier {
        return Err(ReasonCode::SubjectMismatch);
    }

    // Layer 3 — global (coarse) policy, deny by default. "if
    // coarse.has_deny() { return Deny(CoarseDeny) } if !coarse.has_allow() {
    // return Deny(NoGrant) }".
    let coarse = eval_rules(req, pol);
    if let Some(rule) = coarse.denied_by {
        return Err(ReasonCode::CoarseDeny(rule));
    }
    if !coarse.allowed {
        return Err(ReasonCode::NoGrant);
    }

    // Layer 4 — the tier invariant, above and independent of the ACL (P5;
    // project rule 5d, docs/11 §5 / D37 — a DELIBERATE addition with no
    // counterpart in [MS-DTYP] / [MS-ADTS]: Tier-0 objects are writable only
    // by Tier-0 subjects, whatever any ACL says). "if is_write(req.action) {
    // let obj_tier = pip.object_tier(req.resource); if obj_tier == Tier0 &&
    // req.subject.tier != Tier0 { return Deny(TierViolation) } }".
    if is_write(&req.action) {
        let object_tier = from_pip(pip.object_tier(&req.resource))?;
        if object_tier == Tier::Tier0 && req.subject.tier != Tier::Tier0 {
            return Err(ReasonCode::TierViolation);
        }
    }

    // Layer 5 — the object ACL and the attribute class (directory objects
    // only). The rootDSE is not a directory object and has no
    // nTSecurityDescriptor ([MS-ADTS] 3.1.1.3; docs/49 §5.2, R49-10): its
    // reads are decided by layers 1-3 alone.
    if let Resource::DirObject { dn, attr } = &req.resource {
        let sd = from_pip(pip.security_descriptor(dn))?;
        // The root of the object type tree is the most specific class; the
        // rest of the chain is named by deny object ACEs. Spec: [MS-ADTS]
        // 5.1.3.3.3, 3.1.1.2.4.3; A-28 (Q-081).
        let classes = from_pip(pip.object_classes(dn))?;
        let object = DirObjectContext {
            object_class: classes.most_specific.0,
            superclasses: classes.superclasses.iter().map(|c| c.0).collect(),
            object_sid: from_pip(pip.object_sid(dn))?,
        };
        let right = desired_right(&req.action, attr.as_ref(), pip)?;
        // "if !acl_grants(&req.subject, &pip.security_descriptor(dn),
        // desired_right(req.action)) { return Deny(Acl) }".
        if !acl_grants(&req.subject, &sd, &object, &right) {
            return Err(ReasonCode::Acl);
        }
        if let Some(a) = attr {
            match from_pip(pip.attr_class(a))? {
                // Project rule 5c (docs/11 §4-§5, D37) — DELIBERATE addition:
                // "Secret => return Deny(NoSuchPath)" — P6: unreachable, no
                // action reaches secret material, whatever the ACL grants.
                AttrClass::Secret => return Err(ReasonCode::NoSuchPath),
                // Project rule 5c: "Sensitive if !has_control_right(..) =>
                // return Deny(Sensitive)" — the attribute's control access
                // right ([MS-ADTS] 5.1.3.3.4) is required on top of the ACL
                // grant.
                AttrClass::Sensitive {
                    control_access_right,
                } => {
                    let control = Right::ControlAccess {
                        right: control_access_right.0,
                    };
                    if !acl_grants(&req.subject, &sd, &object, &control) {
                        return Err(ReasonCode::Sensitive);
                    }
                }
                AttrClass::Normal => {}
            }
        }
    }

    // "Allow(obligations: [Audit, RateLimit(rl_key(req)), ...])" — the
    // obligations of the matching Allow rules follow; they never contain a
    // second Audit (policy.rs), so there is exactly one (P7).
    let mut obligations = vec![
        Obligation::Audit,
        Obligation::RateLimit(RlKey {
            principal: req.subject.principal,
            class: req.action.class(),
        }),
    ];
    obligations.extend(coarse.obligations);
    Ok(obligations)
}

/// Does the action belong to the resource kind, and does a whole-object
/// action come without an attribute? Spec: docs/11 §1 (each `Action` names the
/// resource it applies to; `attr: None` for a whole-object operation), docs/06
/// §3.
///
/// Two directory-specific checks (narrowing only — each turns a request into
/// `InvalidRequest`):
/// - the rootDSE admits `DirRead` alone (Q-164 item 1: "`well_formed` only
///   with `DirRead`"): its attributes "are read-only" ([MS-ADTS] 3.1.1.3.2),
///   it is not an object (3.1.1.3), and a rootDSE request is a base-object
///   search of the empty base only (docs/49 §5.2, R49-10);
/// - a directory object never has the empty DN: "The rootDSE (empty DN)"
///   ([MS-ADTS] 3.1.1.3) is [`Resource::RootDse`], so
///   `DirObject { dn: <empty> }` is malformed (fail closed, D40) — the
///   spelling the rootDSE had before it had its own resource (docs/49 §5.2).
fn well_formed(action: &Action, resource: &Resource) -> bool {
    if let Resource::DirObject { dn, .. } = resource {
        if dn.rdns().is_empty() {
            return false;
        }
    }
    matches!(
        (action, resource),
        (
            Action::DirRead | Action::DirWrite,
            Resource::DirObject { .. }
        ) | (
            Action::DirAddChild(_)
                | Action::DirDelete
                | Action::DirList
                | Action::DirControlRight(_),
            Resource::DirObject { attr: None, .. },
        ) | (Action::DirRead, Resource::RootDse)
            | (Action::RpcCall, Resource::RpcMethod { .. })
            | (Action::FileRead | Action::FileWrite, Resource::File { .. })
            | (Action::DnsUpdate | Action::DnsXfer, Resource::Dns { .. })
            | (
                Action::KdcAs | Action::KdcTgs | Action::KdcS4u2Self | Action::KdcS4u2Proxy,
                Resource::Kerberos { .. },
            )
            | (Action::PolicyAdmin, Resource::Policy { .. })
    )
}

/// Authenticated = a Kerberos-family strength AND an identity established
/// from a verified ticket. Spec: docs/11 §1 (`AuthStrength`,
/// `ticket_verified`), §4 layer 1; docs/06 §5.1 ("everything else requires
/// Kerberos").
fn is_authenticated(auth: &AuthContext) -> bool {
    auth.strength != AuthStrength::Unauth && auth.ticket_verified
}

/// The configured transport minimum for an unauthenticated request that is
/// on the anonymous allowlist, or `None` if it is not. An entry admits a
/// request only from the source network it names, which is always the
/// internal one (`AnonymousGrant::matches`, `AnonymousGrant::new`; docs/15
/// §6, "from the internal network"; Q-164 item 3; A-51). If several
/// entries match, all of their minimums apply (fail closed). Spec: docs/11 §4
/// (`anon_allowlist`; "anonymous allowlist (rootDSE, CLDAP ping) → configured
/// minimum").
fn anonymous_floor(req: &AccessRequest, pol: &PolicySnapshot) -> Option<TransportSec> {
    pol.anonymous_allowlist()
        .iter()
        .filter(|g| g.matches(req))
        .fold(None, |floor: Option<TransportSec>, g| {
            Some(floor.unwrap_or(TransportSec::NONE).union(g.min_transport()))
        })
}

/// The transport floor of an authenticated request. Spec: docs/11 §4
/// (`required_sec`: "write / secret operation → {encrypted, sealed,
/// channel_bound}; authenticated read → {encrypted}"); docs/06 §5 item 2
/// ("every write requires an encrypted channel + channel binding; every RPC
/// requires PKT_PRIVACY"); docs/05 §7 ("bind without PKT_PRIVACY is
/// rejected").
///
/// Per-action floors (project decision A-22, Q-052 item 4 resolved):
/// - `RpcCall`: the RPC floor of docs/06 §5 (PKT_PRIVACY = encrypted +
///   sealed): ncacn_ip_tcp has no channel binding, so the write floor would
///   make every RPC impossible.
/// - `DnsUpdate`: NO transport floor. A dynamic update is protected only by
///   its GSS-TSIG signature, which signs but cannot encrypt (docs/40 §2,
///   D166; RFC 3645 / RFC 8945 as cited there). PEP contract: an
///   authenticated `Subject` for `DnsUpdate` may come only from a verified
///   GSS-TSIG signature over that update message. An unauthenticated
///   `DnsUpdate` is always denied at layer 1 — the anonymous allowlist never
///   applies to it (docs/40 §2: no unauthenticated update), so there is no
///   anonymous floor for it either.
/// - `KdcAs`, `KdcTgs`, `KdcS4u2Self`, `KdcS4u2Proxy`: NO transport floor.
///   Kerberos messages carry their own protection, verified inside keyd
///   (pre-authentication; TGT + authenticator + req-body checksum). FAST is
///   a separate input (`AuthContext.armored`, docs/11 §1), not a transport
///   property, and is not mapped to `encrypted`; it is made mandatory by
///   policy rules (`Match.auth`, D126; docs/48 §7.2; Q-127 interim — see
///   [`crate::mandatory_fast`]), not by this table.
/// - Every other write (`is_write`): the write floor; every other read
///   (including `DnsXfer`): the read floor.
#[must_use]
pub fn required_sec(action: &Action) -> TransportSec {
    const WRITE_FLOOR: TransportSec = TransportSec {
        encrypted: true,
        sealed: true,
        channel_bound: true,
    };
    const RPC_FLOOR: TransportSec = TransportSec {
        encrypted: true,
        sealed: true,
        channel_bound: false,
    };
    const READ_FLOOR: TransportSec = TransportSec {
        encrypted: true,
        sealed: false,
        channel_bound: false,
    };
    match action {
        Action::RpcCall => RPC_FLOOR,
        // A-22: protected at the message level, not by the transport.
        Action::DnsUpdate
        | Action::KdcAs
        | Action::KdcTgs
        | Action::KdcS4u2Self
        | Action::KdcS4u2Proxy => TransportSec::NONE,
        a if is_write(a) => WRITE_FLOOR,
        _ => READ_FLOOR,
    }
}

/// The transport floor of an authenticated request that arrived on
/// `transport`: exactly [`required_sec`], on **every** transport — the rule
/// of docs/11 §4 with no exception.
///
/// History: A-74 (Q-292 option (a)) exempted [`Transport::LocalIpc`] — the
/// admin plane's `dird-admin.sock` — from `channel_bound`, because no admin
/// AP-REQ was bound to its operation (a documented residual: a compromised
/// admind could attach an administrator's AP-REQ to another operation). R2
/// (docs/52 §3.2, §5 item 4; decision A-102) removed the cause: every admin
/// AP-REQ's Authenticator `cksum` binds the operation digest (RFC 4120
/// §5.5.1, key usage 10), keyd verifies it, and the admin PEP reports
/// `channel_bound: true` only for a request every ticket of which keyd
/// verified bound to it. So the exemption — an instance fix — is gone, and
/// an unbound admin write is `WeakTransport` like any other.
///
/// Every variant is listed, so a transport added later must take a
/// position here rather than inherit a floor by default.
///
/// Spec: docs/11 §4 (`required_sec`); docs/52 §3.2, §5 item 4 (R2);
/// docs/questions/Q-463 (A-102, superseding Q-292 / A-74 option (a)).
#[must_use]
pub fn required_sec_on(action: &Action, transport: Transport) -> TransportSec {
    let floor = required_sec(action);
    match transport {
        Transport::LocalIpc
        | Transport::Ldap
        | Transport::Ldaps
        | Transport::LdapSasl
        | Transport::Cldap
        | Transport::SmbEnc
        | Transport::NcacnIpTcpPrivacy
        | Transport::Dns
        | Transport::Kerberos => floor,
    }
}

/// Actions the anonymous allowlist can never admit, whatever the policy
/// says. Spec: docs/40 §2 / D166 ("dynamic update only GSS-TSIG signed ...
/// no unauthenticated update"); A-22 (Q-052 item 4) — with no transport
/// floor for `DnsUpdate`, layer 1 alone keeps it closed to anonymous callers.
fn never_anonymous(action: &Action) -> bool {
    matches!(action, Action::DnsUpdate)
}

/// Actions that may modify state, for the tier invariant of layer 4 (P5).
/// Conservative: an RPC call and a control access right may modify state
/// (e.g. a password reset), so both count as writes. Spec: docs/11 §4
/// (`is_write`), §10 P5; docs/06 §10.
#[must_use]
pub fn is_write(action: &Action) -> bool {
    match action {
        Action::DirWrite
        | Action::DirAddChild(_)
        | Action::DirDelete
        | Action::DirControlRight(_)
        | Action::RpcCall
        | Action::FileWrite
        | Action::DnsUpdate
        | Action::PolicyAdmin => true,
        Action::DirRead
        | Action::DirList
        | Action::FileRead
        | Action::DnsXfer
        | Action::KdcAs
        | Action::KdcTgs
        | Action::KdcS4u2Self
        | Action::KdcS4u2Proxy => false,
    }
}

/// The right a directory action needs. Spec: docs/11 §4
/// (`desired_right(req.action)`):
/// - `DirRead` / `DirWrite` of an attribute: RIGHT_DS_READ_PROPERTY /
///   RIGHT_DS_WRITE_PROPERTY on that attribute ([MS-ADTS] 3.1.1.4.3:
///   "RIGHT_DS_READ_PROPERTY on OA"; 5.1.3.2 RP / WP); of the whole object:
///   the same right on the object ([MS-ADTS] 5.1.3.2: "If ObjectType does not
///   contain a GUID, the ACE controls the right to read all attributes");
/// - `DirRead` of nTSecurityDescriptor ([`AttrId::NT_SECURITY_DESCRIPTOR`]):
///   [MS-ADTS] 3.1.1.4.4, "OA: nTSecurityDescriptor — Requires right(s):
///   (ACCESS_SYSTEM_SECURITY) and (RIGHT_READ_CONTROL)" — both, on the
///   object, instead of RIGHT_DS_READ_PROPERTY (Q-164, A-48: asking only
///   RIGHT_DS_READ_PROPERTY granted more than 3.1.1.4.4 allows). The request
///   names the whole descriptor: the resource cannot name a part of it, and
///   with no LDAP_SERVER_SD_FLAGS_OID control a read covers owner, group,
///   DACL and SACL ([MS-ADTS] 3.1.1.3.4.1.11) — rights per part are Q-164
///   item 4, a later task. ACCESS_SYSTEM_SECURITY is granted only through
///   SeSecurityPrivilege ([MS-DTYP] 2.5.3.2: "IF Token.Privileges contains
///   SeSecurityPrivilege THEN ... ELSE ... Return access_denied"; 2.4.3:
///   "This bit MUST NOT be set in an ACE that is part of a DACL"), and a
///   `Subject` carries no privileges, so [`acl_grants`] refuses this right
///   for every descriptor: the read is always denied (fail closed);
/// - `DirAddChild(c)`: RIGHT_DS_CREATE_CHILD for class c ([MS-ADTS]
///   3.1.1.5.2.1);
/// - `DirDelete`: RIGHT_DELETE on the object ([MS-ADTS] 3.1.1.5.5.4). The
///   alternative "RIGHT_DS_DELETE_CHILD on the parent" needs the parent's
///   descriptor, which a docs/11 `Resource` does not name; it is not
///   implemented (fewer grants, never more);
/// - `DirList`: RIGHT_DS_LIST_CONTENTS on the container ([MS-ADTS]
///   3.1.1.4.3, 5.1.3.2 LC);
/// - `DirControlRight(g)`: the control access right g ([MS-ADTS]
///   5.1.3.3.4).
fn desired_right<P: Pip + ?Sized>(
    action: &Action,
    attr: Option<&AttrId>,
    pip: &P,
) -> Result<Right, ReasonCode> {
    let property = |mask: u32, a: &AttrId| -> Result<Right, ReasonCode> {
        Ok(Right::Property {
            mask,
            property_set: from_pip(pip.property_set(a))?,
            attribute: a.0,
        })
    };
    match (action, attr) {
        // [MS-ADTS] 3.1.1.4.4: "(ACCESS_SYSTEM_SECURITY) and
        // (RIGHT_READ_CONTROL)" — never grantable here (doc comment above).
        (Action::DirRead, Some(a)) if *a == AttrId::NT_SECURITY_DESCRIPTOR => Ok(Right::Object {
            mask: ACCESS_SYSTEM_SECURITY | RIGHT_READ_CONTROL,
        }),
        (Action::DirRead, Some(a)) => property(RIGHT_DS_READ_PROPERTY, a),
        (Action::DirRead, None) => Ok(Right::Object {
            mask: RIGHT_DS_READ_PROPERTY,
        }),
        (Action::DirWrite, Some(a)) => property(RIGHT_DS_WRITE_PROPERTY, a),
        (Action::DirWrite, None) => Ok(Right::Object {
            mask: RIGHT_DS_WRITE_PROPERTY,
        }),
        (Action::DirAddChild(class), None) => Ok(Right::CreateChild { class: class.0 }),
        (Action::DirDelete, None) => Ok(Right::Object { mask: RIGHT_DELETE }),
        (Action::DirList, None) => Ok(Right::Object {
            mask: RIGHT_DS_LIST_CONTENTS,
        }),
        (Action::DirControlRight(right), None) => Ok(Right::ControlAccess { right: right.0 }),
        _ => Err(ReasonCode::InvalidRequest),
    }
}
