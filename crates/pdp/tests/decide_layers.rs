//! `decide`, layer by layer.
//!
//! Source: docs/11 §4 (the five layers and their deny reasons), §3 (rule
//! model), §1b / §8 (obligations), §10 (P3, P7); docs/06 §5-§6; D40. Hand-made
//! cases; no vector from another implementation.

mod common;

use std::collections::BTreeMap;

use common::*;
use pdp::access_check::rights::*;
use pdp::{
    decide, required_sec, AccessRequest, Action, ActionClass, ActionMatch, AnonymousGrant,
    AuthStrength, ClaimId, ClaimValue, Constraint, ContextMatch, Dn, Effect, Instant, IpScope,
    KerbResKind, Match, Obligation, PolicySnapshot, PolicyVersion, ReasonCode, Resource,
    ResourceMatch, Rule, RuleId, SubjectMatch, Tier, TimeWindow, TransportSec,
};

fn readable_pip() -> MockPip {
    MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_READ, group())]))
}

fn read_req() -> AccessRequest {
    dir_request(the_user(), Action::DirRead, Some(attr_alone()))
}

fn rule(id: u32, effect: Effect, when: Match) -> Rule {
    Rule {
        id: RuleId(id),
        effect,
        when,
        obligations: vec![],
    }
}

// ------------------------------------------------------- well-formedness ----

/// A malformed request (action and resource that do not belong together, or
/// a whole-object action with an attribute) is denied (P1, D40).
#[test]
fn malformed_requests_are_denied() {
    let pip = readable_pip();
    let pol = policy(vec![allow_everything(1)]);
    let mut list_with_attr = dir_request(the_user(), Action::DirList, Some(attr_alone()));
    assert_eq!(
        decide(&list_with_attr, &pol, &pip).reason,
        ReasonCode::InvalidRequest
    );
    list_with_attr.action = Action::FileRead;
    assert_eq!(
        decide(&list_with_attr, &pol, &pip).reason,
        ReasonCode::InvalidRequest
    );
}

// --------------------------------------------------------------- layer 1 ----

/// Layer 1: "if req.subject.auth.strength == Unauth && !anon_allowlist(req)
/// { return Deny(Unauthenticated) }" (docs/11 §4).
#[test]
fn layer1_unauthenticated_is_denied() {
    let pip = readable_pip();
    let pol = policy(vec![allow_everything(1)]);
    let mut req = read_req();
    req.subject.auth.strength = AuthStrength::Unauth;
    assert_eq!(decide(&req, &pol, &pip).reason, ReasonCode::Unauthenticated);
}

/// Layer 1: an identity not established from a verified ticket counts as
/// unauthenticated (docs/11 §1 `ticket_verified`; fail closed).
#[test]
fn layer1_unverified_ticket_is_unauthenticated() {
    let pip = readable_pip();
    let pol = policy(vec![allow_everything(1)]);
    let mut req = read_req();
    req.subject.auth.ticket_verified = false;
    assert_eq!(decide(&req, &pol, &pip).reason, ReasonCode::Unauthenticated);
}

/// Layer 1: the anonymous allowlist lets an unauthenticated request through
/// to the later layers (it is not an Allow by itself) and replaces
/// `required_sec` by its configured minimum (docs/11 §4; docs/05 §3: rootDSE
/// only). The rootDSE is `Resource::RootDse` and the entry names the source
/// network (docs/49 §5.2, R49-10; docs/15 §6; Q-164 items 1, 3) — the
/// former spelling, a subtree with an empty base, is refused (Q-164 item 2).
#[test]
fn layer1_anonymous_allowlist() {
    let pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_READ, everyone())]));
    let grant = AnonymousGrant::new(
        ActionMatch::Exact(Action::DirRead),
        ResourceMatch::RootDse,
        TransportSec::NONE,
        IpScope::Internal,
    )
    .expect("a bounded grant");
    let mut anon = subject(everyone(), &[], Tier::Tier1);
    anon.auth.strength = AuthStrength::Unauth;
    anon.auth.ticket_verified = false;
    let mut req = AccessRequest {
        subject: anon,
        resource: Resource::RootDse,
        action: Action::DirRead,
        context: strong_context(),
    };
    req.context.transport_sec = TransportSec::NONE;

    // Allowlisted but no Allow rule: layer 3 still denies.
    let no_rules = PolicySnapshot::new(PolicyVersion(1), vec![], vec![grant.clone()]);
    assert_eq!(decide(&req, &no_rules, &pip).reason, ReasonCode::NoGrant);

    // Allowlisted and an Allow rule: allowed over an unprotected transport.
    let pol = PolicySnapshot::new(PolicyVersion(1), vec![allow_everything(1)], vec![grant]);
    assert_eq!(decide(&req, &pol, &pip).effect, Effect::Allow);

    // Not allowlisted (a directory object): unauthenticated.
    req.resource = Resource::DirObject {
        dn: obj_dn(),
        attr: None,
    };
    assert_eq!(decide(&req, &pol, &pip).reason, ReasonCode::Unauthenticated);

    // The former spelling of the rootDSE cannot be written any more.
    assert_eq!(
        pdp::SubtreeBase::new(Dn::new(vec![])),
        Err(pdp::RuleError::EmptySubtreeBase)
    );
}

// --------------------------------------------------------------- layer 2 ----

/// Layer 2: `required_sec` — write → {encrypted, sealed, channel_bound};
/// authenticated read → {encrypted}; RPC → PKT_PRIVACY (docs/11 §4; docs/06
/// §5 item 2); DnsUpdate and the Kdc* actions → no transport floor (A-22:
/// GSS-TSIG / Kerberos protect the message itself; docs/40 §2, D166).
#[test]
fn layer2_required_sec_table() {
    let all = TransportSec {
        encrypted: true,
        sealed: true,
        channel_bound: true,
    };
    let encrypted = TransportSec {
        encrypted: true,
        sealed: false,
        channel_bound: false,
    };
    let privacy = TransportSec {
        encrypted: true,
        sealed: true,
        channel_bound: false,
    };
    assert_eq!(required_sec(&Action::DirWrite), all);
    assert_eq!(required_sec(&Action::DirDelete), all);
    assert_eq!(required_sec(&Action::FileWrite), all);
    assert_eq!(required_sec(&Action::PolicyAdmin), all);
    assert_eq!(required_sec(&Action::DirRead), encrypted);
    assert_eq!(required_sec(&Action::FileRead), encrypted);
    assert_eq!(required_sec(&Action::DnsXfer), encrypted);
    assert_eq!(required_sec(&Action::RpcCall), privacy);
    for action in [
        Action::DnsUpdate,
        Action::KdcAs,
        Action::KdcTgs,
        Action::KdcS4u2Self,
        Action::KdcS4u2Proxy,
    ] {
        assert_eq!(required_sec(&action), TransportSec::NONE, "{action:?}");
    }
}

/// A-22: an authenticated DnsUpdate and each Kdc* action pass layers 1-2
/// over a transport with no protection at all; with a granting policy
/// (control) they are allowed, so the outcome is decided by the later layers.
#[test]
fn layer2_message_protected_actions_have_no_transport_floor() {
    let pip = readable_pip();
    let pol = policy(vec![allow_everything(1)]);
    let cases = [
        (
            Action::DnsUpdate,
            Resource::Dns {
                zone: pdp::ZoneId("test".into()),
                record: Some(pdp::RecordKey("host1".into())),
            },
        ),
        (
            Action::KdcAs,
            Resource::Kerberos {
                kind: KerbResKind::Tgt,
            },
        ),
        (
            Action::KdcTgs,
            Resource::Kerberos {
                kind: KerbResKind::Service(pdp::Spn("ldap/dc1.test".into())),
            },
        ),
        (
            Action::KdcS4u2Self,
            Resource::Kerberos {
                kind: KerbResKind::Service(pdp::Spn("http/web1.test".into())),
            },
        ),
        (
            Action::KdcS4u2Proxy,
            Resource::Kerberos {
                kind: KerbResKind::Service(pdp::Spn("cifs/fs1.test".into())),
            },
        ),
    ];
    for (action, resource) in cases {
        let mut req = AccessRequest {
            subject: the_user(),
            resource,
            action: action.clone(),
            context: strong_context(),
        };
        req.context.transport_sec = TransportSec::NONE;
        let d = decide(&req, &pol, &pip);
        assert_eq!(d.effect, Effect::Allow, "{action:?}: {d:?}");
        // The later layers still decide: no Allow rule ⇒ NoGrant, not a
        // transport failure.
        assert_eq!(
            decide(&req, &policy(vec![]), &pip).reason,
            ReasonCode::NoGrant,
            "{action:?}"
        );
    }
}

/// A-22 / docs/40 §2 ("no unauthenticated update"): an unauthenticated
/// DnsUpdate is denied at layer 1 — even if the anonymous allowlist names it.
#[test]
fn layer1_unauthenticated_dns_update_is_denied() {
    let pip = readable_pip();
    let mut req = AccessRequest {
        subject: the_user(),
        resource: Resource::Dns {
            zone: pdp::ZoneId("test".into()),
            record: None,
        },
        action: Action::DnsUpdate,
        context: strong_context(),
    };
    req.subject.auth.strength = AuthStrength::Unauth;
    req.subject.auth.ticket_verified = false;
    let allowlisting = PolicySnapshot::new(
        PolicyVersion(1),
        vec![allow_everything(1)],
        vec![AnonymousGrant::new(
            ActionMatch::Exact(Action::DnsUpdate),
            ResourceMatch::Dns {
                zone: pdp::ZoneId("test".into()),
            },
            TransportSec::NONE,
            IpScope::Internal,
        )
        .expect("a bounded grant")],
    );
    for pol in [policy(vec![allow_everything(1)]), allowlisting] {
        assert_eq!(decide(&req, &pol, &pip).reason, ReasonCode::Unauthenticated);
    }
}

/// Layer 2: "if !meets(req.context.transport_sec, required_sec(req.action))
/// { return Deny(WeakTransport) }" — checked before any rule or ACL.
#[test]
fn layer2_weak_transport_is_denied() {
    let pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_ALL, group())]));
    let pol = policy(vec![allow_everything(1)]);

    let mut write = dir_request(the_user(), Action::DirWrite, Some(attr_alone()));
    write.context.transport_sec.channel_bound = false;
    assert_eq!(decide(&write, &pol, &pip).reason, ReasonCode::WeakTransport);
    // A directory write with no transport protection at all (A-22 leaves
    // directory writes on the write floor).
    write.context.transport_sec = TransportSec::NONE;
    assert_eq!(decide(&write, &pol, &pip).reason, ReasonCode::WeakTransport);

    let mut read = read_req();
    read.context.transport_sec = TransportSec::NONE;
    assert_eq!(decide(&read, &pol, &pip).reason, ReasonCode::WeakTransport);
    read.context.transport_sec.encrypted = true;
    assert_eq!(decide(&read, &pol, &pip).effect, Effect::Allow);
}

// -------------------------------------------------------------------- P3 ----

/// P3: `Subject.tier` must agree with the PIP; a request claiming Tier 0 for
/// a principal the PIP places in Tier 1 is denied.
#[test]
fn p3_subject_tier_must_match_the_pip() {
    let pip = readable_pip();
    let pol = policy(vec![allow_everything(1)]);
    let mut req = read_req();
    req.subject.tier = Tier::Tier0;
    assert_eq!(decide(&req, &pol, &pip).reason, ReasonCode::SubjectMismatch);
}

// --------------------------------------------------------------- layer 3 ----

/// Layer 3: no matching Allow ⇒ Deny(NoGrant) (docs/11 §3: "no matching
/// Allow → Deny").
#[test]
fn layer3_no_allow_rule_is_denied() {
    let pip = readable_pip();
    assert_eq!(
        decide(&read_req(), &policy(vec![]), &pip).reason,
        ReasonCode::NoGrant
    );
    let only_rpc = rule(
        7,
        Effect::Allow,
        Match {
            action: ActionMatch::Class(ActionClass::Rpc),
            ..match_all()
        },
    );
    assert_eq!(
        decide(&read_req(), &policy(vec![only_rpc]), &pip).reason,
        ReasonCode::NoGrant
    );
}

/// Layer 3: an explicit Deny wins over any Allow, whatever the rule order
/// (docs/11 §3: "explicit Deny wins").
#[test]
fn layer3_explicit_deny_wins() {
    let pip = readable_pip();
    let deny_group = rule(
        9,
        Effect::Deny,
        Match {
            subject: SubjectMatch::MemberOf(group()),
            ..match_all()
        },
    );
    for rules in [
        vec![allow_everything(1), deny_group.clone()],
        vec![deny_group.clone(), allow_everything(1)],
    ] {
        let d = decide(&read_req(), &policy(rules), &pip);
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.reason, ReasonCode::CoarseDeny(RuleId(9)));
    }
}

/// Layer 3 matchers: DN subtree, principal, tier, claim, source zone,
/// transport floor and time window (docs/11 §3).
#[test]
fn layer3_matchers() {
    let pip = readable_pip();
    let allowed = |when: Match, req: &AccessRequest| {
        decide(req, &policy(vec![rule(1, Effect::Allow, when)]), &pip).effect == Effect::Allow
    };
    let req = read_req();

    let inside = Match {
        resource: subtree(parent_dn()),
        ..match_all()
    };
    assert!(allowed(inside, &req));
    let elsewhere = Match {
        resource: subtree(Dn::new(vec!["ou=other".into(), "dc=test".into()])),
        ..match_all()
    };
    assert!(!allowed(elsewhere, &req));

    assert!(allowed(
        Match {
            subject: SubjectMatch::Principal(user()),
            ..match_all()
        },
        &req
    ));
    assert!(!allowed(
        Match {
            subject: SubjectMatch::Principal(group()),
            ..match_all()
        },
        &req
    ));
    assert!(allowed(
        Match {
            subject: SubjectMatch::Tier(Tier::Tier1),
            ..match_all()
        },
        &req
    ));
    assert!(!allowed(
        Match {
            subject: SubjectMatch::Tier(Tier::Tier0),
            ..match_all()
        },
        &req
    ));

    let claim = SubjectMatch::Claim(ClaimId("dept".into()), ClaimValue::Text("it".into()));
    assert!(!allowed(
        Match {
            subject: claim.clone(),
            ..match_all()
        },
        &req
    ));
    let mut with_claim = req.clone();
    with_claim.subject.claims =
        BTreeMap::from([(ClaimId("dept".into()), ClaimValue::Text("it".into()))]);
    assert!(allowed(
        Match {
            subject: claim,
            ..match_all()
        },
        &with_claim
    ));

    let external_only = Match {
        context: ContextMatch {
            src_net: Some(IpScope::External),
            ..ContextMatch::ANY
        },
        ..match_all()
    };
    assert!(!allowed(external_only, &req));

    let window = TimeWindow::new(Instant(10), Instant(20)).expect("ordered");
    let timed = Match {
        context: ContextMatch {
            time_window: Some(window),
            ..ContextMatch::ANY
        },
        ..match_all()
    };
    let mut at = req.clone();
    at.context.time = Instant(15);
    assert!(allowed(timed.clone(), &at));
    at.context.time = Instant(21);
    assert!(!allowed(timed, &at));
    assert!(TimeWindow::new(Instant(20), Instant(10)).is_none());

    let sealed_only = Match {
        context: ContextMatch {
            min_transport: TransportSec {
                encrypted: true,
                sealed: true,
                channel_bound: false,
            },
            ..ContextMatch::ANY
        },
        ..match_all()
    };
    let mut unsealed = req.clone();
    unsealed.context.transport_sec.sealed = false;
    assert!(!allowed(sealed_only, &unsealed));

    let kerberos_tgt = Match {
        resource: ResourceMatch::Kerberos {
            kind: Some(KerbResKind::Tgt),
        },
        ..match_all()
    };
    assert!(!allowed(kerberos_tgt, &req));
}

// --------------------------------------------------------------- layer 5 ----

/// Layer 5: the ACL is consulted only for directory objects, after the rules
/// allowed; an ACL that does not grant ⇒ Deny(Acl).
#[test]
fn layer5_acl_denies() {
    let pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_DS_READ_PROPERTY, other_group())]));
    let d = decide(&read_req(), &policy(vec![allow_everything(1)]), &pip);
    assert_eq!(d.reason, ReasonCode::Acl);
}

/// Layer 5: each directory action asks for the right docs/11 §4
/// `desired_right` names ([MS-ADTS] 3.1.1.4.3, 3.1.1.5.2.1, 3.1.1.5.5.4,
/// 5.1.3.3.4).
#[test]
fn layer5_desired_rights() {
    let pol = policy(vec![allow_everything(1)]);
    let check = |aces: Vec<dtyp::Ace>, action: Action, attr: Option<dtyp::Guid>| {
        let pip = MockPip::with_sd(sd(None, aces));
        decide(&dir_request(the_user(), action, attr), &pol, &pip).effect
    };
    let u = user;
    assert_eq!(
        check(
            vec![allow(RIGHT_DS_LIST_CONTENTS, u())],
            Action::DirList,
            None
        ),
        Effect::Allow
    );
    assert_eq!(
        check(
            vec![allow(RIGHT_DS_READ_PROPERTY, u())],
            Action::DirList,
            None
        ),
        Effect::Deny
    );
    assert_eq!(
        check(vec![allow(RIGHT_DELETE, u())], Action::DirDelete, None),
        Effect::Allow
    );
    assert_eq!(
        check(
            vec![allow(RIGHT_DS_DELETE_TREE, u())],
            Action::DirDelete,
            None
        ),
        Effect::Deny
    );
    assert_eq!(
        check(
            vec![allow_obj(RIGHT_DS_WRITE_PROPERTY, Some(attr_alone()), u())],
            Action::DirWrite,
            Some(attr_alone())
        ),
        Effect::Allow
    );
    assert_eq!(
        check(
            vec![allow(RIGHT_DS_WRITE_PROPERTY_EXTENDED, u())],
            Action::DirWrite,
            Some(attr_alone())
        ),
        Effect::Deny
    );
    assert_eq!(
        check(
            vec![allow_obj(RIGHT_DS_CREATE_CHILD, Some(class_group()), u())],
            Action::DirAddChild(pdp::ObjClass(class_group())),
            None
        ),
        Effect::Allow
    );
    assert_eq!(
        check(
            vec![allow_obj(RIGHT_DS_CONTROL_ACCESS, Some(right_a()), u())],
            Action::DirControlRight(pdp::ControlRightId(right_a())),
            None
        ),
        Effect::Allow
    );
}

/// Layer 5 via the PIP's property set: a grant on the property set reaches
/// the attribute ([MS-ADTS] 5.1.3.3.3).
#[test]
fn layer5_property_set_from_pip() {
    let pip = MockPip::with_sd(sd(
        None,
        vec![allow_obj(RIGHT_DS_READ_PROPERTY, Some(propset()), user())],
    ));
    let pol = policy(vec![allow_everything(1)]);
    let in_set = dir_request(the_user(), Action::DirRead, Some(attr_in_set()));
    assert_eq!(decide(&in_set, &pol, &pip).effect, Effect::Allow);
    assert_eq!(decide(&read_req(), &pol, &pip).reason, ReasonCode::Acl);
}

/// Layer 5 via the PIP's class chain (A-28, Q-081; [MS-ADTS] 5.1.3.3.3,
/// 3.1.1.2.4.3): a deny object ACE on a superclass GUID denies once the PIP
/// lists that class in the object's chain, and an allow on it never grants.
#[test]
fn layer5_class_chain_from_pip() {
    let pol = policy(vec![allow_everything(1)]);
    let deny_top = sd(
        None,
        vec![
            deny_obj(RIGHT_DS_READ_PROPERTY, Some(class_top()), user()),
            allow(RIGHT_GENERIC_READ, group()),
        ],
    );
    // Default chain (`class_user` alone): `class_top` is not in it.
    let pip = MockPip::with_sd(deny_top.clone());
    assert_eq!(decide(&read_req(), &pol, &pip).effect, Effect::Allow);
    // Computer chain: `class_top` is a superclass ⇒ the deny applies.
    let mut pip = MockPip::with_sd(deny_top);
    pip.classes.insert(obj_dn(), computer_chain());
    let d = decide(&read_req(), &pol, &pip);
    assert_eq!(d.reason, ReasonCode::Acl);
    // An allow on a superclass GUID does not grant; on the most specific
    // class it does.
    let mut pip = MockPip::with_sd(sd(
        None,
        vec![allow_obj(
            RIGHT_DS_READ_PROPERTY,
            Some(class_user()),
            user(),
        )],
    ));
    pip.classes.insert(obj_dn(), computer_chain());
    assert_eq!(decide(&read_req(), &pol, &pip).reason, ReasonCode::Acl);
    let mut pip = MockPip::with_sd(sd(
        None,
        vec![allow_obj(
            RIGHT_DS_READ_PROPERTY,
            Some(class_computer()),
            user(),
        )],
    ));
    pip.classes.insert(obj_dn(), computer_chain());
    assert_eq!(decide(&read_req(), &pol, &pip).effect, Effect::Allow);
}

/// Layer 5 via the PIP's property set flag (A-28, Q-081 item 2): an allow on
/// a property set GUID that is also an attribute's schemaIDGUID grants that
/// attribute only, not the set's other members.
#[test]
fn layer5_shared_property_set_from_pip() {
    let pip = MockPip::with_sd(sd(
        None,
        vec![allow_obj(
            RIGHT_DS_READ_PROPERTY,
            Some(shared_guid()),
            user(),
        )],
    ));
    let pol = policy(vec![allow_everything(1)]);
    let attribute = dir_request(the_user(), Action::DirRead, Some(shared_guid()));
    assert_eq!(decide(&attribute, &pol, &pip).effect, Effect::Allow);
    let other_member = dir_request(the_user(), Action::DirRead, Some(attr_in_shared_set()));
    assert_eq!(decide(&other_member, &pol, &pip).reason, ReasonCode::Acl);
}

/// D40: every PIP failure is a Deny(PipFailure).
#[test]
fn pip_failures_deny() {
    let pol = policy(vec![allow_everything(1)]);
    for failing in [
        Failing::TierOf,
        Failing::ObjectTier,
        Failing::SecurityDescriptor,
        Failing::AttrClass,
        Failing::ObjectClasses,
        Failing::ObjectSid,
        Failing::PropertySet,
    ] {
        let mut pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_ALL, group())]));
        pip.failing = failing;
        // A write exercises object_tier too.
        let req = dir_request(the_user(), Action::DirWrite, Some(attr_alone()));
        let d = decide(&req, &pol, &pip);
        assert_eq!(d.effect, Effect::Deny, "{failing:?}");
        assert_eq!(d.reason, ReasonCode::PipFailure, "{failing:?}");
    }
    // An unknown object (no descriptor) is a PIP absence ⇒ Deny.
    let pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_ALL, group())]));
    let mut req = read_req();
    req.resource = Resource::DirObject {
        dn: Dn::new(vec!["cn=missing".into()]),
        attr: None,
    };
    assert_eq!(decide(&req, &pol, &pip).reason, ReasonCode::PipFailure);
}

// ----------------------------------------------------------- obligations ----

/// docs/11 §4 / §8: an Allow carries Audit, RateLimit(rl_key) and the
/// matching Allow rules' obligations — and exactly one Audit (P7), even when a
/// rule lists Audit itself. A Deny carries exactly [Audit].
#[test]
fn obligations() {
    let pip = readable_pip();
    let r = Rule {
        id: RuleId(1),
        effect: Effect::Allow,
        when: match_all(),
        obligations: vec![
            Obligation::Audit,
            Obligation::Constrain(Constraint::MaxPageSize(100)),
        ],
    };
    let d = decide(&read_req(), &policy(vec![r]), &pip);
    assert_eq!(d.effect, Effect::Allow);
    assert_eq!(
        d.obligations,
        vec![
            Obligation::Audit,
            Obligation::RateLimit(pdp::RlKey {
                principal: user(),
                class: ActionClass::Directory,
            }),
            Obligation::Constrain(Constraint::MaxPageSize(100)),
        ]
    );
    let denied = decide(&read_req(), &policy(vec![]), &pip);
    assert_eq!(denied.obligations, vec![Obligation::Audit]);
}

/// Non-directory resources have no layer 5: an RPC call allowed by the rules
/// over PKT_PRIVACY is allowed.
#[test]
fn non_directory_resources_skip_layer5() {
    let pip = readable_pip();
    let req = AccessRequest {
        subject: the_user(),
        resource: Resource::RpcMethod {
            iface: guid(0x55),
            opnum: 1,
        },
        action: Action::RpcCall,
        context: strong_context(),
    };
    let pol = policy(vec![rule(
        3,
        Effect::Allow,
        Match {
            resource: ResourceMatch::RpcMethod {
                iface: guid(0x55),
                opnum: Some(1),
            },
            ..match_all()
        },
    )]);
    assert_eq!(decide(&req, &pol, &pip).effect, Effect::Allow);
    let mut other_opnum = req.clone();
    other_opnum.resource = Resource::RpcMethod {
        iface: guid(0x55),
        opnum: 2,
    };
    assert_eq!(decide(&other_opnum, &pol, &pip).reason, ReasonCode::NoGrant);
}
