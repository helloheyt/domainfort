//! The PDP extensions for LDAP and the two fixes found in merged code.
//!
//! Source (each test names its own): Q-164 items 1-3 (A-48); Q-170 item 3
//! (A-51: External forbidden in `AnonymousGrant`); docs/49 §5.2
//! (R49-10); docs/15 §6 ("only these, from the internal network"); docs/11
//! §4 (layers, `required_sec`); [MS-ADTS] v20261026 3.1.1.3 ("The rootDSE
//! (empty DN) ... rather than with particular objects"), 3.1.1.3.2 (rootDSE
//! attributes "are read-only"), 3.1.1.4.4 (nTSecurityDescriptor:
//! "(ACCESS_SYSTEM_SECURITY) and (RIGHT_READ_CONTROL)"); [MS-DTYP] v20241119
//! 2.3.4.2 (GUID packet), 2.5.3.2 (ACCESS_SYSTEM_SECURITY only through
//! SeSecurityPrivilege); [MS-ADA3] v20180912 2.37 (nTSecurityDescriptor
//! schemaIdGuid); A-31 (GUID string form). Hand-made cases; no vector from
//! another implementation.

mod common;

use common::*;
use dtyp::Ace;
use pdp::access_check::rights::*;
use pdp::{
    acl_grants, decide, AccessRequest, Action, ActionClass, ActionMatch, AnonymousGrant, AttrClass,
    AttrId, AuthStrength, ControlRightId, DirObjectContext, Dn, Effect, IpScope, KerbResKind,
    Match, ObjClass, PolicySnapshot, PolicyVersion, ReasonCode, Resource, ResourceMatch, Right,
    Rule, RuleError, RuleId, Subject, SubtreeBase, Tier, TransportSec,
};

const ENCRYPTED: TransportSec = TransportSec {
    encrypted: true,
    sealed: false,
    channel_bound: false,
};

fn anonymous() -> Subject {
    let mut s = subject(everyone(), &[], Tier::Tier1);
    s.auth.strength = AuthStrength::Unauth;
    s.auth.ticket_verified = false;
    s
}

fn root_dse_read(s: Subject, src_net: IpScope, sec: TransportSec) -> AccessRequest {
    let mut req = AccessRequest {
        subject: s,
        resource: Resource::RootDse,
        action: Action::DirRead,
        context: strong_context(),
    };
    req.context.src_net = src_net;
    req.context.transport_sec = sec;
    req
}

fn root_dse_grant(src_net: IpScope, min: TransportSec) -> AnonymousGrant {
    AnonymousGrant::new(
        ActionMatch::Exact(Action::DirRead),
        ResourceMatch::RootDse,
        min,
        src_net,
    )
    .expect("a bounded grant")
}

fn snapshot(rules: Vec<Rule>, grants: Vec<AnonymousGrant>) -> PolicySnapshot {
    PolicySnapshot::new(PolicyVersion(1), rules, grants)
}

fn rule(id: u32, effect: Effect, resource: ResourceMatch) -> Rule {
    Rule {
        id: RuleId(id),
        effect,
        when: Match {
            resource,
            ..match_all()
        },
        obligations: vec![],
    }
}

/// A PIP whose only object grants everything to Everyone.
fn open_pip() -> MockPip {
    MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_ALL, everyone())]))
}

// ------------------------------------------------- Q-164 item 2: subtree ----

/// Q-164 item 2 (A-48): a DN subtree with no RDN component is refused when
/// it is built; any non-empty DN is accepted and kept as given.
#[test]
fn subtree_base_refuses_the_empty_dn() {
    assert_eq!(
        SubtreeBase::new(Dn::new(vec![])),
        Err(RuleError::EmptySubtreeBase)
    );
    for dn in [
        Dn::new(vec!["dc=test".into()]),
        parent_dn(),
        obj_dn(),
        // A single empty component is still a component: matched exactly
        // like any other spelling (it names no object the directory has).
        Dn::new(vec![String::new()]),
    ] {
        let base = SubtreeBase::new(dn.clone()).expect("non-empty");
        assert_eq!(base.dn(), &dn);
    }
}

// ------------------------------------- Q-164 items 2-3: anonymous grants ----

/// Q-164 items 2-3; docs/15 §6 (the anonymous allowlist is "only these"): an
/// anonymous-allowlist entry over every resource is refused, whatever its
/// action, network or transport minimum. Bounded entries are accepted and
/// keep their fields.
#[test]
fn anonymous_grant_refuses_every_resource() {
    for action in [
        ActionMatch::Any,
        ActionMatch::Exact(Action::DirRead),
        ActionMatch::Class(ActionClass::Directory),
    ] {
        // The resource is checked before the network (`AnonymousGrant::new`),
        // so an external entry over every resource reports this refusal.
        for net in [IpScope::Internal, IpScope::External] {
            for min in [TransportSec::NONE, ENCRYPTED] {
                assert_eq!(
                    AnonymousGrant::new(action.clone(), ResourceMatch::Any, min, net),
                    Err(RuleError::UnboundedAnonymousResource)
                );
            }
        }
    }
    let bounded = [
        ResourceMatch::RootDse,
        subtree(parent_dn()),
        ResourceMatch::Dns {
            zone: pdp::ZoneId("test".into()),
        },
        ResourceMatch::Kerberos {
            kind: Some(KerbResKind::Tgt),
        },
    ];
    for resource in bounded {
        let g = AnonymousGrant::new(
            ActionMatch::Exact(Action::DirRead),
            resource.clone(),
            ENCRYPTED,
            IpScope::Internal,
        )
        .expect("bounded");
        assert_eq!(g.action(), &ActionMatch::Exact(Action::DirRead));
        assert_eq!(g.resource(), &resource);
        assert_eq!(g.min_transport(), ENCRYPTED);
        assert_eq!(g.src_net(), IpScope::Internal);
    }
}

/// docs/15 §6 ("only these, from the internal network"); A-51 (Q-170 item
/// 3: External is forbidden in `AnonymousGrant`): an entry for the external
/// network is refused, whatever its action, its (bounded) resource or its
/// transport minimum; the same entry for the internal network is accepted
/// and keeps its fields.
#[test]
fn anonymous_grant_refuses_the_external_network() {
    let actions = [
        ActionMatch::Any,
        ActionMatch::Exact(Action::DirRead),
        ActionMatch::AnyOf(vec![Action::DirRead, Action::DirList]),
        ActionMatch::Class(ActionClass::Directory),
        ActionMatch::Class(ActionClass::Dns),
    ];
    let bounded = [
        ResourceMatch::RootDse,
        subtree(parent_dn()),
        ResourceMatch::Dns {
            zone: pdp::ZoneId("test".into()),
        },
        ResourceMatch::Kerberos { kind: None },
        ResourceMatch::Kerberos {
            kind: Some(KerbResKind::Tgt),
        },
    ];
    let all = TransportSec {
        encrypted: true,
        sealed: true,
        channel_bound: true,
    };
    for action in &actions {
        for resource in &bounded {
            for min in [TransportSec::NONE, ENCRYPTED, all] {
                assert_eq!(
                    AnonymousGrant::new(action.clone(), resource.clone(), min, IpScope::External),
                    Err(RuleError::AnonymousExternalNetwork),
                    "{action:?} {resource:?}"
                );
                let g =
                    AnonymousGrant::new(action.clone(), resource.clone(), min, IpScope::Internal)
                        .expect("bounded, internal");
                assert_eq!(g.action(), action);
                assert_eq!(g.resource(), resource);
                assert_eq!(g.min_transport(), min);
                assert_eq!(g.src_net(), IpScope::Internal);
            }
        }
    }
}

/// docs/15 §6 ("from the internal network"); Q-164 item 3; A-51 (Q-170
/// item 3): an entry admits an anonymous request only from the network it
/// names, which can only be the internal one — an anonymous request from
/// the external network is unauthenticated over every transport. The
/// external entry that would have admitted it cannot be built.
/// Authenticated requests never consult the allowlist, so they are allowed
/// from either network.
#[test]
fn anonymous_grant_admits_only_its_source_network() {
    let pip = open_pip();
    let all = TransportSec {
        encrypted: true,
        sealed: true,
        channel_bound: true,
    };
    let internal_only = snapshot(
        vec![allow_everything(1)],
        vec![root_dse_grant(IpScope::Internal, TransportSec::NONE)],
    );
    assert_eq!(
        AnonymousGrant::new(
            ActionMatch::Exact(Action::DirRead),
            ResourceMatch::RootDse,
            TransportSec::NONE,
            IpScope::External,
        ),
        Err(RuleError::AnonymousExternalNetwork)
    );
    let reason = |req: &AccessRequest, pol: &PolicySnapshot| decide(req, pol, &pip).reason;

    for sec in [TransportSec::NONE, ENCRYPTED, all] {
        assert_eq!(
            reason(
                &root_dse_read(anonymous(), IpScope::Internal, sec),
                &internal_only
            ),
            ReasonCode::Allowed
        );
        assert_eq!(
            reason(
                &root_dse_read(anonymous(), IpScope::External, sec),
                &internal_only
            ),
            ReasonCode::Unauthenticated
        );
    }
    for net in [IpScope::Internal, IpScope::External] {
        // An authenticated read over the read floor, from either network.
        let authenticated = root_dse_read(the_user(), net, ENCRYPTED);
        assert_eq!(reason(&authenticated, &internal_only), ReasonCode::Allowed);
    }
}

/// docs/11 §4 ("anonymous allowlist ... → configured minimum"); docs/15 §6;
/// A-51: the transport minimum of the matching entries applies; an
/// anonymous request from the external network matches no entry, so no
/// minimum applies to it and it stays unauthenticated.
#[test]
fn anonymous_grant_floor_applies_to_its_network() {
    let pip = open_pip();
    let all = TransportSec {
        encrypted: true,
        sealed: true,
        channel_bound: true,
    };
    let encrypted_floor = snapshot(
        vec![allow_everything(1)],
        vec![root_dse_grant(IpScope::Internal, ENCRYPTED)],
    );
    let plain = root_dse_read(anonymous(), IpScope::Internal, TransportSec::NONE);
    assert_eq!(
        decide(&plain, &encrypted_floor, &pip).reason,
        ReasonCode::WeakTransport
    );
    let tls = root_dse_read(anonymous(), IpScope::Internal, ENCRYPTED);
    assert_eq!(decide(&tls, &encrypted_floor, &pip).effect, Effect::Allow);

    // Two matching entries on one network: both minimums apply.
    let joined = snapshot(
        vec![allow_everything(1)],
        vec![
            root_dse_grant(IpScope::Internal, TransportSec::NONE),
            root_dse_grant(IpScope::Internal, all),
        ],
    );
    assert_eq!(
        decide(&tls, &joined, &pip).reason,
        ReasonCode::WeakTransport
    );
    // From the external network no entry matches (none can name it,
    // A-51): unauthenticated, not a transport failure, over every transport.
    for sec in [TransportSec::NONE, ENCRYPTED, all] {
        let external = root_dse_read(anonymous(), IpScope::External, sec);
        for pol in [&encrypted_floor, &joined] {
            assert_eq!(
                decide(&external, pol, &pip).reason,
                ReasonCode::Unauthenticated
            );
        }
    }
}

// ----------------------------------------------- Q-164 item 1: rootDSE ----

/// Q-164 item 1 ("`well_formed` only with `DirRead`"); [MS-ADTS] 3.1.1.3.2
/// (rootDSE attributes "are read-only"): every other action on the rootDSE
/// is a malformed request, even under an Allow-everything policy with the
/// anonymous allowlist naming it.
#[test]
fn root_dse_admits_only_dir_read() {
    let pip = open_pip();
    let pol = snapshot(
        vec![allow_everything(1)],
        vec![AnonymousGrant::new(
            ActionMatch::Any,
            ResourceMatch::RootDse,
            TransportSec::NONE,
            IpScope::Internal,
        )
        .expect("bounded")],
    );
    let others = [
        Action::DirWrite,
        Action::DirList,
        Action::DirDelete,
        Action::DirAddChild(ObjClass(class_group())),
        Action::DirControlRight(ControlRightId(right_a())),
        Action::RpcCall,
        Action::FileRead,
        Action::FileWrite,
        Action::DnsUpdate,
        Action::DnsXfer,
        Action::KdcAs,
        Action::KdcTgs,
        Action::KdcS4u2Self,
        Action::KdcS4u2Proxy,
        Action::PolicyAdmin,
    ];
    for s in [the_user(), anonymous()] {
        for action in &others {
            let mut req =
                root_dse_read(s.clone(), IpScope::Internal, strong_context().transport_sec);
            req.action = action.clone();
            assert_eq!(
                decide(&req, &pol, &pip).reason,
                ReasonCode::InvalidRequest,
                "{action:?}"
            );
        }
        let read = root_dse_read(s, IpScope::Internal, strong_context().transport_sec);
        assert_eq!(decide(&read, &pol, &pip).effect, Effect::Allow);
    }
}

/// docs/49 §5.2 ("layer 5 does not apply (no object)"); [MS-ADTS] 3.1.1.3:
/// the rootDSE has no descriptor, classes, objectSid or attribute, so no PIP
/// failure about an object can affect its read — only the subject's tier
/// (P3) is still checked.
#[test]
fn root_dse_has_no_layer_5() {
    let pol = policy(vec![allow_everything(1)]);
    let req = root_dse_read(the_user(), IpScope::Internal, ENCRYPTED);
    for failing in [
        Failing::None,
        Failing::ObjectTier,
        Failing::SecurityDescriptor,
        Failing::AttrClass,
        Failing::ObjectClasses,
        Failing::ObjectSid,
        Failing::PropertySet,
    ] {
        // A PIP that knows no object at all.
        let mut pip = MockPip::with_sd(sd(None, vec![]));
        pip.sds.clear();
        pip.failing = failing;
        assert_eq!(
            decide(&req, &pol, &pip).effect,
            Effect::Allow,
            "{failing:?}"
        );
    }
    let mut pip = open_pip();
    pip.failing = Failing::TierOf;
    assert_eq!(decide(&req, &pol, &pip).reason, ReasonCode::PipFailure);
    let mut mismatched = req.clone();
    mismatched.subject.tier = Tier::Tier0;
    assert_eq!(
        decide(&mismatched, &pol, &open_pip()).reason,
        ReasonCode::SubjectMismatch
    );
}

/// docs/49 §5.2 (R49-10): `ResourceMatch::RootDse` matches the rootDSE and
/// nothing else; no DN subtree matches the rootDSE; `Any` matches it. Through
/// `decide`: a subtree grant does not reach it, its own grant does, and an
/// explicit Deny on it wins (P4).
#[test]
fn root_dse_is_matched_only_by_its_own_matcher() {
    let others = [
        Resource::DirObject {
            dn: obj_dn(),
            attr: None,
        },
        Resource::DirObject {
            dn: Dn::new(vec!["dc=test".into()]),
            attr: Some(AttrId(attr_alone())),
        },
        Resource::Kerberos {
            kind: KerbResKind::Tgt,
        },
        Resource::Dns {
            zone: pdp::ZoneId("test".into()),
            record: None,
        },
        Resource::Policy {
            scope: pdp::PolicyScope("domain".into()),
        },
    ];
    assert!(ResourceMatch::RootDse.matches(&Resource::RootDse));
    assert!(ResourceMatch::Any.matches(&Resource::RootDse));
    for r in &others {
        assert!(!ResourceMatch::RootDse.matches(r), "{r:?}");
    }
    for base in [
        Dn::new(vec!["dc=test".into()]),
        parent_dn(),
        obj_dn(),
        Dn::new(vec![String::new()]),
    ] {
        assert!(!subtree(base).matches(&Resource::RootDse));
    }

    let pip = open_pip();
    let req = root_dse_read(the_user(), IpScope::Internal, ENCRYPTED);
    let only_subtree = policy(vec![rule(
        1,
        Effect::Allow,
        subtree(Dn::new(vec!["dc=test".into()])),
    )]);
    assert_eq!(
        decide(&req, &only_subtree, &pip).reason,
        ReasonCode::NoGrant
    );
    let own = policy(vec![rule(1, Effect::Allow, ResourceMatch::RootDse)]);
    assert_eq!(decide(&req, &own, &pip).effect, Effect::Allow);
    let denied = policy(vec![
        allow_everything(1),
        rule(2, Effect::Deny, ResourceMatch::RootDse),
    ]);
    assert_eq!(
        decide(&req, &denied, &pip).reason,
        ReasonCode::CoarseDeny(RuleId(2))
    );
}

/// docs/11 §4 (`required_sec`: "authenticated read → {encrypted}"): an
/// authenticated rootDSE read has the read floor; the anonymous allowlist
/// does not lower it for authenticated subjects.
#[test]
fn root_dse_authenticated_read_has_the_read_floor() {
    let pip = open_pip();
    let pol = snapshot(
        vec![allow_everything(1)],
        vec![root_dse_grant(IpScope::Internal, TransportSec::NONE)],
    );
    let plain = root_dse_read(the_user(), IpScope::Internal, TransportSec::NONE);
    assert_eq!(decide(&plain, &pol, &pip).reason, ReasonCode::WeakTransport);
    let tls = root_dse_read(the_user(), IpScope::Internal, ENCRYPTED);
    assert_eq!(decide(&tls, &pol, &pip).effect, Effect::Allow);
}

/// docs/49 §5.2 (R49-10: the anonymous entry is `{DirRead, RootDse}` with a
/// network); docs/15 §6; docs/11 §4 layer 1: an anonymous rootDSE read
/// needs an entry naming the rootDSE, its action and its network — an entry
/// for a subtree, for another action, or none at all leaves it
/// unauthenticated; and layer 3 still needs an Allow rule.
#[test]
fn anonymous_root_dse_needs_an_entry_naming_it() {
    let pip = open_pip();
    let req = root_dse_read(anonymous(), IpScope::Internal, TransportSec::NONE);
    let with = |grants: Vec<AnonymousGrant>| snapshot(vec![allow_everything(1)], grants);
    let subtree_entry = AnonymousGrant::new(
        ActionMatch::Exact(Action::DirRead),
        subtree(parent_dn()),
        TransportSec::NONE,
        IpScope::Internal,
    )
    .expect("bounded");
    let list_entry = AnonymousGrant::new(
        ActionMatch::Exact(Action::DirList),
        ResourceMatch::RootDse,
        TransportSec::NONE,
        IpScope::Internal,
    )
    .expect("bounded");
    for grants in [vec![], vec![subtree_entry], vec![list_entry]] {
        assert_eq!(
            decide(&req, &with(grants), &pip).reason,
            ReasonCode::Unauthenticated
        );
    }
    let entry = root_dse_grant(IpScope::Internal, TransportSec::NONE);
    assert_eq!(
        decide(&req, &with(vec![entry.clone()]), &pip).effect,
        Effect::Allow
    );
    assert_eq!(
        decide(&req, &snapshot(vec![], vec![entry]), &pip).reason,
        ReasonCode::NoGrant
    );
}

/// [MS-ADTS] 3.1.1.3 ("The rootDSE (empty DN)"): no directory object has the
/// empty DN — the rootDSE is `Resource::RootDse` — so every directory action
/// on `DirObject { dn: <empty> }` is malformed, even when the PIP holds a
/// granting descriptor for that DN.
#[test]
fn empty_dn_is_not_a_directory_object() {
    let mut pip = open_pip();
    pip.sds.insert(
        Dn::new(vec![]),
        sd(None, vec![allow(RIGHT_GENERIC_ALL, everyone())]),
    );
    let pol = policy(vec![allow_everything(1)]);
    let actions = [
        (Action::DirRead, None),
        (Action::DirRead, Some(AttrId(attr_alone()))),
        (Action::DirWrite, Some(AttrId(attr_alone()))),
        (Action::DirList, None),
        (Action::DirDelete, None),
        (Action::DirAddChild(ObjClass(class_group())), None),
        (Action::DirControlRight(ControlRightId(right_a())), None),
    ];
    for (action, attr) in actions {
        let req = AccessRequest {
            subject: the_user(),
            resource: Resource::DirObject {
                dn: Dn::new(vec![]),
                attr,
            },
            action: action.clone(),
            context: strong_context(),
        };
        assert_eq!(
            decide(&req, &pol, &pip).reason,
            ReasonCode::InvalidRequest,
            "{action:?}"
        );
    }
}

// -------------------------------------------- A-48: nTSecurityDescriptor ----

/// [MS-ADA3] 2.37 ("schemaIdGuid: bf9679e3-0de6-11d0-a285-00aa003049e2"),
/// with the project's mapping of the printed groups to the members (A-31)
/// and the packet layout of [MS-DTYP] 2.3.4.2 (Data1, Data2, Data3
/// little-endian, then Data4 in array order).
#[test]
fn nt_security_descriptor_identifier() {
    let g = AttrId::NT_SECURITY_DESCRIPTOR.0;
    assert_eq!(g.data1, 0xbf96_79e3);
    assert_eq!(g.data2, 0x0de6);
    assert_eq!(g.data3, 0x11d0);
    assert_eq!(g.data4, [0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2]);
    assert_eq!(
        g.to_packet(),
        [
            0xe3, 0x79, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30,
            0x49, 0xe2
        ]
    );
}

/// The descriptors of the nTSecurityDescriptor tests: each grants the user
/// (member of `group()`) RIGHT_DS_READ_PROPERTY on the attribute — enough
/// before the fix — and most also RIGHT_READ_CONTROL, through simple ACEs,
/// object ACEs naming the attribute, generic rights, or ownership. The flag
/// says whether it also grants the whole-object read (the control).
fn granting_descriptors() -> Vec<(Option<dtyp::Sid>, Vec<Ace>, bool)> {
    let ntsd = Some(AttrId::NT_SECURITY_DESCRIPTOR.0);
    vec![
        (None, vec![allow(RIGHT_GENERIC_ALL, user())], true),
        (None, vec![allow(RIGHT_GENERIC_ALL, group())], true),
        (None, vec![allow(RIGHT_GENERIC_READ, group())], true),
        (
            None,
            vec![allow(RIGHT_DS_READ_PROPERTY | RIGHT_READ_CONTROL, user())],
            true,
        ),
        (
            Some(user()),
            vec![allow(RIGHT_DS_READ_PROPERTY, user())],
            true,
        ),
        (
            None,
            vec![
                allow_obj(RIGHT_DS_READ_PROPERTY | RIGHT_READ_CONTROL, ntsd, user()),
                allow(RIGHT_READ_CONTROL, user()),
            ],
            false,
        ),
        (
            None,
            vec![allow_obj(
                RIGHT_GENERIC_ALL | ACCESS_SYSTEM_SECURITY,
                ntsd,
                user(),
            )],
            false,
        ),
    ]
}

/// [MS-ADTS] 3.1.1.4.4 ("nTSecurityDescriptor — (ACCESS_SYSTEM_SECURITY) and
/// (RIGHT_READ_CONTROL)"); [MS-DTYP] 2.5.3.2 (ACCESS_SYSTEM_SECURITY only
/// with SeSecurityPrivilege, "ELSE ... Return access_denied"): a read of
/// nTSecurityDescriptor is denied by the ACL layer for every descriptor —
/// including grant-all, ownership, object ACEs naming the attribute, and an
/// ACE carrying the ACCESS_SYSTEM_SECURITY bit — for Tier-0 and Tier-1
/// subjects and every attribute class. The same descriptors still grant the
/// read of an ordinary attribute and of the whole object (control).
#[test]
fn nt_security_descriptor_read_is_never_granted() {
    let pol = policy(vec![allow_everything(1)]);
    let ntsd = AttrId::NT_SECURITY_DESCRIPTOR;
    for (owner, aces, grants_whole_read) in granting_descriptors() {
        for tier in [Tier::Tier0, Tier::Tier1] {
            for class in [
                AttrClass::Normal,
                AttrClass::Sensitive {
                    control_access_right: ControlRightId(right_a()),
                },
            ] {
                let mut pip = MockPip::with_sd(sd(owner, aces.clone()));
                pip.tiers.insert(user(), tier);
                pip.attr_classes.insert(ntsd, class);
                let s = subject(user(), &[group()], tier);
                let read = dir_request(s.clone(), Action::DirRead, Some(ntsd.0));
                assert_eq!(
                    decide(&read, &pol, &pip).reason,
                    ReasonCode::Acl,
                    "{aces:?} owner {owner:?}"
                );
                // Control: the same descriptor and policy still grant the
                // whole-object read where the descriptor grants it.
                let whole = dir_request(s.clone(), Action::DirRead, None);
                assert_eq!(
                    decide(&whole, &pol, &pip).effect == Effect::Allow,
                    grants_whole_read,
                    "{aces:?}"
                );
            }
        }
    }
}

/// [MS-ADTS] 3.1.1.4.4 needs both rights; [MS-DTYP] 2.5.3.2 / 2.4.3: the
/// ACCESS_SYSTEM_SECURITY half is never granted by an ACE. Over every DACL
/// of up to two ACEs from an alphabet of simple and object ACEs with every
/// directory right (and the ACCESS_SYSTEM_SECURITY bit), for owners none /
/// the user: the conjunction is never granted, while RIGHT_READ_CONTROL
/// alone is granted somewhere in the domain (so the refusal is the
/// ACCESS_SYSTEM_SECURITY half, not an empty domain).
#[test]
fn nt_security_descriptor_rights_are_never_granted_together() {
    let ntsd = Some(AttrId::NT_SECURITY_DESCRIPTOR.0);
    let masks = [
        RIGHT_READ_CONTROL,
        RIGHT_GENERIC_ALL,
        RIGHT_GENERIC_READ,
        DIRECTORY_RIGHTS,
        ACCESS_SYSTEM_SECURITY | RIGHT_READ_CONTROL,
        u32::MAX,
    ];
    let mut alphabet = Vec::new();
    for mask in masks {
        for sid in [user(), everyone()] {
            alphabet.push(allow(mask, sid));
            alphabet.push(allow_obj(mask, ntsd, sid));
            alphabet.push(allow_obj(mask, None, sid));
        }
    }
    let o = DirObjectContext {
        object_class: class_user(),
        superclasses: vec![],
        object_sid: Some(user()),
    };
    let both = Right::Object {
        mask: ACCESS_SYSTEM_SECURITY | RIGHT_READ_CONTROL,
    };
    let rc_only = Right::Object {
        mask: RIGHT_READ_CONTROL,
    };
    let s = the_user();
    let mut rc_granted = 0usize;
    let mut checked = 0usize;
    let mut dacls: Vec<Vec<Ace>> = vec![vec![]];
    dacls.extend(alphabet.iter().map(|a| vec![a.clone()]));
    for a in &alphabet {
        for b in &alphabet {
            dacls.push(vec![a.clone(), b.clone()]);
        }
    }
    for aces in &dacls {
        for owner in [None, Some(user())] {
            let d = sd(owner, aces.clone());
            assert!(!acl_grants(&s, &d, &o, &both), "{aces:?} owner {owner:?}");
            rc_granted += usize::from(acl_grants(&s, &d, &o, &rc_only));
            checked += 1;
        }
    }
    assert!(checked > 1000, "{checked}");
    assert!(rc_granted > 0);
}

/// docs/questions/Q-190 item 2 (A-54): `Transport::Ldap` lets the LDAP PEP
/// report a cleartext connection truthfully, and must change no decision —
/// docs/11 §4 decides on `Context.transport_sec`, never on
/// `Context.transport`. Every request of a broad hand-made matrix (an
/// authenticated and an anonymous subject, directory reads, lists, writes and
/// deletes and the rootDSE, every combination of the three transport
/// properties, both source networks, an open and a closed descriptor,
/// policies with and without rules and an anonymous grant) gets exactly the
/// same Decision under every `Transport` value as under `Transport::Ldaps` —
/// `Transport::LocalIpc` included since its write exemption was removed (R2,
/// A-102; tests/local_ipc_transport.rs).
#[test]
fn the_cleartext_ldap_transport_changes_no_decision() {
    use pdp::Transport;
    let transports = [
        Transport::Ldap,
        Transport::Ldaps,
        Transport::LdapSasl,
        Transport::Cldap,
        Transport::SmbEnc,
        Transport::NcacnIpTcpPrivacy,
        Transport::Dns,
        Transport::Kerberos,
        Transport::LocalIpc,
    ];
    let subjects = [the_user(), anonymous()];
    let object = |attr: Option<AttrId>| Resource::DirObject { dn: obj_dn(), attr };
    let requests: Vec<(Action, Resource)> = vec![
        (Action::DirRead, Resource::RootDse),
        (Action::DirRead, object(None)),
        (Action::DirRead, object(Some(AttrId(attr_in_set())))),
        (Action::DirList, object(None)),
        (Action::DirWrite, object(Some(AttrId(attr_alone())))),
        (Action::DirDelete, object(None)),
    ];
    let pips = [
        open_pip(),
        MockPip::with_sd(sd(None, vec![deny(RIGHT_GENERIC_ALL, everyone())])),
    ];
    let anonymous_grant = AnonymousGrant::new(
        ActionMatch::AnyOf(vec![Action::DirRead, Action::DirList]),
        ResourceMatch::RootDse,
        TransportSec::NONE,
        IpScope::Internal,
    )
    .expect("a bounded grant");
    let policies = [
        snapshot(vec![], vec![]),
        snapshot(vec![allow_everything(1)], vec![]),
        snapshot(vec![allow_everything(1)], vec![anonymous_grant]),
        snapshot(vec![rule(2, Effect::Deny, ResourceMatch::RootDse)], vec![]),
    ];
    let mut compared = 0usize;
    for subject in &subjects {
        for (action, resource) in &requests {
            for bits in 0u8..8 {
                let sec = TransportSec {
                    encrypted: bits & 1 != 0,
                    sealed: bits & 2 != 0,
                    channel_bound: bits & 4 != 0,
                };
                for src_net in [IpScope::Internal, IpScope::External] {
                    for pip in &pips {
                        for pol in &policies {
                            let mut req = AccessRequest {
                                subject: subject.clone(),
                                resource: resource.clone(),
                                action: action.clone(),
                                context: strong_context(),
                            };
                            req.context.transport_sec = sec;
                            req.context.src_net = src_net;
                            req.context.transport = Transport::Ldaps;
                            let reference = decide(&req, pol, pip);
                            for transport in transports {
                                req.context.transport = transport;
                                assert_eq!(decide(&req, pol, pip), reference, "{req:?}");
                                compared += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(compared, 2 * 6 * 8 * 2 * 2 * 4 * transports.len());
}
