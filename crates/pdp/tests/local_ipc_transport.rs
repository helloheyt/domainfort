//! `Transport::LocalIpc` and its write floor (task A3 of docs/51 §12; R2).
//!
//! Sources: docs/11 §4 (`required_sec`: "write / secret operation →
//! {encrypted, sealed, channel_bound}; authenticated read → {encrypted}");
//! docs/51 §5.4 (R51-9); docs/52 §3.2, §5 item 4 and docs/questions/Q-463
//! (decided A-102, superseding Q-292 / A-74 option (a)): the admin plane's
//! local socket reports `{encrypted, sealed}` and `channel_bound` only once
//! keyd verified each AP-REQ's operation binding, and its floor is the floor
//! of every transport — no exemption. Fixtures are the hand-made ones of
//! `common`; no vector comes from any other implementation.

mod common;

use common::*;
use pdp::access_check::rights::RIGHT_GENERIC_ALL;
use pdp::{
    decide, required_sec, required_sec_on, AccessRequest, Action, AttrId, ControlRightId, Effect,
    KerbResKind, ObjClass, PolicyScope, ReasonCode, Resource, ShareId, Spn, Transport,
    TransportSec, ZoneId,
};

/// The security a PEP on the admin plane's local socket reports when an
/// AP-REQ was not verified bound to the operation (no binding).
const LOCAL: TransportSec = TransportSec {
    encrypted: true,
    sealed: true,
    channel_bound: false,
};

/// The security it reports once keyd verified every AP-REQ's operation
/// binding (R2, docs/52 §5 item 4).
const BOUND: TransportSec = TransportSec {
    encrypted: true,
    sealed: true,
    channel_bound: true,
};

/// Every transport other than `LocalIpc` (task K6 added `Kpasswd`,
/// docs/53 §5.6 step 4: the same floor as every other).
const NETWORK_TRANSPORTS: [Transport; 9] = [
    Transport::Ldap,
    Transport::Ldaps,
    Transport::LdapSasl,
    Transport::Cldap,
    Transport::SmbEnc,
    Transport::NcacnIpTcpPrivacy,
    Transport::Dns,
    Transport::Kerberos,
    Transport::Kpasswd,
];

/// One request of every action kind, on a resource it belongs to.
fn every_action() -> Vec<(Action, Resource)> {
    let dir = |attr: Option<dtyp::Guid>| Resource::DirObject {
        dn: obj_dn(),
        attr: attr.map(AttrId),
    };
    let dns = Resource::Dns {
        zone: ZoneId("test".into()),
        record: None,
    };
    let kerberos = Resource::Kerberos {
        kind: KerbResKind::Service(Spn("ldap/dc1.test".into())),
    };
    let file = Resource::File {
        share: ShareId("sysvol".into()),
        path: pdp::FilePath(vec!["a".into()]),
    };
    vec![
        (Action::DirRead, dir(Some(attr_alone()))),
        (Action::DirWrite, dir(Some(attr_alone()))),
        (Action::DirAddChild(ObjClass(class_group())), dir(None)),
        (Action::DirDelete, dir(None)),
        (Action::DirList, dir(None)),
        (
            Action::DirControlRight(ControlRightId(right_a())),
            dir(None),
        ),
        (
            Action::RpcCall,
            Resource::RpcMethod {
                iface: guid(0x66),
                opnum: 0,
            },
        ),
        (Action::FileRead, file.clone()),
        (Action::FileWrite, file),
        (Action::DnsUpdate, dns.clone()),
        (Action::DnsXfer, dns),
        (Action::KdcAs, kerberos.clone()),
        (Action::KdcTgs, kerberos.clone()),
        (Action::KdcS4u2Self, kerberos.clone()),
        (Action::KdcS4u2Proxy, kerberos),
        (
            Action::PolicyAdmin,
            Resource::Policy {
                scope: PolicyScope("domain".into()),
            },
        ),
    ]
}

/// The request `action` on `resource` by the test user over `transport`
/// with `sec`.
fn request(
    action: Action,
    resource: Resource,
    transport: Transport,
    sec: TransportSec,
) -> AccessRequest {
    let mut req = AccessRequest {
        subject: the_user(),
        resource,
        action,
        context: strong_context(),
    };
    req.context.transport = transport;
    req.context.transport_sec = sec;
    req
}

/// docs/11 §4 + R2 (A-102): `required_sec_on` IS `required_sec`, for every
/// action, on every transport — `LocalIpc` included (the A-74 exemption is
/// gone).
#[test]
fn the_floor_table_is_the_same_on_every_transport() {
    for (action, _) in every_action() {
        for transport in NETWORK_TRANSPORTS.into_iter().chain([Transport::LocalIpc]) {
            assert_eq!(
                required_sec_on(&action, transport),
                required_sec(&action),
                "{action:?} on {transport:?}"
            );
        }
    }
    // The write actions of the docs/11 §4 table need the binding on the
    // admin plane's local socket too.
    for action in [
        Action::DirWrite,
        Action::DirDelete,
        Action::FileWrite,
        Action::PolicyAdmin,
    ] {
        assert!(
            required_sec_on(&action, Transport::LocalIpc).channel_bound,
            "{action:?}"
        );
    }
}

/// R2 (docs/52 §5 item 4): an authenticated write over `LocalIpc` whose PEP
/// could not report `channel_bound` (an AP-REQ keyd did not verify bound to
/// the operation) is `WeakTransport` at layer 2; reads and the actions with
/// no binding floor still pass. The same over every other transport.
#[test]
fn writes_without_channel_binding_are_weak_transport_on_every_transport() {
    let pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_ALL, group())]));
    let pol = policy(vec![allow_everything(1)]);
    let mut refused = 0usize;
    let transports: Vec<Transport> = NETWORK_TRANSPORTS
        .into_iter()
        .chain([Transport::LocalIpc])
        .collect();
    for transport in &transports {
        for (action, resource) in every_action() {
            let d = decide(
                &request(action.clone(), resource, *transport, LOCAL),
                &pol,
                &pip,
            );
            if required_sec(&action).channel_bound {
                assert_eq!(d.effect, Effect::Deny, "{action:?} on {transport:?}");
                assert_eq!(
                    d.reason,
                    ReasonCode::WeakTransport,
                    "{action:?} on {transport:?}"
                );
                refused += 1;
            } else {
                assert_eq!(d.effect, Effect::Allow, "{action:?} on {transport:?}");
            }
        }
    }
    // Six actions have the binding floor (DirWrite, DirAddChild, DirDelete,
    // DirControlRight, FileWrite, PolicyAdmin), each on nine transports.
    assert_eq!(refused, 6 * transports.len());
}

/// R2: with the binding keyd verified — `{encrypted, sealed, channel_bound}`
/// — every action over `LocalIpc` passes layer 2 (an Allow-all policy and a
/// granting descriptor ⇒ allowed).
#[test]
fn local_ipc_writes_with_channel_binding_are_allowed() {
    let pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_ALL, group())]));
    let pol = policy(vec![allow_everything(1)]);
    for (action, resource) in every_action() {
        let d = decide(
            &request(action.clone(), resource, Transport::LocalIpc, BOUND),
            &pol,
            &pip,
        );
        assert_eq!(d.effect, Effect::Allow, "{action:?}: {d:?}");
        assert_eq!(d.reason, ReasonCode::Allowed, "{action:?}");
    }
}

/// The binding is not enough on its own: a write over `LocalIpc` without
/// `sealed`, or without `encrypted`, is still `WeakTransport`.
#[test]
fn local_ipc_still_needs_encrypted_and_sealed_for_writes() {
    let pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_ALL, group())]));
    let pol = policy(vec![allow_everything(1)]);
    for sec in [
        TransportSec {
            encrypted: true,
            sealed: false,
            channel_bound: true,
        },
        TransportSec {
            encrypted: false,
            sealed: true,
            channel_bound: true,
        },
        TransportSec::NONE,
    ] {
        let d = decide(
            &request(
                Action::DirWrite,
                Resource::DirObject {
                    dn: obj_dn(),
                    attr: Some(AttrId(attr_alone())),
                },
                Transport::LocalIpc,
                sec,
            ),
            &pol,
            &pip,
        );
        assert_eq!(d.reason, ReasonCode::WeakTransport, "{sec:?}");
    }
}

/// Layer 1 runs first (docs/11 §4): an unauthenticated write over
/// `LocalIpc` is `Unauthenticated`, even with the binding reported.
#[test]
fn local_ipc_does_not_touch_layer_one() {
    let pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_ALL, everyone())]));
    let pol = policy(vec![allow_everything(1)]);
    let mut req = request(
        Action::DirWrite,
        Resource::DirObject {
            dn: obj_dn(),
            attr: Some(AttrId(attr_alone())),
        },
        Transport::LocalIpc,
        BOUND,
    );
    req.subject.auth.ticket_verified = false;
    let d = decide(&req, &pol, &pip);
    assert_eq!(d.reason, ReasonCode::Unauthenticated);
}
