//! `Transport::LocalIpc` and the narrow write-floor exemption of
//! `required_sec_on` (task A3 of docs/51 §12).
//!
//! Sources: docs/11 §4 (`required_sec`: "write / secret operation →
//! {encrypted, sealed, channel_bound}; authenticated read → {encrypted}");
//! docs/51 §5.4 (R51-9); docs/questions/Q-292, decided A-74 option (a): the
//! admin plane's local socket reports `{encrypted, sealed}` with
//! `channel_bound: false`, and the exemption from `channel_bound` applies to
//! `LocalIpc` **only** — every other transport keeps the existing floor.
//! Both halves are tested here. Fixtures are the hand-made ones of `common`;
//! no vector comes from any other implementation.

mod common;

use common::*;
use pdp::access_check::rights::RIGHT_GENERIC_ALL;
use pdp::{
    decide, required_sec, required_sec_on, AccessRequest, Action, AttrId, ControlRightId, Effect,
    KerbResKind, ObjClass, PolicyScope, ReasonCode, Resource, ShareId, Spn, Transport,
    TransportSec, ZoneId,
};

/// The security a PEP on the admin plane's local socket reports (A-74).
const LOCAL: TransportSec = TransportSec {
    encrypted: true,
    sealed: true,
    channel_bound: false,
};

/// Every transport other than `LocalIpc`.
const NETWORK_TRANSPORTS: [Transport; 8] = [
    Transport::Ldap,
    Transport::Ldaps,
    Transport::LdapSasl,
    Transport::Cldap,
    Transport::SmbEnc,
    Transport::NcacnIpTcpPrivacy,
    Transport::Dns,
    Transport::Kerberos,
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

/// docs/11 §4 + A-74: on `LocalIpc` a write's floor is `{encrypted,
/// sealed}` (no `channel_bound`); every other floor on it equals
/// `required_sec`. On every other transport `required_sec_on` IS
/// `required_sec`, for every action.
#[test]
fn the_floor_table_differs_only_for_writes_on_local_ipc() {
    let write_without_binding = TransportSec {
        encrypted: true,
        sealed: true,
        channel_bound: false,
    };
    for (action, _) in every_action() {
        for transport in NETWORK_TRANSPORTS {
            assert_eq!(
                required_sec_on(&action, transport),
                required_sec(&action),
                "{action:?} on {transport:?}"
            );
        }
        let local = required_sec_on(&action, Transport::LocalIpc);
        if required_sec(&action).channel_bound {
            assert!(pdp::is_write(&action), "{action:?}");
            assert_eq!(local, write_without_binding, "{action:?}");
        } else {
            assert_eq!(local, required_sec(&action), "{action:?}");
        }
        assert!(!local.channel_bound, "{action:?}");
    }
    // The write actions of the docs/11 §4 table all have the binding floor
    // elsewhere, and lose only the binding on LocalIpc.
    for action in [
        Action::DirWrite,
        Action::DirDelete,
        Action::FileWrite,
        Action::PolicyAdmin,
    ] {
        assert!(required_sec(&action).channel_bound, "{action:?}");
        assert_eq!(
            required_sec_on(&action, Transport::LocalIpc),
            write_without_binding,
            "{action:?}"
        );
    }
}

/// A-74, first half: an authenticated write over `LocalIpc` with
/// `{encrypted, sealed}` and `channel_bound: false` passes layer 2 — with an
/// Allow-all policy and a granting descriptor it is allowed.
#[test]
fn local_ipc_writes_are_accepted_without_channel_binding() {
    let pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_ALL, group())]));
    let pol = policy(vec![allow_everything(1)]);
    for (action, resource) in every_action() {
        let d = decide(
            &request(action.clone(), resource, Transport::LocalIpc, LOCAL),
            &pol,
            &pip,
        );
        assert_eq!(d.effect, Effect::Allow, "{action:?}: {d:?}");
        assert_eq!(d.reason, ReasonCode::Allowed, "{action:?}");
    }
}

/// A-74, second half: the same writes with the same transport security over
/// any other transport are still refused at layer 2 (`WeakTransport`) — the
/// exemption applies only to `LocalIpc`. Reads and the actions with no
/// binding floor are unaffected (they pass on every transport).
#[test]
fn other_transports_without_channel_binding_still_refuse_writes() {
    let pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_ALL, group())]));
    let pol = policy(vec![allow_everything(1)]);
    let mut refused = 0usize;
    for transport in NETWORK_TRANSPORTS {
        for (action, resource) in every_action() {
            let d = decide(
                &request(action.clone(), resource, transport, LOCAL),
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
    // DirControlRight, FileWrite, PolicyAdmin), each on eight transports.
    assert_eq!(refused, 6 * NETWORK_TRANSPORTS.len());
}

/// The exemption removes `channel_bound` only: a write over `LocalIpc`
/// without `sealed`, or without `encrypted`, is still `WeakTransport`.
#[test]
fn local_ipc_still_needs_encrypted_and_sealed_for_writes() {
    let pip = MockPip::with_sd(sd(None, vec![allow(RIGHT_GENERIC_ALL, group())]));
    let pol = policy(vec![allow_everything(1)]);
    for sec in [
        TransportSec {
            encrypted: true,
            sealed: false,
            channel_bound: false,
        },
        TransportSec {
            encrypted: false,
            sealed: true,
            channel_bound: false,
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

/// The exemption is part of the authenticated floor only (docs/11 §4 layer
/// 1 runs first): an unauthenticated write over `LocalIpc` is still
/// `Unauthenticated`.
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
        LOCAL,
    );
    req.subject.auth.ticket_verified = false;
    let d = decide(&req, &pol, &pip);
    assert_eq!(d.reason, ReasonCode::Unauthenticated);
}
