//! Tier 1 (docs/50 §9: "codecs: round-trip for every op, canonicity
//! (`encode(decode(b)) == b`), every bound, every unknown kind, a trailing
//! octet, a wrong version"): every request and reply kind of the admin
//! channel, its bounds, and the server-side disposition of what does not
//! decode.
//!
//! Sources: docs/51 §7.1-§7.3, §7.5; docs/50 §3.3, §9; A-59; A-85 (one
//! spelling of "never"); docs/questions/Q-882 (A-148: one dual-control
//! mechanism — the request queue's kinds; the in-request approvals and the
//! key-only kinds retired). Every value is constructed by hand for these
//! tests (the SID layout is the [MS-DTYP] 2.4.2.4 example's); no vector
//! comes from any other implementation.

use dtyp::{Guid, Sid, SECURITY_NT_AUTHORITY};
use ipc::{
    decode_body, decode_reply, encode_frame, reply_round_trip_is_canonical,
    round_trip_is_canonical, Direction, FrameReader, Refused, REFUSED_KIND,
};
use ipc_dird_admin::channel::{
    request_kind, MAX_AP_REQ, MAX_DESCRIPTION, MAX_DNS_HOST_NAME, MAX_DN_COMPONENT,
    MAX_DN_COMPONENTS, MAX_FACTS, MAX_LISTED_REQUESTS, MAX_NAME, MAX_POLICY_CHANGES,
    MAX_POLICY_DN_COMPONENTS, MAX_PRINCIPAL_NAME, MAX_REASON_REF, MAX_SID,
};
use ipc_dird_admin::{
    decode_request, encode_reply, AccountExpires, AccountKind, AdminReply, AdminRequest, Auth,
    Fact, FactTier, Found, KeyOperation, KeyRef, KeyTarget, ListScope, LookupKey, Operation,
    PasswordSet, PasswordSetOutcome, PendingRequestState, PolicyChange, PolicyTier, RefusalStatus,
    Rejection, Reply, Request, RequestShown, RequestState, RequestSummary, ACCOUNT_EXPIRES_NEVER,
    ADMIN_CHANNEL, ADMIN_MAGIC, ADMIN_VERSION, MAX_REPLY_BODY, MAX_REQUEST_BODY, REPLY_LIMIT,
    REQUEST_LIMIT,
};
use keyd_types::{KeyHandle, KeyPurpose, PrincipalBinding, PrincipalId};
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_HST};
use krb_proto::{KerberosString, PrincipalName};

fn guid(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0xDA,
        data3: 0x0001,
        data4: [0xD, 0xA, 0xD, 0xA, 0xD, 0xA, 0xD, 0xA],
    }
}

fn sid(rid: u32) -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, rid]).unwrap()
}

fn auth() -> Auth {
    Auth::of(vec![0x6E; 300])
}

/// `operation` as a request — a planned operation as the `Commit` of a plan
/// ([`planned`]: task MA2, a planned operation has no frame of its own).
fn op(operation: Operation) -> Request {
    Request::Operation {
        auth: auth(),
        operation: planned(operation),
    }
}

/// The plan digest the samples commit to.
const PLAN: [u8; 32] = [0x5C; 32];

/// A planned operation (`request_kind::PLANNED`) wrapped in the `Commit` of
/// [`PLAN`]; anything else as it is (docs/questions/Q-980).
fn planned(operation: Operation) -> Operation {
    // An operation without a wire form stays as it is (its request then has
    // none either).
    let Ok(wire) = operation.to_wire() else {
        return operation;
    };
    if ipc_dird_admin::channel::request_kind::PLANNED.contains(&wire.kind()) {
        Operation::Commit {
            plan: PLAN,
            operation: Box::new(operation),
        }
    } else {
        operation
    }
}

/// A small effect plan of every kind of effect but the account ones: alice
/// gains the T0-Admins group and enters Tier 0, which the tier map names.
fn sample_plan() -> ipc_dird_admin::EffectPlan {
    use ipc_dird_admin::{
        Effect, EffectPlan, PlanPrincipal, PlanPrincipalKind, PlanTier, PolicyReferenceKind,
    };
    use std::collections::BTreeSet;
    EffectPlan::new(
        [
            PlanPrincipal {
                sid: sid(1107),
                guid: guid(41),
                kind: PlanPrincipalKind::User,
                name: "alice2".into(),
            },
            PlanPrincipal {
                sid: sid(1105),
                guid: guid(40),
                kind: PlanPrincipalKind::Group,
                name: "T0-Admins".into(),
            },
        ],
        [
            Effect::MembershipDelta {
                gained: BTreeSet::from([sid(1105)]),
                lost: BTreeSet::new(),
                principals: BTreeSet::from([sid(1107)]),
            },
            Effect::TierDelta {
                subject: (PlanTier::None, PlanTier::Tier0),
                object: (PlanTier::None, PlanTier::Tier0),
                principals: BTreeSet::from([sid(1107)]),
            },
            Effect::PolicyReference {
                reference: PolicyReferenceKind::TierMap(PlanTier::Tier0),
                principals: BTreeSet::from([sid(1105)]),
            },
        ],
    )
    .unwrap()
}

fn kstr(s: &str) -> KerberosString {
    KerberosString::new(s).unwrap()
}

/// One sample of every request kind (and the optional fields both ways).
fn requests() -> Vec<Request> {
    vec![
        op(Operation::CreateUser {
            parent: guid(1),
            sam: "carol".into(),
            upn: Some("carol@example.test".into()),
            description: Some("Désirée's account".into()),
        }),
        op(Operation::CreateUser {
            parent: guid(1),
            sam: "dave".into(),
            upn: None,
            description: None,
        }),
        op(Operation::CreateComputer {
            parent: guid(2),
            name: "ws02".into(),
            dns_host_name: "ws02.example.test".into(),
            spn: Some("host/ws02.example.test".into()),
        }),
        op(Operation::CreateComputer {
            parent: guid(2),
            name: "ws03".into(),
            dns_host_name: "ws03.example.test".into(),
            spn: None,
        }),
        op(Operation::CreateGroup {
            parent: guid(3),
            sam: "ops".into(),
            group_type: Some(0x8000_0002),
        }),
        op(Operation::CreateGroup {
            parent: guid(3),
            sam: "ops2".into(),
            group_type: None,
        }),
        op(Operation::CreateOu {
            parent: guid(4),
            name: "Branch".into(),
        }),
        op(Operation::CreateContainer {
            parent: guid(4),
            name: "Things".into(),
        }),
        op(Operation::BeginPasswordSet { target: guid(5) }),
        op(Operation::CompletePasswordSet {
            target: guid(5),
            outcome: PasswordSetOutcome::Completed,
            kvnos: vec![2, 3],
        }),
        op(Operation::CompletePasswordSet {
            target: guid(5),
            outcome: PasswordSetOutcome::Failed,
            kvnos: vec![],
        }),
        op(Operation::SetEnabled {
            target: guid(6),
            enabled: false,
        }),
        op(Operation::SetAccountExpires {
            target: guid(6),
            value: AccountExpires::Never,
        }),
        op(Operation::SetAccountExpires {
            target: guid(6),
            value: AccountExpires::At(134_400_000_000_000_000),
        }),
        op(Operation::AddMember {
            group: guid(7),
            member: guid(8),
        }),
        op(Operation::RemoveMember {
            group: guid(7),
            member: guid(8),
        }),
        op(Operation::Delete { target: guid(9) }),
        op(Operation::Lookup(LookupKey::SamAccountName("carol".into()))),
        op(Operation::Lookup(LookupKey::ServicePrincipalName(
            "host/ws02.example.test".into(),
        ))),
        op(Operation::Lookup(LookupKey::Dn(vec![
            "cn=carol".into(),
            "ou=Staff".into(),
            "dc=example".into(),
            "dc=test".into(),
        ]))),
        Request::Operation {
            auth: auth(),
            operation: planned(Operation::Delete { target: guid(10) }),
        },
        Request::Operation {
            auth: auth(),
            operation: planned(Operation::Delete { target: guid(11) }),
        },
        // Task D2-c (docs/questions/Q-882): the request queue — a proposal of
        // every proposable kind's shape (a directory write, a policy change,
        // each key operation), with and without a reason; the steps.
        op(Operation::Propose {
            reason_ref: Some("CHG-1182".into()),
            operation: Box::new(planned(Operation::SetEnabled {
                target: guid(30),
                enabled: false,
            })),
        }),
        op(Operation::Propose {
            reason_ref: None,
            operation: Box::new(planned(Operation::ChangePolicy {
                changes: vec![PolicyChange::AddPrincipal(sid(1203), PolicyTier::Tier0)],
            })),
        }),
        op(Operation::Propose {
            reason_ref: None,
            operation: Box::new(planned(Operation::KeyOperation(KeyOperation::RotateKrbtgt))),
        }),
        op(Operation::Propose {
            reason_ref: None,
            operation: Box::new(planned(Operation::KeyOperation(KeyOperation::RotateKey {
                service: guid(30),
            }))),
        }),
        op(Operation::Propose {
            reason_ref: Some("x".into()),
            operation: Box::new(planned(Operation::KeyOperation(KeyOperation::RetireKvno {
                key: KeyRef::Service(guid(31)),
                kvno: u32::MAX,
            }))),
        }),
        // Task MA2: the plan of each planned shape.
        op(Operation::PlanOperation(Box::new(Operation::AddMember {
            group: guid(40),
            member: guid(41),
        }))),
        op(Operation::PlanOperation(Box::new(Operation::KeyOperation(
            KeyOperation::RotateKrbtgt,
        )))),
        op(Operation::Approve {
            id: u64::MAX,
            digest: [0xD1; 32],
        }),
        op(Operation::Reject {
            id: 1,
            digest: [0xD2; 32],
        }),
        op(Operation::Withdraw { id: 0x0102_0304 }),
        op(Operation::ListRequests(ListScope::Mine)),
        op(Operation::ListRequests(ListScope::AwaitingMe)),
        op(Operation::ShowRequest { id: 7 }),
        Request::Ping,
        // Task A16: every change of the tier-map edit, and the bound.
        Request::Operation {
            auth: auth(),
            operation: planned(Operation::ChangePolicy {
                changes: vec![
                    PolicyChange::AddPrincipal(sid(1200), PolicyTier::Tier1),
                    PolicyChange::RemovePrincipal(sid(1201)),
                    PolicyChange::AddSubtree(
                        vec!["ou=Lab".into(), "dc=example".into(), "dc=test".into()],
                        PolicyTier::Tier2,
                    ),
                    PolicyChange::RemoveSubtree(vec!["ou=Old".into(), "dc=test".into()]),
                ],
            }),
        },
        op(Operation::ChangePolicy {
            changes: vec![PolicyChange::AddPrincipal(sid(1202), PolicyTier::Tier0)],
        }),
    ]
}

fn binding(name: PrincipalName) -> PrincipalBinding {
    PrincipalBinding::new(kstr("EXAMPLE.TEST"), name)
}

/// One sample of every reply kind.
fn replies() -> Vec<Reply> {
    let longterm = KeyTarget {
        handle: KeyHandle::new(
            PrincipalId::from_bytes(guid(5).to_packet()),
            KeyPurpose::PrincipalLongterm,
        ),
        binding: binding(PrincipalName {
            name_type: KRB_NT_PRINCIPAL,
            name_string: vec![kstr("ws02$")],
        }),
    };
    let service = KeyTarget {
        handle: KeyHandle::new(
            PrincipalId::from_bytes(guid(5).to_packet()),
            KeyPurpose::Service,
        ),
        binding: binding(PrincipalName {
            name_type: KRB_NT_SRV_HST,
            name_string: vec![kstr("host"), kstr("ws02.example.test")],
        }),
    };
    vec![
        Reply::Created {
            guid: guid(20),
            sid: Some(sid(1120)),
        },
        Reply::Created {
            guid: guid(21),
            sid: None,
        },
        Reply::PasswordSet(PasswordSet {
            kind: AccountKind::Computer,
            keys: vec![longterm.clone(), service],
            salt: kstr("EXAMPLE.TESThostws02.example.test"),
        }),
        Reply::PasswordSet(PasswordSet {
            kind: AccountKind::User,
            keys: vec![longterm],
            salt: kstr("EXAMPLE.TESTcarol"),
        }),
        Reply::Done,
        Reply::Found(Found {
            guid: guid(22),
            dn: vec!["cn=carol".into(), "dc=example".into(), "dc=test".into()],
            class: "user".into(),
            sid: Some(sid(1121)),
        }),
        Reply::Found(Found {
            guid: guid(23),
            dn: vec!["ou=Staff".into(), "dc=example".into(), "dc=test".into()],
            class: "organizationalUnit".into(),
            sid: None,
        }),
        Reply::Refused(RefusalStatus::Denied),
        Reply::Refused(RefusalStatus::ApprovalRequired),
        Reply::Refused(RefusalStatus::NotFound),
        Reply::Refused(RefusalStatus::Invalid),
        Reply::Refused(RefusalStatus::Conflict),
        Reply::Refused(RefusalStatus::Unavailable),
        Reply::Pong,
        // Task D2-c (docs/questions/Q-882): the request queue's replies.
        Reply::PendingRequest(PendingRequestState {
            id: 17,
            digest: [0xD1; 32],
            state: RequestState::Pending,
            approvals: 0,
            quorum: 2,
            expires: 1_794_000_000,
        }),
        Reply::PendingRequest(PendingRequestState {
            id: u64::MAX,
            digest: [0xD2; 32],
            state: RequestState::Approved,
            approvals: 1,
            quorum: 2,
            expires: u64::MAX,
        }),
        Reply::RequestList(vec![]),
        Reply::RequestList(vec![RequestSummary {
            id: 9,
            digest: [0xD3; 32],
            state: RequestState::Pending,
            operation: request_kind::KEY_OPERATION,
            requester: sid(1104),
            approvals: 0,
            quorum: 2,
            expires: 5,
        }]),
        Reply::RequestShown(Box::new(RequestShown {
            id: 9,
            digest: [0xD4; 32],
            state: RequestState::Pending,
            requester: sid(1104),
            approvers: vec![],
            quorum: 2,
            expires: 5,
            reason_ref: Some("CHG-1182".into()),
            // Task MA2: the `Commit` of the plan dird holds, shown beside it.
            operation: Operation::Commit {
                plan: sample_plan().digest().unwrap(),
                operation: Box::new(Operation::AddMember {
                    group: guid(40),
                    member: guid(41),
                }),
            },
            facts: vec![
                Fact {
                    guid: guid(40),
                    dn: vec!["cn=T0-Admins".into(), "dc=example".into(), "dc=test".into()],
                    class: "group".into(),
                    sid: Some(sid(1105)),
                    tier: FactTier::Tier0,
                },
                Fact {
                    guid: guid(41),
                    dn: vec!["cn=alice2".into(), "dc=example".into(), "dc=test".into()],
                    class: "user".into(),
                    sid: Some(sid(1107)),
                    tier: FactTier::Unclassified,
                },
            ],
            plan: Some(sample_plan()),
        })),
        Reply::RequestShown(Box::new(RequestShown {
            id: 10,
            digest: [0xD5; 32],
            state: RequestState::Approved,
            requester: sid(1104),
            approvers: vec![sid(1106)],
            quorum: 2,
            expires: 6,
            reason_ref: None,
            operation: Operation::Commit {
                plan: ipc_dird_admin::EffectPlan::empty().digest().unwrap(),
                operation: Box::new(Operation::KeyOperation(KeyOperation::RotateKrbtgt)),
            },
            facts: vec![],
            plan: Some(ipc_dird_admin::EffectPlan::empty()),
        })),
        // A create's request: no plan.
        Reply::RequestShown(Box::new(RequestShown {
            id: 11,
            digest: [0xD6; 32],
            state: RequestState::Pending,
            requester: sid(1104),
            approvers: vec![],
            quorum: 2,
            expires: 7,
            reason_ref: None,
            operation: Operation::CreateOu {
                parent: guid(4),
                name: "Lab".into(),
            },
            facts: vec![],
            plan: None,
        })),
        // Task A16.
        Reply::PolicyNext { version: 2 },
        Reply::PolicyNext { version: u64::MAX },
        // Task MA2.
        Reply::Plan {
            plan: sample_plan(),
            digest: sample_plan().digest().unwrap(),
        },
        Reply::Plan {
            plan: ipc_dird_admin::EffectPlan::empty(),
            digest: ipc_dird_admin::EffectPlan::empty().digest().unwrap(),
        },
    ]
}

fn request_body(request: &Request) -> Vec<u8> {
    let wire = request.to_wire().unwrap();
    encode_frame(ADMIN_CHANNEL, Direction::Request, &wire)
        .unwrap()
        .body()
        .to_vec()
}

fn reply_body(reply: &Reply) -> Vec<u8> {
    encode_reply(reply).unwrap().body().to_vec()
}

/// docs/50 §3.3, §9 (round trip, canonicity); docs/51 §7.3: every request
/// kind decodes back to itself, typed and wire, and re-encodes to the same
/// octets.
#[test]
fn every_request_round_trips_canonically() {
    let mut kinds = std::collections::BTreeSet::new();
    for request in requests() {
        let body = request_body(&request);
        assert_eq!(&body[..2], &ADMIN_MAGIC.to_be_bytes());
        assert_eq!(body[2], ADMIN_VERSION);
        kinds.insert(body[3]);
        assert_eq!(decode_request(&body).unwrap(), request);
        assert!(
            round_trip_is_canonical::<AdminRequest>(ADMIN_CHANNEL, Direction::Request, &body)
                .unwrap()
        );
    }
    let all: std::collections::BTreeSet<u8> = request_kind::ALL.iter().copied().collect();
    assert_eq!(kinds, all, "every request kind sampled");
}

/// docs/50 §3.3, §9; docs/51 §7.3: every reply kind round-trips.
#[test]
fn every_reply_round_trips_canonically() {
    let mut kinds = std::collections::BTreeSet::new();
    for reply in replies() {
        kinds.insert(reply_body(&reply)[3]);
        let body = reply_body(&reply);
        let decoded = match decode_reply::<AdminReply>(ADMIN_CHANNEL, &body).unwrap() {
            ipc::Reply::Message(m) => Reply::from_wire(&m).unwrap(),
            ipc::Reply::Refused(r) => panic!("{r:?}"),
        };
        assert_eq!(decoded, reply);
        assert!(reply_round_trip_is_canonical::<AdminReply>(ADMIN_CHANNEL, &body).unwrap());
    }
    let all: std::collections::BTreeSet<u8> = ipc_dird_admin::channel::reply_kind::ALL
        .iter()
        .copied()
        .collect();
    assert_eq!(kinds, all, "every reply kind sampled");
}

/// Task D2-c (docs/questions/Q-882 items 1, 6): the request queue's layouts,
/// octet for octet, assembled here by hand from the decided layout —
/// `auth := requester:bytes ‖ approvals:seq<_, 0>` (the retired count, 0);
/// `Propose := auth ‖ reason_ref:Option<bytes<64>> ‖ kind:u8 ‖ fields`;
/// `Approve := auth ‖ id:u64 ‖ digest:[32]`; `Withdraw := auth ‖ id:u64`;
/// `ListRequests := auth ‖ scope:u8`; `KeyOperation := u8 1 | u8 2 ‖ [16] |
/// u8 3 ‖ KeyRef ‖ u32` under the inner kind `0x1D`; and the replies
/// `PendingRequest := id ‖ digest ‖ state ‖ approvals ‖ quorum ‖
/// expires:u64`.
#[test]
fn request_queue_layouts() {
    let auth_octets = |a: &Auth| {
        let mut out = Vec::new();
        out.extend((a.requester.len() as u32).to_be_bytes());
        out.extend(&a.requester);
        out.extend(0u32.to_be_bytes()); // the retired approvals: always none
        out
    };
    let envelope = |kind: u8| {
        let mut out = ADMIN_MAGIC.to_be_bytes().to_vec();
        out.push(ADMIN_VERSION);
        out.push(kind);
        out
    };
    // Task MA2: a planned operation is proposed as the `Commit` of its plan:
    // `0x1F ‖ plan:[32] ‖ inner kind ‖ fields`.
    // Propose(reason "CHG-1", Commit(PLAN, RotateKrbtgt)).
    let request = op(Operation::Propose {
        reason_ref: Some("CHG-1".into()),
        operation: Box::new(planned(Operation::KeyOperation(KeyOperation::RotateKrbtgt))),
    });
    let mut expected = envelope(0x17);
    expected.extend(auth_octets(&auth()));
    expected.extend([1, 0, 0, 0, 5]);
    expected.extend(b"CHG-1");
    expected.push(0x1F);
    expected.extend(PLAN);
    expected.extend([0x1D, 1]); // KeyOperation ‖ RotateKrbtgt
    assert_eq!(request_body(&request), expected);
    // Propose(no reason, Commit(PLAN, RetireKvno(Service(g), 9))).
    let request = op(Operation::Propose {
        reason_ref: None,
        operation: Box::new(planned(Operation::KeyOperation(KeyOperation::RetireKvno {
            key: KeyRef::Service(guid(40)),
            kvno: 9,
        }))),
    });
    let mut expected = envelope(0x17);
    expected.extend(auth_octets(&auth()));
    expected.extend([0, 0x1F]);
    expected.extend(PLAN);
    expected.extend([0x1D, 3, 2]);
    expected.extend(guid(40).to_packet());
    expected.extend(9u32.to_be_bytes());
    assert_eq!(request_body(&request), expected);
    // Propose(Commit(PLAN, Delete(g))): the inner kind is Delete's own (0x0C).
    let request = op(Operation::Propose {
        reason_ref: None,
        operation: Box::new(planned(Operation::Delete { target: guid(41) })),
    });
    let mut expected = envelope(0x17);
    expected.extend(auth_octets(&auth()));
    expected.extend([0, 0x1F]);
    expected.extend(PLAN);
    expected.push(0x0C);
    expected.extend(guid(41).to_packet());
    assert_eq!(request_body(&request), expected);
    // Commit(PLAN, Delete(g)) and PlanOperation(Delete(g)) at top level.
    let request = op(Operation::Delete { target: guid(41) });
    let mut expected = envelope(0x1F);
    expected.extend(auth_octets(&auth()));
    expected.extend(PLAN);
    expected.push(0x0C);
    expected.extend(guid(41).to_packet());
    assert_eq!(request_body(&request), expected);
    let request = op(Operation::PlanOperation(Box::new(Operation::Delete {
        target: guid(41),
    })));
    let mut expected = envelope(0x1E);
    expected.extend(auth_octets(&auth()));
    expected.push(0x0C);
    expected.extend(guid(41).to_packet());
    assert_eq!(request_body(&request), expected);
    // Approve(id 0x0102030405060708, digest).
    let request = op(Operation::Approve {
        id: 0x0102_0304_0506_0708,
        digest: [0xA5; 32],
    });
    let mut expected = envelope(0x18);
    expected.extend(auth_octets(&auth()));
    expected.extend([1, 2, 3, 4, 5, 6, 7, 8]);
    expected.extend([0xA5; 32]);
    assert_eq!(request_body(&request), expected);
    // Reject has Approve's layout under 0x19; Withdraw / ShowRequest an id.
    let request = op(Operation::Reject {
        id: 2,
        digest: [0x5A; 32],
    });
    let mut expected = envelope(0x19);
    expected.extend(auth_octets(&auth()));
    expected.extend(2u64.to_be_bytes());
    expected.extend([0x5A; 32]);
    assert_eq!(request_body(&request), expected);
    for (operation, kind) in [
        (Operation::Withdraw { id: 3 }, 0x1A),
        (Operation::ShowRequest { id: 3 }, 0x1C),
    ] {
        let mut expected = envelope(kind);
        expected.extend(auth_octets(&auth()));
        expected.extend(3u64.to_be_bytes());
        assert_eq!(request_body(&op(operation)), expected);
    }
    for (scope, code) in [(ListScope::Mine, 1u8), (ListScope::AwaitingMe, 2)] {
        let mut expected = envelope(0x1B);
        expected.extend(auth_octets(&auth()));
        expected.push(code);
        assert_eq!(request_body(&op(Operation::ListRequests(scope))), expected);
    }
    // PendingRequest.
    let reply = reply_body(&Reply::PendingRequest(PendingRequestState {
        id: 0x11,
        digest: [0xEE; 32],
        state: RequestState::Approved,
        approvals: 1,
        quorum: 2,
        expires: 0x0203,
    }));
    let mut expected = envelope(0x8C);
    expected.extend(0x11u64.to_be_bytes());
    expected.extend([0xEE; 32]);
    expected.extend([2, 1, 2]);
    expected.extend(0x0203u64.to_be_bytes());
    assert_eq!(reply, expected);
    // Strictness: an unknown key-operation tag, key-reference tag, scope
    // and request state are malformed.
    let mut body = envelope(0x17);
    body.extend(auth_octets(&auth()));
    body.extend([0, 0x1D, 4]); // KeyOperation 4
    assert_eq!(
        decode_request(&body),
        Err(Rejection::Refuse(Refused::Malformed))
    );
    let mut body = envelope(0x17);
    body.extend(auth_octets(&auth()));
    body.extend([0, 0x1D, 3, 3]); // KeyRef 3
    body.extend(1u32.to_be_bytes());
    assert_eq!(
        decode_request(&body),
        Err(Rejection::Refuse(Refused::Malformed))
    );
    for bad in [0u8, 3, 0xFF] {
        let mut body = envelope(0x1B);
        body.extend(auth_octets(&auth()));
        body.push(bad);
        assert_eq!(
            decode_request(&body),
            Err(Rejection::Refuse(Refused::Malformed)),
            "scope {bad}"
        );
    }
    let mut bad_state = reply.clone();
    bad_state[4 + 8 + 32] = 3;
    assert!(decode_reply::<AdminReply>(ADMIN_CHANNEL, &bad_state).is_err());
}

/// Task D2-c (docs/questions/Q-882 item 1): only `request_kind::PROPOSABLE`
/// may be proposed — a `Lookup`, a `CompletePasswordSet`, a queue step or a
/// `Propose` inside a `Propose` is refused on encoding and malformed on
/// decoding; the inner key-operation kind alone is no request (it does not
/// encode, and a frame of it closes).
#[test]
fn only_proposable_operations_are_proposed() {
    let nested = |inner: Operation| {
        op(Operation::Propose {
            reason_ref: None,
            operation: Box::new(inner),
        })
    };
    for inner in [
        Operation::Lookup(LookupKey::SamAccountName("a".into())),
        Operation::CompletePasswordSet {
            target: guid(1),
            outcome: PasswordSetOutcome::Completed,
            kvnos: vec![1],
        },
        Operation::Approve {
            id: 1,
            digest: [0; 32],
        },
        Operation::Withdraw { id: 1 },
        Operation::ListRequests(ListScope::Mine),
        Operation::ShowRequest { id: 1 },
        Operation::Propose {
            reason_ref: None,
            operation: Box::new(planned(Operation::Delete { target: guid(1) })),
        },
        // Task MA2: a bare planned operation, and a plan request, are not
        // proposable (only the `Commit` of a plan is).
        Operation::Delete { target: guid(1) },
        Operation::PlanOperation(Box::new(Operation::Delete { target: guid(1) })),
    ] {
        let wire = nested(inner.clone()).to_wire().unwrap();
        assert!(
            encode_frame(ADMIN_CHANNEL, Direction::Request, &wire).is_err(),
            "{inner:?}"
        );
    }
    // Hand-built: a Propose whose inner kind is Lookup's (0x0D), Propose's
    // (0x17) or Approve's (0x18) — malformed.
    let delete = request_body(&nested(planned(Operation::Delete { target: guid(2) })));
    let kind_at = delete.len() - 16 - 1;
    assert_eq!(delete[kind_at], 0x0C);
    assert_eq!(delete[kind_at - 33], 0x1F);
    for bad in [0x0D, 0x07, 0x17, 0x18, 0x1B, 0x14, 0x0E, 0x0F] {
        let mut body = delete.clone();
        body[kind_at] = bad;
        assert_eq!(
            decode_request(&body),
            Err(Rejection::Refuse(Refused::Malformed)),
            "{bad:#x}"
        );
    }
    // The inner key-operation kind on its own: no encoding, a close.
    let alone = op(Operation::KeyOperation(KeyOperation::RotateKrbtgt));
    let wire = alone.to_wire().unwrap();
    assert!(encode_frame(ADMIN_CHANNEL, Direction::Request, &wire).is_err());
    let mut body = request_body(&Request::Ping);
    body[3] = request_kind::KEY_OPERATION;
    assert_eq!(decode_request(&body), Err(Rejection::Close));
}
/// A-102 (docs/52 §4.6, §4.8; docs/questions/Q-460): keyadm's
/// `FetchApproved` / `Complete` / `ListPendingDestruction` (`0x10`–`0x12`)
/// are retired — they are not in the closed request table, so a frame of
/// one closes the connection without a reply, whatever its payload (the
/// former layouts: an id; an id and an outcome; a cursor); their replies
/// `Approved` / `PendingDestruction` (`0x89`, `0x8A`) are not in the reply
/// table either. The numbers stay unused.
#[test]
fn retired_keyadm_kinds_are_unknown() {
    let envelope = |kind: u8| {
        let mut out = ADMIN_MAGIC.to_be_bytes().to_vec();
        out.push(ADMIN_VERSION);
        out.push(kind);
        out
    };
    assert_eq!(request_kind::RETIRED, &[0x0E, 0x0F, 0x10, 0x11, 0x12]);
    for kind in request_kind::RETIRED {
        assert!(!request_kind::ALL.contains(kind), "{kind:#x}");
    }
    for (kind, payload) in [
        (0x10u8, 5u64.to_be_bytes().to_vec()),
        (
            0x11,
            [5u64.to_be_bytes().to_vec(), vec![1, 1, 0, 0, 0, 3]].concat(),
        ),
        (0x12, vec![0]),
    ] {
        let mut body = envelope(kind);
        body.extend(payload);
        assert_eq!(decode_request(&body), Err(Rejection::Close), "{kind:#x}");
    }
    let replies = ipc_dird_admin::channel::reply_kind::RETIRED;
    assert_eq!(replies, &[0x88, 0x89, 0x8A]);
    for kind in replies {
        assert!(!ipc_dird_admin::channel::reply_kind::ALL.contains(kind));
        let mut body = envelope(*kind);
        body.extend(17u64.to_be_bytes());
        assert!(decode_reply::<AdminReply>(ADMIN_CHANNEL, &body).is_err());
    }
}

/// Task D2-c (docs/questions/Q-882 item 6, A-148): the in-request approvals
/// are retired — `Auth` has no field for them, and on the wire the sequence
/// keeps only its count, always 0: a request that still carries an approval
/// (the old form, count 1 or 2 and an AP-REQ) is malformed, whatever its
/// kind, before anything after `auth` is read. The retired key-only kinds
/// (`0x0E` `RequestKeyOperation`, `0x0F` `Approve {id, operation}`) close the
/// connection like any unknown kind.
#[test]
fn in_request_approvals_are_retired() {
    let body = request_body(&Request::Operation {
        auth: auth(),
        operation: planned(Operation::Delete { target: guid(1) }),
    });
    let count_at = 4 + 4 + 300;
    assert_eq!(&body[count_at..count_at + 4], &0u32.to_be_bytes());
    for approvals in [1u32, 2, 3] {
        // The old form: the count, then that many AP-REQs of 4 octets.
        let mut old = body[..count_at].to_vec();
        old.extend(approvals.to_be_bytes());
        for _ in 0..approvals {
            old.extend([0, 0, 0, 4, 0x6E, 0x6E, 0x6E, 0x6E]);
        }
        old.extend(&body[count_at + 4..]);
        assert_eq!(
            decode_request(&old),
            Err(Rejection::Refuse(Refused::Malformed)),
            "{approvals} approvals"
        );
    }
    // The same for a ChangePolicy, which carried its approvers this way.
    let policy = request_body(&op(Operation::ChangePolicy {
        changes: vec![PolicyChange::AddPrincipal(sid(5), PolicyTier::Tier0)],
    }));
    let mut old = policy[..count_at].to_vec();
    old.extend(1u32.to_be_bytes());
    old.extend([0, 0, 0, 1, 0xBB]);
    old.extend(&policy[count_at + 4..]);
    assert_eq!(
        decode_request(&old),
        Err(Rejection::Refuse(Refused::Malformed))
    );
    // The retired key-only kinds: their former layouts close.
    let envelope = |kind: u8| {
        let mut out = ADMIN_MAGIC.to_be_bytes().to_vec();
        out.push(ADMIN_VERSION);
        out.push(kind);
        out
    };
    for (kind, payload) in [
        (0x0Eu8, vec![1]),
        (0x0F, [5u64.to_be_bytes().to_vec(), vec![1]].concat()),
    ] {
        let mut frame = envelope(kind);
        frame.extend(&body[4..count_at + 4]);
        frame.extend(payload);
        assert_eq!(decode_request(&frame), Err(Rejection::Close), "{kind:#x}");
    }
}

/// The `bytes<max>` bound of `field` in `make(len)`: `max` octets pass,
/// `max + 1` are refused on encoding and, built by hand, on decoding.
fn check_bound(max: u32, make: impl Fn(usize) -> Request) {
    let at = make(max as usize);
    let body = request_body(&at);
    assert_eq!(decode_request(&body).unwrap(), at);
    let over = make(max as usize + 1);
    let wire = over.to_wire().unwrap();
    assert!(encode_frame(ADMIN_CHANNEL, Direction::Request, &wire).is_err());
}

/// docs/51 §7.5 (every bound), docs/50 §9: each byte-string field at its
/// bound and one past it.
#[test]
fn every_field_bound() {
    let ascii = |n: usize| "a".repeat(n);
    check_bound(MAX_AP_REQ, |n| Request::Operation {
        auth: Auth::of(vec![1; n]),
        operation: planned(Operation::Delete { target: guid(1) }),
    });
    // Task D2-c: the `reason_ref` of a `Propose`.
    check_bound(MAX_REASON_REF, |n| {
        op(Operation::Propose {
            reason_ref: Some(ascii(n)),
            operation: Box::new(planned(Operation::Delete { target: guid(1) })),
        })
    });
    check_bound(MAX_NAME, |n| {
        op(Operation::CreateUser {
            parent: guid(1),
            sam: ascii(n),
            upn: None,
            description: None,
        })
    });
    check_bound(MAX_PRINCIPAL_NAME, |n| {
        op(Operation::CreateUser {
            parent: guid(1),
            sam: "x".into(),
            upn: Some(ascii(n)),
            description: None,
        })
    });
    check_bound(MAX_DESCRIPTION, |n| {
        op(Operation::CreateUser {
            parent: guid(1),
            sam: "x".into(),
            upn: None,
            description: Some(ascii(n)),
        })
    });
    check_bound(MAX_DNS_HOST_NAME, |n| {
        op(Operation::CreateComputer {
            parent: guid(1),
            name: "x".into(),
            dns_host_name: ascii(n),
            spn: None,
        })
    });
    check_bound(MAX_PRINCIPAL_NAME, |n| {
        op(Operation::CreateComputer {
            parent: guid(1),
            name: "x".into(),
            dns_host_name: "x".into(),
            spn: Some(ascii(n)),
        })
    });
    check_bound(MAX_NAME, |n| {
        op(Operation::CreateOu {
            parent: guid(1),
            name: ascii(n),
        })
    });
    check_bound(MAX_NAME, |n| {
        op(Operation::Lookup(LookupKey::SamAccountName(ascii(n))))
    });
    check_bound(MAX_PRINCIPAL_NAME, |n| {
        op(Operation::Lookup(LookupKey::ServicePrincipalName(ascii(n))))
    });
    check_bound(MAX_DN_COMPONENT, |n| {
        op(Operation::Lookup(LookupKey::Dn(vec![ascii(n)])))
    });
    // Sequence bounds: 64 DN components, 2 kvnos.
    check_bound(MAX_DN_COMPONENTS, |n| {
        op(Operation::Lookup(LookupKey::Dn(vec!["dc=x".into(); n])))
    });
    check_bound(2, |n| {
        op(Operation::CompletePasswordSet {
            target: guid(1),
            outcome: PasswordSetOutcome::Completed,
            kvnos: vec![1; n],
        })
    });
}

/// docs/51 §7.5: the largest request (the AP-REQ at its bound and the
/// largest payload) fits 256 KiB; a declared body over 256 KiB is refused at
/// the length prefix, before any body octet (docs/50 §3.3).
#[test]
fn the_body_bounds() {
    let largest = Request::Operation {
        auth: Auth::of(vec![1; MAX_AP_REQ as usize]),
        operation: Operation::Lookup(LookupKey::Dn(vec![
            "c".repeat(MAX_DN_COMPONENT as usize);
            MAX_DN_COMPONENTS as usize
        ])),
    };
    let body = request_body(&largest);
    assert!(body.len() <= MAX_REQUEST_BODY as usize);
    assert_eq!(decode_request(&body).unwrap(), largest);

    let mut reader = FrameReader::new(REQUEST_LIMIT);
    let prefix = (MAX_REQUEST_BODY + 1).to_be_bytes();
    assert!(reader.push(&prefix).is_err(), "over-bound length refused");
    let mut reader = FrameReader::new(REPLY_LIMIT);
    let prefix = (MAX_REPLY_BODY + 1).to_be_bytes();
    assert!(reader.push(&prefix).is_err(), "over-bound reply refused");
    // A body handed over directly past the bound is refused too.
    let mut huge = body.clone();
    huge.resize(MAX_REQUEST_BODY as usize + 1, 0);
    assert_eq!(decode_request(&huge), Err(Rejection::Close));
}

/// docs/50 §3.3 ("kind closed: unknown op ⇒ close"); A-59: an unknown kind,
/// the unused number between the key-operation requests and `Ping` (`0x13`,
/// the deferred join token — task A12), the inner kind of a proposed key
/// operation (`0x1D`, never a request of its own — task D2-c), the first
/// number after the request queue, and the reserved `REFUSED_KIND` close
/// the connection without a reply.
#[test]
fn unknown_kinds_close() {
    // Task MA2: the planned kinds (0x06, 0x08-0x0C, 0x16) left the table;
    // 0x1E / 0x1F are `PlanOperation` / `Commit`, so 0x20 is unused.
    for kind in [
        0x00,
        0x06,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x13,
        0x15,
        0x16,
        0x1D,
        0x20,
        0x81,
        0x7F,
        REFUSED_KIND,
    ] {
        let mut body = request_body(&Request::Ping);
        body[3] = kind;
        assert_eq!(decode_request(&body), Err(Rejection::Close), "{kind:#x}");
    }
}

/// docs/50 §3.3 ("no trailing byte … `Malformed` + close").
#[test]
fn a_trailing_octet_is_malformed() {
    for request in requests() {
        let mut body = request_body(&request);
        body.push(0);
        assert_eq!(
            decode_request(&body),
            Err(Rejection::Refuse(Refused::Malformed))
        );
    }
}

/// docs/50 §3.3 (exact version ⇒ `Refused{VersionMismatch}` + close; magic
/// mismatch ⇒ close).
#[test]
fn wrong_version_and_wrong_magic() {
    let mut body = request_body(&Request::Ping);
    body[2] = ADMIN_VERSION + 1;
    assert_eq!(
        decode_request(&body),
        Err(Rejection::Refuse(Refused::VersionMismatch))
    );
    let mut body = request_body(&Request::Ping);
    body[0..2].copy_from_slice(&0x4452u16.to_be_bytes());
    assert_eq!(decode_request(&body), Err(Rejection::Close));
}

/// docs/50 §3.3 ("a single encoding per value"); A-85: "never" has one
/// spelling — `At(0x7FFFFFFFFFFFFFFF)` is refused both ways; text must be
/// UTF-8; a closed code outside its table is malformed.
#[test]
fn second_spellings_and_bad_values_are_malformed() {
    let never_as_at = op(Operation::SetAccountExpires {
        target: guid(1),
        value: AccountExpires::At(ACCOUNT_EXPIRES_NEVER),
    });
    assert!(never_as_at.to_wire().is_err());
    let mut body = request_body(&op(Operation::SetAccountExpires {
        target: guid(1),
        value: AccountExpires::At(1),
    }));
    let n = body.len();
    body[n - 8..].copy_from_slice(&ACCOUNT_EXPIRES_NEVER.to_be_bytes());
    assert_eq!(
        decode_request(&body),
        Err(Rejection::Refuse(Refused::Malformed))
    );

    let mut body = request_body(&op(Operation::Lookup(LookupKey::SamAccountName(
        "ab".into(),
    ))));
    let n = body.len();
    body[n - 1] = 0xFF;
    assert_eq!(
        decode_request(&body),
        Err(Rejection::Refuse(Refused::Malformed))
    );

    // SetEnabled with a boolean octet 2; CompletePasswordSet outcome 3; a
    // lookup tag 4; an expiry tag 3.
    for (request, offset_from_end, value) in [
        (
            op(Operation::SetEnabled {
                target: guid(1),
                enabled: true,
            }),
            1,
            2u8,
        ),
        (
            op(Operation::CompletePasswordSet {
                target: guid(1),
                outcome: PasswordSetOutcome::Failed,
                kvnos: vec![],
            }),
            5,
            3,
        ),
        (
            op(Operation::Lookup(LookupKey::SamAccountName("a".into()))),
            6,
            4,
        ),
        (
            op(Operation::SetAccountExpires {
                target: guid(1),
                value: AccountExpires::Never,
            }),
            1,
            3,
        ),
    ] {
        let mut body = request_body(&request);
        let n = body.len();
        body[n - offset_from_end] = value;
        assert_eq!(
            decode_request(&body),
            Err(Rejection::Refuse(Refused::Malformed)),
            "{request:?}"
        );
    }
}

/// docs/50 §3.3 ("replies are decoded with the same strictness"): an
/// unknown status, a `Krbtgt` key purpose, a trailing octet and a bad SID
/// in a reply are refused by the client's decoder.
#[test]
fn replies_are_decoded_strictly() {
    let decode = |body: &[u8]| -> Result<Reply, ()> {
        match decode_reply::<AdminReply>(ADMIN_CHANNEL, body).map_err(|_| ())? {
            ipc::Reply::Message(m) => Reply::from_wire(&m).map_err(|_| ()),
            ipc::Reply::Refused(_) => Err(()),
        }
    };
    let mut body = reply_body(&Reply::Refused(RefusalStatus::Denied));
    body[4] = 0x07;
    assert!(decode(&body).is_err());
    let mut body = reply_body(&Reply::Done);
    body.push(0);
    assert!(decode(&body).is_err());
    let mut body = reply_body(&Reply::Created {
        guid: guid(1),
        sid: Some(sid(2000)),
    });
    body[4 + 16 + 1 + 4] = 2; // the SID's revision
    assert!(decode(&body).is_err());
    // The purpose octet of the first key target (after kind, count, the
    // principal).
    let set = Reply::PasswordSet(PasswordSet {
        kind: AccountKind::User,
        keys: vec![KeyTarget {
            handle: KeyHandle::new(
                PrincipalId::from_bytes([7; 16]),
                KeyPurpose::PrincipalLongterm,
            ),
            binding: binding(PrincipalName {
                name_type: KRB_NT_PRINCIPAL,
                name_string: vec![kstr("carol")],
            }),
        }],
        salt: kstr("EXAMPLE.TESTcarol"),
    });
    let mut body = reply_body(&set);
    body[4 + 1 + 4 + 16] = 0x00;
    assert!(decode(&body).is_err());
    // A Krbtgt key target has no wire form.
    let krbtgt = Reply::PasswordSet(PasswordSet {
        kind: AccountKind::User,
        keys: vec![KeyTarget {
            handle: KeyHandle::new(PrincipalId::from_bytes([7; 16]), KeyPurpose::Krbtgt),
            binding: binding(PrincipalName {
                name_type: KRB_NT_PRINCIPAL,
                name_string: vec![kstr("krbtgt")],
            }),
        }],
        salt: kstr("x"),
    });
    assert!(encode_reply(&krbtgt).is_err());
}

/// The wire decoder never sees a frame of the reply direction as a request
/// (kinds are per direction) and vice versa.
#[test]
fn directions_do_not_mix() {
    let body = reply_body(&Reply::Pong);
    assert!(decode_body::<AdminRequest>(ADMIN_CHANNEL, Direction::Request, &body).is_err());
    let body = request_body(&Request::Ping);
    assert!(decode_reply::<AdminReply>(ADMIN_CHANNEL, &body).is_err());
}

/// Task A16 (docs/51 §5.10; docs/questions/Q-592): the `ChangePolicy`
/// layout octet for octet — `auth ‖ changes:seq<PolicyChange, 4>`,
/// `PolicyChange := u8 1 ‖ sid:bytes<68> ‖ tier:u8 | u8 2 ‖ sid | u8 3 ‖
/// dn:seq<bytes<128>,16> ‖ tier | u8 4 ‖ dn`, `tier := 0 | 1 | 2` — and the
/// `PolicyNext` reply (`version:u64`), assembled by hand.
#[test]
fn change_policy_layout() {
    // Task MA2: the policy change travels as the `Commit` of its plan.
    let request = Request::Operation {
        auth: Auth::of(vec![0xAA]),
        operation: planned(Operation::ChangePolicy {
            changes: vec![
                PolicyChange::AddPrincipal(sid(7), PolicyTier::Tier1),
                PolicyChange::RemoveSubtree(vec!["ou=X".into()]),
            ],
        }),
    };
    let mut expected = vec![0x44, 0x41, 0x01, 0x1F];
    expected.extend([0, 0, 0, 1, 0xAA, 0, 0, 0, 0]); // requester; no approvals (retired)
    expected.extend(PLAN);
    expected.push(0x16); // ChangePolicy
    expected.extend([0, 0, 0, 2]);
    let packet = sid(7).encode();
    expected.push(0x01);
    expected.extend((packet.len() as u32).to_be_bytes());
    expected.extend(&packet);
    expected.push(0x01);
    expected.push(0x04);
    expected.extend([0, 0, 0, 1, 0, 0, 0, 4]);
    expected.extend(b"ou=X");
    assert_eq!(request_body(&request), expected);
    assert_eq!(decode_request(&expected).unwrap(), request);

    let reply = reply_body(&Reply::PolicyNext { version: 0x0102 });
    assert_eq!(
        reply,
        [0x44, 0x41, 0x01, 0x8B, 0, 0, 0, 0, 0, 0, 0x01, 0x02]
    );
}

/// Task A16 (docs/51 §7.5; docs/questions/Q-592): at most
/// `MAX_POLICY_CHANGES` changes and `MAX_POLICY_DN_COMPONENTS` components of
/// at most `MAX_DN_COMPONENT` octets — refused one past each bound; the
/// largest request fits the payload bound (it has a digest); `Untiered`
/// (the policy file's code 3) and unknown change tags are malformed; a SID
/// that does not decode is malformed.
#[test]
fn change_policy_bounds_and_codes() {
    let subtree = |components: usize, len: usize| {
        PolicyChange::AddSubtree(vec!["a".repeat(len); components], PolicyTier::Tier2)
    };
    let request = |changes: Vec<PolicyChange>| op(Operation::ChangePolicy { changes });
    // The largest request: every change a subtree at the component bounds.
    let largest_changes = vec![
        subtree(MAX_POLICY_DN_COMPONENTS as usize, MAX_DN_COMPONENT as usize);
        MAX_POLICY_CHANGES as usize
    ];
    let largest = request(largest_changes.clone());
    let body = request_body(&largest);
    assert_eq!(decode_request(&body).unwrap(), largest);
    assert!(ipc_dird_admin::operation_digest(&Operation::ChangePolicy {
        changes: largest_changes
    })
    .is_ok());
    // One past each bound does not encode.
    let unencodable = |r: Request| {
        let wire = r.to_wire().unwrap();
        encode_frame(ADMIN_CHANNEL, Direction::Request, &wire).is_err()
    };
    assert!(unencodable(request(vec![
        subtree(1, 1);
        MAX_POLICY_CHANGES as usize + 1
    ])));
    assert!(unencodable(request(vec![subtree(
        MAX_POLICY_DN_COMPONENTS as usize + 1,
        1
    )])));
    assert!(unencodable(request(vec![subtree(
        1,
        MAX_DN_COMPONENT as usize + 1
    )])));
    // A tier code outside the table (3 = Untiered in the policy file) and
    // an unknown change tag are malformed.
    let one = request(vec![PolicyChange::AddPrincipal(sid(9), PolicyTier::Tier0)]);
    let mut body = request_body(&one);
    let tier_at = body.len() - 1;
    for bad in [0x03, 0x04, 0xFF] {
        body[tier_at] = bad;
        assert_eq!(
            decode_request(&body),
            Err(Rejection::Refuse(Refused::Malformed)),
            "{bad:#x}"
        );
    }
    let tag_at = body.len() - 1 - sid(9).encode().len() - 4 - 1;
    let mut body = request_body(&one);
    for bad in [0x00, 0x05] {
        body[tag_at] = bad;
        assert_eq!(
            decode_request(&body),
            Err(Rejection::Refuse(Refused::Malformed)),
            "{bad:#x}"
        );
    }
    // A SID packet that does not decode (revision 2, [MS-DTYP] 2.4.2.2).
    let mut body = request_body(&one);
    body[tag_at + 1 + 4] = 0x02;
    assert_eq!(
        decode_request(&body),
        Err(Rejection::Refuse(Refused::Malformed))
    );
}

/// Task D2-c (docs/questions/Q-882 item 1; Q-936): the request queue's reply
/// bounds — at most `MAX_LISTED_REQUESTS` entries and `MAX_FACTS` facts — fit
/// the 64 KiB reply body at their largest (a `RequestShown` of the largest
/// proposable operation with two facts of 64-component DNs), and one past
/// each sequence bound is refused.
#[test]
fn request_queue_reply_bounds() {
    let largest_sid = Sid::new(SECURITY_NT_AUTHORITY, &[u32::MAX; 15]).unwrap();
    assert_eq!(largest_sid.encode().len(), MAX_SID as usize);
    let fact = |n: u32| Fact {
        guid: guid(n),
        dn: vec!["c".repeat(MAX_DN_COMPONENT as usize); MAX_DN_COMPONENTS as usize],
        class: "organizationalUnit".into(),
        sid: Some(largest_sid),
        tier: FactTier::Tier0,
    };
    let largest_create = Operation::CreateUser {
        parent: guid(1),
        sam: "a".repeat(MAX_NAME as usize),
        upn: Some("u".repeat(MAX_PRINCIPAL_NAME as usize)),
        description: Some("d".repeat(MAX_DESCRIPTION as usize)),
    };
    let shown = |facts: Vec<Fact>| {
        Reply::RequestShown(Box::new(RequestShown {
            id: u64::MAX,
            digest: [0xFF; 32],
            state: RequestState::Approved,
            requester: largest_sid,
            approvers: vec![largest_sid; 2],
            quorum: 3,
            expires: u64::MAX,
            reason_ref: Some("r".repeat(MAX_REASON_REF as usize)),
            operation: largest_create.clone(),
            facts,
            // A create has no plan; the largest plan beside the largest
            // operation is checked at compile time (crate::channel).
            plan: None,
        }))
    };
    let body = reply_body(&shown(vec![fact(1); MAX_FACTS as usize]));
    assert!(body.len() <= MAX_REPLY_BODY as usize, "{}", body.len());
    assert!(encode_reply(&shown(vec![fact(1); MAX_FACTS as usize + 1])).is_err());
    let summary = RequestSummary {
        id: 1,
        digest: [1; 32],
        state: RequestState::Pending,
        operation: request_kind::DELETE,
        requester: largest_sid,
        approvals: 0,
        quorum: 2,
        expires: 1,
    };
    let list = |n: usize| Reply::RequestList(vec![summary.clone(); n]);
    let body = reply_body(&list(MAX_LISTED_REQUESTS as usize));
    assert!(body.len() <= MAX_REPLY_BODY as usize);
    assert!(encode_reply(&list(MAX_LISTED_REQUESTS as usize + 1)).is_err());
    // A summary naming a kind that is not proposable has no wire form.
    let lookup = RequestSummary {
        operation: request_kind::LOOKUP,
        ..summary
    };
    assert!(encode_reply(&Reply::RequestList(vec![lookup])).is_err());
}

/// Task D2-c (docs/questions/Q-888): the digest an `Approve` names and a
/// `Propose`'s fingerprint are the operation digest of the proposed
/// operation sent on its own — the same function, the same octets: a
/// proposed `Delete` has the fingerprint of the `Delete` itself, and the
/// `Propose`'s own digest (what the requester's AP-REQ is bound to) differs
/// from it and covers the `reason_ref`.
#[test]
fn the_fingerprint_is_the_operations_own_digest() {
    // Task MA2: the operation proposed is the `Commit` of its plan.
    let delete = planned(Operation::Delete { target: guid(7) });
    let fingerprint = ipc_dird_admin::operation_digest(&delete).unwrap();
    let propose = |reason: Option<&str>| Operation::Propose {
        reason_ref: reason.map(str::to_owned),
        operation: Box::new(delete.clone()),
    };
    let a = ipc_dird_admin::operation_digest(&propose(None)).unwrap();
    let b = ipc_dird_admin::operation_digest(&propose(Some("CHG-1"))).unwrap();
    assert_ne!(a, fingerprint);
    assert_ne!(a, b);
    // A key operation's fingerprint: the inner kind's digest.
    let rotate = Operation::KeyOperation(KeyOperation::RotateKrbtgt);
    let retire = Operation::KeyOperation(KeyOperation::RetireKvno {
        key: KeyRef::Krbtgt,
        kvno: 2,
    });
    assert_ne!(
        ipc_dird_admin::operation_digest(&rotate).unwrap(),
        ipc_dird_admin::operation_digest(&retire).unwrap()
    );
}
