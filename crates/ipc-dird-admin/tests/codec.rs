//! Tier 1 (docs/50 §9: "codecs: round-trip for every op, canonicity
//! (`encode(decode(b)) == b`), every bound, every unknown kind, a trailing
//! octet, a wrong version"): every request and reply kind of the admin
//! channel, its bounds, and the server-side disposition of what does not
//! decode.
//!
//! Sources: docs/51 §7.1-§7.3, §7.5; docs/50 §3.3, §9; A-59; A-85 (one
//! spelling of "never"). Every value is constructed by hand for these
//! tests (the SID layout is the [MS-DTYP] 2.4.2.4 example's); no vector
//! comes from any other implementation.

use dtyp::{Guid, Sid, SECURITY_NT_AUTHORITY};
use ipc::{
    decode_body, decode_reply, encode_frame, reply_round_trip_is_canonical,
    round_trip_is_canonical, Direction, FrameReader, Refused, REFUSED_KIND,
};
use ipc_dird_admin::channel::{
    request_kind, MAX_AP_REQ, MAX_DESCRIPTION, MAX_DNS_HOST_NAME, MAX_DN_COMPONENT,
    MAX_DN_COMPONENTS, MAX_NAME, MAX_POLICY_CHANGES, MAX_POLICY_DN_COMPONENTS, MAX_PRINCIPAL_NAME,
};
use ipc_dird_admin::{
    decode_request, encode_reply, AccountExpires, AccountKind, AdminReply, AdminRequest, Auth,
    Found, KeyOperation, KeyRef, KeyRequestState, KeyTarget, LookupKey, Operation, PasswordSet,
    PasswordSetOutcome, PolicyChange, PolicyTier, RefusalStatus, Rejection, Reply, Request,
    ACCOUNT_EXPIRES_NEVER, ADMIN_CHANNEL, ADMIN_MAGIC, ADMIN_VERSION, MAX_REPLY_BODY,
    MAX_REQUEST_BODY, REPLY_LIMIT, REQUEST_LIMIT,
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

fn auth(approvals: usize) -> Auth {
    Auth {
        requester: vec![0x6E; 300],
        approvals: (0..approvals).map(|i| vec![0x6E, i as u8, 1, 2]).collect(),
    }
}

fn op(operation: Operation) -> Request {
    Request::Operation {
        auth: auth(1),
        operation,
    }
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
            auth: auth(0),
            operation: Operation::Delete { target: guid(10) },
        },
        Request::Operation {
            auth: auth(2),
            operation: Operation::Delete { target: guid(11) },
        },
        // Task A10 (docs/51 §5.6, §6): the key-operation requests.
        op(Operation::RequestKeyOperation {
            operation: KeyOperation::RotateKrbtgt,
        }),
        op(Operation::RequestKeyOperation {
            operation: KeyOperation::RotateKey { service: guid(30) },
        }),
        op(Operation::RequestKeyOperation {
            operation: KeyOperation::RetireKvno {
                key: KeyRef::Krbtgt,
                kvno: 7,
            },
        }),
        op(Operation::Approve {
            id: u64::MAX,
            operation: KeyOperation::RetireKvno {
                key: KeyRef::Service(guid(31)),
                kvno: u32::MAX,
            },
        }),
        Request::Ping,
        // Task A16: every change of the tier-map edit, and the bound.
        Request::Operation {
            auth: auth(2),
            operation: Operation::ChangePolicy {
                changes: vec![
                    PolicyChange::AddPrincipal(sid(1200), PolicyTier::Tier1),
                    PolicyChange::RemovePrincipal(sid(1201)),
                    PolicyChange::AddSubtree(
                        vec!["ou=Lab".into(), "dc=example".into(), "dc=test".into()],
                        PolicyTier::Tier2,
                    ),
                    PolicyChange::RemoveSubtree(vec!["ou=Old".into(), "dc=test".into()]),
                ],
            },
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
        // Task A10.
        Reply::KeyRequest(KeyRequestState {
            id: 17,
            digest: [0xD1; 32],
            operation: KeyOperation::RotateKrbtgt,
            approvals: 1,
            quorum: 2,
        }),
        // Task A16.
        Reply::PolicyNext { version: 2 },
        Reply::PolicyNext { version: u64::MAX },
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

/// Task A10 (docs/51 §5.6, §6; docs/questions/Q-422): the key-operation
/// layouts, octet for octet, assembled here by hand from the decided
/// layout — `RequestKeyOperation := auth ‖ KeyOperation`; `Approve := auth ‖
/// id:u64 ‖ KeyOperation`; `KeyOperation := u8 1 | u8 2 ‖ [16] | u8 3 ‖
/// KeyRef ‖ u32`; `KeyRef := u8 1 | u8 2 ‖ [16]`. keyadm's requests are
/// retired (A-102): see [`retired_keyadm_kinds_are_unknown`].
#[test]
fn key_operation_layouts() {
    let auth_octets = |a: &Auth| {
        let mut out = Vec::new();
        out.extend((a.requester.len() as u32).to_be_bytes());
        out.extend(&a.requester);
        out.extend((a.approvals.len() as u32).to_be_bytes());
        for approval in &a.approvals {
            out.extend((approval.len() as u32).to_be_bytes());
            out.extend(approval);
        }
        out
    };
    let envelope = |kind: u8| {
        let mut out = ADMIN_MAGIC.to_be_bytes().to_vec();
        out.push(ADMIN_VERSION);
        out.push(kind);
        out
    };
    // RequestKeyOperation(RotateKrbtgt).
    let request = op(Operation::RequestKeyOperation {
        operation: KeyOperation::RotateKrbtgt,
    });
    let mut expected = envelope(0x0E);
    expected.extend(auth_octets(&auth(1)));
    expected.push(1);
    assert_eq!(request_body(&request), expected);
    // Approve(id 0x0102030405060708, RetireKvno(Service(g), 9)).
    let request = op(Operation::Approve {
        id: 0x0102_0304_0506_0708,
        operation: KeyOperation::RetireKvno {
            key: KeyRef::Service(guid(40)),
            kvno: 9,
        },
    });
    let mut expected = envelope(0x0F);
    expected.extend(auth_octets(&auth(1)));
    expected.extend([1, 2, 3, 4, 5, 6, 7, 8]);
    expected.extend([3, 2]);
    expected.extend(guid(40).to_packet());
    expected.extend(9u32.to_be_bytes());
    assert_eq!(request_body(&request), expected);
    let mut body = envelope(0x0E);
    body.extend(auth_octets(&auth(0)));
    body.push(4); // KeyOperation 4    let mut body = envelope(0x0E);
    body.extend(auth_octets(&auth(0)));
    body.push(4); // KeyOperation 4
    assert_eq!(
        decode_request(&body),
        Err(Rejection::Refuse(Refused::Malformed))
    );
    let mut body = envelope(0x0E);
    body.extend(auth_octets(&auth(0)));
    body.extend([3, 3]); // KeyRef 3
    body.extend(1u32.to_be_bytes());
    assert_eq!(
        decode_request(&body),
        Err(Rejection::Refuse(Refused::Malformed))
    );
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
    assert_eq!(request_kind::RETIRED, &[0x10, 0x11, 0x12]);
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
    assert_eq!(replies, &[0x89, 0x8A]);
    for kind in replies {
        assert!(!ipc_dird_admin::channel::reply_kind::ALL.contains(kind));
        let mut body = envelope(*kind);
        body.extend(17u64.to_be_bytes());
        assert!(decode_reply::<AdminReply>(ADMIN_CHANNEL, &body).is_err());
    }
}

/// docs/51 §7.2: the auth field carries at most two approvals.
#[test]
fn three_approvals_are_refused() {
    let request = Request::Operation {
        auth: auth(3),
        operation: Operation::Delete { target: guid(1) },
    };
    let wire = request.to_wire().unwrap();
    assert!(encode_frame(ADMIN_CHANNEL, Direction::Request, &wire).is_err());
    // Hand-built: the count octet raised to 3 (one approval of 4 octets
    // appended).
    let mut body = request_body(&Request::Operation {
        auth: auth(2),
        operation: Operation::Delete { target: guid(1) },
    });
    let count_at = 4 + 4 + 300;
    assert_eq!(&body[count_at..count_at + 4], &2u32.to_be_bytes());
    body[count_at..count_at + 4].copy_from_slice(&3u32.to_be_bytes());
    let insert_at = body.len() - 16;
    body.splice(insert_at..insert_at, [0, 0, 0, 1, 0x6E]);
    assert_eq!(
        decode_request(&body),
        Err(Rejection::Refuse(Refused::Malformed))
    );
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
        auth: Auth {
            requester: vec![1; n],
            approvals: vec![],
        },
        operation: Operation::Delete { target: guid(1) },
    });
    check_bound(MAX_AP_REQ, |n| Request::Operation {
        auth: Auth {
            requester: vec![1],
            approvals: vec![vec![2; n], vec![3; n]],
        },
        operation: Operation::Delete { target: guid(1) },
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

/// docs/51 §7.5: the largest request (three AP-REQs at their bound and the
/// largest payload) fits 256 KiB; a declared body over 256 KiB is refused at
/// the length prefix, before any body octet (docs/50 §3.3).
#[test]
fn the_body_bounds() {
    let largest = Request::Operation {
        auth: Auth {
            requester: vec![1; MAX_AP_REQ as usize],
            approvals: vec![vec![2; MAX_AP_REQ as usize], vec![3; MAX_AP_REQ as usize]],
        },
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
/// the deferred join token — task A12), and the reserved `REFUSED_KIND`
/// close the connection without a reply.
#[test]
fn unknown_kinds_close() {
    for kind in [0x00, 0x13, 0x15, 0x81, 0x7F, REFUSED_KIND] {
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
    let request = Request::Operation {
        auth: Auth {
            requester: vec![0xAA],
            approvals: vec![vec![0xBB]],
        },
        operation: Operation::ChangePolicy {
            changes: vec![
                PolicyChange::AddPrincipal(sid(7), PolicyTier::Tier1),
                PolicyChange::RemoveSubtree(vec!["ou=X".into()]),
            ],
        },
    };
    let mut expected = vec![0x44, 0x41, 0x01, 0x16];
    expected.extend([0, 0, 0, 1, 0xAA, 0, 0, 0, 1, 0, 0, 0, 1, 0xBB]);
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
