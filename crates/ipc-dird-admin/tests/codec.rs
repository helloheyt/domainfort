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
    MAX_DN_COMPONENTS, MAX_NAME, MAX_PRINCIPAL_NAME,
};
use ipc_dird_admin::{
    decode_request, encode_reply, AccountExpires, AccountKind, AdminReply, AdminRequest, Auth,
    Found, KeyTarget, LookupKey, Operation, PasswordSet, PasswordSetOutcome, RefusalStatus,
    Rejection, Reply, Request, ACCOUNT_EXPIRES_NEVER, ADMIN_CHANNEL, ADMIN_MAGIC, ADMIN_VERSION,
    MAX_REPLY_BODY, MAX_REQUEST_BODY, REPLY_LIMIT, REQUEST_LIMIT,
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
        Request::Ping,
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
    for reply in replies() {
        let body = reply_body(&reply);
        let decoded = match decode_reply::<AdminReply>(ADMIN_CHANNEL, &body).unwrap() {
            ipc::Reply::Message(m) => Reply::from_wire(&m).unwrap(),
            ipc::Reply::Refused(r) => panic!("{r:?}"),
        };
        assert_eq!(decoded, reply);
        assert!(reply_round_trip_is_canonical::<AdminReply>(ADMIN_CHANNEL, &body).unwrap());
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
/// an unused number between `Lookup` and `Ping`, and the reserved
/// `REFUSED_KIND` close the connection without a reply.
#[test]
fn unknown_kinds_close() {
    for kind in [0x00, 0x0E, 0x13, 0x15, 0x81, 0x7F, REFUSED_KIND] {
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
