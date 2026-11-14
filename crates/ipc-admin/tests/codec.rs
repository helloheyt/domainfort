//! Tier 1 (docs/50 §9: "codecs: round-trip for every op, canonicity
//! (`encode(decode(b)) == b`), every bound, every unknown kind, a trailing
//! octet, a wrong version"): every request and reply kind of the
//! administrators' channel, its bounds, admind's disposition of what does
//! not decode, the forwarded operations' layouts (dird's, byte for byte),
//! and the password's absence from every `Debug` output.
//!
//! Sources: docs/51 §7.1-§7.3, §7.5, §7.6; docs/50 §3.3, §8.2, §9; A-59;
//! A-85 (one spelling of "never"); docs/questions/Q-400. Every value is
//! constructed by hand for these tests (the SID layout is the [MS-DTYP]
//! 2.4.2.4 example's); no vector comes from any other implementation.

use dtyp::{Guid, Sid, SECURITY_NT_AUTHORITY};
use ipc::{
    decode_body, encode_frame, reply_round_trip_is_canonical, round_trip_is_canonical, Direction,
    FrameReader, Refused, Secret, REFUSED_KIND,
};
use ipc_admin::channel::{
    reply_kind, request_kind, MAX_COMPLETION_AP_REQ, MAX_KVNOS, MAX_PASSWORD,
};
use ipc_admin::{
    answers, decode_reply, decode_request, encode_reply, encode_request, AdminReply, AdminRequest,
    ConversionError, Password, PasswordChanged, RefusalStatus, Rejected, Rejection, Reply, Request,
    SetPassword, WireSetPassword, ADMIN_CHANNEL, ADMIN_MAGIC, ADMIN_VERSION, MAX_REPLY_BODY,
    MAX_REQUEST_BODY, REPLY_LIMIT, REQUEST_LIMIT,
};
use ipc_dird_admin::channel::{MAX_AP_REQ, MAX_DN_COMPONENT, MAX_DN_COMPONENTS};
use ipc_dird_admin::{AccountExpires, Auth, Found, LookupKey, Operation, PasswordSetOutcome};
use zeroize::Zeroizing;

/// A password used only by these tests (test data).
const PASSWORD: &str = "Orchard-Lantern-7-Quiver";

fn guid(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0xAD,
        data3: 0x0009,
        data4: [0xA, 0xD, 0xA, 0xD, 0xA, 0xD, 0xA, 0xD],
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

fn forward(operation: Operation) -> Request {
    Request::Forward {
        auth: auth(1),
        operation,
    }
}

fn password(text: &str) -> Password {
    Password::new(Zeroizing::new(text.to_owned()))
}

fn set_password(text: &str, approvals: usize) -> Request {
    Request::SetPassword(SetPassword {
        auth: auth(approvals),
        completion: vec![0x6E; 77],
        target: guid(5),
        password: password(text),
    })
}

/// One sample of every forwarded operation (and the optional fields both
/// ways).
fn forwarded() -> Vec<Operation> {
    vec![
        Operation::CreateUser {
            parent: guid(1),
            sam: "carol".into(),
            upn: Some("carol@example.test".into()),
            description: Some("Désirée's account".into()),
        },
        Operation::CreateUser {
            parent: guid(1),
            sam: "dave".into(),
            upn: None,
            description: None,
        },
        Operation::CreateComputer {
            parent: guid(2),
            name: "ws02".into(),
            dns_host_name: "ws02.example.test".into(),
            spn: Some("host/ws02.example.test".into()),
        },
        Operation::CreateGroup {
            parent: guid(3),
            sam: "ops".into(),
            group_type: Some(0x8000_0002),
        },
        Operation::CreateGroup {
            parent: guid(3),
            sam: "ops2".into(),
            group_type: None,
        },
        Operation::CreateOu {
            parent: guid(4),
            name: "Branch".into(),
        },
        Operation::CreateContainer {
            parent: guid(4),
            name: "Things".into(),
        },
        Operation::SetEnabled {
            target: guid(6),
            enabled: false,
        },
        Operation::SetAccountExpires {
            target: guid(6),
            value: AccountExpires::Never,
        },
        Operation::SetAccountExpires {
            target: guid(6),
            value: AccountExpires::At(134_400_000_000_000_000),
        },
        Operation::AddMember {
            group: guid(7),
            member: guid(8),
        },
        Operation::RemoveMember {
            group: guid(7),
            member: guid(8),
        },
        Operation::Delete { target: guid(9) },
        Operation::Lookup(LookupKey::SamAccountName("carol".into())),
        Operation::Lookup(LookupKey::ServicePrincipalName(
            "host/ws02.example.test".into(),
        )),
        Operation::Lookup(LookupKey::Dn(vec![
            "cn=carol".into(),
            "ou=Staff".into(),
            "dc=example".into(),
            "dc=test".into(),
        ])),
    ]
}

/// One sample of every request kind.
fn requests() -> Vec<Request> {
    let mut all: Vec<Request> = forwarded().into_iter().map(forward).collect();
    all.push(Request::Forward {
        auth: auth(0),
        operation: Operation::Delete { target: guid(10) },
    });
    all.push(Request::Forward {
        auth: auth(2),
        operation: Operation::Delete { target: guid(11) },
    });
    all.push(set_password(PASSWORD, 0));
    all.push(set_password("ünïcødé-passwörd-☃-𝄞", 2));
    all.push(Request::Ping);
    all
}

/// One sample of every reply kind.
fn replies() -> Vec<Reply> {
    vec![
        Reply::Created {
            guid: guid(20),
            sid: Some(sid(1120)),
        },
        Reply::Created {
            guid: guid(21),
            sid: None,
        },
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
        Reply::PasswordChanged(PasswordChanged {
            kvnos: vec![1],
            completion_recorded: true,
        }),
        Reply::PasswordChanged(PasswordChanged {
            kvnos: vec![4, 4],
            completion_recorded: false,
        }),
        Reply::Refused(RefusalStatus::Denied),
        Reply::Refused(RefusalStatus::ApprovalRequired),
        Reply::Refused(RefusalStatus::NotFound),
        Reply::Refused(RefusalStatus::Invalid),
        Reply::Refused(RefusalStatus::Conflict),
        Reply::Refused(RefusalStatus::Unavailable),
        Reply::Refused(RefusalStatus::OutcomeUnknown),
        Reply::Refused(RefusalStatus::Incomplete),
        Reply::Pong,
    ]
}

fn request_body(request: &Request) -> Vec<u8> {
    encode_request(request).unwrap().body().to_vec()
}

fn reply_body(reply: &Reply) -> Vec<u8> {
    encode_reply(reply).unwrap().body().to_vec()
}

fn refused(refused: Refused, error: Option<ipc::Error>) -> Result<(), Rejected> {
    Err(Rejected {
        action: Rejection::Refuse(refused),
        error,
    })
}

fn closed(error: ipc::Error) -> Result<(), Rejected> {
    Err(Rejected {
        action: Rejection::Close,
        error: Some(error),
    })
}

fn disposition(body: &[u8]) -> Result<(), Rejected> {
    decode_request(body).map(|_| ())
}

/// docs/50 §3.3, §9 (round trip, canonicity); docs/51 §7.6: every request
/// kind decodes, re-encodes to the same octets, and keeps its values.
#[test]
fn every_request_round_trips_canonically() {
    let mut kinds = std::collections::BTreeSet::new();
    for request in requests() {
        let body = request_body(&request);
        assert_eq!(&body[..2], &ADMIN_MAGIC.to_be_bytes());
        assert_eq!(body[2], ADMIN_VERSION);
        kinds.insert(body[3]);
        let decoded = decode_request(&body).unwrap();
        assert_eq!(request_body(&decoded), body, "{request:?}");
        match (&request, &decoded) {
            (
                Request::Forward { auth, operation },
                Request::Forward {
                    auth: a,
                    operation: o,
                },
            ) => {
                assert_eq!(a, auth);
                assert_eq!(o, operation);
            }
            (Request::SetPassword(s), Request::SetPassword(d)) => {
                assert_eq!(d.auth, s.auth);
                assert_eq!(d.completion, s.completion);
                assert_eq!(d.target, s.target);
                assert_eq!(d.password.expose(), s.password.expose());
            }
            (Request::Ping, Request::Ping) => {}
            other => panic!("{other:?}"),
        }
        assert!(
            round_trip_is_canonical::<AdminRequest>(ADMIN_CHANNEL, Direction::Request, &body)
                .unwrap()
        );
    }
    let all: std::collections::BTreeSet<u8> = request_kind::ALL.iter().copied().collect();
    assert_eq!(kinds, all, "every request kind sampled");
}

/// docs/51 §7.6 ("the same operations"): a forwarded operation's payload is
/// exactly dird's admin-channel payload — the octets after the envelope
/// are identical, and the kind is dird's number.
#[test]
fn forwarded_operations_are_dirds_layout_byte_for_byte() {
    for operation in forwarded() {
        let ours = request_body(&forward(operation.clone()));
        let theirs_request = ipc_dird_admin::Request::Operation {
            auth: auth(1),
            operation,
        };
        let theirs = encode_frame(
            ipc_dird_admin::ADMIN_CHANNEL,
            Direction::Request,
            &theirs_request.to_wire().unwrap(),
        )
        .unwrap();
        let theirs = theirs.body();
        assert_eq!(ours[3], theirs[3], "the kind is dird's");
        assert_eq!(&ours[4..], &theirs[4..], "the payload is dird's");
    }
}

/// docs/50 §3.3, §9; docs/51 §7.6: every reply kind round-trips.
#[test]
fn every_reply_round_trips_canonically() {
    let mut kinds = std::collections::BTreeSet::new();
    for reply in replies() {
        let body = reply_body(&reply);
        kinds.insert(body[3]);
        match decode_reply(&body).unwrap() {
            ipc::Reply::Message(decoded) => assert_eq!(decoded, reply),
            ipc::Reply::Refused(r) => panic!("{r:?}"),
        }
        assert!(reply_round_trip_is_canonical::<AdminReply>(ADMIN_CHANNEL, &body).unwrap());
    }
    let all: std::collections::BTreeSet<u8> = reply_kind::ALL.iter().copied().collect();
    assert_eq!(kinds, all, "every reply kind sampled");
    // The shared refusal (A-59).
    for code in [
        Refused::Busy,
        Refused::Unavailable,
        Refused::Malformed,
        Refused::VersionMismatch,
    ] {
        let frame = ipc_admin::encode_refusal(code).unwrap();
        assert_eq!(frame.body()[3], REFUSED_KIND);
        assert_eq!(
            decode_reply(frame.body()).unwrap(),
            ipc::Reply::Refused(code)
        );
    }
}

/// docs/51 §7.6: dird's `BeginPasswordSet` / `CompletePasswordSet` never
/// travel on admin.sock — no typed form, no wire form, and their kind
/// numbers close the connection.
#[test]
fn dirds_password_set_steps_are_not_on_this_channel() {
    for operation in [
        Operation::BeginPasswordSet { target: guid(1) },
        Operation::CompletePasswordSet {
            target: guid(1),
            outcome: PasswordSetOutcome::Completed,
            kvnos: vec![1],
        },
    ] {
        assert!(!ipc_admin::forwarded(&operation));
        let request = forward(operation.clone());
        assert_eq!(
            request.to_wire().err(),
            Some(ConversionError::NotOnThisChannel)
        );
        let wire = AdminRequest::Forward {
            auth: auth(1),
            operation: operation.to_wire().unwrap(),
        };
        assert_eq!(
            encode_frame(ADMIN_CHANNEL, Direction::Request, &wire).err(),
            Some(ipc::Error::UnknownKind)
        );
        // dird's own frame of the operation, under this channel's magic.
        let dird = ipc_dird_admin::Request::Operation {
            auth: auth(1),
            operation,
        };
        let frame = encode_frame(
            ipc_dird_admin::ADMIN_CHANNEL,
            Direction::Request,
            &dird.to_wire().unwrap(),
        )
        .unwrap();
        let mut body = frame.body().to_vec();
        body[0..2].copy_from_slice(&ADMIN_MAGIC.to_be_bytes());
        assert_eq!(disposition(&body), closed(ipc::Error::UnknownKind));
    }
}

/// docs/50 §3.3 ("kind closed: unknown op ⇒ close"); A-59: unknown kinds,
/// the unused numbers (dird's password-set steps, the key operations and
/// keyadm forwards of A10, the join token), and the reserved
/// `REFUSED_KIND` close the connection without a reply.
#[test]
fn unknown_kinds_close() {
    for kind in [
        0x00,
        0x06,
        0x07,
        0x0E,
        0x0F,
        0x10,
        0x11,
        0x12,
        0x13,
        0x16,
        0x81,
        0x87,
        0x7F,
        REFUSED_KIND,
    ] {
        let mut body = request_body(&Request::Ping);
        body[3] = kind;
        assert_eq!(
            disposition(&body),
            closed(ipc::Error::UnknownKind),
            "{kind:#x}"
        );
    }
}

/// docs/50 §3.3 ("no trailing byte … `Malformed` + close").
#[test]
fn a_trailing_octet_is_malformed() {
    for request in requests() {
        let mut body = request_body(&request);
        body.push(0);
        assert_eq!(
            disposition(&body),
            refused(Refused::Malformed, Some(ipc::Error::TrailingBytes)),
            "{request:?}"
        );
    }
}

/// docs/50 §3.3 (exact version ⇒ `Refused{VersionMismatch}` + close; magic
/// mismatch ⇒ close) — dird's admin-channel magic included.
#[test]
fn wrong_version_and_wrong_magic() {
    let mut body = request_body(&set_password(PASSWORD, 0));
    body[2] = ADMIN_VERSION + 1;
    assert_eq!(
        disposition(&body),
        refused(Refused::VersionMismatch, Some(ipc::Error::VersionMismatch))
    );
    for magic in [ipc_dird_admin::ADMIN_MAGIC, 0x4B44, 0x0000] {
        let mut body = request_body(&Request::Ping);
        body[0..2].copy_from_slice(&magic.to_be_bytes());
        assert_eq!(disposition(&body), closed(ipc::Error::WrongMagic));
    }
}

/// docs/51 §7.6 (`password: secret bytes<1024>`): 1024 octets pass, 1025
/// are refused on encoding and, built by hand, on decoding.
#[test]
fn the_password_bound() {
    let at = set_password(&"p".repeat(MAX_PASSWORD as usize), 0);
    let body = request_body(&at);
    match decode_request(&body).unwrap() {
        Request::SetPassword(set) => assert_eq!(set.password.expose().len(), 1024),
        other => panic!("{other:?}"),
    }
    let over = set_password(&"p".repeat(MAX_PASSWORD as usize + 1), 0);
    assert!(encode_request(&over).is_err());
    // Hand-built: the password's length prefix raised to 1025, one octet
    // more appended.
    let mut body = request_body(&set_password(&"p".repeat(1024), 0));
    let length_at = body.len() - 1024 - 4;
    assert_eq!(&body[length_at..length_at + 4], &1024u32.to_be_bytes());
    body[length_at..length_at + 4].copy_from_slice(&1025u32.to_be_bytes());
    body.push(b'p');
    assert_eq!(
        disposition(&body),
        refused(Refused::Malformed, Some(ipc::Error::LengthOverBound))
    );
}

/// docs/51 §7.2: the AP-REQ fields at their bound (64 KiB each), the
/// completion AP-REQ included, and one past it; at most two approvals.
#[test]
fn the_ap_req_bounds() {
    let make = |requester: usize, completion: usize, approvals: usize| {
        Request::SetPassword(SetPassword {
            auth: Auth {
                requester: vec![1; requester],
                approvals: vec![vec![2; MAX_AP_REQ as usize]; approvals],
            },
            completion: vec![3; completion],
            target: guid(1),
            password: password(PASSWORD),
        })
    };
    let max = MAX_AP_REQ as usize;
    assert_eq!(MAX_COMPLETION_AP_REQ, MAX_AP_REQ);
    let largest = make(max, max, 2);
    let body = request_body(&largest);
    assert!(body.len() <= MAX_REQUEST_BODY as usize, "{}", body.len());
    assert_eq!(request_body(&decode_request(&body).unwrap()), body);
    assert!(encode_request(&make(max + 1, 1, 0)).is_err());
    assert!(encode_request(&make(1, max + 1, 0)).is_err());
    assert!(encode_request(&make(1, 1, 3)).is_err());
    // The largest forwarded operation fits too.
    let forwarded = Request::Forward {
        auth: Auth {
            requester: vec![1; max],
            approvals: vec![vec![2; max], vec![3; max]],
        },
        operation: Operation::Lookup(LookupKey::Dn(vec![
            "c".repeat(MAX_DN_COMPONENT as usize);
            MAX_DN_COMPONENTS as usize
        ])),
    };
    let body = request_body(&forwarded);
    assert!(body.len() <= MAX_REQUEST_BODY as usize);
    assert_eq!(request_body(&decode_request(&body).unwrap()), body);
}

/// docs/50 §3.3 (bound before allocation): a declared body over 288 KiB is
/// refused at the length prefix, before any body octet; a reply over 16
/// KiB likewise; a body handed over directly past the bound closes.
#[test]
fn the_body_bounds() {
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    assert!(reader.push(&(MAX_REQUEST_BODY + 1).to_be_bytes()).is_err());
    let mut reader = FrameReader::new(REQUEST_LIMIT);
    assert_eq!(reader.push(&MAX_REQUEST_BODY.to_be_bytes()), Ok(4));
    let mut reader = FrameReader::new(REPLY_LIMIT);
    assert!(reader.push(&(MAX_REPLY_BODY + 1).to_be_bytes()).is_err());
    let mut huge = request_body(&Request::Ping);
    huge.resize(MAX_REQUEST_BODY as usize + 1, 0);
    assert_eq!(disposition(&huge), closed(ipc::Error::FrameTooLarge));
}

/// docs/50 §3.4 (keyd takes passwords as text): a password that is not
/// UTF-8 is malformed — refused by the typed layer (no `ipc` rule broken).
#[test]
fn a_password_that_is_not_utf8_is_malformed() {
    let wire = AdminRequest::SetPassword(WireSetPassword {
        auth: auth(0),
        completion: vec![1],
        target: guid(1).to_packet(),
        password: Secret::from_slice(&[0x70, 0xFF, 0x70]),
    });
    let frame = encode_frame(ADMIN_CHANNEL, Direction::Request, &wire).unwrap();
    assert_eq!(disposition(frame.body()), refused(Refused::Malformed, None));
}

/// docs/50 §3.3 ("a single encoding per value"); A-85: "never" has one
/// spelling on this channel too (dird's typed decoder); text must be UTF-8.
#[test]
fn second_spellings_are_malformed() {
    let mut body = request_body(&forward(Operation::SetAccountExpires {
        target: guid(1),
        value: AccountExpires::At(1),
    }));
    let n = body.len();
    body[n - 8..].copy_from_slice(&ipc_dird_admin::ACCOUNT_EXPIRES_NEVER.to_be_bytes());
    assert_eq!(disposition(&body), refused(Refused::Malformed, None));
    let mut body = request_body(&forward(Operation::Lookup(LookupKey::SamAccountName(
        "ab".into(),
    ))));
    let n = body.len();
    body[n - 1] = 0xFF;
    assert_eq!(disposition(&body), refused(Refused::Malformed, None));
}

/// docs/50 §8.2; AGENTS.md §6 ("secrets never in logs, panics, debug
/// output"): no `Debug` of the typed request, the `SetPassword`, the
/// password, the wire request or its fields prints the password — not as
/// text, not as octets.
#[test]
fn debug_never_prints_the_password() {
    let request = set_password(PASSWORD, 1);
    let body = request_body(&request);
    let decoded = decode_request(&body).unwrap();
    let wire = decode_body::<AdminRequest>(ADMIN_CHANNEL, Direction::Request, &body).unwrap();
    let as_octets = format!("{:?}", &PASSWORD.as_bytes()[..6]);
    let as_octets = as_octets.trim_matches(|c| c == '[' || c == ']');
    let mut outputs = vec![
        format!("{request:?}"),
        format!("{request:#?}"),
        format!("{decoded:?}"),
        format!("{wire:?}"),
        format!("{wire:#?}"),
    ];
    if let Request::SetPassword(set) = &decoded {
        outputs.push(format!("{set:?}"));
        outputs.push(format!("{:?}", set.password));
        assert_eq!(set.password.expose(), PASSWORD, "the value itself is kept");
    }
    if let AdminRequest::SetPassword(set) = &wire {
        outputs.push(format!("{set:?}"));
        outputs.push(format!("{:?}", set.password));
    }
    for output in outputs {
        assert!(!output.contains(PASSWORD), "{output}");
        assert!(!output.contains("Orchard"), "{output}");
        assert!(!output.contains(as_octets), "{output}");
        assert!(output.contains("redacted"), "{output}");
    }
}

/// docs/50 §3.3 ("replies are decoded with the same strictness"): an
/// unknown status, a boolean octet other than 00 / 01, more than two kvnos,
/// a trailing octet and a bad SID are refused by the client's decoder.
#[test]
fn replies_are_decoded_strictly() {
    let mut body = reply_body(&Reply::Refused(RefusalStatus::Denied));
    for code in [0x00, 0x09, 0xFF] {
        body[4] = code;
        assert!(decode_reply(&body).is_err(), "{code:#x}");
    }
    let mut body = reply_body(&Reply::PasswordChanged(PasswordChanged {
        kvnos: vec![1],
        completion_recorded: true,
    }));
    let n = body.len();
    body[n - 1] = 2;
    assert!(decode_reply(&body).is_err());
    let three = AdminReply::PasswordChanged {
        kvnos: vec![1; MAX_KVNOS as usize + 1],
        completion_recorded: true,
    };
    assert!(encode_frame(ADMIN_CHANNEL, Direction::Reply, &three).is_err());
    let mut body = reply_body(&Reply::Done);
    body.push(0);
    assert!(decode_reply(&body).is_err());
    let mut body = reply_body(&Reply::Created {
        guid: guid(1),
        sid: Some(sid(2000)),
    });
    body[4 + 16 + 1 + 4] = 2; // the SID's revision
    assert!(decode_reply(&body).is_err());
    // dird's `PasswordSet` reply kind does not exist here.
    let mut body = reply_body(&Reply::Done);
    body[3] = ipc_dird_admin::channel::reply_kind::PASSWORD_SET;
    assert!(decode_reply(&body).is_err());
}

/// The decoders never take a frame of one direction for the other.
#[test]
fn directions_do_not_mix() {
    let body = reply_body(&Reply::Pong);
    assert!(decode_body::<AdminRequest>(ADMIN_CHANNEL, Direction::Request, &body).is_err());
    let body = request_body(&Request::Ping);
    assert!(decode_reply(&body).is_err());
}

/// docs/51 §7.3, §7.6: the closed reply column.
#[test]
fn which_reply_answers_which_request() {
    let created = Reply::Created {
        guid: guid(1),
        sid: None,
    };
    let changed = Reply::PasswordChanged(PasswordChanged {
        kvnos: vec![1],
        completion_recorded: true,
    });
    let found = Reply::Found(Found {
        guid: guid(1),
        dn: vec!["dc=test".into()],
        class: "domainDNS".into(),
        sid: None,
    });
    let refusal = Reply::Refused(RefusalStatus::OutcomeUnknown);
    let set = set_password(PASSWORD, 0);
    assert!(answers(&set, &changed));
    assert!(answers(&set, &refusal));
    assert!(!answers(&set, &Reply::Done));
    assert!(answers(&Request::Ping, &Reply::Pong));
    assert!(!answers(&Request::Ping, &refusal));
    let create = forward(forwarded()[0].clone());
    assert!(answers(&create, &created));
    assert!(!answers(&create, &Reply::Done));
    assert!(!answers(&create, &changed));
    let lookup = forward(Operation::Lookup(LookupKey::SamAccountName("x".into())));
    assert!(answers(&lookup, &found));
    assert!(!answers(&lookup, &Reply::Done));
    let delete = forward(Operation::Delete { target: guid(1) });
    assert!(answers(&delete, &Reply::Done));
    assert!(answers(&delete, &refusal));
    assert!(!answers(&delete, &Reply::Pong));
}

/// docs/51 §7.6: dird's reply to a forwarded operation reaches the
/// administrator unchanged; dird's statuses keep their names and codes;
/// dird's `PasswordSet` has no form here.
#[test]
fn dirds_replies_map_by_name() {
    use ipc_dird_admin::RefusalStatus as Dird;
    for (dird, ours) in [
        (Dird::Denied, RefusalStatus::Denied),
        (Dird::ApprovalRequired, RefusalStatus::ApprovalRequired),
        (Dird::NotFound, RefusalStatus::NotFound),
        (Dird::Invalid, RefusalStatus::Invalid),
        (Dird::Conflict, RefusalStatus::Conflict),
        (Dird::Unavailable, RefusalStatus::Unavailable),
    ] {
        assert_eq!(RefusalStatus::from_dird(dird), ours);
        assert_eq!(ours.code(), dird.code());
        assert_eq!(
            Reply::from_dird(ipc_dird_admin::Reply::Refused(dird)),
            Some(Reply::Refused(ours))
        );
    }
    for code in 1..=8u8 {
        assert_eq!(RefusalStatus::from_code(code).map(|s| s.code()), Some(code));
    }
    assert_eq!(RefusalStatus::from_code(0), None);
    assert_eq!(RefusalStatus::from_code(9), None);
    assert_eq!(
        Reply::from_dird(ipc_dird_admin::Reply::Done),
        Some(Reply::Done)
    );
    // dird's `BeginPasswordSet` answer, through dird's own decoder.
    let wire = ipc_dird_admin::AdminReply::PasswordSet {
        kind: ipc_dird_admin::channel::codes::KIND_USER,
        keys: vec![],
        salt: b"EXAMPLE.TESTcarol".to_vec(),
    };
    let set = ipc_dird_admin::Reply::from_wire(&wire).unwrap();
    assert!(matches!(set, ipc_dird_admin::Reply::PasswordSet(_)));
    assert_eq!(Reply::from_dird(set), None);
}
