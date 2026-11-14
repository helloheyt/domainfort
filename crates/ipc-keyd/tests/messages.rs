//! The keyd channel's message set: canonical round trips of every request
//! and reply, the documented kind tables, strict decoding (truncation,
//! trailing octets, a one-octet mutation sweep), no secret in `Debug`, no
//! `now` on the wire and no role in any request — and the one role the
//! wire does carry, the caller role of the `DescribeConfig` reply (its
//! closed table, its bounds, its refusal of unknown values).
//!
//! Sources: docs/50 §3.3 (layout; "a single encoding per value"; "every
//! decoder checks `encode(decode(b)) == b` in property tests"; Kerberos
//! values decoded by krb-proto; secret-bearing buffers; no trailing byte;
//! "enum = `u8` from a closed table"; bound before allocation), §3.4 (the
//! keyd rows; "no `now` field in any request"), §8.2 (no secret in debug
//! output), §9 tier 1; R50-3, R50-5; A-56; A-59; docs/10 §2 (`enum Role`);
//! docs/questions/Q-351 (A-87).

mod samples;

use ipc::{
    decode_body, decode_reply, encode_frame, reply_round_trip_is_canonical,
    round_trip_is_canonical, Direction, Refused, Reply, REFUSED_KIND,
};
use ipc_keyd::channel::{reply_kind, request_kind, MAX_ENCTYPES, MAX_REPLY_BODY, MAX_REPLY_FIELD};
use ipc_keyd::wire::WireConfigDescription;
use ipc_keyd::{
    decode_request, encode_answer, Answer, Call, DescribedConfig, KeydReply, KeydRequest,
    Rejection, KEYD_CHANNEL, KEYD_MAGIC, KEYD_VERSION,
};
use keyd_types::{EncTypeId, Operation, Role, TicketPolicy};
use std::collections::BTreeSet;

/// The request frame body of a call.
fn request_body(call: &Call) -> Vec<u8> {
    let request = call.to_wire().expect("encodable");
    encode_frame(KEYD_CHANNEL, Direction::Request, &request)
        .expect("within the request bound")
        .body()
        .to_vec()
}

/// The reply frame body of an answer.
fn reply_body(answer: &Answer) -> Vec<u8> {
    encode_answer(answer).expect("encodable").body().to_vec()
}

/// docs/50 §3.3 round-trip row, request direction: the wire layer and the
/// typed layer (krb-proto included) both give back the exact octets.
#[test]
fn round_trip_is_canonical_for_every_request() {
    let mut kinds = BTreeSet::new();
    for call in samples::calls() {
        let body = request_body(&call);
        kinds.insert(body[3]);
        assert_eq!(
            round_trip_is_canonical::<KeydRequest>(KEYD_CHANNEL, Direction::Request, &body),
            Ok(true),
            "{:?}",
            call.operation()
        );
        // Typed layer: decode (krb-proto strict) and encode again.
        let decoded = decode_request(&body).expect("a sample decodes");
        assert_eq!(decoded.operation(), call.operation());
        assert_eq!(request_body(&decoded), body, "{:?}", call.operation());
    }
    // Every request kind of the closed table was exercised.
    assert_eq!(
        kinds,
        request_kind::ALL.iter().copied().collect::<BTreeSet<u8>>()
    );
}

/// docs/50 §3.3 round-trip row, reply direction: every success reply and
/// every error variant (A-26 classes, `Unavailable`) round-trips, and the
/// typed answer comes back equal.
#[test]
fn round_trip_is_canonical_for_every_reply() {
    let mut kinds = BTreeSet::new();
    for answer in samples::answers() {
        let body = reply_body(&answer);
        kinds.insert(body[3]);
        assert_eq!(
            reply_round_trip_is_canonical::<KeydReply>(KEYD_CHANNEL, &body),
            Ok(true),
            "{answer:?}"
        );
        let Ok(Reply::Message(reply)) = decode_reply::<KeydReply>(KEYD_CHANNEL, &body) else {
            panic!("a reply message");
        };
        let typed = Answer::from_wire(answer.operation(), reply).expect("typed");
        assert_eq!(typed, answer);
    }
    assert_eq!(
        kinds,
        reply_kind::ALL.iter().copied().collect::<BTreeSet<u8>>()
    );
}

/// docs/50 §3.3 (envelope), §3.4 (one request kind and one reply kind per
/// row): the documented magic, version and kind values, and the reserved
/// `REFUSED_KIND` in neither table (A-59; also asserted at compile time).
#[test]
fn kind_tables_are_as_documented() {
    assert_eq!(KEYD_MAGIC, 0x4B44);
    assert_eq!(KEYD_VERSION, 1);
    // 0x11 `grant_set_secret` appended by task A15a (docs/questions/Q-450);
    // 0x12 `register_decision`, 0x13 `seal_ceremony`, 0x14
    // `list_destroy_decisions` appended by A-102 (docs/52 §4.6).
    assert_eq!(request_kind::ALL, (0x01..=0x14).collect::<Vec<u8>>());
    for (request, reply) in request_kind::ALL.iter().zip(reply_kind::ALL) {
        assert_eq!(*reply, 0x80 | request);
    }
    assert_eq!(&reply_kind::ALL[20..], &[0xF1, 0xF2, 0xF3]);
    assert!(!request_kind::ALL.contains(&REFUSED_KIND));
    assert!(!reply_kind::ALL.contains(&REFUSED_KIND));
    let body = request_body(&Call::Ping);
    assert_eq!(body, vec![0x4B, 0x44, 0x01, 0x10]);
}

/// The error type of an operation (docs/10 §9): 1 `AuthnError`, 2
/// `IssueError`, 3 `keyd::Error`.
fn error_type(operation: keyd_types::Operation) -> u8 {
    use keyd_types::Operation as O;
    match operation {
        O::VerifyPreauth
        | O::OpenFastArmor
        | O::OpenAndVerifyTgt
        | O::OpenAndVerifyServiceTicket => 1,
        O::IssueAsRep | O::IssueTgsRep => 2,
        _ => 3,
    }
}

/// Whether an answer is a refusal.
fn is_refusal(answer: &Answer) -> bool {
    !matches!(
        answer,
        Answer::VerifyPreauth(Ok(_))
            | Answer::IssueAsRep(Ok(_))
            | Answer::OpenFastArmor(Ok(_))
            | Answer::OpenAndVerifyTgt(Ok(_))
            | Answer::IssueTgsRep(Ok(_))
            | Answer::SealFastError(Ok(_))
            | Answer::OpenAndVerifyServiceTicket(Ok(_))
            | Answer::SetSecret(Ok(_))
            | Answer::VerifySecret(Ok(_))
            | Answer::CreateKey(Ok(_))
            | Answer::RotateKey(Ok(_))
            | Answer::RotateKrbtgt(Ok(_))
            | Answer::RetireKvno(Ok(_))
            | Answer::DestroyKeySet(Ok(_))
            | Answer::GrantSetSecret(Ok(_))
            | Answer::RegisterDecision(Ok(_))
            | Answer::SealCeremony(Ok(_))
            | Answer::ListDestroyDecisions(Ok(_))
            | Answer::DescribeConfig(Ok(_))
            | Answer::Ping(Ok(_))
    )
}

/// docs/50 §3.4: a success reply is accepted only for its own operation,
/// and a failure reply only for the operations of its error type (docs/10
/// §9) — anything else is refused by the client's typed layer (R50-7:
/// strict request → reply).
#[test]
fn a_reply_of_another_operation_is_refused() {
    for answer in samples::answers() {
        let body = reply_body(&answer);
        let Ok(Reply::Message(reply)) = decode_reply::<KeydReply>(KEYD_CHANNEL, &body) else {
            panic!("a reply message");
        };
        for operation in keyd_types::Operation::ALL {
            let result = Answer::from_wire(operation, reply.clone());
            let expected = if is_refusal(&answer) {
                error_type(operation) == error_type(answer.operation())
            } else {
                operation == answer.operation()
            };
            assert_eq!(result.is_ok(), expected, "{operation:?} / {answer:?}");
        }
    }
}

/// docs/50 §3.3 ("after the last field — exactly the end of the body"):
/// every truncation and every appended octet is refused, with the refusal
/// ipc's table gives (`Malformed` for payload errors).
#[test]
fn truncated_or_extended_bodies_are_refused() {
    for call in samples::calls() {
        let body = request_body(&call);
        for cut in 0..body.len() {
            let rejection = decode_request(&body[..cut]).map(|_| ()).unwrap_err();
            if cut >= 4 {
                assert_eq!(rejection.refusal(), Some(ipc::Refused::Malformed));
            }
        }
        let mut extended = body.clone();
        extended.push(0);
        assert_eq!(
            decode_request(&extended).map(|_| ()),
            Err(Rejection::Ipc(ipc::Error::TrailingBytes))
        );
    }
}

/// docs/50 §3.3 ("Kerberos values … decoded in krb-proto (strict DER)"): a
/// DER blob that is not the strict DER of its type is refused `Malformed`
/// after the ipc layer accepted the frame.
#[test]
fn a_blob_that_is_not_strict_der_is_malformed() {
    let call = Call::VerifyPreauth {
        client: samples::handle(0xA1, keyd_types::KeyPurpose::PrincipalLongterm),
        padata: samples::padata(2),
        armor: None,
    };
    let mut body = request_body(&call);
    // Layout: envelope 4, handle 17, then the padata length (u32) and DER;
    // the DER's first octet is its SEQUENCE tag (0x30).
    assert_eq!(body[25], 0x30);
    body[25] = 0x31; // a SET tag: the frame is fine, the DER is not.
    assert!(decode_body::<KeydRequest>(KEYD_CHANNEL, Direction::Request, &body).is_ok());
    let rejection = decode_request(&body).map(|_| ()).unwrap_err();
    assert!(matches!(rejection, Rejection::Value(_)));
    assert_eq!(rejection.refusal(), Some(ipc::Refused::Malformed));
}

/// docs/50 §3.3 (strict decoding; AGENTS.md §6: never panic on input): a
/// one-octet mutation sweep over every sample request never panics, and
/// every mutated body that is accepted re-encodes to exactly itself — no
/// value has two encodings, through the wire and the krb-proto layers.
#[test]
fn mutation_sweep_over_request_decoding_never_panics() {
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for call in samples::calls() {
        let body = request_body(&call);
        for index in 0..body.len() {
            for value in [0x00, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF, body[index] ^ 0x01] {
                if value == body[index] {
                    continue;
                }
                let mut mutated = body.clone();
                mutated[index] = value;
                match decode_request(&mutated) {
                    Ok(decoded) => {
                        accepted += 1;
                        assert_eq!(request_body(&decoded), mutated, "index {index}");
                    }
                    Err(_) => rejected += 1,
                }
            }
        }
    }
    assert!(accepted > 0 && rejected > 0);
}

/// The same sweep over the client's reply decoding (docs/50 §3.3: replies
/// are decoded with the same strictness).
#[test]
fn mutation_sweep_over_reply_decoding_never_panics() {
    for answer in samples::answers() {
        let body = reply_body(&answer);
        let operation = answer.operation();
        for index in 0..body.len() {
            for value in [0x00, 0x01, 0x7F, 0x80, 0xFF, body[index] ^ 0x01] {
                let mut mutated = body.clone();
                mutated[index] = value;
                if let Ok(Reply::Message(reply)) = decode_reply::<KeydReply>(KEYD_CHANNEL, &mutated)
                {
                    if let Ok(typed) = Answer::from_wire(operation, reply) {
                        assert_eq!(reply_body(&typed), mutated, "index {index}");
                    }
                }
            }
        }
    }
}

/// docs/50 §8.2 ("secret-bearing types without a Debug that prints
/// content"), §3.3 (password in `Zeroizing`); docs/10 I7: neither the typed
/// call, the wire request, nor the request decoded on the server shows the
/// password or its octets.
#[test]
fn secret_carrying_messages_show_no_password_in_debug() {
    let password = samples::PASSWORD;
    let octets_as_decimal = format!("{:?}", password.as_bytes());
    let octets_inner = &octets_as_decimal[1..octets_as_decimal.len() - 1];
    for call in samples::calls() {
        if !matches!(
            call.operation(),
            keyd_types::Operation::SetSecret | keyd_types::Operation::VerifySecret
        ) {
            continue;
        }
        let wire = call.to_wire().unwrap();
        let decoded = decode_request(&request_body(&call)).unwrap();
        for text in [
            format!("{call:?}"),
            format!("{wire:?}"),
            format!("{decoded:?}"),
            format!("{call:#?}"),
            format!("{wire:#?}"),
        ] {
            assert!(!text.contains(password), "{text}");
            assert!(!text.contains(octets_inner), "{text}");
            assert!(text.contains("redacted"), "{text}");
        }
    }
}

/// The identifiers of a Rust source file outside comments.
fn code_identifiers(source: &str) -> Vec<String> {
    source
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .flat_map(|code| {
            code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|token| !token.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// R50-5 / A-56 ("`now` does not cross the wire") and R50-3 (the role keyd
/// authorizes with comes only from the transport), checked on the source of
/// the message definitions (`wire.rs`, the only definitions of what is
/// encoded):
///
/// * no identifier `now`, `CallerId` or `KerberosTime` in its code;
/// * no identifier naming a role or a caller in the field helpers and the
///   requests (from the field helpers to the replies section) — no request
///   can carry a role;
/// * among the replies, role identifiers only for the caller role of the
///   `DescribeConfig` reply (Q-351, A-87): exactly one field names a role in
///   the whole file, `pub caller_role: Role`, and it is
///   `WireConfigDescription`'s;
///
/// and every time field encoded is a ticket fact or a template time — never
/// a value handed to keyd as its `now`. The type-level argument: `dispatch`
/// and `execute` take `now` as a parameter and build every keyd call from
/// it; `Call` (what a request decodes to) has no time field outside
/// templates, proofs and contexts, and no role field at all.
#[test]
fn no_now_on_the_wire_and_no_role_in_any_request() {
    let wire = include_str!("../src/wire.rs");
    let identifiers = code_identifiers(wire);
    for forbidden in ["now", "CallerId", "KerberosTime"] {
        assert!(
            !identifiers.iter().any(|i| i == forbidden),
            "`{forbidden}` in wire.rs"
        );
    }
    let (_imports, rest) = wire
        .split_once("// Field helpers")
        .expect("the field helpers section");
    let (requests, replies) = rest.split_once("// Replies.").expect("the replies section");
    for identifier in code_identifiers(requests) {
        let lower = identifier.to_ascii_lowercase();
        assert!(
            !lower.contains("role") && !lower.contains("caller"),
            "`{identifier}` among the field helpers or requests of wire.rs"
        );
    }
    for identifier in code_identifiers(replies) {
        let lower = identifier.to_ascii_lowercase();
        if lower.contains("role") || lower.contains("caller") {
            assert!(
                [
                    "Role",
                    "role",
                    "caller_role",
                    "caller_role_code",
                    "caller_role_from_code"
                ]
                .contains(&identifier.as_str()),
                "`{identifier}` among the replies of wire.rs"
            );
        }
    }
    let role_fields: Vec<&str> = wire
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("pub ") && line.to_ascii_lowercase().contains("role"))
        .collect();
    assert_eq!(role_fields, ["pub caller_role: Role,"]);
    let start = replies
        .find("pub struct WireConfigDescription {")
        .expect("the DescribeConfig reply");
    let end = replies[start..].find("\n}").expect("its end") + start;
    assert!(replies[start..end].contains("pub caller_role: Role,"));
    let allowed = [
        "authtime",
        "starttime",
        "endtime",
        "renew_till",
        "armor_authtime",
    ];
    let mut time_fields = BTreeSet::new();
    for line in wire.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("pub ") {
            if let Some((field, ty)) = rest.split_once(':') {
                if ty.contains("WireTime") && !field.contains(' ') {
                    time_fields.insert(field.to_owned());
                }
            }
        }
    }
    assert!(!time_fields.is_empty());
    for field in &time_fields {
        assert!(allowed.contains(&field.as_str()), "time field `{field}`");
    }
    // The server's entry points take `now` from their caller (the daemon).
    // They live in crates/ipc-keyd-server since D182 / A-63.
    let server = include_str!("../../ipc-keyd-server/src/lib.rs");
    assert!(server.contains("caller: CallerId,\n    now: KerberosTime,\n    request_body: &[u8],"));
    assert!(server.contains("caller: CallerId,\n    now: KerberosTime,\n    call: Call,"));
}

// ---- the caller role of the DescribeConfig reply (Q-351, A-87) ----------------------

/// The closed table of the caller role, as wire.rs documents it (a project
/// choice: keyd-types' order, from 0x01).
const ROLE_CODES: [(Role, u8); 4] = [
    (Role::Kdc, 0x01),
    (Role::Directory, 0x02),
    (Role::Admin, 0x03),
    (Role::Ldap, 0x04),
];

/// The reply body of a described configuration for a caller of `role`.
fn described_body(role: Role) -> Vec<u8> {
    reply_body(&Answer::DescribeConfig(Ok(samples::described(true, role))))
}

/// docs/50 §3.3 (round trip; "enum = `u8` from a closed table"; nothing
/// after the last field), §3.4; docs/10 §2; Q-351 (A-87: the reply carries
/// the caller's role): the role is the reply's last octet, one code per
/// role; only that octet differs between the roles; each body decodes to
/// the description and that role, and re-encodes to itself.
#[test]
fn the_describe_config_reply_carries_each_caller_role() {
    let kdc = described_body(Role::Kdc);
    for (role, code) in ROLE_CODES {
        let body = described_body(role);
        assert_eq!(body.last(), Some(&code), "{role:?}");
        assert_eq!(body[..body.len() - 1], kdc[..kdc.len() - 1], "{role:?}");
        assert_eq!(
            reply_round_trip_is_canonical::<KeydReply>(KEYD_CHANNEL, &body),
            Ok(true)
        );
        let Ok(Reply::Message(reply)) = decode_reply::<KeydReply>(KEYD_CHANNEL, &body) else {
            panic!("a reply message ({role:?})");
        };
        let typed = Answer::from_wire(Operation::DescribeConfig, reply).expect("typed");
        assert_eq!(
            typed,
            Answer::DescribeConfig(Ok(DescribedConfig {
                description: samples::description(true),
                caller_role: role,
            }))
        );
        assert_eq!(reply_body(&typed), body, "canonical ({role:?})");
    }
}

/// docs/50 §3.3 ("enum = `u8` from a closed table"; "after the last field —
/// exactly the end of the body"); docs/07 §5 via §3.3 (replies decoded with
/// the same strictness); Q-351 (A-87): every caller-role octet outside the
/// table is refused (`UnknownCode`), as is a reply without the role octet
/// (`Truncated`) or with an octet after it (`TrailingBytes`) — the client
/// never takes a reply it cannot read as a role.
#[test]
fn an_unknown_caller_role_is_refused() {
    let body = described_body(Role::Kdc);
    let last = body.len() - 1;
    for code in 0..=u8::MAX {
        let mut mutated = body.clone();
        mutated[last] = code;
        let decoded = decode_reply::<KeydReply>(KEYD_CHANNEL, &mutated);
        if ROLE_CODES.iter().any(|(_, known)| *known == code) {
            assert!(matches!(decoded, Ok(Reply::Message(_))), "{code:#04x}");
        } else {
            assert!(
                matches!(decoded, Err(ipc::Error::UnknownCode)),
                "{code:#04x}: {decoded:?}"
            );
        }
    }
    assert!(matches!(
        decode_reply::<KeydReply>(KEYD_CHANNEL, &body[..last]),
        Err(ipc::Error::Truncated)
    ));
    let mut extended = body.clone();
    extended.push(0x01);
    assert!(matches!(
        decode_reply::<KeydReply>(KEYD_CHANNEL, &extended),
        Err(ipc::Error::TrailingBytes)
    ));
}

/// docs/50 §3.3 (bound before allocation; `bytes<max>` and `seq<T,max>` over
/// their bound refused; the reply bound ≥ every reply): the largest
/// `DescribeConfig` reply — a realm of `MAX_REPLY_FIELD` octets, the
/// `MAX_ENCTYPES` encryption types, the s2kparams and the caller role —
/// encodes within `MAX_REPLY_BODY` and round-trips; one realm octet or one
/// encryption type more is refused when encoding, and a declared count over
/// `MAX_ENCTYPES` when decoding.
#[test]
fn the_describe_config_reply_is_bounded() {
    let largest = |realm_len: usize, enctypes: usize| {
        KeydReply::DescribeConfig(WireConfigDescription {
            realm: vec![b'A'; realm_len],
            enctypes: vec![EncTypeId::Aes256CtsHmacSha196; enctypes],
            clock_skew_secs: u32::MAX,
            token_lifetime_secs: u32::MAX,
            ticket_policy: TicketPolicy::default(),
            s2k_params: Some([0xFF; 4]),
            caller_role: Role::Ldap,
        })
    };
    let field = MAX_REPLY_FIELD as usize;
    let count = MAX_ENCTYPES as usize;
    let reply = largest(field, count);
    let frame = encode_frame(KEYD_CHANNEL, Direction::Reply, &reply).expect("within bounds");
    assert!(frame.body().len() <= MAX_REPLY_BODY as usize);
    let Ok(Reply::Message(decoded)) = decode_reply::<KeydReply>(KEYD_CHANNEL, frame.body()) else {
        panic!("the largest reply decodes");
    };
    assert_eq!(decoded, reply);
    assert!(matches!(
        encode_frame(KEYD_CHANNEL, Direction::Reply, &largest(field + 1, count)),
        Err(ipc::Error::LengthOverBound)
    ));
    assert!(matches!(
        encode_frame(KEYD_CHANNEL, Direction::Reply, &largest(4, count + 1)),
        Err(ipc::Error::CountOverBound)
    ));
    // A peer declaring one encryption type more than the bound: envelope (4)
    // ‖ realm length (4) ‖ realm (4) ‖ the count (u32), then the codes.
    let small = encode_frame(KEYD_CHANNEL, Direction::Reply, &largest(4, count)).unwrap();
    let mut body = small.body().to_vec();
    assert_eq!(body[12..16], (MAX_ENCTYPES).to_be_bytes());
    body[12..16].copy_from_slice(&(MAX_ENCTYPES + 1).to_be_bytes());
    body.insert(16, body[16]);
    assert!(matches!(
        decode_reply::<KeydReply>(KEYD_CHANNEL, &body),
        Err(ipc::Error::CountOverBound)
    ));
}

/// Task A15a (docs/50 §3.3; docs/questions/Q-450 item 9): the
/// `grant_set_secret` request is strict and canonical — kind `0x11`, then
/// the account kind from its closed table (1 User, 2 Computer), the targets
/// (handle, binding, salt — the salt since A-102, N4) counted up to
/// `MAX_GRANT_TARGETS`, the lifetime; another account-kind code, a count
/// over the bound, a missing or a trailing octet are refused `Malformed`,
/// never decoded.
#[test]
fn the_grant_request_is_strict() {
    let computer = samples::calls()
        .into_iter()
        .find(|c| matches!(c, Call::GrantSetSecret { targets, .. } if targets.len() == 2))
        .unwrap();
    let body = request_body(&computer);
    // Envelope (4) ‖ account kind (1) ‖ target count (u32) ‖ …
    assert_eq!(body[3], 0x11);
    assert_eq!(body[4], 0x02, "Computer");
    assert_eq!(body[5..9], 2u32.to_be_bytes());
    assert!(decode_request(&body).is_ok());
    let malformed = |body: &[u8]| {
        decode_request(body)
            .err()
            .and_then(|rejection| rejection.refusal())
    };
    for code in [0x00, 0x03, 0xFF] {
        let mut bad = body.clone();
        bad[4] = code;
        assert_eq!(malformed(&bad), Some(Refused::Malformed), "kind {code:#x}");
    }
    let mut three = body.clone();
    three[5..9].copy_from_slice(&3u32.to_be_bytes());
    assert_eq!(malformed(&three), Some(Refused::Malformed));
    let mut trailing = body.clone();
    trailing.push(0);
    assert_eq!(malformed(&trailing), Some(Refused::Malformed));
    let short = &body[..body.len() - 1];
    assert_eq!(malformed(short), Some(Refused::Malformed));
}

/// The `Malformed` refusal of a request body, if it is refused that way.
fn refusal_of(body: &[u8]) -> Option<Refused> {
    decode_request(body)
        .err()
        .and_then(|rejection| rejection.refusal())
}

/// A-102 (docs/52 §4.2, §4.6): `rotate_key`, `rotate_krbtgt`, `retire_kvno`
/// and `destroy_key_set` carry **only** the decision id — the envelope, then
/// eight octets (`u64`, big-endian), nothing else: no handle, kvno or
/// dual-control token can travel. One octet more or less is `Malformed`.
#[test]
fn the_executions_carry_only_a_decision_id() {
    let id = ipc_keyd::DecisionId::new(0x0102_0304_0506_0708);
    for (call, kind) in [
        (Call::RotateKey { decision: id }, request_kind::ROTATE_KEY),
        (
            Call::RotateKrbtgt { decision: id },
            request_kind::ROTATE_KRBTGT,
        ),
        (Call::RetireKvno { decision: id }, request_kind::RETIRE_KVNO),
        (
            Call::DestroyKeySet { decision: id },
            request_kind::DESTROY_KEY_SET,
        ),
    ] {
        let body = request_body(&call);
        let mut expected = vec![0x4B, 0x44, 0x01, kind];
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(body, expected, "{:?}", call.operation());
        let decoded = decode_request(&body).expect("decodes");
        assert_eq!(decoded.decision(), Some(id));
        let mut long = body.clone();
        long.push(0);
        assert_eq!(refusal_of(&long), Some(Refused::Malformed));
        assert_eq!(
            refusal_of(&body[..body.len() - 1]),
            Some(Refused::Malformed)
        );
    }
    assert_eq!(Call::SealCeremony.decision(), None);
}

/// A-102 (docs/52 §4.6; docs/50 §3.3 — closed tables, bounded counts): the
/// `register_decision` request is strict — the decided operation's code is
/// one of 1-5 (another code is `Malformed`), and at most three approvers
/// are carried (a fourth is `Malformed` before anything is allocated for
/// it).
#[test]
fn the_register_decision_request_is_strict() {
    let rotate_key = samples::calls()
        .into_iter()
        .find(|c| {
            matches!(
                c,
                Call::RegisterDecision {
                    operation: ipc_keyd::DecidedOperation::RotateKey { .. },
                    ..
                }
            )
        })
        .unwrap();
    let body = request_body(&rotate_key);
    // Envelope (4) ‖ id (8) ‖ operation code (1) ‖ handle (17) ‖ approver
    // count (u32) ‖ 3 × 16 ‖ lifetime (u32).
    assert_eq!(body[3], request_kind::REGISTER_DECISION);
    assert_eq!(body[12], 0x03, "RotateKey");
    assert_eq!(body[30..34], 3u32.to_be_bytes());
    assert_eq!(body.len(), 86);
    assert!(decode_request(&body).is_ok());
    for code in [0x00, 0x06, 0xFF] {
        let mut bad = body.clone();
        bad[12] = code;
        assert_eq!(refusal_of(&bad), Some(Refused::Malformed), "code {code:#x}");
    }
    let mut four = body.clone();
    four[30..34].copy_from_slice(&4u32.to_be_bytes());
    four.splice(82..82, [0x04; 16]);
    assert_eq!(refusal_of(&four), Some(Refused::Malformed));
    let mut trailing = body.clone();
    trailing.push(0);
    assert_eq!(refusal_of(&trailing), Some(Refused::Malformed));
    // `list_destroy_decisions`: the envelope and an optional id only.
    assert_eq!(
        request_body(&Call::ListDestroyDecisions { after: None }),
        vec![0x4B, 0x44, 0x01, request_kind::LIST_DESTROY_DECISIONS, 0x00]
    );
    assert_eq!(
        request_body(&Call::SealCeremony),
        vec![0x4B, 0x44, 0x01, request_kind::SEAL_CEREMONY]
    );
}

/// A-102 (docs/52 §4.6; docs/50 §3.3 — "bound before allocation"): a
/// `list_destroy_decisions` reply carries at most `MAX_DESTROY_PAGE` (64)
/// entries; a count of 65 is refused before the entries are read.
#[test]
fn the_destroy_page_is_bounded() {
    assert_eq!(ipc_keyd::channel::MAX_DESTROY_PAGE, 64);
    let full = encode_answer(&Answer::ListDestroyDecisions(Ok(
        samples::destruction_page(1, 64, Some(64)),
    )))
    .expect("64 entries fit");
    let mut body = full.body().to_vec();
    assert_eq!(body[3], reply_kind::LIST_DESTROY_DECISIONS);
    assert_eq!(body[4..8], 64u32.to_be_bytes());
    body[4..8].copy_from_slice(&65u32.to_be_bytes());
    let insert_at = 8 + 64 * 24;
    body.splice(insert_at..insert_at, [0x41; 24]);
    assert!(matches!(
        decode_reply::<KeydReply>(KEYD_CHANNEL, &body),
        Err(ipc::Error::CountOverBound)
    ));
    // Writing 65 is refused too: the encoder keeps the same bound.
    assert!(encode_answer(&Answer::ListDestroyDecisions(Ok(
        samples::destruction_page(1, 65, None)
    )))
    .is_err());
}
