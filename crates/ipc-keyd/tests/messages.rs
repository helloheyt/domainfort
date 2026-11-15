//! The keyd channel's message set: canonical round trips of every request
//! and reply, the documented kind tables, strict decoding (truncation,
//! trailing octets, a one-octet mutation sweep), no secret in `Debug`, no
//! `now` on the wire and no role in any request — and the one role the
//! wire does carry, the caller role of the `DescribeConfig` and `Ping`
//! replies (its closed table, its bounds, its refusal of unknown values);
//! and the split of the calls into state calls and issuance calls by
//! keyd's one table (task R9).
//!
//! Sources: docs/50 §3.3 (layout; "a single encoding per value"; "every
//! decoder checks `encode(decode(b)) == b` in property tests"; Kerberos
//! values decoded by krb-proto; secret-bearing buffers; no trailing byte;
//! "enum = `u8` from a closed table"; bound before allocation), §3.4 (the
//! keyd rows; "no `now` field in any request"), §8.2 (no secret in debug
//! output), §9 tier 1; R50-3, R50-5; A-56; A-59; docs/10 §2 (`enum Role`),
//! §10 (the key-state changes); docs/52 §3.10 (c); docs/questions/Q-351
//! (A-87), Q-466 items 2-3 (A-102).

mod samples;

use ipc::{
    decode_body, decode_reply, encode_frame, reply_round_trip_is_canonical,
    round_trip_is_canonical, Direction, Refused, Reply, REFUSED_KIND,
};
use ipc_keyd::channel::{reply_kind, request_kind, MAX_ENCTYPES, MAX_REPLY_BODY, MAX_REPLY_FIELD};
use ipc_keyd::wire::WireConfigDescription;
use ipc_keyd::{
    decode_request, encode_answer, Answer, Call, DescribedConfig, IssuanceCall, KeydReply,
    KeydRequest, Rejection, RoutedCall, StateCall, KEYD_CHANNEL, KEYD_MAGIC, KEYD_VERSION,
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
    // `list_destroy_decisions` appended by A-102 (docs/52 §4.6); 0x15
    // `verify_operation_ticket` appended by Q-523; 0x16-0x18 the three
    // change-password operations, appended by task K4 (docs/53 §5.5); 0x19
    // `revoke_decision`, appended by task F3 (docs/questions/Q-976); 0x1A
    // `install_attestation_key`, appended by task PN9 (docs/59 §7.5).
    assert_eq!(request_kind::ALL, (0x01..=0x1A).collect::<Vec<u8>>());
    for (request, reply) in request_kind::ALL.iter().zip(reply_kind::ALL) {
        assert_eq!(*reply, 0x80 | request);
    }
    assert_eq!(&reply_kind::ALL[26..], &[0xF1, 0xF2, 0xF3]);
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
        | O::OpenAndVerifyServiceTicket
        | O::VerifyOperationTicket
        | O::OpenChangePasswordRequest => 1,
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
            | Answer::VerifyOperationTicket(Ok(_))
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
            | Answer::OpenChangePasswordRequest(Ok(_))
            | Answer::CompleteChangePassword(Ok(_))
            | Answer::SealChangePasswordError(Ok(_))
            | Answer::RevokeDecision(Ok(_))
            | Answer::InstallAttestationKey(Ok(_))
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

/// R2 (docs/52 §5 item 3) and Q-523 (append-only, docs/50 §3.3): kind 0x07
/// (`open_and_verify_service_ticket`) keeps its layout — principal ‖ binding
/// octet ‖ ap_req — but its binding octet now admits only `u8 1` (Unbound):
/// the R2 operation-digest form (`u8 2` ‖ 32 octets) and every other code
/// are refused `Malformed`, so no operation-bound verification can reach
/// the context-keeping path. The operation-bound verification is kind 0x15
/// (principal ‖ digest 32 ‖ ap_req), whose digest cut short is refused too.
/// Neither carries a purpose: keyd derives it. The `AdminService` purpose
/// has its own handle code (4) and round-trips.
#[test]
fn the_service_ticket_binding_is_a_closed_table() {
    let digest = keyd_types::OperationDigest::new([0xD3; 32]);
    let unbound = Call::OpenAndVerifyServiceTicket {
        service: keyd_types::PrincipalId::from_bytes([0xAD; 16]),
        ap_req_octets: vec![0x30, 0x00],
    };
    let body = request_body(&unbound);
    // envelope 4 ‖ principal 16 ‖ binding code ‖ ap_req (u32 length ‖ DER).
    assert_eq!(body[3], request_kind::OPEN_AND_VERIFY_SERVICE_TICKET);
    assert_eq!(&body[4..20], &[0xAD; 16]);
    assert_eq!(body[20], 0x01);
    assert_eq!(&body[21..], &[0, 0, 0, 2, 0x30, 0x00]);
    for code in [0x00, 0x02, 0x03, 0xFF] {
        let mut mutated = body.clone();
        mutated[20] = code;
        assert_eq!(
            decode_request(&mutated).map(|_| ()).unwrap_err().refusal(),
            Some(ipc::Refused::Malformed),
            "binding code {code:#04x}"
        );
    }
    // The R2 layout of an operation-bound 0x07 (code 2 ‖ digest): refused.
    let mut r2_bound = body[..20].to_vec();
    r2_bound.push(0x02);
    r2_bound.extend_from_slice(digest.as_bytes());
    r2_bound.extend_from_slice(&body[21..]);
    assert_eq!(
        decode_request(&r2_bound).map(|_| ()).unwrap_err().refusal(),
        Some(ipc::Refused::Malformed)
    );
    // Kind 0x15: principal ‖ digest ‖ ap_req.
    let bound = Call::VerifyOperationTicket {
        service: keyd_types::PrincipalId::from_bytes([0xAD; 16]),
        operation: digest,
        ap_req_octets: vec![0x30, 0x00],
    };
    let bound_body = request_body(&bound);
    assert_eq!(bound_body[3], request_kind::VERIFY_OPERATION_TICKET);
    assert_eq!(&bound_body[4..20], &[0xAD; 16]);
    assert_eq!(&bound_body[20..52], digest.as_bytes());
    assert_eq!(&bound_body[52..], &[0, 0, 0, 2, 0x30, 0x00]);
    assert_eq!(
        request_body(&decode_request(&bound_body).unwrap()),
        bound_body
    );
    assert_eq!(
        decode_request(&bound_body[..40])
            .map(|_| ())
            .unwrap_err()
            .refusal(),
        Some(ipc::Refused::Malformed)
    );
    // The admin purpose's handle code.
    let call = Call::VerifyPreauth {
        client: samples::handle(0xAD, keyd_types::KeyPurpose::AdminService),
        padata: samples::padata(2),
        armor: None,
    };
    let body = request_body(&call);
    assert_eq!(body[20], 0x04);
    assert_eq!(request_body(&decode_request(&body).unwrap()), body);
}

/// Q-523 (append-only, docs/50 §3.3): the `ServiceContext` reply (0x87)
/// keeps its layout, and its last octet — the former `bound_operation`
/// option marker — admits only `00` (absent): an unbound verification is
/// bound to no operation, and the R2 present form (`01` ‖ 32 octets) is
/// refused (`UnknownCode`). The operation-bound answer (0x95) carries the
/// digest and no context id. Source: docs/50 §3.3 (closed tables, one
/// encoding per value); docs/10 §5ב; docs/questions/Q-523.
#[test]
fn the_service_context_reply_names_no_operation() {
    let answer = samples::answers()
        .into_iter()
        .find(|a| matches!(a, Answer::OpenAndVerifyServiceTicket(Ok(_))))
        .expect("a ServiceContext sample");
    let body = reply_body(&answer);
    assert_eq!(body[3], reply_kind::OPEN_AND_VERIFY_SERVICE_TICKET);
    assert_eq!(body.last(), Some(&0x00));
    let mut present = body.clone();
    *present.last_mut().unwrap() = 0x01;
    assert!(matches!(
        decode_reply::<KeydReply>(KEYD_CHANNEL, &present),
        Err(ipc::Error::UnknownCode)
    ));
    present.extend_from_slice(&[0xD2; 32]);
    assert!(matches!(
        decode_reply::<KeydReply>(KEYD_CHANNEL, &present),
        Err(ipc::Error::UnknownCode)
    ));
    // The operation-bound answer: ... ‖ flags ‖ the 32 digest octets, no
    // context id anywhere (it starts with the realm's length).
    let bound = samples::answers()
        .into_iter()
        .find(|a| matches!(a, Answer::VerifyOperationTicket(Ok(_))))
        .expect("an OperationTicket sample");
    let body = reply_body(&bound);
    assert_eq!(body[3], reply_kind::VERIFY_OPERATION_TICKET);
    assert_eq!(&body[body.len() - 32..], &[0xD2; 32]);
    assert_eq!(&body[4..8], &[0, 0, 0, 11], "EXAMPLE.ORG first");
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
///   `DescribeConfig` reply (Q-351, A-87) and of the `Ping` reply (task R9,
///   Q-466 — the tuple variant `Ping(Role)`, no named field): exactly one
///   field names a role in the whole file, `pub caller_role: Role`, and it
///   is `WireConfigDescription`'s;
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

// ---- the caller role of the Ping reply (task R9, Q-466 item 2) ------------

/// docs/50 §3.3 (envelope `magic ‖ version ‖ kind ‖ payload`; "enum = `u8`
/// from a closed table"; round trip), §3.4 (`Ping` — every role); docs/10
/// §2, §7א; Q-466 item 2 (A-102: "caller role in Ping"): the `Ping` reply is
/// the envelope (kind `0x90`) and one octet, the caller role, from the
/// table of the `DescribeConfig` reply; each body decodes to that role and
/// re-encodes to itself.
#[test]
fn the_ping_reply_carries_each_caller_role() {
    for (role, code) in ROLE_CODES {
        let body = reply_body(&Answer::Ping(Ok(role)));
        assert_eq!(body, [0x4B, 0x44, 0x01, 0x90, code], "{role:?}");
        assert_eq!(
            reply_round_trip_is_canonical::<KeydReply>(KEYD_CHANNEL, &body),
            Ok(true)
        );
        let Ok(Reply::Message(reply)) = decode_reply::<KeydReply>(KEYD_CHANNEL, &body) else {
            panic!("a reply message ({role:?})");
        };
        assert_eq!(reply, KeydReply::Ping(role));
        assert_eq!(
            Answer::from_wire(Operation::Ping, reply),
            Ok(Answer::Ping(Ok(role)))
        );
    }
}

/// docs/50 §3.3 (closed tables; "after the last field — exactly the end of
/// the body"; replies decoded with the same strictness); Q-466 item 2: a
/// `Ping` reply whose role octet is outside the table is refused
/// (`UnknownCode`); one without it — the reply's earlier, empty form — is
/// `Truncated`, and one with an octet after it `TrailingBytes`. A client
/// never takes a `Ping` reply it cannot read as a role.
#[test]
fn an_unknown_ping_caller_role_is_refused() {
    for code in 0..=u8::MAX {
        let body = [0x4B, 0x44, 0x01, 0x90, code];
        let decoded = decode_reply::<KeydReply>(KEYD_CHANNEL, &body);
        if ROLE_CODES.iter().any(|(_, known)| *known == code) {
            assert!(matches!(decoded, Ok(Reply::Message(KeydReply::Ping(_)))));
        } else {
            assert!(
                matches!(decoded, Err(ipc::Error::UnknownCode)),
                "{code:#04x}: {decoded:?}"
            );
        }
    }
    assert!(matches!(
        decode_reply::<KeydReply>(KEYD_CHANNEL, &[0x4B, 0x44, 0x01, 0x90]),
        Err(ipc::Error::Truncated)
    ));
    assert!(matches!(
        decode_reply::<KeydReply>(KEYD_CHANNEL, &[0x4B, 0x44, 0x01, 0x90, 0x01, 0x01]),
        Err(ipc::Error::TrailingBytes)
    ));
}

// ---- state calls and issuance calls (task R9, Q-466 item 3) ---------------

/// docs/10 §10 (the six key-state changes; `grant_set_secret` and
/// `register_decision` loosen keyd and take the same audit path); docs/52
/// §3.10 (c); Q-466 item 3 (A-102: "state calls only through call_with_fate
/// by type"): for every call of every operation (tests/samples), the split
/// follows keyd's one table — `keyd_types::authz::requires_acknowledged_intent`,
/// the table keyd-daemon's classification reads — and the expected ten
/// operations (the eight of R9, the change-password completion of task K4
/// and the attestation key's install of task PN9) are exactly the state
/// calls: an `IssuanceCall` (the only
/// argument `KeydClient::call` takes) can be made of every other call and
/// of none of these, a `StateCall` of these and of no other.
#[test]
fn the_state_calls_are_keyds_table_and_never_issuance_calls() {
    let state_operations = [
        Operation::SetSecret,
        Operation::CreateKey,
        Operation::RotateKey,
        Operation::RotateKrbtgt,
        Operation::RetireKvno,
        Operation::DestroyKeySet,
        Operation::GrantSetSecret,
        Operation::RegisterDecision,
        Operation::CompleteChangePassword,
        Operation::InstallAttestationKey,
    ];
    for operation in Operation::ALL {
        assert_eq!(
            keyd_types::authz::requires_acknowledged_intent(operation),
            state_operations.contains(&operation),
            "{operation:?}"
        );
    }
    let mut seen = BTreeSet::new();
    // `Call` is not `Clone` (a password has no second copy): three fresh
    // sample lists, in the same order.
    let samples = samples::calls()
        .into_iter()
        .zip(samples::calls())
        .zip(samples::calls());
    for ((call, for_issuance), for_state) in samples {
        let operation = call.operation();
        seen.insert(format!("{operation:?}"));
        let state = state_operations.contains(&operation);
        assert_eq!(call.is_state_call(), state, "{operation:?}");
        match IssuanceCall::new(for_issuance) {
            Some(issuance) => {
                assert!(!state, "{operation:?} became an IssuanceCall");
                assert_eq!(issuance.into_call().operation(), operation);
            }
            None => assert!(state, "{operation:?} refused as an IssuanceCall"),
        }
        match StateCall::new(for_state) {
            Some(state_call) => {
                assert!(state, "{operation:?} became a StateCall");
                assert_eq!(state_call.into_call().operation(), operation);
            }
            None => assert!(!state, "{operation:?} refused as a StateCall"),
        }
        match call.route() {
            RoutedCall::State(routed) => assert!(state && routed.call().operation() == operation),
            RoutedCall::Issuance(routed) => {
                assert!(!state && routed.call().operation() == operation)
            }
        }
    }
    assert_eq!(seen.len(), Operation::ALL.len(), "every operation sampled");
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
/// one of 1-6 (6, `ChangePassword`, appended by task K4; another code is
/// `Malformed`), and at most three approvers
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
    for code in [0x00, 0x07, 0xFF] {
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

/// Task K4 (docs/53 §5.5; docs/50 §3.3 — closed tables, one encoding per
/// value; RFC 3244 §2; RFC 4120 7.1): the change-password messages are
/// strict.
/// * `seal_change_password_error` carries exactly the context id and a
///   16-bit result code: 0 (SUCCESS — "not allowed in a KRB-ERROR
///   message"), 0xFFFF and every undefined value are `Malformed`;
/// * a `HostAddr` has one encoding: an IPv4-mapped IPv6 address in the
///   IPv6 form is `Malformed` ("MUST be represented as addresses of type
///   2"), as is an unknown family;
/// * the `ChangePasswordContext` reply's verdict is one of the closed
///   table (another code is refused);
/// * no change-password request has a password field: the password is only
///   inside the KRB-PRIV ciphertext (docs/53 R53-4).
#[test]
fn the_change_password_messages_are_strict() {
    use ipc_keyd::{ChangePasswordCtxId, HostAddr, NonZeroResultCode};
    let seal = Call::SealChangePasswordError {
        ctx: ChangePasswordCtxId::from_bytes([0x11; 16]),
        code: NonZeroResultCode::AuthError,
    };
    let body = request_body(&seal);
    let mut expected = vec![0x4B, 0x44, 0x01, request_kind::SEAL_CHANGE_PASSWORD_ERROR];
    expected.extend_from_slice(&[0x11; 16]);
    expected.extend_from_slice(&3u16.to_be_bytes());
    assert_eq!(body, expected);
    for value in [0u16, 8, 0x00FF, 0xFFFF] {
        let mut bad = body.clone();
        bad[20..22].copy_from_slice(&value.to_be_bytes());
        assert_eq!(refusal_of(&bad), Some(Refused::Malformed), "{value:#x}");
    }
    for value in 1u16..=7 {
        let mut good = body.clone();
        good[20..22].copy_from_slice(&value.to_be_bytes());
        assert!(decode_request(&good).is_ok(), "{value}");
    }

    // An IPv6 peer, an IPv4 local address: the body ends with
    // 0x02 ‖ 16 octets ‖ 0x01 ‖ 4 octets.
    let mut v6 = [0u8; 16];
    v6[0] = 0x20;
    v6[1] = 0x01;
    v6[2] = 0x0d;
    v6[3] = 0xb8;
    v6[15] = 0x0a;
    let open = Call::OpenChangePasswordRequest {
        service: keyd_types::PrincipalId::from_bytes([0xCF; 16]),
        ap_req_octets: vec![0x30, 0x00],
        krb_priv_octets: vec![0x30, 0x00],
        peer: HostAddr::ipv6(v6),
        local: HostAddr::ipv4([192, 0, 2, 1]),
    };
    let body = request_body(&open);
    let n = body.len();
    assert_eq!(body[n - 22], 0x02);
    assert_eq!(&body[n - 21..n - 5], &v6);
    assert_eq!(&body[n - 5..], &[0x01, 192, 0, 2, 1]);
    assert!(decode_request(&body).is_ok());
    let mut mapped = body.clone();
    mapped[n - 21..n - 5]
        .copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 10]);
    assert_eq!(refusal_of(&mapped), Some(Refused::Malformed));
    for family in [0x00, 0x03, 0xFF] {
        let mut bad = body.clone();
        bad[n - 5] = family;
        assert_eq!(refusal_of(&bad), Some(Refused::Malformed), "{family:#x}");
    }
    // The typed IPv4-mapped peer is held as IPv4 and encoded so.
    let normalized = Call::OpenChangePasswordRequest {
        service: keyd_types::PrincipalId::from_bytes([0xCF; 16]),
        ap_req_octets: vec![0x30, 0x00],
        krb_priv_octets: vec![0x30, 0x00],
        peer: HostAddr::ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 10]),
        local: HostAddr::ipv4([192, 0, 2, 1]),
    };
    let body = request_body(&normalized);
    let n = body.len();
    assert_eq!(&body[n - 10..], &[0x01, 192, 0, 2, 10, 0x01, 192, 0, 2, 1]);

    // The verdict is the context reply's last octet.
    let answer = Answer::OpenChangePasswordRequest(Ok(samples::change_password_context(
        keyd_types::ChangePasswordVerdict::Acceptable,
    )));
    let body = reply_body(&answer);
    let n = body.len();
    assert_eq!(body[n - 1], 0x01);
    for code in [0x00, 0x06, 0xFF] {
        let mut bad = body.clone();
        bad[n - 1] = code;
        assert!(
            matches!(
                decode_reply::<KeydReply>(KEYD_CHANNEL, &bad),
                Err(ipc::Error::UnknownCode)
            ),
            "{code:#x}"
        );
    }
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

// ---- the attestation key's install (task PN9) ----------------------------------------

/// Task PN9 (docs/59 §7.5; docs/50 §3.3 — strict, bounded, one encoding per
/// value): `install_attestation_key` is kind `0x1A`, then the key as
/// `secret bytes<32>` — the length field always 32, then exactly 32
/// octets, nothing else. A length of 31 or 33 (with that many octets), a
/// length of 32 with 31 octets, a trailing octet, and the all-zero key are
/// all refused `Malformed` — never decoded, never handed to keyd; a key of
/// another length cannot be carried at all.
#[test]
fn the_attestation_key_request_is_strict() {
    let body = request_body(&Call::InstallAttestationKey {
        key: samples::attestation_key(),
    });
    let mut expected = vec![0x4B, 0x44, 0x01, request_kind::INSTALL_ATTESTATION_KEY];
    expected.extend_from_slice(&32u32.to_be_bytes());
    expected.extend_from_slice(&samples::ATTESTATION_KEY);
    assert_eq!(body, expected);
    let Ok(Call::InstallAttestationKey { key }) = decode_request(&body) else {
        panic!("decodes as the install");
    };
    assert_eq!(key.expose(), &samples::ATTESTATION_KEY);

    let with = |length: u32, octets: &[u8]| {
        let mut body = vec![0x4B, 0x44, 0x01, request_kind::INSTALL_ATTESTATION_KEY];
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(octets);
        body
    };
    let mut trailing = body.clone();
    trailing.push(0);
    for bad in [
        with(31, &[0x6B; 31]),
        with(33, &[0x6B; 33]),
        with(32, &[0x6B; 31]),
        with(0, &[]),
        with(u32::MAX, &[0x6B; 32]),
        trailing,
        body[..body.len() - 1].to_vec(),
    ] {
        assert_eq!(
            refusal_of(&bad),
            Some(Refused::Malformed),
            "{} octets",
            bad.len()
        );
    }
    // The all-zero key: a well-formed field, refused by the typed layer.
    let zero = with(32, &[0u8; 32]);
    assert!(matches!(
        decode_request(&zero),
        Err(Rejection::Value(ipc_keyd::ConversionError::AttestationKey))
    ));
    assert_eq!(refusal_of(&zero), Some(Refused::Malformed));
    // The carrier holds exactly 32 octets, never all zero.
    for octets in [&[0x6B; 31][..], &[0x6B; 33][..], &[][..], &[0u8; 32][..]] {
        assert!(ipc_keyd::AttestationKeyOctets::from_slice(octets).is_none());
    }
    // Encoding a wire request whose key is not 32 octets is refused.
    for length in [0usize, 31, 33] {
        let request =
            KeydRequest::InstallAttestationKey(ipc_keyd::wire::InstallAttestationKeyRequest {
                key: ipc::Secret::from_slice(&vec![0x6B; length]),
            });
        assert!(encode_frame(KEYD_CHANNEL, Direction::Request, &request).is_err());
    }
    // The reply: kind 0x9A, no payload; a failure is `Error` (0xF3).
    let ok = reply_body(&Answer::InstallAttestationKey(Ok(())));
    assert_eq!(
        ok,
        vec![0x4B, 0x44, 0x01, reply_kind::INSTALL_ATTESTATION_KEY]
    );
    assert_eq!(reply_kind::INSTALL_ATTESTATION_KEY, 0x9A);
}

/// docs/50 §8.2 ("secret-bearing types without a Debug that prints
/// content"), §3.3; AGENTS.md §6; docs/59 §7.4 (the key is never exported):
/// neither the typed call, the wire request, nor the request decoded on the
/// server shows the attestation key's octets in any rendering — each says
/// it is redacted.
#[test]
fn the_attestation_key_never_shows_in_debug() {
    let call = Call::InstallAttestationKey {
        key: samples::attestation_key(),
    };
    let wire = call.to_wire().unwrap();
    let decoded = decode_request(&request_body(&call)).unwrap();
    for text in [
        format!("{call:?}"),
        format!("{wire:?}"),
        format!("{decoded:?}"),
        format!("{call:#?}"),
        format!("{wire:#?}"),
    ] {
        assert!(!text.contains("107"), "{text}");
        assert!(!text.contains("6b") && !text.contains("6B"), "{text}");
        assert!(text.contains("redacted"), "{text}");
    }
}
