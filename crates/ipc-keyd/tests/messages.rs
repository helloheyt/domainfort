//! The keyd channel's message set: canonical round trips of every request
//! and reply, the documented kind tables, strict decoding (truncation,
//! trailing octets, a one-octet mutation sweep), no secret in `Debug`, and
//! no `now` (and no role) on the wire.
//!
//! Sources: docs/50 §3.3 (layout; "a single encoding per value"; "every
//! decoder checks `encode(decode(b)) == b` in property tests"; Kerberos
//! values decoded by krb-proto; secret-bearing buffers; no trailing byte),
//! §3.4 (the keyd rows; "no `now` field in any request"), §8.2 (no secret
//! in debug output), §9 tier 1; R50-3, R50-5; A-56; A-59.

mod samples;

use ipc::{
    decode_body, decode_reply, encode_frame, reply_round_trip_is_canonical,
    round_trip_is_canonical, Direction, Reply, REFUSED_KIND,
};
use ipc_keyd::channel::{reply_kind, request_kind};
use ipc_keyd::{
    decode_request, encode_answer, Answer, Call, KeydReply, KeydRequest, Rejection, KEYD_CHANNEL,
    KEYD_MAGIC, KEYD_VERSION,
};
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
    assert_eq!(request_kind::ALL, (0x01..=0x10).collect::<Vec<u8>>());
    for (request, reply) in request_kind::ALL.iter().zip(reply_kind::ALL) {
        assert_eq!(*reply, 0x80 | request);
    }
    assert_eq!(&reply_kind::ALL[16..], &[0xF1, 0xF2, 0xF3]);
    assert!(!request_kind::ALL.contains(&REFUSED_KIND));
    assert!(!reply_kind::ALL.contains(&REFUSED_KIND));
    let body = request_body(&Call::Ping);
    assert_eq!(body, vec![0x4B, 0x44, 0x01, 0x10]);
}

/// The error type of an operation (docs/10 §9): 1 `AuthnError`, 2
/// `IssueError`, 3 `keyd::Error`.
fn error_type(operation: keyd::Operation) -> u8 {
    use keyd::Operation as O;
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
        for operation in keyd::Operation::ALL {
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
        client: samples::handle(0xA1, keyd::KeyPurpose::PrincipalLongterm),
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
            keyd::Operation::SetSecret | keyd::Operation::VerifySecret
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

/// R50-5 / A-56 ("`now` does not cross the wire") and R50-3 (the role comes
/// only from the transport), checked on the source of the message
/// definitions: no identifier `now`, `role` or `caller` occurs in the code
/// of `wire.rs` (the only definitions of what is encoded), and every time
/// field encoded is a ticket fact or a template time — never a value
/// handed to keyd as its `now`. The type-level argument: `dispatch` and
/// `execute` take `now` as a parameter and build every keyd call from it;
/// `Call` (what a request decodes to) has no time field outside templates,
/// proofs and contexts.
#[test]
fn no_now_and_no_role_on_the_wire() {
    let wire = include_str!("../src/wire.rs");
    let identifiers = code_identifiers(wire);
    for forbidden in ["now", "role", "caller", "Role", "CallerId", "KerberosTime"] {
        assert!(
            !identifiers.iter().any(|i| i == forbidden),
            "`{forbidden}` in wire.rs"
        );
    }
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
    let server = include_str!("../src/server.rs");
    assert!(server.contains("caller: CallerId,\n    now: KerberosTime,\n    request_body: &[u8],"));
    assert!(server.contains("caller: CallerId,\n    now: KerberosTime,\n    call: Call,"));
}
