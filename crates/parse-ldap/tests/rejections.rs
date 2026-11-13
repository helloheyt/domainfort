//! Every profile rule rejects what it must, with its typed error.
//!
//! Each test names its source: the RFC 4511 / X.690 clause or project decision
//! (A-45, docs/49 §2.3 E-rule, §2.4 bound) the input violates. Inputs are
//! hand-built from RFC 4511 App. B with the X.690 element builder in `common`.

mod common;

use common::{
    canonical_request, decode_request, message, request_error, search_with_filter, tlv,
    wire_response, PRESENT_A,
};
use parse_ldap::{
    decode_message, encode_message, AuthState, AuthenticationChoice, DecodeOptions, Error, Filter,
    Limit, ProtocolOp, Scope, UnsupportedOp, MAX_ATTRIBUTE_SELECTORS, MAX_CONTROLS,
    MAX_FILTER_DEPTH, MAX_FILTER_NODES, MAX_LDAPDN_OCTETS, MAX_PREAUTH_MESSAGE_OCTETS,
    MAX_SUBSTRING_ANY,
};

/// A BindRequest message with the given name contents and authentication
/// element. Spec: RFC 4511 §4.2.
fn bind_with(name: &[u8], authentication: &[u8]) -> Vec<u8> {
    let mut contents = vec![0x02, 0x01, 0x03];
    contents.extend_from_slice(&tlv(0x04, name));
    contents.extend_from_slice(authentication);
    message(&tlv(0x60, &contents))
}

/// A SearchRequest message whose components are given raw, in order.
/// Spec: RFC 4511 §4.5.1.
fn search_raw(components: &[&[u8]]) -> Vec<u8> {
    message(&tlv(0x63, &components.concat()))
}

const BASE_EMPTY: &[u8] = &[0x04, 0x00];
const SCOPE_BASE: &[u8] = &[0x0A, 0x01, 0x00];
const DEREF_NEVER: &[u8] = &[0x0A, 0x01, 0x00];
const ZERO: &[u8] = &[0x02, 0x01, 0x00];
const FALSE: &[u8] = &[0x01, 0x01, 0x00];
const NO_ATTRIBUTES: &[u8] = &[0x30, 0x00];

// ---- lengths (RFC 4511 §5.1; X.690 8.1.3; A-45) ----

#[test]
fn indefinite_length_rejected() {
    // Source: RFC 4511 §5.1 bullet 1; X.690 8.1.3.6 — an UnbindRequest message
    // with the indefinite form and end-of-contents.
    let bytes = [0x30, 0x80, 0x02, 0x01, 0x01, 0x42, 0x00, 0x00, 0x00];
    assert_eq!(request_error(&bytes), Error::IndefiniteLength);
    // Also inside a component.
    let nested = message(&[0x63, 0x80, 0x00, 0x00]);
    assert_eq!(request_error(&nested), Error::IndefiniteLength);
}

#[test]
fn five_octet_length_rejected() {
    // Source: A-45 (at most four length octets).
    let bytes = [
        0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00,
    ];
    assert_eq!(request_error(&bytes), Error::TooManyLengthOctets);
    // Four octets, non-minimal: accepted by the wire profile (A-45; X.690
    // 8.1.3.5 NOTE 2), refused by the canonical one (X.690 10.1).
    let four = [
        0x30, 0x84, 0x00, 0x00, 0x00, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00,
    ];
    assert!(decode_request(&four).is_ok());
    assert_eq!(
        decode_message(&four, &canonical_request()),
        Err(Error::NonMinimalLength)
    );
}

#[test]
fn reserved_length_octet_rejected() {
    // Source: X.690 8.1.3.5 c).
    let bytes = [0x30, 0xFF, 0x02, 0x01, 0x01];
    assert_eq!(request_error(&bytes), Error::ReservedLengthOctet);
}

#[test]
fn length_beyond_input_rejected() {
    // Source: X.690 8.1.3.3 — an inner length longer than its container.
    let bytes = message(&[0x42, 0x05]);
    assert_eq!(request_error(&bytes), Error::LengthExceedsInput);
}

// ---- identifiers (X.690 8.1.2, 8.1.5; docs/49 E6, E1) ----

#[test]
fn high_tag_number_rejected() {
    // Source: X.690 8.1.2.4; docs/49 §2.3 E6 — [APPLICATION 31] escape.
    let bytes = message(&[0x5F, 0x1F, 0x00]);
    assert_eq!(request_error(&bytes), Error::HighTagNumber);
}

#[test]
fn end_of_contents_rejected() {
    // Source: X.690 8.1.5; RFC 4511 §5.1 — 00 00 after the protocolOp.
    let bytes = message(&[0x42, 0x00, 0x00, 0x00]);
    assert_eq!(request_error(&bytes), Error::EndOfContents);
}

// ---- BOOLEAN and DEFAULT (RFC 4511 §5.1; A-45 / Q-160 items 3, 4) ----

#[test]
fn boolean_other_than_ff_rejected() {
    // Source: RFC 4511 §5.1 bullet 3 (TRUE is FF); A-45 — typesOnly = 01.
    let bytes = search_raw(&[
        BASE_EMPTY,
        SCOPE_BASE,
        DEREF_NEVER,
        ZERO,
        ZERO,
        &[0x01, 0x01, 0x01],
        &PRESENT_A,
        NO_ATTRIBUTES,
    ]);
    assert_eq!(request_error(&bytes), Error::InvalidBoolean);
    // Two contents octets. Source: X.690 8.2.1.
    let bytes = search_raw(&[
        BASE_EMPTY,
        SCOPE_BASE,
        DEREF_NEVER,
        ZERO,
        ZERO,
        &[0x01, 0x02, 0xFF, 0xFF],
        &PRESENT_A,
        NO_ATTRIBUTES,
    ]);
    assert_eq!(request_error(&bytes), Error::InvalidBoolean);
}

#[test]
fn explicit_default_rejected() {
    // Source: RFC 4511 §5.1 bullet 4; A-45 — criticality FALSE present.
    let control = tlv(
        0x30,
        &[&[0x04, 0x01, 0x31][..], &[0x01, 0x01, 0x00]].concat(),
    );
    let bytes = tlv(
        0x30,
        &[&[0x02, 0x01, 0x01][..], &[0x42, 0x00], &tlv(0xA0, &control)].concat(),
    );
    assert_eq!(request_error(&bytes), Error::ExplicitDefault);
    // dnAttributes [4] FALSE present.
    let mra = tlv(
        0xA9,
        &[
            &[0x82, 0x01, 0x61][..],
            &[0x83, 0x01, 0x62],
            &[0x84, 0x01, 0x00],
        ]
        .concat(),
    );
    assert_eq!(
        request_error(&search_with_filter(&mra)),
        Error::ExplicitDefault
    );
}

// ---- OCTET STRING form (RFC 4511 §5.1 bullet 2; X.690 8.7.1, 8.14.4) ----

#[test]
fn constructed_octet_string_rejected() {
    // Source: RFC 4511 §5.1 — baseObject as a constructed OCTET STRING.
    let base = tlv(0x24, &[0x04, 0x01, 0x61]);
    let bytes = search_raw(&[
        &base,
        SCOPE_BASE,
        DEREF_NEVER,
        ZERO,
        ZERO,
        FALSE,
        &PRESENT_A,
        NO_ATTRIBUTES,
    ]);
    assert_eq!(request_error(&bytes), Error::ConstructedOctetString);
    // simple [0] constructed (implicit tag on OCTET STRING).
    let bytes = bind_with(b"", &[0xA0, 0x00]);
    assert_eq!(request_error(&bytes), Error::ConstructedOctetString);
    // present [7] constructed.
    let bytes = search_with_filter(&[0xA7, 0x01, 0x61]);
    assert_eq!(request_error(&bytes), Error::ConstructedOctetString);
    // DelRequest [APPLICATION 10] constructed.
    let bytes = message(&[0x6A, 0x00]);
    assert_eq!(request_error(&bytes), Error::ConstructedOctetString);
}

// ---- UTF-8 (RFC 4511 §4.1.2; RFC 4512 §1.4 UTF8 production) ----

#[test]
fn non_utf8_ldapstring_rejected() {
    // Source: RFC 4512 §1.4 — sequences outside UTF1..UTF4.
    let invalid: [&[u8]; 6] = [
        &[0xFF],                   // never a UTF-8 octet
        &[0x80],                   // lone UTF0
        &[0xC0, 0x80],             // overlong (UTF2 starts at C2)
        &[0xED, 0xA0, 0x80],       // surrogate (ED is followed by 80-9F)
        &[0xF4, 0x90, 0x80, 0x80], // above U+10FFFF (F4 is followed by 80-8F)
        &[0xE2, 0x82],             // truncated UTF3
    ];
    for name in invalid {
        assert_eq!(
            request_error(&bind_with(name, &[0x80, 0x00])),
            Error::InvalidUtf8
        );
    }
    // Valid UTF2, UTF3, UTF4 sequences are accepted.
    let valid: [&[u8]; 3] = [
        &[0xC3, 0xA9],
        &[0xE2, 0x82, 0xAC],
        &[0xF0, 0x9F, 0x98, 0x80],
    ];
    for name in valid {
        assert!(decode_request(&bind_with(name, &[0x80, 0x00])).is_ok());
    }
    // AssertionValue is an OCTET STRING, not an LDAPString: not checked.
    let eq = tlv(
        0xA3,
        &[&[0x04, 0x01, 0x61][..], &[0x04, 0x01, 0xFF]].concat(),
    );
    assert!(decode_request(&search_with_filter(&eq)).is_ok());
}

// ---- Filter bounds and structure (docs/49 §2.4; RFC 4511 §4.5.1) ----

/// `depth` nested Filter elements: (depth - 1) `not` around a `present`.
fn nested_not(depth: usize) -> Vec<u8> {
    let mut f = PRESENT_A.to_vec();
    for _ in 1..depth {
        f = tlv(0xA2, &f);
    }
    f
}

#[test]
fn filter_depth_bound() {
    // Source: docs/49 §2.4 — filter depth 32 accepted, 33 rejected.
    assert!(decode_request(&search_with_filter(&nested_not(MAX_FILTER_DEPTH))).is_ok());
    assert_eq!(
        request_error(&search_with_filter(&nested_not(MAX_FILTER_DEPTH + 1))),
        Error::LimitExceeded(Limit::FilterDepth)
    );
}

#[test]
fn filter_node_bound() {
    // Source: docs/49 §2.4 — 256 filter elements accepted, 257 rejected.
    let and_of = |n: usize| tlv(0xA0, &PRESENT_A.repeat(n));
    assert!(decode_request(&search_with_filter(&and_of(MAX_FILTER_NODES - 1))).is_ok());
    assert_eq!(
        request_error(&search_with_filter(&and_of(MAX_FILTER_NODES))),
        Error::LimitExceeded(Limit::FilterNodes)
    );
}

#[test]
fn empty_and_or_rejected() {
    // Source: RFC 4511 §4.5.1 (SET SIZE (1..MAX)), §4.5.1.7; docs/49 E16.
    assert_eq!(
        request_error(&search_with_filter(&[0xA0, 0x00])),
        Error::EmptySet
    );
    assert_eq!(
        request_error(&search_with_filter(&[0xA1, 0x00])),
        Error::EmptySet
    );
}

#[test]
fn not_holds_exactly_one_filter() {
    // Source: RFC 4511 §4.5.1.7 (explicit in BER); X.690 8.14.3.
    let two = tlv(0xA2, &PRESENT_A.repeat(2));
    assert_eq!(
        request_error(&search_with_filter(&two)),
        Error::TrailingData
    );
    assert_eq!(
        request_error(&search_with_filter(&[0xA2, 0x00])),
        Error::MissingComponent
    );
}

/// A substrings filter on "cn" with the given substring elements.
fn substrings(items: &[&[u8]]) -> Vec<u8> {
    let list = tlv(0x30, &items.concat());
    tlv(0xA4, &[&[0x04, 0x02, 0x63, 0x6E][..], &list].concat())
}

#[test]
fn substring_rules() {
    // Source: RFC 4511 §4.5.1.7.2; docs/49 §2.3 E15, §2.4.
    let initial: &[u8] = &[0x80, 0x01, 0x61];
    let any: &[u8] = &[0x81, 0x01, 0x62];
    let fin: &[u8] = &[0x82, 0x01, 0x63];
    let ok = |items: &[&[u8]]| decode_request(&search_with_filter(&substrings(items))).is_ok();
    let err = |items: &[&[u8]]| request_error(&search_with_filter(&substrings(items)));
    assert!(ok(&[initial, any, any, fin]));
    assert!(ok(&[any]));
    assert!(ok(&[fin]));
    assert_eq!(err(&[]), Error::EmptySubstrings);
    assert_eq!(err(&[any, initial]), Error::SubstringOrder);
    assert_eq!(err(&[initial, initial]), Error::SubstringOrder);
    assert_eq!(err(&[fin, any]), Error::SubstringOrder);
    assert_eq!(err(&[fin, fin]), Error::SubstringOrder);
    assert!(ok(&vec![any; MAX_SUBSTRING_ANY]));
    assert_eq!(
        err(&vec![any; MAX_SUBSTRING_ANY + 1]),
        Error::LimitExceeded(Limit::SubstringAny)
    );
    // An undefined alternative [3] inside the substring CHOICE is refused.
    assert_eq!(err(&[&[0x83, 0x01, 0x61]]), Error::UnexpectedTag);
    // A constructed initial (implicit tag on OCTET STRING).
    assert_eq!(err(&[&[0xA0, 0x00]]), Error::ConstructedOctetString);
}

#[test]
fn extensible_match_needs_rule_or_type() {
    // Source: RFC 4511 §4.5.1.7.7 ("If the matchingRule field is absent, the
    // type field MUST be present").
    let mra = tlv(0xA9, &[0x83, 0x01, 0x61]);
    assert_eq!(
        request_error(&search_with_filter(&mra)),
        Error::MissingMatchingRuleAndType
    );
    let with_type = tlv(
        0xA9,
        &[&[0x82, 0x01, 0x61][..], &[0x83, 0x01, 0x62]].concat(),
    );
    assert!(decode_request(&search_with_filter(&with_type)).is_ok());
}

#[test]
fn unrecognized_filter_alternative() {
    // Source: RFC 4511 §4.5.1.7 ("The type of filtering requested is not
    // implemented" → Undefined); docs/49 §2.3 E13.
    let unknown = tlv(0xAA, &[0x04, 0x01, 0x61]);
    let decoded = decode_request(&search_with_filter(&unknown)).unwrap();
    let ProtocolOp::SearchRequest(search) = decoded.protocol_op else {
        panic!("expected a search");
    };
    assert_eq!(search.filter, Filter::Unrecognized { tag_number: 10 });
    // Its contents are still validated (RFC 4511 §5.1 inside it).
    let bad = tlv(0xAA, &[0x24, 0x00]);
    assert_eq!(
        request_error(&search_with_filter(&bad)),
        Error::ConstructedOctetString
    );
    // The canonical profile accepts it only as an empty primitive element.
    assert_eq!(
        decode_message(&search_with_filter(&unknown), &canonical_request()),
        Err(Error::NonCanonical)
    );
    assert!(decode_message(&search_with_filter(&[0x8A, 0x00]), &canonical_request()).is_ok());
    // A non-context class in the filter position is malformed.
    assert_eq!(
        request_error(&search_with_filter(&[0x04, 0x01, 0x61])),
        Error::UnexpectedTag
    );
}

// ---- size bounds (docs/49 §2.4; [MS-ADTS] 3.1.1.3.4.6) ----

#[test]
fn oversize_message_rejected() {
    // Source: docs/49 §2.4; [MS-ADTS] 3.1.1.3.4.6 ("drop the connection") — a
    // SASL bind with 70,000 octets of credentials exceeds 64 KiB.
    let sasl = tlv(
        0xA3,
        &[tlv(0x04, b"GSSAPI"), tlv(0x04, &vec![0x5A; 70_000])].concat(),
    );
    let bytes = bind_with(b"", &sasl);
    assert!(bytes.len() > MAX_PREAUTH_MESSAGE_OCTETS);
    assert_eq!(request_error(&bytes), Error::MessageTooLarge);
    let authenticated = DecodeOptions::request(AuthState::Authenticated);
    let decoded = decode_message(&bytes, &authenticated).unwrap();
    let ProtocolOp::BindRequest(bind) = decoded.protocol_op else {
        panic!("expected a bind");
    };
    let AuthenticationChoice::Sasl(creds) = bind.authentication else {
        panic!("expected SASL");
    };
    assert_eq!(creds.credentials.map(|c| c.len()), Some(70_000));
}

#[test]
fn ldapdn_bound() {
    // Source: docs/49 §2.4 (2048 octets).
    let at_bound = vec![b'a'; MAX_LDAPDN_OCTETS];
    assert!(decode_request(&bind_with(&at_bound, &[0x80, 0x00])).is_ok());
    let over = vec![b'a'; MAX_LDAPDN_OCTETS + 1];
    assert_eq!(
        request_error(&bind_with(&over, &[0x80, 0x00])),
        Error::LimitExceeded(Limit::LdapDnOctets)
    );
}

#[test]
fn selector_bound() {
    // Source: docs/49 §2.4 (64 selectors).
    let selection = |n: usize| tlv(0x30, &[0x04, 0x01, 0x61].repeat(n));
    let with = |n: usize| {
        search_raw(&[
            BASE_EMPTY,
            SCOPE_BASE,
            DEREF_NEVER,
            ZERO,
            ZERO,
            FALSE,
            &PRESENT_A,
            &selection(n),
        ])
    };
    assert!(decode_request(&with(MAX_ATTRIBUTE_SELECTORS)).is_ok());
    assert_eq!(
        request_error(&with(MAX_ATTRIBUTE_SELECTORS + 1)),
        Error::LimitExceeded(Limit::AttributeSelectors)
    );
}

#[test]
fn control_bound() {
    // Source: docs/49 §2.4 (8 controls).
    let control = tlv(0x30, &[0x04, 0x01, 0x31]);
    let with = |n: usize| {
        tlv(
            0x30,
            &[
                &[0x02, 0x01, 0x01][..],
                &[0x42, 0x00],
                &tlv(0xA0, &control.repeat(n)),
            ]
            .concat(),
        )
    };
    assert!(decode_request(&with(MAX_CONTROLS)).is_ok());
    assert_eq!(
        request_error(&with(MAX_CONTROLS + 1)),
        Error::LimitExceeded(Limit::Controls)
    );
}

#[test]
fn element_depth_bound_in_skipped_component() {
    // Source: docs/49 §2.4 (element depth 64), E12 (skipped components are
    // validated within the bounds) — 70 nested [1] after the protocolOp.
    let mut deep = vec![0x81, 0x00];
    for _ in 0..70 {
        deep = tlv(0xA1, &deep);
    }
    let bytes = message(&[&[0x42, 0x00][..], &deep].concat());
    assert_eq!(request_error(&bytes), Error::LimitExceeded(Limit::TlvDepth));
}

// ---- framing within the message (RFC 4511 §5.2) ----

#[test]
fn trailing_garbage_rejected() {
    // Source: RFC 4511 §5.2 — octets after the LDAPMessage inside one input.
    let bytes = [0x30, 0x05, 0x02, 0x01, 0x06, 0x42, 0x00, 0x00];
    assert_eq!(request_error(&bytes), Error::TrailingData);
}

#[test]
fn truncation_sweep_on_hand_built_inputs() {
    // Source: X.690 8.1.1.1; RFC 4511 §4.1.1 — every proper prefix fails.
    let inputs = [
        bind_with(b"cn=a", &[0x80, 0x00]),
        search_with_filter(&nested_not(5)),
        search_with_filter(&substrings(&[&[0x80, 0x01, 0x61], &[0x82, 0x01, 0x62]])),
    ];
    for bytes in inputs {
        assert!(decode_request(&bytes).is_ok());
        for cut in 0..bytes.len() {
            assert!(decode_request(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }
}

// ---- protocolOp (RFC 4511 §4.1.1; docs/49 E13, A-48) ----

#[test]
fn unknown_protocol_op_rejected() {
    // Source: RFC 4511 §4.1.1 ("the tag of the protocolOp is not recognized
    // as a request").
    // [APPLICATION 30] — no such operation.
    assert_eq!(
        request_error(&message(&[0x7E, 0x00])),
        Error::UnrecognizedProtocolOp
    );
    // A response sent by a client: BindResponse.
    let bind_response = [0x61, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00];
    assert_eq!(
        request_error(&message(&bind_response)),
        Error::UnrecognizedProtocolOp
    );
    // IntermediateResponse [APPLICATION 25] (no code path, R49-17).
    assert_eq!(
        request_error(&message(&[0x79, 0x00])),
        Error::UnrecognizedProtocolOp
    );
    // A context-specific tag in the protocolOp position.
    assert_eq!(
        request_error(&message(&[0x80, 0x00])),
        Error::UnrecognizedProtocolOp
    );
    // A request in the response direction.
    assert_eq!(
        decode_message(&message(&[0x42, 0x00]), &wire_response()),
        Err(Error::UnrecognizedProtocolOp)
    );
}

#[test]
fn unsupported_operations_not_decoded() {
    // Source: A-48; docs/49 §5.1 — Modify/Add/ModifyDN/Compare recognised by
    // tag; their bodies (here bytes that are not LDAP-BER at all) are bounded
    // by the outer length but never decoded.
    for (identifier, op_tag) in [
        (0x66, UnsupportedOp::ModifyRequest),
        (0x68, UnsupportedOp::AddRequest),
        (0x6C, UnsupportedOp::ModifyDnRequest),
        (0x6E, UnsupportedOp::CompareRequest),
    ] {
        let bytes = message(&[identifier, 0x03, 0xFF, 0xFF, 0xFF]);
        let decoded = decode_request(&bytes).unwrap();
        assert_eq!(decoded.protocol_op, ProtocolOp::Unsupported { op_tag });
        // Canonical form: the tag with an empty body.
        let canonical = encode_message(&decoded).unwrap();
        assert_eq!(canonical, message(&[identifier, 0x00]));
        assert_eq!(
            decode_message(&canonical, &canonical_request()).unwrap(),
            decoded
        );
        assert_eq!(
            decode_message(&bytes, &canonical_request()),
            Err(Error::NonCanonical)
        );
        // Wrong form: a primitive SEQUENCE-based operation.
        assert_eq!(
            request_error(&message(&[identifier & !0x20, 0x00])),
            Error::PrimitiveConstructedMismatch
        );
    }
    // DelRequest is an implicitly tagged LDAPDN: primitive.
    let del = message(&[&[0x4A, 0x04][..], b"dc=x"].concat());
    assert_eq!(
        decode_request(&del).unwrap().protocol_op,
        ProtocolOp::Unsupported {
            op_tag: UnsupportedOp::DelRequest
        }
    );
}

// ---- MessageID and version (RFC 4511 §4.1.1, §4.1.1.1, §4.2) ----

/// An UnbindRequest message with the given messageID contents octets.
fn unbind_with_id(id_contents: &[u8]) -> Vec<u8> {
    tlv(0x30, &[tlv(0x02, id_contents), vec![0x42, 0x00]].concat())
}

#[test]
fn message_id_range() {
    // Source: RFC 4511 §4.1.1 (0 .. maxInt = 2^31 - 1).
    assert!(decode_request(&unbind_with_id(&[0x7F, 0xFF, 0xFF, 0xFF])).is_ok());
    assert_eq!(
        request_error(&unbind_with_id(&[0x00, 0x80, 0x00, 0x00, 0x00])),
        Error::MessageIdOutOfRange
    );
    assert_eq!(
        request_error(&unbind_with_id(&[0x80, 0x00, 0x00, 0x00])),
        Error::MessageIdOutOfRange
    );
    assert_eq!(
        request_error(&unbind_with_id(&[0xFF])),
        Error::MessageIdOutOfRange
    );
    assert_eq!(
        request_error(&unbind_with_id(&[0x01; 9])),
        Error::MessageIdOutOfRange
    );
    // Source: RFC 4511 §4.1.1.1 — zero is reserved in requests.
    assert_eq!(
        request_error(&unbind_with_id(&[0x00])),
        Error::ZeroMessageId
    );
    // Source: X.690 8.3.2 — not minimal.
    assert_eq!(
        request_error(&unbind_with_id(&[0x00, 0x05])),
        Error::NonMinimalInteger
    );
    // Source: X.690 8.3.1 — no contents.
    assert_eq!(request_error(&unbind_with_id(&[])), Error::EmptyInteger);
}

#[test]
fn version_range() {
    // Source: RFC 4511 §4.2 (version INTEGER (1 .. 127)); docs/49 E9.
    let bind = |version: &[u8]| {
        let contents = [tlv(0x02, version), vec![0x04, 0x00, 0x80, 0x00]].concat();
        message(&tlv(0x60, &contents))
    };
    assert_eq!(request_error(&bind(&[0x00])), Error::VersionOutOfRange);
    assert_eq!(
        request_error(&bind(&[0x00, 0x80])),
        Error::VersionOutOfRange
    );
    assert_eq!(request_error(&bind(&[0xFF])), Error::VersionOutOfRange);
    // 2 is in range: decoded; the engine answers protocolError (E9).
    assert!(decode_request(&bind(&[0x02])).is_ok());
}

#[test]
fn size_and_time_limit_range() {
    // Source: RFC 4511 §4.5.1 (INTEGER (0 .. maxInt)).
    let negative: &[u8] = &[0x02, 0x01, 0xFF];
    let bytes = search_raw(&[
        BASE_EMPTY,
        SCOPE_BASE,
        DEREF_NEVER,
        negative,
        ZERO,
        FALSE,
        &PRESENT_A,
        NO_ATTRIBUTES,
    ]);
    assert_eq!(request_error(&bytes), Error::IntegerOutOfRange);
}

#[test]
fn unknown_scope_is_kept_for_the_engine() {
    // Source: RFC 4511 §4.5.1 (scope is extensible); docs/49 E14 — not a
    // codec error: the engine answers protocolError.
    let bytes = search_raw(&[
        BASE_EMPTY,
        &[0x0A, 0x01, 0x05],
        DEREF_NEVER,
        ZERO,
        ZERO,
        FALSE,
        &PRESENT_A,
        NO_ATTRIBUTES,
    ]);
    let ProtocolOp::SearchRequest(search) = decode_request(&bytes).unwrap().protocol_op else {
        panic!("expected a search");
    };
    assert_eq!(search.scope, Scope::Unrecognized(5));
}

// ---- NULL (RFC 4511 §4.3; X.690 8.8) ----

#[test]
fn unbind_must_be_empty_primitive() {
    assert_eq!(
        request_error(&message(&[0x42, 0x01, 0x00])),
        Error::InvalidNull
    );
    assert_eq!(
        request_error(&message(&[0x62, 0x00])),
        Error::PrimitiveConstructedMismatch
    );
}

// ---- trailing components (RFC 4511 §4; docs/49 E12; A-45 item 2) ----

#[test]
fn trailing_components() {
    // An unrecognised [10] after the AuthenticationChoice: skipped (wire),
    // refused (canonical).
    let with_trailer = bind_with(b"", &[0x80, 0x00, 0x8A, 0x01, 0x00]);
    let decoded = decode_request(&with_trailer).unwrap();
    assert_eq!(
        decoded,
        decode_request(&bind_with(b"", &[0x80, 0x00])).unwrap()
    );
    assert_eq!(
        decode_message(&with_trailer, &canonical_request()),
        Err(Error::UnrecognizedComponent)
    );
    // A tag BindRequest defines, out of place: malformed in both profiles.
    let misplaced = bind_with(b"", &[0x80, 0x00, 0x04, 0x00]);
    assert_eq!(request_error(&misplaced), Error::UnexpectedTag);
    // Skipped components are validated: an indefinite length inside one.
    let hidden = bind_with(b"", &[0x80, 0x00, 0xAA, 0x02, 0x30, 0x80]);
    assert_eq!(request_error(&hidden), Error::IndefiniteLength);
    // ... and a non-FF BOOLEAN inside one.
    let hidden = bind_with(b"", &[0x80, 0x00, 0xAA, 0x03, 0x01, 0x01, 0x01]);
    assert_eq!(request_error(&hidden), Error::InvalidBoolean);
    // At the LDAPMessage level: an unknown [5] after the protocolOp is
    // skipped; controls [0] after it is then out of place.
    assert!(decode_request(&message(&[0x42, 0x00, 0x85, 0x00])).is_ok());
    assert_eq!(
        request_error(&message(&[0x42, 0x00, 0x85, 0x00, 0xA0, 0x00])),
        Error::UnexpectedTag
    );
}

#[test]
fn unrecognized_authentication_choice() {
    // Source: RFC 4511 §4.2 (extensible; unsupported choices answered with
    // authMethodNotSupported by the engine); docs/49 E13.
    let bytes = bind_with(b"", &[0xA9, 0x02, 0x04, 0x00]);
    let ProtocolOp::BindRequest(bind) = decode_request(&bytes).unwrap().protocol_op else {
        panic!("expected a bind");
    };
    assert_eq!(
        bind.authentication,
        AuthenticationChoice::Unrecognized { tag_number: 9 }
    );
    // A non-context class in that position is malformed.
    assert_eq!(
        request_error(&bind_with(b"", &[0x04, 0x00])),
        Error::UnexpectedTag
    );
}

#[test]
fn simple_password_is_never_retained() {
    // Source: docs/49 §2.3 (simple decoded to shape only); Q-185 — the
    // canonical encoding writes the single placeholder octet.
    let bytes = bind_with(b"cn=a", &tlv(0x80, b"secret"));
    let decoded = decode_request(&bytes).unwrap();
    let ProtocolOp::BindRequest(bind) = &decoded.protocol_op else {
        panic!("expected a bind");
    };
    assert_eq!(
        bind.authentication,
        AuthenticationChoice::Simple {
            password_empty: false
        }
    );
    let canonical = encode_message(&decoded).unwrap();
    assert_eq!(canonical, bind_with(b"cn=a", &[0x80, 0x01, 0x00]));
    assert!(!canonical.windows(6).any(|w| w == b"secret"));
    // The canonical profile accepts no other password octets.
    assert_eq!(
        decode_message(&bytes, &canonical_request()),
        Err(Error::NonCanonical)
    );
    assert_eq!(
        decode_message(&canonical, &canonical_request()).unwrap(),
        decoded
    );
}

// ---- response direction (RFC 4511 §4.1.1.1, §4.1.9; R49-17) ----

#[test]
fn response_direction_rules() {
    // Zero messageID only on the unsolicited notification.
    let done_zero = tlv(
        0x30,
        &[
            &[0x02, 0x01, 0x00][..],
            &[0x65, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00],
        ]
        .concat(),
    );
    assert_eq!(
        decode_message(&done_zero, &wire_response()),
        Err(Error::ZeroMessageId)
    );
    // referral [3] has no code path: out of place after diagnosticMessage.
    let with_referral = message(&tlv(
        0x65,
        &[
            &[0x0A, 0x01, 0x0A][..],
            &[0x04, 0x00, 0x04, 0x00],
            &tlv(0xA3, &[0x04, 0x01, 0x61]),
        ]
        .concat(),
    ));
    assert_eq!(
        decode_message(&with_referral, &wire_response()),
        Err(Error::UnexpectedTag)
    );
    // resultCode 9 is reserved, not defined.
    let reserved = message(&[0x65, 0x07, 0x0A, 0x01, 0x09, 0x04, 0x00, 0x04, 0x00]);
    assert_eq!(
        decode_message(&reserved, &wire_response()),
        Err(Error::UnrecognizedResultCode)
    );
}
