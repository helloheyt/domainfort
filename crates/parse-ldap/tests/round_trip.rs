//! Round trips: `decode(encode(x)) == x` for every typed message, and
//! `encode(decode(b))` is canonical and stable.
//!
//! Source: RFC 4511 App. B (the types), §5.1 (the encoding subset), and
//! docs/49 §11 (R49-16: the canonical re-encoding decodes under the canonical
//! profile to the same value). Values are hand-built from the ASN.1 module.

mod common;

use common::{canonical_request, canonical_response, message, tlv, wire_request, wire_response};
use parse_ldap::{
    decode_message, encode_message, AttributeValueAssertion, AuthenticationChoice, BindRequest,
    BindResponse, Control, DecodeOptions, DerefAliases, Error, ExtendedRequest, ExtendedResponse,
    Filter, LdapMessage, LdapResult, MatchingRuleAssertion, MessageId, PartialAttribute,
    ProtocolOp, ResultCode, SaslCredentials, Scope, SearchRequest, SearchResultEntry, Substring,
    SubstringFilter, UnsupportedOp, MAX_FILTER_DEPTH, MAX_INT,
};

fn id(n: u32) -> MessageId {
    MessageId::new(n).unwrap()
}

fn msg(n: u32, op: ProtocolOp) -> LdapMessage {
    LdapMessage {
        message_id: id(n),
        protocol_op: op,
        controls: None,
    }
}

/// `decode(encode(x)) == x` under both profiles, and the encoding is stable.
fn assert_round_trip(value: &LdapMessage, wire: &DecodeOptions, canonical: &DecodeOptions) {
    let bytes = encode_message(value).unwrap();
    assert_eq!(&decode_message(&bytes, wire).unwrap(), value);
    assert_eq!(&decode_message(&bytes, canonical).unwrap(), value);
    let again = encode_message(&decode_message(&bytes, canonical).unwrap()).unwrap();
    assert_eq!(again, bytes);
}

fn request_round_trip(value: &LdapMessage) {
    assert_round_trip(value, &wire_request(), &canonical_request());
}

fn response_round_trip(value: &LdapMessage) {
    assert_round_trip(value, &wire_response(), &canonical_response());
}

fn ava(desc: &str, value: &[u8]) -> AttributeValueAssertion {
    AttributeValueAssertion {
        attribute_desc: desc.to_owned(),
        assertion_value: value.to_vec(),
    }
}

/// A filter using every alternative of RFC 4511 §4.5.1 at least once.
fn every_filter_alternative() -> Filter {
    Filter::Or(vec![
        Filter::And(vec![
            Filter::EqualityMatch(ava("cn", b"a")),
            Filter::GreaterOrEqual(ava("uSNChanged", b"10")),
            Filter::LessOrEqual(ava("uSNChanged", b"20")),
            Filter::ApproxMatch(ava("sn", b"b")),
        ]),
        Filter::Not(Box::new(Filter::Present("objectClass".to_owned()))),
        Filter::Substrings(SubstringFilter {
            r#type: "cn".to_owned(),
            substrings: vec![
                Substring::Initial(b"a".to_vec()),
                Substring::Any(b"b".to_vec()),
                Substring::Any(Vec::new()),
                Substring::Final(b"c".to_vec()),
            ],
        }),
        Filter::ExtensibleMatch(MatchingRuleAssertion {
            matching_rule: Some("2.5.13.2".to_owned()),
            r#type: Some("cn".to_owned()),
            match_value: b"x".to_vec(),
            dn_attributes: true,
        }),
        Filter::ExtensibleMatch(MatchingRuleAssertion {
            matching_rule: None,
            r#type: Some("cn".to_owned()),
            match_value: Vec::new(),
            dn_attributes: false,
        }),
        Filter::ExtensibleMatch(MatchingRuleAssertion {
            matching_rule: Some("caseIgnoreMatch".to_owned()),
            r#type: None,
            match_value: b"y".to_vec(),
            dn_attributes: false,
        }),
        Filter::Unrecognized { tag_number: 10 },
        Filter::Unrecognized { tag_number: 30 },
    ])
}

#[test]
fn bind_requests() {
    for authentication in [
        AuthenticationChoice::Simple {
            password_empty: true,
        },
        AuthenticationChoice::Simple {
            password_empty: false,
        },
        AuthenticationChoice::Sasl(SaslCredentials {
            mechanism: "GSSAPI".to_owned(),
            credentials: None,
        }),
        AuthenticationChoice::Sasl(SaslCredentials {
            mechanism: "GSSAPI".to_owned(),
            credentials: Some(Vec::new()),
        }),
        AuthenticationChoice::Sasl(SaslCredentials {
            mechanism: "GSSAPI".to_owned(),
            credentials: Some(vec![0x60; 300]),
        }),
        AuthenticationChoice::Unrecognized { tag_number: 1 },
        AuthenticationChoice::Unrecognized { tag_number: 9 },
    ] {
        for version in [1, 3, 127] {
            request_round_trip(&msg(
                MAX_INT,
                ProtocolOp::BindRequest(BindRequest {
                    version,
                    name: "cn=é".to_owned(),
                    authentication: authentication.clone(),
                }),
            ));
        }
    }
}

#[test]
fn unsupported_operation_responses() {
    // RFC 4511 App. B: ModifyResponse ::= [APPLICATION 7] LDAPResult,
    // AddResponse 9, DelResponse 11, ModifyDNResponse 13, CompareResponse 15;
    // docs/questions/Q-190 item 1 (A-54): a typed response.
    for (op, tag) in [
        (UnsupportedOp::ModifyRequest, 7u8),
        (UnsupportedOp::AddRequest, 9),
        (UnsupportedOp::DelRequest, 11),
        (UnsupportedOp::ModifyDnRequest, 13),
        (UnsupportedOp::CompareRequest, 15),
    ] {
        let value = msg(
            9,
            ProtocolOp::UnsupportedResponse {
                op,
                result: LdapResult::new(ResultCode::UnwillingToPerform),
            },
        );
        response_round_trip(&value);
        // X.690 8.1.2.2 / 8.1.2.5 / 8.14.4: class APPLICATION (01),
        // constructed (bit 6), the tag number; contents = the LDAPResult
        // components: ENUMERATED 53, matchedDN "", diagnosticMessage "".
        // Built independently with the test's own element builder.
        let expected = message(&tlv(0x60 | tag, &[0x0A, 0x01, 53, 0x04, 0x00, 0x04, 0x00]));
        let mut expected = expected;
        // `message` writes messageID 1; this value uses 9.
        expected[4] = 9;
        assert_eq!(encode_message(&value).unwrap(), expected);
        // The request direction never accepts a response tag.
        assert!(decode_message(&expected, &canonical_request()).is_err());
    }
}

#[test]
fn bind_responses() {
    for creds in [None, Some(Vec::new()), Some(vec![0xA1; 200])] {
        response_round_trip(&msg(
            1,
            ProtocolOp::BindResponse(BindResponse {
                result: LdapResult {
                    result_code: ResultCode::SaslBindInProgress,
                    matched_dn: String::new(),
                    diagnostic_message: String::new(),
                },
                server_sasl_creds: creds,
            }),
        ));
    }
}

#[test]
fn every_result_code() {
    // RFC 4511 §4.1.9: every defined code survives encode/decode.
    for code in (0..=80).filter_map(ResultCode::from_code) {
        assert_eq!(ResultCode::from_code(i64::from(code.code())), Some(code));
        response_round_trip(&msg(5, ProtocolOp::SearchResultDone(LdapResult::new(code))));
    }
    assert_eq!(ResultCode::from_code(9), None);
    assert_eq!(ResultCode::from_code(70), None);
}

#[test]
fn unbind_and_abandon() {
    request_round_trip(&msg(2, ProtocolOp::UnbindRequest));
    for target in [0, 1, 127, 128, 65_535, MAX_INT] {
        request_round_trip(&msg(3, ProtocolOp::AbandonRequest(id(target))));
    }
}

#[test]
fn search_requests() {
    let scopes = [
        Scope::BaseObject,
        Scope::SingleLevel,
        Scope::WholeSubtree,
        Scope::Unrecognized(3),
        Scope::Unrecognized(-1),
    ];
    let derefs = [
        DerefAliases::NeverDerefAliases,
        DerefAliases::DerefInSearching,
        DerefAliases::DerefFindingBaseObj,
        DerefAliases::DerefAlways,
        DerefAliases::Unrecognized(4),
    ];
    for (scope, deref_aliases) in scopes.into_iter().zip(derefs) {
        request_round_trip(&msg(
            4,
            ProtocolOp::SearchRequest(SearchRequest {
                base_object: "dc=example,dc=test".to_owned(),
                scope,
                deref_aliases,
                size_limit: MAX_INT,
                time_limit: 30,
                types_only: true,
                filter: every_filter_alternative(),
                attributes: vec!["cn".to_owned(), "*".to_owned(), "1.1".to_owned()],
            }),
        ));
    }
}

#[test]
fn deepest_filter_round_trips() {
    let mut f = Filter::Present("a".to_owned());
    for _ in 1..MAX_FILTER_DEPTH {
        f = Filter::Not(Box::new(f));
    }
    let value = msg(
        4,
        ProtocolOp::SearchRequest(SearchRequest {
            base_object: String::new(),
            scope: Scope::BaseObject,
            deref_aliases: DerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: f.clone(),
            attributes: Vec::new(),
        }),
    );
    request_round_trip(&value);
    // One level deeper is refused by the encoder too (docs/49 §2.4).
    let mut too_deep = value;
    if let ProtocolOp::SearchRequest(s) = &mut too_deep.protocol_op {
        s.filter = Filter::Not(Box::new(f));
    }
    assert_eq!(
        encode_message(&too_deep),
        Err(Error::LimitExceeded(parse_ldap::Limit::FilterDepth))
    );
}

#[test]
fn search_result_entries() {
    response_round_trip(&msg(
        4,
        ProtocolOp::SearchResultEntry(SearchResultEntry {
            object_name: "cn=a,dc=test".to_owned(),
            attributes: vec![
                PartialAttribute {
                    r#type: "objectClass".to_owned(),
                    vals: vec![b"top".to_vec(), b"person".to_vec()],
                },
                PartialAttribute {
                    r#type: "member".to_owned(),
                    vals: Vec::new(),
                },
                PartialAttribute {
                    r#type: "objectGUID".to_owned(),
                    vals: vec![vec![0x00; 16]],
                },
            ],
        }),
    ));
    response_round_trip(&msg(
        4,
        ProtocolOp::SearchResultEntry(SearchResultEntry {
            object_name: String::new(),
            attributes: Vec::new(),
        }),
    ));
}

#[test]
fn extended_operations() {
    request_round_trip(&msg(
        1,
        ProtocolOp::ExtendedRequest(ExtendedRequest {
            request_name: parse_ldap::START_TLS_OID.to_owned(),
            request_value: None,
        }),
    ));
    request_round_trip(&msg(
        1,
        ProtocolOp::ExtendedRequest(ExtendedRequest {
            request_name: "1.2.3.4".to_owned(),
            request_value: Some(vec![0x00, 0x30, 0x00]),
        }),
    ));
    response_round_trip(&msg(
        1,
        ProtocolOp::ExtendedResponse(ExtendedResponse {
            result: LdapResult::new(ResultCode::Success),
            response_name: Some(parse_ldap::START_TLS_OID.to_owned()),
            response_value: None,
        }),
    ));
    response_round_trip(&msg(
        1,
        ProtocolOp::ExtendedResponse(ExtendedResponse {
            result: LdapResult::new(ResultCode::ProtocolError),
            response_name: None,
            response_value: Some(vec![0xFF]),
        }),
    ));
    response_round_trip(&LdapMessage::notice_of_disconnection(
        ResultCode::StrongerAuthRequired,
    ));
}

#[test]
fn controls() {
    let mut value = msg(9, ProtocolOp::UnbindRequest);
    value.controls = Some(Vec::new());
    request_round_trip(&value);
    value.controls = Some(vec![
        Control {
            control_type: "1.2.840.1".to_owned(),
            criticality: true,
            control_value: None,
        },
        Control {
            control_type: "1.2.840.2".to_owned(),
            criticality: false,
            control_value: Some(vec![0x30, 0x00]),
        },
        Control {
            control_type: "1.2.840.3".to_owned(),
            criticality: false,
            control_value: Some(Vec::new()),
        },
    ]);
    request_round_trip(&value);
}

#[test]
fn unsupported_operations() {
    for op_tag in [
        UnsupportedOp::ModifyRequest,
        UnsupportedOp::AddRequest,
        UnsupportedOp::DelRequest,
        UnsupportedOp::ModifyDnRequest,
        UnsupportedOp::CompareRequest,
    ] {
        request_round_trip(&msg(6, ProtocolOp::Unsupported { op_tag }));
        assert_eq!(op_tag.response_tag_number(), op_tag.tag_number() + 1);
    }
}

#[test]
fn wire_input_reencodes_canonically() {
    // A request with non-minimal lengths (A-45), a skipped trailing component
    // (RFC 4511 §4), an unrecognised filter alternative with contents and a
    // simple password: the canonical re-encoding decodes under the canonical
    // profile to the same value, and is never longer than the input.
    let filter = tlv(
        0xA0,
        &[
            vec![0xAB, 0x84, 0x00, 0x00, 0x00, 0x03, 0x04, 0x01, 0x61],
            vec![0x87, 0x81, 0x01, 0x61],
        ]
        .concat(),
    );
    let mut search = vec![
        0x04, 0x81, 0x00, // baseObject "" with a long-form length
        0x0A, 0x01, 0x02, 0x0A, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0xFF,
    ];
    search.extend_from_slice(&filter);
    search.extend_from_slice(&[0x30, 0x00]);
    search.extend_from_slice(&[0x9E, 0x02, 0xAB, 0xCD]); // unrecognised [30]
    let bytes = message(&tlv(0x63, &search));
    let decoded = decode_message(&bytes, &wire_request()).unwrap();
    let canonical = encode_message(&decoded).unwrap();
    assert!(canonical.len() < bytes.len());
    assert_eq!(
        decode_message(&canonical, &canonical_request()).unwrap(),
        decoded
    );
    assert_eq!(
        decode_message(&bytes, &canonical_request()),
        Err(Error::NonMinimalLength)
    );
    let ProtocolOp::SearchRequest(s) = decoded.protocol_op else {
        panic!("expected a search");
    };
    assert_eq!(
        s.filter,
        Filter::And(vec![
            Filter::Unrecognized { tag_number: 11 },
            Filter::Present("a".to_owned()),
        ])
    );
}

#[test]
fn encoder_refuses_unrepresentable_values() {
    let search = |filter: Filter, scope: Scope| {
        msg(
            4,
            ProtocolOp::SearchRequest(SearchRequest {
                base_object: String::new(),
                scope,
                deref_aliases: DerefAliases::NeverDerefAliases,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter,
                attributes: Vec::new(),
            }),
        )
    };
    let present = || Filter::Present("a".to_owned());
    // An Unrecognized carrying a defined value would decode as that value.
    assert_eq!(
        encode_message(&search(present(), Scope::Unrecognized(2))),
        Err(Error::InvalidValue)
    );
    assert_eq!(
        encode_message(&search(
            Filter::Unrecognized { tag_number: 7 },
            Scope::BaseObject
        )),
        Err(Error::InvalidValue)
    );
    assert_eq!(
        encode_message(&search(
            Filter::Unrecognized { tag_number: 31 },
            Scope::BaseObject
        )),
        Err(Error::InvalidValue)
    );
    // Filter grammar (RFC 4511 §4.5.1, §4.5.1.7.2, §4.5.1.7.7).
    assert_eq!(
        encode_message(&search(Filter::And(Vec::new()), Scope::BaseObject)),
        Err(Error::EmptySet)
    );
    let bad_substrings = Filter::Substrings(SubstringFilter {
        r#type: "cn".to_owned(),
        substrings: vec![Substring::Any(Vec::new()), Substring::Initial(Vec::new())],
    });
    assert_eq!(
        encode_message(&search(bad_substrings, Scope::BaseObject)),
        Err(Error::SubstringOrder)
    );
    let no_rule_no_type = Filter::ExtensibleMatch(MatchingRuleAssertion {
        matching_rule: None,
        r#type: None,
        match_value: Vec::new(),
        dn_attributes: false,
    });
    assert_eq!(
        encode_message(&search(no_rule_no_type, Scope::BaseObject)),
        Err(Error::MissingMatchingRuleAndType)
    );
    // version outside 1..127 (RFC 4511 §4.2).
    let bind = msg(
        1,
        ProtocolOp::BindRequest(BindRequest {
            version: 0,
            name: String::new(),
            authentication: AuthenticationChoice::Simple {
                password_empty: true,
            },
        }),
    );
    assert_eq!(encode_message(&bind), Err(Error::VersionOutOfRange));
    // MessageID outside 0..maxInt cannot even be constructed (RFC 4511 §4.1.1).
    assert_eq!(MessageId::new(MAX_INT + 1), Err(Error::MessageIdOutOfRange));
}

/// Every message this file builds, encoded.
fn sample_messages() -> Vec<Vec<u8>> {
    let mut with_controls = msg(9, ProtocolOp::AbandonRequest(id(3)));
    with_controls.controls = Some(vec![Control {
        control_type: "1.2".to_owned(),
        criticality: true,
        control_value: Some(vec![0x01]),
    }]);
    [
        msg(
            1,
            ProtocolOp::BindRequest(BindRequest {
                version: 3,
                name: "cn=a".to_owned(),
                authentication: AuthenticationChoice::Sasl(SaslCredentials {
                    mechanism: "GSSAPI".to_owned(),
                    credentials: Some(vec![0x60, 0x01, 0x00]),
                }),
            }),
        ),
        msg(
            4,
            ProtocolOp::SearchRequest(SearchRequest {
                base_object: "dc=test".to_owned(),
                scope: Scope::WholeSubtree,
                deref_aliases: DerefAliases::NeverDerefAliases,
                size_limit: 10,
                time_limit: 0,
                types_only: false,
                filter: every_filter_alternative(),
                attributes: vec!["cn".to_owned()],
            }),
        ),
        with_controls,
        msg(
            1,
            ProtocolOp::ExtendedRequest(ExtendedRequest {
                request_name: parse_ldap::START_TLS_OID.to_owned(),
                request_value: None,
            }),
        ),
    ]
    .iter()
    .map(|m| encode_message(m).unwrap())
    .collect()
}

#[test]
fn single_octet_mutations_never_panic() {
    // Robustness property (docs/CLEAN-ROOM.md: never panic; fail closed): replacing
    // any one octet of a valid request either fails with a typed error or
    // yields a value whose canonical encoding decodes, under the canonical
    // profile, to the same value (R49-16).
    for original in sample_messages() {
        for position in 0..original.len() {
            let current = original[position];
            for replacement in [
                0x00,
                0x01,
                0x7F,
                0x80,
                0x81,
                0x84,
                0xFF,
                current ^ 0x20,
                current.wrapping_add(1),
                current.wrapping_sub(1),
            ] {
                let mut mutated = original.clone();
                mutated[position] = replacement;
                if let Ok(value) = decode_message(&mutated, &wire_request()) {
                    let canonical = encode_message(&value).unwrap();
                    assert_eq!(
                        decode_message(&canonical, &canonical_request()).unwrap(),
                        value
                    );
                    assert!(canonical.len() <= mutated.len());
                }
                // What the canonical profile accepts is already canonical.
                if let Ok(value) = decode_message(&mutated, &canonical_request()) {
                    assert_eq!(encode_message(&value).unwrap(), mutated);
                }
            }
        }
    }
}

#[test]
fn sasl_credentials_are_redacted_in_debug() {
    // docs/CLEAN-ROOM.md / docs/49 §10: SASL tokens never reach debug output.
    let creds = SaslCredentials {
        mechanism: "GSSAPI".to_owned(),
        credentials: Some(b"TOKEN-OCTETS".to_vec()),
    };
    let shown = format!("{creds:?}");
    assert!(shown.contains("GSSAPI"));
    assert!(shown.contains("12 octets"));
    assert!(!shown.contains("TOKEN"));
    let response = BindResponse {
        result: LdapResult::new(ResultCode::Success),
        server_sasl_creds: Some(b"REPLY-OCTETS".to_vec()),
    };
    assert!(!format!("{response:?}").contains("REPLY"));
}
