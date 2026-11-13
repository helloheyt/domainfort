//! Hand-derived byte vectors for the LDAP-BER codec.
//!
//! Every vector names its source. Each is derived here, element by element,
//! from the ASN.1 module of RFC 4511 App. B (`IMPLICIT TAGS`) and the encoding
//! rules of X.690 (02/2021): identifier octets 8.1.2 (class bits Table 1;
//! universal numbers X.680 Table 1), definite lengths 8.1.3.4/8.1.3.5,
//! INTEGER 8.3, ENUMERATED 8.4, BOOLEAN 8.2 (TRUE = FF per RFC 4511 §5.1),
//! OCTET STRING 8.7.2 (primitive per §5.1), SEQUENCE 8.9, SET OF 8.12, and
//! implicit tags 8.14.4 (form of the base type). The one external vector is the
//! example payload of [MS-ADTS] v20261026 6.3.3, used verbatim. No vector
//! comes from any other implementation or test suite (AGENTS.md §4.5).

mod common;

use common::{canonical_request, canonical_response, wire_request, wire_response};
use parse_ldap::{
    decode_message, encode_message, AttributeValueAssertion, AuthenticationChoice, BindRequest,
    BindResponse, Control, DerefAliases, ExtendedRequest, Filter, LdapMessage, LdapResult,
    MessageId, PartialAttribute, ProtocolOp, ResultCode, SaslCredentials, Scope, SearchRequest,
    SearchResultEntry, Substring, SubstringFilter, START_TLS_OID,
};

fn id(n: u32) -> MessageId {
    MessageId::new(n).unwrap()
}

/// `bytes` is canonical and decodes to `value` as a request: wire and
/// canonical profiles agree, and the encoder reproduces the exact octets.
fn assert_request_vector(bytes: &[u8], value: &LdapMessage) {
    assert_eq!(&decode_message(bytes, &wire_request()).unwrap(), value);
    assert_eq!(&decode_message(bytes, &canonical_request()).unwrap(), value);
    assert_eq!(encode_message(value).unwrap(), bytes);
    assert_truncations_rejected(bytes, &wire_request());
}

/// The same, as a response.
fn assert_response_vector(bytes: &[u8], value: &LdapMessage) {
    assert_eq!(&decode_message(bytes, &wire_response()).unwrap(), value);
    assert_eq!(
        &decode_message(bytes, &canonical_response()).unwrap(),
        value
    );
    assert_eq!(encode_message(value).unwrap(), bytes);
    assert_truncations_rejected(bytes, &wire_response());
}

/// Every proper prefix of a valid message is rejected (never accepted, never a
/// panic). Spec: X.690 8.1.1.1 (an encoding has all its components); RFC 4511
/// §4.1.1 (incorrect lengths are malformed).
fn assert_truncations_rejected(bytes: &[u8], options: &parse_ldap::DecodeOptions) {
    for cut in 0..bytes.len() {
        assert!(
            decode_message(&bytes[..cut], options).is_err(),
            "prefix of {cut} octets must be rejected"
        );
    }
}

#[test]
fn simple_bind_anonymous() {
    // Source: RFC 4511 §4.2, App. B — hand-derived.
    //   version INTEGER 3                    02 01 03
    //   name LDAPDN ""                       04 00
    //   simple [0] OCTET STRING ""           80 00   (implicit, primitive)
    //   BindRequest [APPLICATION 0] SEQUENCE 60 07   (3 + 2 + 2 = 7)
    //   messageID 1                          02 01 01
    //   LDAPMessage SEQUENCE                 30 0C   (3 + 9 = 12)
    let bytes = [
        &[0x30, 0x0C][..],
        &[0x02, 0x01, 0x01],
        &[0x60, 0x07],
        &[0x02, 0x01, 0x03],
        &[0x04, 0x00],
        &[0x80, 0x00],
    ]
    .concat();
    let value = LdapMessage {
        message_id: id(1),
        protocol_op: ProtocolOp::BindRequest(BindRequest {
            version: 3,
            name: String::new(),
            authentication: AuthenticationChoice::Simple {
                password_empty: true,
            },
        }),
        controls: None,
    };
    assert_request_vector(&bytes, &value);
}

#[test]
fn sasl_bind() {
    // Source: RFC 4511 §4.2, App. B — hand-derived. The credentials are an
    // arbitrary three-octet value (01 02 03), not a real token.
    //   mechanism LDAPString "GSSAPI"        04 06 47 53 53 41 50 49
    //   credentials OCTET STRING             04 03 01 02 03
    //   sasl [3] SaslCredentials             A3 0D   (8 + 5 = 13, constructed)
    //   version 3, name ""                   02 01 03 04 00
    //   BindRequest                          60 14   (3 + 2 + 15 = 20)
    //   messageID 2                          02 01 02
    //   LDAPMessage                          30 19   (3 + 22 = 25)
    let bytes = [
        &[0x30, 0x19][..],
        &[0x02, 0x01, 0x02],
        &[0x60, 0x14],
        &[0x02, 0x01, 0x03],
        &[0x04, 0x00],
        &[0xA3, 0x0D],
        &[0x04, 0x06],
        b"GSSAPI",
        &[0x04, 0x03, 0x01, 0x02, 0x03],
    ]
    .concat();
    let value = LdapMessage {
        message_id: id(2),
        protocol_op: ProtocolOp::BindRequest(BindRequest {
            version: 3,
            name: String::new(),
            authentication: AuthenticationChoice::Sasl(SaslCredentials {
                mechanism: "GSSAPI".to_owned(),
                credentials: Some(vec![0x01, 0x02, 0x03]),
            }),
        }),
        controls: None,
    };
    assert_request_vector(&bytes, &value);
}

/// The search vector: base "dc=x", wholeSubtree, filter
/// `(&(objectClass=user)(!(cn=a*)))`, attributes `cn`.
fn search_vector() -> (Vec<u8>, LdapMessage) {
    // Source: RFC 4511 §4.5.1, App. B — hand-derived.
    //   equalityMatch [3] AVA                A3 13   (13 + 6 = 19)
    //     attributeDesc "objectClass"        04 0B ...
    //     assertionValue "user"              04 04 ...
    //   substrings [4] SubstringFilter       A4 09   (4 + 5 = 9)
    //     type "cn"                          04 02 63 6E
    //     substrings SEQUENCE OF             30 03
    //       initial [0] "a"                  80 01 61 (implicit, primitive)
    //   not [2] Filter (explicit in BER)     A2 0B   (11)
    //   and [0] SET OF Filter                A0 22   (21 + 13 = 34)
    //   attributes SEQUENCE OF               30 04 04 02 63 6E
    //   baseObject "dc=x"                    04 04 64 63 3D 78
    //   scope wholeSubtree (2)               0A 01 02
    //   derefAliases neverDerefAliases (0)   0A 01 00
    //   sizeLimit 0, timeLimit 0             02 01 00 02 01 00
    //   typesOnly FALSE                      01 01 00
    //   SearchRequest [APPLICATION 3]        63 3F   (6+3+3+3+3+3+36+6 = 63)
    //   messageID 3                          02 01 03
    //   LDAPMessage                          30 44   (3 + 65 = 68)
    let bytes = [
        &[0x30, 0x44][..],
        &[0x02, 0x01, 0x03],
        &[0x63, 0x3F],
        &[0x04, 0x04],
        b"dc=x",
        &[0x0A, 0x01, 0x02],
        &[0x0A, 0x01, 0x00],
        &[0x02, 0x01, 0x00],
        &[0x02, 0x01, 0x00],
        &[0x01, 0x01, 0x00],
        &[0xA0, 0x22],
        &[0xA3, 0x13],
        &[0x04, 0x0B],
        b"objectClass",
        &[0x04, 0x04],
        b"user",
        &[0xA2, 0x0B],
        &[0xA4, 0x09],
        &[0x04, 0x02],
        b"cn",
        &[0x30, 0x03],
        &[0x80, 0x01],
        b"a",
        &[0x30, 0x04],
        &[0x04, 0x02],
        b"cn",
    ]
    .concat();
    let value = LdapMessage {
        message_id: id(3),
        protocol_op: ProtocolOp::SearchRequest(SearchRequest {
            base_object: "dc=x".to_owned(),
            scope: Scope::WholeSubtree,
            deref_aliases: DerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::And(vec![
                Filter::EqualityMatch(AttributeValueAssertion {
                    attribute_desc: "objectClass".to_owned(),
                    assertion_value: b"user".to_vec(),
                }),
                Filter::Not(Box::new(Filter::Substrings(SubstringFilter {
                    r#type: "cn".to_owned(),
                    substrings: vec![Substring::Initial(b"a".to_vec())],
                }))),
            ]),
            attributes: vec!["cn".to_owned()],
        }),
        controls: None,
    };
    (bytes, value)
}

#[test]
fn search_with_nested_filter() {
    let (bytes, value) = search_vector();
    assert_eq!(bytes.len(), 70);
    assert_request_vector(&bytes, &value);
}

#[test]
fn start_tls_extended_request() {
    // Source: RFC 4511 §4.12, §4.14.1 ("requestName is 1.3.6.1.4.1.1466.20037,
    // and the requestValue field is always absent"), App. B — hand-derived.
    //   requestName [0] LDAPOID (22 octets)  80 16 ...  (implicit, primitive)
    //   ExtendedRequest [APPLICATION 23]     77 18   (24)
    //   messageID 1                          02 01 01
    //   LDAPMessage                          30 1D   (3 + 26 = 29)
    let bytes = [
        &[0x30, 0x1D][..],
        &[0x02, 0x01, 0x01],
        &[0x77, 0x18],
        &[0x80, 0x16],
        b"1.3.6.1.4.1.1466.20037",
    ]
    .concat();
    let request = ExtendedRequest {
        request_name: START_TLS_OID.to_owned(),
        request_value: None,
    };
    assert!(request.is_start_tls());
    let value = LdapMessage {
        message_id: id(1),
        protocol_op: ProtocolOp::ExtendedRequest(request),
        controls: None,
    };
    assert_request_vector(&bytes, &value);
}

#[test]
fn abandon_request() {
    // Source: RFC 4511 §4.11 ("AbandonRequest ::= [APPLICATION 16] MessageID")
    // — hand-derived: implicit tag on INTEGER, so primitive (X.690 8.14.4 a)).
    //   AbandonRequest, MessageID 3          50 01 03
    //   messageID 5                          02 01 05
    //   LDAPMessage                          30 06
    let bytes = [0x30, 0x06, 0x02, 0x01, 0x05, 0x50, 0x01, 0x03];
    let value = LdapMessage {
        message_id: id(5),
        protocol_op: ProtocolOp::AbandonRequest(id(3)),
        controls: None,
    };
    assert_request_vector(&bytes, &value);
}

#[test]
fn unbind_request() {
    // Source: RFC 4511 §4.3 ("UnbindRequest ::= [APPLICATION 2] NULL") —
    // hand-derived: implicit tag on NULL, primitive with no contents (X.690
    // 8.8, 8.14.4 a)).
    //   UnbindRequest                        42 00
    //   messageID 6                          02 01 06
    //   LDAPMessage                          30 05
    let bytes = [0x30, 0x05, 0x02, 0x01, 0x06, 0x42, 0x00];
    let value = LdapMessage {
        message_id: id(6),
        protocol_op: ProtocolOp::UnbindRequest,
        controls: None,
    };
    assert_request_vector(&bytes, &value);
}

#[test]
fn abandon_with_critical_control() {
    // Source: RFC 4511 §4.1.1, §4.1.11, §5.1 — hand-derived. The control type
    // "1.2.3" is an arbitrary dotted-decimal string.
    //   controlType "1.2.3"                  04 05 31 2E 32 2E 33
    //   criticality TRUE (FF, §5.1)          01 01 FF
    //   controlValue AB CD                   04 02 AB CD
    //   Control SEQUENCE                     30 0E   (7 + 3 + 4 = 14)
    //   controls [0] Controls (constructed)  A0 10   (16)
    //   messageID 7, AbandonRequest 3        02 01 07 50 01 03
    //   LDAPMessage                          30 18   (3 + 3 + 18 = 24)
    let bytes = [
        &[0x30, 0x18][..],
        &[0x02, 0x01, 0x07],
        &[0x50, 0x01, 0x03],
        &[0xA0, 0x10],
        &[0x30, 0x0E],
        &[0x04, 0x05],
        b"1.2.3",
        &[0x01, 0x01, 0xFF],
        &[0x04, 0x02, 0xAB, 0xCD],
    ]
    .concat();
    let value = LdapMessage {
        message_id: id(7),
        protocol_op: ProtocolOp::AbandonRequest(id(3)),
        controls: Some(vec![Control {
            control_type: "1.2.3".to_owned(),
            criticality: true,
            control_value: Some(vec![0xAB, 0xCD]),
        }]),
    };
    assert_request_vector(&bytes, &value);
}

#[test]
fn bind_response_success() {
    // Source: RFC 4511 §4.1.9, §4.2.2 — hand-derived.
    //   resultCode success (0)               0A 01 00
    //   matchedDN "", diagnosticMessage ""   04 00 04 00
    //   BindResponse [APPLICATION 1]         61 07
    //   messageID 1                          02 01 01
    //   LDAPMessage                          30 0C
    let bytes = [
        0x30, 0x0C, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
    ];
    let value = LdapMessage {
        message_id: id(1),
        protocol_op: ProtocolOp::BindResponse(BindResponse {
            result: LdapResult::new(ResultCode::Success),
            server_sasl_creds: None,
        }),
        controls: None,
    };
    assert_response_vector(&bytes, &value);
}

#[test]
fn search_result_entry_and_done() {
    // Source: RFC 4511 §4.5.2, §4.1.7 — hand-derived.
    //   vals SET OF { "x" }                  31 03 04 01 78
    //   PartialAttribute { "cn", vals }      30 09 04 02 63 6E 31 03 ...
    //   PartialAttributeList                 30 0B
    //   objectName "dc=x"                    04 04 64 63 3D 78
    //   SearchResultEntry [APPLICATION 4]    64 13   (6 + 13 = 19)
    //   messageID 3                          02 01 03
    //   LDAPMessage                          30 18   (3 + 21 = 24)
    let entry = [
        &[0x30, 0x18][..],
        &[0x02, 0x01, 0x03],
        &[0x64, 0x13],
        &[0x04, 0x04],
        b"dc=x",
        &[0x30, 0x0B],
        &[0x30, 0x09],
        &[0x04, 0x02],
        b"cn",
        &[0x31, 0x03, 0x04, 0x01],
        b"x",
    ]
    .concat();
    let entry_value = LdapMessage {
        message_id: id(3),
        protocol_op: ProtocolOp::SearchResultEntry(SearchResultEntry {
            object_name: "dc=x".to_owned(),
            attributes: vec![PartialAttribute {
                r#type: "cn".to_owned(),
                vals: vec![b"x".to_vec()],
            }],
        }),
        controls: None,
    };
    assert_response_vector(&entry, &entry_value);

    // SearchResultDone [APPLICATION 5] LDAPResult, success: 65 07 0A 01 00
    // 04 00 04 00, inside messageID 3.
    let done = [
        0x30, 0x0C, 0x02, 0x01, 0x03, 0x65, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
    ];
    let done_value = LdapMessage {
        message_id: id(3),
        protocol_op: ProtocolOp::SearchResultDone(LdapResult::new(ResultCode::Success)),
        controls: None,
    };
    assert_response_vector(&done, &done_value);
}

#[test]
fn notice_of_disconnection() {
    // Source: RFC 4511 §4.4, §4.4.1 (messageID zero; responseName
    // 1.3.6.1.4.1.1466.20036; responseValue absent) — hand-derived.
    //   resultCode protocolError (2)         0A 01 02
    //   matchedDN "", diagnosticMessage ""   04 00 04 00
    //   responseName [10] (22 octets)        8A 16 ...   (implicit, primitive)
    //   ExtendedResponse [APPLICATION 24]    78 1F   (3 + 2 + 2 + 24 = 31)
    //   messageID 0                          02 01 00
    //   LDAPMessage                          30 24   (3 + 33 = 36)
    let bytes = [
        &[0x30, 0x24][..],
        &[0x02, 0x01, 0x00],
        &[0x78, 0x1F],
        &[0x0A, 0x01, 0x02],
        &[0x04, 0x00, 0x04, 0x00],
        &[0x8A, 0x16],
        b"1.3.6.1.4.1.1466.20036",
    ]
    .concat();
    let value = LdapMessage::notice_of_disconnection(ResultCode::ProtocolError);
    assert_response_vector(&bytes, &value);
}

/// Source: [MS-ADTS] v20261026 6.3.3, "Network payload" — verbatim. It is the
/// `filter` and `attributes` of a rootDSE SearchRequest (an LDAP ping): an
/// `and` of six equalityMatch items, every length in the four-octet long form,
/// then the AttributeSelection `"netlogon"`.
const MS_ADTS_6_3_3_PAYLOAD: &[u8] = &[
    0xA0, 0x84, 0x00, 0x00, 0x00, 0xA8, 0xA3, 0x84, 0x00, 0x00, 0x00, 0x25, 0x04, 0x09, 0x44, 0x6E,
    0x73, 0x44, 0x6F, 0x6D, 0x61, 0x69, 0x6E, 0x04, 0x18, 0x61, 0x62, 0x63, 0x64, 0x65, 0x2E, 0x63,
    0x6F, 0x72, 0x70, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x2E, 0x63, 0x6F,
    0x6D, 0xA3, 0x84, 0x00, 0x00, 0x00, 0x14, 0x04, 0x04, 0x48, 0x6F, 0x73, 0x74, 0x04, 0x0C, 0x61,
    0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x2D, 0x64, 0x65, 0x76, 0xA3, 0x84, 0x00, 0x00, 0x00,
    0x15, 0x04, 0x04, 0x55, 0x73, 0x65, 0x72, 0x04, 0x0D, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x2D, 0x64, 0x65, 0x76, 0x24, 0xA3, 0x84, 0x00, 0x00, 0x00, 0x0B, 0x04, 0x03, 0x41, 0x41,
    0x43, 0x04, 0x04, 0x80, 0x00, 0x00, 0x00, 0xA3, 0x84, 0x00, 0x00, 0x00, 0x1E, 0x04, 0x0A, 0x44,
    0x6F, 0x6D, 0x61, 0x69, 0x6E, 0x47, 0x75, 0x69, 0x64, 0x04, 0x10, 0x3B, 0xB0, 0x21, 0xCA, 0xD3,
    0x6D, 0xD1, 0x11, 0x8A, 0x7D, 0xB8, 0xDF, 0xB1, 0x56, 0x87, 0x1F, 0xA3, 0x84, 0x00, 0x00, 0x00,
    0x0D, 0x04, 0x05, 0x4E, 0x74, 0x56, 0x65, 0x72, 0x04, 0x04, 0x06, 0x00, 0x00, 0x00, 0x30, 0x84,
    0x00, 0x00, 0x00, 0x0A, 0x04, 0x08, 0x6E, 0x65, 0x74, 0x6C, 0x6F, 0x67, 0x6F, 0x6E,
];

/// The 6.3.3 payload inside a hand-derived SearchRequest envelope.
fn ms_adts_ping_message() -> Vec<u8> {
    // Envelope hand-derived from RFC 4511 §4.5.1 (the payload supplies filter
    // and attributes):
    //   baseObject "" (rootDSE)              04 00
    //   scope baseObject, derefAliases never 0A 01 00 0A 01 00
    //   sizeLimit 0, timeLimit 0             02 01 00 02 01 00
    //   typesOnly FALSE                      01 01 00
    //   SearchRequest                        63 81 CF   (17 + 190 = 207)
    //   messageID 1                          02 01 01
    //   LDAPMessage                          30 81 D5   (3 + 3 + 207 = 213)
    assert_eq!(MS_ADTS_6_3_3_PAYLOAD.len(), 190);
    [
        &[0x30, 0x81, 0xD5][..],
        &[0x02, 0x01, 0x01],
        &[0x63, 0x81, 0xCF],
        &[0x04, 0x00],
        &[0x0A, 0x01, 0x00, 0x0A, 0x01, 0x00],
        &[0x02, 0x01, 0x00, 0x02, 0x01, 0x00],
        &[0x01, 0x01, 0x00],
        MS_ADTS_6_3_3_PAYLOAD,
    ]
    .concat()
}

#[test]
fn ms_adts_6_3_3_ldap_ping_decodes() {
    let bytes = ms_adts_ping_message();
    assert_eq!(bytes.len(), 216);
    let decoded = decode_message(&bytes, &wire_request()).unwrap();
    let eq = |name: &str, value: &[u8]| {
        Filter::EqualityMatch(AttributeValueAssertion {
            attribute_desc: name.to_owned(),
            assertion_value: value.to_vec(),
        })
    };
    let expected = LdapMessage {
        message_id: id(1),
        protocol_op: ProtocolOp::SearchRequest(SearchRequest {
            base_object: String::new(),
            scope: Scope::BaseObject,
            deref_aliases: DerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::And(vec![
                eq("DnsDomain", b"abcde.corp.microsoft.com"),
                eq("Host", b"abcdefgh-dev"),
                eq("User", b"abcdefgh-dev$"),
                eq("AAC", &[0x80, 0x00, 0x00, 0x00]),
                eq(
                    "DomainGuid",
                    &[
                        0x3B, 0xB0, 0x21, 0xCA, 0xD3, 0x6D, 0xD1, 0x11, 0x8A, 0x7D, 0xB8, 0xDF,
                        0xB1, 0x56, 0x87, 0x1F,
                    ],
                ),
                eq("NtVer", &[0x06, 0x00, 0x00, 0x00]),
            ]),
            attributes: vec!["netlogon".to_owned()],
        }),
        controls: None,
    };
    assert_eq!(decoded, expected);

    // The canonical profile refuses the non-minimal lengths (X.690 10.1) ...
    assert_eq!(
        decode_message(&bytes, &canonical_request()),
        Err(parse_ldap::Error::NonMinimalLength)
    );
    // ... and the canonical re-encoding replaces each `84 00 00 00 nn` by the
    // short form (24 octets saved in the six items, 4 in the selection, the
    // `and` length becomes `81 90`), decoding canonically to the same value.
    let canonical = encode_message(&decoded).unwrap();
    assert_eq!(canonical.len(), 185);
    assert_eq!(&canonical[..3], &[0x30, 0x81, 0xB6]);
    assert_eq!(
        decode_message(&canonical, &canonical_request()).unwrap(),
        expected
    );
    assert_truncations_rejected(&bytes, &wire_request());
}
