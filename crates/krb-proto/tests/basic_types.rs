//! Basic types (RFC 4120 5.2): hand-derived DER vectors, round trips, and
//! rejection of every constraint violation.
//!
//! Each test names the clause its vector was derived from. Encodings follow
//! ITU-T X.690 (02/2021); structure follows the RFC 4120 Appendix A module.
//! No vector comes from any other implementation.

mod common;

use common::*;
use krb_proto::{
    limits, ApOptions, AuthorizationData, AuthorizationElement, Checksum, EncryptedData,
    EncryptionKey, Error, HostAddress, HostAddresses, KdcOptions, KerberosFlags, KerberosString,
    KerberosTime, KeyValue, Microseconds, PaData, PaEncTsEnc, PrincipalName, TicketFlags,
};

// ===========================================================================
// PrincipalName — RFC 4120 5.2.2
// ===========================================================================

#[test]
fn principal_name_literal_vector() {
    // Source: RFC 4120 5.2.2 (PrincipalName ::= SEQUENCE { name-type [0]
    // Int32, name-string [1] SEQUENCE OF KerberosString }), 7.5.8
    // (KRB_NT_PRINCIPAL = 1); X.690 8.9, 8.10, 8.14.3. Hand-derived octet by
    // octet:
    //   30 0F                         SEQUENCE, 15 octets
    //      A0 03 02 01 01             [0] INTEGER 1
    //      A1 08 30 06 1B 04 "user"   [1] SEQUENCE OF { GeneralString "user" }
    let bytes = [
        0x30, 0x0F, 0xA0, 0x03, 0x02, 0x01, 0x01, 0xA1, 0x08, 0x30, 0x06, 0x1B, 0x04, b'u', b's',
        b'e', b'r',
    ];
    // The helper derivation agrees with the literal one.
    assert_eq!(pname_der(&[0x01], &["user"]), bytes);
    round_trip(
        &bytes,
        &pname(1, &["user"]),
        PrincipalName::decode,
        PrincipalName::encode,
    );
}

#[test]
fn principal_name_two_components() {
    // Source: RFC 4120 5.2.2, 6.2 / 7.3 (krbtgt/REALM, NT-SRV-INST = 2).
    round_trip(
        &pname_der(&[0x02], &["krbtgt", "EXAMPLE.ORG"]),
        &pname(2, &["krbtgt", "EXAMPLE.ORG"]),
        PrincipalName::decode,
        PrincipalName::encode,
    );
}

#[test]
fn principal_name_unregistered_name_type_preserved() {
    // Source: RFC 4120 5.2.2 (name-type is a hint) and 1.5.1 (preserve typed
    // holes). A negative / unassigned Int32 is carried unchanged: -2 = FE.
    round_trip(
        &pname_der(&[0xFE], &["x"]),
        &pname(-2, &["x"]),
        PrincipalName::decode,
        PrincipalName::encode,
    );
}

#[test]
fn principal_name_component_limit() {
    // Resource bound (limits::MAX_NAME_COMPONENTS) on RFC 4120 5.2.2
    // name-string: at the bound decodes, one over is rejected both ways.
    let at: Vec<&str> = vec!["a"; limits::MAX_NAME_COMPONENTS];
    let over: Vec<&str> = vec!["a"; limits::MAX_NAME_COMPONENTS + 1];
    assert!(PrincipalName::decode(&pname_der(&[0x01], &at)).is_ok());
    assert_eq!(
        PrincipalName::decode(&pname_der(&[0x01], &over)),
        Err(Error::TooManyElements)
    );
    assert_eq!(pname(1, &over).encode(), Err(Error::TooManyElements));
}

#[test]
fn principal_name_rejects_missing_field() {
    // RFC 4120 5.2.2: name-string [1] is not OPTIONAL (X.690 8.9.2).
    let bytes = seq(&[&ctx(0, &int(&[0x01]))]);
    assert_eq!(PrincipalName::decode(&bytes), Err(Error::MissingField));
    // name-type [0] is not OPTIONAL either.
    let bytes = seq(&[&ctx(1, &seq(&[&gstring(b"a")]))]);
    assert_eq!(PrincipalName::decode(&bytes), Err(Error::MissingField));
}

#[test]
fn principal_name_rejects_out_of_order_and_duplicate_fields() {
    // X.690 8.9.2/8.9.3: components appear once, in definition order.
    let name_type = ctx(0, &int(&[0x01]));
    let name_string = ctx(1, &seq(&[&gstring(b"a")]));
    assert_eq!(
        PrincipalName::decode(&seq(&[&name_string, &name_type])),
        Err(Error::FieldOutOfOrder)
    );
    assert_eq!(
        PrincipalName::decode(&seq(&[&name_type, &name_type, &name_string])),
        Err(Error::DuplicateField)
    );
}

#[test]
fn principal_name_rejects_unknown_field() {
    // RFC 4120 1.5 / 1.5.1 (no extension by adding fields), Appendix A (no
    // extension marker), 5.1.4: an undefined context tag [2] is an error.
    let bytes = seq(&[
        &ctx(0, &int(&[0x01])),
        &ctx(1, &seq(&[&gstring(b"a")])),
        &ctx(2, &int(&[0x00])),
    ]);
    assert_eq!(PrincipalName::decode(&bytes), Err(Error::UnknownField));
}

#[test]
fn rejects_unknown_high_tag_number_field() {
    // RFC 4120 5.1.5: tag numbers > 30 (X.690 8.1.2.4 high-tag-number form,
    // here [31] = BF 1F) are answered with an error, not a crash.
    let mut unknown = vec![0xBF, 0x1F];
    let inner = int(&[0x00]);
    unknown.push(inner.len() as u8);
    unknown.extend_from_slice(&inner);
    let bytes = seq(&[
        &ctx(0, &int(&[0x01])),
        &ctx(1, &seq(&[&gstring(b"a")])),
        &unknown,
    ]);
    assert_eq!(PrincipalName::decode(&bytes), Err(Error::UnknownField));
}

#[test]
fn principal_name_rejects_non_context_component() {
    // RFC 4120 §5 "DEFINITIONS EXPLICIT TAGS": every component is [n]-tagged;
    // a bare INTEGER in the SEQUENCE is rejected.
    let bytes = seq(&[&int(&[0x01]), &ctx(1, &seq(&[&gstring(b"a")]))]);
    assert_eq!(
        PrincipalName::decode(&bytes),
        Err(Error::ExpectedContextTag)
    );
}

#[test]
fn principal_name_rejects_wrong_outer_type() {
    // RFC 4120 5.2.2: a PrincipalName is a universal SEQUENCE, not an
    // [APPLICATION n] value.
    let bytes = app(1, &pname_der(&[0x01], &["a"]));
    assert_eq!(PrincipalName::decode(&bytes), Err(Error::ExpectedSequence));
}

#[test]
fn principal_name_rejects_trailing_data() {
    // Strict framing (X.690 8.1; parse-asn1): nothing may follow the value.
    let mut bytes = pname_der(&[0x01], &["user"]);
    bytes.push(0x00);
    assert_eq!(
        PrincipalName::decode(&bytes),
        Err(Error::Der(parse_asn1::Error::TrailingData))
    );
}

#[test]
fn rejects_primitive_context_tag() {
    // RFC 4120 §5 EXPLICIT TAGS → X.690 8.14.3: an explicit tag is
    // constructed. A primitive [0] (0x80) is rejected by the DER layer.
    let bytes = seq(&[&tlv(0x80, &[0x01]), &ctx(1, &seq(&[&gstring(b"a")]))]);
    assert_eq!(
        PrincipalName::decode(&bytes),
        Err(Error::Der(parse_asn1::Error::PrimitiveConstructedMismatch))
    );
}

#[test]
fn rejects_input_over_size_bound() {
    // Resource bound limits::MAX_MESSAGE_LEN, checked before parsing.
    let bytes = vec![0u8; limits::MAX_MESSAGE_LEN + 1];
    assert_eq!(PrincipalName::decode(&bytes), Err(Error::MessageTooLarge));
}

// ===========================================================================
// KerberosString — RFC 4120 5.2.1
// ===========================================================================

#[test]
fn kerberos_string_rejects_non_ia5() {
    // RFC 4120 5.2.1: KerberosString ::= GeneralString (IA5String); octets
    // >= 0x80 are outside IA5String (X.680 Table 8). Leniency not taken.
    let bytes = pname_der(&[0x01], &["ok"]);
    let bad = {
        let strings = seq(&[&tlv(0x1B, &[b'a', 0xC3, 0xA9])]);
        seq(&[&ctx(0, &int(&[0x01])), &ctx(1, &strings)])
    };
    assert!(PrincipalName::decode(&bytes).is_ok());
    assert_eq!(PrincipalName::decode(&bad), Err(Error::NonIa5Character));
    assert_eq!(
        KerberosString::new("caf\u{e9}"),
        Err(Error::NonIa5Character)
    );
}

#[test]
fn kerberos_string_rejects_control_characters() {
    // RFC 4120 5.2.1 (control characters SHOULD NOT be used in names), 5.2.2
    // (realms shall not contain NUL): rejected everywhere (fail closed). Covers
    // NUL, LF, ESC (ISO 2022 designation) and DEL.
    for ctl in [0x00u8, 0x0A, 0x1B, 0x7F] {
        let strings = seq(&[&tlv(0x1B, &[b'a', ctl])]);
        let bad = seq(&[&ctx(0, &int(&[0x01])), &ctx(1, &strings)]);
        assert_eq!(PrincipalName::decode(&bad), Err(Error::ControlCharacter));
        assert_eq!(
            KerberosString::from_bytes(&[b'a', ctl]),
            Err(Error::ControlCharacter)
        );
    }
    // SPACE (0x20) and '~' (0x7E) are printable IA5 characters and accepted.
    assert!(KerberosString::new("a b~").is_ok());
}

#[test]
fn kerberos_string_rejects_wrong_universal_type() {
    // RFC 4120 5.2.1: GeneralString (UNIVERSAL 27). An OCTET STRING in its
    // place is rejected.
    let strings = seq(&[&octets(b"a")]);
    let bad = seq(&[&ctx(0, &int(&[0x01])), &ctx(1, &strings)]);
    assert_eq!(
        PrincipalName::decode(&bad),
        Err(Error::ExpectedGeneralString)
    );
}

// ===========================================================================
// KerberosTime — RFC 4120 5.2.3 (via PA-ENC-TS-ENC, RFC 4120 5.2.7.2)
// ===========================================================================

#[test]
fn kerberos_time_rfc_example_in_pa_enc_ts_enc() {
    // Source: RFC 4120 5.2.3 example "19851106210627Z" — "the only valid
    // format" for that instant — inside PA-ENC-TS-ENC (5.2.7.2):
    //   30 13                 SEQUENCE, 19 octets
    //      A0 11              [0]
    //         18 0F "19851106210627Z"   GeneralizedTime
    let mut bytes = vec![0x30, 0x13, 0xA0, 0x11, 0x18, 0x0F];
    bytes.extend_from_slice(b"19851106210627Z");
    let value = PaEncTsEnc {
        patimestamp: KerberosTime::new(1985, 11, 6, 21, 6, 27).unwrap(),
        pausec: None,
    };
    round_trip(&bytes, &value, PaEncTsEnc::decode, PaEncTsEnc::encode);
}

#[test]
fn pa_enc_ts_enc_with_pausec() {
    // Source: RFC 4120 5.2.7.2 (pausec [1] Microseconds OPTIONAL), 5.2.4.
    // 123456 = 0x01E240 → contents 01 E2 40 (X.690 8.3.2: leading octet 01
    // has its top bit clear, so it is already minimal).
    //   30 1A  A0 11 18 0F "20261113090000Z"  A1 05 02 03 01 E2 40
    let mut bytes = vec![0x30, 0x1A, 0xA0, 0x11, 0x18, 0x0F];
    bytes.extend_from_slice(b"20261113090000Z");
    bytes.extend_from_slice(&[0xA1, 0x05, 0x02, 0x03, 0x01, 0xE2, 0x40]);
    let value = PaEncTsEnc {
        patimestamp: ktime("20261113090000Z"),
        pausec: Some(Microseconds::new(123_456).unwrap()),
    };
    round_trip(&bytes, &value, PaEncTsEnc::decode, PaEncTsEnc::encode);
}

fn ts_enc(time: &[u8]) -> Vec<u8> {
    seq(&[&ctx(0, &gtime(time))])
}

#[test]
fn kerberos_time_rejects_fractional_seconds() {
    // RFC 4120 5.2.3: "shall not include any fractional portions of the
    // seconds". "…27.5Z" is valid DER GeneralizedTime (X.690 11.7.3) but not a
    // KerberosTime.
    assert_eq!(
        PaEncTsEnc::decode(&ts_enc(b"19851106210627.5Z")),
        Err(Error::FractionalKerberosTime)
    );
}

#[test]
fn kerberos_time_rejects_invalid_calendar_values() {
    // X.680 46.2/46.3 (calendar date; time of day excluding midnight at the
    // end of a day), X.690 11.7.5 (its "19920520240000Z" invalid example);
    // RFC 4120 5.2.3. Leap second 60: not defined by the allowed sources,
    // rejected (docs/questions/Q-030).
    for bad in [
        &b"19920520240000Z"[..], // hour 24 (X.690 11.7.5 invalid example)
        b"20261301000000Z",      // month 13
        b"20260001000000Z",      // month 00
        b"20260100000000Z",      // day 00
        b"20260431000000Z",      // 31 April
        b"20230229000000Z",      // 29 Feb, non-leap year
        b"19000229000000Z",      // 29 Feb 1900 (century, not /400)
        b"20261113236000Z",      // minute 60
        b"20261113235960Z",      // second 60
    ] {
        assert_eq!(
            PaEncTsEnc::decode(&ts_enc(bad)),
            Err(Error::InvalidKerberosTime),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    // Leap days that do exist decode (Gregorian rule).
    assert!(PaEncTsEnc::decode(&ts_enc(b"20240229000000Z")).is_ok());
    assert!(PaEncTsEnc::decode(&ts_enc(b"20000229235959Z")).is_ok());
    // X.690 11.7.5 valid midnight example.
    assert!(PaEncTsEnc::decode(&ts_enc(b"19920521000000Z")).is_ok());
    // Constructor applies the same rules.
    assert_eq!(
        KerberosTime::new(2023, 2, 29, 0, 0, 0),
        Err(Error::InvalidKerberosTime)
    );
}

#[test]
fn kerberos_time_rejects_non_utc_forms_at_der_layer() {
    // X.690 11.7.1: DER GeneralizedTime terminates with "Z" (no local time,
    // no offset) — rejected by parse-asn1 before reaching KerberosTime.
    assert_eq!(
        PaEncTsEnc::decode(&ts_enc(b"19851106210627")),
        Err(Error::Der(parse_asn1::Error::InvalidGeneralizedTime))
    );
}

#[test]
fn kerberos_time_ordering_is_chronological() {
    // RFC 4120 5.2.3 times compare chronologically.
    assert!(ktime("20261113090000Z") < ktime("20261113090001Z"));
    assert!(ktime("20251231235959Z") < ktime("20260101000000Z"));
}

#[test]
fn kerberos_time_rejects_wrong_type() {
    // RFC 4120 5.2.7.2: patimestamp is a KerberosTime (GeneralizedTime).
    let bytes = seq(&[&ctx(0, &gstring(b"19851106210627Z"))]);
    assert_eq!(
        PaEncTsEnc::decode(&bytes),
        Err(Error::ExpectedGeneralizedTime)
    );
}

// ===========================================================================
// Constrained integers — RFC 4120 5.2.4
// ===========================================================================

fn principal_with_type(contents: &[u8]) -> Vec<u8> {
    pname_der(contents, &["a"])
}

#[test]
fn int32_range() {
    // RFC 4120 5.2.4: Int32 ::= INTEGER (-2147483648..2147483647). Minimal
    // two's-complement contents (X.690 8.3.2):
    //   2147483647  = 7F FF FF FF        (accepted)
    //  -2147483648  = 80 00 00 00        (accepted)
    //   2147483648  = 00 80 00 00 00     (rejected)
    //  -2147483649  = FF 7F FF FF FF     (rejected)
    assert_eq!(
        PrincipalName::decode(&principal_with_type(&[0x7F, 0xFF, 0xFF, 0xFF]))
            .unwrap()
            .name_type,
        i32::MAX
    );
    assert_eq!(
        PrincipalName::decode(&principal_with_type(&[0x80, 0x00, 0x00, 0x00]))
            .unwrap()
            .name_type,
        i32::MIN
    );
    assert_eq!(
        PrincipalName::decode(&principal_with_type(&[0x00, 0x80, 0x00, 0x00, 0x00])),
        Err(Error::Int32OutOfRange)
    );
    assert_eq!(
        PrincipalName::decode(&principal_with_type(&[0xFF, 0x7F, 0xFF, 0xFF, 0xFF])),
        Err(Error::Int32OutOfRange)
    );
    // Wider than 64 bits (9 octets) is also out of range.
    assert_eq!(
        PrincipalName::decode(&principal_with_type(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0])),
        Err(Error::Int32OutOfRange)
    );
}

#[test]
fn int32_rejects_enumerated_and_other_types() {
    // RFC 4120 5.2.2: name-type is an INTEGER; ENUMERATED (UNIVERSAL 10 =
    // 0x0A, same contents) and OCTET STRING are other types.
    let enumerated = seq(&[
        &ctx(0, &tlv(0x0A, &[0x01])),
        &ctx(1, &seq(&[&gstring(b"a")])),
    ]);
    assert_eq!(
        PrincipalName::decode(&enumerated),
        Err(Error::ExpectedInteger)
    );
    let octet = seq(&[&ctx(0, &octets(&[0x01])), &ctx(1, &seq(&[&gstring(b"a")]))]);
    assert_eq!(PrincipalName::decode(&octet), Err(Error::ExpectedInteger));
}

fn enc_with_kvno(kvno_contents: &[u8]) -> Vec<u8> {
    enc_data_der(&[0x12], Some(kvno_contents), &[0xAA])
}

#[test]
fn uint32_range() {
    // RFC 4120 5.2.4: UInt32 ::= INTEGER (0..4294967295); EncryptedData kvno
    // [1] UInt32 (5.2.9).
    //   4294967295 = 00 FF FF FF FF      (accepted; leading 00 per X.690 8.3.2)
    //   4294967296 = 01 00 00 00 00      (rejected)
    //   -1         = FF                  (rejected; 5.5.1 leniency not taken)
    assert_eq!(
        EncryptedData::decode(&enc_with_kvno(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF]))
            .unwrap()
            .kvno,
        Some(u32::MAX)
    );
    assert_eq!(
        EncryptedData::decode(&enc_with_kvno(&[0x00])).unwrap().kvno,
        Some(0)
    );
    assert_eq!(
        EncryptedData::decode(&enc_with_kvno(&[0x01, 0x00, 0x00, 0x00, 0x00])),
        Err(Error::UInt32OutOfRange)
    );
    assert_eq!(
        EncryptedData::decode(&enc_with_kvno(&[0xFF])),
        Err(Error::UInt32OutOfRange)
    );
}

#[test]
fn microseconds_range() {
    // RFC 4120 5.2.4: Microseconds ::= INTEGER (0..999999); PA-ENC-TS-ENC
    // pausec (5.2.7.2).
    //   999999  = 0F 42 3F  (accepted)
    //   1000000 = 0F 42 40  (rejected)
    //   -1      = FF        (rejected)
    let with =
        |contents: &[u8]| seq(&[&ctx(0, &gtime(b"20261113090000Z")), &ctx(1, &int(contents))]);
    assert_eq!(
        PaEncTsEnc::decode(&with(&[0x0F, 0x42, 0x3F]))
            .unwrap()
            .pausec
            .map(Microseconds::get),
        Some(999_999)
    );
    assert_eq!(
        PaEncTsEnc::decode(&with(&[0x0F, 0x42, 0x40])),
        Err(Error::MicrosecondsOutOfRange)
    );
    assert_eq!(
        PaEncTsEnc::decode(&with(&[0xFF])),
        Err(Error::MicrosecondsOutOfRange)
    );
    assert_eq!(
        Microseconds::new(1_000_000),
        Err(Error::MicrosecondsOutOfRange)
    );
}

// ===========================================================================
// HostAddress(es) — RFC 4120 5.2.5
// ===========================================================================

#[test]
fn host_addresses_round_trip() {
    // Source: RFC 4120 5.2.5 (HostAddress ::= SEQUENCE { addr-type [0] Int32,
    // address [1] OCTET STRING }; HostAddresses ::= SEQUENCE OF HostAddress),
    // 7.5.3 (IPv4 = 2, IPv6 = 24 — used here only as sample Int32 values).
    let v4 = seq(&[&ctx(0, &int(&[0x02])), &ctx(1, &octets(&[192, 0, 2, 1]))]);
    let v6_addr: Vec<u8> = (0..16).collect();
    let v6 = seq(&[&ctx(0, &int(&[0x18])), &ctx(1, &octets(&v6_addr))]);
    let bytes = seq(&[&v4, &v6]);
    let value = HostAddresses(vec![
        HostAddress {
            addr_type: 2,
            address: vec![192, 0, 2, 1],
        },
        HostAddress {
            addr_type: 24,
            address: v6_addr.clone(),
        },
    ]);
    round_trip(&bytes, &value, HostAddresses::decode, HostAddresses::encode);
    round_trip(&v4, &value.0[0], HostAddress::decode, HostAddress::encode);
}

#[test]
fn host_addresses_empty_accepted_per_5_1_3() {
    // RFC 4120 5.1.3: an empty SEQUENCE OF "SHOULD" be accepted (as absent);
    // it is preserved so it re-encodes exactly. 30 00.
    round_trip(
        &[0x30, 0x00],
        &HostAddresses(vec![]),
        HostAddresses::decode,
        HostAddresses::encode,
    );
}

#[test]
fn host_addresses_limit() {
    // Resource bound limits::MAX_HOST_ADDRESSES.
    let one = seq(&[&ctx(0, &int(&[0x02])), &ctx(1, &octets(&[0; 4]))]);
    let many: Vec<&[u8]> = vec![one.as_slice(); limits::MAX_HOST_ADDRESSES + 1];
    assert_eq!(
        HostAddresses::decode(&seq(&many)),
        Err(Error::TooManyElements)
    );
}

// ===========================================================================
// AuthorizationData — RFC 4120 5.2.6
// ===========================================================================

#[test]
fn authorization_data_round_trip_with_nested_if_relevant() {
    // Source: RFC 4120 5.2.6 (AuthorizationData ::= SEQUENCE OF SEQUENCE {
    // ad-type [0] Int32, ad-data [1] OCTET STRING }), 5.2.6.1 (AD-IF-RELEVANT
    // ::= AuthorizationData, ad-type 1). Inner element uses a negative
    // (local-use, 5.2.6) ad-type -17 = EF.
    let inner = seq(&[seq(&[&ctx(0, &int(&[0xEF])), &ctx(1, &octets(&[1, 2, 3]))]).as_slice()]);
    let inner_value = AuthorizationData(vec![AuthorizationElement {
        ad_type: -17,
        ad_data: vec![1, 2, 3],
    }]);
    round_trip(
        &inner,
        &inner_value,
        AuthorizationData::decode,
        AuthorizationData::encode,
    );
    let outer = seq(&[seq(&[&ctx(0, &int(&[0x01])), &ctx(1, &octets(&inner))]).as_slice()]);
    let outer_value = AuthorizationData(vec![AuthorizationElement {
        ad_type: 1,
        ad_data: inner.clone(),
    }]);
    round_trip(
        &outer,
        &outer_value,
        AuthorizationData::decode,
        AuthorizationData::encode,
    );
    // The ad-data of the container decodes as AuthorizationData again.
    assert_eq!(
        AuthorizationData::decode(&outer_value.0[0].ad_data).unwrap(),
        inner_value
    );
}

#[test]
fn authorization_data_limit() {
    // Resource bound limits::MAX_AUTHORIZATION_ELEMENTS.
    let element = seq(&[&ctx(0, &int(&[0x01])), &ctx(1, &octets(&[]))]);
    let many: Vec<&[u8]> = vec![element.as_slice(); limits::MAX_AUTHORIZATION_ELEMENTS + 1];
    assert_eq!(
        AuthorizationData::decode(&seq(&many)),
        Err(Error::TooManyElements)
    );
}

// ===========================================================================
// PA-DATA — RFC 4120 5.2.7
// ===========================================================================

#[test]
fn pa_data_round_trip_and_unknown_type_preserved() {
    // Source: RFC 4120 5.2.7 (PA-DATA ::= SEQUENCE { padata-type [1] Int32,
    // padata-value [2] OCTET STRING } — "first tag is [1], not [0]").
    // padata-type 2 = PA-ENC-TIMESTAMP (7.5.2).
    let bytes = seq(&[&ctx(1, &int(&[0x02])), &ctx(2, &octets(&[0xDE, 0xAD]))]);
    let value = PaData {
        padata_type: 2,
        padata_value: vec![0xDE, 0xAD],
    };
    round_trip(&bytes, &value, PaData::decode, PaData::encode);
    // RFC 4120 1.5.1: an unknown padata-type (here 0x7FFF = 32767, contents
    // 7F FF) is a typed-hole extension — preserved, never rejected.
    let unknown = seq(&[&ctx(1, &int(&[0x7F, 0xFF])), &ctx(2, &octets(&[0x01]))]);
    round_trip(
        &unknown,
        &PaData {
            padata_type: 32767,
            padata_value: vec![0x01],
        },
        PaData::decode,
        PaData::encode,
    );
}

#[test]
fn pa_data_rejects_tag_zero() {
    // RFC 4120 5.2.7: PA-DATA defines tags [1] and [2] only; a [0] component
    // is not defined for the type.
    let bytes = seq(&[
        &ctx(0, &int(&[0x02])),
        &ctx(1, &int(&[0x02])),
        &ctx(2, &octets(&[])),
    ]);
    assert_eq!(PaData::decode(&bytes), Err(Error::UnknownField));
}

#[test]
fn pa_data_rejects_wrong_value_type() {
    // RFC 4120 5.2.7: padata-value is an OCTET STRING.
    let bytes = seq(&[&ctx(1, &int(&[0x02])), &ctx(2, &gstring(b"x"))]);
    assert_eq!(PaData::decode(&bytes), Err(Error::ExpectedOctetString));
}

// ===========================================================================
// KerberosFlags — RFC 4120 5.2.8 (via the KDCOptions / APOptions / TicketFlags
// uses; bit numbering X.680 22.4, X.690 8.6.2.1)
// ===========================================================================

#[test]
fn kerberos_flags_bit_numbering() {
    // X.690 8.6.2.1: bit 0 (the leading bit, X.680 22.2/22.4) is bit 8 of the
    // first content octet. RFC 4120 5.4.1: forwardable(1), renewable(8),
    // renewable-ok(27) → 0x40000000 | 0x00800000 | 0x00000010 = 40 80 00 10.
    let options = KdcOptions::FORWARDABLE
        .union(KdcOptions::RENEWABLE)
        .union(KdcOptions::RENEWABLE_OK);
    assert_eq!(options.0.bits(), 0x4080_0010);
    assert!(options.0.is_set(1) && options.0.is_set(8) && options.0.is_set(27));
    assert!(!options.0.is_set(0) && !options.0.is_set(31) && !options.0.is_set(32));
    // RFC 4120 5.4.1: validate(31) is the last bit, 00 00 00 01.
    assert_eq!(KdcOptions::VALIDATE.0.bits(), 0x0000_0001);
    // RFC 4120 5.5.1: mutual-required(2) → 20 00 00 00.
    assert_eq!(ApOptions::MUTUAL_REQUIRED.0.bits(), 0x2000_0000);
    // RFC 4120 5.3: ok-as-delegate(13) → 00 04 00 00.
    assert_eq!(TicketFlags::OK_AS_DELEGATE.0.bits(), 0x0004_0000);
    let mut flags = TicketFlags::empty();
    flags.insert(TicketFlags::INITIAL);
    assert!(flags.contains(TicketFlags::INITIAL));
    flags.remove(TicketFlags::INITIAL);
    assert_eq!(flags, TicketFlags::empty());
    assert_eq!(KerberosFlags::from_bits(7).bits(), 7);
}

// ===========================================================================
// EncryptedData / EncryptionKey / Checksum — RFC 4120 5.2.9
// ===========================================================================

#[test]
fn encrypted_data_with_and_without_kvno() {
    // Source: RFC 4120 5.2.9 (EncryptedData ::= SEQUENCE { etype [0] Int32,
    // kvno [1] UInt32 OPTIONAL, cipher [2] OCTET STRING }); etype 18 is
    // aes256-cts-hmac-sha1-96 (RFC 3962 §7).
    round_trip(
        &enc_data_der(&[0x12], Some(&[0x05]), &[1, 2, 3, 4]),
        &EncryptedData {
            etype: 18,
            kvno: Some(5),
            cipher: vec![1, 2, 3, 4],
        },
        EncryptedData::decode,
        EncryptedData::encode,
    );
    round_trip(
        &enc_data_der(&[0x11], None, &[]),
        &EncryptedData {
            etype: 17,
            kvno: None,
            cipher: vec![],
        },
        EncryptedData::decode,
        EncryptedData::encode,
    );
}

#[test]
fn encryption_key_literal_vector() {
    // Source: RFC 4120 5.2.9 (EncryptionKey ::= SEQUENCE { keytype [0] Int32,
    // keyvalue [1] OCTET STRING }); keytype 18 (RFC 3962 §7, 256-bit key →
    // 32 octets). Hand-derived:
    //   30 29                   SEQUENCE, 41 octets
    //      A0 03 02 01 12       [0] INTEGER 18
    //      A1 22 04 20 <32>     [1] OCTET STRING (32 octets 00..1F)
    let key: Vec<u8> = (0x00..0x20).collect();
    let mut bytes = vec![
        0x30, 0x29, 0xA0, 0x03, 0x02, 0x01, 0x12, 0xA1, 0x22, 0x04, 0x20,
    ];
    bytes.extend_from_slice(&key);
    let value = EncryptionKey {
        keytype: 18,
        keyvalue: KeyValue::from_slice(&key),
    };
    round_trip(&bytes, &value, EncryptionKey::decode, EncryptionKey::encode);
}

#[test]
fn checksum_round_trip() {
    // Source: RFC 4120 5.2.9 (Checksum ::= SEQUENCE { cksumtype [0] Int32,
    // checksum [1] OCTET STRING }); cksumtype 16 = hmac-sha1-96-aes256
    // (RFC 3962 §7, 96-bit → 12 octets).
    let sum: Vec<u8> = (0x30..0x3C).collect();
    let bytes = seq(&[&ctx(0, &int(&[0x10])), &ctx(1, &octets(&sum))]);
    round_trip(
        &bytes,
        &Checksum {
            cksumtype: 16,
            checksum: sum,
        },
        Checksum::decode,
        Checksum::encode,
    );
}
