//! The certificate reader against RFC 5280 §4.1 structures built in-test
//! (tests/common/build.rs) — the profile rules one by one, the DER rules on
//! the framing, the bounds.
//!
//! The reader interprets no algorithm, so these tests use one opaque
//! algorithm identifier throughout: the object identifier `{2 999 3}` of the
//! X.690 8.19 EXAMPLE, with no parameters. The public-key and signature
//! octets are arbitrary (no signature is verified here). Real ECDSA
//! certificates signed with real keys are built and checked in
//! crates/ldap-front's tests.
//!
//! Sources: RFC 5280 §4.1, §4.1.1.2, §4.1.1.3, §4.1.2.1-§4.1.2.9, §4.2,
//! §4.2.1.6, §4.2.1.9, A.1, A.2; X.690 8.1.3, 8.6.2, 8.14, 10.1, 11.5-11.8;
//! hand-derived instants in crates/parse-x509 src/time.rs. Every value is
//! made here.

#[path = "common/build.rs"]
mod build;

use build::*;
use parse_x509::{
    parse_certificate, Error, Field, MAX_CERTIFICATE_OCTETS, MAX_EXTENSIONS, MAX_NAME_RDNS,
};

/// The opaque algorithm: AlgorithmIdentifier contents = the OID {2 999 3}
/// (X.690 8.19 EXAMPLE), no parameters.
fn algorithm() -> Vec<u8> {
    oid(&[2, 999, 3])
}

/// 2025-01-01T00:00:00Z (hand-derived in src/time.rs).
const JAN_2025: i64 = 1_735_689_600;

fn base_tbs() -> Tbs {
    Tbs {
        version: Some(version_v3()),
        serial_number: integer(1),
        signature: algorithm_identifier(&algorithm()),
        issuer: name("Test CA"),
        validity: validity(
            utc_time("250101000000Z"),
            generalized_time("99991231235959Z"),
        ),
        subject: name("dc1.example.org"),
        subject_public_key_info: subject_public_key_info(&algorithm(), &[0x04, 1, 2, 3]),
        unique_ids: Vec::new(),
        extensions: Some(extensions(&[
            extension(
                &ID_CE_SUBJECT_ALT_NAME,
                false,
                &subject_alt_name_dns(&["dc1.example.org"]),
            ),
            extension(&ID_CE_BASIC_CONSTRAINTS, true, &basic_constraints_ca()),
        ])),
    }
}

fn build(tbs: &Tbs) -> Vec<u8> {
    certificate(
        &tbs.encode(),
        &algorithm_identifier(&algorithm()),
        &[9, 8, 7],
    )
}

fn with(mutate: impl FnOnce(&mut Tbs)) -> Vec<u8> {
    let mut tbs = base_tbs();
    mutate(&mut tbs);
    build(&tbs)
}

fn refused(input: &[u8]) -> Error {
    parse_certificate(input).expect_err("refused")
}

/// RFC 5280 4.1, 4.1.1.1-4.1.1.3, 4.1.2.1-4.1.2.9: every field of a
/// well-formed v3 certificate is returned where §4.1 puts it.
#[test]
fn a_v3_certificate_is_read_field_by_field() {
    let tbs = base_tbs();
    let tbs_der = tbs.encode();
    let der = build(&tbs);
    let parsed = parse_certificate(&der).unwrap();
    assert_eq!(parsed.encoding, der.as_slice());
    let t = &parsed.tbs_certificate;
    assert_eq!(t.encoding, tbs_der.as_slice(), "the signed octets");
    assert_eq!(t.serial_number, &[1]);
    assert_eq!(t.signature.contents, algorithm().as_slice());
    assert_eq!(t.signature.algorithm, algorithm().as_slice());
    assert_eq!(t.signature.parameters, None);
    assert_eq!(
        t.signature.encoding,
        algorithm_identifier(&algorithm()).as_slice()
    );
    assert_eq!(t.issuer, name("Test CA").as_slice());
    assert_eq!(t.subject, name("dc1.example.org").as_slice());
    assert_eq!(t.validity.not_before.unix_seconds(), JAN_2025);
    assert!(t.validity.not_after > t.validity.not_before);
    let spki = &t.subject_public_key_info;
    assert_eq!(spki.algorithm.contents, algorithm().as_slice());
    assert_eq!(spki.subject_public_key, &[0x04, 1, 2, 3]);
    assert_eq!(
        spki.encoding,
        subject_public_key_info(&algorithm(), &[0x04, 1, 2, 3]).as_slice()
    );
    assert_eq!(t.extensions.len(), 2);
    assert_eq!(
        t.extensions[0].extn_id,
        oid(&ID_CE_SUBJECT_ALT_NAME).as_slice()
    );
    assert!(!t.extensions[0].critical);
    assert_eq!(
        t.extensions[0].extn_value,
        subject_alt_name_dns(&["dc1.example.org"]).as_slice()
    );
    assert!(t.extensions[1].critical);
    assert_eq!(parsed.signature_algorithm.encoding, t.signature.encoding);
    assert_eq!(parsed.signature_value, &[9, 8, 7]);
}

/// RFC 5280 4.1.1.2 (`parameters ANY … OPTIONAL`): a parameters element is
/// kept as octets; RFC 5280 4.1.2.9 (extensions OPTIONAL): none is fine;
/// 4.1.2.6: an empty subject is fine.
#[test]
fn optional_parts() {
    let with_parameters = [algorithm(), octet_string(b"p")].concat();
    let der = with(|t| {
        t.signature = algorithm_identifier(&with_parameters);
        t.extensions = None;
        t.subject = empty_name();
    });
    let parsed = parse_certificate(&der).unwrap();
    let t = &parsed.tbs_certificate;
    assert_eq!(t.signature.parameters, Some(octet_string(b"p").as_slice()));
    assert_eq!(t.signature.contents, with_parameters.as_slice());
    assert!(t.extensions.is_empty());
    assert_eq!(t.subject, empty_name().as_slice());
}

/// RFC 5280 4.1 (`version [0] EXPLICIT Version DEFAULT v1`), 4.1.2.1: v3
/// only — absent (v1), v2, an explicit v1, and a [0] with two INTEGERs are
/// refused.
#[test]
fn only_version_3() {
    assert_eq!(refused(&with(|t| t.version = None)), Error::VersionNotV3);
    assert_eq!(
        refused(&with(|t| t.version = Some(explicit(0, &integer(1))))),
        Error::VersionNotV3
    );
    assert_eq!(
        refused(&with(|t| t.version = Some(explicit(0, &integer(0))))),
        Error::VersionNotV3
    );
    assert_eq!(
        refused(&with(
            |t| t.version = Some(explicit(0, &[integer(2), integer(2)].concat()))
        )),
        Error::TrailingData(Field::Version)
    );
}

/// RFC 5280 4.1.2.2 (at most 20 octets); X.690 8.3.2 (minimal INTEGER).
#[test]
fn serial_number_rules() {
    let twenty = element(parse_asn1::TagClass::Universal, false, 2, &[0x7F; 20]);
    assert!(parse_certificate(&with(|t| t.serial_number = twenty)).is_ok());
    let twenty_one = element(parse_asn1::TagClass::Universal, false, 2, &[0x7F; 21]);
    assert_eq!(
        refused(&with(|t| t.serial_number = twenty_one)),
        Error::SerialNumberTooLong
    );
    let padded = element(parse_asn1::TagClass::Universal, false, 2, &[0x00, 0x01]);
    assert_eq!(
        refused(&with(|t| t.serial_number = padded)),
        Error::Der(Field::SerialNumber, parse_asn1::Error::NonMinimalInteger)
    );
}

/// RFC 5280 4.1.2.4 (non-empty issuer; RDNSequence of SET SIZE (1..MAX) OF
/// AttributeTypeAndValue); X.690 11.6 (SET OF order).
#[test]
fn name_rules() {
    assert_eq!(
        refused(&with(|t| t.issuer = empty_name())),
        Error::EmptyIssuer
    );
    // An empty RDN.
    assert_eq!(
        refused(&with(|t| t.issuer = sequence(&[set_of(&[])]))),
        Error::MalformedName(Field::Issuer)
    );
    // An RDN that is a SEQUENCE, not a SET.
    let not_a_set = sequence(&[sequence(&[sequence(&[
        oid(&ID_AT_COMMON_NAME),
        utf8_string("x"),
    ])])]);
    assert_eq!(
        refused(&with(|t| t.subject = not_a_set)),
        Error::MalformedName(Field::Subject)
    );
    // Two attributes in one RDN, in X.690 11.6 order and reversed.
    let a = sequence(&[oid(&ID_AT_COMMON_NAME), utf8_string("a")]);
    let b = sequence(&[oid(&ID_AT_COMMON_NAME), utf8_string("b")]);
    let ordered = sequence(&[set_of(&[a.clone(), b.clone()])]);
    assert!(parse_certificate(&with(|t| t.subject = ordered)).is_ok());
    let reversed = sequence(&[set_of(&[b, a])]);
    assert_eq!(
        refused(&with(|t| t.subject = reversed)),
        Error::MalformedName(Field::Subject)
    );
    // An AttributeTypeAndValue with a third component, and one whose type
    // is not an OBJECT IDENTIFIER.
    let three = sequence(&[set_of(&[sequence(&[
        oid(&ID_AT_COMMON_NAME),
        utf8_string("x"),
        utf8_string("y"),
    ])])]);
    assert_eq!(
        refused(&with(|t| t.subject = three)),
        Error::MalformedName(Field::Subject)
    );
    let typeless = sequence(&[set_of(&[sequence(&[integer(3), utf8_string("x")])])]);
    assert_eq!(
        refused(&with(|t| t.subject = typeless)),
        Error::MalformedName(Field::Subject)
    );
    // The RDN bound.
    let rdn = set_of(&[sequence(&[oid(&ID_AT_COMMON_NAME), utf8_string("x")])]);
    let long = sequence(&vec![rdn; MAX_NAME_RDNS + 1]);
    assert_eq!(
        refused(&with(|t| t.subject = long)),
        Error::TooManyComponents(Field::Subject)
    );
}

/// RFC 5280 4.1.2.5, 4.1.2.5.1, 4.1.2.5.2; X.690 11.7, 11.8, 10.2.
#[test]
fn time_rules() {
    let validity_with = |nb: Vec<u8>, na: Vec<u8>| with(|t| t.validity = validity(nb, na));
    let far = || generalized_time("99991231235959Z");
    // UTCTime without seconds.
    assert_eq!(
        refused(&validity_with(utc_time("2501010000Z"), far())),
        Error::InvalidTime(Field::NotBefore)
    );
    // GeneralizedTime before 2050 (RFC 5280 4.1.2.5).
    assert_eq!(
        refused(&validity_with(
            utc_time("250101000000Z"),
            generalized_time("20491231235959Z")
        )),
        Error::InvalidTime(Field::NotAfter)
    );
    // GeneralizedTime with a fraction: DER-valid (X.690 11.7.3) but outside
    // RFC 5280 4.1.2.5.2.
    assert_eq!(
        refused(&validity_with(
            utc_time("250101000000Z"),
            generalized_time("20500101000000.5Z")
        )),
        Error::InvalidTime(Field::NotAfter)
    );
    // GeneralizedTime with a trailing zero in the fraction: not DER.
    assert_eq!(
        refused(&validity_with(
            utc_time("250101000000Z"),
            generalized_time("20500101000000.50Z")
        )),
        Error::Der(Field::NotAfter, parse_asn1::Error::InvalidGeneralizedTime)
    );
    // A Time that is an OCTET STRING, and a constructed UTCTime.
    assert_eq!(
        refused(&validity_with(octet_string(b"250101000000Z"), far())),
        Error::UnexpectedElement(Field::NotBefore)
    );
    let constructed = element(
        parse_asn1::TagClass::Universal,
        true,
        23,
        &utc_time("250101000000Z"),
    );
    assert_eq!(
        refused(&validity_with(constructed, far())),
        Error::UnexpectedElement(Field::NotBefore)
    );
    // A third Time.
    assert_eq!(
        refused(&with(
            |t| t.validity = sequence(&[utc_time("250101000000Z"), far(), far()])
        )),
        Error::TrailingData(Field::Validity)
    );
}

/// RFC 5280 4.1.2.5 ("from notBefore through notAfter, inclusive").
#[test]
fn validity_is_inclusive() {
    let der = with(|t| {
        t.validity = validity(utc_time("250101000000Z"), utc_time("250101000010Z"));
    });
    let parsed = parse_certificate(&der).unwrap();
    let v = parsed.tbs_certificate.validity;
    assert!(!v.contains(JAN_2025 - 1));
    assert!(v.contains(JAN_2025));
    assert!(v.contains(JAN_2025 + 10));
    assert!(!v.contains(JAN_2025 + 11));
}

/// RFC 5280 4.1, 4.1.1.3, 4.1.2.7 (project profile: whole octets); X.690
/// 11.2.1.
#[test]
fn bit_strings_carry_whole_octets() {
    let partial_key = sequence(&[algorithm_identifier(&algorithm()), bit_string(1, &[0x02])]);
    assert_eq!(
        refused(&with(|t| t.subject_public_key_info = partial_key)),
        Error::PartialOctet(Field::SubjectPublicKey)
    );
    let tbs = base_tbs().encode();
    let partial_signature = sequence(&[
        tbs,
        algorithm_identifier(&algorithm()),
        bit_string(4, &[0xF0]),
    ]);
    assert_eq!(
        refused(&partial_signature),
        Error::PartialOctet(Field::SignatureValue)
    );
}

/// RFC 5280 4.1 (`SEQUENCE SIZE (1..MAX) OF Extension`, `critical BOOLEAN
/// DEFAULT FALSE`, `extnValue OCTET STRING`), 4.2 (no extension twice);
/// X.690 11.5 (a default value is not encoded).
#[test]
fn extension_rules() {
    assert_eq!(
        refused(&with(|t| t.extensions = Some(extensions(&[])))),
        Error::EmptyExtensions
    );
    let san = extension(
        &ID_CE_SUBJECT_ALT_NAME,
        false,
        &subject_alt_name_dns(&["a"]),
    );
    assert_eq!(
        refused(&with(
            |t| t.extensions = Some(extensions(&[san.clone(), san.clone()]))
        )),
        Error::DuplicateExtension
    );
    let explicit_false = sequence(&[
        oid(&ID_CE_KEY_USAGE),
        boolean(false),
        octet_string(&key_usage_digital_signature()),
    ]);
    assert_eq!(
        refused(&with(|t| t.extensions = Some(extensions(&[explicit_false])))),
        Error::DefaultEncoded
    );
    let value_not_octets = sequence(&[oid(&ID_CE_KEY_USAGE), key_usage_digital_signature()]);
    assert_eq!(
        refused(&with(
            |t| t.extensions = Some(extensions(&[value_not_octets]))
        )),
        Error::UnexpectedElement(Field::Extension)
    );
    let many: Vec<Vec<u8>> = (0..=MAX_EXTENSIONS as u64)
        .map(|n| extension(&[2, 999, 3, n], false, &[0x05, 0x00]))
        .collect();
    assert_eq!(
        refused(&with(|t| t.extensions = Some(extensions(&many)))),
        Error::TooManyComponents(Field::Extensions)
    );
    // Two SEQUENCEs inside the explicit [3] (X.690 8.14.3).
    let once = sequence(std::slice::from_ref(&san));
    let doubled = explicit(3, &[once.clone(), once].concat());
    assert_eq!(
        refused(&with(|t| t.extensions = Some(doubled))),
        Error::TrailingData(Field::Extensions)
    );
}

/// RFC 5280 4.1 (`[1] IMPLICIT UniqueIdentifier`, `[2] …`, in that order),
/// 4.1.2.8 (parsed, not processed); X.690 8.6.2.2, 8.14.4.
#[test]
fn unique_identifiers() {
    let issuer_id = implicit(1, &[0x00, 0xAB]);
    let subject_id = implicit(2, &[0x00, 0xCD]);
    let ok = with(|t| t.unique_ids = vec![issuer_id.clone(), subject_id.clone()]);
    assert!(parse_certificate(&ok).is_ok());
    let bad_unused = implicit(1, &[0x08, 0xAB]);
    assert_eq!(
        refused(&with(|t| t.unique_ids = vec![bad_unused])),
        Error::Der(
            Field::IssuerUniqueId,
            parse_asn1::Error::BitStringUnusedBits
        )
    );
    // [2] before [1]: [1] is then an element §4.1 does not allow there.
    assert_eq!(
        refused(&with(|t| t.unique_ids = vec![subject_id, issuer_id])),
        Error::TrailingData(Field::TbsCertificate)
    );
}

/// RFC 5280 4.1 (three components, nothing after the Certificate); X.690
/// 8.1.3.6, 10.1 (definite, minimal lengths); the size bound; truncation.
#[test]
fn framing_rules() {
    let der = build(&base_tbs());
    // A trailing octet.
    let mut trailing = der.clone();
    trailing.push(0x00);
    assert_eq!(refused(&trailing), Error::TrailingData(Field::Certificate));
    // The same contents under a non-minimal long-form length (a leading
    // zero length octet) and under the indefinite form.
    let contents = parse_asn1::split_element(&der).unwrap().0.contents.to_vec();
    let length = u16::try_from(contents.len()).unwrap().to_be_bytes();
    let mut long_form = vec![0x30, 0x83, 0x00, length[0], length[1]];
    long_form.extend_from_slice(&contents);
    assert_eq!(
        refused(&long_form),
        Error::Der(Field::Certificate, parse_asn1::Error::NonMinimalLength)
    );
    let mut indefinite = vec![0x30, 0x80];
    indefinite.extend_from_slice(&contents);
    indefinite.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(
        refused(&indefinite),
        Error::Der(Field::Certificate, parse_asn1::Error::IndefiniteLength)
    );
    // Every proper prefix is refused (never a panic).
    for cut in 0..der.len() {
        assert!(parse_certificate(&der[..cut]).is_err(), "prefix {cut}");
    }
    // Over the bound, even before any octet is read.
    assert_eq!(
        refused(&vec![0x30; MAX_CERTIFICATE_OCTETS + 1]),
        Error::TooLarge
    );
    // Not a SEQUENCE; a fourth component; a missing signatureValue.
    assert_eq!(
        refused(&octet_string(&der)),
        Error::UnexpectedElement(Field::Certificate)
    );
    let tbs = base_tbs().encode();
    let alg = algorithm_identifier(&algorithm());
    let four = sequence(&[tbs.clone(), alg.clone(), bit_string(0, &[1]), integer(0)]);
    assert_eq!(refused(&four), Error::TrailingData(Field::Certificate));
    let two = sequence(&[tbs, alg]);
    assert_eq!(
        refused(&two),
        Error::UnexpectedElement(Field::SignatureValue)
    );
    // An AlgorithmIdentifier with three components.
    let three = algorithm_identifier(&[algorithm(), integer(1), integer(2)].concat());
    assert_eq!(
        refused(&with(|t| t.signature = three)),
        Error::TrailingData(Field::Signature)
    );
}
