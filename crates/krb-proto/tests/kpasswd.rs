//! KRB-PRIV / EncKrbPrivPart (RFC 4120 5.7.1) and the RFC 3244 §2
//! change-password user data: ChangePasswdData and the result data.
//!
//! RFC 3244 has no examples and RFC 4120 has no KRB-PRIV vectors, so every
//! vector here is built by hand from the ASN.1 in RFC 4120 5.7.1 / Appendix A
//! and RFC 3244 §2, one X.690 (02/2021) clause at a time (see
//! `common/mod.rs`; explicit tagging for ChangePasswdData per X.680 13.2,
//! 31.2.7 b) — docs/questions/Q-620). Field values (times, sequence numbers,
//! addresses, passwords) are arbitrary test data. No vector comes from any
//! other implementation.

mod common;

use common::*;
use krb_proto::{
    limits, ChangePasswdData, EncKrbPrivPart, EncryptedData, Error, HostAddress, KrbPriv,
    Microseconds, NewPasswd, NonZeroResultCode, PasswordRequest, ResultCode, UserData,
};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/// An arbitrary test password with a marker easy to spot in formatted output.
const PASSWORD: &[u8] = b"Marker-New-Pw-2026";

/// RFC 3244 §2 ChangePasswdData, change form: SEQUENCE { [0] OCTET STRING }.
fn cpd_change_der(newpasswd: &[u8]) -> Vec<u8> {
    seq(&[&ctx(0, &octets(newpasswd))])
}

/// The KRB-PRIV components, separately so tests can alter them.
/// RFC 4120 5.7.1: pvno [0] = 5, msg-type [1] = 21 (0x15), enc-part [3].
fn krb_priv_parts() -> Vec<Vec<u8>> {
    vec![
        ctx(0, &int(&[0x05])),
        ctx(1, &int(&[0x15])),
        ctx(3, &enc_data_der(&[0x12], None, &krb_priv_cipher())),
    ]
}

/// Arbitrary cipher octets (the codec never decrypts).
fn krb_priv_cipher() -> Vec<u8> {
    (0x40..0x60).collect()
}

fn krb_priv_from(parts: &[Vec<u8>]) -> Vec<u8> {
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    app(21, &seq(&refs))
}

/// The value of `krb_priv_from(&krb_priv_parts())`. Etype 18 is an arbitrary
/// Int32 here (the codec carries it raw).
fn krb_priv_value() -> KrbPriv {
    KrbPriv {
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: krb_priv_cipher(),
        },
    }
}

/// HostAddress DER (RFC 4120 5.2.5): SEQUENCE { [0] Int32, [1] OCTET STRING }.
fn host_address_der(addr_type: &[u8], address: &[u8]) -> Vec<u8> {
    seq(&[&ctx(0, &int(addr_type)), &ctx(1, &octets(address))])
}

/// A request-direction EncKrbPrivPart (RFC 3244 §2): user-data = the
/// ChangePasswdData DER; timestamp; usec 100000 (0x0186A0); seq-number
/// 0x3A5C0F21; s-address Directional (type 3) with address 0, "the party
/// sending the original KRB_AP_REQ" (RFC 4120 7.1). Components separately.
fn enc_part_request_parts() -> Vec<Vec<u8>> {
    vec![
        ctx(0, &octets(&cpd_change_der(PASSWORD))),
        ctx(1, &gtime(b"20261115120000Z")),
        ctx(2, &int(&[0x01, 0x86, 0xA0])),
        ctx(3, &int(&[0x3A, 0x5C, 0x0F, 0x21])),
        ctx(4, &host_address_der(&[0x03], &[0, 0, 0, 0])),
    ]
}

fn enc_part_from(parts: &[Vec<u8>]) -> Vec<u8> {
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    app(28, &seq(&refs))
}

fn enc_part_request_value() -> EncKrbPrivPart {
    EncKrbPrivPart {
        user_data: UserData::new(cpd_change_der(PASSWORD)),
        timestamp: Some(ktime("20261115120000Z")),
        usec: Some(Microseconds::new(100_000).unwrap()),
        seq_number: Some(0x3A5C_0F21),
        s_address: HostAddress {
            addr_type: 3,
            address: vec![0, 0, 0, 0],
        },
        r_address: None,
    }
}

// ===========================================================================
// KRB-PRIV — RFC 4120 5.7.1
// ===========================================================================

#[test]
fn krb_priv_structure_and_round_trip() {
    // RFC 4120 5.7.1: [APPLICATION 21] SEQUENCE { pvno [0], msg-type [1],
    // enc-part [3] } — no [2]. Application tag 21 → identifier 0x75 (5.10;
    // X.690 8.1.2.2: class 01, constructed, number 21).
    let der = krb_priv_from(&krb_priv_parts());
    assert_eq!(der[0], 0x75);
    round_trip(&der, &krb_priv_value(), KrbPriv::decode, KrbPriv::encode);
}

#[test]
fn krb_priv_with_kvno_round_trips() {
    // RFC 4120 5.2.9: EncryptedData kvno [1] OPTIONAL is carried when present.
    let mut parts = krb_priv_parts();
    parts[2] = ctx(3, &enc_data_der(&[0x11], Some(&[0x03]), &[0xEE; 16]));
    let value = KrbPriv {
        enc_part: EncryptedData {
            etype: 17,
            kvno: Some(3),
            cipher: vec![0xEE; 16],
        },
    };
    round_trip(
        &krb_priv_from(&parts),
        &value,
        KrbPriv::decode,
        KrbPriv::encode,
    );
}

#[test]
fn krb_priv_rejects_the_undefined_tag_2() {
    // RFC 4120 5.7.1: "NOTE: there is no [2] tag".
    let mut parts = krb_priv_parts();
    parts.insert(2, ctx(2, &int(&[0x00])));
    assert_eq!(
        KrbPriv::decode(&krb_priv_from(&parts)),
        Err(Error::UnknownField)
    );
}

#[test]
fn krb_priv_rejects_wrong_pvno_and_msg_type() {
    // RFC 4120 5.7.1 pvno INTEGER (5), msg-type INTEGER (21); 3.5.2 (a
    // mismatch is KRB_AP_ERR_BADVERSION / KRB_AP_ERR_MSG_TYPE).
    let mut parts = krb_priv_parts();
    parts[0] = ctx(0, &int(&[0x04]));
    assert_eq!(
        KrbPriv::decode(&krb_priv_from(&parts)),
        Err(Error::InvalidPvno)
    );
    for msg_type in [0x14, 0x16, 0x1E] {
        // KRB_SAFE 20, KRB_CRED 22, KRB_ERROR 30 (RFC 4120 7.5.7).
        let mut parts = krb_priv_parts();
        parts[1] = ctx(1, &int(&[msg_type]));
        assert_eq!(
            KrbPriv::decode(&krb_priv_from(&parts)),
            Err(Error::InvalidMsgType)
        );
    }
}

#[test]
fn krb_priv_rejects_missing_or_reordered_components() {
    // RFC 4120 5.7.1: enc-part is not OPTIONAL; X.690 8.9.2 definition order.
    let parts = krb_priv_parts();
    assert_eq!(
        KrbPriv::decode(&krb_priv_from(&parts[..2])),
        Err(Error::MissingField)
    );
    let reordered = vec![parts[1].clone(), parts[0].clone(), parts[2].clone()];
    assert_eq!(
        KrbPriv::decode(&krb_priv_from(&reordered)),
        Err(Error::FieldOutOfOrder)
    );
    let duplicated = vec![parts[0].clone(), parts[1].clone(), parts[1].clone()];
    assert_eq!(
        KrbPriv::decode(&krb_priv_from(&duplicated)),
        Err(Error::DuplicateField)
    );
}

#[test]
fn krb_priv_and_enc_krb_priv_part_tags_are_not_interchangeable() {
    // RFC 4120 5.10: KRB-PRIV is [APPLICATION 21], EncKrbPrivPart 28, KRB-SAFE
    // 20, EncAPRepPart 27.
    let priv_der = krb_priv_from(&krb_priv_parts());
    let enc_der = enc_part_from(&enc_part_request_parts());
    assert_eq!(
        KrbPriv::decode(&enc_der),
        Err(Error::UnexpectedApplicationTag)
    );
    assert_eq!(
        EncKrbPrivPart::decode(&priv_der),
        Err(Error::UnexpectedApplicationTag)
    );
    for tag in [20u8, 27] {
        let parts = krb_priv_parts();
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        assert_eq!(
            KrbPriv::decode(&app(tag, &seq(&refs))),
            Err(Error::UnexpectedApplicationTag)
        );
    }
    // A bare SEQUENCE is not an application-tagged message.
    let parts = krb_priv_parts();
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    assert_eq!(
        KrbPriv::decode(&seq(&refs)),
        Err(Error::ExpectedApplicationTag)
    );
}

#[test]
fn krb_priv_rejects_non_der_framing() {
    // RFC 4120 5.1.1 (DER only); X.690 8.1.3.6 (indefinite length), 10.1
    // (minimal length octets), 8.3.2 (minimal INTEGER); no trailing data.
    let der = krb_priv_from(&krb_priv_parts());

    let mut trailing = der.clone();
    trailing.push(0x00);
    assert_eq!(
        KrbPriv::decode(&trailing),
        Err(Error::Der(parse_asn1::Error::TrailingData))
    );

    // Indefinite length on the outer [APPLICATION 21]: 0x80 + end-of-contents.
    let mut indefinite = vec![der[0], 0x80];
    indefinite.extend_from_slice(&der[2..]);
    indefinite.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(
        KrbPriv::decode(&indefinite),
        Err(Error::Der(parse_asn1::Error::IndefiniteLength))
    );

    // Long-form length where the short form fits (0x81 n with n < 128).
    assert!(der.len() - 2 < 0x80, "vector uses the short form");
    let mut long_form = vec![der[0], 0x81, der[1]];
    long_form.extend_from_slice(&der[2..]);
    assert_eq!(
        KrbPriv::decode(&long_form),
        Err(Error::Der(parse_asn1::Error::NonMinimalLength))
    );

    // pvno encoded as 00 05 (a redundant leading zero octet).
    let mut parts = krb_priv_parts();
    parts[0] = ctx(0, &int(&[0x00, 0x05]));
    assert_eq!(
        KrbPriv::decode(&krb_priv_from(&parts)),
        Err(Error::Der(parse_asn1::Error::NonMinimalInteger))
    );

    // Truncated: every proper prefix fails.
    for len in 0..der.len() {
        assert!(KrbPriv::decode(&der[..len]).is_err(), "prefix {len}");
    }
}

#[test]
fn krb_priv_rejects_oversized_input() {
    // Resource bound (krb_proto::limits::MAX_MESSAGE_LEN; AGENTS.md §6).
    let huge = vec![0u8; limits::MAX_MESSAGE_LEN + 1];
    assert_eq!(KrbPriv::decode(&huge), Err(Error::MessageTooLarge));
}

// ===========================================================================
// EncKrbPrivPart — RFC 4120 5.7.1
// ===========================================================================

#[test]
fn enc_krb_priv_part_request_form_round_trips() {
    // RFC 4120 5.7.1 field order [0]..[4]; RFC 3244 §2: user-data is the
    // ChangePasswdData, seq-number present. Application tag 28 → 0x7C.
    let der = enc_part_from(&enc_part_request_parts());
    assert_eq!(der[0], 0x7C);
    round_trip(
        &der,
        &enc_part_request_value(),
        EncKrbPrivPart::decode,
        EncKrbPrivPart::encode,
    );
}

#[test]
fn enc_krb_priv_part_reply_form_round_trips() {
    // A reply-direction EncKrbPrivPart (docs/53 §5.7, Q-604 item 2): user-data
    // = result data 00 00 (KRB5_KPASSWD_SUCCESS, RFC 3244 §2), timestamp,
    // usec 0, seq-number, s-address Directional 1 ("the party to whom that
    // KRB_AP_REQ was sent", RFC 4120 7.1).
    let der = enc_part_from(&[
        ctx(0, &octets(&[0x00, 0x00])),
        ctx(1, &gtime(b"20261115120001Z")),
        ctx(2, &int(&[0x00])),
        ctx(3, &int(&[0x12, 0x34, 0x56, 0x78])),
        ctx(4, &host_address_der(&[0x03], &[0, 0, 0, 1])),
    ]);
    let value = EncKrbPrivPart {
        user_data: UserData::from_slice(&ResultCode::Success.result_data()),
        timestamp: Some(ktime("20261115120001Z")),
        usec: Some(Microseconds::new(0).unwrap()),
        seq_number: Some(0x1234_5678),
        s_address: HostAddress {
            addr_type: 3,
            address: vec![0, 0, 0, 1],
        },
        r_address: None,
    };
    round_trip(&der, &value, EncKrbPrivPart::decode, EncKrbPrivPart::encode);
}

#[test]
fn enc_krb_priv_part_minimal_and_full_forms_round_trip() {
    // RFC 4120 5.7.1: only user-data [0] and s-address [4] are required;
    // r-address [5] is OPTIONAL. IPv4 address type 2, 4 octets MSB first
    // (RFC 4120 7.1). Max UInt32 seq-number needs a leading zero octet (X.690
    // 8.3.2).
    let minimal = enc_part_from(&[
        ctx(0, &octets(&[])),
        ctx(4, &host_address_der(&[0x02], &[10, 1, 2, 3])),
    ]);
    let minimal_value = EncKrbPrivPart {
        user_data: UserData::new(Vec::new()),
        timestamp: None,
        usec: None,
        seq_number: None,
        s_address: HostAddress {
            addr_type: 2,
            address: vec![10, 1, 2, 3],
        },
        r_address: None,
    };
    round_trip(
        &minimal,
        &minimal_value,
        EncKrbPrivPart::decode,
        EncKrbPrivPart::encode,
    );

    let full = enc_part_from(&[
        ctx(0, &octets(b"x")),
        ctx(1, &gtime(b"20261115235959Z")),
        ctx(2, &int(&[0x0F, 0x42, 0x3F])),
        ctx(3, &int(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF])),
        ctx(4, &host_address_der(&[0x02], &[10, 1, 2, 3])),
        ctx(5, &host_address_der(&[0x02], &[10, 9, 8, 7])),
    ]);
    let full_value = EncKrbPrivPart {
        user_data: UserData::from_slice(b"x"),
        timestamp: Some(ktime("20261115235959Z")),
        usec: Some(Microseconds::new(999_999).unwrap()),
        seq_number: Some(u32::MAX),
        s_address: HostAddress {
            addr_type: 2,
            address: vec![10, 1, 2, 3],
        },
        r_address: Some(HostAddress {
            addr_type: 2,
            address: vec![10, 9, 8, 7],
        }),
    };
    round_trip(
        &full,
        &full_value,
        EncKrbPrivPart::decode,
        EncKrbPrivPart::encode,
    );
}

#[test]
fn enc_krb_priv_part_requires_s_address() {
    // RFC 4120 5.7.1: s-address is not OPTIONAL; 3.5.2 "The sender's address
    // MUST be included in the control information".
    let mut parts = enc_part_request_parts();
    parts.pop();
    assert_eq!(
        EncKrbPrivPart::decode(&enc_part_from(&parts)),
        Err(Error::MissingField)
    );
}

#[test]
fn enc_krb_priv_part_requires_user_data() {
    // RFC 4120 5.7.1: user-data [0] is not OPTIONAL.
    let parts = enc_part_request_parts();
    assert_eq!(
        EncKrbPrivPart::decode(&enc_part_from(&parts[1..])),
        Err(Error::MissingField)
    );
}

#[test]
fn enc_krb_priv_part_rejects_range_violations() {
    // RFC 4120 5.2.4: Microseconds 0..999999; UInt32 0..4294967295 (negative
    // seq-number rejected: the 5.5.1 leniency is not taken).
    let mut parts = enc_part_request_parts();
    parts[2] = ctx(2, &int(&[0x0F, 0x42, 0x40])); // 1000000
    assert_eq!(
        EncKrbPrivPart::decode(&enc_part_from(&parts)),
        Err(Error::MicrosecondsOutOfRange)
    );
    let mut parts = enc_part_request_parts();
    parts[3] = ctx(3, &int(&[0xFF])); // -1
    assert_eq!(
        EncKrbPrivPart::decode(&enc_part_from(&parts)),
        Err(Error::UInt32OutOfRange)
    );
    let mut parts = enc_part_request_parts();
    parts[3] = ctx(3, &int(&[0x01, 0x00, 0x00, 0x00, 0x00])); // 2^32
    assert_eq!(
        EncKrbPrivPart::decode(&enc_part_from(&parts)),
        Err(Error::UInt32OutOfRange)
    );
    // KerberosTime with fractional seconds (RFC 4120 5.2.3).
    let mut parts = enc_part_request_parts();
    parts[1] = ctx(1, &gtime(b"20261115120000.5Z"));
    assert_eq!(
        EncKrbPrivPart::decode(&enc_part_from(&parts)),
        Err(Error::FractionalKerberosTime)
    );
}

#[test]
fn enc_krb_priv_part_rejects_unknown_and_reordered_fields() {
    // RFC 4120 1.5 / 1.5.1: no fields are added to Kerberos types;
    // X.690 8.9.2: definition order, one value per component.
    let mut parts = enc_part_request_parts();
    parts.push(ctx(6, &int(&[0x00])));
    assert_eq!(
        EncKrbPrivPart::decode(&enc_part_from(&parts)),
        Err(Error::UnknownField)
    );
    let mut parts = enc_part_request_parts();
    parts.swap(1, 3);
    assert_eq!(
        EncKrbPrivPart::decode(&enc_part_from(&parts)),
        Err(Error::FieldOutOfOrder)
    );
    let mut parts = enc_part_request_parts();
    let again = parts[3].clone();
    parts.insert(3, again);
    assert_eq!(
        EncKrbPrivPart::decode(&enc_part_from(&parts)),
        Err(Error::DuplicateField)
    );
}

#[test]
fn enc_krb_priv_part_rejects_constructed_user_data() {
    // X.690 10.2: DER encodes an OCTET STRING primitive only (the BER
    // constructed form is refused; RFC 4120 5.1.1).
    let mut parts = enc_part_request_parts();
    parts[0] = ctx(0, &tlv(0x24, &octets(b"ab")));
    assert_eq!(
        EncKrbPrivPart::decode(&enc_part_from(&parts)),
        Err(Error::Der(parse_asn1::Error::PrimitiveConstructedMismatch))
    );
}

// ===========================================================================
// ChangePasswdData — RFC 3244 §2
// ===========================================================================

#[test]
fn change_passwd_data_change_form_round_trips() {
    // RFC 3244 §2: SEQUENCE { newpasswd [0] OCTET STRING, targname [1]
    // OPTIONAL, targrealm [2] OPTIONAL }; explicit context tag [0] → 0xA0.
    let der = cpd_change_der(PASSWORD);
    assert_eq!(der[0], 0x30);
    assert_eq!(der[2], 0xA0);
    let value = ChangePasswdData::change(NewPasswd::from_slice(PASSWORD));
    round_trip(
        &der,
        &value,
        ChangePasswdData::decode,
        ChangePasswdData::encode,
    );
}

#[test]
fn change_passwd_data_change_form_exposes_the_password() {
    // [MS-KILE] 3.1.5.12: "If the fields are absent, then this is a password
    // change".
    let decoded = ChangePasswdData::decode(&cpd_change_der(PASSWORD)).unwrap();
    match decoded.request() {
        PasswordRequest::Change { newpasswd } => assert_eq!(newpasswd.as_bytes(), PASSWORD),
        PasswordRequest::Set => panic!("absent targname/targrealm is a change"),
    }
}

#[test]
fn change_passwd_data_set_forms_are_decoded_but_carry_nothing() {
    // [MS-KILE] 3.1.5.12: "If the fields are present, then this is a request
    // to set a password"; docs/53 §5.4 item 4: targname OR targrealm ⇒ set,
    // refused without looking the target up (Q-600 item 2). The decoded value
    // still re-encodes exactly (lossless), but `request()` exposes neither the
    // target nor the password.
    let targname = ctx(1, &pname_der(&[0x01], &["bob"]));
    let targrealm = ctx(2, &gstring(b"EXAMPLE.ORG"));
    let pw = ctx(0, &octets(PASSWORD));
    for der in [
        seq(&[&pw, &targname]),
        seq(&[&pw, &targrealm]),
        seq(&[&pw, &targname, &targrealm]),
    ] {
        let decoded = ChangePasswdData::decode(&der).expect("strictly decoded");
        assert_eq!(decoded.request(), PasswordRequest::Set);
        assert_eq!(decoded.encode().unwrap().as_slice(), der.as_slice());
    }
}

#[test]
fn change_passwd_data_set_form_with_the_clients_own_name_is_still_set() {
    // Q-600 item 2: a set "even when targname names the client itself".
    let der = seq(&[
        &ctx(0, &octets(PASSWORD)),
        &ctx(1, &pname_der(&[0x01], &["alice"])),
        &ctx(2, &gstring(b"EXAMPLE.ORG")),
    ]);
    assert_eq!(
        ChangePasswdData::decode(&der).unwrap().request(),
        PasswordRequest::Set
    );
}

#[test]
fn change_passwd_data_refuses_fields_after_targrealm() {
    // RFC 3244 §2 "should be prepared to ignore fields after targrealm" is not
    // taken (docs/questions/Q-603 item 6: refuse, MALFORMED).
    let der = seq(&[
        &ctx(0, &octets(PASSWORD)),
        &ctx(2, &gstring(b"EXAMPLE.ORG")),
        &ctx(3, &int(&[0x00])),
    ]);
    assert_eq!(ChangePasswdData::decode(&der), Err(Error::UnknownField));
    let der = seq(&[&ctx(0, &octets(PASSWORD)), &ctx(3, &octets(b"ext"))]);
    assert_eq!(ChangePasswdData::decode(&der), Err(Error::UnknownField));
}

#[test]
fn change_passwd_data_requires_newpasswd() {
    // RFC 3244 §2: newpasswd [0] is not OPTIONAL.
    let der = seq(&[&ctx(2, &gstring(b"EXAMPLE.ORG"))]);
    assert_eq!(ChangePasswdData::decode(&der), Err(Error::MissingField));
    assert_eq!(
        ChangePasswdData::decode(&seq(&[])),
        Err(Error::MissingField)
    );
}

#[test]
fn change_passwd_data_rejects_reordered_and_duplicate_fields() {
    // X.690 8.9.2: definition order, each component once.
    let pw = ctx(0, &octets(PASSWORD));
    let name = ctx(1, &pname_der(&[0x01], &["bob"]));
    let realm = ctx(2, &gstring(b"EXAMPLE.ORG"));
    assert_eq!(
        ChangePasswdData::decode(&seq(&[&name, &pw])),
        Err(Error::FieldOutOfOrder)
    );
    assert_eq!(
        ChangePasswdData::decode(&seq(&[&pw, &realm, &name])),
        Err(Error::FieldOutOfOrder)
    );
    assert_eq!(
        ChangePasswdData::decode(&seq(&[&pw, &pw])),
        Err(Error::DuplicateField)
    );
}

#[test]
fn change_passwd_data_newpasswd_bound() {
    // docs/53 §5.4 item 4 / §5.9: newpasswd ≤ 1024 octets
    // (limits::MAX_NEWPASSWD_LEN), on decode and on encode.
    assert_eq!(limits::MAX_NEWPASSWD_LEN, 1024);
    let at_bound = vec![b'a'; limits::MAX_NEWPASSWD_LEN];
    let der = cpd_change_der(&at_bound);
    let value = ChangePasswdData::change(NewPasswd::from_slice(&at_bound));
    round_trip(
        &der,
        &value,
        ChangePasswdData::decode,
        ChangePasswdData::encode,
    );

    let over = vec![b'a'; limits::MAX_NEWPASSWD_LEN + 1];
    assert_eq!(
        ChangePasswdData::decode(&cpd_change_der(&over)),
        Err(Error::NewPasswdTooLong)
    );
    assert_eq!(
        ChangePasswdData::change(NewPasswd::new(over)).encode(),
        Err(Error::NewPasswdTooLong)
    );
}

#[test]
fn change_passwd_data_accepts_any_newpasswd_octets() {
    // RFC 3244 §2 states no encoding for newpasswd; UTF-8 validity is keyd's
    // check with a PasswordRefused verdict (docs/53 §5.4 item 5; Q-603 item 7),
    // not a decode failure (which would be MALFORMED). An empty password is
    // keyd's policy check too.
    for pw in [&[0xFF, 0xFE, 0x00][..], &[][..]] {
        let der = cpd_change_der(pw);
        let value = ChangePasswdData::change(NewPasswd::from_slice(pw));
        round_trip(
            &der,
            &value,
            ChangePasswdData::decode,
            ChangePasswdData::encode,
        );
    }
}

#[test]
fn change_passwd_data_rejects_implicit_tagging_and_wrong_types() {
    // Explicit tags (X.680 13.2, 31.2.7 b); Q-620): an implicitly tagged
    // newpasswd (primitive 0x80) is not the definition's encoding.
    let implicit = seq(&[&tlv(0x80, PASSWORD)]);
    assert_eq!(
        ChangePasswdData::decode(&implicit),
        Err(Error::Der(parse_asn1::Error::PrimitiveConstructedMismatch))
    );
    // newpasswd must be an OCTET STRING (RFC 3244 §2).
    let wrong = seq(&[&ctx(0, &gstring(PASSWORD))]);
    assert_eq!(
        ChangePasswdData::decode(&wrong),
        Err(Error::ExpectedOctetString)
    );
    // targname must be a PrincipalName (RFC 4120 5.2.2) and targrealm a Realm
    // of IA5 characters (RFC 4120 5.2.1).
    let bad_name = seq(&[&ctx(0, &octets(PASSWORD)), &ctx(1, &gstring(b"bob"))]);
    assert_eq!(
        ChangePasswdData::decode(&bad_name),
        Err(Error::ExpectedSequence)
    );
    let bad_realm = seq(&[&ctx(0, &octets(PASSWORD)), &ctx(2, &gstring(&[0xC3, 0xA9]))]);
    assert_eq!(
        ChangePasswdData::decode(&bad_realm),
        Err(Error::NonIa5Character)
    );
    // Not a SEQUENCE at all.
    assert_eq!(
        ChangePasswdData::decode(&octets(PASSWORD)),
        Err(Error::ExpectedSequence)
    );
}

#[test]
fn change_passwd_data_rejects_non_der_framing() {
    // RFC 4120 5.1.1 / docs/53 §5.4 item 4 (strict DER); X.690 8.1.3.6, 10.1,
    // 10.2.
    let der = cpd_change_der(PASSWORD);

    let mut indefinite = vec![0x30, 0x80];
    indefinite.extend_from_slice(&der[2..]);
    indefinite.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(
        ChangePasswdData::decode(&indefinite),
        Err(Error::Der(parse_asn1::Error::IndefiniteLength))
    );

    let mut long_form = vec![0x30, 0x81, der[1]];
    long_form.extend_from_slice(&der[2..]);
    assert_eq!(
        ChangePasswdData::decode(&long_form),
        Err(Error::Der(parse_asn1::Error::NonMinimalLength))
    );

    let constructed = seq(&[&ctx(0, &tlv(0x24, &octets(PASSWORD)))]);
    assert_eq!(
        ChangePasswdData::decode(&constructed),
        Err(Error::Der(parse_asn1::Error::PrimitiveConstructedMismatch))
    );

    let mut trailing = der.clone();
    trailing.push(0x00);
    assert_eq!(
        ChangePasswdData::decode(&trailing),
        Err(Error::Der(parse_asn1::Error::TrailingData))
    );

    for len in 0..der.len() {
        assert!(
            ChangePasswdData::decode(&der[..len]).is_err(),
            "prefix {len}"
        );
    }
}

#[test]
fn change_passwd_data_inside_enc_krb_priv_part() {
    // RFC 3244 §2: the user-data of the request KRB-PRIV is the
    // ChangePasswdData "encoded as an OCTET STRING".
    let enc = EncKrbPrivPart::decode(&enc_part_from(&enc_part_request_parts())).unwrap();
    let cpd = ChangePasswdData::decode(enc.user_data.as_bytes()).unwrap();
    assert_eq!(
        cpd,
        ChangePasswdData::change(NewPasswd::from_slice(PASSWORD))
    );
}

// ===========================================================================
// Result codes and result data — RFC 3244 §2
// ===========================================================================

#[test]
fn result_code_table() {
    // RFC 3244 §2, the table of result codes (0-7), big-endian 16-bit.
    let table = [
        (0u16, ResultCode::Success),
        (1, ResultCode::Failure(NonZeroResultCode::Malformed)),
        (2, ResultCode::Failure(NonZeroResultCode::HardError)),
        (3, ResultCode::Failure(NonZeroResultCode::AuthError)),
        (4, ResultCode::Failure(NonZeroResultCode::SoftError)),
        (5, ResultCode::Failure(NonZeroResultCode::AccessDenied)),
        (6, ResultCode::Failure(NonZeroResultCode::BadVersion)),
        (7, ResultCode::Failure(NonZeroResultCode::InitialFlagNeeded)),
    ];
    for (value, code) in table {
        assert_eq!(code.value(), value);
        assert_eq!(ResultCode::from_value(value), Ok(code));
        assert_eq!(code.result_data(), [0x00, value as u8]);
        assert_eq!(ResultCode::from_result_data(&[0x00, value as u8]), Ok(code));
        if let ResultCode::Failure(failure) = code {
            assert_eq!(failure.value(), value);
            assert_eq!(NonZeroResultCode::from_value(value), Ok(failure));
            assert_eq!(failure.result_data(), [0x00, value as u8]);
            assert_eq!(
                NonZeroResultCode::from_result_data(&[0x00, value as u8]),
                Ok(failure)
            );
            assert_eq!(ResultCode::from(failure), code);
        }
    }
}

#[test]
fn result_code_values_are_big_endian() {
    // RFC 3244 §2: "All 16 bit fields are in big-endian order"; result code
    // "(big-endian integer)". 01 00 is 256, not MALFORMED.
    assert_eq!(
        ResultCode::from_result_data(&[0x01, 0x00]),
        Err(Error::UnknownResultCode)
    );
    assert_eq!(NonZeroResultCode::AccessDenied.result_data(), [0x00, 0x05]);
}

#[test]
fn result_code_set_is_closed() {
    // RFC 3244 §2: "The result code must have one of the following values";
    // 0xFFFF is never sent by this project (docs/questions/Q-604 item 4).
    for value in [8u16, 0x00FF, 0x0100, 0xFF80, 0xFFFE, 0xFFFF] {
        assert_eq!(ResultCode::from_value(value), Err(Error::UnknownResultCode));
        assert_eq!(
            NonZeroResultCode::from_value(value),
            Err(Error::UnknownResultCode)
        );
    }
}

#[test]
fn success_is_not_a_failure_code() {
    // RFC 3244 §2: KRB5_KPASSWD_SUCCESS "is not allowed in a KRB-ERROR
    // message" — NonZeroResultCode cannot hold 0.
    assert_eq!(
        NonZeroResultCode::from_value(0),
        Err(Error::SuccessNotAllowed)
    );
    assert_eq!(
        NonZeroResultCode::from_result_data(&[0x00, 0x00]),
        Err(Error::SuccessNotAllowed)
    );
}

#[test]
fn result_data_is_exactly_the_code() {
    // RFC 3244 §2: result code (16 bits) then an optional result string;
    // docs/questions/Q-604 item 5: the string is always omitted, so result
    // data is exactly two octets — shorter is truncated, longer would carry a
    // string.
    for data in [&[][..], &[0x00][..], &[0x00, 0x04, b'x'][..]] {
        assert_eq!(
            ResultCode::from_result_data(data),
            Err(Error::ResultDataLength)
        );
        assert_eq!(
            NonZeroResultCode::from_result_data(data),
            Err(Error::ResultDataLength)
        );
    }
}

// ===========================================================================
// Secrets — AGENTS.md §6
// ===========================================================================

fn assert_no_password_text(text: &str) {
    for needle in ["Marker", "New-Pw", "77, 97", "4d"] {
        assert!(
            !text.contains(needle),
            "formatted output leaks the password ({needle}): {text}"
        );
    }
}

#[test]
fn passwords_are_redacted_in_debug() {
    // AGENTS.md §6: the new password never appears in Debug output — not in
    // NewPasswd, ChangePasswdData, PasswordRequest, UserData (which holds the
    // ChangePasswdData DER) or EncKrbPrivPart.
    let newpasswd = NewPasswd::from_slice(PASSWORD);
    let text = format!("{newpasswd:?}");
    assert_eq!(text, "NewPasswd(<redacted>)");
    let cpd = ChangePasswdData::change(newpasswd);
    assert_no_password_text(&format!("{cpd:?} {cpd:#?}"));
    assert_no_password_text(&format!("{:?}", cpd.request()));
    let enc = enc_part_request_value();
    let text = format!("{enc:?} {:?}", enc.user_data);
    assert!(text.contains("UserData(<redacted>)"), "{text}");
    assert_no_password_text(&text);
}

#[test]
fn password_bearing_encodings_are_zeroizing() {
    // AGENTS.md §6: the DER of ChangePasswdData / EncKrbPrivPart carries the
    // password and is returned in a Zeroizing buffer (compile-time type check).
    let cpd = ChangePasswdData::change(NewPasswd::from_slice(PASSWORD));
    let encoded: Zeroizing<Vec<u8>> = cpd.encode().unwrap();
    assert_eq!(ChangePasswdData::decode(&encoded).unwrap(), cpd);
    let enc = enc_part_request_value();
    let encoded: Zeroizing<Vec<u8>> = enc.encode().unwrap();
    assert_eq!(EncKrbPrivPart::decode(&encoded).unwrap(), enc);
}

#[test]
fn errors_carry_no_password() {
    // A valid newpasswd followed by an undefined field [3]: a unit error that
    // cannot contain the password octets.
    let der = seq(&[&ctx(0, &octets(PASSWORD)), &ctx(3, &int(&[0x00]))]);
    let err = ChangePasswdData::decode(&der).unwrap_err();
    assert_eq!(err, Error::UnknownField);
    assert_no_password_text(&format!("{err:?}"));
    assert_no_password_text(&err.to_string());
}

#[test]
fn secret_octet_types_compare_every_octet() {
    // The one secret-octets definition (KeyValue / UserData / NewPasswd):
    // structural equality over every octet; lengths differ → unequal.
    let a = NewPasswd::from_slice(b"abc");
    assert_eq!(a, NewPasswd::new(b"abc".to_vec()));
    assert_ne!(a, NewPasswd::from_slice(b"abd"));
    assert_ne!(a, NewPasswd::from_slice(b"ab"));
    assert_eq!(a.len(), 3);
    assert!(!a.is_empty());
    let u = UserData::from_slice(&[]);
    assert!(u.is_empty());
    assert_eq!(u, UserData::new(Vec::new()));
}

// ---------------------------------------------------------------------------
// The change-password service principal — RFC 3244 §2 (the one definition:
// docs/questions/Q-955 item 5, A-158; Q-987)
// ---------------------------------------------------------------------------

/// A PrincipalName of `name_type` with `parts` (RFC 4120 5.2.2).
fn principal(name_type: i32, parts: &[&str]) -> krb_proto::PrincipalName {
    krb_proto::PrincipalName {
        name_type,
        name_string: parts
            .iter()
            .map(|part| krb_proto::KerberosString::new(part).unwrap())
            .collect(),
    }
}

/// RFC 3244 §2 ("the service principal kadmin/changepw@REALM"): the name is
/// exactly the two components `kadmin`, `changepw`.
#[test]
fn the_change_password_service_name_is_rfc3244s() {
    assert_eq!(
        krb_proto::CHANGE_PASSWORD_SERVICE_NAME,
        ["kadmin", "changepw"]
    );
}

/// RFC 3244 §2; RFC 4120 6.2 ("The name-type SHOULD be treated only as a
/// hint … It is not significant when checking for equivalence"): exactly
/// `kadmin` / `changepw`, octet for octet, is the change-password service
/// whatever the name-type; a case variant, a reordering, one or three
/// components, one joined component, a trailing space, another instance or
/// no component at all are not.
#[test]
fn the_change_password_service_rule_is_exact() {
    use krb_proto::is_change_password_service_name;
    for name_type in [0, 1, 2, 3, 10] {
        assert!(
            is_change_password_service_name(&principal(name_type, &["kadmin", "changepw"])),
            "{name_type}"
        );
    }
    for parts in [
        &["KADMIN", "changepw"][..],
        &["kadmin", "CHANGEPW"][..],
        &["changepw", "kadmin"][..],
        &["kadmin"][..],
        &["kadmin", "changepw", "x"][..],
        &["kadmin/changepw"][..],
        &["kadmin", "admin"][..],
        &["kadmin", "changepw "][..],
        &[][..],
    ] {
        assert!(
            !is_change_password_service_name(&principal(2, parts)),
            "{parts:?}"
        );
    }
}
