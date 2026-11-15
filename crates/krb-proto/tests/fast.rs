//! RFC 6113 FAST message types: round trips, hand-derived DER vectors,
//! rejections, key-material handling and a never-panic smoke test.
//!
//! Every vector is derived here from the RFC 6113 Appendix B module (which
//! imports the basic types from RFC 4120) using the X.690 (02/2021) encoders in
//! `common` — identifier octets per 8.1.2.2, definite lengths per 8.1.3 / 10.1,
//! INTEGER per 8.3.2 / 8.3.3, explicit tags per 8.14.3, SEQUENCE per 8.9,
//! SEQUENCE OF per 8.10, CHOICE per 8.13. Each test names its source. RFC 6113
//! prints no example encodings of these types (its Appendix A vectors are for
//! KRB-FX-CF2 only), so there is no printed vector to reuse. No vector comes
//! from any other implementation.

mod common;

use common::*;
use krb_proto::{
    constants, limits, ApOptions, ApReq, AsReq, Checksum, EncryptedChallenge, EncryptedData,
    EncryptionKey, Error, EtypeInfo2, FastOptions, KdcOptions, KdcReq, KdcReqBody, KerberosFlags,
    KeyValue, KrbError, KrbFastArmor, KrbFastArmoredRep, KrbFastArmoredReq, KrbFastFinished,
    KrbFastReq, KrbFastResponse, MethodData, Microseconds, PaData, PaEncTsEnc, PaFxFastReply,
    PaFxFastRequest,
};
use zeroize::Zeroizing;

// ===========================================================================
// Builders. Each returns (hand-derived DER, expected typed value).
// ===========================================================================

/// PA-DATA DER, RFC 4120 5.2.7: SEQUENCE { [1] padata-type, [2] padata-value }.
fn pa_der(type_contents: &[u8], value: &[u8]) -> Vec<u8> {
    seq(&[&ctx(1, &int(type_contents)), &ctx(2, &octets(value))])
}

/// Checksum DER, RFC 4120 5.2.9: SEQUENCE { [0] cksumtype, [1] checksum }.
/// cksumtype 16 = hmac-sha1-96-aes256, 96 bits = 12 octets (RFC 3962 §7);
/// the 12 checksum octets are arbitrary (`first`, `first`+1, ...).
fn checksum(first: u8) -> (Vec<u8>, Checksum) {
    let sum: Vec<u8> = (first..first + 12).collect();
    let der = seq(&[&ctx(0, &int(&[0x10])), &ctx(1, &octets(&sum))]);
    (
        der,
        Checksum {
            cksumtype: 16,
            checksum: sum,
        },
    )
}

/// EncryptedData DER, RFC 4120 5.2.9, etype 18 = aes256-cts-hmac-sha1-96
/// (RFC 3962 §7), no kvno, arbitrary cipher octets.
fn enc(cipher: &[u8]) -> (Vec<u8>, EncryptedData) {
    (
        enc_data_der(&[0x12], None, cipher),
        EncryptedData {
            etype: 18,
            kvno: None,
            cipher: cipher.to_vec(),
        },
    )
}

/// The AP-REQ of ticket-based armor (RFC 6113 5.4.1.1: armor-value "contains
/// an ASN.1 DER encoded AP-REQ"; the armor ticket is a TGT). RFC 4120 5.5.1:
/// AP-REQ ::= [APPLICATION 14] SEQUENCE { pvno [0] 5, msg-type [1] 14,
/// ap-options [2], ticket [3], authenticator [4] }; authenticator opaque.
fn armor_ap_req() -> (Vec<u8>, ApReq) {
    let (tgt_der, tgt_value) = tgt();
    let (auth_der, auth_value) = enc(&(0x60..0x74).collect::<Vec<u8>>());
    let der = app(
        14,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &int(&[0x0E])),
            &ctx(2, &flags32([0x00, 0x00, 0x00, 0x00])),
            &ctx(3, &tgt_der),
            &ctx(4, &auth_der),
        ]),
    );
    let value = ApReq {
        ap_options: ApOptions::empty(),
        ticket: tgt_value,
        authenticator: auth_value,
    };
    (der, value)
}

/// KrbFastArmor with FX_FAST_ARMOR_AP_REQUEST (1). RFC 6113 5.4.1, 7.2.
fn armor() -> (Vec<u8>, KrbFastArmor) {
    let (ap_der, _) = armor_ap_req();
    let der = seq(&[&ctx(0, &int(&[0x01])), &ctx(1, &octets(&ap_der))]);
    let value = KrbFastArmor {
        armor_type: constants::FX_FAST_ARMOR_AP_REQUEST,
        armor_value: ap_der,
    };
    (der, value)
}

/// KrbFastArmoredReq of an AS request (armor present). RFC 6113 5.4.2.
fn armored_req_as() -> (Vec<u8>, KrbFastArmoredReq) {
    let (armor_der, armor_value) = armor();
    let (sum_der, sum_value) = checksum(0x01);
    let (enc_der, enc_value) = enc(&(0x80..0xA0).collect::<Vec<u8>>());
    let der = seq(&[&ctx(0, &armor_der), &ctx(1, &sum_der), &ctx(2, &enc_der)]);
    let value = KrbFastArmoredReq {
        armor: Some(armor_value),
        req_checksum: sum_value,
        enc_fast_req: enc_value,
    };
    (der, value)
}

/// PA-FX-FAST-REQUEST of an AS request: armored-data [0]. RFC 6113 5.4.2.
fn pa_fx_fast_request_as() -> (Vec<u8>, PaFxFastRequest) {
    let (inner_der, inner_value) = armored_req_as();
    (
        ctx(0, &inner_der),
        PaFxFastRequest::ArmoredData(inner_value),
    )
}

/// The KDC-REQ-BODY of an AS request (RFC 4120 5.4.1): kdc-options
/// forwardable(1) = 40 00 00 00; cname alice (NT-PRINCIPAL 1); realm; sname
/// krbtgt/EXAMPLE.ORG (NT-SRV-INST 2); till; nonce 0x9C3A5E21 (top bit set →
/// leading 00, X.690 8.3.2); etype [18].
fn as_req_body() -> (Vec<u8>, KdcReqBody) {
    let der = seq(&[
        &ctx(0, &flags32([0x40, 0x00, 0x00, 0x00])),
        &ctx(1, &pname_der(&[0x01], &["alice"])),
        &ctx(2, &gstring(b"EXAMPLE.ORG")),
        &ctx(3, &pname_der(&[0x02], &["krbtgt", "EXAMPLE.ORG"])),
        &ctx(5, &gtime(b"20261114000000Z")),
        &ctx(7, &int(&[0x00, 0x9C, 0x3A, 0x5E, 0x21])),
        &ctx(8, &seq(&[&int(&[0x12])])),
    ]);
    let value = KdcReqBody {
        kdc_options: KdcOptions::FORWARDABLE,
        cname: Some(pname(1, &["alice"])),
        realm: realm("EXAMPLE.ORG"),
        sname: Some(pname(2, &["krbtgt", "EXAMPLE.ORG"])),
        from: None,
        till: ktime("20261114000000Z"),
        rtime: None,
        nonce: 0x9C3A_5E21,
        etype: vec![18],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    (der, value)
}

/// KrbFastReq (the plaintext of enc-fast-req), RFC 6113 5.4.2:
/// - fast-options hide-client-names(1) → bit 1 → 40 00 00 00 (X.690 8.6.2.1);
/// - padata: PA-ENCRYPTED-CHALLENGE (138 = 0x8A → INTEGER 00 8A, X.690 8.3.2)
///   whose value is an EncryptedChallenge (RFC 6113 5.4.6), then PA-FX-COOKIE
///   (133 = 0x85 → 00 85) echoing an opaque cookie (5.2);
/// - req-body: [`as_req_body`].
fn krb_fast_req() -> (Vec<u8>, KrbFastReq) {
    let (challenge_der, _) = enc(&(0x40..0x5C).collect::<Vec<u8>>());
    let cookie = b"opaque-kdc-cookie".to_vec();
    let (body_der, body_value) = as_req_body();
    let der = seq(&[
        &ctx(0, &flags32([0x40, 0x00, 0x00, 0x00])),
        &ctx(
            1,
            &seq(&[
                &pa_der(&[0x00, 0x8A], &challenge_der),
                &pa_der(&[0x00, 0x85], &cookie),
            ]),
        ),
        &ctx(2, &body_der),
    ]);
    let value = KrbFastReq {
        fast_options: FastOptions::HIDE_CLIENT_NAMES,
        padata: vec![
            PaData {
                padata_type: constants::PA_ENCRYPTED_CHALLENGE,
                padata_value: challenge_der,
            },
            PaData {
                padata_type: constants::PA_FX_COOKIE,
                padata_value: cookie,
            },
        ],
        req_body: body_value,
    };
    (der, value)
}

/// KrbFastFinished, RFC 6113 5.4.3: timestamp 20261113090512Z; usec 123456 =
/// 0x01E240 → INTEGER 01 E2 40; crealm EXAMPLE.ORG; cname alice; ticket-checksum
/// (cksumtype 16, 12 octets).
fn krb_fast_finished() -> (Vec<u8>, KrbFastFinished) {
    let (sum_der, sum_value) = checksum(0xB0);
    let der = seq(&[
        &ctx(0, &gtime(b"20261113090512Z")),
        &ctx(1, &int(&[0x01, 0xE2, 0x40])),
        &ctx(2, &gstring(b"EXAMPLE.ORG")),
        &ctx(3, &pname_der(&[0x01], &["alice"])),
        &ctx(4, &sum_der),
    ]);
    let value = KrbFastFinished {
        timestamp: ktime("20261113090512Z"),
        usec: Microseconds::new(123_456).unwrap(),
        crealm: realm("EXAMPLE.ORG"),
        cname: pname(1, &["alice"]),
        ticket_checksum: sum_value,
    };
    (der, value)
}

/// EncryptionKey DER, RFC 4120 5.2.9 (keytype 18; 32-octet aes256 key,
/// RFC 3962 §7).
fn strengthen_key(fill: &[u8]) -> (Vec<u8>, EncryptionKey) {
    (
        seq(&[&ctx(0, &int(&[0x12])), &ctx(1, &octets(fill))]),
        EncryptionKey {
            keytype: 18,
            keyvalue: KeyValue::from_slice(fill),
        },
    )
}

/// KrbFastResponse of an AS reply, RFC 6113 5.4.3: padata carrying the KDC's
/// PA-ENCRYPTED-CHALLENGE (5.4.6), strengthen-key present, finished present,
/// nonce 0x9C3A5E21 (→ 00 9C 3A 5E 21).
fn krb_fast_response_as() -> (Vec<u8>, KrbFastResponse) {
    let (challenge_der, _) = enc(&(0x70..0x8C).collect::<Vec<u8>>());
    let key: Vec<u8> = (0x20..0x40).collect();
    let (key_der, key_value) = strengthen_key(&key);
    let (finished_der, finished_value) = krb_fast_finished();
    let der = seq(&[
        &ctx(0, &seq(&[&pa_der(&[0x00, 0x8A], &challenge_der)])),
        &ctx(1, &key_der),
        &ctx(2, &finished_der),
        &ctx(3, &int(&[0x00, 0x9C, 0x3A, 0x5E, 0x21])),
    ]);
    let value = KrbFastResponse {
        padata: vec![PaData {
            padata_type: constants::PA_ENCRYPTED_CHALLENGE,
            padata_value: challenge_der,
        }],
        strengthen_key: Some(key_value),
        finished: Some(finished_value),
        nonce: 0x9C3A_5E21,
    };
    (der, value)
}

/// The KRB-ERROR inside PA-FX-ERROR (RFC 6113 5.4.4: e-data absent). RFC 4120
/// 5.9.1: pvno 5, msg-type 30 (0x1E), stime, susec 0, error-code 25 (0x19,
/// KDC_ERR_PREAUTH_REQUIRED, RFC 4120 7.5.9), realm, sname.
fn inner_krb_error() -> (Vec<u8>, KrbError) {
    let der = app(
        30,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &int(&[0x1E])),
            &ctx(4, &gtime(b"20261113090000Z")),
            &ctx(5, &int(&[0x00])),
            &ctx(6, &int(&[0x19])),
            &ctx(9, &gstring(b"EXAMPLE.ORG")),
            &ctx(10, &pname_der(&[0x02], &["krbtgt", "EXAMPLE.ORG"])),
        ]),
    );
    let value = KrbError {
        ctime: None,
        cusec: None,
        stime: ktime("20261113090000Z"),
        susec: Microseconds::new(0).unwrap(),
        error_code: constants::KDC_ERR_PREAUTH_REQUIRED,
        crealm: None,
        cname: None,
        realm: realm("EXAMPLE.ORG"),
        sname: pname(2, &["krbtgt", "EXAMPLE.ORG"]),
        e_text: None,
        e_data: None,
    };
    (der, value)
}

/// KrbFastResponse of a FAST error, RFC 6113 5.4.4: padata = PA-FX-ERROR
/// (137 = 0x89 → 00 89) with the inner KRB-ERROR, PA-FX-COOKIE (00 85),
/// PA-ETYPE-INFO2 (19 = 0x13; RFC 4120 5.2.7.5: one entry, etype 18, salt
/// "EXAMPLE.ORGalice"); strengthen-key and finished absent ("MUST be absent in
/// KRB-ERROR", 5.4.3); nonce 0x9C3A5E21.
fn krb_fast_response_error() -> (Vec<u8>, KrbFastResponse) {
    let (error_der, _) = inner_krb_error();
    let cookie = b"next-cookie".to_vec();
    let etype_info2 = seq(&[&seq(&[
        &ctx(0, &int(&[0x12])),
        &ctx(1, &gstring(b"EXAMPLE.ORGalice")),
    ])]);
    let der = seq(&[
        &ctx(
            0,
            &seq(&[
                &pa_der(&[0x00, 0x89], &error_der),
                &pa_der(&[0x00, 0x85], &cookie),
                &pa_der(&[0x13], &etype_info2),
            ]),
        ),
        &ctx(3, &int(&[0x00, 0x9C, 0x3A, 0x5E, 0x21])),
    ]);
    let value = KrbFastResponse {
        padata: vec![
            PaData {
                padata_type: constants::PA_FX_ERROR,
                padata_value: error_der,
            },
            PaData {
                padata_type: constants::PA_FX_COOKIE,
                padata_value: cookie,
            },
            PaData {
                padata_type: constants::PA_ETYPE_INFO2,
                padata_value: etype_info2,
            },
        ],
        strengthen_key: None,
        finished: None,
        nonce: 0x9C3A_5E21,
    };
    (der, value)
}

/// PA-FX-FAST-REPLY: armored-data [0] KrbFastArmoredRep { enc-fast-rep [0] }.
/// RFC 6113 5.4.3.
fn pa_fx_fast_reply() -> (Vec<u8>, PaFxFastReply) {
    let (enc_der, enc_value) = enc(&(0x90..0xC0).collect::<Vec<u8>>());
    (
        ctx(0, &seq(&[&ctx(0, &enc_der)])),
        PaFxFastReply::ArmoredData(KrbFastArmoredRep {
            enc_fast_rep: enc_value,
        }),
    )
}

/// Rebuild a SEQUENCE from separately encoded components.
fn seq_of_parts(parts: &[Vec<u8>]) -> Vec<u8> {
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    seq(&refs)
}

// ===========================================================================
// Constants — RFC 6113 6.1, 6.4, 7.2
// ===========================================================================

#[test]
fn constants_match_rfc_6113_tables() {
    // Source: RFC 6113 6.4 "New PA-DATA Types" (also 5.2, 5.4.2, 5.4.4, 5.4.6
    // and the 7.1 registry).
    assert_eq!(constants::PA_FX_COOKIE, 133);
    assert_eq!(constants::PA_FX_FAST, 136);
    assert_eq!(constants::PA_FX_ERROR, 137);
    assert_eq!(constants::PA_ENCRYPTED_CHALLENGE, 138);
    // Source: RFC 6113 7.2 "Fast Armor Types" (also 5.4.1).
    assert_eq!(constants::FX_FAST_ARMOR_AP_REQUEST, 1);
    // Source: RFC 6113 6.1 "New Errors".
    assert_eq!(constants::KDC_ERR_PREAUTH_EXPIRED, 90);
    assert_eq!(constants::KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, 91);
    assert_eq!(constants::KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET, 92);
    assert_eq!(constants::KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS, 93);
}

// ===========================================================================
// KrbFastArmor — RFC 6113 5.4.1
// ===========================================================================

#[test]
fn krb_fast_armor_literal_vector() {
    // Source: RFC 6113 5.4.1 (KrbFastArmor ::= SEQUENCE { armor-type [0] Int32,
    // armor-value [1] OCTET STRING, ... }), 7.2 (FX_FAST_ARMOR_AP_REQUEST = 1).
    // Derivation (X.690):
    //   INTEGER 1              02 01 01          (8.3.2: one octet)
    //   [0] explicit           A0 03 <5 octets>  (8.1.2.2: context 10,
    //                                             constructed 1, number 0;
    //                                             8.14.3)
    //   OCTET STRING 01 02     04 02 01 02       (8.7, 10.2 primitive)
    //   [1] explicit           A1 04 <6 octets>
    //   SEQUENCE               30 0B <11 octets> (8.9; 8.1.3.4 short form)
    let bytes = [
        0x30, 0x0B, 0xA0, 0x03, 0x02, 0x01, 0x01, 0xA1, 0x04, 0x04, 0x02, 0x01, 0x02,
    ];
    let value = KrbFastArmor {
        armor_type: constants::FX_FAST_ARMOR_AP_REQUEST,
        armor_value: vec![0x01, 0x02],
    };
    round_trip(&bytes, &value, KrbFastArmor::decode, KrbFastArmor::encode);
}

#[test]
fn krb_fast_armor_ap_request_round_trip() {
    // Source: RFC 6113 5.4.1.1 — armor-value is the DER encoding of an AP-REQ
    // (RFC 4120 5.5.1) whose ticket is the armor TGT.
    let (der, value) = armor();
    round_trip(&der, &value, KrbFastArmor::decode, KrbFastArmor::encode);
    let (ap_der, ap_value) = armor_ap_req();
    round_trip(&ap_der, &ap_value, ApReq::decode, ApReq::encode);
    assert_eq!(ApReq::decode(&value.armor_value).unwrap(), ap_value);
}

#[test]
fn krb_fast_armor_unknown_type_preserved() {
    // Source: RFC 6113 5.4.1 ("If a FAST KDC receives an unknown armor type it
    // MUST respond with KDC_ERR_PREAUTH_FAILED" — a KDC decision, so the codec
    // keeps the value), 7.2 (a signed 32-bit integer). Int32 extremes:
    // -2147483648 = 80 00 00 00 and 2147483647 = 7F FF FF FF (X.690 8.3.3).
    for (contents, armor_type) in [
        (vec![0x80, 0x00, 0x00, 0x00], i32::MIN),
        (vec![0x7F, 0xFF, 0xFF, 0xFF], i32::MAX),
        (vec![0x00], 0), // 0 is "Reserved" in 7.2
    ] {
        let der = seq(&[&ctx(0, &int(&contents)), &ctx(1, &octets(b"x"))]);
        let value = KrbFastArmor {
            armor_type,
            armor_value: b"x".to_vec(),
        };
        round_trip(&der, &value, KrbFastArmor::decode, KrbFastArmor::encode);
    }
}

// ===========================================================================
// PA-FX-FAST-REQUEST / KrbFastArmoredReq — RFC 6113 5.4.2
// ===========================================================================

#[test]
fn pa_fx_fast_request_literal_vector_tgs_form() {
    // Source: RFC 6113 5.4.2 (PA-FX-FAST-REQUEST ::= CHOICE { armored-data [0]
    // KrbFastArmoredReq, ... }; KrbFastArmoredReq with armor [0] absent, as in
    // a TGS request using implicit armor), Appendix B (EXPLICIT TAGS);
    // X.690 8.13 (the choice is encoded as its alternative, tag [0]).
    // cksumtype 16 / 12 octets and etype 18: RFC 3962 §7.
    #[rustfmt::skip]
    let bytes = [
        0xA0, 0x2C,                         // armored-data [0], 44 octets
          0x30, 0x2A,                       // KrbFastArmoredReq, 42 octets
            0xA1, 0x17,                     // req-checksum [1], 23 octets
              0x30, 0x15,                   // Checksum, 21 octets
                0xA0, 0x03, 0x02, 0x01, 0x10,           // cksumtype [0] 16
                0xA1, 0x0E, 0x04, 0x0C,                 // checksum [1], 12 octets
                  0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                  0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            0xA2, 0x0F,                     // enc-fast-req [2], 15 octets
              0x30, 0x0D,                   // EncryptedData, 13 octets
                0xA0, 0x03, 0x02, 0x01, 0x12,           // etype [0] 18
                0xA2, 0x06, 0x04, 0x04,                 // cipher [2], 4 octets
                  0xC1, 0xC2, 0xC3, 0xC4,
    ];
    let value = PaFxFastRequest::ArmoredData(KrbFastArmoredReq {
        armor: None,
        req_checksum: Checksum {
            cksumtype: 16,
            checksum: (0x01..=0x0C).collect(),
        },
        enc_fast_req: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![0xC1, 0xC2, 0xC3, 0xC4],
        },
    });
    round_trip(
        &bytes,
        &value,
        PaFxFastRequest::decode,
        PaFxFastRequest::encode,
    );
    // The literal agrees with the clause-by-clause builders in `common`.
    let (sum_der, _) = checksum(0x01);
    let (enc_der, _) = enc(&[0xC1, 0xC2, 0xC3, 0xC4]);
    assert_eq!(
        bytes.as_slice(),
        ctx(0, &seq(&[&ctx(1, &sum_der), &ctx(2, &enc_der)])).as_slice()
    );
}

#[test]
fn pa_fx_fast_request_as_form_round_trip() {
    // Source: RFC 6113 5.4.2 ("In an AS request, the armor field in the
    // KrbFastArmoredReq structure MUST be present"), 5.4.1.1 (AP-REQ armor).
    let (der, value) = armored_req_as();
    round_trip(
        &der,
        &value,
        KrbFastArmoredReq::decode,
        KrbFastArmoredReq::encode,
    );
    let (der, value) = pa_fx_fast_request_as();
    round_trip(
        &der,
        &value,
        PaFxFastRequest::decode,
        PaFxFastRequest::encode,
    );
}

// ===========================================================================
// KrbFastReq / FastOptions — RFC 6113 5.4.2
// ===========================================================================

#[test]
fn krb_fast_req_round_trip() {
    // Source: RFC 6113 5.4.2 (KrbFastReq ::= SEQUENCE { fast-options [0],
    // padata [1] SEQUENCE OF PA-DATA, req-body [2] KDC-REQ-BODY, ... }),
    // 5.4.6 (PA-ENCRYPTED-CHALLENGE 138), 5.2 (PA-FX-COOKIE 133).
    let (der, value) = krb_fast_req();
    round_trip(&der, &value, KrbFastReq::decode, KrbFastReq::encode);
    // The inner body re-encodes to exactly its own octets (RFC 6113 5.4.2:
    // checksums over the KDC-REQ-BODY use the one in the FAST structure).
    let (body_der, body_value) = as_req_body();
    assert_eq!(value.req_body.encode().unwrap(), body_der);
    assert_eq!(value.req_body, body_value);
    // The PA-ENCRYPTED-CHALLENGE value is an EncryptedChallenge (5.4.6).
    let challenge = EncryptedChallenge::decode(&value.padata[0].padata_value).unwrap();
    assert_eq!(challenge.etype, 18);
}

#[test]
fn krb_fast_req_empty_padata_accepted() {
    // Source: RFC 6113 5.4.2 — padata [1] SEQUENCE OF PA-DATA is required but
    // has no size constraint, so an empty SEQUENCE OF (30 00, X.690 8.10.2
    // "zero, one or more") is a valid value and is preserved.
    let (body_der, body_value) = as_req_body();
    let der = seq(&[
        &ctx(0, &flags32([0x00, 0x00, 0x00, 0x00])),
        &ctx(1, &seq(&[])),
        &ctx(2, &body_der),
    ]);
    let value = KrbFastReq {
        fast_options: FastOptions::empty(),
        padata: vec![],
        req_body: body_value,
    };
    round_trip(&der, &value, KrbFastReq::decode, KrbFastReq::encode);
}

#[test]
fn fast_options_bits_and_unknown_bits_preserved() {
    // Source: RFC 6113 5.4.2 / 7.3 (hide-client-names = bit 1; bit 16
    // kdc-follow-referrals reserved; bits 1-15 critical, 16+ non-critical);
    // RFC 4120 5.2.8 + X.690 8.6.2.1 (bit n → mask 0x80000000 >> n).
    assert_eq!(FastOptions::HIDE_CLIENT_NAMES.0.bits(), 0x4000_0000);
    assert!(FastOptions::HIDE_CLIENT_NAMES.0.is_set(1));
    // hide-client-names(1) + unknown critical bit 15 (0x00010000) + reserved
    // bit 16 (0x00008000): 40 01 80 00. All bits survive the round trip — the
    // KDC, not the codec, decides on unsupported critical options.
    let (body_der, body_value) = as_req_body();
    let der = seq(&[
        &ctx(0, &flags32([0x40, 0x01, 0x80, 0x00])),
        &ctx(1, &seq(&[])),
        &ctx(2, &body_der),
    ]);
    let value = KrbFastReq {
        fast_options: FastOptions(KerberosFlags::from_bits(0x4001_8000)),
        padata: vec![],
        req_body: body_value,
    };
    round_trip(&der, &value, KrbFastReq::decode, KrbFastReq::encode);
    let options = KrbFastReq::decode(&der).unwrap().fast_options;
    assert!(options.contains(FastOptions::HIDE_CLIENT_NAMES));
    assert!(options.0.is_set(15) && options.0.is_set(16));
}

// ===========================================================================
// PA-FX-FAST-REPLY / KrbFastArmoredRep — RFC 6113 5.4.3
// ===========================================================================

#[test]
fn pa_fx_fast_reply_literal_vector() {
    // Source: RFC 6113 5.4.3 (PA-FX-FAST-REPLY ::= CHOICE { armored-data [0]
    // KrbFastArmoredRep, ... }; KrbFastArmoredRep ::= SEQUENCE { enc-fast-rep
    // [0] EncryptedData, ... }); X.690 8.13, 8.14.3. etype 18: RFC 3962 §7.
    #[rustfmt::skip]
    let bytes = [
        0xA0, 0x13,                         // armored-data [0], 19 octets
          0x30, 0x11,                       // KrbFastArmoredRep, 17 octets
            0xA0, 0x0F,                     // enc-fast-rep [0], 15 octets
              0x30, 0x0D,                   // EncryptedData, 13 octets
                0xA0, 0x03, 0x02, 0x01, 0x12,           // etype [0] 18
                0xA2, 0x06, 0x04, 0x04,                 // cipher [2], 4 octets
                  0xC1, 0xC2, 0xC3, 0xC4,
    ];
    let rep = KrbFastArmoredRep {
        enc_fast_rep: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![0xC1, 0xC2, 0xC3, 0xC4],
        },
    };
    round_trip(
        &bytes,
        &PaFxFastReply::ArmoredData(rep.clone()),
        PaFxFastReply::decode,
        PaFxFastReply::encode,
    );
    // The armored-data contents alone are the KrbFastArmoredRep.
    round_trip(
        &bytes[2..],
        &rep,
        KrbFastArmoredRep::decode,
        KrbFastArmoredRep::encode,
    );
}

#[test]
fn pa_fx_fast_reply_round_trip() {
    // Source: RFC 6113 5.4.3.
    let (der, value) = pa_fx_fast_reply();
    round_trip(&der, &value, PaFxFastReply::decode, PaFxFastReply::encode);
}

// ===========================================================================
// KrbFastResponse / KrbFastFinished — RFC 6113 5.4.3, 5.4.4
// ===========================================================================

#[test]
fn krb_fast_finished_round_trip() {
    // Source: RFC 6113 5.4.3 (KrbFastFinished ::= SEQUENCE { timestamp [0]
    // KerberosTime, usec [1] Microseconds, crealm [2] Realm, cname [3]
    // PrincipalName, ticket-checksum [4] Checksum, ... }).
    let (der, value) = krb_fast_finished();
    round_trip(
        &der,
        &value,
        KrbFastFinished::decode,
        KrbFastFinished::encode,
    );
}

#[test]
fn krb_fast_response_as_reply_round_trip() {
    // Source: RFC 6113 5.4.3 (KrbFastResponse ::= SEQUENCE { padata [0],
    // strengthen-key [1] EncryptionKey OPTIONAL, finished [2] KrbFastFinished
    // OPTIONAL, nonce [3] UInt32, ... }); AS reply with strengthen-key and
    // finished present; 5.4.6 (the KDC's PA-ENCRYPTED-CHALLENGE).
    let (der, value) = krb_fast_response_as();
    round_trip(
        &der,
        &value,
        KrbFastResponse::decode,
        KrbFastResponse::encode,
    );
}

#[test]
fn krb_fast_response_error_round_trip_and_pa_fx_error() {
    // Source: RFC 6113 5.4.4 (the KrbFastResponse of an error carries
    // PA-FX-ERROR — "the ASN.1 DER encoding of the type KRB-ERROR", e-data
    // absent — plus the cookie and PA-ETYPE-INFO2); 5.4.3 (strengthen-key and
    // finished absent in an error).
    let (der, value) = krb_fast_response_error();
    round_trip(
        &der,
        &value,
        KrbFastResponse::decode,
        KrbFastResponse::encode,
    );
    let (error_der, error_value) = inner_krb_error();
    let fx_error = &value.padata[0];
    assert_eq!(fx_error.padata_type, constants::PA_FX_ERROR);
    assert_eq!(fx_error.padata_value, error_der);
    let inner = KrbError::decode(&fx_error.padata_value).unwrap();
    assert_eq!(inner, error_value);
    assert_eq!(inner.e_data, None);
    // PA-ETYPE-INFO2 inside the FAST response (RFC 4120 5.2.7.5).
    let info = EtypeInfo2::decode(&value.padata[2].padata_value).unwrap();
    assert_eq!(info.0[0].etype, 18);
}

#[test]
fn encrypted_challenge_is_encrypted_data() {
    // Source: RFC 6113 5.4.6 (EncryptedChallenge ::= EncryptedData, the
    // encryption of a PA-ENC-TS-ENC) and RFC 4120 5.2.7.2 (PA-ENC-TS-ENC).
    let (der, value) = enc(&[0x11, 0x22, 0x33]);
    round_trip(
        &der,
        &value,
        EncryptedChallenge::decode,
        EncryptedChallenge::encode,
    );
    // The plaintext type the challenge key protects (decoded after keyd
    // decrypts): PA-ENC-TS-ENC { patimestamp [0] }.
    let ts = seq(&[&ctx(0, &gtime(b"20261113090512Z"))]);
    let plain = PaEncTsEnc::decode(&ts).unwrap();
    assert_eq!(plain.patimestamp, ktime("20261113090512Z"));
}

// ===========================================================================
// Embedding — RFC 4120 5.2.7 / 5.9.1 with RFC 6113 5.4.2 / 5.4.4
// ===========================================================================

#[test]
fn as_req_carries_pa_fx_fast_request() {
    // Source: RFC 6113 5.4.2 (PA-FX-FAST padata-value = DER of
    // PA-FX-FAST-REQUEST; the outer body "SHOULD be filled in"), 5.4.5 (the
    // outer AS request typically carries only PA-FX-FAST); RFC 4120 5.4.1.
    // padata-type 136 = 0x88 → INTEGER 00 88.
    let (fast_der, fast_value) = pa_fx_fast_request_as();
    let (body_der, body_value) = as_req_body();
    let der = app(
        10,
        &seq(&[
            &ctx(1, &int(&[0x05])),
            &ctx(2, &int(&[0x0A])),
            &ctx(3, &seq(&[&pa_der(&[0x00, 0x88], &fast_der)])),
            &ctx(4, &body_der),
        ]),
    );
    let value = AsReq(KdcReq {
        padata: Some(vec![PaData {
            padata_type: constants::PA_FX_FAST,
            padata_value: fast_der,
        }]),
        req_body: body_value,
    });
    round_trip(&der, &value, AsReq::decode, AsReq::encode);
    let pa = &value.0.padata.as_ref().unwrap()[0];
    assert_eq!(
        PaFxFastRequest::decode(&pa.padata_value).unwrap(),
        fast_value
    );
}

#[test]
fn krb_error_method_data_carries_pa_fx_fast_reply() {
    // Source: RFC 6113 5.4.4 (the KRB-ERROR e-data is METHOD-DATA containing
    // a PA-FX-FAST whose value is a PA-FX-FAST-REPLY); RFC 4120 5.9.1.
    let (reply_der, reply_value) = pa_fx_fast_reply();
    let method_data = seq(&[&pa_der(&[0x00, 0x88], &reply_der)]);
    let (_, mut outer) = inner_krb_error();
    outer.e_data = Some(method_data.clone());
    let decoded = KrbError::decode(&outer.encode().unwrap()).unwrap();
    let methods = MethodData::decode(decoded.e_data.as_ref().unwrap()).unwrap();
    assert_eq!(methods.0[0].padata_type, constants::PA_FX_FAST);
    assert_eq!(
        PaFxFastReply::decode(&methods.0[0].padata_value).unwrap(),
        reply_value
    );
    // Advertisement: PA-FX-FAST with an empty pa-value (5.4.2 "KDCs MUST send
    // the advertisement of PA-FX-FAST with an empty pa-value") is preserved.
    let advert = seq(&[&pa_der(&[0x00, 0x88], &[])]);
    round_trip(
        &advert,
        &MethodData(vec![PaData {
            padata_type: constants::PA_FX_FAST,
            padata_value: vec![],
        }]),
        MethodData::decode,
        MethodData::encode,
    );
}

// ===========================================================================
// Rejections: CHOICE alternatives — RFC 6113 Appendix B; X.690 8.13
// ===========================================================================

#[test]
fn choice_rejects_undefined_alternatives() {
    // Source: RFC 6113 5.4.2 / 5.4.3 — only armored-data [0] is defined; the
    // extension marker is not taken as permission (docs/questions/Q-032).
    let (req_der, _) = armored_req_as();
    let (rep_der, _) = pa_fx_fast_reply();
    let rep_inner = rep_der[2..].to_vec();
    // [1] KrbFastArmoredReq: a context tag selecting no alternative.
    assert_eq!(
        PaFxFastRequest::decode(&ctx(1, &req_der)),
        Err(Error::UnknownChoiceAlternative)
    );
    assert_eq!(
        PaFxFastReply::decode(&ctx(1, &rep_inner)),
        Err(Error::UnknownChoiceAlternative)
    );
    // The bare SEQUENCE without its [0] alternative tag.
    assert_eq!(
        PaFxFastRequest::decode(&req_der),
        Err(Error::UnknownChoiceAlternative)
    );
    assert_eq!(
        PaFxFastReply::decode(&rep_inner),
        Err(Error::UnknownChoiceAlternative)
    );
    // An APPLICATION-class tag (X.690 Table 1 class 01) is not [0].
    assert_eq!(
        PaFxFastRequest::decode(&app(0, &req_der)),
        Err(Error::UnknownChoiceAlternative)
    );
    // A primitive [0] (0x80) breaks EXPLICIT tagging (X.690 8.14.3).
    assert_eq!(
        PaFxFastRequest::decode(&tlv(0x80, &[0x00])),
        Err(Error::Der(parse_asn1::Error::PrimitiveConstructedMismatch))
    );
}

#[test]
fn request_and_reply_are_not_interchangeable() {
    // Source: RFC 6113 5.4.2 / 5.4.3 — KrbFastArmoredRep defines only [0];
    // KrbFastArmoredReq's [0] is a KrbFastArmor, which defines [0] and [1].
    let (req_der, _) = pa_fx_fast_request_as();
    let (rep_der, _) = pa_fx_fast_reply();
    assert_eq!(PaFxFastReply::decode(&req_der), Err(Error::UnknownField));
    assert_eq!(PaFxFastRequest::decode(&rep_der), Err(Error::UnknownField));
}

// ===========================================================================
// Rejections: components — X.690 8.9.2 / 8.9.3; RFC 6113 Appendix B
// ===========================================================================

/// KrbFastArmoredReq components, separately, so tests can drop / reorder.
fn armored_req_parts() -> Vec<Vec<u8>> {
    let (armor_der, _) = armor();
    let (sum_der, _) = checksum(0x01);
    let (enc_der, _) = enc(&[0xC1, 0xC2]);
    vec![ctx(0, &armor_der), ctx(1, &sum_der), ctx(2, &enc_der)]
}

#[test]
fn krb_fast_armored_req_component_rules() {
    // Source: RFC 6113 5.4.2 — req-checksum [1] and enc-fast-req [2] are not
    // OPTIONAL; components in definition order, each once (X.690 8.9.2/8.9.3);
    // only [0]..[2] are defined (an undefined [3] is rejected, Q-032).
    let ok = seq_of_parts(&armored_req_parts());
    assert!(KrbFastArmoredReq::decode(&ok).is_ok());

    let mut parts = armored_req_parts();
    parts.remove(1);
    assert_eq!(
        KrbFastArmoredReq::decode(&seq_of_parts(&parts)),
        Err(Error::MissingField)
    );
    let mut parts = armored_req_parts();
    parts.remove(2);
    assert_eq!(
        KrbFastArmoredReq::decode(&seq_of_parts(&parts)),
        Err(Error::MissingField)
    );
    let mut parts = armored_req_parts();
    parts.swap(1, 2);
    assert_eq!(
        KrbFastArmoredReq::decode(&seq_of_parts(&parts)),
        Err(Error::FieldOutOfOrder)
    );
    let mut parts = armored_req_parts();
    parts.insert(1, parts[0].clone());
    assert_eq!(
        KrbFastArmoredReq::decode(&seq_of_parts(&parts)),
        Err(Error::DuplicateField)
    );
    let mut parts = armored_req_parts();
    parts.push(ctx(3, &int(&[0x00])));
    assert_eq!(
        KrbFastArmoredReq::decode(&seq_of_parts(&parts)),
        Err(Error::UnknownField)
    );
    let mut parts = armored_req_parts();
    parts.push(int(&[0x00]));
    assert_eq!(
        KrbFastArmoredReq::decode(&seq_of_parts(&parts)),
        Err(Error::ExpectedContextTag)
    );
    // Not a SEQUENCE at all.
    assert_eq!(
        KrbFastArmoredReq::decode(&octets(&[0x30, 0x00])),
        Err(Error::ExpectedSequence)
    );
}

#[test]
fn krb_fast_armor_rejections() {
    // Source: RFC 6113 5.4.1 — armor-type [0] Int32 (RFC 4120 5.2.4 range),
    // armor-value [1] OCTET STRING, both required; only [0], [1] defined.
    // 2^31 = 00 80 00 00 00 (X.690 8.3.2) is outside Int32.
    assert_eq!(
        KrbFastArmor::decode(&seq(&[
            &ctx(0, &int(&[0x00, 0x80, 0x00, 0x00, 0x00])),
            &ctx(1, &octets(&[]))
        ])),
        Err(Error::Int32OutOfRange)
    );
    assert_eq!(
        KrbFastArmor::decode(&seq(&[&ctx(0, &int(&[0x01])), &ctx(1, &int(&[0x01]))])),
        Err(Error::ExpectedOctetString)
    );
    // ENUMERATED (universal 10, 0x0A) is not an INTEGER.
    assert_eq!(
        KrbFastArmor::decode(&seq(&[&ctx(0, &tlv(0x0A, &[0x01])), &ctx(1, &octets(&[]))])),
        Err(Error::ExpectedInteger)
    );
    assert_eq!(
        KrbFastArmor::decode(&seq(&[&ctx(0, &int(&[0x01]))])),
        Err(Error::MissingField)
    );
    assert_eq!(
        KrbFastArmor::decode(&seq(&[
            &ctx(0, &int(&[0x01])),
            &ctx(1, &octets(&[])),
            &ctx(2, &octets(&[]))
        ])),
        Err(Error::UnknownField)
    );
}

#[test]
fn krb_fast_req_rejections() {
    // Source: RFC 6113 5.4.2; RFC 4120 5.2.8 (KerberosFlags, exactly 32 bits
    // here: 24 bits rejected), 5.2.7 (PA-DATA).
    let (body_der, _) = as_req_body();
    let with = |options: Vec<u8>, padata: Option<Vec<u8>>, extra: Option<Vec<u8>>| {
        let mut parts = vec![ctx(0, &options)];
        if let Some(pa) = padata {
            parts.push(ctx(1, &pa));
        }
        parts.push(ctx(2, &body_der));
        if let Some(extra) = extra {
            parts.push(extra);
        }
        seq_of_parts(&parts)
    };
    let flags = flags32([0, 0, 0, 0]);
    let empty = seq(&[]);
    assert!(KrbFastReq::decode(&with(flags.clone(), Some(empty.clone()), None)).is_ok());
    assert_eq!(
        KrbFastReq::decode(&with(
            tlv(0x03, &[0x00, 0x40, 0x00, 0x00]),
            Some(empty.clone()),
            None
        )),
        Err(Error::KerberosFlagsLength)
    );
    assert_eq!(
        KrbFastReq::decode(&with(octets(&[0, 0, 0, 0]), Some(empty.clone()), None)),
        Err(Error::ExpectedBitString)
    );
    assert_eq!(
        KrbFastReq::decode(&with(flags.clone(), None, None)),
        Err(Error::MissingField)
    );
    assert_eq!(
        KrbFastReq::decode(&with(
            flags.clone(),
            Some(empty),
            Some(ctx(3, &int(&[0x00])))
        )),
        Err(Error::UnknownField)
    );
    // A PA-DATA with the forbidden [0] tag (RFC 4120 5.2.7: "first tag is
    // [1], not [0]") inside the FAST padata.
    let bad_pa = seq(&[&seq(&[&ctx(0, &int(&[0x02])), &ctx(2, &octets(&[]))])]);
    assert_eq!(
        KrbFastReq::decode(&with(flags, Some(bad_pa), None)),
        Err(Error::UnknownField)
    );
}

#[test]
fn krb_fast_response_rejections() {
    // Source: RFC 6113 5.4.3 — padata [0] and nonce [3] required, nonce is a
    // UInt32 (RFC 4120 5.2.4: -1 = FF and 2^32 = 01 00 00 00 00 rejected),
    // order [0] < [1] < [2] < [3], only [0]..[3] defined.
    let (key_der, _) = strengthen_key(&[0x5A; 32]);
    let (finished_der, _) = krb_fast_finished();
    let padata = ctx(0, &seq(&[]));
    let nonce = ctx(3, &int(&[0x01]));
    assert!(KrbFastResponse::decode(&seq(&[&padata, &nonce])).is_ok());
    assert_eq!(
        KrbFastResponse::decode(&seq(&[&padata])),
        Err(Error::MissingField)
    );
    assert_eq!(
        KrbFastResponse::decode(&seq(&[&nonce])),
        Err(Error::MissingField)
    );
    for bad in [vec![0xFF], vec![0x01, 0x00, 0x00, 0x00, 0x00]] {
        assert_eq!(
            KrbFastResponse::decode(&seq(&[&padata, &ctx(3, &int(&bad))])),
            Err(Error::UInt32OutOfRange)
        );
    }
    assert_eq!(
        KrbFastResponse::decode(&seq(&[
            &padata,
            &ctx(2, &finished_der),
            &ctx(1, &key_der),
            &nonce
        ])),
        Err(Error::FieldOutOfOrder)
    );
    assert_eq!(
        KrbFastResponse::decode(&seq(&[&padata, &nonce, &ctx(4, &int(&[0x00]))])),
        Err(Error::UnknownField)
    );
}

#[test]
fn krb_fast_finished_rejections() {
    // Source: RFC 6113 5.4.3; RFC 4120 5.2.3 (no fractional seconds), 5.2.4
    // (Microseconds 0..999999: 1000000 = 0F 42 40), 5.2.1 (IA5 realm).
    let (sum_der, _) = checksum(0xB0);
    let parts = || {
        vec![
            ctx(0, &gtime(b"20261113090512Z")),
            ctx(1, &int(&[0x00])),
            ctx(2, &gstring(b"EXAMPLE.ORG")),
            ctx(3, &pname_der(&[0x01], &["alice"])),
            ctx(4, &sum_der),
        ]
    };
    assert!(KrbFastFinished::decode(&seq_of_parts(&parts())).is_ok());
    let mut p = parts();
    p[0] = ctx(0, &gtime(b"20261113090512.5Z"));
    assert_eq!(
        KrbFastFinished::decode(&seq_of_parts(&p)),
        Err(Error::FractionalKerberosTime)
    );
    let mut p = parts();
    p[1] = ctx(1, &int(&[0x0F, 0x42, 0x40]));
    assert_eq!(
        KrbFastFinished::decode(&seq_of_parts(&p)),
        Err(Error::MicrosecondsOutOfRange)
    );
    let mut p = parts();
    p[2] = ctx(2, &gstring(&[0x45, 0xC3, 0xA9]));
    assert_eq!(
        KrbFastFinished::decode(&seq_of_parts(&p)),
        Err(Error::NonIa5Character)
    );
    let mut p = parts();
    p.pop();
    assert_eq!(
        KrbFastFinished::decode(&seq_of_parts(&p)),
        Err(Error::MissingField)
    );
    let mut p = parts();
    p.push(ctx(5, &int(&[0x00])));
    assert_eq!(
        KrbFastFinished::decode(&seq_of_parts(&p)),
        Err(Error::UnknownField)
    );
}

#[test]
fn krb_fast_armored_rep_rejections() {
    // Source: RFC 6113 5.4.3 — enc-fast-rep [0] required and the only
    // defined component.
    let (enc_der, _) = enc(&[0x01]);
    assert_eq!(
        KrbFastArmoredRep::decode(&seq(&[])),
        Err(Error::MissingField)
    );
    assert_eq!(
        KrbFastArmoredRep::decode(&seq(&[&ctx(0, &enc_der), &ctx(1, &int(&[0x00]))])),
        Err(Error::UnknownField)
    );
}

// ===========================================================================
// Rejections: resource bounds — crate::limits (docs/CLEAN-ROOM.md)
// ===========================================================================

#[test]
fn fast_padata_is_bounded_on_decode_and_encode() {
    // limits::MAX_PADATA on RFC 6113 5.4.2 KrbFastReq padata and 5.4.3
    // KrbFastResponse padata (same bound as the outer padata they replace).
    let pa = pa_der(&[0x00, 0x85], &[0x00]);
    let at: Vec<&[u8]> = vec![pa.as_slice(); limits::MAX_PADATA];
    let over: Vec<&[u8]> = vec![pa.as_slice(); limits::MAX_PADATA + 1];
    let (body_der, body_value) = as_req_body();
    let req = |list: &[&[u8]]| {
        seq(&[
            &ctx(0, &flags32([0, 0, 0, 0])),
            &ctx(1, &seq(list)),
            &ctx(2, &body_der),
        ])
    };
    assert!(KrbFastReq::decode(&req(&at)).is_ok());
    assert_eq!(KrbFastReq::decode(&req(&over)), Err(Error::TooManyElements));
    let rep = |list: &[&[u8]]| seq(&[&ctx(0, &seq(list)), &ctx(3, &int(&[0x01]))]);
    assert!(KrbFastResponse::decode(&rep(&at)).is_ok());
    assert_eq!(
        KrbFastResponse::decode(&rep(&over)),
        Err(Error::TooManyElements)
    );
    // Encoding refuses what decoding would refuse.
    let one = PaData {
        padata_type: constants::PA_FX_COOKIE,
        padata_value: vec![0x00],
    };
    let too_many = vec![one; limits::MAX_PADATA + 1];
    let fast_req = KrbFastReq {
        fast_options: FastOptions::empty(),
        padata: too_many.clone(),
        req_body: body_value,
    };
    assert_eq!(fast_req.encode(), Err(Error::TooManyElements));
    let fast_rep = KrbFastResponse {
        padata: too_many,
        strengthen_key: None,
        finished: None,
        nonce: 1,
    };
    assert_eq!(fast_rep.encode().map(|_| ()), Err(Error::TooManyElements));
}

#[test]
fn rejects_input_over_size_bound() {
    // limits::MAX_MESSAGE_LEN is checked before any parsing.
    let big = vec![0u8; limits::MAX_MESSAGE_LEN + 1];
    assert_eq!(PaFxFastRequest::decode(&big), Err(Error::MessageTooLarge));
    assert_eq!(KrbFastResponse::decode(&big), Err(Error::MessageTooLarge));
}

// ===========================================================================
// Rejections: framing and BER — RFC 4120 5.1.1 (DER only); X.690 8.1.3, 10.1
// ===========================================================================

#[test]
fn rejects_trailing_data() {
    // After the top-level value, and after the single value inside the
    // explicit armored-data [0] (X.690 8.14.3: contents are exactly the
    // complete base encoding).
    let (der, _) = pa_fx_fast_reply();
    let mut trailing = der.clone();
    trailing.push(0x00);
    assert_eq!(
        PaFxFastReply::decode(&trailing),
        Err(Error::Der(parse_asn1::Error::TrailingData))
    );
    let inner = &der[2..];
    let doubled = ctx(0, &cat(&[inner, &[0x05, 0x00]]));
    assert_eq!(
        PaFxFastReply::decode(&doubled),
        Err(Error::Der(parse_asn1::Error::TrailingData))
    );
}

#[test]
fn rejects_truncation() {
    // X.690 8.1.3.3: the declared length must be present.
    let (der, _) = pa_fx_fast_request_as();
    assert_eq!(
        PaFxFastRequest::decode(&der[..der.len() - 1]),
        Err(Error::Der(parse_asn1::Error::LengthExceedsInput))
    );
    for len in 0..der.len() {
        assert!(
            PaFxFastRequest::decode(&der[..len]).is_err(),
            "prefix {len}"
        );
    }
    let (der, _) = krb_fast_response_as();
    for len in 0..der.len() {
        assert!(
            KrbFastResponse::decode(&der[..len]).is_err(),
            "prefix {len}"
        );
    }
}

#[test]
fn rejects_ber_length_forms() {
    // RFC 4120 5.1.1: DER only — the BER leniency ("MAY accept such
    // encodings") is not taken. X.690 10.1: definite form, minimum octets.
    let (der, _) = pa_fx_fast_reply();
    // armored-data [0] with a short-form length (< 128, X.690 8.1.3.4).
    let short_length = der[1];
    assert_eq!(der[0], 0xA0);
    assert!(short_length < 0x80);
    assert!(PaFxFastReply::decode(&der).is_ok());
    // Indefinite length (8.1.3.6: single octet 0x80) + end-of-contents 00 00.
    let mut indefinite = vec![0xA0, 0x80];
    indefinite.extend_from_slice(&der[2..]);
    indefinite.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(
        PaFxFastReply::decode(&indefinite),
        Err(Error::Der(parse_asn1::Error::IndefiniteLength))
    );
    // Long form for a length that fits the short form (81 L instead of L).
    let mut long_form = vec![0xA0, 0x81, short_length];
    long_form.extend_from_slice(&der[2..]);
    assert_eq!(
        PaFxFastReply::decode(&long_form),
        Err(Error::Der(parse_asn1::Error::NonMinimalLength))
    );
    // Non-minimal INTEGER armor-type 00 01 (X.690 8.3.2).
    let bad_int = seq(&[&ctx(0, &int(&[0x00, 0x01])), &ctx(1, &octets(&[]))]);
    assert_eq!(
        KrbFastArmor::decode(&bad_int),
        Err(Error::Der(parse_asn1::Error::NonMinimalInteger))
    );
    assert!(PaFxFastRequest::decode(&[]).is_err());
}

// ===========================================================================
// Key material — RFC 6113 5.4.3 strengthen-key; RFC 4120 5.2.9; docs/CLEAN-ROOM.md
// ===========================================================================

/// A KrbFastResponse whose only secret is a strengthen-key of 32 × 0x5A
/// ("90" decimal, "5a" hex) — easy to spot if it leaked.
fn marker_response() -> KrbFastResponse {
    KrbFastResponse {
        padata: vec![],
        strengthen_key: Some(EncryptionKey {
            keytype: 18,
            keyvalue: KeyValue::new(vec![0x5A; 32]),
        }),
        finished: None,
        nonce: 1,
    }
}

fn assert_no_key_text(text: &str) {
    for needle in ["90", "5a", "5A", "Z"] {
        assert!(
            !text.contains(needle),
            "formatted output leaks key material ({needle}): {text}"
        );
    }
}

#[test]
fn krb_fast_response_debug_redacts_strengthen_key() {
    // RFC 6113 5.4.3 (strengthen-key is key material); docs/CLEAN-ROOM.md
    let response = marker_response();
    let text = format!("{response:?}");
    assert!(text.contains("redacted"), "{text}");
    assert_no_key_text(&text);
    let text = format!("{response:#?}");
    assert_no_key_text(&text);
    // The full AS-reply response too (it has names and times, never key bytes).
    let (_, full) = krb_fast_response_as();
    let text = format!("{full:?}");
    assert!(text.contains("redacted"));
    assert!(!text.contains("32, 33, 34"), "{text}"); // key octets 0x20.. in decimal
}

#[test]
fn krb_fast_response_encoding_is_zeroizing() {
    // docs/CLEAN-ROOM.md: the DER of a key-bearing structure is key material and is
    // returned in a Zeroizing buffer (compile-time type check).
    let response = marker_response();
    let encoded: Zeroizing<Vec<u8>> = response.encode().unwrap();
    assert_eq!(KrbFastResponse::decode(&encoded).unwrap(), response);
}

#[test]
fn krb_fast_response_errors_carry_no_key_material() {
    // A strengthen-key followed by an undefined component [4]: the error is a
    // unit value that cannot contain key octets.
    let (key_der, _) = strengthen_key(&[0x5A; 32]);
    let bytes = seq(&[
        &ctx(0, &seq(&[])),
        &ctx(1, &key_der),
        &ctx(3, &int(&[0x01])),
        &ctx(4, &int(&[0x00])),
    ]);
    let err = KrbFastResponse::decode(&bytes).unwrap_err();
    assert_eq!(err, Error::UnknownField);
    assert_no_key_text(&format!("{err:?}"));
    assert_no_key_text(&err.to_string());
    // A malformed strengthen-key (keyvalue not an OCTET STRING).
    let bytes = seq(&[
        &ctx(0, &seq(&[])),
        &ctx(1, &seq(&[&ctx(0, &int(&[0x12])), &ctx(1, &int(&[0x5A]))])),
        &ctx(3, &int(&[0x01])),
    ]);
    let err = KrbFastResponse::decode(&bytes).unwrap_err();
    assert_eq!(err, Error::ExpectedOctetString);
    assert_no_key_text(&err.to_string());
}

// ===========================================================================
// Never-panic smoke over FAST seeds (complements the cargo-fuzz target)
// ===========================================================================

macro_rules! check {
    ($ty:ty, $data:expr) => {
        if let Ok(value) = <$ty>::decode($data) {
            let reencoded = value.encode().expect("accepted value must re-encode");
            assert_eq!(AsRef::<[u8]>::as_ref(&reencoded), $data);
        }
    };
}

fn fast_decoders(data: &[u8]) {
    check!(PaFxFastRequest, data);
    check!(KrbFastArmoredReq, data);
    check!(KrbFastArmor, data);
    check!(KrbFastReq, data);
    check!(PaFxFastReply, data);
    check!(KrbFastArmoredRep, data);
    check!(KrbFastResponse, data);
    check!(KrbFastFinished, data);
    check!(EncryptedChallenge, data);
}

fn fast_seeds() -> Vec<Vec<u8>> {
    vec![
        pa_fx_fast_request_as().0,
        krb_fast_req().0,
        pa_fx_fast_reply().0,
        krb_fast_response_as().0,
        krb_fast_response_error().0,
    ]
}

#[test]
fn fast_seeds_every_truncation_and_substitution_fails_closed() {
    // Every truncation and every single-octet substitution of each seed is fed
    // to every FAST decoder: Ok (then lossless) or Err, never a panic.
    const SUBSTITUTES: [u8; 10] = [0x00, 0x01, 0x1F, 0x30, 0x7F, 0x80, 0x81, 0x84, 0xA0, 0xFF];
    for seed in fast_seeds() {
        fast_decoders(&seed);
        for len in 0..seed.len() {
            fast_decoders(&seed[..len]);
        }
        let mut mutated = seed.clone();
        for i in 0..seed.len() {
            for &octet in &SUBSTITUTES {
                mutated[i] = octet;
                fast_decoders(&mutated);
            }
            mutated[i] = seed[i];
        }
    }
}
