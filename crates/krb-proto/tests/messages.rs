//! Message round trips for every in-scope RFC 4120 message type, with DER
//! hand-derived from the Appendix A module clause by clause (X.690 (02/2021)
//! encodings via the helpers in `common`). Each test names its clause.
//! No vector comes from any other implementation.

mod common;

use common::*;
use krb_proto::{
    constants, ApOptions, ApRep, ApReq, AsRep, AsReq, Authenticator, AuthorizationData,
    AuthorizationElement, Checksum, EncApRepPart, EncAsRepPart, EncKdcRepPart, EncTgsRepPart,
    EncTicketPart, EncryptedData, EncryptionKey, EtypeInfo2, EtypeInfo2Entry, HostAddress,
    HostAddresses, KdcOptions, KdcRep, KdcReq, KdcReqBody, KdcRequest, KerberosFlags, KeyValue,
    KrbError, LastReq, LastReqEntry, MethodData, Microseconds, PaData, PaEncTimestamp, TgsRep,
    TgsReq, Ticket, TicketFlags, TransitedEncoding,
};

/// A 32-octet session key (RFC 3962 §7: aes256 → 256-bit key).
fn key32(first: u8) -> Vec<u8> {
    (first..first + 32).collect()
}

/// EncryptionKey DER, RFC 4120 5.2.9.
fn key_der(keytype_contents: &[u8], key: &[u8]) -> Vec<u8> {
    seq(&[&ctx(0, &int(keytype_contents)), &ctx(1, &octets(key))])
}

fn key_value(keytype: i32, key: &[u8]) -> EncryptionKey {
    EncryptionKey {
        keytype,
        keyvalue: KeyValue::from_slice(key),
    }
}

// ===========================================================================
// Tickets — RFC 4120 5.3
// ===========================================================================

#[test]
fn ticket_round_trip() {
    // Source: RFC 4120 5.3 (Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0]
    // INTEGER (5), realm [1], sname [2], enc-part [3] }), 5.10 (tag 1).
    let (der, value) = tgt();
    round_trip(&der, &value, Ticket::decode, Ticket::encode);
    let (der, value) = service_ticket();
    round_trip(&der, &value, Ticket::decode, Ticket::encode);
}

#[test]
fn transited_encoding_round_trip() {
    // Source: RFC 4120 5.3 (TransitedEncoding ::= SEQUENCE { tr-type [0]
    // Int32, contents [1] OCTET STRING }), 7.5.5 (DOMAIN-X500-COMPRESS = 1).
    let bytes = seq(&[&ctx(0, &int(&[0x01])), &ctx(1, &octets(b"EXAMPLE.ORG,"))]);
    round_trip(
        &bytes,
        &TransitedEncoding {
            tr_type: constants::DOMAIN_X500_COMPRESS,
            contents: b"EXAMPLE.ORG,".to_vec(),
        },
        TransitedEncoding::decode,
        TransitedEncoding::encode,
    );
}

/// Full EncTicketPart (every OPTIONAL present). RFC 4120 5.3.
fn enc_ticket_part_full() -> (Vec<u8>, EncTicketPart) {
    let key = key32(0x00);
    // flags: forwardable(1) renewable(8) initial(9) pre-authent(10)
    //   → 0x40000000 | 0x00800000 | 0x00400000 | 0x00200000 = 40 E0 00 00.
    let inner_ad = seq(&[seq(&[&ctx(0, &int(&[0xEF])), &ctx(1, &octets(&[9, 9]))]).as_slice()]);
    let der = app(
        3,
        &seq(&[
            &ctx(0, &flags32([0x40, 0xE0, 0x00, 0x00])),
            &ctx(1, &key_der(&[0x12], &key)),
            &ctx(2, &gstring(b"EXAMPLE.ORG")),
            &ctx(3, &pname_der(&[0x01], &["alice"])),
            &ctx(4, &seq(&[&ctx(0, &int(&[0x01])), &ctx(1, &octets(&[]))])),
            &ctx(5, &gtime(b"20261113090000Z")),
            &ctx(6, &gtime(b"20261113090000Z")),
            &ctx(7, &gtime(b"20261113190000Z")),
            &ctx(8, &gtime(b"20261120090000Z")),
            &ctx(
                9,
                &seq(&[
                    seq(&[&ctx(0, &int(&[0x02])), &ctx(1, &octets(&[192, 0, 2, 7]))]).as_slice(),
                ]),
            ),
            &ctx(
                10,
                &seq(&[seq(&[&ctx(0, &int(&[0x01])), &ctx(1, &octets(&inner_ad))]).as_slice()]),
            ),
        ]),
    );
    let value = EncTicketPart {
        flags: TicketFlags::FORWARDABLE
            .union(TicketFlags::RENEWABLE)
            .union(TicketFlags::INITIAL)
            .union(TicketFlags::PRE_AUTHENT),
        key: key_value(18, &key),
        crealm: realm("EXAMPLE.ORG"),
        cname: pname(1, &["alice"]),
        transited: TransitedEncoding {
            tr_type: 1,
            contents: vec![],
        },
        authtime: ktime("20261113090000Z"),
        starttime: Some(ktime("20261113090000Z")),
        endtime: ktime("20261113190000Z"),
        renew_till: Some(ktime("20261120090000Z")),
        caddr: Some(HostAddresses(vec![HostAddress {
            addr_type: 2,
            address: vec![192, 0, 2, 7],
        }])),
        authorization_data: Some(AuthorizationData(vec![AuthorizationElement {
            ad_type: 1,
            ad_data: inner_ad.clone(),
        }])),
    };
    (der, value)
}

#[test]
fn enc_ticket_part_full_round_trip() {
    // Source: RFC 4120 5.3 (EncTicketPart ::= [APPLICATION 3] SEQUENCE, tags
    // [0]..[10]), 5.10 (tag 3), 5.2.6.1 (AD-IF-RELEVANT, ad-type 1).
    let (der, value) = enc_ticket_part_full();
    round_trip(&der, &value, EncTicketPart::decode, EncTicketPart::encode);
}

#[test]
fn enc_ticket_part_minimal_round_trip() {
    // Source: RFC 4120 5.3 — only the components without OPTIONAL.
    let key = key32(0x40);
    let der = app(
        3,
        &seq(&[
            &ctx(0, &flags32([0x00, 0x00, 0x00, 0x00])),
            &ctx(1, &key_der(&[0x11], &key[..16])),
            &ctx(2, &gstring(b"EXAMPLE.ORG")),
            &ctx(3, &pname_der(&[0x01], &["bob"])),
            &ctx(4, &seq(&[&ctx(0, &int(&[0x01])), &ctx(1, &octets(&[]))])),
            &ctx(5, &gtime(b"20261113090000Z")),
            &ctx(7, &gtime(b"20261113190000Z")),
        ]),
    );
    let value = EncTicketPart {
        flags: TicketFlags::empty(),
        key: key_value(17, &key[..16]),
        crealm: realm("EXAMPLE.ORG"),
        cname: pname(1, &["bob"]),
        transited: TransitedEncoding {
            tr_type: 1,
            contents: vec![],
        },
        authtime: ktime("20261113090000Z"),
        starttime: None,
        endtime: ktime("20261113190000Z"),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    round_trip(&der, &value, EncTicketPart::decode, EncTicketPart::encode);
}

// ===========================================================================
// KDC exchange — RFC 4120 5.4
// ===========================================================================

/// AS-REQ with PA-ENC-TIMESTAMP. RFC 4120 5.4.1, 5.2.7.2.
fn as_req() -> (Vec<u8>, AsReq) {
    let ts_cipher: Vec<u8> = (0x40..0x50).collect();
    let padata_value = enc_data_der(&[0x12], None, &ts_cipher);
    let pa = seq(&[&ctx(1, &int(&[0x02])), &ctx(2, &octets(&padata_value))]);
    // kdc-options forwardable(1) renewable(8) renewable-ok(27) = 40 80 00 10.
    // nonce 0x9C3A5E21: top bit set → leading 00 (X.690 8.3.2).
    let body = seq(&[
        &ctx(0, &flags32([0x40, 0x80, 0x00, 0x10])),
        &ctx(1, &pname_der(&[0x01], &["alice"])),
        &ctx(2, &gstring(b"EXAMPLE.ORG")),
        &ctx(3, &pname_der(&[0x02], &["krbtgt", "EXAMPLE.ORG"])),
        &ctx(5, &gtime(b"20261114000000Z")),
        &ctx(6, &gtime(b"20261120000000Z")),
        &ctx(7, &int(&[0x00, 0x9C, 0x3A, 0x5E, 0x21])),
        &ctx(8, &seq(&[&int(&[0x12]), &int(&[0x11])])),
    ]);
    let der = app(
        10,
        &seq(&[
            &ctx(1, &int(&[0x05])),
            &ctx(2, &int(&[0x0A])),
            &ctx(3, &seq(&[&pa])),
            &ctx(4, &body),
        ]),
    );
    let value = AsReq(KdcReq {
        padata: Some(vec![PaData {
            padata_type: constants::PA_ENC_TIMESTAMP,
            padata_value,
        }]),
        req_body: KdcReqBody {
            kdc_options: KdcOptions::FORWARDABLE
                .union(KdcOptions::RENEWABLE)
                .union(KdcOptions::RENEWABLE_OK),
            cname: Some(pname(1, &["alice"])),
            realm: realm("EXAMPLE.ORG"),
            sname: Some(pname(2, &["krbtgt", "EXAMPLE.ORG"])),
            from: None,
            till: ktime("20261114000000Z"),
            rtime: Some(ktime("20261120000000Z")),
            nonce: 0x9C3A_5E21,
            etype: vec![18, 17],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    });
    (der, value)
}

#[test]
fn as_req_round_trip() {
    // Source: RFC 4120 5.4.1 (AS-REQ ::= [APPLICATION 10] KDC-REQ; KDC-REQ
    // tags [1]..[4], "first tag is [1], not [0]"; KDC-REQ-BODY), 5.2.7
    // (PA-DATA), 5.2.7.2 (PA-ENC-TIMESTAMP), 7.5.2 (padata-type 2).
    let (der, value) = as_req();
    round_trip(&der, &value, AsReq::decode, AsReq::encode);
    // The padata-value is itself a PA-ENC-TIMESTAMP (EncryptedData).
    let pa = &value.0.padata.as_ref().unwrap()[0];
    let ts = PaEncTimestamp::decode(&pa.padata_value).unwrap();
    assert_eq!(ts.etype, 18);
    // The KDC dispatcher picks the AS-REQ form.
    assert_eq!(
        KdcRequest::decode(&der).unwrap(),
        KdcRequest::As(value.clone())
    );
    round_trip(
        &der,
        &KdcRequest::As(value),
        KdcRequest::decode,
        KdcRequest::encode,
    );
}

/// AP-REQ carrying the TGT, as used in PA-TGS-REQ. RFC 4120 5.5.1.
fn ap_req() -> (Vec<u8>, ApReq) {
    let (tgt_der, tgt_value) = tgt();
    let auth_cipher: Vec<u8> = (0x60..0x74).collect();
    let der = app(
        14,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &int(&[0x0E])),
            &ctx(2, &flags32([0x00, 0x00, 0x00, 0x00])),
            &ctx(3, &tgt_der),
            &ctx(4, &enc_data_der(&[0x12], None, &auth_cipher)),
        ]),
    );
    let value = ApReq {
        ap_options: ApOptions::empty(),
        ticket: tgt_value,
        authenticator: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: auth_cipher,
        },
    };
    (der, value)
}

/// TGS-REQ with PA-TGS-REQ. RFC 4120 5.4.1, 5.2.7.1.
fn tgs_req() -> (Vec<u8>, Vec<u8>, TgsReq) {
    let (ap_der, _) = ap_req();
    let pa = seq(&[&ctx(1, &int(&[0x01])), &ctx(2, &octets(&ap_der))]);
    let body = seq(&[
        &ctx(0, &flags32([0x40, 0x00, 0x00, 0x00])),
        &ctx(2, &gstring(b"EXAMPLE.ORG")),
        &ctx(3, &pname_der(&[0x03], &["host", "server.example.org"])),
        &ctx(5, &gtime(b"20261114000000Z")),
        &ctx(7, &int(&[0x12, 0x34, 0x56, 0x78])),
        &ctx(8, &seq(&[&int(&[0x12])])),
    ]);
    let der = app(
        12,
        &seq(&[
            &ctx(1, &int(&[0x05])),
            &ctx(2, &int(&[0x0C])),
            &ctx(3, &seq(&[&pa])),
            &ctx(4, &body),
        ]),
    );
    let value = TgsReq(KdcReq {
        padata: Some(vec![PaData {
            padata_type: constants::PA_TGS_REQ,
            padata_value: ap_der,
        }]),
        req_body: KdcReqBody {
            kdc_options: KdcOptions::FORWARDABLE,
            cname: None,
            realm: realm("EXAMPLE.ORG"),
            sname: Some(pname(3, &["host", "server.example.org"])),
            from: None,
            till: ktime("20261114000000Z"),
            rtime: None,
            nonce: 0x1234_5678,
            etype: vec![18],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    });
    (der, body, value)
}

#[test]
fn tgs_req_round_trip() {
    // Source: RFC 4120 5.4.1 (TGS-REQ ::= [APPLICATION 12] KDC-REQ), 5.2.7.1
    // (PA-TGS-REQ carries an AP-REQ), 7.5.2 (padata-type 1).
    let (der, _, value) = tgs_req();
    round_trip(&der, &value, TgsReq::decode, TgsReq::encode);
    let pa = &value.0.padata.as_ref().unwrap()[0];
    let (_, ap_value) = ap_req();
    assert_eq!(ApReq::decode(&pa.padata_value).unwrap(), ap_value);
    assert_eq!(KdcRequest::decode(&der).unwrap(), KdcRequest::Tgs(value));
}

#[test]
fn tgs_req_body_reencodes_to_received_octets() {
    // RFC 4120 5.4.1 / 5.2.7.1: the PA-TGS-REQ authenticator checksum is
    // computed over the KDC-REQ-BODY encoding. Decoding is lossless, so the
    // decoded body re-encodes to exactly the received body octets.
    let (der, body, _) = tgs_req();
    let decoded = TgsReq::decode(&der).unwrap();
    assert_eq!(decoded.0.req_body.encode().unwrap(), body);
    assert_eq!(KdcReqBody::decode(&body).unwrap(), decoded.0.req_body);
}

#[test]
fn kdc_req_body_all_fields_round_trip() {
    // Source: RFC 4120 5.4.1 — KDC-REQ-BODY with every component [0]..[11]
    // present. kdc-options enc-tkt-in-skey(28) renew(30) → 00 00 00 0A; till
    // "19700101000000Z" is the 5.4.1 "maximum endtime" value; nonce 0 → 00.
    let (tgt_der, tgt_value) = tgt();
    let enc_ad: Vec<u8> = (0x70..0x78).collect();
    let body = seq(&[
        &ctx(0, &flags32([0x00, 0x00, 0x00, 0x0A])),
        &ctx(1, &pname_der(&[0x01], &["alice"])),
        &ctx(2, &gstring(b"EXAMPLE.ORG")),
        &ctx(3, &pname_der(&[0x02], &["krbtgt", "EXAMPLE.ORG"])),
        &ctx(4, &gtime(b"20261113100000Z")),
        &ctx(5, &gtime(b"19700101000000Z")),
        &ctx(6, &gtime(b"20261120000000Z")),
        &ctx(7, &int(&[0x00])),
        &ctx(8, &seq(&[&int(&[0x12]), &int(&[0x11])])),
        &ctx(
            9,
            &seq(&[seq(&[&ctx(0, &int(&[0x02])), &ctx(1, &octets(&[192, 0, 2, 9]))]).as_slice()]),
        ),
        &ctx(10, &enc_data_der(&[0x12], None, &enc_ad)),
        &ctx(11, &seq(&[&tgt_der])),
    ]);
    let value = KdcReqBody {
        kdc_options: KdcOptions::ENC_TKT_IN_SKEY.union(KdcOptions::RENEW),
        cname: Some(pname(1, &["alice"])),
        realm: realm("EXAMPLE.ORG"),
        sname: Some(pname(2, &["krbtgt", "EXAMPLE.ORG"])),
        from: Some(ktime("20261113100000Z")),
        till: ktime("19700101000000Z"),
        rtime: Some(ktime("20261120000000Z")),
        nonce: 0,
        etype: vec![18, 17],
        addresses: Some(HostAddresses(vec![HostAddress {
            addr_type: 2,
            address: vec![192, 0, 2, 9],
        }])),
        enc_authorization_data: Some(EncryptedData {
            etype: 18,
            kvno: None,
            cipher: enc_ad,
        }),
        additional_tickets: Some(vec![tgt_value]),
    };
    assert_eq!(value.kdc_options.0.bits(), 0x0000_000A);
    round_trip(&body, &value, KdcReqBody::decode, KdcReqBody::encode);
}

#[test]
fn kdc_req_empty_optional_sequence_of_preserved() {
    // RFC 4120 5.1.3: an empty OPTIONAL SEQUENCE OF ("NOTE: not empty"
    // padata) SHOULD be accepted as equivalent to omitted. It is accepted and
    // preserved as Some(empty) so the encoding round-trips exactly.
    let (_, _, value) = tgs_req();
    let body = value.0.req_body.encode().unwrap();
    let der = app(
        12,
        &seq(&[
            &ctx(1, &int(&[0x05])),
            &ctx(2, &int(&[0x0C])),
            &ctx(3, &seq(&[])),
            &ctx(4, &body),
        ]),
    );
    let expected = TgsReq(KdcReq {
        padata: Some(vec![]),
        req_body: value.0.req_body.clone(),
    });
    round_trip(&der, &expected, TgsReq::decode, TgsReq::encode);
}

/// ETYPE-INFO2 with one salted entry. RFC 4120 5.2.7.5.
fn etype_info2_single() -> (Vec<u8>, EtypeInfo2) {
    let der = seq(&[seq(&[
        &ctx(0, &int(&[0x12])),
        &ctx(1, &gstring(b"EXAMPLE.ORGalice")),
    ])
    .as_slice()]);
    let value = EtypeInfo2(vec![EtypeInfo2Entry {
        etype: 18,
        salt: Some(kstr("EXAMPLE.ORGalice")),
        s2kparams: None,
    }]);
    (der, value)
}

#[test]
fn etype_info2_round_trip() {
    // Source: RFC 4120 5.2.7.5 (ETYPE-INFO2-ENTRY ::= SEQUENCE { etype [0]
    // Int32, salt [1] KerberosString OPTIONAL, s2kparams [2] OCTET STRING
    // OPTIONAL }; ETYPE-INFO2 ::= SEQUENCE SIZE (1..MAX) OF ...).
    let (der, value) = etype_info2_single();
    round_trip(&der, &value, EtypeInfo2::decode, EtypeInfo2::encode);
    let entry_full = seq(&[
        &ctx(0, &int(&[0x12])),
        &ctx(1, &gstring(b"EXAMPLE.ORGbob")),
        &ctx(2, &octets(&[0x00, 0x00, 0x10, 0x00])),
    ]);
    let entry_bare = seq(&[&ctx(0, &int(&[0x11]))]);
    let full_value = EtypeInfo2Entry {
        etype: 18,
        salt: Some(kstr("EXAMPLE.ORGbob")),
        s2kparams: Some(vec![0x00, 0x00, 0x10, 0x00]),
    };
    round_trip(
        &entry_full,
        &full_value,
        EtypeInfo2Entry::decode,
        EtypeInfo2Entry::encode,
    );
    round_trip(
        &seq(&[&entry_full, &entry_bare]),
        &EtypeInfo2(vec![
            full_value,
            EtypeInfo2Entry {
                etype: 17,
                salt: None,
                s2kparams: None,
            },
        ]),
        EtypeInfo2::decode,
        EtypeInfo2::encode,
    );
}

/// AS-REP with ETYPE-INFO2 padata. RFC 4120 5.4.2.
fn as_rep() -> (Vec<u8>, AsRep) {
    let (tgt_der, tgt_value) = tgt();
    let (info_der, _) = etype_info2_single();
    let cipher: Vec<u8> = (0x80..0xA0).collect();
    let pa = seq(&[&ctx(1, &int(&[0x13])), &ctx(2, &octets(&info_der))]);
    let der = app(
        11,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &int(&[0x0B])),
            &ctx(2, &seq(&[&pa])),
            &ctx(3, &gstring(b"EXAMPLE.ORG")),
            &ctx(4, &pname_der(&[0x01], &["alice"])),
            &ctx(5, &tgt_der),
            &ctx(6, &enc_data_der(&[0x12], Some(&[0x01]), &cipher)),
        ]),
    );
    let value = AsRep(KdcRep {
        padata: Some(vec![PaData {
            padata_type: constants::PA_ETYPE_INFO2,
            padata_value: info_der,
        }]),
        crealm: realm("EXAMPLE.ORG"),
        cname: pname(1, &["alice"]),
        ticket: tgt_value,
        enc_part: EncryptedData {
            etype: 18,
            kvno: Some(1),
            cipher,
        },
    });
    (der, value)
}

#[test]
fn as_rep_round_trip() {
    // Source: RFC 4120 5.4.2 (AS-REP ::= [APPLICATION 11] KDC-REP; KDC-REP
    // tags [0]..[6]), 7.5.2 (PA-ETYPE-INFO2 = 19 = 0x13).
    let (der, value) = as_rep();
    round_trip(&der, &value, AsRep::decode, AsRep::encode);
    let pa = &value.0.padata.as_ref().unwrap()[0];
    assert_eq!(
        EtypeInfo2::decode(&pa.padata_value).unwrap(),
        etype_info2_single().1
    );
}

#[test]
fn tgs_rep_round_trip() {
    // Source: RFC 4120 5.4.2 (TGS-REP ::= [APPLICATION 13] KDC-REP; no padata;
    // enc-part under the session key, so no kvno).
    let (st_der, st_value) = service_ticket();
    let cipher: Vec<u8> = (0x20..0x40).collect();
    let der = app(
        13,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &int(&[0x0D])),
            &ctx(3, &gstring(b"EXAMPLE.ORG")),
            &ctx(4, &pname_der(&[0x01], &["alice"])),
            &ctx(5, &st_der),
            &ctx(6, &enc_data_der(&[0x12], None, &cipher)),
        ]),
    );
    let value = TgsRep(KdcRep {
        padata: None,
        crealm: realm("EXAMPLE.ORG"),
        cname: pname(1, &["alice"]),
        ticket: st_value,
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher,
        },
    });
    round_trip(&der, &value, TgsRep::decode, TgsRep::encode);
}

/// EncKDCRepPart contents (inner SEQUENCE). RFC 4120 5.4.2.
fn enc_kdc_rep_part(full: bool) -> (Vec<u8>, EncKdcRepPart) {
    let key = key32(0x20);
    let last_req =
        seq(&[seq(&[&ctx(0, &int(&[0x00])), &ctx(1, &gtime(b"20261113090000Z"))]).as_slice()]);
    let mut parts: Vec<Vec<u8>> = vec![
        ctx(0, &key_der(&[0x12], &key)),
        ctx(1, &last_req),
        ctx(2, &int(&[0x00, 0x9C, 0x3A, 0x5E, 0x21])),
    ];
    if full {
        parts.push(ctx(3, &gtime(b"20270101000000Z")));
    }
    parts.extend([
        ctx(4, &flags32([0x40, 0xE0, 0x00, 0x00])),
        ctx(5, &gtime(b"20261113090000Z")),
        ctx(6, &gtime(b"20261113090000Z")),
        ctx(7, &gtime(b"20261113190000Z")),
        ctx(8, &gtime(b"20261120090000Z")),
        ctx(9, &gstring(b"EXAMPLE.ORG")),
        ctx(10, &pname_der(&[0x02], &["krbtgt", "EXAMPLE.ORG"])),
    ]);
    if full {
        parts.push(ctx(
            11,
            &seq(&[seq(&[&ctx(0, &int(&[0x02])), &ctx(1, &octets(&[192, 0, 2, 7]))]).as_slice()]),
        ));
    }
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let der = seq(&refs);
    let value = EncKdcRepPart {
        key: key_value(18, &key),
        last_req: LastReq(vec![LastReqEntry {
            lr_type: 0,
            lr_value: ktime("20261113090000Z"),
        }]),
        nonce: 0x9C3A_5E21,
        key_expiration: full.then(|| ktime("20270101000000Z")),
        flags: TicketFlags(KerberosFlags::from_bits(0x40E0_0000)),
        authtime: ktime("20261113090000Z"),
        starttime: Some(ktime("20261113090000Z")),
        endtime: ktime("20261113190000Z"),
        renew_till: Some(ktime("20261120090000Z")),
        srealm: realm("EXAMPLE.ORG"),
        sname: pname(2, &["krbtgt", "EXAMPLE.ORG"]),
        caddr: full.then(|| {
            HostAddresses(vec![HostAddress {
                addr_type: 2,
                address: vec![192, 0, 2, 7],
            }])
        }),
    };
    (der, value)
}

#[test]
fn enc_as_rep_part_round_trip() {
    // Source: RFC 4120 5.4.2 (EncASRepPart ::= [APPLICATION 25]
    // EncKDCRepPart; EncKDCRepPart tags [0]..[11]; LastReq), 5.10 (tag 25).
    let (inner, value) = enc_kdc_rep_part(false);
    round_trip(
        &app(25, &inner),
        &EncAsRepPart(value),
        EncAsRepPart::decode,
        EncAsRepPart::encode,
    );
}

#[test]
fn enc_tgs_rep_part_round_trip() {
    // Source: RFC 4120 5.4.2 (EncTGSRepPart ::= [APPLICATION 26]
    // EncKDCRepPart), 5.10 (tag 26); key-expiration [3] and caddr [11] present.
    let (inner, value) = enc_kdc_rep_part(true);
    round_trip(
        &app(26, &inner),
        &EncTgsRepPart(value),
        EncTgsRepPart::decode,
        EncTgsRepPart::encode,
    );
}

#[test]
fn last_req_round_trip() {
    // Source: RFC 4120 5.4.2 (LastReq ::= SEQUENCE OF SEQUENCE { lr-type [0]
    // Int32, lr-value [1] KerberosTime }); negative lr-type -1 = FF ("pertains
    // only to the responding server"); an empty LastReq is valid (no SIZE).
    let bytes = seq(&[
        seq(&[&ctx(0, &int(&[0xFF])), &ctx(1, &gtime(b"20261113090000Z"))]).as_slice(),
        seq(&[&ctx(0, &int(&[0x06])), &ctx(1, &gtime(b"20270101000000Z"))]).as_slice(),
    ]);
    let value = LastReq(vec![
        LastReqEntry {
            lr_type: -1,
            lr_value: ktime("20261113090000Z"),
        },
        LastReqEntry {
            lr_type: 6,
            lr_value: ktime("20270101000000Z"),
        },
    ]);
    round_trip(&bytes, &value, LastReq::decode, LastReq::encode);
    round_trip(
        &[0x30, 0x00],
        &LastReq(vec![]),
        LastReq::decode,
        LastReq::encode,
    );
}

// ===========================================================================
// AP exchange — RFC 4120 5.5
// ===========================================================================

#[test]
fn ap_req_round_trip() {
    // Source: RFC 4120 5.5.1 (AP-REQ ::= [APPLICATION 14] SEQUENCE { pvno [0],
    // msg-type [1] INTEGER (14), ap-options [2], ticket [3], authenticator
    // [4] }), 5.10 (tag 14).
    let (der, value) = ap_req();
    round_trip(&der, &value, ApReq::decode, ApReq::encode);
    // With mutual-required(2) → 20 00 00 00.
    let (tgt_der, tgt_value) = tgt();
    let der = app(
        14,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &int(&[0x0E])),
            &ctx(2, &flags32([0x20, 0x00, 0x00, 0x00])),
            &ctx(3, &tgt_der),
            &ctx(4, &enc_data_der(&[0x12], None, &[0x01])),
        ]),
    );
    let value = ApReq {
        ap_options: ApOptions::MUTUAL_REQUIRED,
        ticket: tgt_value,
        authenticator: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![0x01],
        },
    };
    round_trip(&der, &value, ApReq::decode, ApReq::encode);
}

#[test]
fn authenticator_full_round_trip() {
    // Source: RFC 4120 5.5.1 (Authenticator ::= [APPLICATION 2] SEQUENCE,
    // tags [0]..[8]), 5.10 (tag 2). cksum type 16 (RFC 3962 §7); cusec 999999
    // = 0F 42 3F; seq-number 4294967295 = 00 FF FF FF FF (X.690 8.3.2).
    let subkey = key32(0x80);
    let sum: Vec<u8> = (0x30..0x3C).collect();
    let der = app(
        2,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &gstring(b"EXAMPLE.ORG")),
            &ctx(2, &pname_der(&[0x01], &["alice"])),
            &ctx(3, &seq(&[&ctx(0, &int(&[0x10])), &ctx(1, &octets(&sum))])),
            &ctx(4, &int(&[0x0F, 0x42, 0x3F])),
            &ctx(5, &gtime(b"20261113090512Z")),
            &ctx(6, &key_der(&[0x12], &subkey)),
            &ctx(7, &int(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF])),
            &ctx(
                8,
                &seq(&[seq(&[&ctx(0, &int(&[0xFF])), &ctx(1, &octets(&[0x42]))]).as_slice()]),
            ),
        ]),
    );
    let value = Authenticator {
        crealm: realm("EXAMPLE.ORG"),
        cname: pname(1, &["alice"]),
        cksum: Some(Checksum {
            cksumtype: 16,
            checksum: sum,
        }),
        cusec: Microseconds::new(999_999).unwrap(),
        ctime: ktime("20261113090512Z"),
        subkey: Some(key_value(18, &subkey)),
        seq_number: Some(u32::MAX),
        authorization_data: Some(AuthorizationData(vec![AuthorizationElement {
            ad_type: -1,
            ad_data: vec![0x42],
        }])),
    };
    round_trip(&der, &value, Authenticator::decode, Authenticator::encode);
}

#[test]
fn authenticator_minimal_round_trip() {
    // Source: RFC 4120 5.5.1 — components without OPTIONAL only; cusec 0.
    let der = app(
        2,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &gstring(b"EXAMPLE.ORG")),
            &ctx(2, &pname_der(&[0x01], &["alice"])),
            &ctx(4, &int(&[0x00])),
            &ctx(5, &gtime(b"20261113090512Z")),
        ]),
    );
    let value = Authenticator {
        crealm: realm("EXAMPLE.ORG"),
        cname: pname(1, &["alice"]),
        cksum: None,
        cusec: Microseconds::new(0).unwrap(),
        ctime: ktime("20261113090512Z"),
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    round_trip(&der, &value, Authenticator::decode, Authenticator::encode);
}

#[test]
fn ap_rep_round_trip() {
    // Source: RFC 4120 5.5.2 (AP-REP ::= [APPLICATION 15] SEQUENCE { pvno [0],
    // msg-type [1] INTEGER (15), enc-part [2] }), 5.10 (tag 15).
    let cipher: Vec<u8> = (0x01..0x1D).collect();
    let der = app(
        15,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &int(&[0x0F])),
            &ctx(2, &enc_data_der(&[0x12], None, &cipher)),
        ]),
    );
    let value = ApRep {
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher,
        },
    };
    round_trip(&der, &value, ApRep::decode, ApRep::encode);
}

#[test]
fn ap_rep_literal_vector() {
    // Source: RFC 4120 5.5.2 (AP-REP ::= [APPLICATION 15] SEQUENCE { pvno [0]
    // INTEGER (5), msg-type [1] INTEGER (15), enc-part [2] EncryptedData }),
    // 5.2.9 (EncryptedData), 5.10 (tag 15); X.690 8.1.2.2 ([APPLICATION 15]
    // constructed = 0x6F), 8.9, 8.14.3. Hand-derived octet by octet:
    //   6F 1D                          [APPLICATION 15], 29 octets
    //     30 1B                        SEQUENCE, 27 octets
    //       A0 03 02 01 05             [0] pvno 5
    //       A1 03 02 01 0F             [1] msg-type 15
    //       A2 0F                      [2] enc-part, 15 octets
    //         30 0D                    EncryptedData, 13 octets
    //           A0 03 02 01 12         [0] etype 18
    //           A2 06 04 04 01 02 03 04  [2] cipher
    let bytes = [
        0x6F, 0x1D, 0x30, 0x1B, 0xA0, 0x03, 0x02, 0x01, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x0F, 0xA2,
        0x0F, 0x30, 0x0D, 0xA0, 0x03, 0x02, 0x01, 0x12, 0xA2, 0x06, 0x04, 0x04, 0x01, 0x02, 0x03,
        0x04,
    ];
    let value = ApRep {
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![1, 2, 3, 4],
        },
    };
    round_trip(&bytes, &value, ApRep::decode, ApRep::encode);
}

#[test]
fn enc_ap_rep_part_round_trip() {
    // Source: RFC 4120 5.5.2 (EncAPRepPart ::= [APPLICATION 27] SEQUENCE {
    // ctime [0], cusec [1], subkey [2] OPTIONAL, seq-number [3] OPTIONAL }),
    // 5.10 (tag 27). cusec 512 = 02 00; seq-number 1.
    let subkey = key32(0xC0);
    let der = app(
        27,
        &seq(&[
            &ctx(0, &gtime(b"20261113090512Z")),
            &ctx(1, &int(&[0x02, 0x00])),
            &ctx(2, &key_der(&[0x12], &subkey)),
            &ctx(3, &int(&[0x01])),
        ]),
    );
    let value = EncApRepPart {
        ctime: ktime("20261113090512Z"),
        cusec: Microseconds::new(512).unwrap(),
        subkey: Some(key_value(18, &subkey)),
        seq_number: Some(1),
    };
    round_trip(&der, &value, EncApRepPart::decode, EncApRepPart::encode);
    // Minimal form.
    let der = app(
        27,
        &seq(&[&ctx(0, &gtime(b"20261113090512Z")), &ctx(1, &int(&[0x00]))]),
    );
    let value = EncApRepPart {
        ctime: ktime("20261113090512Z"),
        cusec: Microseconds::default(),
        subkey: None,
        seq_number: None,
    };
    round_trip(&der, &value, EncApRepPart::decode, EncApRepPart::encode);
}

// ===========================================================================
// KRB-ERROR / METHOD-DATA — RFC 4120 5.9.1
// ===========================================================================

#[test]
fn krb_error_preauth_required_with_method_data() {
    // Source: RFC 4120 5.9.1 (KRB-ERROR ::= [APPLICATION 30] SEQUENCE, tags
    // [0]..[12]; e-data for KDC_ERR_PREAUTH_REQUIRED is METHOD-DATA ::=
    // SEQUENCE OF PA-DATA), 7.5.9 (KDC_ERR_PREAUTH_REQUIRED = 25 = 0x19),
    // 7.5.2 (PA-ENC-TIMESTAMP 2, PA-ETYPE-INFO2 19), 8.1 (the KDC lists
    // PA-ENC-TIMESTAMP as an acceptable method).
    let (info_der, _) = etype_info2_single();
    let method_data = seq(&[
        &seq(&[&ctx(1, &int(&[0x02])), &ctx(2, &octets(&[]))]),
        &seq(&[&ctx(1, &int(&[0x13])), &ctx(2, &octets(&info_der))]),
    ]);
    let method_value = MethodData(vec![
        PaData {
            padata_type: constants::PA_ENC_TIMESTAMP,
            padata_value: vec![],
        },
        PaData {
            padata_type: constants::PA_ETYPE_INFO2,
            padata_value: info_der.clone(),
        },
    ]);
    round_trip(
        &method_data,
        &method_value,
        MethodData::decode,
        MethodData::encode,
    );
    let der = app(
        30,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &int(&[0x1E])),
            &ctx(4, &gtime(b"20261113090000Z")),
            &ctx(5, &int(&[0x00])),
            &ctx(6, &int(&[0x19])),
            &ctx(8, &pname_der(&[0x01], &["alice"])),
            &ctx(9, &gstring(b"EXAMPLE.ORG")),
            &ctx(10, &pname_der(&[0x02], &["krbtgt", "EXAMPLE.ORG"])),
            &ctx(12, &octets(&method_data)),
        ]),
    );
    let value = KrbError {
        ctime: None,
        cusec: None,
        stime: ktime("20261113090000Z"),
        susec: Microseconds::default(),
        error_code: constants::KDC_ERR_PREAUTH_REQUIRED,
        crealm: None,
        cname: Some(pname(1, &["alice"])),
        realm: realm("EXAMPLE.ORG"),
        sname: pname(2, &["krbtgt", "EXAMPLE.ORG"]),
        e_text: None,
        e_data: Some(method_data.clone()),
    };
    round_trip(&der, &value, KrbError::decode, KrbError::encode);
    assert_eq!(
        MethodData::decode(value.e_data.as_deref().unwrap()).unwrap(),
        method_value
    );
}

#[test]
fn krb_error_all_fields_round_trip() {
    // Source: RFC 4120 5.9.1 — every component [0]..[12] present; error-code
    // KRB_AP_ERR_SKEW = 37 = 0x25 (7.5.9); cusec 7, susec 999999 = 0F 42 3F.
    let der = app(
        30,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &int(&[0x1E])),
            &ctx(2, &gtime(b"20261113085500Z")),
            &ctx(3, &int(&[0x07])),
            &ctx(4, &gtime(b"20261113090000Z")),
            &ctx(5, &int(&[0x0F, 0x42, 0x3F])),
            &ctx(6, &int(&[0x25])),
            &ctx(7, &gstring(b"EXAMPLE.ORG")),
            &ctx(8, &pname_der(&[0x01], &["alice"])),
            &ctx(9, &gstring(b"EXAMPLE.ORG")),
            &ctx(10, &pname_der(&[0x03], &["host", "server.example.org"])),
            &ctx(11, &gstring(b"clock skew")),
            &ctx(12, &octets(&[0x00])),
        ]),
    );
    let value = KrbError {
        ctime: Some(ktime("20261113085500Z")),
        cusec: Some(Microseconds::new(7).unwrap()),
        stime: ktime("20261113090000Z"),
        susec: Microseconds::new(999_999).unwrap(),
        error_code: constants::KRB_AP_ERR_SKEW,
        crealm: Some(realm("EXAMPLE.ORG")),
        cname: Some(pname(1, &["alice"])),
        realm: realm("EXAMPLE.ORG"),
        sname: pname(3, &["host", "server.example.org"]),
        e_text: Some(kstr("clock skew")),
        e_data: Some(vec![0x00]),
    };
    round_trip(&der, &value, KrbError::decode, KrbError::encode);
}
