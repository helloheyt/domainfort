//! Main-session decision 13: keyd verifies the TGS authenticator checksum
//! over the raw KDC-REQ-BODY octets (RFC 4120 5.2.7.1: "computed over the
//! KDC-REQ-BODY encoding"; A-17). krb-proto exposes no raw-body accessor, so
//! the KDC re-encodes the decoded body. That is sound only because:
//! - krb-proto accepts DER only (RFC 4120 5.1.1; the BER leniency is not
//!   taken) — any non-canonical encoding is refused before re-encoding; and
//! - krb-proto's decoding is lossless (`encode(decode(b)) == b`, its crate
//!   docs), including OPTIONAL empty SEQUENCE OF values (RFC 4120 5.1.3).
//!
//! These tests prove the property on varied bodies, on every accepted
//! mutation of a valid request, end to end through keyd's checksum check,
//! and show that a non-minimal length is refused.
//!
//! The armored AS path relies on the same property: keyd verifies the FAST
//! req-checksum over the KDC's re-encoding of the outer KDC-REQ-BODY
//! (RFC 6113 5.4.2).
//!
//! Sources: RFC 4120 5.1.1, 5.1.3, 5.2.7.1, 5.4.1, 5.5.1; RFC 6113 5.4.2;
//! krb-proto / parse-asn1 crate documentation (this project's own work);
//! main-session decision 13. All values hand-made.

mod common;

use common::*;
use krb_proto::constants::PA_TGS_REQ;
use krb_proto::{
    EncryptedData, HostAddress, HostAddresses, KdcReq, KdcReqBody, KdcRequest, PaData, TgsReq,
};

fn tgs_request(body: KdcReqBody, padata: Vec<PaData>) -> Vec<u8> {
    TgsReq(KdcReq {
        padata: Some(padata),
        req_body: body,
    })
    .encode()
    .unwrap()
}

fn bodies() -> Vec<KdcReqBody> {
    let base = TgsReqSpec::service().body();
    let mut out = vec![base.clone()];
    let mut b = base.clone();
    b.kdc_options = options(&[1, 8, 15, 27]);
    b.from = Some(at(-60));
    b.rtime = Some(kt("20261120100000Z"));
    b.etype = vec![RC4_HMAC, AES128, AES256, AES128];
    out.push(b);
    let mut b = base.clone();
    b.cname = Some(alice_name());
    b.addresses = Some(HostAddresses(vec![HostAddress {
        addr_type: 24,
        address: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    }]));
    b.enc_authorization_data = Some(EncryptedData {
        etype: AES256,
        kvno: Some(7),
        cipher: vec![0x55; 48],
    });
    out.push(b);
    let mut b = base.clone();
    b.addresses = Some(HostAddresses(Vec::new()));
    b.etype = Vec::new();
    out.push(b);
    let mut b = base;
    b.sname = Some(name(10, &["a", "", "c"]));
    b.nonce = u32::MAX;
    out.push(b);
    out
}

/// Decision 13: for varied bodies, the body travels verbatim inside the
/// TGS-REQ (EXPLICIT [4], RFC 4120 5.4.1), and re-encoding the decoded body
/// reproduces exactly the octets the client checksummed.
#[test]
fn reencoded_body_equals_received_octets() {
    let padata = vec![PaData {
        padata_type: PA_TGS_REQ,
        padata_value: vec![0x6E, 0x00],
    }];
    for body in bodies() {
        let sent_body = body.encode().unwrap();
        let request = tgs_request(body, padata.clone());
        assert!(contains_bytes(&request, &sent_body));
        let Ok(KdcRequest::Tgs(decoded)) = KdcRequest::decode(&request) else {
            panic!("a TGS-REQ");
        };
        assert_eq!(decoded.0.req_body.encode().unwrap(), sent_body);
    }
}

/// Decision 13: on every mutation of a valid TGS-REQ that krb-proto still
/// accepts, the whole message re-encodes to the received octets, and the
/// re-encoded body occurs verbatim in them.
#[test]
fn accepted_mutations_reencode_losslessly() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let (valid, _) = TgsReqSpec::service().encode(&tgt);
    let mut accepted = 0;
    for i in 0..valid.len() {
        for delta in [1u8, 0x80] {
            let mut mutated = valid.clone();
            mutated[i] ^= delta;
            if let Ok(KdcRequest::Tgs(decoded)) = KdcRequest::decode(&mutated) {
                accepted += 1;
                assert_eq!(decoded.encode().unwrap(), mutated);
                let body = decoded.0.req_body.encode().unwrap();
                assert!(contains_bytes(&mutated, &body));
            }
        }
    }
    assert!(accepted > 0);
}

/// RFC 4120 5.1.1 (DER) / parse-asn1 NonMinimalLength (its docs: X.690 10.1):
/// a body whose length is not in the minimum number of octets is refused, so
/// it can never be re-encoded differently.
#[test]
fn non_minimal_body_length_is_refused() {
    let body = TgsReqSpec::service().body().encode().unwrap();
    assert!(KdcReqBody::decode(&body).is_ok());
    let mut longer = vec![body[0]];
    match body[1] {
        short if short < 0x80 => longer.extend([0x81, short]),
        0x81 => longer.extend([0x82, 0x00, body[2]]),
        other => panic!("unexpected length octet {other:#x}"),
    }
    let skip = if body[1] < 0x80 { 2 } else { 3 };
    longer.extend_from_slice(&body[skip..]);
    assert!(KdcReqBody::decode(&longer).is_err());
}

/// Decision 13 end to end: an (outer) body with an empty `addresses`
/// SEQUENCE OF (RFC 4120 5.1.3: accepted as absent) is preserved by the
/// re-encoding, so keyd's checksum over it verifies and the ticket is issued
/// (a re-encoding that dropped the empty element would fail the checksum).
/// Under FAST the authenticator checksum still covers the OUTER body
/// (docs/questions/Q-124 item 1).
#[test]
fn checksum_verifies_over_preserved_empty_sequence() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let mut spec = TgsReqSpec::service();
    let mut body = spec.body();
    body.addresses = Some(HostAddresses(Vec::new()));
    spec.outer = Some(body);
    let (request, body_bytes) = spec.encode(&tgt);
    assert!(contains_bytes(&request, &body_bytes));
    let (_, part) = open_tgs_rep(&sent(f.send(&request)), &tgt, &spec);
    assert_eq!(part.0.sname, service_name());
}

/// The same property for the armored AS-REQ (RFC 6113 5.4.2: the
/// req-checksum "is performed over the type KDC-REQ-BODY for the req-body
/// field" — keyd verifies it over the KDC's re-encoding of the outer body):
/// an outer body with an empty `addresses` SEQUENCE OF verifies, and alice
/// gets her TGT.
#[test]
fn req_checksum_verifies_over_preserved_empty_sequence() {
    let mut f = Fixture::new();
    let key = alice_key(AES256);
    let mut spec = AsReqSpec::alice().with_challenge(&key);
    let mut outer = spec.body();
    outer.addresses = Some(HostAddresses(Vec::new()));
    spec.outer = Some(outer);
    let fast = f.send_fast(&spec);
    let tgt = open_fast_as_rep(&sent(fast.reply), &fast.armor_key, &key);
    assert_eq!(tgt.rep.0.cname, alice_name());
}
