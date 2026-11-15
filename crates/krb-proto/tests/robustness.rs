//! Deterministic never-panic smoke test (complements the cargo-fuzz target in
//! `fuzz/`, which is pending owner approval of its harness dependency).
//!
//! Seeds are this crate's own hand-derived vectors (RFC 4120 Appendix A via
//! X.690 (02/2021)); every truncation and every single-octet substitution of
//! each seed is fed to every decoder. Each decoder must return `Ok` or `Err`
//! without panicking, and anything accepted must re-encode to the identical
//! octets (decoding is lossless; RFC 4120 5.1.1 / X.690 clause 10).

mod common;

use common::*;

macro_rules! check {
    ($ty:ty, $data:expr) => {
        if let Ok(value) = <$ty>::decode($data) {
            let reencoded = value.encode().expect("accepted value must re-encode");
            assert_eq!(AsRef::<[u8]>::as_ref(&reencoded), $data);
        }
    };
}

fn all_decoders(data: &[u8]) {
    check!(krb_proto::KdcRequest, data);
    check!(krb_proto::AsReq, data);
    check!(krb_proto::TgsReq, data);
    check!(krb_proto::AsRep, data);
    check!(krb_proto::TgsRep, data);
    check!(krb_proto::ApReq, data);
    check!(krb_proto::ApRep, data);
    check!(krb_proto::KrbError, data);
    check!(krb_proto::Ticket, data);
    check!(krb_proto::EncTicketPart, data);
    check!(krb_proto::EncAsRepPart, data);
    check!(krb_proto::EncTgsRepPart, data);
    check!(krb_proto::Authenticator, data);
    check!(krb_proto::EncApRepPart, data);
    check!(krb_proto::PaEncTsEnc, data);
    check!(krb_proto::EtypeInfo2, data);
    check!(krb_proto::MethodData, data);
    check!(krb_proto::AuthorizationData, data);
    check!(krb_proto::KdcReqBody, data);
    check!(krb_proto::EncryptedData, data);
    check!(krb_proto::EncryptionKey, data);
    check!(krb_proto::PrincipalName, data);
    // RFC 6113 FAST types (their own seeds are exercised in tests/fast.rs).
    check!(krb_proto::PaFxFastRequest, data);
    check!(krb_proto::KrbFastArmoredReq, data);
    check!(krb_proto::KrbFastArmor, data);
    check!(krb_proto::KrbFastReq, data);
    check!(krb_proto::PaFxFastReply, data);
    check!(krb_proto::KrbFastArmoredRep, data);
    check!(krb_proto::KrbFastResponse, data);
    check!(krb_proto::KrbFastFinished, data);
    // RFC 4120 5.7.1 KRB_PRIV and the RFC 3244 §2 ChangePasswdData.
    check!(krb_proto::KrbPriv, data);
    check!(krb_proto::EncKrbPrivPart, data);
    check!(krb_proto::ChangePasswdData, data);
    check!(krb_proto::HostAddress, data);
}

/// Seeds: a TGT, a service ticket, an AP-REQ around the TGT, an AS-REQ body,
/// an EncTicketPart (RFC 4120 5.3, 5.4.1, 5.5.1), a ChangePasswdData (RFC 3244
/// §2), an EncKrbPrivPart and a KRB-PRIV (RFC 4120 5.7.1).
fn seeds() -> Vec<Vec<u8>> {
    let (tgt_der, _) = tgt();
    let (st_der, _) = service_ticket();
    let ap_req = app(
        14,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &int(&[0x0E])),
            &ctx(2, &flags32([0x20, 0, 0, 0])),
            &ctx(3, &tgt_der),
            &ctx(4, &enc_data_der(&[0x12], None, &[1, 2, 3])),
        ]),
    );
    let body = seq(&[
        &ctx(0, &flags32([0x40, 0x80, 0x00, 0x10])),
        &ctx(1, &pname_der(&[0x01], &["alice"])),
        &ctx(2, &gstring(b"EXAMPLE.ORG")),
        &ctx(3, &pname_der(&[0x02], &["krbtgt", "EXAMPLE.ORG"])),
        &ctx(5, &gtime(b"20261114000000Z")),
        &ctx(7, &int(&[0x00, 0x9C, 0x3A, 0x5E, 0x21])),
        &ctx(8, &seq(&[&int(&[0x12]), &int(&[0x11])])),
    ]);
    let as_req = app(
        10,
        &seq(&[
            &ctx(1, &int(&[0x05])),
            &ctx(2, &int(&[0x0A])),
            &ctx(
                3,
                &seq(&[&seq(&[&ctx(1, &int(&[0x02])), &ctx(2, &octets(&[0]))])]),
            ),
            &ctx(4, &body),
        ]),
    );
    let key: Vec<u8> = (0..32).collect();
    let enc_ticket_part = app(
        3,
        &seq(&[
            &ctx(0, &flags32([0x40, 0xE0, 0x00, 0x00])),
            &ctx(1, &seq(&[&ctx(0, &int(&[0x12])), &ctx(1, &octets(&key))])),
            &ctx(2, &gstring(b"EXAMPLE.ORG")),
            &ctx(3, &pname_der(&[0x01], &["alice"])),
            &ctx(4, &seq(&[&ctx(0, &int(&[0x01])), &ctx(1, &octets(&[]))])),
            &ctx(5, &gtime(b"20261113090000Z")),
            &ctx(7, &gtime(b"20261113190000Z")),
        ]),
    );
    // RFC 4120 5.7.1 KRB-PRIV / EncKrbPrivPart and RFC 3244 §2
    // ChangePasswdData (set form, so every optional component is present).
    let change_passwd_data = seq(&[
        &ctx(0, &octets(b"seed-password")),
        &ctx(1, &pname_der(&[0x01], &["bob"])),
        &ctx(2, &gstring(b"EXAMPLE.ORG")),
    ]);
    let enc_krb_priv_part = app(
        28,
        &seq(&[
            &ctx(0, &octets(&change_passwd_data)),
            &ctx(1, &gtime(b"20261115120000Z")),
            &ctx(2, &int(&[0x01, 0x86, 0xA0])),
            &ctx(3, &int(&[0x3A, 0x5C, 0x0F, 0x21])),
            &ctx(
                4,
                &seq(&[&ctx(0, &int(&[0x03])), &ctx(1, &octets(&[0; 4]))]),
            ),
            &ctx(
                5,
                &seq(&[&ctx(0, &int(&[0x02])), &ctx(1, &octets(&[10, 0, 0, 1]))]),
            ),
        ]),
    );
    let krb_priv = app(
        21,
        &seq(&[
            &ctx(0, &int(&[0x05])),
            &ctx(1, &int(&[0x15])),
            &ctx(3, &enc_data_der(&[0x12], Some(&[0x01]), &[9, 8, 7])),
        ]),
    );
    vec![
        tgt_der,
        st_der,
        ap_req,
        as_req,
        body,
        enc_ticket_part,
        change_passwd_data,
        enc_krb_priv_part,
        krb_priv,
    ]
}

#[test]
fn seeds_round_trip() {
    for seed in seeds() {
        all_decoders(&seed);
    }
}

#[test]
fn every_truncation_fails_closed() {
    for seed in seeds() {
        for len in 0..seed.len() {
            all_decoders(&seed[..len]);
        }
    }
}

#[test]
fn every_single_octet_substitution_fails_closed() {
    // Substitutions chosen to hit tag classes, the constructed bit, length
    // forms (0x80 indefinite, 0x81..0x84 long, 0xFF reserved) and values.
    const SUBSTITUTES: [u8; 10] = [0x00, 0x01, 0x1F, 0x30, 0x7F, 0x80, 0x81, 0x84, 0xA0, 0xFF];
    for seed in seeds() {
        let mut mutated = seed.clone();
        for i in 0..seed.len() {
            for &octet in &SUBSTITUTES {
                mutated[i] = octet;
                all_decoders(&mutated);
            }
            mutated[i] = seed[i];
        }
    }
}
