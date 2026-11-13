//! KRB-ERROR content and audit hygiene.
//!
//! Sources: RFC 4120 5.9.1 (KRB-ERROR fields), 7.5.9; docs/10 §9 and docs/11
//! §8 (terse errors, reason to audit only); AGENTS.md §6 (secrets never in
//! errors or logs); main-session decisions 3-6, 11, 14, 15. All values
//! hand-made.

mod common;

use common::*;
use kdc::{AccountState, ConfigError, KdcConfig, KdcReply, LocalKeyd, Transport};
use keyd::{InMemoryKeyStore, KeyPurpose, Keyd, KeydConfig};
use krb_proto::constants::{KDC_ERR_C_PRINCIPAL_UNKNOWN, KDC_ERR_PREAUTH_REQUIRED, PA_FX_FAST};
use krb_proto::{KrbError, MethodData, Microseconds};

/// Every KRB-ERROR the KDC produced in a sweep of refusal scenarios —
/// unarmored ones (before or without FAST) and armored ones (RFC 6113 5.4.4).
fn refusals() -> Vec<Vec<u8>> {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let mut out = Vec::new();
    let mut push = |reply: KdcReply| {
        if let KdcReply::Send(bytes) | KdcReply::SendAndClose(bytes) = reply {
            if KrbError::decode(&bytes).is_ok() {
                out.push(bytes);
            }
        }
    };
    // Unarmored AS: the FAST gate, an unknown client, the bootstrap.
    push(f.send(&AsReqSpec::alice().encode()));
    let mut unknown = AsReqSpec::alice();
    unknown.cname = Some(name(1, &["nobody"]));
    push(f.send(&unknown.encode()));
    push(f.send(&AsReqSpec::machine().encode()));
    push(
        f.send(
            &AsReqSpec::machine()
                .with_timestamp(&alice_key(AES256))
                .encode(),
        ),
    );
    // Armored AS: preauth required / failed / unknown / etype / options / times.
    push(f.send_fast(&AsReqSpec::alice()).reply);
    push(
        f.send_fast(&AsReqSpec::alice().with_challenge(&password_key(AES256, "wrong", ALICE_SALT)))
            .reply,
    );
    push(f.send_fast(&unknown).reply);
    let mut spec = AsReqSpec::alice();
    spec.etypes = vec![RC4_HMAC];
    push(f.send_fast(&spec).reply);
    let mut spec = AsReqSpec::alice();
    spec.options = options(&[30]);
    push(f.send_fast(&spec).reply);
    let mut spec = AsReqSpec::alice().with_challenge(&alice_key(AES256));
    spec.till = kt("20261113090000Z");
    push(f.send_fast(&spec).reply);
    // TGS: replay, revoked, unknown service, unarmored.
    let (request, _) = TgsReqSpec::service().encode(&tgt);
    push(f.send(&request));
    let mut replay = TgsReqSpec::service();
    replay.extra_padata = vec![krb_proto::PaData {
        padata_type: 128,
        padata_value: Vec::new(),
    }];
    push(f.send(&replay.encode(&tgt).0));
    let mut spec = TgsReqSpec::service();
    spec.sname = Some(name(3, &["host", "none.example.org"]));
    spec.cusec = 2;
    push(f.send(&spec.encode(&tgt).0));
    let mut spec = TgsReqSpec::service();
    spec.armored = false;
    spec.cusec = 4;
    push(f.send(&spec.encode(&tgt).0));
    f.accounts()
        .client_mut(&realm(), &alice_name())
        .unwrap()
        .state = AccountState {
        enabled: false,
        ..AccountState::ACTIVE
    };
    let mut spec = TgsReqSpec::service();
    spec.cusec = 3;
    push(f.send(&spec.encode(&tgt).0));
    // Undecodable.
    push(f.send(&[0x30, 0x00]));
    push(f.send(&[0xDE, 0xAD, 0xBE, 0xEF]));
    out
}

/// Decision 11 / docs/10 §9: no KRB-ERROR carries e-text; e-data only for
/// KDC_ERR_PREAUTH_REQUIRED (RFC 4120 5.9.1 METHOD-DATA) or for an armored
/// error, where it is METHOD-DATA with exactly one PA-FX-FAST (RFC 6113
/// 5.4.4); no key octets, passwords or derived keys anywhere in the bytes
/// (AGENTS.md §6) — the computer account's key and its TGT session key
/// included.
#[test]
fn no_krb_error_carries_e_text_or_key_material() {
    let errors = refusals();
    assert!(errors.len() >= 16, "sweep produced {} errors", errors.len());
    let alice_aes256 = alice_key(AES256);
    let alice_aes128 = alice_key(AES128);
    let f = Fixture::new();
    let machine_session = f.machine_tgt.session.octets().to_vec();
    let secrets: Vec<&[u8]> = vec![
        &KRBTGT_KEY[..],
        &KRBTGT_KEY[..16],
        &SERVICE_KEY[..],
        &SERVICE_KEY[..16],
        &MACHINE_KEY[..],
        &MACHINE_KEY[..16],
        &machine_session,
        alice_aes256.octets(),
        alice_aes128.octets(),
        ALICE_PASSWORD.as_bytes(),
        BOB_PASSWORD.as_bytes(),
    ];
    let mut armored = 0;
    for bytes in &errors {
        let error = KrbError::decode(bytes).unwrap();
        assert!(error.e_text.is_none(), "code {}", error.error_code);
        if let Some(e_data) = &error.e_data {
            let methods = MethodData::decode(e_data).unwrap();
            if error.error_code != KDC_ERR_PREAUTH_REQUIRED {
                assert_eq!(methods.0.len(), 1, "code {}", error.error_code);
                assert_eq!(methods.0[0].padata_type, PA_FX_FAST);
                armored += 1;
            }
        }
        assert!(error.ctime.is_none() && error.cusec.is_none());
        for secret in &secrets {
            assert!(!contains_bytes(bytes, secret));
        }
    }
    assert!(armored >= 6, "armored errors: {armored}");
}

/// RFC 4120 5.9.1 / decision 11: stime from the caller's `now`, susec 0
/// (KerberosTime has whole seconds); realm / sname from the request; for an
/// AS-REQ the requested crealm / cname.
#[test]
fn error_fields_come_from_now_and_the_request() {
    let mut f = Fixture::new();
    let mut spec = AsReqSpec::alice();
    spec.cname = Some(name(1, &["nobody"]));
    let when = at(42);
    let error = error_of(f.send_at(&spec.encode(), Transport::Tcp, when));
    assert_eq!(error.error_code, KDC_ERR_C_PRINCIPAL_UNKNOWN);
    assert_eq!(error.stime, when);
    assert_eq!(error.susec, Microseconds::default());
    assert_eq!(error.realm, realm());
    assert_eq!(error.sname, krbtgt_name());
    assert_eq!(error.crealm, Some(realm()));
    assert_eq!(error.cname, Some(name(1, &["nobody"])));
}

/// Decision 14: exactly one audit event per request, and no event carries
/// key material — its Debug rendering contains no secret octets in hex or
/// decimal-list form and no password.
#[test]
fn one_audit_event_per_request_without_secrets() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let (request, _) = TgsReqSpec::service().encode(&tgt);
    sent(f.send(&request));
    f.send(&AsReqSpec::alice().encode());
    f.send_at(&[1, 2, 3], Transport::Udp, now());
    assert_eq!(f.events().len(), 4);
    let text = format!("{:?}", f.events());
    assert!(!text.contains(ALICE_PASSWORD));
    for marker in [
        "199, 199, 199",
        "217, 217, 217",
        "227, 227, 227",
        "c7c7c7",
        "d9d9d9",
        "e3e3e3",
    ] {
        assert!(!text.contains(marker), "{marker}");
    }
}

/// Decision 3 / docs/10 §1: the configuration is checked at construction —
/// realm must be keyd's, the krbtgt handle must have purpose Krbtgt, the
/// custody caller must be the Kdc role (fail closed).
#[test]
fn configuration_is_validated() {
    let keyd_config = KeydConfig::new(realm());
    let mut config = KdcConfig::new(krb_proto::Realm::new("OTHER.ORG").unwrap(), KRBTGT);
    assert_eq!(
        config.validate(&keyd_config.description()),
        Err(ConfigError::RealmMismatch)
    );
    config.realm = realm();
    config.krbtgt = keyd::KeyHandle::new(KRBTGT.principal, KeyPurpose::Service);
    assert_eq!(
        config.validate(&keyd_config.description()),
        Err(ConfigError::KrbtgtPurpose)
    );
    config.krbtgt = KRBTGT;
    config.retransmit_capacity = 0;
    assert_eq!(
        config.validate(&keyd_config.description()),
        Err(ConfigError::RetransmitBounds)
    );
    let keyd = Keyd::with_entropy(
        keyd_config,
        InMemoryKeyStore::new(4),
        KeydAudit::default(),
        TestEntropy::default(),
        &keyd_started(),
    )
    .unwrap();
    assert!(matches!(
        LocalKeyd::new(keyd, DIRECTORY),
        Err(ConfigError::CustodyRole)
    ));
}
