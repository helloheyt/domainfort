//! The FAST armor core through keyd (docs/48 task T1): `open_fast_armor` and
//! `seal_fast_error` for the AS conversation, with the test acting as the KDC
//! (calling keyd) and as the client (building the armor AP-REQ, the subkey,
//! the req-checksum and the encrypted KrbFastReq with krb-crypto, and opening
//! the sealed KrbFastResponse with the armor key it derives itself).
//!
//! The client side is written from RFC 6113 §5.1 (KRB-FX-CF2), §5.4.1.1
//! (armor key, subkey MUST), §5.4.2 (req-checksum, enc-fast-req, usages
//! 50 / 51), §5.4.3-5.4.4 (KrbFastResponse, PA-FX-ERROR, usage 52) and RFC
//! 4120 §5.5.1 (authenticator, usage 11 per docs/questions/Q-120). RFC 6113
//! has no test vector for these derivations (docs/48 §9.2 item 15): these are
//! round-trip property tests. The computer account, keys and names are made
//! up for these tests; nothing comes from any other implementation.

mod common;

use common::*;
use keyd::{
    AuditOutcome, AuditReason, AuthnError, Error, FastArmor, FastConversation, KeyHandle,
    KeyPurpose, Kvno, Operation, PrincipalId, MAX_FX_COOKIE_LENGTH,
};
use krb_crypto::{ChecksumType, EncType, ProtocolKey};
use krb_proto::constants::{
    KDC_ERR_NONE, KDC_ERR_PREAUTH_FAILED, KDC_ERR_PREAUTH_REQUIRED, KRB_NT_SRV_INST,
    PA_ENCRYPTED_CHALLENGE, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, PA_FX_COOKIE, PA_FX_ERROR,
    PA_FX_FAST,
};
use krb_proto::{
    ApOptions, ApReq, Checksum, EncTgsRepPart, EncryptedData, EtypeInfo2, EtypeInfo2Entry,
    KerberosTime, KrbError, KrbFastArmoredReq, KrbFastReq, KrbFastResponse, PaData, PrincipalName,
    Realm, Ticket,
};

/// The client's armor subkey (RFC 6113 5.4.1.1), made up for the tests.
const SUBKEY: [u8; 32] = [0xA7; 32];
/// Outer and inner request nonces differ, so a test can tell which one keyd
/// used (RFC 6113 5.4.2: the inner req-body "is preferred").
const OUTER_NONCE: u32 = 0x0101_0101;
const INNER_NONCE: u32 = 0x2222_3333;

/// One armored AS request as the client built it, plus the armor key the
/// client derived (the KDC never has it).
struct Armored {
    req: KrbFastArmoredReq,
    outer: Vec<u8>,
    inner: KrbFastReq,
    armor_key: ProtocolKey,
}

/// keyd with the computer account and the computer's TGT (via the existing
/// AS path), audit cleared.
fn setup_with(endtime: KerberosTime) -> (Fixture, Tgt) {
    let mut f = Fixture::new();
    add_computer(&mut f);
    let tgt = obtain_computer_tgt(&mut f, now(), endtime);
    f.keyd.audit_sink_mut().records.clear();
    (f, tgt)
}

fn setup() -> (Fixture, Tgt) {
    setup_with(kt("20261113180000Z"))
}

/// An armored request on `ticket` / `session` with the armor authenticator
/// `spec`.
fn armored_on(ticket: &Ticket, session: &ProtocolKey, spec: &ArmorAuthSpec) -> Armored {
    let ap = ap_req(ticket, armor_authenticator(session, spec));
    let armor_key = client_armor_key(&spec.subkey.unwrap_or(SUBKEY), session);
    let (_, outer) = as_req_body(OUTER_NONCE);
    let inner = fast_req(INNER_NONCE);
    let req = armored_req(&ap, &armor_key, &outer, &inner);
    Armored {
        req,
        outer,
        inner,
        armor_key,
    }
}

fn armored_with(tgt: &Tgt, spec: &ArmorAuthSpec) -> Armored {
    armored_on(&tgt.parts.ticket, &tgt.session, spec)
}

/// A valid armored request; `cusec` makes the armor authenticator unique.
fn armored(tgt: &Tgt, cusec: u32) -> Armored {
    armored_with(tgt, &ArmorAuthSpec::new(now(), cusec, SUBKEY))
}

fn open_armor(f: &mut Fixture, a: &Armored, when: KerberosTime) -> Result<FastArmor, AuthnError> {
    f.keyd
        .open_fast_armor(&KDC, &KRBTGT, &a.req, &a.outer, &when)
}

fn last_reason(f: &Fixture) -> AuditReason {
    f.records().last().unwrap().reason
}

fn pa(padata_type: i32, padata_value: Vec<u8>) -> PaData {
    PaData {
        padata_type,
        padata_value,
    }
}

fn etype_info2(etype: i32) -> PaData {
    pa(
        PA_ETYPE_INFO2,
        EtypeInfo2(vec![EtypeInfo2Entry {
            etype,
            salt: Some(kstr(ALICE_SALT)),
            s2kparams: None,
        }])
        .encode()
        .unwrap(),
    )
}

fn cookie() -> PaData {
    pa(PA_FX_COOKIE, b"cookie-v1".to_vec())
}

fn seal(
    f: &mut Fixture,
    armor: &FastArmor,
    error: &KrbError,
    padata: &[PaData],
) -> Result<EncryptedData, Error> {
    f.keyd.seal_fast_error(
        &KDC,
        &FastConversation::As(armor.armor_id),
        error,
        padata,
        &now(),
    )
}

/// Full armor round trip: a computer TGT obtained through the AS path armors
/// an AS request; keyd returns the inner request and the armor ticket's
/// client, and audits the krbtgt handle and kvno. Source: RFC 6113 5.4.1.1
/// (armor TGT, subkey, armor key), 5.4.2 (req-checksum over the outer body,
/// enc-fast-req, inner req-body preferred); docs/48 §2.3, §2.4, §9.2 item 15.
#[test]
fn armor_round_trip_returns_the_inner_request() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 1);
    let armor = open_armor(&mut f, &a, now()).unwrap();
    assert_eq!(armor.fast_req, a.inner);
    assert_eq!(armor.fast_req.req_body.nonce, INNER_NONCE);
    assert_eq!(armor.armor_crealm, realm());
    assert_eq!(armor.armor_cname, ws01_name());
    assert_eq!(armor.armor_authtime, tgt.rep.0.authtime);

    let rec = f.records().last().unwrap();
    assert_eq!(rec.op, Operation::OpenFastArmor);
    assert_eq!(rec.result, AuditOutcome::Success);
    assert_eq!(rec.principal, Some(KRBTGT_ID));
    assert_eq!(rec.purpose, Some(KeyPurpose::Krbtgt));
    assert_eq!(rec.kvno, Some(Kvno::new(1)));
    assert_eq!(f.records().len(), 1, "one record per call (I8)");
}

/// A service ticket cannot be an armor ticket, even with a valid
/// authenticator under its session key. Source: RFC 6113 5.4.2 ("a non-TGT
/// cannot be used as an armor ticket in FX_FAST_ARMOR_AP_REQUEST"), 5.4.1.1
/// ("MUST identify the TGS of the target realm"); docs/48 §9.2 item 10.
#[test]
fn service_ticket_is_not_an_armor_ticket() {
    let (mut f, _) = setup();
    let alice_tgt = obtain_tgt(&mut f, now(), &as_template());
    let ctx = open_tgt(&mut f, &alice_tgt, 90, 90);
    let tgs = f
        .keyd
        .issue_tgs(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(90), &now())
        .unwrap();
    let service_session = key_from(
        &EncTgsRepPart::decode(&open(&alice_tgt.session, 8, &tgs.enc_part))
            .unwrap()
            .0
            .key,
    );
    let mut spec = ArmorAuthSpec::new(now(), 2, SUBKEY);
    spec.cname = alice_name();
    let a = armored_on(&tgs.ticket, &service_session, &spec);
    assert_eq!(open_armor(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::NotLocalTgt);
}

/// An armor ticket of another realm, or naming another realm's TGS, is
/// refused. Source: RFC 6113 5.4.1.1 ("The server name field of the armor
/// ticket MUST identify the TGS of the target realm"); RFC 4120 7.3;
/// docs/48 §9.2 item 10.
#[test]
fn armor_ticket_of_another_realm_denied() {
    let (mut f, tgt) = setup();
    let other = Realm::new("OTHER.ORG").unwrap();
    let mut foreign = tgt.parts.ticket.clone();
    foreign.realm = other.clone();
    let a = armored_on(
        &foreign,
        &tgt.session,
        &ArmorAuthSpec::new(now(), 3, SUBKEY),
    );
    assert_eq!(open_armor(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::NotLocalTgt);

    let mut foreign_tgs = tgt.parts.ticket.clone();
    foreign_tgs.sname = PrincipalName {
        name_type: KRB_NT_SRV_INST,
        name_string: vec![kstr("krbtgt"), other],
    };
    let a = armored_on(
        &foreign_tgs,
        &tgt.session,
        &ArmorAuthSpec::new(now(), 4, SUBKEY),
    );
    assert_eq!(open_armor(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::NotLocalTgt);
}

/// The krbtgt handle must be bound to krbtgt/REALM (A-19): a Krbtgt-purpose
/// key bound to another TGS name is refused — even with the very same key
/// octets, so it is the binding that refuses, not decryption. A handle of
/// another purpose is refused before any key is touched (I3). Source:
/// docs/questions/Q-040 (A-19); docs/48 §3.4, §9.1 I3; RFC 4120 7.3.
#[test]
fn armor_needs_the_bound_krbtgt_key() {
    let (mut f, tgt) = setup();
    let other_tgs = KeyHandle::new(PrincipalId::from_bytes([0x7C; 16]), KeyPurpose::Krbtgt);
    f.entropy.push(&KRBTGT_KEY);
    f.keyd
        .create_key(
            &ADMIN,
            &other_tgs,
            &bound(PrincipalName {
                name_type: KRB_NT_SRV_INST,
                name_string: vec![kstr("krbtgt"), kstr("OTHER.ORG")],
            }),
            &now(),
        )
        .unwrap();
    let a = armored(&tgt, 5);
    assert_eq!(
        f.keyd
            .open_fast_armor(&KDC, &other_tgs, &a.req, &a.outer, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameBindingMismatch);

    assert_eq!(
        f.keyd
            .open_fast_armor(&KDC, &SERVICE, &a.req, &a.outer, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::PurposeMismatch);

    // The refusals left the replay cache untouched: the request still works.
    assert!(open_armor(&mut f, &a, now()).is_ok());
}

/// The armor AP-REQ subkey is mandatory. Source: RFC 6113 5.4.1.1 ("The
/// subkey field in the AP-REQ MUST be present"); docs/48 §9.2 item 10.
#[test]
fn missing_subkey_denied() {
    let (mut f, tgt) = setup();
    let mut spec = ArmorAuthSpec::new(now(), 6, SUBKEY);
    spec.subkey = None;
    let a = armored_with(&tgt, &spec);
    assert_eq!(open_armor(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::ArmorSubkeyMissing);
}

/// A bad armor authenticator is refused uniformly: encrypted with the
/// PA-TGS-REQ usage 7 instead of 11 (Q-120 item 1), tampered, carrying a
/// checksum (Q-120 item 3), naming another client, or asking for
/// USE-SESSION-KEY. Source: RFC 4120 5.5.1 (usage 11 / 7, cksum,
/// use-session-key), 3.2.3 (BAD_INTEGRITY, BADMATCH); docs/questions/Q-120
/// (A-32); docs/48 §3.2, §9.2 item 10.
#[test]
fn bad_armor_authenticator_denied() {
    let (mut f, tgt) = setup();

    let mut spec = ArmorAuthSpec::new(now(), 7, SUBKEY);
    spec.usage = 7;
    let a = armored_with(&tgt, &spec);
    assert_eq!(open_armor(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);

    let a = armored(&tgt, 8);
    let mut ap = ApReq::decode(&a.req.armor.as_ref().unwrap().armor_value).unwrap();
    let last = ap.authenticator.cipher.len() - 1;
    ap.authenticator.cipher[last] ^= 0x01;
    let tampered = armored_req(&ap, &a.armor_key, &a.outer, &a.inner);
    assert_eq!(
        f.keyd
            .open_fast_armor(&KDC, &KRBTGT, &tampered, &a.outer, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);

    let mut spec = ArmorAuthSpec::new(now(), 9, SUBKEY);
    spec.cksum_over = Some(a.outer.clone());
    let a = armored_with(&tgt, &spec);
    assert_eq!(open_armor(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::ArmorChecksumPresent);

    let mut spec = ArmorAuthSpec::new(now(), 10, SUBKEY);
    spec.cname = bob_name();
    let a = armored_with(&tgt, &spec);
    assert_eq!(open_armor(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::NameMismatch);

    let a = armored(&tgt, 11);
    let mut ap = ApReq::decode(&a.req.armor.as_ref().unwrap().armor_value).unwrap();
    ap.ap_options = ApOptions::USE_SESSION_KEY;
    let u2u = armored_req(&ap, &a.armor_key, &a.outer, &a.inner);
    assert_eq!(
        f.keyd
            .open_fast_armor(&KDC, &KRBTGT, &u2u, &a.outer, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::UnsupportedApOption);
}

/// A replayed armor AP-REQ is the `Replay` class: the armor authenticator is
/// in the replay cache (Q-120 item 2), and only after the chain completed.
/// A fresh authenticator is accepted. Source: RFC 4120 3.2.3 (replay cache,
/// KRB_AP_ERR_REPEAT); docs/questions/Q-120 (A-32); docs/48 §3.3, §9.2
/// item 11.
#[test]
fn replayed_armor_authenticator_is_replay() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 12);
    assert!(open_armor(&mut f, &a, now()).is_ok());
    assert_eq!(open_armor(&mut f, &a, at(1)), Err(AuthnError::Replay));
    assert_eq!(last_reason(&f), AuditReason::Replay);
    assert!(open_armor(&mut f, &armored(&tgt, 13), now()).is_ok());
}

/// The req-checksum binds the armored part to the outer request: over a
/// different outer body, with the wrong key usage, under the subkey instead
/// of the armor key, or of a checksum type other than the armor key's
/// required one, it is refused. Source: RFC 6113 5.4.2 (checksum key = armor
/// key, required checksum type, KEY_USAGE_FAST_REQ_CHKSUM); RFC 3961 §3
/// (required checksum mechanism); docs/48 §9.2 item 9.
#[test]
fn req_checksum_must_cover_the_outer_body() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 14);
    let (_, other_outer) = as_req_body(OUTER_NONCE + 1);
    assert_eq!(
        f.keyd
            .open_fast_armor(&KDC, &KRBTGT, &a.req, &other_outer, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::FastChecksumMismatch);

    let mic = |key: &ProtocolKey, usage_number: u32| Checksum {
        cksumtype: ChecksumType::HmacSha196Aes256.number(),
        checksum: krb_crypto::get_mic(
            key,
            ChecksumType::HmacSha196Aes256,
            usage(usage_number),
            &a.outer,
        )
        .unwrap(),
    };
    let subkey = krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &SUBKEY).unwrap();
    for (name, checksum) in [
        ("usage 51", mic(&a.armor_key, 51)),
        ("subkey", mic(&subkey, 50)),
    ] {
        let mut req = a.req.clone();
        req.req_checksum = checksum;
        assert_eq!(
            f.keyd
                .open_fast_armor(&KDC, &KRBTGT, &req, &a.outer, &now()),
            Err(AuthnError::Denied),
            "{name}"
        );
        assert_eq!(last_reason(&f), AuditReason::FastChecksumMismatch, "{name}");
    }

    let mut req = a.req.clone();
    req.req_checksum.cksumtype = ChecksumType::HmacSha196Aes128.number();
    assert_eq!(
        f.keyd
            .open_fast_armor(&KDC, &KRBTGT, &req, &a.outer, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::ChecksumUnsupported);
}

/// enc-fast-req must decrypt under the armor key with usage 51 and decode as
/// KrbFastReq: tampered, sealed with usage 52, of another enctype, or a
/// well-sealed non-KrbFastReq is refused. Source: RFC 6113 5.4.2
/// (KEY_USAGE_FAST_ENC), 5.1 (the armor key has the subkey's enctype);
/// RFC 3961 §3 (decrypt integrity); docs/48 §6.3.
#[test]
fn tampered_enc_fast_req_denied() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 15);
    let try_req = |f: &mut Fixture, req: &KrbFastArmoredReq| {
        f.keyd.open_fast_armor(&KDC, &KRBTGT, req, &a.outer, &now())
    };

    let mut req = a.req.clone();
    req.enc_fast_req.cipher[20] ^= 0x80;
    assert_eq!(try_req(&mut f, &req), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);

    let mut req = a.req.clone();
    req.enc_fast_req.cipher = krb_crypto::encrypt(
        &a.armor_key,
        usage(52),
        &[0x66; 16],
        &a.inner.encode().unwrap(),
    )
    .unwrap();
    assert_eq!(try_req(&mut f, &req), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);

    let mut req = a.req.clone();
    req.enc_fast_req.etype = 17;
    assert_eq!(try_req(&mut f, &req), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::UnsupportedEncType);

    let mut req = a.req.clone();
    req.enc_fast_req.cipher =
        krb_crypto::encrypt(&a.armor_key, usage(51), &[0x66; 16], &a.outer).unwrap();
    assert_eq!(try_req(&mut f, &req), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::MalformedInput);
}

/// A-26 inside FAST: an expired armor TGT is the `TicketExpired` class only
/// when the whole chain passed; with a bad req-checksum, a tampered
/// enc-fast-req or no subkey it is the uniform `Denied`. A skewed
/// authenticator with a bad checksum is `Denied` too. Source: A-26
/// (docs/questions/Q-071); docs/48 §6.3, §9.2 item 11; RFC 4120 3.2.3.
#[test]
fn armor_classes_only_after_the_chain() {
    let (mut f, tgt) = setup_with(kt("20261113103000Z"));
    let later = kt("20261113103501Z"); // endtime + 301 s: expired
    let at_later = |cusec| ArmorAuthSpec::new(later, cusec, SUBKEY);

    let a = armored_with(&tgt, &at_later(20));
    let (_, other_outer) = as_req_body(OUTER_NONCE + 1);
    assert_eq!(
        f.keyd
            .open_fast_armor(&KDC, &KRBTGT, &a.req, &other_outer, &later),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::FastChecksumMismatch);

    let mut req = a.req.clone();
    req.enc_fast_req.cipher[16] ^= 0x01;
    assert_eq!(
        f.keyd
            .open_fast_armor(&KDC, &KRBTGT, &req, &a.outer, &later),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);

    let mut spec = at_later(21);
    spec.subkey = None;
    let no_subkey = armored_with(&tgt, &spec);
    assert_eq!(
        open_armor(&mut f, &no_subkey, later),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::ArmorSubkeyMissing);

    // The whole chain passes: now the class.
    assert_eq!(
        open_armor(&mut f, &a, later),
        Err(AuthnError::TicketExpired)
    );
    assert_eq!(last_reason(&f), AuditReason::TicketExpired);

    // Skewed authenticator (valid ticket) with a bad checksum: Denied.
    let (mut f, tgt) = setup();
    let skewed = armored_with(&tgt, &ArmorAuthSpec::new(at(-400), 22, SUBKEY));
    assert_eq!(
        f.keyd
            .open_fast_armor(&KDC, &KRBTGT, &skewed.req, &other_outer, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(open_armor(&mut f, &skewed, now()), Err(AuthnError::Skew));
}

/// Refused requests never enter the replay cache (A-26): the same armor
/// authenticator, refused for skew or for a bad req-checksum, is accepted
/// when presented correctly. Source: A-26 (docs/questions/Q-071); RFC 4120
/// 3.2.3; docs/48 §9.2 item 11 ("failures do not enter the replay cache").
#[test]
fn refusals_leave_the_replay_cache_unchanged() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 30);
    assert_eq!(open_armor(&mut f, &a, at(301)), Err(AuthnError::Skew));
    let (_, other_outer) = as_req_body(OUTER_NONCE + 1);
    assert_eq!(
        f.keyd
            .open_fast_armor(&KDC, &KRBTGT, &a.req, &other_outer, &now()),
        Err(AuthnError::Denied)
    );
    assert!(open_armor(&mut f, &a, now()).is_ok());
}

/// The armor must be present, of type FX_FAST_ARMOR_AP_REQUEST, a DER
/// AP-REQ; the outer body must be a KDC-REQ-BODY. Source: RFC 6113 5.4.1
/// ("If a FAST KDC receives an unknown armor type it MUST respond with
/// KDC_ERR_PREAUTH_FAILED" — keyd's `Denied`), 5.4.1.1, 5.4.2 ("MUST be
/// present in AS-REQ"); docs/48 §4.1 A3.
#[test]
fn armor_shape_is_checked() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 40);
    let try_req = |f: &mut Fixture, req: &KrbFastArmoredReq, outer: &[u8]| {
        f.keyd.open_fast_armor(&KDC, &KRBTGT, req, outer, &now())
    };

    let mut req = a.req.clone();
    req.armor = None;
    assert_eq!(try_req(&mut f, &req, &a.outer), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::ArmorMissing);

    let mut req = a.req.clone();
    req.armor.as_mut().unwrap().armor_type = 2;
    assert_eq!(try_req(&mut f, &req, &a.outer), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::ArmorTypeUnsupported);

    let mut req = a.req.clone();
    req.armor.as_mut().unwrap().armor_value = vec![0x30, 0x00];
    assert_eq!(try_req(&mut f, &req, &a.outer), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::MalformedInput);

    assert_eq!(
        try_req(&mut f, &a.req, &[0x30, 0x00]),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::MalformedInput);
}

/// The armor id is one-time, caller-bound and short-lived; the armor table is
/// bounded and fails closed. Source: docs/48 §2.3 ("every armor_id is
/// consumed exactly once ... or expires"), §9.1 I4, §9.2 item 2; docs/10 §8,
/// D36.
#[test]
fn armor_id_is_one_time_caller_bound_and_short_lived() {
    let (mut f, tgt) = setup();
    let error = fast_krb_error(KDC_ERR_PREAUTH_REQUIRED);

    // Used once, then unknown.
    let armor = open_armor(&mut f, &armored(&tgt, 50), now()).unwrap();
    assert!(seal(&mut f, &armor, &error, &[]).is_ok());
    assert_eq!(seal(&mut f, &armor, &error, &[]), Err(Error::Denied));
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);

    // Expired (30-second token lifetime): refused, and the entry is gone.
    let armor = open_armor(&mut f, &armored(&tgt, 51), now()).unwrap();
    let late = f.keyd.seal_fast_error(
        &KDC,
        &FastConversation::As(armor.armor_id),
        &error,
        &[],
        &at(31),
    );
    assert_eq!(late, Err(Error::Denied));
    assert_eq!(last_reason(&f), AuditReason::TokenExpired);
    assert_eq!(seal(&mut f, &armor, &error, &[]), Err(Error::Denied));
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);

    // Another caller: refused, and the armor is destroyed.
    let armor = open_armor(&mut f, &armored(&tgt, 52), now()).unwrap();
    assert_eq!(
        f.keyd.seal_fast_error(
            &KDC_OTHER,
            &FastConversation::As(armor.armor_id),
            &error,
            &[],
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TokenCallerMismatch);
    assert_eq!(seal(&mut f, &armor, &error, &[]), Err(Error::Denied));
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);

    // Bounded: one live armor at most; the second is refused (Denied to the
    // caller) instead of evicting the first.
    let mut c = config();
    c.max_armor_contexts = 1;
    let mut f = Fixture::with_config(c);
    add_computer(&mut f);
    let tgt = obtain_computer_tgt(&mut f, now(), kt("20261113180000Z"));
    let first = open_armor(&mut f, &armored(&tgt, 53), now()).unwrap();
    assert_eq!(
        open_armor(&mut f, &armored(&tgt, 54), now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TokenTableFull);
    assert_eq!(
        f.records().last().unwrap().result,
        AuditOutcome::Unavailable
    );
    assert!(seal(&mut f, &first, &error, &[]).is_ok());
}

/// The armor key never leaves keyd: no output, no Debug rendering and no
/// audit record holds the armor key, the subkey, the armor ticket's session
/// key or the long-term keys; the armor id's Debug shows a short prefix
/// only. Source: docs/48 §2.2, §9.1 I1, I8, §9.2 item 1; docs/10 §12 I1, I8;
/// docs/CLEAN-ROOM.md
#[test]
fn no_armor_key_in_any_output_or_audit_record() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 60);
    let armor = open_armor(&mut f, &a, now()).unwrap();
    let sealed = seal(
        &mut f,
        &armor,
        &fast_krb_error(KDC_ERR_PREAUTH_REQUIRED),
        &[cookie()],
    )
    .unwrap();

    let secrets: Vec<Vec<u8>> = vec![
        a.armor_key.octets().to_vec(),
        SUBKEY.to_vec(),
        tgt.rep.0.key.keyvalue.as_bytes().to_vec(),
        KRBTGT_KEY.to_vec(),
        WS01_KEY.to_vec(),
    ];
    let outputs: Vec<Vec<u8>> = vec![
        format!("{armor:?}").into_bytes(),
        armor.fast_req.encode().unwrap(),
        sealed.encode().unwrap(),
        format!("{sealed:?}").into_bytes(),
        format!("{:?}", f.keyd).into_bytes(),
        format!("{:?}", f.records()).into_bytes(),
    ];
    for out in &outputs {
        for secret in &secrets {
            assert!(!contains_bytes(out, secret));
        }
    }
    // Text renderings of the armor key's first octets (a leaked byte slice
    // in Debug output would look like these).
    let k = a.armor_key.octets();
    let renderings = [
        format!("{}, {}, {}, {}", k[0], k[1], k[2], k[3]),
        format!("{:02x}{:02x}{:02x}{:02x}", k[0], k[1], k[2], k[3]),
        format!("{:02X}{:02X}{:02X}{:02X}", k[0], k[1], k[2], k[3]),
    ];
    let text = format!("{armor:?}{:?}{:?}", f.keyd, f.records());
    for r in &renderings {
        assert!(!text.contains(r.as_str()), "{r}");
    }
    let id = format!("{:?}", armor.armor_id);
    assert!(id.starts_with("ArmorId(") && id.ends_with("..)"), "{id}");
}

/// The sealed error decrypts under the armor key (usage 52) to a
/// KrbFastResponse with the allowed padata, then PA-FX-ERROR holding the
/// KRB-ERROR (no e-data), the nonce of the stored INNER request, no
/// strengthen-key and no finished. Nothing else opens it: not the armor
/// ticket's session key, not the subkey, not the armor key under another
/// usage. Source: RFC 6113 5.4.3 (KEY_USAGE_FAST_REP; strengthen-key "MUST be
/// absent in KRB-ERROR"; finished "absent otherwise"; nonce), 5.4.4
/// (PA-FX-ERROR, e-data absent, padata in the KrbFastResponse); docs/48
/// §6.1, §9.2 items 3, 6, 7, 13.
#[test]
fn sealed_error_round_trip() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 70);
    let armor = open_armor(&mut f, &a, now()).unwrap();
    let error = fast_krb_error(KDC_ERR_PREAUTH_REQUIRED);
    let padata = vec![
        pa(PA_ENCRYPTED_CHALLENGE, Vec::new()),
        etype_info2(18),
        cookie(),
    ];
    let sealed = seal(&mut f, &armor, &error, &padata).unwrap();
    assert_eq!(sealed.etype, 18);
    assert_eq!(sealed.kvno, None);

    let plain = krb_crypto::decrypt(&a.armor_key, usage(52), &sealed.cipher).unwrap();
    let rep = KrbFastResponse::decode(&plain).unwrap();
    assert_eq!(rep.nonce, INNER_NONCE, "the stored inner nonce");
    assert_ne!(rep.nonce, OUTER_NONCE);
    assert!(rep.strengthen_key.is_none());
    assert!(rep.finished.is_none());
    assert_eq!(rep.padata.len(), padata.len() + 1);
    assert_eq!(rep.padata[..padata.len()], padata[..]);
    let fx = rep.padata.last().unwrap();
    assert_eq!(fx.padata_type, PA_FX_ERROR);
    let inner_error = KrbError::decode(&fx.padata_value).unwrap();
    assert_eq!(inner_error, error);
    assert!(inner_error.e_data.is_none());

    let subkey = krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &SUBKEY).unwrap();
    assert!(krb_crypto::decrypt(&tgt.session, usage(52), &sealed.cipher).is_err());
    assert!(krb_crypto::decrypt(&subkey, usage(52), &sealed.cipher).is_err());
    assert!(krb_crypto::decrypt(&a.armor_key, usage(51), &sealed.cipher).is_err());

    let rec = f.records().last().unwrap();
    assert_eq!(rec.op, Operation::SealFastError);
    assert_eq!(rec.result, AuditOutcome::Success);
    assert_eq!(rec.principal, None);

    // Names may be omitted (RFC 4120 5.9.1 "SHOULD be omitted" when unknown).
    let armor = open_armor(&mut f, &armored(&tgt, 71), now()).unwrap();
    let mut nameless = fast_krb_error(KDC_ERR_PREAUTH_FAILED);
    nameless.crealm = None;
    nameless.cname = None;
    assert!(seal(&mut f, &armor, &nameless, &[]).is_ok());
}

/// Padata outside the allowlist — or repeated, or with an unacceptable value
/// — is refused, and the armor is consumed anyway. Source: docs/48 §2.3
/// ("allowlist: PA-ETYPE-INFO2, PA-FX-COOKIE, PA-ENCRYPTED-CHALLENGE (empty
/// value)"), §6.1, §9.2 item 13; RFC 6113 5.4.4; Q-126 (cookie); docs/10
/// §12 I5 (only configured enctypes advertised).
#[test]
fn padata_outside_the_allowlist_is_refused() {
    let (mut f, tgt) = setup();
    let fx_error = fast_krb_error(25).encode().unwrap();
    let cases: Vec<(&str, Vec<PaData>)> = vec![
        ("PA-ENC-TIMESTAMP", vec![pa(PA_ENC_TIMESTAMP, Vec::new())]),
        ("caller PA-FX-ERROR", vec![pa(PA_FX_ERROR, fx_error)]),
        ("PA-FX-FAST", vec![pa(PA_FX_FAST, Vec::new())]),
        ("unknown type", vec![pa(165, vec![1])]),
        ("repeated cookie", vec![cookie(), cookie()]),
        (
            "challenge with a value",
            vec![pa(PA_ENCRYPTED_CHALLENGE, vec![1, 2, 3])],
        ),
        ("empty cookie", vec![pa(PA_FX_COOKIE, Vec::new())]),
        (
            "oversized cookie",
            vec![pa(PA_FX_COOKIE, vec![0x43; MAX_FX_COOKIE_LENGTH + 1])],
        ),
        ("unconfigured enctype", vec![etype_info2(17)]),
        (
            "undecodable ETYPE-INFO2",
            vec![pa(PA_ETYPE_INFO2, vec![0x30, 0x00])],
        ),
        (
            "allowed then refused",
            vec![cookie(), pa(PA_FX_FAST, Vec::new())],
        ),
    ];
    for (i, (name, padata)) in cases.iter().enumerate() {
        let armor = open_armor(&mut f, &armored(&tgt, 100 + i as u32), now()).unwrap();
        assert_eq!(
            seal(&mut f, &armor, &fast_krb_error(25), padata),
            Err(Error::Denied),
            "{name}"
        );
        assert_eq!(
            last_reason(&f),
            AuditReason::FastErrorPadataRefused,
            "{name}"
        );
        assert_eq!(
            seal(&mut f, &armor, &fast_krb_error(25), &[]),
            Err(Error::Denied),
            "{name}: consumed"
        );
    }
    // The bound itself is accepted.
    let armor = open_armor(&mut f, &armored(&tgt, 150), now()).unwrap();
    assert!(seal(
        &mut f,
        &armor,
        &fast_krb_error(25),
        &[pa(PA_FX_COOKIE, vec![0x43; MAX_FX_COOKIE_LENGTH])]
    )
    .is_ok());
}

/// A compromised KDC cannot have keyd seal anything but an error bound to
/// the request being answered: e-data, e-text, KDC_ERR_NONE, a negative
/// code, an stime other than now, or names other than the inner request's
/// are refused. Source: RFC 6113 5.4.4 ("The e-data field MUST be absent in
/// the PA-FX-ERROR"; "All other fields should be the same as the outer
/// KRB-ERROR"); RFC 4120 7.5.9 (KDC_ERR_NONE "No error"); docs/48 §2.3,
/// §6.1, §8, §9.2 item 13.
#[test]
fn forged_error_content_is_refused() {
    let (mut f, tgt) = setup();
    type Mutation = Box<dyn Fn(&mut KrbError)>;
    let cases: Vec<(&str, Mutation)> = vec![
        ("e-data", Box::new(|e| e.e_data = Some(Vec::new()))),
        ("e-text", Box::new(|e| e.e_text = Some(kstr("detail")))),
        ("KDC_ERR_NONE", Box::new(|e| e.error_code = KDC_ERR_NONE)),
        ("negative code", Box::new(|e| e.error_code = -1)),
        ("stime", Box::new(|e| e.stime = at(1))),
        ("another client", Box::new(|e| e.cname = Some(bob_name()))),
        (
            "another client realm",
            Box::new(|e| e.crealm = Some(Realm::new("OTHER.ORG").unwrap())),
        ),
        (
            "another realm",
            Box::new(|e| e.realm = Realm::new("OTHER.ORG").unwrap()),
        ),
        ("another service", Box::new(|e| e.sname = service_name())),
    ];
    for (i, (name, mutate)) in cases.iter().enumerate() {
        let armor = open_armor(&mut f, &armored(&tgt, 200 + i as u32), now()).unwrap();
        let mut error = fast_krb_error(KDC_ERR_PREAUTH_FAILED);
        mutate(&mut error);
        assert_eq!(
            seal(&mut f, &armor, &error, &[]),
            Err(Error::Denied),
            "{name}"
        );
        assert_eq!(
            last_reason(&f),
            AuditReason::FastErrorContentRefused,
            "{name}"
        );
    }
}
