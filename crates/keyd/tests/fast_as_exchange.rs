//! The armored AS exchange through keyd (docs/48 task T2): `verify_preauth`
//! with the encrypted challenge FAST factor under an opened armor, and
//! `issue_as_rep` with that armor — the strengthened reply key, the KDC's
//! encrypted challenge, KrbFastFinished and the sealed KrbFastResponse.
//!
//! The test acts as the KDC (calling keyd) and as the client: it builds the
//! armor (RFC 6113 §5.4.1.1, §5.4.2) and the encrypted challenge (§5.4.6),
//! and opens the reply with keys it derives itself — the armor key, the
//! challenge keys (KRB-FX-CF2 with the §5.4.6 peppers), the strengthened
//! reply key (KRB-FX-CF2 with the §5.4.3 peppers) — then verifies the
//! ticket-checksum of KrbFastFinished over the ticket octets (§5.4.3; the
//! full DER of the Ticket, docs/questions/Q-122). Key usages: RFC 6113 §6.2
//! (50-55) and RFC 4120 §7.5.1 (2, 3; usage 3 under the strengthened reply
//! key per docs/questions/Q-121).
//!
//! RFC 6113 has no test vector for these derivations (docs/48 §9.2 item
//! 15): these are round-trip and property tests. The accounts, keys, names
//! and nonces are made up for these tests; nothing comes from any other
//! implementation.

mod common;

use common::*;
use keyd::{
    AsRepParts, AsTicketTemplate, AuditOutcome, AuditReason, AuthnError, AuthnProof, Error,
    FastArmor, FastConversation, IssueError, KeyPurpose, Kvno, Operation, ThrottlePolicy,
};
use krb_crypto::{ChecksumType, EncType, ProtocolKey};
use krb_proto::constants::{
    KDC_ERR_PREAUTH_FAILED, KRB_AP_ERR_SKEW, PA_ENCRYPTED_CHALLENGE, PA_ETYPE_INFO2,
};
use krb_proto::{
    EncAsRepPart, EncTicketPart, EncryptedData, EtypeInfo2, EtypeInfo2Entry, KerberosTime,
    KrbFastReq, KrbFastResponse, Microseconds, PaData, PaEncTsEnc, Realm,
};

/// The client's armor subkey (RFC 6113 5.4.1.1), made up for the tests.
const SUBKEY: [u8; 32] = [0xA7; 32];
/// Outer and inner request nonces differ, so a test can tell which one keyd
/// used (RFC 6113 5.4.2: the inner req-body "is preferred").
const OUTER_NONCE: u32 = 0x0101_0101;
const INNER_NONCE: u32 = 0x2222_3333;

/// The client challenge key: KRB-FX-CF2(armor_key, long_term_key,
/// "clientchallengearmor", "challengelongterm") — RFC 6113 5.4.6.
fn client_challenge_key(armor_key: &ProtocolKey, long_term: &ProtocolKey) -> ProtocolKey {
    krb_crypto::krb_fx_cf2(
        armor_key,
        long_term,
        b"clientchallengearmor",
        b"challengelongterm",
    )
    .unwrap()
}

/// The KDC challenge key: KRB-FX-CF2(armor_key, long_term_key,
/// "kdcchallengearmor", "challengelongterm") — RFC 6113 5.4.6.
fn kdc_challenge_key(armor_key: &ProtocolKey, long_term: &ProtocolKey) -> ProtocolKey {
    krb_crypto::krb_fx_cf2(
        armor_key,
        long_term,
        b"kdcchallengearmor",
        b"challengelongterm",
    )
    .unwrap()
}

/// The strengthened reply key: KRB-FX-CF2(strengthen-key,
/// padata-reply-key, "strengthenkey", "replykey") — RFC 6113 5.4.3.
fn reply_key(strengthen: &ProtocolKey, client_key: &ProtocolKey) -> ProtocolKey {
    krb_crypto::krb_fx_cf2(strengthen, client_key, b"strengthenkey", b"replykey").unwrap()
}

fn pa(padata_type: i32, padata_value: Vec<u8>) -> PaData {
    PaData {
        padata_type,
        padata_value,
    }
}

/// PA-ENCRYPTED-CHALLENGE: PA-ENC-TS-ENC encrypted in `key` with key usage
/// `usage_number` (54 for the client), as EncryptedData of `etype`.
/// RFC 6113 5.4.6; RFC 4120 5.2.7.2.
fn challenge_with(key: &ProtocolKey, usage_number: u32, etype: i32, ts: KerberosTime) -> PaData {
    let plain = PaEncTsEnc {
        patimestamp: ts,
        pausec: Some(Microseconds::new(77).unwrap()),
    }
    .encode()
    .unwrap();
    let cipher = krb_crypto::encrypt(key, usage(usage_number), &[0x77; 16], &plain).unwrap();
    pa(
        PA_ENCRYPTED_CHALLENGE,
        EncryptedData {
            etype,
            kvno: None,
            cipher,
        }
        .encode()
        .unwrap(),
    )
}

/// A correct encrypted challenge of the client holding `long_term` under the
/// armor key `armor_key`, at `ts`.
fn challenge(armor_key: &ProtocolKey, long_term: &ProtocolKey, ts: KerberosTime) -> PaData {
    let key = client_challenge_key(armor_key, long_term);
    challenge_with(&key, 54, key.enc_type().number(), ts)
}

/// An inner request for alice (cname, realm, etype list adjustable).
fn inner_request(nonce: u32) -> KrbFastReq {
    fast_req(nonce)
}

/// keyd with the computer account and its TGT (the armor TGT, D126),
/// obtained through the unarmored AS path; audit cleared.
fn setup_with(config: keyd::KeydConfig) -> (Fixture, Tgt) {
    let mut f = Fixture::with_config(config);
    add_computer(&mut f);
    let tgt = obtain_computer_tgt(&mut f, now(), kt("20261113180000Z"));
    f.keyd.audit_sink_mut().records.clear();
    (f, tgt)
}

fn setup() -> (Fixture, Tgt) {
    setup_with(config())
}

/// Open an armor with the client subkey `subkey` for `inner` (armor
/// authenticator made unique by `cusec`); returns keyd's FastArmor and the
/// armor key the CLIENT derived.
fn open_armor_keyed(
    f: &mut Fixture,
    tgt: &Tgt,
    cusec: u32,
    subkey: [u8; 32],
    inner: &KrbFastReq,
) -> (FastArmor, ProtocolKey) {
    let ap = ap_req(
        &tgt.parts.ticket,
        armor_authenticator(&tgt.session, &ArmorAuthSpec::new(now(), cusec, subkey)),
    );
    let armor_key = client_armor_key(&subkey, &tgt.session);
    let (_, outer) = as_req_body(OUTER_NONCE);
    let req = armored_req(&ap, &armor_key, &outer, inner);
    let armor = f
        .keyd
        .open_fast_armor(&KDC, &KRBTGT, &req, &outer, &now())
        .unwrap();
    (armor, armor_key)
}

/// [`open_armor_keyed`] with [`SUBKEY`].
fn open_armor_for(
    f: &mut Fixture,
    tgt: &Tgt,
    cusec: u32,
    inner: &KrbFastReq,
) -> (FastArmor, ProtocolKey) {
    open_armor_keyed(f, tgt, cusec, SUBKEY, inner)
}

fn open_armor(f: &mut Fixture, tgt: &Tgt, cusec: u32) -> (FastArmor, ProtocolKey) {
    open_armor_for(f, tgt, cusec, &inner_request(INNER_NONCE))
}

/// alice's TGT template answering the inner request (its nonce).
fn armored_template() -> AsTicketTemplate {
    AsTicketTemplate {
        nonce: INNER_NONCE,
        ..as_template()
    }
}

fn preauth(f: &mut Fixture, armor: &FastArmor, padata: &PaData) -> Result<AuthnProof, AuthnError> {
    f.keyd
        .verify_preauth(&KDC, &ALICE, padata, Some(armor.armor_id), &now())
}

fn issue(
    f: &mut Fixture,
    proof: &AuthnProof,
    armor: &FastArmor,
    template: &AsTicketTemplate,
) -> Result<AsRepParts, IssueError> {
    f.keyd.issue_as(
        &KDC,
        &ALICE,
        &KRBTGT,
        proof,
        Some(armor.armor_id),
        template,
        &now(),
    )
}

/// An armored KRB-ERROR sealed by the KDC for `armor` (docs/48 §6.1).
fn seal_error(f: &mut Fixture, armor: &FastArmor, code: i32) -> Result<EncryptedData, Error> {
    let etype_info2 = pa(
        PA_ETYPE_INFO2,
        EtypeInfo2(vec![EtypeInfo2Entry {
            etype: 18,
            salt: Some(kstr(ALICE_SALT)),
            s2kparams: None,
        }])
        .encode()
        .unwrap(),
    );
    f.keyd.seal_fast_error(
        &KDC,
        &FastConversation::As(armor.armor_id),
        &fast_krb_error(code),
        &[etype_info2],
        &now(),
    )
}

fn last_reason(f: &Fixture) -> AuditReason {
    f.records().last().unwrap().reason
}

/// The decrypted KrbFastResponse of an armored reply.
fn fast_response(armor_key: &ProtocolKey, parts: &AsRepParts) -> KrbFastResponse {
    let fast_rep = parts.fast_rep.as_ref().expect("armored reply has fast_rep");
    KrbFastResponse::decode(&open(armor_key, 52, fast_rep)).unwrap()
}

/// Full armored AS round trip. The client builds the armor and an encrypted
/// challenge; keyd verifies it and issues; the client decrypts KrbFastResponse
/// with its armor key (usage 52), takes the strengthen key, derives the reply
/// key, decrypts EncASRepPart (usage 3), checks the KDC's encrypted challenge
/// (usage 55) and verifies the ticket-checksum of KrbFastFinished over the
/// ticket octets (usage 53). The armor is consumed. Source: RFC 6113 5.4.3
/// (strengthen-key, reply-key, KrbFastFinished, nonce, KEY_USAGE_FAST_REP /
/// FINISHED), 5.4.6 (challenge keys, usages 54 / 55, "it MUST include a padata
/// element of type PA-ENCRYPTED-CHALLENGE"), 6.2; RFC 4120 5.4.2 (usage 3,
/// client kvno); docs/48 §4.3, §4.4, §9.2 items 3, 6, 7, 15;
/// docs/questions/Q-121, Q-122, Q-123.
#[test]
fn armored_as_round_trip() {
    let (mut f, tgt) = setup();
    let (armor, armor_key) = open_armor(&mut f, &tgt, 1);
    let proof = preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())).unwrap();
    let parts = issue(&mut f, &proof, &armor, &armored_template()).unwrap();

    // The KrbFastResponse, under the armor key.
    let fast_rep = parts.fast_rep.as_ref().unwrap();
    assert_eq!(fast_rep.etype, 18);
    assert_eq!(fast_rep.kvno, None);
    let response = fast_response(&armor_key, &parts);
    assert_eq!(response.nonce, INNER_NONCE, "the stored inner nonce");

    // The strengthen key, of the client key's enctype, and the reply key.
    let strengthen = key_from(response.strengthen_key.as_ref().unwrap());
    assert_eq!(strengthen.enc_type(), EncType::Aes256CtsHmacSha196);
    let reply = reply_key(&strengthen, &alice_key());
    assert_eq!(parts.enc_part.etype, 18);
    assert_eq!(parts.enc_part.kvno, Some(1), "the client kvno (Q-121)");
    let rep = EncAsRepPart::decode(&open(&reply, 3, &parts.enc_part)).unwrap();
    assert_eq!(rep.0.nonce, INNER_NONCE);
    assert_eq!(rep.0.sname, krbtgt_name());

    // The ticket: under krbtgt, for alice, with the session key of the reply.
    let ticket_part =
        EncTicketPart::decode(&open(&krbtgt_key(), 2, &parts.ticket.enc_part)).unwrap();
    assert_eq!(ticket_part.cname, alice_name());
    assert_eq!(ticket_part.key, rep.0.key);

    // KrbFastFinished: KDC time, the ticket's client, the ticket-checksum.
    let finished = response.finished.as_ref().unwrap();
    assert_eq!(finished.timestamp, now());
    assert_eq!(finished.usec, Microseconds::default());
    assert_eq!(finished.crealm, realm());
    assert_eq!(finished.cname, alice_name());
    assert_eq!(
        finished.ticket_checksum.cksumtype,
        ChecksumType::HmacSha196Aes256.number()
    );
    let ticket_octets = parts.ticket.encode().unwrap();
    krb_crypto::verify_mic(
        &armor_key,
        ChecksumType::HmacSha196Aes256,
        usage(53),
        &ticket_octets,
        &finished.ticket_checksum.checksum,
    )
    .expect("ticket-checksum over the ticket DER (Q-122)");

    // The KDC's encrypted challenge: its current time, KDC challenge key.
    assert_eq!(response.padata.len(), 1);
    assert_eq!(response.padata[0].padata_type, PA_ENCRYPTED_CHALLENGE);
    let kdc_challenge = EncryptedData::decode(&response.padata[0].padata_value).unwrap();
    assert_eq!(kdc_challenge.etype, 18);
    assert_eq!(kdc_challenge.kvno, None);
    let kdc_key = kdc_challenge_key(&armor_key, &alice_key());
    let ts = PaEncTsEnc::decode(&open(&kdc_key, 55, &kdc_challenge)).unwrap();
    assert_eq!(ts.patimestamp, now());
    assert_eq!(ts.pausec, None);
    // Key separation: the client challenge key does not open it.
    let client_key = client_challenge_key(&armor_key, &alice_key());
    assert!(krb_crypto::decrypt(&client_key, usage(55), &kdc_challenge.cipher).is_err());

    // One record per call; the armor is consumed (exactly once).
    let ops: Vec<_> = f.records().iter().map(|r| (r.op, r.result)).collect();
    assert_eq!(
        ops,
        [
            (Operation::OpenFastArmor, AuditOutcome::Success),
            (Operation::VerifyPreauth, AuditOutcome::Success),
            (Operation::IssueAsRep, AuditOutcome::Success),
        ]
    );
    let rec = f.records().last().unwrap();
    assert_eq!(rec.principal, Some(ALICE_ID));
    assert_eq!(rec.purpose, Some(KeyPurpose::PrincipalLongterm));
    assert_eq!(rec.kvno, Some(Kvno::new(1)));
    assert_eq!(
        seal_error(&mut f, &armor, KDC_ERR_PREAUTH_FAILED),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);
}

/// The strengthened enc-part does not open under the plain client key, nor
/// under the strengthen key alone; the KrbFastResponse does not open without
/// the armor key — not under the armor ticket's session key, the subkey, the
/// client key or krbtgt, nor under the armor key with another usage. Each
/// reply draws a fresh strengthen key. Source: RFC 6113 5.4 (FAST against
/// offline dictionary attacks), 5.4.3 (strengthen-key "MUST be randomly
/// generated"; KEY_USAGE_FAST_REP); docs/48 §4.3, §9.2 item 3.
#[test]
fn reply_needs_the_armor_and_the_strengthen_key() {
    let (mut f, tgt) = setup();
    let (armor, armor_key) = open_armor(&mut f, &tgt, 2);
    let proof = preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())).unwrap();
    let parts = issue(&mut f, &proof, &armor, &armored_template()).unwrap();
    let response = fast_response(&armor_key, &parts);
    let strengthen = key_from(response.strengthen_key.as_ref().unwrap());

    let enc = &parts.enc_part.cipher;
    assert!(krb_crypto::decrypt(&alice_key(), usage(3), enc).is_err());
    assert!(krb_crypto::decrypt(&strengthen, usage(3), enc).is_err());
    assert!(krb_crypto::decrypt(&reply_key(&strengthen, &alice_key()), usage(3), enc).is_ok());

    let fast = &parts.fast_rep.as_ref().unwrap().cipher;
    let subkey = krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &SUBKEY).unwrap();
    for (name, key) in [
        ("armor ticket session key", &tgt.session),
        ("subkey", &subkey),
        ("client key", &alice_key()),
        ("krbtgt", &krbtgt_key()),
    ] {
        assert!(krb_crypto::decrypt(key, usage(52), fast).is_err(), "{name}");
    }
    assert!(krb_crypto::decrypt(&armor_key, usage(51), fast).is_err());

    // A second conversation: a different strengthen key.
    let (armor, armor_key) = open_armor(&mut f, &tgt, 3);
    let proof = preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())).unwrap();
    let parts = issue(&mut f, &proof, &armor, &armored_template()).unwrap();
    let second = fast_response(&armor_key, &parts);
    assert_ne!(second.strengthen_key, response.strengthen_key);
}

/// A challenge that is not the client's, for this armor, is the uniform
/// `Denied`: a wrong password's key, the plain client key (no KRB-FX-CF2), the
/// KDC challenge key, the right key with the PA-ENC-TIMESTAMP usage, a
/// challenge cut from another conversation (another armor), a tampered
/// ciphertext, a well-sealed non-PA-ENC-TS-ENC, an undecodable value, or a
/// challenge of an enctype other than the armor key's. Source: RFC 6113 5.4.6
/// ("If the decryption fails the KDC SHOULD return KDC_ERR_PREAUTH_FAILED"),
/// 5.1 (enctype of k1), 8 ("bind each FAST factor to the armor key");
/// docs/48 §4.5; A-26.
#[test]
fn wrong_or_tampered_challenge_denied() {
    // Many failures in a row: a throttle policy that does not cut in (the
    // throttle itself is covered below).
    let mut c = config();
    c.preauth_throttle = ThrottlePolicy {
        max_failures: 100,
        window_secs: 60,
        capacity: 8,
    };
    let (mut f, tgt) = setup_with(c);
    let wrong_password = password_key(EncType::Aes256CtsHmacSha196, "not alice's", ALICE_SALT);
    // Each case builds its padata from the client's armor key.
    type Case<'a> = (
        &'a str,
        Box<dyn Fn(&ProtocolKey) -> PaData + 'a>,
        AuditReason,
    );
    let cases: Vec<Case> = vec![
        (
            "wrong password",
            Box::new(|ak: &ProtocolKey| challenge(ak, &wrong_password, now())),
            AuditReason::IntegrityFailure,
        ),
        (
            "plain client key",
            Box::new(|_: &ProtocolKey| challenge_with(&alice_key(), 54, 18, now())),
            AuditReason::IntegrityFailure,
        ),
        (
            "KDC challenge key",
            Box::new(|ak: &ProtocolKey| {
                challenge_with(&kdc_challenge_key(ak, &alice_key()), 54, 18, now())
            }),
            AuditReason::IntegrityFailure,
        ),
        (
            "usage 1",
            Box::new(|ak: &ProtocolKey| {
                challenge_with(&client_challenge_key(ak, &alice_key()), 1, 18, now())
            }),
            AuditReason::IntegrityFailure,
        ),
        (
            "tampered",
            Box::new(|ak: &ProtocolKey| {
                let mut p = challenge(ak, &alice_key(), now());
                let mut enc = EncryptedData::decode(&p.padata_value).unwrap();
                let last = enc.cipher.len() - 1;
                enc.cipher[last] ^= 0x01;
                p.padata_value = enc.encode().unwrap();
                p
            }),
            AuditReason::IntegrityFailure,
        ),
        (
            "not PA-ENC-TS-ENC",
            Box::new(|ak: &ProtocolKey| {
                let key = client_challenge_key(ak, &alice_key());
                let cipher =
                    krb_crypto::encrypt(&key, usage(54), &[0x77; 16], &[0x30, 0x00]).unwrap();
                let enc = EncryptedData {
                    etype: 18,
                    kvno: None,
                    cipher,
                };
                pa(PA_ENCRYPTED_CHALLENGE, enc.encode().unwrap())
            }),
            AuditReason::MalformedInput,
        ),
        (
            "undecodable",
            Box::new(|_: &ProtocolKey| pa(PA_ENCRYPTED_CHALLENGE, vec![0x30, 0x00])),
            AuditReason::MalformedInput,
        ),
        (
            "enctype other than the armor key's",
            Box::new(|ak: &ProtocolKey| {
                challenge_with(&client_challenge_key(ak, &alice_key()), 54, 17, now())
            }),
            AuditReason::ChallengeEncTypeMismatch,
        ),
    ];
    for (i, (name, padata, reason)) in cases.iter().enumerate() {
        let (armor, armor_key) = open_armor(&mut f, &tgt, 100 + i as u32);
        assert_eq!(
            preauth(&mut f, &armor, &padata(&armor_key)),
            Err(AuthnError::Denied),
            "{name}"
        );
        assert_eq!(last_reason(&f), *reason, "{name}");
    }

    // Cut and paste from another conversation: a correct challenge for
    // armor A presented with armor B.
    let (_, key_a) = open_armor(&mut f, &tgt, 200);
    let (armor_b, _) = open_armor_keyed(&mut f, &tgt, 201, [0xB7; 32], &inner_request(INNER_NONCE));
    assert_eq!(
        preauth(&mut f, &armor_b, &challenge(&key_a, &alice_key(), now())),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);
}

/// One pre-authentication attempt per armor, success or failure: a second
/// attempt is refused even when correct. A failed attempt leaves the armor
/// live for the armored KDC_ERR_PREAUTH_FAILED. Source: docs/48 §2.3 ("one
/// attempt per armor — success or failure"), §4.1 A10, §9.2 item 2; RFC 6113
/// 5.4.6 (KDC_ERR_PREAUTH_FAILED with PA-ETYPE-INFO2 in the KrbFastResponse).
#[test]
fn one_preauth_attempt_per_armor() {
    let (mut f, tgt) = setup();

    // After a success.
    let (armor, armor_key) = open_armor(&mut f, &tgt, 10);
    let good = challenge(&armor_key, &alice_key(), now());
    assert!(preauth(&mut f, &armor, &good).is_ok());
    assert_eq!(preauth(&mut f, &armor, &good), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::ArmorAlreadyAttempted);

    // After a failure: the correct challenge is refused too, and the KDC can
    // still seal the armored error.
    let (armor, armor_key) = open_armor(&mut f, &tgt, 11);
    let wrong = password_key(EncType::Aes256CtsHmacSha196, "guess", ALICE_SALT);
    assert_eq!(
        preauth(&mut f, &armor, &challenge(&armor_key, &wrong, now())),
        Err(AuthnError::Denied)
    );
    assert_eq!(
        preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::ArmorAlreadyAttempted);
    let sealed = seal_error(&mut f, &armor, KDC_ERR_PREAUTH_FAILED).unwrap();
    let response = KrbFastResponse::decode(&open(&armor_key, 52, &sealed)).unwrap();
    assert_eq!(response.nonce, INNER_NONCE);
    assert!(response.strengthen_key.is_none() && response.finished.is_none());
}

/// The armor id is the caller's and live: another caller's presentation is
/// refused and destroys it; an unknown or expired armor is refused. Source:
/// docs/48 §9.1 I4, §9.2 item 2 ("another caller → Denied and the token is
/// destroyed"); docs/10 §8, D36.
#[test]
fn armor_of_another_caller_or_expired_is_refused() {
    let (mut f, tgt) = setup();
    let (armor, armor_key) = open_armor(&mut f, &tgt, 20);
    let good = challenge(&armor_key, &alice_key(), now());
    assert_eq!(
        f.keyd
            .verify_preauth(&KDC_OTHER, &ALICE, &good, Some(armor.armor_id), &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TokenCallerMismatch);
    assert_eq!(preauth(&mut f, &armor, &good), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);
    assert_eq!(
        seal_error(&mut f, &armor, KDC_ERR_PREAUTH_FAILED),
        Err(Error::Denied)
    );

    // Expired (30-second token lifetime).
    let (armor, armor_key) = open_armor(&mut f, &tgt, 21);
    assert_eq!(
        f.keyd.verify_preauth(
            &KDC,
            &ALICE,
            &challenge(&armor_key, &alice_key(), at(31)),
            Some(armor.armor_id),
            &at(31),
        ),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TokenExpired);
}

/// The proof and the armor are one conversation: a proof of armor A is
/// refused with armor B (and B still issues with its own proof); an
/// unarmored proof is refused with an armor (which stays live for the
/// armored error); an armored proof is refused without its armor. The proof
/// is consumed by the refused call. Source: docs/48 §2.3 ("None↔None,
/// Some(a)↔Some(a)"; "a proof bound to armor A is not accepted with armor
/// B, nor without armor"), §9.2 item 8.
#[test]
fn proof_is_bound_to_its_armor() {
    let (mut f, tgt) = setup();
    // Two conversations, each with its own fresh armor key (RFC 6113 5.4).
    let (armor_a, key_a) = open_armor(&mut f, &tgt, 30);
    let (armor_b, key_b) =
        open_armor_keyed(&mut f, &tgt, 31, [0xB7; 32], &inner_request(INNER_NONCE));
    let proof_a = preauth(&mut f, &armor_a, &challenge(&key_a, &alice_key(), now())).unwrap();
    let proof_b = preauth(&mut f, &armor_b, &challenge(&key_b, &alice_key(), now())).unwrap();
    assert_eq!(
        issue(&mut f, &proof_a, &armor_b, &armored_template()),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::ArmorProofMismatch);
    assert!(issue(&mut f, &proof_b, &armor_b, &armored_template()).is_ok());
    // proof_a was consumed by the refused call.
    assert_eq!(
        issue(&mut f, &proof_a, &armor_a, &armored_template()),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);

    // An unarmored proof (PA-ENC-TIMESTAMP) with an armor.
    let (armor_c, _) = open_armor(&mut f, &tgt, 32);
    let unarmored = f
        .keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), now()),
            None,
            &now(),
        )
        .unwrap();
    assert_eq!(
        issue(&mut f, &unarmored, &armor_c, &armored_template()),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::ArmorProofMismatch);
    assert!(seal_error(&mut f, &armor_c, KDC_ERR_PREAUTH_FAILED).is_ok());

    // An armored proof without its armor.
    let (armor_d, key_d) = open_armor(&mut f, &tgt, 33);
    let proof_d = preauth(&mut f, &armor_d, &challenge(&key_d, &alice_key(), now())).unwrap();
    assert_eq!(
        f.keyd.issue_as(
            &KDC,
            &ALICE,
            &KRBTGT,
            &proof_d,
            None,
            &armored_template(),
            &now()
        ),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::ArmorProofMismatch);
}

/// The template must answer the inner request keyd stored: a nonce other
/// than the inner one (e.g. the outer one), a cname or a realm other than the
/// inner req-body's is refused — and the armor stays live for the armored
/// refusal. Source: docs/48 §3.4 (template crealm / cname / nonce equal the
/// inner req-body's), §4.1 A13, §9.2 items 7, 8; RFC 6113 5.4.2 ("This
/// req-body field is preferred over the outer field"), 5.4.3 (nonce "binds
/// the KDC response with the client request").
#[test]
fn template_must_answer_the_inner_request() {
    let (mut f, tgt) = setup();

    // The outer nonce instead of the inner one.
    let (armor, armor_key) = open_armor(&mut f, &tgt, 40);
    let proof = preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())).unwrap();
    let outer_nonce = AsTicketTemplate {
        nonce: OUTER_NONCE,
        ..as_template()
    };
    assert_eq!(
        issue(&mut f, &proof, &armor, &outer_nonce),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::FastBindingMismatch);
    assert!(seal_error(&mut f, &armor, KDC_ERR_PREAUTH_FAILED).is_ok());

    // The client asked for bob; the KDC issues for alice (whose key
    // pre-authenticated) — the inner cname is not the template's.
    let mut for_bob = inner_request(INNER_NONCE);
    for_bob.req_body.cname = Some(bob_name());
    let (armor, armor_key) = open_armor_for(&mut f, &tgt, 41, &for_bob);
    let proof = preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())).unwrap();
    assert_eq!(
        issue(&mut f, &proof, &armor, &armored_template()),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::FastBindingMismatch);

    // The inner req-body names another realm.
    let mut other_realm = inner_request(INNER_NONCE);
    other_realm.req_body.realm = Realm::new("OTHER.ORG").unwrap();
    let (armor, armor_key) = open_armor_for(&mut f, &tgt, 42, &other_realm);
    let proof = preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())).unwrap();
    assert_eq!(
        issue(&mut f, &proof, &armor, &armored_template()),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::FastBindingMismatch);
}

/// A skewed encrypted challenge is the `Skew` class only after it decrypted
/// under the challenge key; with a wrong key it is the uniform `Denied`. The
/// skew uses up the armor's attempt, does not count for the throttle, and
/// leaves the armor live for the armored KRB_AP_ERR_SKEW. Source: RFC 6113
/// 5.4.6 ("confirms that the timestamp falls within its current clock skew
/// returning KRB_APP_ERR_SKEW if not"); A-26 (docs/questions/Q-071);
/// docs/48 R48-6, §6.3; A-34.
#[test]
fn skewed_challenge_is_skew_only_after_decryption() {
    let (mut f, tgt) = setup();
    let wrong = password_key(EncType::Aes256CtsHmacSha196, "guess", ALICE_SALT);

    let (armor, armor_key) = open_armor(&mut f, &tgt, 50);
    assert_eq!(
        preauth(&mut f, &armor, &challenge(&armor_key, &wrong, at(-400))),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);

    let (armor, armor_key) = open_armor(&mut f, &tgt, 51);
    assert_eq!(
        preauth(
            &mut f,
            &armor,
            &challenge(&armor_key, &alice_key(), at(-400))
        ),
        Err(AuthnError::Skew)
    );
    assert_eq!(last_reason(&f), AuditReason::ClockSkew);
    assert_eq!(
        preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::ArmorAlreadyAttempted);
    assert!(seal_error(&mut f, &armor, KRB_AP_ERR_SKEW).is_ok());

    let (armor, armor_key) = open_armor(&mut f, &tgt, 52);
    assert_eq!(
        preauth(
            &mut f,
            &armor,
            &challenge(&armor_key, &alice_key(), at(301))
        ),
        Err(AuthnError::Skew)
    );
}

/// The A-34 throttle counts encrypted-challenge failures exactly as
/// PA-ENC-TIMESTAMP failures, in one per-principal count: after three
/// failures (mixed) even a correct challenge — or a correct timestamp — is
/// refused as the uniform `Denied`, audited `Throttled` before any key is
/// resolved; a successful challenge clears the count. Source: decision A-34;
/// docs/10 §4 (throttle); docs/48 §4.5.
#[test]
fn throttle_counts_encrypted_challenge_failures() {
    let mut c = config();
    c.preauth_throttle = ThrottlePolicy {
        max_failures: 3,
        window_secs: 60,
        capacity: 8,
    };
    let (mut f, tgt) = setup_with(c);
    let wrong = password_key(EncType::Aes256CtsHmacSha196, "guess", ALICE_SALT);

    // A success clears: two failures, a success, two failures — admitted.
    for i in 0..2 {
        let (armor, armor_key) = open_armor(&mut f, &tgt, 60 + i);
        assert!(preauth(&mut f, &armor, &challenge(&armor_key, &wrong, now())).is_err());
    }
    let (armor, armor_key) = open_armor(&mut f, &tgt, 62);
    assert!(preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())).is_ok());

    // Two challenge failures and one timestamp failure: throttled.
    for i in 0..2 {
        let (armor, armor_key) = open_armor(&mut f, &tgt, 63 + i);
        assert_eq!(
            preauth(&mut f, &armor, &challenge(&armor_key, &wrong, now())),
            Err(AuthnError::Denied)
        );
        assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);
    }
    assert!(f
        .keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&wrong, Some(1), now()),
            None,
            &now()
        )
        .is_err());
    let (armor, armor_key) = open_armor(&mut f, &tgt, 65);
    assert_eq!(
        preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())),
        Err(AuthnError::Denied)
    );
    let rec = f.records().last().unwrap();
    assert_eq!(rec.reason, AuditReason::Throttled);
    assert_eq!(rec.result, AuditOutcome::RateLimited);
    assert_eq!(rec.kvno, None, "decided before any secret work");
    assert_eq!(
        f.keyd.verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), now()),
            None,
            &now()
        ),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::Throttled);
}

/// The factor must match the armor: PA-ENC-TIMESTAMP is not accepted with
/// an armor (it is no factor inside FAST in phase 1 — and the attempt is used
/// up), and PA-ENCRYPTED-CHALLENGE is not accepted without one ("A FAST
/// factor MUST NOT be used outside of FAST"). Source: RFC 6113 5.4, 5.4.6;
/// docs/48 §2.3 (EncTimestamp only with armor = None, EncryptedChallenge only
/// with armor = Some), §4.5, §9.2 item 5.
#[test]
fn factor_must_match_the_armor() {
    let (mut f, tgt) = setup();
    let (armor, armor_key) = open_armor(&mut f, &tgt, 70);
    assert_eq!(
        preauth(
            &mut f,
            &armor,
            &pa_enc_timestamp(&alice_key(), Some(1), now())
        ),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::UnsupportedPadataType);
    assert_eq!(
        preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::ArmorAlreadyAttempted);

    let (_, armor_key) = open_armor(&mut f, &tgt, 71);
    assert_eq!(
        f.keyd.verify_preauth(
            &KDC,
            &ALICE,
            &challenge(&armor_key, &alice_key(), now()),
            None,
            &now()
        ),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::UnsupportedPadataType);
}

/// The long-term key of the challenge is the one keyd selects: the first
/// enctype of the inner etype list that is configured and that the client
/// has. With [aes128, aes256] requested, only the aes128 key opens it; the
/// challenge key keeps the armor key's enctype (aes256, k1), while the
/// strengthen key, the reply key and the enc-part take the client key's
/// (aes128). An unconfigured etype is skipped; nothing usable → `Denied`.
/// Source: docs/questions/Q-123 (A-32); RFC 4120 3.1.3 ("the first valid
/// strong etype for which an encryption key is available"); RFC 6113 5.1
/// ("the enctype of k1"), 5.4.3 (strengthen-key "the same etype as that of
/// the reply key before being strengthened").
#[test]
fn long_term_key_follows_the_inner_etype_list() {
    let mut c = config();
    c.enctypes = vec![
        keyd::EncTypeId::Aes256CtsHmacSha196,
        keyd::EncTypeId::Aes128CtsHmacSha196,
    ];
    let (mut f, tgt) = setup_with(c);
    let alice_128 = password_key(EncType::Aes128CtsHmacSha196, ALICE_PASSWORD, ALICE_SALT);
    let with_etypes = |etypes: Vec<i32>| {
        let mut inner = inner_request(INNER_NONCE);
        inner.req_body.etype = etypes;
        inner
    };

    let (armor, armor_key) = open_armor_for(&mut f, &tgt, 80, &with_etypes(vec![17, 18]));
    assert_eq!(
        preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);

    let (armor, armor_key) = open_armor_for(&mut f, &tgt, 81, &with_etypes(vec![17, 18]));
    let padata = challenge(&armor_key, &alice_128, now());
    assert_eq!(
        EncryptedData::decode(&padata.padata_value).unwrap().etype,
        18
    );
    let proof = preauth(&mut f, &armor, &padata).unwrap();
    let parts = issue(&mut f, &proof, &armor, &armored_template()).unwrap();
    assert_eq!(parts.enc_part.etype, 17);
    assert_eq!(parts.fast_rep.as_ref().unwrap().etype, 18);
    let response = fast_response(&armor_key, &parts);
    let strengthen = key_from(response.strengthen_key.as_ref().unwrap());
    assert_eq!(strengthen.enc_type(), EncType::Aes128CtsHmacSha196);
    let rep = EncAsRepPart::decode(&open(
        &reply_key(&strengthen, &alice_128),
        3,
        &parts.enc_part,
    ));
    assert_eq!(rep.unwrap().0.nonce, INNER_NONCE);
    let kdc_challenge = EncryptedData::decode(&response.padata[0].padata_value).unwrap();
    assert!(krb_crypto::decrypt(
        &kdc_challenge_key(&armor_key, &alice_128),
        usage(55),
        &kdc_challenge.cipher
    )
    .is_ok());

    // An unconfigured etype (RC4, 23) is skipped; then aes256 is chosen.
    let (armor, armor_key) = open_armor_for(&mut f, &tgt, 82, &with_etypes(vec![23, 18]));
    assert!(preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())).is_ok());

    // Nothing usable.
    let (armor, armor_key) = open_armor_for(&mut f, &tgt, 83, &with_etypes(vec![23]));
    assert_eq!(
        preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::KeyNotFound);
}

/// An EncryptedChallenge carries no kvno: the challenge key is derived per
/// conversation, and a kvno "is only present in messages encrypted under
/// long lasting keys". A present kvno — even the client's current one — is
/// refused (interim strict reading). Source: RFC 4120 5.2.9 (kvno); RFC 6113
/// 5.4.6; docs/questions/Q-145.
#[test]
fn challenge_carries_no_kvno() {
    let (mut f, tgt) = setup();
    let with_kvno = |armor_key: &ProtocolKey, kvno: u32| {
        let mut p = challenge(armor_key, &alice_key(), now());
        let mut enc = EncryptedData::decode(&p.padata_value).unwrap();
        enc.kvno = Some(kvno);
        p.padata_value = enc.encode().unwrap();
        p
    };
    for (cusec, kvno) in [(90, 9), (91, 1)] {
        let (armor, armor_key) = open_armor(&mut f, &tgt, cusec);
        assert_eq!(
            preauth(&mut f, &armor, &with_kvno(&armor_key, kvno)),
            Err(AuthnError::Denied),
            "kvno {kvno}"
        );
        assert_eq!(last_reason(&f), AuditReason::KvnoMismatch);
    }
}

/// No FAST key leaves keyd: no output, no Debug rendering and no audit
/// record holds the armor key, the challenge keys, the strengthen key, the
/// reply key, the session key, the subkey, the armor ticket's session key or
/// any long-term key. Source: docs/48 §2.2 ("no FAST key — armor, challenge,
/// strengthen, reply — leaves keyd"), §9.1 I1, I8, §9.2 item 1; docs/10 §12
/// I1, I8; docs/CLEAN-ROOM.md
#[test]
fn no_fast_key_in_any_output_or_audit_record() {
    let (mut f, tgt) = setup();
    let (armor, armor_key) = open_armor(&mut f, &tgt, 95);
    let proof = preauth(&mut f, &armor, &challenge(&armor_key, &alice_key(), now())).unwrap();
    let parts = issue(&mut f, &proof, &armor, &armored_template()).unwrap();
    let response = fast_response(&armor_key, &parts);
    let strengthen = key_from(response.strengthen_key.as_ref().unwrap());
    let reply = reply_key(&strengthen, &alice_key());
    let rep = EncAsRepPart::decode(&open(&reply, 3, &parts.enc_part)).unwrap();

    let secrets: Vec<Vec<u8>> = vec![
        armor_key.octets().to_vec(),
        client_challenge_key(&armor_key, &alice_key())
            .octets()
            .to_vec(),
        kdc_challenge_key(&armor_key, &alice_key())
            .octets()
            .to_vec(),
        strengthen.octets().to_vec(),
        reply.octets().to_vec(),
        rep.0.key.keyvalue.as_bytes().to_vec(),
        SUBKEY.to_vec(),
        tgt.rep.0.key.keyvalue.as_bytes().to_vec(),
        alice_key().octets().to_vec(),
        KRBTGT_KEY.to_vec(),
        WS01_KEY.to_vec(),
    ];
    let fast_rep = parts.fast_rep.as_ref().unwrap();
    let outputs: Vec<Vec<u8>> = vec![
        format!("{parts:?}").into_bytes(),
        format!("{proof:?}").into_bytes(),
        format!("{armor:?}").into_bytes(),
        parts.ticket.encode().unwrap(),
        parts.enc_part.encode().unwrap(),
        fast_rep.encode().unwrap(),
        format!("{:?}", f.keyd).into_bytes(),
        format!("{:?}", f.records()).into_bytes(),
    ];
    for out in &outputs {
        for secret in &secrets {
            assert!(!contains_bytes(out, secret));
        }
    }
    let text = format!("{parts:?}{proof:?}{armor:?}{:?}{:?}", f.keyd, f.records());
    for key in [&strengthen, &reply, &armor_key] {
        let k = key.octets();
        for r in [
            format!("{}, {}, {}, {}", k[0], k[1], k[2], k[3]),
            format!("{:02x}{:02x}{:02x}{:02x}", k[0], k[1], k[2], k[3]),
        ] {
            assert!(!text.contains(r.as_str()), "{r}");
        }
    }
    assert_eq!(f.records().len(), 3, "one record per call (I8)");
}

/// The unarmored AS path is unchanged by T2: no `fast_rep`, the enc-part
/// under the plain client key. Source: docs/48 §2.3 ("bootstrap:
/// verify_preauth(EncTimestamp, None) → issue_as_rep(proof, None)
/// (unchanged)"), §7.3.
#[test]
fn unarmored_reply_has_no_fast_rep() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    assert_eq!(tgt.parts.fast_rep, None);
    assert_eq!(tgt.rep.0.nonce, as_template().nonce);
}
