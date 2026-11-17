//! The armored TGS exchange through keyd (docs/48 task T3): the implicit
//! FAST armor of `open_and_verify_tgt`, `issue_tgs_rep` on the armored
//! context (strengthened reply key, KrbFastFinished, the sealed
//! KrbFastResponse) and `seal_fast_error(Tgs)`.
//!
//! The test acts as the KDC (calling keyd) and as the client: it builds a
//! TGS-REQ whose PA-TGS-REQ authenticator carries a subkey ("a subkey MUST be
//! included in the PA-TGS-REQ authenticator", RFC 6113 §5.4.2), derives the
//! implicit armor key itself — KRB-FX-CF2(subkey, TGT session key,
//! "subkeyarmor", "ticketarmor"), "the same armor key that would be computed
//! if the TGS-REQ authenticator was used in an FX_FAST_ARMOR_AP_REQUEST
//! armor" (§5.4.2, §5.4.1.1) — computes the req-checksum "over the type AP-REQ
//! in the PA-TGS-REQ padata" (§5.4.2, usage 50) and seals the KrbFastReq
//! (usage 51); then it opens the reply: KrbFastResponse under the armor key
//! (usage 52), the reply key KRB-FX-CF2(strengthen-key, subkey,
//! "strengthenkey", "replykey") (§5.4.3), EncTGSRepPart under it (usage 9,
//! docs/questions/Q-121), and the ticket-checksum of KrbFastFinished over the
//! ticket DER (usage 53, docs/questions/Q-122). The PA-TGS-REQ authenticator
//! checksum covers the OUTER body (docs/questions/Q-124). Key usages: RFC
//! 6113 §6.2 and RFC 4120 §7.5.1.
//!
//! RFC 6113 has no test vector for these derivations (docs/48 §9.2 item
//! 15): these are round-trip and property tests. Keys, names and nonces are
//! made up for these tests; nothing comes from any other implementation.

mod common;

use common::*;
use keyd::{
    ArmorId, AuditOutcome, AuditReason, AuthnError, CtxId, Error, FastConversation, IssueError,
    Operation, TgsFastRequest, TgsRepParts, TgtContext,
};
use krb_crypto::{ChecksumType, EncType, ProtocolKey};
use krb_proto::constants::{
    FX_FAST_ARMOR_AP_REQUEST, KDC_ERR_NONE, KDC_ERR_POLICY, KDC_ERR_SERVICE_REVOKED,
    PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, PA_FX_COOKIE, PA_FX_ERROR, PA_FX_FAST,
};
use krb_proto::{
    ApReq, Checksum, EncTgsRepPart, EncTicketPart, EncryptedData, EtypeInfo2, EtypeInfo2Entry,
    FastOptions, KerberosTime, KrbError, KrbFastArmor, KrbFastArmoredReq, KrbFastReq,
    KrbFastResponse, Microseconds, PaData, Realm,
};

/// The client's PA-TGS-REQ subkey (RFC 6113 5.4.2), made up for the tests.
const SUBKEY: [u8; 32] = [0xB9; 32];
/// Outer and inner request nonces differ, so a test can tell which one keyd
/// used (RFC 6113 5.4.2: the inner req-body "is preferred").
const OUTER_NONCE: u32 = 0x0303_0303;
const INNER_NONCE: u32 = 0x4444_5555;

/// One armored TGS request as the client built it, plus the armor key the
/// client derived (the KDC never has it).
struct ArmoredTgs {
    ap_req: ApReq,
    ap_req_octets: Vec<u8>,
    outer_body: Vec<u8>,
    armored_req: KrbFastArmoredReq,
    armor_key: ProtocolKey,
}

impl ArmoredTgs {
    fn fast(&self) -> TgsFastRequest<'_> {
        TgsFastRequest {
            ap_req_octets: &self.ap_req_octets,
            armored_req: &self.armored_req,
        }
    }
}

/// The KrbFastReq of an armored TGS request for the test service (RFC 6113
/// 5.4.2): no fast-options, no padata ("PA-TGS-REQ padata is not included in
/// this field"), the inner req-body.
fn inner_request(nonce: u32) -> KrbFastReq {
    KrbFastReq {
        fast_options: FastOptions::empty(),
        padata: Vec::new(),
        req_body: tgs_req_body(nonce, service_name()).0,
    }
}

/// req-checksum over `checksummed` (armor key, its required checksum type,
/// usage 50) and enc-fast-req (armor key, usage 51); no armor field — the
/// TGS uses implicit armor. RFC 6113 5.4.2.
fn tgs_armored_req(
    armor_key: &ProtocolKey,
    checksummed: &[u8],
    inner: &KrbFastReq,
) -> KrbFastArmoredReq {
    let req_checksum = Checksum {
        cksumtype: ChecksumType::HmacSha196Aes256.number(),
        checksum: krb_crypto::get_mic(
            armor_key,
            ChecksumType::HmacSha196Aes256,
            usage(50),
            checksummed,
        )
        .unwrap(),
    };
    let cipher =
        krb_crypto::encrypt(armor_key, usage(51), &[0x88; 16], &inner.encode().unwrap()).unwrap();
    KrbFastArmoredReq {
        armor: None,
        req_checksum,
        enc_fast_req: EncryptedData {
            etype: armor_key.enc_type().number(),
            kvno: None,
            cipher,
        },
    }
}

/// An armored TGS request on `tgt`: the PA-TGS-REQ authenticator at `ctime`
/// (made unique by `cusec`) with `subkey` and a checksum over the OUTER body
/// (usage 6, Q-124), the AP-REQ octets, and the KrbFastArmoredReq for
/// `inner`. Without a subkey the client has no armor key; a stand-in key
/// derived from [`SUBKEY`] seals the FAST part (keyd must refuse first).
fn build(
    tgt: &Tgt,
    ctime: KerberosTime,
    cusec: u32,
    subkey: Option<&[u8; 32]>,
    inner: &KrbFastReq,
) -> ArmoredTgs {
    let (_, outer_body) = tgs_req_body(OUTER_NONCE, service_name());
    let mut spec = AuthenticatorSpec::new(ctime, cusec, &outer_body);
    spec.subkey = subkey;
    let ap_req = ap_req(&tgt.parts.ticket, authenticator(&tgt.session, &spec));
    let ap_req_octets = ap_req.encode().unwrap();
    let armor_key = client_armor_key(subkey.unwrap_or(&SUBKEY), &tgt.session);
    let armored_req = tgs_armored_req(&armor_key, &ap_req_octets, inner);
    ArmoredTgs {
        ap_req,
        ap_req_octets,
        outer_body,
        armored_req,
        armor_key,
    }
}

/// A valid armored request at `now`.
fn armored(tgt: &Tgt, cusec: u32) -> ArmoredTgs {
    build(
        tgt,
        now(),
        cusec,
        Some(&SUBKEY),
        &inner_request(INNER_NONCE),
    )
}

fn open_armored(
    f: &mut Fixture,
    a: &ArmoredTgs,
    when: KerberosTime,
) -> Result<TgtContext, AuthnError> {
    f.keyd.open_and_verify_tgt(
        &KDC,
        &KRBTGT,
        &a.ap_req,
        &a.outer_body,
        Some(a.fast()),
        &when,
    )
}

fn setup() -> (Fixture, Tgt) {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    f.keyd.audit_sink_mut().records.clear();
    (f, tgt)
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

fn cookie() -> PaData {
    pa(PA_FX_COOKIE, b"cookie-v1".to_vec())
}

fn etype_info2() -> PaData {
    pa(
        PA_ETYPE_INFO2,
        EtypeInfo2(vec![EtypeInfo2Entry {
            etype: 18,
            salt: None,
            s2kparams: None,
        }])
        .encode()
        .unwrap(),
    )
}

/// A KRB-ERROR as the KDC builds it for alice's armored TGS request
/// (crates/kdc krb_error.rs rule: no e-text, stime = now; realm / sname of
/// the request — here the inner one — and crealm / cname of the TGT's
/// client once keyd verified it).
fn tgs_fast_error(code: i32) -> KrbError {
    KrbError {
        ctime: None,
        cusec: None,
        stime: now(),
        susec: Microseconds::default(),
        error_code: code,
        crealm: Some(realm()),
        cname: Some(alice_name()),
        realm: realm(),
        sname: service_name(),
        e_text: None,
        e_data: None,
    }
}

fn seal_tgs_error(
    f: &mut Fixture,
    caller: &keyd::CallerId,
    ctx: &CtxId,
    error: &KrbError,
    padata: &[PaData],
) -> Result<EncryptedData, Error> {
    f.keyd
        .seal_fast_error(caller, &FastConversation::Tgs(*ctx), error, padata, &now())
}

/// The strengthened reply key: KRB-FX-CF2(strengthen-key, padata-reply-key,
/// "strengthenkey", "replykey") — RFC 6113 5.4.3.
fn reply_key(strengthen: &ProtocolKey, padata_reply_key: &ProtocolKey) -> ProtocolKey {
    krb_crypto::krb_fx_cf2(strengthen, padata_reply_key, b"strengthenkey", b"replykey").unwrap()
}

fn subkey() -> ProtocolKey {
    krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &SUBKEY).unwrap()
}

/// The decrypted KrbFastResponse of an armored reply (armor key, usage 52).
fn fast_response(armor_key: &ProtocolKey, parts: &TgsRepParts) -> KrbFastResponse {
    let fast_rep = parts.fast_rep.as_ref().expect("armored reply has fast_rep");
    KrbFastResponse::decode(&open(armor_key, 52, fast_rep)).unwrap()
}

fn issue(f: &mut Fixture, ctx: &TgtContext, nonce: u32) -> Result<TgsRepParts, IssueError> {
    f.keyd
        .issue_tgs(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(nonce), &now())
}

/// Full armored TGS round trip. keyd returns the inner request; the issued
/// reply's KrbFastResponse opens under the client's armor key (usage 52) and
/// carries the stored inner nonce, no padata, a strengthen key (mandatory in
/// a TGS reply) and KrbFastFinished; the client derives the reply key from
/// the strengthen key and the subkey and opens EncTGSRepPart (usage 9); the
/// ticket-checksum verifies over the ticket DER (usage 53). Source: RFC 6113
/// 5.4.2 (implicit armor key, req-checksum over the AP-REQ, inner req-body
/// preferred), 5.4.3 (strengthen-key "MUST be set in a TGS reply", reply-key,
/// KrbFastFinished, nonce, KEY_USAGE_FAST_REP / FINISHED), 6.2; RFC 4120
/// 5.4.2 (usage 9, no kvno), 3.3.3; docs/48 §5.2, §9.2 items 3, 6, 7;
/// docs/questions/Q-121, Q-122, Q-124.
#[test]
fn armored_tgs_round_trip() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 1);
    let ctx = open_armored(&mut f, &a, now()).unwrap();
    assert_eq!(ctx.cname, alice_name());
    assert_eq!(ctx.crealm, realm());
    let fast_req = ctx.fast_req.as_ref().expect("armored context");
    assert_eq!(*fast_req, inner_request(INNER_NONCE));
    assert_eq!(fast_req.req_body.nonce, INNER_NONCE);

    let parts = issue(&mut f, &ctx, INNER_NONCE).unwrap();

    // The KrbFastResponse, under the armor key.
    let fast_rep = parts.fast_rep.as_ref().unwrap();
    assert_eq!(fast_rep.etype, 18);
    assert_eq!(fast_rep.kvno, None);
    let response = fast_response(&a.armor_key, &parts);
    assert_eq!(response.nonce, INNER_NONCE, "the stored inner nonce");
    assert!(response.padata.is_empty());

    // The strengthen key (of the subkey's enctype) and the reply key.
    let strengthen = key_from(
        response
            .strengthen_key
            .as_ref()
            .expect("MUST be set in TGS"),
    );
    assert_eq!(strengthen.enc_type(), EncType::Aes256CtsHmacSha196);
    let reply = reply_key(&strengthen, &subkey());
    assert_eq!(parts.enc_part.etype, 18);
    assert_eq!(parts.enc_part.kvno, None, "RFC 4120 5.4.2: no kvno");
    let rep = EncTgsRepPart::decode(&open(&reply, 9, &parts.enc_part))
        .unwrap()
        .0;
    assert_eq!(rep.nonce, INNER_NONCE);
    assert_eq!(rep.sname, service_name());
    assert_eq!(rep.srealm, realm());

    // The service ticket: under the service key, for alice, with the
    // session key of the reply.
    let ticket_part =
        EncTicketPart::decode(&open(&service_key(), 2, &parts.ticket.enc_part)).unwrap();
    assert_eq!(ticket_part.cname, alice_name());
    assert_eq!(ticket_part.key, rep.key);

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
    krb_crypto::verify_mic(
        &a.armor_key,
        ChecksumType::HmacSha196Aes256,
        usage(53),
        &parts.ticket.encode().unwrap(),
        &finished.ticket_checksum.checksum,
    )
    .expect("ticket-checksum over the ticket DER (Q-122)");

    // One record per call; the context is consumed (exactly once).
    let ops: Vec<_> = f.records().iter().map(|r| (r.op, r.result)).collect();
    assert_eq!(
        ops,
        [
            (Operation::OpenAndVerifyTgt, AuditOutcome::Success),
            (Operation::IssueTgsRep, AuditOutcome::Success),
        ]
    );
    assert_eq!(
        seal_tgs_error(
            &mut f,
            &KDC,
            &ctx.ctx_id,
            &tgs_fast_error(KDC_ERR_POLICY),
            &[]
        ),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);
}

/// The strengthened enc-part does not open under the plain subkey or the
/// TGT session key (usages 8 / 9), nor under the strengthen key alone; the
/// KrbFastResponse does not open without the armor key — not under the
/// session key, the subkey, the strengthen key, the service key or krbtgt,
/// nor under the armor key with another usage. Each reply draws a fresh
/// strengthen key. Source: RFC 6113 5.4.3 (strengthen-key "MUST be randomly
/// generated"; "so that an attacker cannot remove the FAST PADATA from a TGS
/// reply"; KEY_USAGE_FAST_REP); RFC 4120 5.4.2; docs/48 §9.2 item 3.
#[test]
fn armored_reply_needs_the_armor_and_the_strengthen_key() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 2);
    let ctx = open_armored(&mut f, &a, now()).unwrap();
    let parts = issue(&mut f, &ctx, INNER_NONCE).unwrap();
    let response = fast_response(&a.armor_key, &parts);
    let strengthen = key_from(response.strengthen_key.as_ref().unwrap());

    let enc = &parts.enc_part.cipher;
    for (name, key, usage_number) in [
        ("subkey, usage 9", &subkey(), 9),
        ("subkey, usage 8", &subkey(), 8),
        ("session key, usage 8", &tgt.session, 8),
        ("session key, usage 9", &tgt.session, 9),
        ("strengthen key alone", &strengthen, 9),
    ] {
        assert!(
            krb_crypto::decrypt(key, usage(usage_number), enc).is_err(),
            "{name}"
        );
    }
    assert!(krb_crypto::decrypt(&reply_key(&strengthen, &subkey()), usage(9), enc).is_ok());

    let fast = &parts.fast_rep.as_ref().unwrap().cipher;
    for (name, key) in [
        ("TGT session key", &tgt.session),
        ("subkey", &subkey()),
        ("strengthen key", &strengthen),
        ("service key", &service_key()),
        ("krbtgt", &krbtgt_key()),
    ] {
        assert!(krb_crypto::decrypt(key, usage(52), fast).is_err(), "{name}");
    }
    assert!(krb_crypto::decrypt(&a.armor_key, usage(51), fast).is_err());

    // A second conversation: a different strengthen key.
    let a = armored(&tgt, 3);
    let ctx = open_armored(&mut f, &a, now()).unwrap();
    let parts = issue(&mut f, &ctx, INNER_NONCE).unwrap();
    assert_ne!(
        fast_response(&a.armor_key, &parts).strengthen_key,
        response.strengthen_key
    );
}

/// Under FAST the PA-TGS-REQ authenticator must carry a subkey. Source: RFC
/// 6113 5.4.2 ("a subkey MUST be included in the PA-TGS-REQ authenticator");
/// docs/48 §5.2 step 3.
#[test]
fn fast_without_subkey_denied() {
    let (mut f, tgt) = setup();
    let a = build(&tgt, now(), 4, None, &inner_request(INNER_NONCE));
    assert_eq!(open_armored(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::ArmorSubkeyMissing);
    // The same authenticator without FAST is an ordinary TGS request.
    assert!(f
        .keyd
        .open_and_verify_tgt(&KDC, &KRBTGT, &a.ap_req, &a.outer_body, None, &now())
        .is_ok());
}

/// An explicit armor field in a TGS request is refused, before any key is
/// used — so even an expired TGT yields the uniform `Denied`. Source: RFC
/// 6113 5.4.1.1 ("This armor type is only valid for AS requests; implicit
/// armor ... is the only supported way to establish an armor key for the
/// TGS"), 5.4.2; docs/questions/Q-124 item 2 (A-32); A-26.
#[test]
fn explicit_armor_field_denied() {
    let (mut f, tgt) = setup();
    let mut a = armored(&tgt, 5);
    a.armored_req.armor = Some(KrbFastArmor {
        armor_type: FX_FAST_ARMOR_AP_REQUEST,
        armor_value: a.ap_req_octets.clone(),
    });
    assert_eq!(open_armored(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::TgsExplicitArmor);

    // An expired TGT with an explicit armor: still the uniform Denied.
    let mut t = as_template();
    t.endtime = kt("20261113103000Z");
    let expired = obtain_tgt(&mut f, now(), &t);
    let later = kt("20261113103501Z");
    let mut a = build(
        &expired,
        later,
        6,
        Some(&SUBKEY),
        &inner_request(INNER_NONCE),
    );
    a.armored_req.armor = Some(KrbFastArmor {
        armor_type: 7,
        armor_value: Vec::new(),
    });
    assert_eq!(open_armored(&mut f, &a, later), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::TgsExplicitArmor);
}

/// The req-checksum must be over the PA-TGS-REQ AP-REQ, keyed with the
/// armor key, of its required checksum type, with usage 50: over the outer
/// body instead (the AS rule), over another AP-REQ, with usage 51, under the
/// subkey or the session key instead of the armor key, or of another
/// checksum type, it is refused. Source: RFC 6113 5.4.2 ("for a TGS-REQ, it
/// is performed over the type AP-REQ in the PA-TGS-REQ padata"; checksum key
/// = armor key, required checksum type, KEY_USAGE_FAST_REQ_CHKSUM); RFC 3961
/// §3; docs/48 §9.2 item 9.
#[test]
fn req_checksum_must_cover_the_ap_req() {
    let (mut f, tgt) = setup();
    let other_ap_req = armored(&tgt, 99).ap_req_octets;
    let mic = |key: &ProtocolKey, usage_number: u32, data: &[u8]| Checksum {
        cksumtype: ChecksumType::HmacSha196Aes256.number(),
        checksum: krb_crypto::get_mic(
            key,
            ChecksumType::HmacSha196Aes256,
            usage(usage_number),
            data,
        )
        .unwrap(),
    };
    type Case<'a> = (&'a str, Box<dyn Fn(&ArmoredTgs) -> Checksum + 'a>);
    let cases: Vec<Case> = vec![
        (
            "over the outer body",
            Box::new(|a: &ArmoredTgs| mic(&a.armor_key, 50, &a.outer_body)),
        ),
        (
            "over another AP-REQ",
            Box::new(|a: &ArmoredTgs| mic(&a.armor_key, 50, &other_ap_req)),
        ),
        (
            "usage 51",
            Box::new(|a: &ArmoredTgs| mic(&a.armor_key, 51, &a.ap_req_octets)),
        ),
        (
            "subkey",
            Box::new(|a: &ArmoredTgs| mic(&subkey(), 50, &a.ap_req_octets)),
        ),
        (
            "session key",
            Box::new(|a: &ArmoredTgs| mic(&tgt.session, 50, &a.ap_req_octets)),
        ),
    ];
    for (i, (name, checksum)) in cases.iter().enumerate() {
        let mut a = armored(&tgt, 10 + i as u32);
        a.armored_req.req_checksum = checksum(&a);
        assert_eq!(
            open_armored(&mut f, &a, now()),
            Err(AuthnError::Denied),
            "{name}"
        );
        assert_eq!(last_reason(&f), AuditReason::FastChecksumMismatch, "{name}");
    }

    let mut a = armored(&tgt, 20);
    a.armored_req.req_checksum.cksumtype = ChecksumType::HmacSha196Aes128.number();
    assert_eq!(open_armored(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::ChecksumUnsupported);
}

/// The AP-REQ octets the req-checksum covers must be the AP-REQ keyd opens:
/// another AP-REQ's octets — even with a checksum valid over them — or
/// octets that are no AP-REQ are refused. Source: RFC 6113 5.4.2; RFC 4120
/// 5.2.7.1 ("padata-value will contain an encoded AP-REQ"); docs/48 §5.2
/// step 4.
#[test]
fn ap_req_octets_must_be_the_opened_ap_req() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 21);
    let other = armored(&tgt, 22);
    // The FAST part of `other` (checksum valid over its own octets) with the
    // AP-REQ of `a`.
    assert_eq!(
        f.keyd.open_and_verify_tgt(
            &KDC,
            &KRBTGT,
            &a.ap_req,
            &a.outer_body,
            Some(other.fast()),
            &now()
        ),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::FastApReqMismatch);

    let garbage = [0x30, 0x00];
    assert_eq!(
        f.keyd.open_and_verify_tgt(
            &KDC,
            &KRBTGT,
            &a.ap_req,
            &a.outer_body,
            Some(TgsFastRequest {
                ap_req_octets: &garbage,
                armored_req: &a.armored_req,
            }),
            &now()
        ),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::MalformedInput);
    // Neither attempt entered the replay cache: `a` itself is accepted.
    assert!(open_armored(&mut f, &a, now()).is_ok());
}

/// enc-fast-req must decrypt under the armor key with usage 51 and decode as
/// KrbFastReq whose inner body is for this realm without
/// enc-authorization-data: tampered, sealed with usage 52, of another
/// enctype, a well-sealed non-KrbFastReq, an inner body of another realm or
/// with enc-authorization-data are refused. Source: RFC 6113 5.4.2
/// (KEY_USAGE_FAST_ENC), 5.1 (the armor key has the subkey's enctype); RFC
/// 4120 5.4.1; docs/48 §5.2 step 5.
#[test]
fn tampered_enc_fast_req_denied() {
    let (mut f, tgt) = setup();

    let mut a = armored(&tgt, 30);
    let last = a.armored_req.enc_fast_req.cipher.len() - 1;
    a.armored_req.enc_fast_req.cipher[last] ^= 0x01;
    assert_eq!(open_armored(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);

    let mut a = armored(&tgt, 31);
    a.armored_req.enc_fast_req.cipher = krb_crypto::encrypt(
        &a.armor_key,
        usage(52),
        &[0x99; 16],
        &inner_request(INNER_NONCE).encode().unwrap(),
    )
    .unwrap();
    assert_eq!(open_armored(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);

    let mut a = armored(&tgt, 32);
    a.armored_req.enc_fast_req.etype = 17;
    assert_eq!(open_armored(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::UnsupportedEncType);

    let mut a = armored(&tgt, 33);
    a.armored_req.enc_fast_req.cipher = krb_crypto::encrypt(
        &a.armor_key,
        usage(51),
        &[0x99; 16],
        &tgs_req_body(INNER_NONCE, service_name()).1,
    )
    .unwrap();
    assert_eq!(open_armored(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::MalformedInput);

    let mut other_realm = inner_request(INNER_NONCE);
    other_realm.req_body.realm = Realm::new("OTHER.ORG").unwrap();
    let a = build(&tgt, now(), 34, Some(&SUBKEY), &other_realm);
    assert_eq!(open_armored(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::WrongRealm);

    let mut with_authz = inner_request(INNER_NONCE);
    with_authz.req_body.enc_authorization_data = Some(EncryptedData {
        etype: 18,
        kvno: None,
        cipher: vec![0; 48],
    });
    let a = build(&tgt, now(), 35, Some(&SUBKEY), &with_authz);
    assert_eq!(open_armored(&mut f, &a, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::UnsupportedContent);
}

/// Under FAST the PA-TGS-REQ authenticator checksum still covers the OUTER
/// KDC-REQ-BODY (A-17 unchanged): a checksum over the inner body is
/// refused. Source: RFC 4120 5.2.7.1 ("computed over the KDC-REQ-BODY
/// encoding"), 3.3.2; docs/questions/Q-124 item 1 (A-32).
#[test]
fn authenticator_checksum_covers_the_outer_body() {
    let (mut f, tgt) = setup();
    let inner = inner_request(INNER_NONCE);
    let inner_body = inner.req_body.encode().unwrap();
    let (_, outer_body) = tgs_req_body(OUTER_NONCE, service_name());
    let mut spec = AuthenticatorSpec::new(now(), 40, &inner_body);
    spec.subkey = Some(&SUBKEY);
    let ap = ap_req(&tgt.parts.ticket, authenticator(&tgt.session, &spec));
    let octets = ap.encode().unwrap();
    let armor_key = client_armor_key(&SUBKEY, &tgt.session);
    let req = tgs_armored_req(&armor_key, &octets, &inner);
    assert_eq!(
        f.keyd.open_and_verify_tgt(
            &KDC,
            &KRBTGT,
            &ap,
            &outer_body,
            Some(TgsFastRequest {
                ap_req_octets: &octets,
                armored_req: &req,
            }),
            &now()
        ),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::ChecksumMismatch);
}

/// With an armored context the template must answer the INNER request: its
/// nonce and sname. A template with the outer nonce or another sname is
/// `Denied` — and the armored context survives the refusal, so the KDC can
/// still issue correctly or seal the armored error. An unarmored context is
/// consumed by a refusal, as before. Source: RFC 6113 5.4.2 ("This req-body
/// field is preferred over the outer field"), 5.4.3 (the nonce "binds the
/// KDC response with the client request"); docs/48 §3.4, §9.2 item 7;
/// docs/questions/Q-145 item 3 (A-42), Q-150.
#[test]
fn template_must_answer_the_inner_request() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 50);
    let ctx = open_armored(&mut f, &a, now()).unwrap();

    assert_eq!(issue(&mut f, &ctx, OUTER_NONCE), Err(IssueError::Denied));
    assert_eq!(last_reason(&f), AuditReason::FastBindingMismatch);
    let mut other_service = tgs_template(INNER_NONCE);
    other_service.sname = bob_name();
    assert_eq!(
        f.keyd
            .issue_tgs(&KDC, &SERVICE, &ctx.ctx_id, &other_service, &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::FastBindingMismatch);
    // A refusal past the binding (BadTemplate) leaves it live too.
    let mut too_long = tgs_template(INNER_NONCE);
    too_long.endtime = kt("20261113180001Z");
    assert_eq!(
        f.keyd
            .issue_tgs(&KDC, &SERVICE, &ctx.ctx_id, &too_long, &now()),
        Err(IssueError::BadTemplate)
    );

    // Still live: the correct template issues, armored, once.
    let parts = issue(&mut f, &ctx, INNER_NONCE).unwrap();
    assert_eq!(
        fast_response(&a.armor_key, &parts).nonce,
        INNER_NONCE,
        "never the template's"
    );
    assert_eq!(issue(&mut f, &ctx, INNER_NONCE), Err(IssueError::Denied));
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);

    // After a refusal, the armored error can be sealed instead.
    let a = armored(&tgt, 51);
    let ctx = open_armored(&mut f, &a, now()).unwrap();
    assert_eq!(issue(&mut f, &ctx, OUTER_NONCE), Err(IssueError::Denied));
    assert!(seal_tgs_error(
        &mut f,
        &KDC,
        &ctx.ctx_id,
        &tgs_fast_error(KDC_ERR_POLICY),
        &[]
    )
    .is_ok());

    // Unarmored (unchanged): a refused issuance consumes the context.
    let ctx = open_tgt(&mut f, &tgt, 52, 52);
    assert_eq!(issue(&mut f, &ctx, 53), Err(IssueError::BadTemplate));
    assert_eq!(issue(&mut f, &ctx, 52), Err(IssueError::Denied));
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);
}

/// A-26 under FAST: classes are reported only after the whole chain,
/// including the req-checksum and the KrbFastReq. An expired TGT with a bad
/// FAST checksum, a tampered enc-fast-req or no subkey is the uniform
/// `Denied`; with a valid FAST part it is `TicketExpired`. A skewed
/// authenticator with a bad FAST checksum is `Denied`, with a valid one
/// `Skew`. Refused requests do not enter the replay cache; a replayed
/// armored request is `Replay`. Source: A-26 (docs/questions/Q-071); docs/48
/// §6.3, §9.2 item 11; RFC 4120 3.2.3.
#[test]
fn armored_classes_only_after_the_chain() {
    let (mut f, _) = setup();
    let mut t = as_template();
    t.endtime = kt("20261113103000Z");
    let expired = obtain_tgt(&mut f, now(), &t);
    let later = kt("20261113103501Z"); // endtime + 301 s: expired
    let inner = inner_request(INNER_NONCE);

    let mut a = build(&expired, later, 60, Some(&SUBKEY), &inner);
    a.armored_req.req_checksum.checksum[0] ^= 0x01;
    assert_eq!(open_armored(&mut f, &a, later), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::FastChecksumMismatch);

    let mut a = build(&expired, later, 61, Some(&SUBKEY), &inner);
    a.armored_req.enc_fast_req.cipher[0] ^= 0x01;
    assert_eq!(open_armored(&mut f, &a, later), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);

    let a = build(&expired, later, 62, None, &inner);
    assert_eq!(open_armored(&mut f, &a, later), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::ArmorSubkeyMissing);

    let a = build(&expired, later, 63, Some(&SUBKEY), &inner);
    assert_eq!(
        open_armored(&mut f, &a, later),
        Err(AuthnError::TicketExpired)
    );

    // Skewed authenticator (valid TGT).
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let mut a = build(&tgt, at(-400), 64, Some(&SUBKEY), &inner);
    a.armored_req.req_checksum.checksum[0] ^= 0x01;
    assert_eq!(open_armored(&mut f, &a, now()), Err(AuthnError::Denied));
    let a = build(&tgt, at(-400), 65, Some(&SUBKEY), &inner);
    assert_eq!(open_armored(&mut f, &a, now()), Err(AuthnError::Skew));

    // The same AP-REQ, refused for a bad FAST checksum, is accepted with a
    // valid one (no replay-cache entry); presented again, it is a replay.
    let good = build(&tgt, now(), 66, Some(&SUBKEY), &inner);
    let mut bad = build(&tgt, now(), 66, Some(&SUBKEY), &inner);
    bad.armored_req.req_checksum.checksum[0] ^= 0x01;
    assert_eq!(open_armored(&mut f, &bad, now()), Err(AuthnError::Denied));
    assert!(open_armored(&mut f, &good, now()).is_ok());
    assert_eq!(open_armored(&mut f, &good, at(1)), Err(AuthnError::Replay));
}

/// An armored context is caller-bound and short-lived like any context:
/// presented by another caller — to issue_tgs_rep or to seal_fast_error —
/// it is refused and destroyed; expired, it is refused. Source: docs/10 §8
/// ("one-time, caller-bound"), D36; docs/48 §9.1 I4, §9.2 item 2.
#[test]
fn armored_context_is_caller_bound_and_short_lived() {
    let (mut f, tgt) = setup();

    let ctx = open_armored(&mut f, &armored(&tgt, 70), now()).unwrap();
    assert_eq!(
        f.keyd.issue_tgs(
            &KDC_OTHER,
            &SERVICE,
            &ctx.ctx_id,
            &tgs_template(INNER_NONCE),
            &now()
        ),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TokenCallerMismatch);
    assert_eq!(issue(&mut f, &ctx, INNER_NONCE), Err(IssueError::Denied));
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);

    let ctx = open_armored(&mut f, &armored(&tgt, 71), now()).unwrap();
    assert_eq!(
        seal_tgs_error(
            &mut f,
            &KDC_OTHER,
            &ctx.ctx_id,
            &tgs_fast_error(KDC_ERR_POLICY),
            &[]
        ),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TokenCallerMismatch);
    assert_eq!(issue(&mut f, &ctx, INNER_NONCE), Err(IssueError::Denied));
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);

    // Expired (30 s token lifetime).
    let ctx = open_armored(&mut f, &armored(&tgt, 72), now()).unwrap();
    let mut late = tgs_template(INNER_NONCE);
    late.starttime = None;
    assert_eq!(
        f.keyd
            .issue_tgs(&KDC, &SERVICE, &ctx.ctx_id, &late, &at(31)),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TokenExpired);
}

/// The sealed TGS error decrypts under the armor key (usage 52) to a
/// KrbFastResponse with the allowed padata, then PA-FX-ERROR holding the
/// KRB-ERROR (no e-data), the stored INNER nonce, no strengthen-key and no
/// finished. Nothing else opens it. The context is consumed. Source: RFC
/// 6113 5.4.3 (KEY_USAGE_FAST_REP; strengthen-key "must be absent in an
/// error reply"; finished "not present in an error reply"; nonce), 5.4.4
/// (PA-FX-ERROR, e-data absent, padata in the KrbFastResponse); docs/48
/// §2.3, §6.1, §9.2 items 3, 6, 7, 13.
#[test]
fn sealed_tgs_error_round_trip() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 80);
    let ctx = open_armored(&mut f, &a, now()).unwrap();
    let error = tgs_fast_error(KDC_ERR_SERVICE_REVOKED);
    let padata = vec![etype_info2(), cookie()];
    let sealed = seal_tgs_error(&mut f, &KDC, &ctx.ctx_id, &error, &padata).unwrap();
    assert_eq!(sealed.etype, 18);
    assert_eq!(sealed.kvno, None);

    let rep = KrbFastResponse::decode(&open(&a.armor_key, 52, &sealed)).unwrap();
    assert_eq!(rep.nonce, INNER_NONCE, "the stored inner nonce");
    assert!(rep.strengthen_key.is_none());
    assert!(rep.finished.is_none());
    assert_eq!(rep.padata.len(), padata.len() + 1);
    assert_eq!(rep.padata[..padata.len()], padata[..]);
    let fx = rep.padata.last().unwrap();
    assert_eq!(fx.padata_type, PA_FX_ERROR);
    let inner_error = KrbError::decode(&fx.padata_value).unwrap();
    assert_eq!(inner_error, error);

    for (name, key) in [
        ("TGT session key", &tgt.session),
        ("subkey", &subkey()),
        ("service key", &service_key()),
    ] {
        assert!(
            krb_crypto::decrypt(key, usage(52), &sealed.cipher).is_err(),
            "{name}"
        );
    }
    assert!(krb_crypto::decrypt(&a.armor_key, usage(51), &sealed.cipher).is_err());

    let rec = f.records().last().unwrap();
    assert_eq!(rec.op, Operation::SealFastError);
    assert_eq!(rec.result, AuditOutcome::Success);
    assert_eq!(rec.principal, None);

    // Consumed: no issuance afterwards.
    assert_eq!(issue(&mut f, &ctx, INNER_NONCE), Err(IssueError::Denied));
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);

    // Client names may be omitted (RFC 4120 5.9.1).
    let ctx = open_armored(&mut f, &armored(&tgt, 81), now()).unwrap();
    let mut nameless = tgs_fast_error(KDC_ERR_POLICY);
    nameless.crealm = None;
    nameless.cname = None;
    assert!(seal_tgs_error(&mut f, &KDC, &ctx.ctx_id, &nameless, &[]).is_ok());
}

/// The content rules of the AS conversation hold for the TGS one: e-data,
/// e-text, KDC_ERR_NONE, an stime other than now, a client other than the
/// TGT's, a realm other than this one, or an sname other than the inner
/// request's are refused; padata outside the allowlist is refused. The
/// context is consumed either way. Source: RFC 6113 5.4.4 ("The e-data field
/// MUST be absent in the PA-FX-ERROR"; "All other fields should be the same
/// as the outer KRB-ERROR"); RFC 4120 5.9.1, 7.5.9; docs/48 §2.3, §6.1, §9.2
/// item 13.
#[test]
fn forged_tgs_error_content_is_refused() {
    let (mut f, tgt) = setup();
    type Mutation = Box<dyn Fn(&mut KrbError)>;
    let cases: Vec<(&str, Mutation)> = vec![
        ("e-data", Box::new(|e| e.e_data = Some(Vec::new()))),
        ("e-text", Box::new(|e| e.e_text = Some(kstr("detail")))),
        ("KDC_ERR_NONE", Box::new(|e| e.error_code = KDC_ERR_NONE)),
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
        ("the TGS name", Box::new(|e| e.sname = krbtgt_name())),
        ("another service", Box::new(|e| e.sname = bob_name())),
    ];
    for (i, (name, mutate)) in cases.iter().enumerate() {
        let ctx = open_armored(&mut f, &armored(&tgt, 100 + i as u32), now()).unwrap();
        let mut error = tgs_fast_error(KDC_ERR_POLICY);
        mutate(&mut error);
        assert_eq!(
            seal_tgs_error(&mut f, &KDC, &ctx.ctx_id, &error, &[]),
            Err(Error::Denied),
            "{name}"
        );
        assert_eq!(
            last_reason(&f),
            AuditReason::FastErrorContentRefused,
            "{name}"
        );
        assert_eq!(
            issue(&mut f, &ctx, INNER_NONCE),
            Err(IssueError::Denied),
            "{name}: consumed"
        );
    }

    for (i, (name, padata)) in [
        ("PA-ENC-TIMESTAMP", pa(PA_ENC_TIMESTAMP, Vec::new())),
        ("PA-FX-FAST", pa(PA_FX_FAST, Vec::new())),
        (
            "caller PA-FX-ERROR",
            pa(PA_FX_ERROR, tgs_fast_error(25).encode().unwrap()),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let ctx = open_armored(&mut f, &armored(&tgt, 120 + i as u32), now()).unwrap();
        assert_eq!(
            seal_tgs_error(
                &mut f,
                &KDC,
                &ctx.ctx_id,
                &tgs_fast_error(KDC_ERR_POLICY),
                &[padata]
            ),
            Err(Error::Denied),
            "{name}"
        );
        assert_eq!(
            last_reason(&f),
            AuditReason::FastErrorPadataRefused,
            "{name}"
        );
    }
}

/// `seal_fast_error(Tgs)` needs an ARMORED context: a context opened
/// without FAST has no armor key and is refused (and consumed). The token
/// kinds do not mix: an AS armor id presented as a TGS context is unknown
/// (the armor stays live), and so is a TGS context id presented as an AS
/// armor (the context stays live). Source: docs/48 §2.3, §2.4
/// (`ArmorConversationMismatch`), §9.1 I4 ("a token of As is not accepted as
/// Tgs and vice versa").
#[test]
fn conversation_kinds_do_not_mix() {
    let (mut f, tgt) = setup();

    let ctx = open_tgt(&mut f, &tgt, 130, 130);
    assert_eq!(
        seal_tgs_error(
            &mut f,
            &KDC,
            &ctx.ctx_id,
            &tgs_fast_error(KDC_ERR_POLICY),
            &[]
        ),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::ArmorConversationMismatch);
    assert_eq!(issue(&mut f, &ctx, 130), Err(IssueError::Denied));
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);

    // A TGS context id as an AS armor: unknown; the context stays live.
    let a = armored(&tgt, 131);
    let ctx = open_armored(&mut f, &a, now()).unwrap();
    assert_eq!(
        f.keyd.seal_fast_error(
            &KDC,
            &FastConversation::As(ArmorId::from_bytes(*ctx.ctx_id.as_bytes())),
            &fast_krb_error(KDC_ERR_POLICY),
            &[],
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);
    assert!(issue(&mut f, &ctx, INNER_NONCE).is_ok());

    // An AS armor id as a TGS context: unknown; the armor stays live.
    add_computer(&mut f);
    let computer = obtain_computer_tgt(&mut f, now(), kt("20261113180000Z"));
    let armor_subkey = [0xA7; 32];
    let armor_ap = ap_req(
        &computer.parts.ticket,
        armor_authenticator(
            &computer.session,
            &ArmorAuthSpec::new(now(), 132, armor_subkey),
        ),
    );
    let armor_key = client_armor_key(&armor_subkey, &computer.session);
    let (_, outer) = as_req_body(OUTER_NONCE);
    let req = armored_req(&armor_ap, &armor_key, &outer, &fast_req(INNER_NONCE));
    let armor = f
        .keyd
        .open_fast_armor(&KDC, &KRBTGT, &req, &outer, &now())
        .unwrap();
    assert_eq!(
        seal_tgs_error(
            &mut f,
            &KDC,
            &CtxId::from_bytes(*armor.armor_id.as_bytes()),
            &tgs_fast_error(KDC_ERR_POLICY),
            &[]
        ),
        Err(Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TokenUnknown);
    assert!(f
        .keyd
        .seal_fast_error(
            &KDC,
            &FastConversation::As(armor.armor_id),
            &fast_krb_error(KDC_ERR_POLICY),
            &[],
            &now()
        )
        .is_ok());
}

/// No FAST key leaves keyd: neither the TgtContext (its Debug and the
/// KrbFastReq), nor the reply parts, nor keyd's Debug, nor any audit record
/// holds the armor key, the subkey, the TGT session key, the strengthen
/// key, the strengthened reply key, the service session key or the
/// long-term keys. Source: docs/48 §2.2, §9.1 I1, I8, §9.2 item 1; docs/10
/// §12 I1, I8; docs/CLEAN-ROOM.md
#[test]
fn no_fast_key_in_any_output_or_audit_record() {
    let (mut f, tgt) = setup();
    let a = armored(&tgt, 140);
    let ctx = open_armored(&mut f, &a, now()).unwrap();
    let parts = issue(&mut f, &ctx, INNER_NONCE).unwrap();
    let response = fast_response(&a.armor_key, &parts);
    let strengthen = key_from(response.strengthen_key.as_ref().unwrap());
    let reply = reply_key(&strengthen, &subkey());
    let rep = EncTgsRepPart::decode(&open(&reply, 9, &parts.enc_part))
        .unwrap()
        .0;
    let ctx2 = open_armored(&mut f, &armored(&tgt, 141), now()).unwrap();
    let sealed = seal_tgs_error(
        &mut f,
        &KDC,
        &ctx2.ctx_id,
        &tgs_fast_error(KDC_ERR_POLICY),
        &[cookie()],
    )
    .unwrap();

    let secrets: Vec<Vec<u8>> = vec![
        a.armor_key.octets().to_vec(),
        SUBKEY.to_vec(),
        tgt.session.octets().to_vec(),
        strengthen.octets().to_vec(),
        reply.octets().to_vec(),
        rep.key.keyvalue.as_bytes().to_vec(),
        KRBTGT_KEY.to_vec(),
        SERVICE_KEY.to_vec(),
    ];
    let outputs: Vec<Vec<u8>> = vec![
        format!("{ctx:?}").into_bytes(),
        ctx.fast_req.as_ref().unwrap().encode().unwrap(),
        parts.ticket.encode().unwrap(),
        parts.enc_part.encode().unwrap(),
        parts.fast_rep.as_ref().unwrap().encode().unwrap(),
        format!("{parts:?}").into_bytes(),
        sealed.encode().unwrap(),
        format!("{:?}", f.keyd).into_bytes(),
        format!("{:?}", f.records()).into_bytes(),
    ];
    for out in &outputs {
        for secret in &secrets {
            assert!(!contains_bytes(out, secret));
        }
    }
    let k = a.armor_key.octets();
    let renderings = [
        format!("{}, {}, {}, {}", k[0], k[1], k[2], k[3]),
        format!("{:02x}{:02x}{:02x}{:02x}", k[0], k[1], k[2], k[3]),
    ];
    let text = format!("{ctx:?}{parts:?}{:?}{:?}", f.keyd, f.records());
    for r in &renderings {
        assert!(!text.contains(r.as_str()), "{r}");
    }
}
