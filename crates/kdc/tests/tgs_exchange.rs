//! The TGS exchange (and the full AS → TGS round trip) through
//! `Kdc::handle`.
//!
//! The TGS is always FAST-armored (docs/48 §5, §7; P-10 interim): every
//! TGS-REQ here carries the implicit armor of RFC 6113 5.4.2 — a subkey in
//! the PA-TGS-REQ authenticator, a PA-FX-FAST without armor field whose
//! req-checksum covers the PA-TGS-REQ AP-REQ and whose KrbFastReq carries the
//! inner req-body — and every TGS-REP is opened through the KrbFastResponse
//! (strengthened reply key, KrbFastFinished; RFC 6113 5.4.3).
//!
//! Sources: RFC 4120 2.1, 3.1.2, 3.2.3, 3.3.2, 3.3.3, 3.3.3.1, 5.2.7.1, 5.3,
//! 5.4.1, 5.4.2, 5.5.1, 7.5.1, 7.5.9; RFC 6113 5.4.2, 5.4.3; RFC 3961 §8
//! (etype numbers used as client offers); docs/25 §4 (D53); docs/48 §5;
//! docs/questions/Q-150; main-session decisions 4-10, 13 (named per test);
//! A-26 (docs/questions/Q-071). All values hand-made.

mod common;

use common::*;
use kdc::{AuditOutcome, AuditReason, Exchange};
use krb_proto::constants::{
    KDC_ERR_BADOPTION, KDC_ERR_CLIENT_REVOKED, KDC_ERR_ETYPE_NOSUPP, KDC_ERR_PADATA_TYPE_NOSUPP,
    KDC_ERR_POLICY, KDC_ERR_SERVICE_REVOKED, KDC_ERR_S_PRINCIPAL_UNKNOWN, KDC_ERR_TGT_REVOKED,
    KRB_AP_ERR_BAD_INTEGRITY, KRB_AP_ERR_NOT_US, KRB_AP_ERR_REPEAT, KRB_AP_ERR_SKEW,
    KRB_AP_ERR_TKT_EXPIRED, KRB_AP_ERR_TKT_NYV, KRB_NT_SRV_INST,
};
use krb_proto::{EncryptedData, KdcReq, PaData, PrincipalName, Realm, TgsReq, TicketFlags};
use pdp::{
    ActionMatch, AuthMatch, ContextMatch, Effect, KerbResKind, Match, ResourceMatch, Rule, RuleId,
    Spn, SubjectMatch,
};

/// The full round trip (RFC 4120 3.1 then 3.3): alice gets a TGT, then a
/// service ticket. The client opens the TGS-REP through the KrbFastResponse
/// (RFC 6113 5.4.3: strengthened reply key, usage 9 — Q-121); the service
/// opens the ticket with its key (usage 2, 5.3). Names, flags (PRE-AUTHENT
/// carried, no INITIAL — 2.1) and times (3.3.3) are checked; keyd verified
/// the authenticator checksum over the KDC's re-encoding of the
/// KDC-REQ-BODY (decision 13).
#[test]
fn as_then_tgs_round_trip() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let spec = TgsReqSpec::service();
    let (request, _) = spec.encode(&tgt);
    let bytes = sent(f.send(&request));
    let (rep, part) = open_tgs_rep(&bytes, &tgt, &spec);
    assert_eq!(rep.0.crealm, realm());
    assert_eq!(rep.0.cname, alice_name());
    // RFC 6113 5.4.3: only PA-FX-FAST.
    assert_eq!(rep.0.padata.as_ref().map(Vec::len), Some(1));
    assert_eq!(rep.0.ticket.realm, realm());
    assert_eq!(rep.0.ticket.sname, service_name());
    let p = &part.0;
    assert_eq!(p.nonce, spec.nonce);
    assert_eq!(p.srealm, realm());
    assert_eq!(p.sname, service_name());
    assert_eq!(p.authtime, tgt.part.0.authtime);
    assert_eq!(p.starttime, Some(now()));
    assert_eq!(p.endtime, kt("20261113170000Z"));
    assert_eq!(p.key.keytype, AES256);
    assert!(p.flags.contains(TicketFlags::PRE_AUTHENT));
    assert!(!p.flags.contains(TicketFlags::INITIAL));
    assert!(!p.flags.contains(TicketFlags::FORWARDABLE));
    assert_ne!(p.key.keyvalue, tgt.part.0.key.keyvalue);
    let ticket = open_ticket(&rep.0.ticket, &service_key());
    assert_eq!(ticket.cname, alice_name());
    assert_eq!(ticket.crealm, realm());
    assert_eq!(ticket.key.keyvalue, p.key.keyvalue);
    assert_eq!(ticket.flags, p.flags);
    let events = f.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].exchange, Some(Exchange::Tgs));
    assert_eq!(events[1].outcome, AuditOutcome::Issued);
    assert_eq!(events[1].client.as_ref().unwrap().name, alice_name());
    assert_eq!(events[1].service.as_ref().unwrap().name, service_name());
}

/// RFC 4120 5.4.2 / 3.3.3 with RFC 6113 5.4.3 ("it MUST be set in a TGS
/// reply"): the TGS-REP enc-part (usage 9) opens only under the reply key
/// strengthened from the authenticator subkey — not under the subkey alone,
/// nor under the TGT session key (docs/48 §9.2 item 3).
#[test]
fn subkey_reply_is_strengthened() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let subkey = [0x3B; 32];
    let mut spec = TgsReqSpec::service();
    spec.subkey = Some(subkey);
    let (request, _) = spec.encode(&tgt);
    let bytes = sent(f.send(&request));
    let rep = krb_proto::TgsRep::decode(&bytes).unwrap();
    for (key, n) in [(aes256(&subkey), 9), (aes256(&subkey), 8)] {
        assert!(krb_crypto::decrypt(&key, usage(n), &rep.0.enc_part.cipher).is_err());
    }
    assert!(krb_crypto::decrypt(&tgt.session, usage(8), &rep.0.enc_part.cipher).is_err());
    let (_, part) = open_tgs_rep(&bytes, &tgt, &spec);
    assert_eq!(part.0.sname, service_name());
}

/// Decision 7 / docs/30 §3.3: a PDP Deny at TGS (for this service) is
/// KDC_ERR_POLICY, decided after keyd verified the TGT.
#[test]
fn pdp_deny_at_tgs_is_policy() {
    let mut setup = Setup::new();
    setup.rules.push(Rule {
        id: RuleId(7),
        effect: Effect::Deny,
        when: Match {
            action: ActionMatch::Exact(pdp::Action::KdcTgs),
            resource: ResourceMatch::Kerberos {
                kind: Some(KerbResKind::Service(Spn("host/files.example.org".into()))),
            },
            subject: SubjectMatch::MemberOf(users_group()),
            context: ContextMatch::ANY,
            auth: AuthMatch::ANY,
        },
        obligations: Vec::new(),
    });
    let mut f = setup.build();
    let tgt = obtain_tgt(&mut f);
    let (request, _) = TgsReqSpec::service().encode(&tgt);
    let error = error_of(f.send(&request));
    assert_eq!(error.error_code, KDC_ERR_POLICY);
    // The client is known (keyd verified the TGT) and named in the error
    // (RFC 4120 5.9.1).
    assert_eq!(error.cname, Some(alice_name()));
    assert_eq!(
        f.events()[1].reason,
        AuditReason::PolicyDenied(pdp::ReasonCode::CoarseDeny(RuleId(7)))
    );
}

/// D53 / decision 8: the account is re-read at TGS time. Disabled after the
/// TGT was issued → KDC_ERR_CLIENT_REVOKED; locked, expired or deleted → the
/// same.
#[test]
fn account_change_after_tgt_is_client_revoked() {
    for change in 0..4 {
        let mut f = Fixture::new();
        let tgt = obtain_tgt(&mut f);
        match change {
            0 => {
                f.accounts()
                    .client_mut(&realm(), &alice_name())
                    .unwrap()
                    .state
                    .enabled = false
            }
            1 => {
                f.accounts()
                    .client_mut(&realm(), &alice_name())
                    .unwrap()
                    .state
                    .locked = true
            }
            2 => {
                f.accounts()
                    .client_mut(&realm(), &alice_name())
                    .unwrap()
                    .state
                    .expires = Some(now())
            }
            _ => {
                f.accounts().remove_client(&realm(), &alice_name());
            }
        }
        let (request, _) = TgsReqSpec::service().encode(&tgt);
        assert_eq!(
            code_of(f.send(&request)),
            KDC_ERR_CLIENT_REVOKED,
            "case {change}"
        );
        assert_eq!(f.events()[1].reason, AuditReason::ClientRevoked);
    }
}

/// RFC 4120 3.3.3.1 (hot-list by authtime): a TGT authenticated before the
/// account's revocation instant is refused with KDC_ERR_TGT_REVOKED — e.g.
/// after a password reset or a reused name (no PAC in phase 1).
#[test]
fn tgt_before_revocation_instant_is_tgt_revoked() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    f.accounts()
        .client_mut(&realm(), &alice_name())
        .unwrap()
        .state
        .revoked_before = Some(at(1));
    let (request, _) = TgsReqSpec::service().encode(&tgt);
    assert_eq!(code_of(f.send(&request)), KDC_ERR_TGT_REVOKED);
}

/// RFC 4120 7.5.9 / decision 8: an unknown service is
/// KDC_ERR_S_PRINCIPAL_UNKNOWN; a disabled one KDC_ERR_SERVICE_REVOKED.
#[test]
fn service_unknown_or_revoked() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let mut spec = TgsReqSpec::service();
    spec.sname = Some(name(3, &["host", "nowhere.example.org"]));
    let (request, _) = spec.encode(&tgt);
    assert_eq!(code_of(f.send(&request)), KDC_ERR_S_PRINCIPAL_UNKNOWN);

    f.accounts()
        .service_mut(&realm(), &service_name())
        .unwrap()
        .state
        .enabled = false;
    let mut spec = TgsReqSpec::service();
    spec.cusec = 2;
    let (request, _) = spec.encode(&tgt);
    assert_eq!(code_of(f.send(&request)), KDC_ERR_SERVICE_REVOKED);
}

/// RFC 4120 3.2.3 / 3.3.2 (replay cache; "if the authenticator is a replay,
/// but the rest of the request is not identical, then the KDC SHOULD return
/// KRB_AP_ERR_REPEAT"): the same authenticator and body in a different
/// request (an extra, unknown padata element) is refused with
/// KRB_AP_ERR_REPEAT — keyd reports the Replay class because the crypto
/// chain passed (A-26, docs/questions/Q-071).
#[test]
fn replayed_authenticator_is_refused() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let spec = TgsReqSpec::service();
    let (request, _) = spec.encode(&tgt);
    sent(f.send(&request));
    let mut replay = spec.clone();
    replay.extra_padata = vec![PaData {
        padata_type: 128,
        padata_value: vec![0x30, 0x00],
    }];
    let (replayed, _) = replay.encode(&tgt);
    assert_ne!(replayed, request);
    let error = error_of(f.send(&replayed));
    assert_eq!(error.error_code, KRB_AP_ERR_REPEAT);
    assert_eq!(f.events()[2].reason, AuditReason::AuthenticatorReplay);
    let last = f.keyd_records().last().unwrap();
    assert_eq!(last.op, keyd::Operation::OpenAndVerifyTgt);
    assert_eq!(last.reason, keyd::AuditReason::Replay);
}

/// RFC 4120 3.1.2 / 3.3.2: "the KDC MUST send a valid KRB_TGS_REP message if
/// it receives a KRB_TGS_REQ message identical to one it has recently
/// processed" — the identical request gets the identical reply (same ticket,
/// same session key: "KDCs MAY send the same response"), and keyd is not
/// asked again.
#[test]
fn identical_retransmission_gets_the_same_reply() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let (request, _) = TgsReqSpec::service().encode(&tgt);
    let first = sent(f.send(&request));
    let keyd_calls = f.keyd_records().len();
    let second = sent(f.send_at(&request, kdc::Transport::Udp, at(10)));
    assert_eq!(first, second);
    assert_eq!(f.keyd_records().len(), keyd_calls);
    assert_eq!(f.events()[2].reason, AuditReason::Retransmission);
    // After the window (keyd's clock skew) the entry is gone; the stale
    // authenticator is then refused by keyd as out of skew (A-26).
    let late = f.send_at(&request, kdc::Transport::Tcp, at(301));
    assert_eq!(code_of(late), KRB_AP_ERR_SKEW);
}

/// Decision 9 / RFC 4120 5.4.1: operation options at TGS are
/// KDC_ERR_BADOPTION (the inner request), as are additional tickets (RFC 4120
/// 5.4.1). enc-authorization-data is refused by keyd itself, which under FAST
/// checks both bodies before its chain completes (docs/10 §5א; Q-150 item 2,
/// A-43) — the uniform KRB_AP_ERR_BAD_INTEGRITY (A-26); keyd carries no
/// authorization data (docs/10 §5).
#[test]
fn operation_options_and_content_are_badoption_at_tgs() {
    for bit in [2, 4, 5, 6, 28, 30, 31] {
        let mut f = Fixture::new();
        let tgt = obtain_tgt(&mut f);
        let mut spec = TgsReqSpec::service();
        spec.options = options(&[bit]);
        let (request, _) = spec.encode(&tgt);
        assert_eq!(code_of(f.send(&request)), KDC_ERR_BADOPTION, "bit {bit}");
    }
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let mut spec = TgsReqSpec::service();
    spec.enc_authorization_data = Some(EncryptedData {
        etype: AES256,
        kvno: None,
        cipher: vec![0; 32],
    });
    let (request, _) = spec.encode(&tgt);
    assert_eq!(code_of(f.send(&request)), KRB_AP_ERR_BAD_INTEGRITY);
    assert_eq!(
        f.keyd_records().last().unwrap().reason,
        keyd::AuditReason::UnsupportedContent
    );
    let mut spec = TgsReqSpec::service();
    spec.cusec = 3;
    spec.additional_tickets = Some(vec![tgt.rep.0.ticket.clone()]);
    let (request, _) = spec.encode(&tgt);
    assert_eq!(code_of(f.send(&request)), KDC_ERR_BADOPTION);
}

/// Decision 9 / RFC 4120 5.4.1 ("FORWARDABLE ... in a subsequent request if
/// the TGT on which it is based is also forwardable"): granted only when the
/// policy allows it AND the TGT is forwardable; otherwise withheld.
#[test]
fn flag_options_follow_policy_and_tgt_at_tgs() {
    let mut f = Setup::new()
        .ticket_policy(|p| p.allowed_flags.insert(TicketFlags::FORWARDABLE))
        .build();
    // A TGT without FORWARDABLE.
    let tgt = obtain_tgt(&mut f);
    let mut spec = TgsReqSpec::service();
    spec.options = options(&[1]);
    let (request, _) = spec.encode(&tgt);
    let (_, part) = open_tgs_rep(&sent(f.send(&request)), &tgt, &spec);
    assert!(!part.0.flags.contains(TicketFlags::FORWARDABLE));
    // A forwardable TGT.
    let mut as_spec = AsReqSpec::alice();
    as_spec.options = options(&[1]);
    as_spec.nonce = 99;
    let tgt = obtain_tgt_with(&mut f, as_spec);
    assert!(tgt.part.0.flags.contains(TicketFlags::FORWARDABLE));
    let mut spec = TgsReqSpec::service();
    spec.options = options(&[1]);
    spec.cusec = 2;
    let (request, _) = spec.encode(&tgt);
    let (_, part) = open_tgs_rep(&sent(f.send(&request)), &tgt, &spec);
    assert!(part.0.flags.contains(TicketFlags::FORWARDABLE));
}

/// RFC 4120 3.3.3: the service ticket's endtime is at most the TGT's
/// endtime; renew-till at most the TGT's renew-till, and RENEWABLE needs a
/// renewable TGT (5.4.1).
#[test]
fn service_ticket_times_are_within_the_tgt() {
    let mut f = Fixture::new();
    let mut as_spec = AsReqSpec::alice();
    as_spec.till = kt("20261113120000Z");
    as_spec.options = options(&[8]);
    as_spec.rtime = Some(kt("20261114100000Z"));
    let tgt = obtain_tgt_with(&mut f, as_spec);
    let mut spec = TgsReqSpec::service();
    spec.till = till_max();
    spec.options = options(&[8]);
    spec.rtime = Some(kt("20261120100000Z"));
    let (request, _) = spec.encode(&tgt);
    let (_, part) = open_tgs_rep(&sent(f.send(&request)), &tgt, &spec);
    assert_eq!(part.0.endtime, kt("20261113120000Z"));
    assert!(part.0.flags.contains(TicketFlags::RENEWABLE));
    assert_eq!(part.0.renew_till, Some(kt("20261114100000Z")));

    // A non-renewable TGT: RENEWABLE is withheld (not refused).
    let tgt = obtain_tgt(&mut f);
    let mut spec = TgsReqSpec::service();
    spec.options = options(&[8]);
    spec.rtime = Some(kt("20261120100000Z"));
    spec.cusec = 5;
    let (request, _) = spec.encode(&tgt);
    let (_, part) = open_tgs_rep(&sent(f.send(&request)), &tgt, &spec);
    assert!(!part.0.flags.contains(TicketFlags::RENEWABLE));
    assert_eq!(part.0.renew_till, None);
}

/// Decision 6 / RFC 4120 3.1.3: no acceptable AES session-key type at TGS is
/// KDC_ERR_ETYPE_NOSUPP; a mixed list picks the first acceptable one.
#[test]
fn etype_negotiation_at_tgs() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let mut spec = TgsReqSpec::service();
    spec.etypes = vec![RC4_HMAC, DES_CBC_CRC];
    let (request, _) = spec.encode(&tgt);
    assert_eq!(code_of(f.send(&request)), KDC_ERR_ETYPE_NOSUPP);
    let mut spec = TgsReqSpec::service();
    spec.etypes = vec![RC4_HMAC, AES128, AES256];
    spec.cusec = 2;
    let (request, _) = spec.encode(&tgt);
    let (_, part) = open_tgs_rep(&sent(f.send(&request)), &tgt, &spec);
    assert_eq!(part.0.key.keytype, AES128);
}

/// RFC 4120 3.3.2, 3.2.3; decision 4; docs/questions/Q-070:
/// - no PA-TGS-REQ → KDC_ERR_PADATA_TYPE_NOSUPP;
/// - this realm's TGS as sname → KDC_ERR_POLICY (armored, inner request);
/// - another realm's TGS → KDC_ERR_S_PRINCIPAL_UNKNOWN (armored);
/// - another realm in the request → KRB_AP_ERR_BAD_INTEGRITY: under FAST
///   keyd itself refuses a body (outer or inner) not of this realm before its
///   chain completes (docs/questions/Q-150 item 2, A-43; the uniform `Denied`
///   of A-26), so the KDC's own realm check of the inner body is defence in
///   depth;
/// - a presented ticket that is not this realm's TGT → KRB_AP_ERR_NOT_US;
/// - a body altered after the checksum → KRB_AP_ERR_BAD_INTEGRITY (keyd's
///   checksum check, RFC 4120 3.3.2 / A-17).
#[test]
fn tgs_request_shape_refusals() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);

    let spec = TgsReqSpec::service();
    let bare = TgsReq(KdcReq {
        padata: None,
        req_body: spec.body(),
    })
    .encode()
    .unwrap();
    assert_eq!(code_of(f.send(&bare)), KDC_ERR_PADATA_TYPE_NOSUPP);

    let mut spec = TgsReqSpec::service();
    spec.sname = Some(krbtgt_name());
    assert_eq!(code_of(f.send(&spec.encode(&tgt).0)), KDC_ERR_POLICY);

    // The inner request is checked after keyd opened the armored context,
    // so each request needs a fresh authenticator (keyd's replay cache).
    let mut spec = TgsReqSpec::service();
    spec.sname = Some(name(KRB_NT_SRV_INST, &["krbtgt", "OTHER.ORG"]));
    spec.cusec = 2;
    assert_eq!(
        code_of(f.send(&spec.encode(&tgt).0)),
        KDC_ERR_S_PRINCIPAL_UNKNOWN
    );

    let mut spec = TgsReqSpec::service();
    spec.realm = Realm::new("OTHER.ORG").unwrap();
    spec.cusec = 4;
    assert_eq!(
        code_of(f.send(&spec.encode(&tgt).0)),
        KRB_AP_ERR_BAD_INTEGRITY
    );
    assert_eq!(
        f.keyd_records().last().unwrap().reason,
        keyd::AuditReason::WrongRealm
    );
    // Only the inner body names another realm.
    let mut spec = TgsReqSpec::service();
    spec.cusec = 5;
    spec.outer = Some(spec.body());
    spec.realm = Realm::new("OTHER.ORG").unwrap();
    assert_eq!(
        code_of(f.send(&spec.encode(&tgt).0)),
        KRB_AP_ERR_BAD_INTEGRITY
    );

    // A service ticket presented instead of a TGT.
    let mut spec = TgsReqSpec::service();
    spec.cusec = 7;
    let (request, _) = spec.encode(&tgt);
    let (rep, part) = open_tgs_rep(&sent(f.send(&request)), &tgt, &spec);
    let service_session = key_from(&part.0.key);
    let mut spec = TgsReqSpec::service();
    spec.cusec = 9;
    let (request, _) = spec.encode_with_ticket(&rep.0.ticket, &service_session);
    assert_eq!(code_of(f.send(&request)), KRB_AP_ERR_NOT_US);

    // The authenticator's checksum covers a different body.
    let mut original = TgsReqSpec::service();
    original.cusec = 11;
    let (_, original_body) = original.encode(&tgt);
    let mut altered = original.clone();
    altered.sname = Some(PrincipalName {
        name_type: 3,
        name_string: service_name().name_string,
    });
    altered.nonce = 12345;
    let request = altered.request_with(
        &tgt.rep.0.ticket,
        &tgt.session,
        authenticator(&tgt.session, &original, &original_body),
    );
    assert_eq!(code_of(f.send(&request)), KRB_AP_ERR_BAD_INTEGRITY);
    assert_eq!(
        f.keyd_records().last().unwrap().reason,
        keyd::AuditReason::ChecksumMismatch
    );
}

/// A TGS-REQ for `spec` whose authenticator is `auth` (which may cover
/// another body or be tampered with), armored as usual. RFC 4120 5.4.1,
/// 5.2.7.1; RFC 6113 5.4.2.
fn request_with(tgt: &Tgt, spec: &TgsReqSpec, auth: EncryptedData) -> Vec<u8> {
    spec.request_with(&tgt.rep.0.ticket, &tgt.session, auth)
}

/// A-26 / RFC 4120 3.2.3: once keyd's cryptographic chain passed, each class
/// maps to its RFC code — an expired TGT → KRB_AP_ERR_TKT_EXPIRED, a TGT not
/// yet valid → KRB_AP_ERR_TKT_NYV, an authenticator out of skew →
/// KRB_AP_ERR_SKEW (replay → KRB_AP_ERR_REPEAT: see
/// `replayed_authenticator_is_refused`). stime is the KDC's `now` (5.9.1).
#[test]
fn post_crypto_classes_map_to_rfc_codes() {
    let mut f = Fixture::new();
    // Expired: TGT until 10:10; request at 10:15:01 (beyond the 300 s skew).
    let mut short = AsReqSpec::alice();
    short.till = kt("20261113101000Z");
    let tgt = obtain_tgt_at(&mut f, short, now());
    let mut spec = TgsReqSpec::service();
    spec.ctime = at(901);
    let error = error_of(f.send_at(&spec.encode(&tgt).0, kdc::Transport::Tcp, at(901)));
    assert_eq!(error.error_code, KRB_AP_ERR_TKT_EXPIRED);
    assert_eq!(error.stime, at(901));
    assert_eq!(f.events().last().unwrap().reason, AuditReason::TgtExpired);

    // Not yet valid: TGT authenticated at 10:06:40, request at 10:00.
    let mut later = AsReqSpec::alice();
    later.nonce = 7;
    let tgt = obtain_tgt_at(&mut f, later, at(400));
    let mut spec = TgsReqSpec::service();
    spec.cusec = 2;
    let error = error_of(f.send(&spec.encode(&tgt).0));
    assert_eq!(error.error_code, KRB_AP_ERR_TKT_NYV);
    assert_eq!(
        f.events().last().unwrap().reason,
        AuditReason::TgtNotYetValid
    );

    // Skew: a valid TGT, authenticator ctime 400 s before now.
    let tgt = obtain_tgt(&mut f);
    let mut spec = TgsReqSpec::service();
    spec.ctime = at(-400);
    spec.cusec = 3;
    let error = error_of(f.send(&spec.encode(&tgt).0));
    assert_eq!(error.error_code, KRB_AP_ERR_SKEW);
    assert_eq!(error.stime, now());
    assert_eq!(
        f.events().last().unwrap().reason,
        AuditReason::AuthenticatorSkew
    );
}

/// The ordering property (A-26): a class is reported only after the TGT
/// decrypted, the authenticator decrypted and the req-body checksum
/// verified. For an EXPIRED TGT, an authenticator whose checksum covers
/// another body, or a tampered authenticator, is KRB_AP_ERR_BAD_INTEGRITY —
/// never TKT_EXPIRED; likewise a SKEWED authenticator with a bad checksum.
/// Source: docs/questions/Q-071 (A-26); RFC 4120 3.3.2.
#[test]
fn forged_requests_never_learn_a_class() {
    let mut f = Fixture::new();
    let mut short = AsReqSpec::alice();
    short.till = kt("20261113101000Z");
    let tgt = obtain_tgt_at(&mut f, short, now());
    let mut spec = TgsReqSpec::service();
    spec.ctime = at(901);
    let mut other = spec.clone();
    other.nonce = 1;
    let other_body = other.body().encode().unwrap();

    // Expired + checksum over another body.
    let auth = authenticator(&tgt.session, &spec, &other_body);
    let reply = f.send_at(
        &request_with(&tgt, &spec, auth),
        kdc::Transport::Tcp,
        at(901),
    );
    assert_eq!(code_of(reply), KRB_AP_ERR_BAD_INTEGRITY);
    assert_eq!(
        f.keyd_records().last().unwrap().reason,
        keyd::AuditReason::ChecksumMismatch
    );

    // Expired + tampered authenticator.
    let body = spec.body().encode().unwrap();
    let mut auth = authenticator(&tgt.session, &spec, &body);
    let last = auth.cipher.len() - 1;
    auth.cipher[last] ^= 0x01;
    let reply = f.send_at(
        &request_with(&tgt, &spec, auth),
        kdc::Transport::Tcp,
        at(901),
    );
    assert_eq!(code_of(reply), KRB_AP_ERR_BAD_INTEGRITY);
    assert_eq!(
        f.keyd_records().last().unwrap().reason,
        keyd::AuditReason::IntegrityFailure
    );

    // Skewed authenticator (valid TGT) + checksum over another body.
    let tgt = obtain_tgt(&mut f);
    let mut spec = TgsReqSpec::service();
    spec.ctime = at(-400);
    spec.cusec = 4;
    let mut other = spec.clone();
    other.nonce = 2;
    let auth = authenticator(&tgt.session, &spec, &other.body().encode().unwrap());
    let reply = f.send(&request_with(&tgt, &spec, auth));
    assert_eq!(code_of(reply), KRB_AP_ERR_BAD_INTEGRITY);
}

/// A-26: a request refused as out of skew does not enter keyd's replay
/// cache — the identical retry, once the clocks agree, is answered with a
/// ticket, not KRB_AP_ERR_REPEAT. (Refusals are never put in the retransmit
/// cache either, RFC 4120 3.1.2.)
#[test]
fn skew_refusal_is_not_remembered_as_replay() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let spec = TgsReqSpec::service();
    let (request, _) = spec.encode(&tgt);
    // The KDC's clock runs 301 s ahead of the authenticator: out of skew.
    let ahead = f.send_at(&request, kdc::Transport::Tcp, at(301));
    assert_eq!(code_of(ahead), KRB_AP_ERR_SKEW);
    let (_, part) = open_tgs_rep(&sent(f.send(&request)), &tgt, &spec);
    assert_eq!(part.0.sname, service_name());
}
