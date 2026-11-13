//! The TGS exchange through keyd: open_and_verify_tgt -> issue_tgs_rep, with
//! the test acting as the client (RFC 4120 §3.3, §5.2.7.1, §5.4.2, §5.5.1,
//! key usages 2/6/7/8/9 of §7.5.1), plus the negative cases: replay, tampered
//! request body, clock skew, name mismatch, expired / invalid TGT, and the
//! context misuse cases of invariant I4 (docs/10 §12). All values are
//! constructed for these tests.

mod common;

use common::*;
use keyd::{AuditReason, AuthnError, CtxId, IssueError};
use krb_crypto::EncType;
use krb_proto::constants::{KRB_NT_SRV_HST, KRB_NT_UNKNOWN};
use krb_proto::{ApOptions, EncTgsRepPart, EncTicketPart, PrincipalName, TicketFlags};

/// A change applied to a valid template to make it invalid.
type TgsMutation = Box<dyn Fn(&mut keyd::TgsTicketTemplate)>;

/// Full TGS round trip, reply under the TGT session key. Source: RFC 4120
/// 3.3.2 (TGT decrypted with the TGS key; checksum verified), 3.3.3 (client
/// name, realm, authtime, transited carried over from the TGT; reply in the TGT
/// session key), 5.4.2 (usage 8, no kvno), 5.5.1 (usages 6 and 7), 2.1
/// (PRE-AUTHENT carried, INITIAL clear); docs/10 §5.
#[test]
fn tgs_round_trip_session_key() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let nonce = 0x0A0B_0C0D;
    let (_, body) = tgs_req_body(nonce, service_name());
    let auth = authenticator(&tgt.session, &AuthenticatorSpec::new(now(), 1, &body));
    let ctx = f
        .keyd
        .open_and_verify_tgt(
            &KDC,
            &KRBTGT,
            &ap_req(&tgt.parts.ticket, auth),
            &body,
            &now(),
        )
        .unwrap();
    assert_eq!(ctx.cname, alice_name());
    assert_eq!(ctx.crealm, realm());
    assert_eq!(ctx.authtime, now());
    assert_eq!(ctx.endtime, as_template().endtime);
    assert!(ctx.flags.contains(TicketFlags::INITIAL));

    let template = tgs_template(nonce);
    let parts = f
        .keyd
        .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &template, &now())
        .unwrap();

    // Client side: the enc-part opens with the TGT session key, usage 8.
    assert_eq!(parts.enc_part.kvno, None, "RFC 4120 5.4.2: no kvno");
    let rep = EncTgsRepPart::decode(&open(&tgt.session, 8, &parts.enc_part))
        .unwrap()
        .0;
    assert_eq!(rep.nonce, nonce);
    assert_eq!(rep.sname, service_name());
    assert_eq!(rep.srealm, realm());
    assert_eq!(rep.authtime, now());
    assert!(rep.flags.contains(TicketFlags::PRE_AUTHENT));
    assert!(!rep.flags.contains(TicketFlags::INITIAL));
    assert!(rep.key_expiration.is_none());

    // The service opens the ticket with its key (scripted in the test),
    // usage 2.
    assert_eq!(parts.ticket.sname, service_name());
    assert_eq!(parts.ticket.enc_part.kvno, Some(1));
    let etp = EncTicketPart::decode(&open(&service_key(), 2, &parts.ticket.enc_part)).unwrap();
    assert_eq!(etp.key, rep.key);
    assert_eq!(etp.cname, alice_name(), "carried over from the TGT");
    assert_eq!(etp.crealm, realm());
    assert_eq!(etp.authtime, now(), "carried over from the TGT");
    assert_eq!(etp.flags, rep.flags);
    assert!(etp.authorization_data.is_none(), "no PAC in phase 1");
    assert_ne!(etp.key, tgt.rep.0.key, "a fresh service session key");
}

/// Reply under the authenticator subkey (usage 9); the TGT session key does
/// not open it. Source: RFC 4120 3.3.3 ("encrypted in the sub-session key
/// from the Authenticator, if present"), 5.4.2 (usage 9), 7.5.1.
#[test]
fn tgs_round_trip_subkey() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let subkey = [0xE7u8; 32];
    let (_, body) = tgs_req_body(7, service_name());
    let mut spec = AuthenticatorSpec::new(now(), 2, &body);
    spec.subkey = Some(&subkey);
    let auth = authenticator(&tgt.session, &spec);
    let ctx = f
        .keyd
        .open_and_verify_tgt(
            &KDC,
            &KRBTGT,
            &ap_req(&tgt.parts.ticket, auth),
            &body,
            &now(),
        )
        .unwrap();
    let parts = f
        .keyd
        .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(7), &now())
        .unwrap();
    let sub = krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &subkey).unwrap();
    assert!(EncTgsRepPart::decode(&open(&sub, 9, &parts.enc_part)).is_ok());
    assert!(krb_crypto::decrypt(&tgt.session, usage(8), &parts.enc_part.cipher).is_err());
    assert!(krb_crypto::decrypt(&sub, usage(8), &parts.enc_part.cipher).is_err());
}

/// The same authenticator presented twice is a replay. Source: RFC 4120
/// 3.2.3 (replay cache, KRB_AP_ERR_REPEAT), 3.3.2; docs/10 D33.
#[test]
fn replayed_authenticator_denied() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let (_, body) = tgs_req_body(9, service_name());
    let req = ap_req(
        &tgt.parts.ticket,
        authenticator(&tgt.session, &AuthenticatorSpec::new(now(), 3, &body)),
    );
    assert!(f
        .keyd
        .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, &now())
        .is_ok());
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, &at(1)),
        Err(AuthnError::Denied)
    );
    assert_eq!(f.records().last().unwrap().reason, AuditReason::Replay);
    // A different microsecond value is a different authenticator.
    let req2 = ap_req(
        &tgt.parts.ticket,
        authenticator(&tgt.session, &AuthenticatorSpec::new(now(), 4, &body)),
    );
    assert!(f
        .keyd
        .open_and_verify_tgt(&KDC, &KRBTGT, &req2, &body, &now())
        .is_ok());
}

/// The authenticator checksum binds it to the request body: a different
/// body (cut-and-paste) or a missing checksum is refused. Source: RFC 4120
/// 3.3.2 ("MUST be verified against the contents of the request ...
/// KRB_AP_ERR_MODIFIED"), 5.2.7.1, 5.5.1 (usage 6).
#[test]
fn tampered_req_body_denied() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let (_, body) = tgs_req_body(11, service_name());
    let (_, other_body) = tgs_req_body(12, service_name());
    let req = ap_req(
        &tgt.parts.ticket,
        authenticator(&tgt.session, &AuthenticatorSpec::new(now(), 5, &body)),
    );
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &req, &other_body, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::ChecksumMismatch
    );

    // A single flipped octet inside the body's nonce.
    let mut flipped = body.clone();
    let last = flipped.len() - 20;
    flipped[last] ^= 0x01;
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &req, &flipped, &now()),
        Err(AuthnError::Denied)
    );

    // No checksum at all.
    let mut spec = AuthenticatorSpec::new(now(), 6, &body);
    spec.cksum_over = None;
    let req = ap_req(&tgt.parts.ticket, authenticator(&tgt.session, &spec));
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::ChecksumMissing
    );
}

/// Authenticator ctime outside the skew window. Source: RFC 4120 3.2.3
/// (KRB_AP_ERR_SKEW), §8.2 (5 minutes).
#[test]
fn authenticator_clock_skew_denied() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let (_, body) = tgs_req_body(13, service_name());
    for (offset, ok) in [(-301, false), (301, false), (300, true)] {
        let req = ap_req(
            &tgt.parts.ticket,
            authenticator(&tgt.session, &AuthenticatorSpec::new(at(offset), 7, &body)),
        );
        let r = f
            .keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, &now());
        assert_eq!(r.is_ok(), ok, "offset {offset}");
    }
}

/// Authenticator names must match the ticket. Source: RFC 4120 3.2.3
/// (KRB_AP_ERR_BADMATCH).
#[test]
fn authenticator_name_mismatch_denied() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let (_, body) = tgs_req_body(14, service_name());
    let mut spec = AuthenticatorSpec::new(now(), 8, &body);
    spec.cname = bob_name();
    let req = ap_req(&tgt.parts.ticket, authenticator(&tgt.session, &spec));
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::NameMismatch
    );
}

/// An expired TGT is refused. Source: RFC 4120 3.2.3
/// (KRB_AP_ERR_TKT_EXPIRED), 3.3 ("expired tickets are not accepted by the
/// TGS").
#[test]
fn expired_tgt_denied() {
    let mut f = Fixture::new();
    let mut t = as_template();
    t.endtime = kt("20261113103000Z");
    let tgt = obtain_tgt(&mut f, now(), &t);
    let later = kt("20261113103501Z"); // endtime + 301 s
    let (_, body) = tgs_req_body(15, service_name());
    let req = ap_req(
        &tgt.parts.ticket,
        authenticator(&tgt.session, &AuthenticatorSpec::new(later, 9, &body)),
    );
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, &later),
        Err(AuthnError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::TicketExpired
    );
}

/// A tampered ticket, a ticket that is not this realm's TGT, and the
/// unimplemented USE-SESSION-KEY option are refused. Source: RFC 4120 3.2.3
/// (KRB_AP_ERR_BAD_INTEGRITY), 3.3.2, 7.3, 5.5.1 (use-session-key).
#[test]
fn bad_tickets_denied() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let (_, body) = tgs_req_body(16, service_name());
    let fresh = |cusec| authenticator(&tgt.session, &AuthenticatorSpec::new(now(), cusec, &body));

    let mut tampered = tgt.parts.ticket.clone();
    tampered.enc_part.cipher[20] ^= 0x80;
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &ap_req(&tampered, fresh(10)), &body, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::IntegrityFailure
    );

    let mut not_tgt = tgt.parts.ticket.clone();
    not_tgt.sname = service_name();
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &ap_req(&not_tgt, fresh(11)), &body, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(f.records().last().unwrap().reason, AuditReason::NotLocalTgt);

    let mut u2u = ap_req(&tgt.parts.ticket, fresh(12));
    u2u.ap_options = ApOptions::USE_SESSION_KEY;
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &u2u, &body, &now()),
        Err(AuthnError::Denied)
    );

    // An unknown kvno.
    let mut wrong_kvno = tgt.parts.ticket.clone();
    wrong_kvno.enc_part.kvno = Some(9);
    assert_eq!(
        f.keyd.open_and_verify_tgt(
            &KDC,
            &KRBTGT,
            &ap_req(&wrong_kvno, fresh(13)),
            &body,
            &now()
        ),
        Err(AuthnError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::KvnoMismatch
    );

    // Garbage in place of the KDC-REQ-BODY.
    assert_eq!(
        f.keyd.open_and_verify_tgt(
            &KDC,
            &KRBTGT,
            &ap_req(&tgt.parts.ticket, fresh(14)),
            &[0x30, 0x00],
            &now()
        ),
        Err(AuthnError::Denied)
    );
}

/// I4: issue_tgs_rep without a context, with a reused, expired or
/// foreign-caller context is refused. Source: docs/10 §8 ("without a valid
/// ctx — refuses"), D36, §12 I4.
#[test]
fn context_misuse_denied() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());

    // No context.
    assert_eq!(
        f.keyd.issue_tgs_rep(
            &KDC,
            &SERVICE,
            &CtxId::from_bytes([9; 16]),
            &tgs_template(20),
            &now()
        ),
        Err(IssueError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::TokenUnknown
    );

    // Reused.
    let ctx = open_tgt(&mut f, &tgt, 21, 20);
    assert!(f
        .keyd
        .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(21), &now())
        .is_ok());
    assert_eq!(
        f.keyd
            .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(21), &now()),
        Err(IssueError::Denied)
    );

    // Expired (30 s token lifetime).
    let ctx = open_tgt(&mut f, &tgt, 22, 21);
    let mut late_template = tgs_template(22);
    late_template.starttime = None;
    assert_eq!(
        f.keyd
            .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &late_template, &at(31)),
        Err(IssueError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::TokenExpired
    );

    // Another caller — refused, and the context is destroyed.
    let ctx = open_tgt(&mut f, &tgt, 23, 22);
    assert_eq!(
        f.keyd
            .issue_tgs_rep(&KDC_OTHER, &SERVICE, &ctx.ctx_id, &tgs_template(23), &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::TokenCallerMismatch
    );
    assert_eq!(
        f.keyd
            .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(23), &now()),
        Err(IssueError::Denied)
    );
}

/// Template checks of issue_tgs_rep (BadTemplate): the issued ticket must be
/// for the service and nonce of the authenticated request, within the TGT's
/// lifetime, with allowed flags and a configured enctype. Source: RFC 4120
/// 3.3.3 (endtime bounded by the TGT), 2.1 (no INITIAL), 5.4.1, 5.4.2
/// (nonce), 7.3; docs/10 §5; docs/30 §2.6.
#[test]
fn tgs_template_bad_template() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let cases: Vec<(&str, TgsMutation, AuditReason)> = vec![
        (
            "other service",
            Box::new(|t| t.sname = bob_name()),
            AuditReason::TemplateNames,
        ),
        (
            "krbtgt",
            Box::new(|t| t.sname = krbtgt_name()),
            AuditReason::TemplateNames,
        ),
        (
            "nonce",
            Box::new(|t| t.nonce ^= 1),
            AuditReason::TemplateNonce,
        ),
        (
            "beyond TGT endtime",
            Box::new(|t| t.endtime = kt("20261113180001Z")),
            AuditReason::TemplateTimes,
        ),
        (
            "INITIAL",
            Box::new(|t| t.flags = TicketFlags::INITIAL),
            AuditReason::TemplateFlags,
        ),
        (
            "FORWARDABLE",
            Box::new(|t| t.flags = TicketFlags::FORWARDABLE),
            AuditReason::TemplateFlags,
        ),
        (
            "OK-AS-DELEGATE",
            Box::new(|t| t.flags = TicketFlags::OK_AS_DELEGATE),
            AuditReason::TemplateFlags,
        ),
        (
            "renewable beyond non-renewable TGT",
            Box::new(|t| {
                t.flags = TicketFlags::RENEWABLE;
                t.renew_till = Some(kt("20261113170000Z"));
            }),
            AuditReason::TemplateTimes,
        ),
        (
            "unconfigured enctype",
            Box::new(|t| t.session_enctype = EncType::Aes128CtsHmacSha196),
            AuditReason::TemplateEncType,
        ),
    ];
    for (i, (name, mutate, reason)) in cases.iter().enumerate() {
        let nonce = 100 + i as u32;
        let ctx = open_tgt(&mut f, &tgt, nonce, 100 + i as u32);
        let mut t = tgs_template(nonce);
        mutate(&mut t);
        assert_eq!(
            f.keyd
                .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &t, &now()),
            Err(IssueError::BadTemplate),
            "{name}"
        );
        assert_eq!(f.records().last().unwrap().reason, *reason, "{name}");
    }
}

/// Bounded replay cache: when full of unexpired entries it refuses (fail
/// closed) instead of evicting a live entry; entries older than the skew
/// window age out. Source: RFC 4120 3.2.3 ("MUST reject all requests until
/// the clock skew interval has passed"); docs/10 D33.
#[test]
fn replay_cache_full_fails_closed() {
    let mut c = config();
    c.replay_cache_capacity = 2;
    let mut f = Fixture::with_config(c);
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let (_, body) = tgs_req_body(30, service_name());
    let call = |f: &mut Fixture, ctime, cusec, when| {
        let req = ap_req(
            &tgt.parts.ticket,
            authenticator(&tgt.session, &AuthenticatorSpec::new(ctime, cusec, &body)),
        );
        f.keyd
            .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, &when)
    };
    assert!(call(&mut f, now(), 1, now()).is_ok());
    assert!(call(&mut f, now(), 2, now()).is_ok());
    assert_eq!(call(&mut f, now(), 3, now()), Err(AuthnError::Denied));
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::ReplayCacheFull
    );
    // 301 s later the first two entries are outside the window.
    assert!(call(&mut f, at(301), 3, at(301)).is_ok());
}

/// Name binding (Q-040, A-19): the service key is bound to
/// host/files.example.org; a request (authenticated req-body and template
/// agreeing) for another service S must not be sealed under it — otherwise
/// the holder of that key could accept tickets naming S. Source:
/// docs/questions/Q-040 (A-19); RFC 4120 3.3.3, 5.3 (sname), 6.2.
#[test]
fn service_bound_to_other_name_denied() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let other = PrincipalName {
        name_type: KRB_NT_SRV_HST,
        name_string: vec![kstr("cifs"), kstr("other.example.org")],
    };
    let (_, body) = tgs_req_body(60, other.clone());
    let req = ap_req(
        &tgt.parts.ticket,
        authenticator(&tgt.session, &AuthenticatorSpec::new(now(), 60, &body)),
    );
    let ctx = f
        .keyd
        .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, &now())
        .unwrap();
    let mut t = tgs_template(60);
    t.sname = other;
    assert_eq!(
        f.keyd
            .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &t, &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::NameBindingMismatch
    );
}

/// RFC 4120 6.2: an sname that differs from the service binding only in the
/// name-type identifies the same service and is accepted.
#[test]
fn service_name_type_is_not_significant() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let mut sname = service_name();
    sname.name_type = KRB_NT_UNKNOWN;
    let (_, body) = tgs_req_body(61, sname.clone());
    let req = ap_req(
        &tgt.parts.ticket,
        authenticator(&tgt.session, &AuthenticatorSpec::new(now(), 61, &body)),
    );
    let ctx = f
        .keyd
        .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, &now())
        .unwrap();
    let mut t = tgs_template(61);
    t.sname = sname.clone();
    let parts = f
        .keyd
        .issue_tgs_rep(&KDC, &SERVICE, &ctx.ctx_id, &t, &now())
        .unwrap();
    assert_eq!(parts.ticket.sname, sname);
}
