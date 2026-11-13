//! The AS exchange through `Kdc::handle`.
//!
//! FAST is mandatory for alice, a user (docs/48 §7.1, P-10 interim), so her
//! requests are armored with the computer account's TGT (RFC 6113 5.4.1.1)
//! and pre-authenticated with the encrypted challenge (5.4.6); the request
//! shape steps run on the inner request (5.4.2). The PA-ENC-TIMESTAMP rules
//! are those of the unarmored bootstrap of the computer account ws1$
//! (docs/48 §7.3).
//!
//! Sources: RFC 4120 §2, 3.1.2, 3.1.3, 5.2.7.2-5.2.7.5, 5.4.1, 5.4.2, 5.9.1,
//! 7.5.9, 8.2; RFC 6113 2.1, 5.2, 5.4.2-5.4.6; RFC 3961 §8 (etype numbers used
//! as client offers); docs/48 §4, §7; docs/questions/Q-123; main-session
//! decisions 3-10 (named per test). All values hand-made.

mod common;

use common::*;
use kdc::{AuditOutcome, AuditReason, Exchange};
use krb_proto::constants::{
    KDC_ERR_BADOPTION, KDC_ERR_CANNOT_POSTDATE, KDC_ERR_CLIENT_REVOKED,
    KDC_ERR_C_PRINCIPAL_UNKNOWN, KDC_ERR_ETYPE_NOSUPP, KDC_ERR_NEVER_VALID, KDC_ERR_POLICY,
    KDC_ERR_PREAUTH_FAILED, KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_S_PRINCIPAL_UNKNOWN, KRB_ERR_GENERIC,
    KRB_NT_SRV_INST, PA_ENCRYPTED_CHALLENGE, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, PA_FX_COOKIE,
    PA_FX_ERROR, PA_FX_FAST,
};
use krb_proto::{EtypeInfo2, HostAddress, HostAddresses, MethodData, TicketFlags};
use pdp::{
    ActionMatch, AuthMatch, ContextMatch, Effect, Match, ResourceMatch, Rule, RuleId, SubjectMatch,
};

/// RFC 4120 3.1.3 + RFC 6113 5.4.4, 5.4.6: the armored PREAUTH_REQUIRED's
/// PA-ETYPE-INFO2 (inside the sealed KrbFastResponse), then an encrypted
/// challenge made from the advertised salt, gives a TGT. The client opens the
/// enc-part with the strengthened reply key (usage 3, RFC 6113 5.4.3),
/// checks nonce, names, flags and times; the ticket opens under krbtgt
/// (usage 2, RFC 4120 5.3).
#[test]
fn as_exchange_issues_tgt_using_advertised_salt() {
    let mut f = Fixture::new();
    let spec = AsReqSpec::alice();
    let first = f.send_fast(&spec);
    let error = open_fast_error(first.reply, &first.armor_key);
    assert_eq!(error.outer.error_code, KDC_ERR_PREAUTH_REQUIRED);
    let info = error.padata(PA_ETYPE_INFO2).unwrap();
    let entries = EtypeInfo2::decode(&info.padata_value).unwrap();
    let first_entry = &entries.0[0];
    let salt = first_entry.salt.as_ref().unwrap().as_str().to_owned();
    // The client derives its key from the password and the advertised salt.
    let key = password_key(first_entry.etype, ALICE_PASSWORD, &salt);

    let fast = f.send_fast(&spec.clone().with_challenge(&key));
    let tgt = open_fast_as_rep(&sent(fast.reply), &fast.armor_key, &key);
    assert_eq!(tgt.rep.0.crealm, realm());
    assert_eq!(tgt.rep.0.cname, alice_name());
    // RFC 6113 5.4.5: only PA-FX-FAST outside.
    let padata = tgt.rep.0.padata.as_ref().unwrap();
    assert_eq!(padata.len(), 1);
    assert_eq!(padata[0].padata_type, PA_FX_FAST);
    assert_eq!(tgt.rep.0.ticket.realm, realm());
    assert_eq!(tgt.rep.0.ticket.sname, krbtgt_name());
    let part = &tgt.part.0;
    assert_eq!(part.nonce, spec.nonce);
    assert_eq!(part.srealm, realm());
    assert_eq!(part.sname.name_type, KRB_NT_SRV_INST);
    assert_eq!(part.sname, krbtgt_name());
    assert_eq!(part.authtime, now());
    assert_eq!(part.starttime, None);
    assert_eq!(part.endtime, kt("20261113180000Z"));
    assert_eq!(part.renew_till, None);
    assert_eq!(part.key.keytype, AES256);
    assert!(part.flags.contains(TicketFlags::INITIAL));
    assert!(part.flags.contains(TicketFlags::PRE_AUTHENT));
    assert!(!part.flags.contains(TicketFlags::FORWARDABLE));
    let ticket = open_ticket(&tgt.rep.0.ticket, &krbtgt_key());
    assert_eq!(ticket.cname, alice_name());
    assert_eq!(ticket.crealm, realm());
    assert_eq!(ticket.flags, part.flags);
    assert_eq!(ticket.key.keyvalue, part.key.keyvalue);
    // Exactly one audit event per request (decision 14).
    let events = f.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].outcome, AuditOutcome::Issued);
    assert_eq!(events[1].exchange, Some(Exchange::As));
}

/// RFC 4120 3.1.3, 5.9.1, 5.2.7.5; RFC 6113 2.1, 5.2, 5.4.4, 5.4.6;
/// docs/48 §4.1 A9; docs/questions/Q-123: the armored PREAUTH_REQUIRED's
/// outer METHOD-DATA carries only PA-FX-FAST; its sealed KrbFastResponse
/// advertises PA-ENCRYPTED-CHALLENGE (empty) and carries PA-ETYPE-INFO2 with
/// ONE entry — the first acceptable enctype in the client's order, the key
/// keyd will use — and the PA-FX-COOKIE, then PA-FX-ERROR; never PA-ETYPE-INFO
/// (11) or PA-PW-SALT (3), RFC 4120 5.2.7.4, 5.2.7.3. keyd opened the armor
/// and sealed the error; no pre-authentication was attempted. Decision 5.
#[test]
fn preauth_required_carries_method_data_and_etype_info2() {
    let mut f = Fixture::new();
    for (offer, expected) in [
        (vec![AES256, AES128], AES256),
        (vec![AES128, AES256], AES128),
        (vec![RC4_HMAC, AES128], AES128),
    ] {
        let mut spec = AsReqSpec::alice();
        spec.etypes = offer;
        let fast = f.send_fast(&spec);
        let error = open_fast_error(fast.reply, &fast.armor_key);
        assert_eq!(error.outer.error_code, KDC_ERR_PREAUTH_REQUIRED);
        assert!(error.outer.e_text.is_none());
        assert_eq!(
            error.padata_types(),
            vec![
                PA_ENCRYPTED_CHALLENGE,
                PA_ETYPE_INFO2,
                PA_FX_COOKIE,
                PA_FX_ERROR
            ]
        );
        assert!(error
            .padata(PA_ENCRYPTED_CHALLENGE)
            .unwrap()
            .padata_value
            .is_empty());
        let entries =
            EtypeInfo2::decode(&error.padata(PA_ETYPE_INFO2).unwrap().padata_value).unwrap();
        assert_eq!(entries.0.len(), 1);
        assert_eq!(entries.0[0].etype, expected);
        assert_eq!(entries.0[0].salt.as_ref().unwrap().as_str(), ALICE_SALT);
        assert!(entries.0[0].s2kparams.is_none());
        assert!(!error.padata(PA_FX_COOKIE).unwrap().padata_value.is_empty());
        // The nonce of the INNER request (RFC 6113 5.4.3).
        assert_eq!(error.response.nonce, spec.nonce);
    }
    assert!(!f.keyd_ops().contains(&keyd::Operation::VerifyPreauth));
}

/// RFC 4120 3.1.3, 5.9.1, 5.2.7.5; RFC 6113 5.2, 5.4.2; docs/48 §7.3: the
/// UNARMORED PREAUTH_REQUIRED of the computer account (the bootstrap)
/// advertises PA-FX-FAST (empty — "KDCs MUST send the advertisement of
/// PA-FX-FAST with an empty pa-value"), PA-ENC-TIMESTAMP (empty), PA-ETYPE-INFO2
/// for the acceptable enctypes in the client's order, and the PA-FX-COOKIE
/// ("a KDC MUST include a cookie in a KDC_ERR_PREAUTH_REQUIRED").
#[test]
fn bootstrap_preauth_required_advertises_fast_timestamp_and_cookie() {
    let mut f = Fixture::new();
    for (offer, expected) in [
        (vec![AES256, AES128], vec![AES256, AES128]),
        (vec![AES128, AES256], vec![AES128, AES256]),
        (vec![RC4_HMAC, AES128], vec![AES128]),
    ] {
        let mut spec = AsReqSpec::machine();
        spec.etypes = offer;
        let error = error_of(f.send(&spec.encode()));
        assert_eq!(error.error_code, KDC_ERR_PREAUTH_REQUIRED);
        let methods = MethodData::decode(error.e_data.as_deref().unwrap()).unwrap();
        let types: Vec<i32> = methods.0.iter().map(|p| p.padata_type).collect();
        assert_eq!(
            types,
            vec![PA_FX_FAST, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, PA_FX_COOKIE]
        );
        assert!(methods.0[0].padata_value.is_empty());
        assert!(methods.0[1].padata_value.is_empty());
        let entries = EtypeInfo2::decode(&methods.0[2].padata_value).unwrap();
        let etypes: Vec<i32> = entries.0.iter().map(|e| e.etype).collect();
        assert_eq!(etypes, expected);
        assert!(!methods.0[3].padata_value.is_empty());
    }
    // keyd was never asked: no padata, nothing to verify.
    assert!(f.keyd_records().is_empty());
}

/// RFC 6113 5.4.6 ("If the decryption fails the KDC SHOULD return
/// KDC_ERR_PREAUTH_FAILED, including PA-ETYPE-INFO2 in the KRBFastResponse"),
/// 5.4.4; docs/48 §4.1 A10, §6.1: a challenge made with the wrong password
/// is an ARMORED PREAUTH_FAILED — its KrbFastResponse opens only with the
/// armor key (not with alice's key nor the armor TGT's session key) and
/// carries the single PA-ETYPE-INFO2 entry and the cookie. RFC 4120 3.1.3
/// for the unarmored bootstrap: a wrong key is PREAUTH_FAILED, unarmored.
#[test]
fn wrong_password_is_preauth_failed() {
    let mut f = Fixture::new();
    let wrong = password_key(AES256, "not-alices-password", ALICE_SALT);
    let fast = f.send_fast(&AsReqSpec::alice().with_challenge(&wrong));
    let outer = error_of(fast.reply.clone());
    let fx_fast = error_fx_fast(&outer);
    assert!(!fast_response_opens_with(&fx_fast, &alice_key(AES256)));
    assert!(!fast_response_opens_with(&fx_fast, &f.machine_tgt.session));
    let error = open_fast_error(fast.reply, &fast.armor_key);
    assert_eq!(error.outer.error_code, KDC_ERR_PREAUTH_FAILED);
    assert_eq!(
        error.padata_types(),
        vec![PA_ETYPE_INFO2, PA_FX_COOKIE, PA_FX_ERROR]
    );
    let entries = EtypeInfo2::decode(&error.padata(PA_ETYPE_INFO2).unwrap().padata_value).unwrap();
    assert_eq!(entries.0.len(), 1);
    assert_eq!(f.events()[0].reason, AuditReason::PreauthDenied);
    assert!(f.events()[0].armor.reply_armored);

    // The bootstrap path: a wrong machine key.
    let wrong_machine =
        krb_crypto::random_to_key(krb_crypto::EncType::Aes256CtsHmacSha196, &[0x99; 32]).unwrap();
    let mut spec = AsReqSpec::machine().with_timestamp(&wrong_machine);
    spec.nonce = 41;
    let error = error_of(f.send(&spec.encode()));
    assert_eq!(error.error_code, KDC_ERR_PREAUTH_FAILED);
    assert!(error.e_data.is_none());
    assert_eq!(f.events()[1].reason, AuditReason::PreauthDenied);
}

/// A-26 / RFC 4120 3.1.3, 5.2.7.2 (the unarmored bootstrap): with the correct
/// key but a timestamp outside the skew, keyd reports the Skew class (the
/// timestamp decrypted); RFC 4120 names no code for it other than
/// KDC_ERR_PREAUTH_FAILED, so the client sees the same code as for a wrong
/// key — the classes differ in audit only (PreauthSkew vs PreauthDenied). A
/// wrong key with a skewed timestamp never decrypts: PreauthDenied (no
/// oracle). (The ARMORED challenge out of skew is KRB_AP_ERR_SKEW: tests/fast.rs.)
#[test]
fn skewed_timestamp_is_preauth_failed_audited_apart() {
    let mut f = Fixture::new();
    let mut skewed = AsReqSpec::machine();
    skewed.nonce = 1;
    skewed.padata = Some(vec![pa_enc_timestamp(&machine_key(AES256), at(-400))]);
    let error = error_of(f.send(&skewed.encode()));
    assert_eq!(error.error_code, KDC_ERR_PREAUTH_FAILED);
    assert_eq!(error.stime, now());
    assert_eq!(f.events()[0].reason, AuditReason::PreauthSkew);

    let wrong =
        krb_crypto::random_to_key(krb_crypto::EncType::Aes256CtsHmacSha196, &[0x98; 32]).unwrap();
    let mut wrong_and_skewed = AsReqSpec::machine();
    wrong_and_skewed.nonce = 2;
    wrong_and_skewed.padata = Some(vec![pa_enc_timestamp(&wrong, at(-400))]);
    assert_eq!(
        code_of(f.send(&wrong_and_skewed.encode())),
        KDC_ERR_PREAUTH_FAILED
    );
    assert_eq!(f.events()[1].reason, AuditReason::PreauthDenied);
}

/// RFC 4120 3.1.3: an unknown client is KDC_ERR_C_PRINCIPAL_UNKNOWN
/// (decision 5; user enumeration is a documented residual) — armored, from
/// the inner request.
#[test]
fn unknown_client_is_c_principal_unknown() {
    let mut f = Fixture::new();
    let mut spec = AsReqSpec::alice();
    spec.cname = Some(name(1, &["mallory"]));
    let fast = f.send_fast(&spec);
    let error = open_fast_error(fast.reply, &fast.armor_key);
    assert_eq!(error.outer.error_code, KDC_ERR_C_PRINCIPAL_UNKNOWN);
    assert_eq!(error.outer.cname, Some(name(1, &["mallory"])));
    // Exact match only (decision 4): case is significant.
    spec.cname = Some(name(1, &["Alice"]));
    assert_eq!(
        code_of(f.send_fast(&spec).reply),
        KDC_ERR_C_PRINCIPAL_UNKNOWN
    );
    // Name-type is not (RFC 4120 6.2).
    spec.cname = Some(name(0, &["alice"]));
    assert_eq!(code_of(f.send_fast(&spec).reply), KDC_ERR_PREAUTH_REQUIRED);
    // Unarmored: the same code, before the FAST gate (R6 precedes it).
    spec.cname = Some(name(1, &["mallory"]));
    assert_eq!(code_of(f.send(&spec.encode())), KDC_ERR_C_PRINCIPAL_UNKNOWN);
}

/// Decision 6 / RFC 4120 3.1.3: a list of only non-AES etypes (RFC 3961 §8
/// numbers) is KDC_ERR_ETYPE_NOSUPP — there is no code path for them; keyd
/// is not asked to verify anything.
#[test]
fn rc4_des_only_list_is_etype_nosupp() {
    let mut f = Fixture::new();
    let mut spec = AsReqSpec::alice();
    spec.etypes = vec![RC4_HMAC, DES3_CBC_SHA1_KD, DES_CBC_MD5, DES_CBC_CRC];
    assert_eq!(code_of(f.send_fast(&spec).reply), KDC_ERR_ETYPE_NOSUPP);
    // Even with a valid AES challenge.
    let spec = spec.with_challenge(&alice_key(AES256));
    assert_eq!(code_of(f.send_fast(&spec).reply), KDC_ERR_ETYPE_NOSUPP);
    assert!(!f.keyd_ops().contains(&keyd::Operation::VerifyPreauth));
}

/// Decision 6 / RFC 4120 3.1.3 ("the KDC SHOULD use the first valid strong
/// etype for which an encryption key is available"): a mixed list picks the
/// client's first acceptable AES etype for the session key — and, armored,
/// that is also the long-term key of the challenge (Q-123), so the
/// (strengthened) reply key is aes128.
#[test]
fn mixed_list_picks_first_acceptable_aes() {
    let mut f = Fixture::new();
    let mut spec = AsReqSpec::alice();
    spec.etypes = vec![RC4_HMAC, AES128, DES_CBC_MD5, AES256];
    let key = alice_key(AES128);
    let fast = f.send_fast(&spec.with_challenge(&key));
    let tgt = open_fast_as_rep(&sent(fast.reply), &fast.armor_key, &key);
    assert_eq!(tgt.part.0.key.keytype, AES128);
    assert_eq!(tgt.rep.0.enc_part.etype, AES128);
}

/// RFC 4120 3.1.3 / 5.2.7.2 (the unarmored bootstrap): a PA-ENC-TIMESTAMP in
/// an enctype the client did not offer (or that is not acceptable) is
/// refused, before keyd; two timestamps are ambiguous.
#[test]
fn timestamp_in_unnegotiated_etype_is_preauth_failed() {
    let mut f = Fixture::new();
    let mut spec = AsReqSpec::machine();
    spec.etypes = vec![AES128];
    let reply = f.send(&spec.with_timestamp(&machine_key(AES256)).encode());
    assert_eq!(code_of(reply), KDC_ERR_PREAUTH_FAILED);
    assert_eq!(f.events()[0].reason, AuditReason::PreauthUnacceptable);
    assert!(f.keyd_records().is_empty());
    // Two timestamps are ambiguous.
    let mut spec = AsReqSpec::machine();
    spec.padata = Some(vec![
        pa_enc_timestamp(&machine_key(AES256), now()),
        pa_enc_timestamp(&machine_key(AES128), now()),
    ]);
    assert_eq!(code_of(f.send(&spec.encode())), KDC_ERR_PREAUTH_FAILED);
}

/// Decision 7 / docs/30 §2.4: a PDP Deny at AS is KDC_ERR_POLICY (armored),
/// decided after keyd verified the pre-authentication.
#[test]
fn pdp_deny_at_as_is_policy() {
    let mut setup = Setup::new();
    setup.rules.push(Rule {
        id: RuleId(9),
        effect: Effect::Deny,
        when: Match {
            action: ActionMatch::Exact(pdp::Action::KdcAs),
            resource: ResourceMatch::Any,
            subject: SubjectMatch::Principal(alice_sid()),
            context: ContextMatch::ANY,
            auth: AuthMatch::ANY,
        },
        obligations: Vec::new(),
    });
    let mut f = setup.build();
    let fast = f.send_fast(&AsReqSpec::alice().with_challenge(&alice_key(AES256)));
    let error = open_fast_error(fast.reply, &fast.armor_key);
    assert_eq!(error.outer.error_code, KDC_ERR_POLICY);
    assert_eq!(
        f.events()[0].reason,
        AuditReason::PolicyDenied(pdp::ReasonCode::CoarseDeny(RuleId(9)))
    );
    // verify_preauth ran (and succeeded); issue_as_rep never did.
    let records = f.keyd_records();
    let verify = records
        .iter()
        .find(|r| r.op == keyd::Operation::VerifyPreauth)
        .unwrap();
    assert_eq!(verify.result, keyd::AuditOutcome::Success);
    assert!(!f.keyd_ops().contains(&keyd::Operation::IssueAsRep));
}

/// Decision 7 / docs/11 §2, §8: a PDP Allow without a matching grant (no
/// rules) is a deny; a refused RateLimit obligation is a deny.
#[test]
fn pdp_no_grant_and_rate_limit_are_policy() {
    let mut setup = Setup::new();
    setup.rules.clear();
    let mut f = setup.build();
    let reply = f
        .send_fast(&AsReqSpec::alice().with_challenge(&alice_key(AES256)))
        .reply;
    assert_eq!(code_of(reply), KDC_ERR_POLICY);
    assert_eq!(
        f.events()[0].reason,
        AuditReason::PolicyDenied(pdp::ReasonCode::NoGrant)
    );

    let mut f = Fixture::new();
    f.kdc.rate_limiter_mut().refuse = true;
    let reply = f
        .send_fast(&AsReqSpec::alice().with_challenge(&alice_key(AES256)))
        .reply;
    assert_eq!(code_of(reply), KDC_ERR_POLICY);
    assert_eq!(f.events()[0].reason, AuditReason::RateLimited);
    let key = &f.kdc.rate_limiter_mut().seen[0];
    assert_eq!(key.principal, alice_sid());
}

/// Decision 8: a disabled, locked or expired client is
/// KDC_ERR_CLIENT_REVOKED — checked before pre-authentication, so keyd is
/// never asked to verify (no password oracle for a locked account).
#[test]
fn revoked_client_at_as() {
    for change in 0..3 {
        let mut f = Fixture::new();
        let account = f.accounts().client_mut(&realm(), &alice_name()).unwrap();
        match change {
            0 => account.state.enabled = false,
            1 => account.state.locked = true,
            _ => account.state.expires = Some(now()),
        }
        let reply = f
            .send_fast(&AsReqSpec::alice().with_challenge(&alice_key(AES256)))
            .reply;
        assert_eq!(code_of(reply), KDC_ERR_CLIENT_REVOKED, "case {change}");
        assert!(!f.keyd_ops().contains(&keyd::Operation::VerifyPreauth));
    }
}

/// RFC 4120 3.1.3: the endtime is capped by principal-specific limits — the
/// account's expiry.
#[test]
fn account_expiry_caps_endtime() {
    let mut f = Fixture::new();
    f.accounts()
        .client_mut(&realm(), &alice_name())
        .unwrap()
        .state
        .expires = Some(kt("20261113120000Z"));
    let tgt = obtain_tgt(&mut f);
    assert_eq!(tgt.part.0.endtime, kt("20261113120000Z"));
}

/// Decision 9 / RFC 4120 5.4.1: each operation option phase 1 lacks is
/// KDC_ERR_BADOPTION — FORWARDED (2), PROXY (4), ALLOW-POSTDATE (5),
/// POSTDATED (6), ENC-TKT-IN-SKEY (28), RENEW (30), VALIDATE (31) — decided
/// on the inner request, before any pre-authentication.
#[test]
fn operation_options_are_badoption_at_as() {
    for bit in [2, 4, 5, 6, 28, 30, 31] {
        let mut f = Fixture::new();
        let mut spec = AsReqSpec::alice();
        spec.options = options(&[bit]);
        let reply = f.send_fast(&spec.with_challenge(&alice_key(AES256))).reply;
        assert_eq!(code_of(reply), KDC_ERR_BADOPTION, "bit {bit}");
        assert_eq!(f.events()[0].reason, AuditReason::UnsupportedOption);
        assert!(!f.keyd_ops().contains(&keyd::Operation::VerifyPreauth));
    }
}

/// Decision 9 / RFC 4120 3.1.3 ("set if they have been requested and if the
/// policy of the local realm allows"): with the default policy (RFC 4120 §8.2
/// values, docs/30 §2.6 — no forwardable / proxiable) the flags are withheld
/// and the ticket is still issued; with a policy that allows them, granted.
#[test]
fn flag_options_follow_policy_at_as() {
    let mut spec = AsReqSpec::alice();
    spec.options = options(&[1, 3, 8]); // forwardable, proxiable, renewable
    spec.rtime = Some(kt("20261115100000Z"));

    let mut f = Fixture::new();
    let tgt = obtain_tgt_with(&mut f, spec.clone());
    let flags = tgt.part.0.flags;
    assert!(!flags.contains(TicketFlags::FORWARDABLE));
    assert!(!flags.contains(TicketFlags::PROXIABLE));
    assert!(flags.contains(TicketFlags::RENEWABLE));
    assert_eq!(tgt.part.0.renew_till, Some(kt("20261115100000Z")));

    let mut f = Setup::new()
        .ticket_policy(|p| {
            p.allowed_flags.insert(TicketFlags::FORWARDABLE);
            p.allowed_flags.insert(TicketFlags::PROXIABLE);
            p.allowed_flags.remove(TicketFlags::RENEWABLE);
        })
        .build();
    let tgt = obtain_tgt_with(&mut f, spec);
    let flags = tgt.part.0.flags;
    assert!(flags.contains(TicketFlags::FORWARDABLE));
    assert!(flags.contains(TicketFlags::PROXIABLE));
    assert!(!flags.contains(TicketFlags::RENEWABLE));
    assert_eq!(tgt.part.0.renew_till, None);
}

/// RFC 4120 2.9.1 / 3.1.3: RENEWABLE-OK with a requested life beyond the
/// maximum gives a renewable ticket with renew-till = the requested endtime.
#[test]
fn renewable_ok_when_requested_life_exceeds_maximum() {
    let mut f = Fixture::new();
    let mut spec = AsReqSpec::alice();
    spec.options = options(&[27]);
    spec.till = kt("20261116100000Z");
    let tgt = obtain_tgt_with(&mut f, spec);
    assert_eq!(tgt.part.0.endtime, kt("20261114100000Z"));
    assert!(tgt.part.0.flags.contains(TicketFlags::RENEWABLE));
    assert_eq!(tgt.part.0.renew_till, Some(kt("20261116100000Z")));
}

/// RFC 4120 §2: "KDCs MUST ignore KDC options that are not recognized" —
/// canonicalize (15), opt-hardware-auth (11), disable-transited-check (26) and
/// reserved bits do not refuse the request, and no canonicalisation happens
/// (decision 4): the reply names are the request names.
#[test]
fn unrecognized_options_are_ignored() {
    let mut f = Fixture::new();
    let mut spec = AsReqSpec::alice();
    spec.options = options(&[0, 9, 11, 15, 20, 26]);
    spec.sname = Some(krb_proto::PrincipalName {
        name_type: 1,
        ..krbtgt_name()
    });
    let tgt = obtain_tgt_with(&mut f, spec);
    assert_eq!(tgt.rep.0.cname, alice_name());
    // The TGS is named in its RFC 4120 7.3 form; name-type is not
    // significant (6.2).
    assert_eq!(tgt.part.0.sname, krbtgt_name());
}

/// RFC 4120 5.4.1 (till "19700101000000Z" = maximum endtime permitted) and
/// 3.1.3 (endtime = earlier of request and policy; NEVER_VALID below the
/// minimum; CANNOT_POSTDATE beyond the skew). Decision 10; §8.2 values.
#[test]
fn ticket_times_follow_rfc4120_3_1_3() {
    let mut f = Fixture::new();
    let mut spec = AsReqSpec::alice();
    spec.till = till_max();
    assert_eq!(
        obtain_tgt_with(&mut f, spec.clone()).part.0.endtime,
        kt("20261114100000Z")
    );
    spec.till = kt("20991231235959Z");
    assert_eq!(
        obtain_tgt_with(&mut f, spec.clone()).part.0.endtime,
        kt("20261114100000Z")
    );
    for till in [kt("20261113090000Z"), kt("20261113100200Z")] {
        spec.till = till;
        let reply = f
            .send_fast(&spec.clone().with_challenge(&alice_key(AES256)))
            .reply;
        assert_eq!(code_of(reply), KDC_ERR_NEVER_VALID);
    }
    spec.till = kt("20261113180000Z");
    spec.from = Some(at(301));
    let reply = f
        .send_fast(&spec.clone().with_challenge(&alice_key(AES256)))
        .reply;
    assert_eq!(code_of(reply), KDC_ERR_CANNOT_POSTDATE);
    spec.from = Some(at(-3600));
    assert_eq!(obtain_tgt_with(&mut f, spec).part.0.authtime, now());
}

/// Decision 4: single realm. Another client realm is
/// KDC_ERR_C_PRINCIPAL_UNKNOWN; another realm's TGS is
/// KDC_ERR_S_PRINCIPAL_UNKNOWN; a non-TGS service is KDC_ERR_POLICY (the AS
/// issues TGTs, docs/30 §2). docs/questions/Q-070.
#[test]
fn realm_and_server_rules_at_as() {
    let mut f = Fixture::new();
    let mut spec = AsReqSpec::alice();
    spec.realm = krb_proto::Realm::new("OTHER.ORG").unwrap();
    assert_eq!(
        code_of(f.send_fast(&spec).reply),
        KDC_ERR_C_PRINCIPAL_UNKNOWN
    );

    let mut spec = AsReqSpec::alice();
    spec.sname = Some(name(KRB_NT_SRV_INST, &["krbtgt", "OTHER.ORG"]));
    assert_eq!(
        code_of(f.send_fast(&spec).reply),
        KDC_ERR_S_PRINCIPAL_UNKNOWN
    );

    let mut spec = AsReqSpec::alice();
    spec.sname = Some(service_name());
    assert_eq!(code_of(f.send_fast(&spec).reply), KDC_ERR_POLICY);

    let mut spec = AsReqSpec::alice();
    spec.cname = None;
    assert_eq!(
        code_of(f.send_fast(&spec).reply),
        KDC_ERR_C_PRINCIPAL_UNKNOWN
    );
    let mut spec = AsReqSpec::alice();
    spec.sname = None;
    assert_eq!(
        code_of(f.send_fast(&spec).reply),
        KDC_ERR_S_PRINCIPAL_UNKNOWN
    );
}

/// RFC 4120 5.4.1 / docs/10 §5: requested addresses cannot be honoured
/// (addressless tickets only) → KDC_ERR_BADOPTION; an empty SEQUENCE OF is
/// absent (RFC 4120 5.1.3).
#[test]
fn addresses_are_badoption() {
    let mut f = Fixture::new();
    let mut spec = AsReqSpec::alice();
    spec.addresses = Some(HostAddresses(vec![HostAddress {
        addr_type: 2,
        address: vec![192, 0, 2, 1],
    }]));
    let reply = f
        .send_fast(&spec.clone().with_challenge(&alice_key(AES256)))
        .reply;
    assert_eq!(code_of(reply), KDC_ERR_BADOPTION);
    spec.addresses = Some(HostAddresses(Vec::new()));
    obtain_tgt_with(&mut f, spec);
}

/// Decision 3: an account-source failure fails closed (KRB_ERR_GENERIC, no
/// detail), before keyd is asked (unarmored: R6 runs before the FAST gate).
#[test]
fn account_source_failure_fails_closed() {
    let mut f = Fixture::new();
    f.accounts().set_unavailable(true);
    let reply = f.send(&AsReqSpec::alice().encode());
    let error = error_of(reply);
    assert_eq!(error.error_code, KRB_ERR_GENERIC);
    assert!(error.e_text.is_none());
    assert_eq!(f.events()[0].reason, AuditReason::AccountSourceFailure);
    assert!(f.keyd_records().is_empty());
}
