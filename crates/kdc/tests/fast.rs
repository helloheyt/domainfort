//! FAST in the KDC (docs/48 tasks T5, T6): the armored AS and TGS
//! exchanges, the mandatory-FAST gate (layer 1), the PDP's `armored` input
//! (layer 2), FastOptions, the cookie, and armored / unarmored errors —
//! through `Kdc::handle`, with the real keyd and the real PDP.
//!
//! The test plays the client from RFC 6113 only (tests/common): armor
//! AP-REQ, armor key, req-checksum, enc-fast-req, encrypted challenge,
//! implicit TGS armor; it opens every armored reply itself — KrbFastResponse,
//! strengthened reply keys, KrbFastFinished. RFC 6113 has no vectors for
//! these derivations, so these are round-trip and property tests (docs/48
//! §9.2 item 15). Each test names its source. All values hand-made.

mod common;

use common::*;
use kdc::{AccountKind, ArmorPolicy, AuditOutcome, AuditReason, Exchange, Transport};
use krb_proto::constants::{
    KDC_ERR_C_PRINCIPAL_UNKNOWN, KDC_ERR_POLICY, KDC_ERR_PREAUTH_EXPIRED, KDC_ERR_PREAUTH_FAILED,
    KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_S_PRINCIPAL_UNKNOWN, KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
    KRB_AP_ERR_BAD_INTEGRITY, KRB_AP_ERR_REPEAT, KRB_AP_ERR_SKEW, KRB_AP_ERR_TKT_EXPIRED,
    KRB_ERR_GENERIC, PA_ENCRYPTED_CHALLENGE, PA_ETYPE_INFO2, PA_FX_COOKIE, PA_FX_ERROR, PA_FX_FAST,
    PA_TGS_REQ,
};
use krb_proto::{
    AsReq, EncAsRepPart, KdcReq, KrbFastArmor, KrbFastReq, MethodData, PaData, TgsReq,
};
use pdp::{
    ActionClass, ActionMatch, AuthMatch, ContextMatch, Effect, Match, Obligation, ResourceMatch,
    RlKey, Rule, RuleId, SubjectMatch,
};

/// The first id of the mandatory-FAST rule set in these tests.
const FAST_RULES: RuleId = RuleId(100);

/// The policy of a deployment under P-10 interim: `pdp::mandatory_fast_rules`
/// for the bootstrap group, plus a broad grant (docs/48 §7.2: the explicit
/// Deny must win over it).
fn mandatory_fast_setup() -> Setup {
    let mut setup = Setup::new();
    setup.rules = pdp::mandatory_fast_rules(bootstrap_group(), FAST_RULES).unwrap();
    setup.rules.push(allow_kerberos());
    setup
}

/// The METHOD-DATA padata types of an unarmored KRB-ERROR's e-data.
fn method_types(error: &krb_proto::KrbError) -> Vec<i32> {
    MethodData::decode(error.e_data.as_deref().unwrap())
        .unwrap()
        .0
        .iter()
        .map(|p| p.padata_type)
        .collect()
}

/// The full armored flow (docs/48 §9.2; RFC 6113 5.4.1.1, 5.4.2, 5.4.3,
/// 5.4.6; P-10 interim) under `pdp::mandatory_fast_rules` plus a broad grant:
/// 1. the computer account, a member of the bootstrap group, gets its TGT
///    with an unarmored PA-ENC-TIMESTAMP AS (docs/48 §7.3);
/// 2. that TGT armors alice's AS, pre-authenticated with the encrypted
///    challenge; the client opens the reply under the strengthened reply key
///    — not under her key alone — and checks KrbFastFinished and the KDC's
///    challenge;
/// 3. alice's TGT is used in an armored TGS (implicit armor); the reply opens
///    under the reply key strengthened from the subkey, and the service ticket
///    under the service key.
///
/// Then "disabling FAST for a user is impossible without a policy change":
/// unarmored, alice gets only a FAST advertisement (layer 1); with her
/// account misreported as a bootstrap computer (layer 1 bypassed), the PDP's
/// explicit Deny still refuses (layer 2); a computer outside the bootstrap
/// group is refused by the PDP too; an unarmored TGS is refused by layer 1.
#[test]
fn full_armored_flow_with_mandatory_fast_rules() {
    let mut f = mandatory_fast_setup().build();

    // 1. The bootstrap.
    let mut boot = AsReqSpec::machine();
    boot.nonce = 0x0B00_7000;
    let bytes = sent(f.send(&boot.with_timestamp(&machine_key(AES256)).encode()));
    let machine = open_as_rep(&bytes, &machine_key(AES256));
    assert!(machine.rep.0.padata.is_none());
    assert_eq!(machine.rep.0.cname, machine_name());
    let event = &f.events()[0];
    assert_eq!(event.outcome, AuditOutcome::Issued);
    assert_eq!(event.armor.principal, None);
    assert!(!event.armor.reply_armored);

    // 2. alice's armored AS.
    let key = alice_key(AES256);
    let armor = f.armor_on(&machine, now());
    let spec = AsReqSpec::alice().with_challenge(&key);
    let bytes = sent(f.send(&spec.encode_armored(&armor, now())));
    let rep = krb_proto::AsRep::decode(&bytes).unwrap();
    assert!(
        krb_crypto::decrypt(&key, usage(3), &rep.0.enc_part.cipher).is_err(),
        "the reply key is strengthened (RFC 6113 5.4.3, 5.4.6)"
    );
    let alice = open_fast_as_rep(&bytes, &armor.key, &key);
    assert_eq!(alice.rep.0.cname, alice_name());
    assert_eq!(alice.part.0.nonce, spec.nonce);
    let ticket = open_ticket(&alice.rep.0.ticket, &krbtgt_key());
    assert_eq!(ticket.cname, alice_name());
    let event = &f.events()[1];
    assert_eq!(event.outcome, AuditOutcome::Issued);
    assert!(event
        .armor
        .principal
        .as_ref()
        .unwrap()
        .is(&realm(), &machine_name()));
    assert!(event.armor.reply_armored);

    // 3. The armored TGS.
    let tgs = TgsReqSpec::service();
    let (request, _) = tgs.encode(&alice);
    let (rep, part) = open_tgs_rep(&sent(f.send(&request)), &alice, &tgs);
    assert_eq!(rep.0.cname, alice_name());
    assert_eq!(part.0.sname, service_name());
    let service_ticket = open_ticket(&rep.0.ticket, &service_key());
    assert_eq!(service_ticket.cname, alice_name());
    assert_eq!(service_ticket.key.keyvalue, part.0.key.keyvalue);
    let event = &f.events()[2];
    assert_eq!(event.exchange, Some(Exchange::Tgs));
    assert!(event
        .armor
        .principal
        .as_ref()
        .unwrap()
        .is(&realm(), &alice_name()));
    assert!(event.armor.reply_armored);
    use keyd::Operation::*;
    assert_eq!(
        f.keyd_ops(),
        vec![
            VerifyPreauth,
            IssueAsRep,
            OpenFastArmor,
            VerifyPreauth,
            IssueAsRep,
            OpenAndVerifyTgt,
            IssueTgsRep
        ]
    );

    // Layer 1: unarmored, alice is only told to use FAST.
    let reply = f.send(&AsReqSpec::alice().with_timestamp(&key).encode());
    assert_eq!(
        method_types(&error_of(reply)),
        vec![PA_FX_FAST, PA_FX_COOKIE]
    );
    // Layer 2: alice misreported as a bootstrap computer by the account
    // source; keyd verifies her timestamp, the PDP's explicit Deny refuses.
    {
        let a = f.accounts().client_mut(&realm(), &alice_name()).unwrap();
        a.kind = AccountKind::Computer;
        a.armor_policy = ArmorPolicy::BootstrapAllowed;
    }
    let mut unarmored = AsReqSpec::alice().with_timestamp(&key);
    unarmored.nonce = 5;
    assert_eq!(code_of(f.send(&unarmored.encode())), KDC_ERR_POLICY);
    assert_eq!(
        f.events().last().unwrap().reason,
        AuditReason::PolicyDenied(pdp::ReasonCode::CoarseDeny(FAST_RULES))
    );
    // A computer outside the bootstrap group: refused by the PDP too.
    f.accounts()
        .client_mut(&realm(), &machine_name())
        .unwrap()
        .groups
        .clear();
    let mut outside = AsReqSpec::machine().with_timestamp(&machine_key(AES256));
    outside.nonce = 6;
    assert_eq!(code_of(f.send(&outside.encode())), KDC_ERR_POLICY);
    assert_eq!(
        f.events().last().unwrap().reason,
        AuditReason::PolicyDenied(pdp::ReasonCode::CoarseDeny(FAST_RULES))
    );
    // An unarmored TGS: layer 1.
    let mut tgs = TgsReqSpec::service();
    tgs.armored = false;
    tgs.cusec = 2;
    assert_eq!(code_of(f.send(&tgs.encode(&alice).0)), KDC_ERR_POLICY);
    assert_eq!(f.events().last().unwrap().reason, AuditReason::FastRequired);
}

/// docs/48 §7.2 layer 1, §9.2 item 4; RFC 6113 5.2, 5.4.2: an unarmored AS
/// for a principal that must use FAST — with or without a PA-ENC-TIMESTAMP —
/// gets KDC_ERR_PREAUTH_REQUIRED advertising ONLY PA-FX-FAST (empty) and
/// PA-FX-COOKIE; its padata is not looked at and keyd is never called.
#[test]
fn unarmored_user_as_advertises_only_fast_and_never_calls_keyd() {
    let mut f = Fixture::new();
    for spec in [
        AsReqSpec::alice(),
        AsReqSpec::alice().with_timestamp(&alice_key(AES256)),
    ] {
        let error = error_of(f.send(&spec.encode()));
        assert_eq!(error.error_code, KDC_ERR_PREAUTH_REQUIRED);
        let methods = MethodData::decode(error.e_data.as_deref().unwrap()).unwrap();
        assert_eq!(methods.0.len(), 2);
        assert_eq!(methods.0[0].padata_type, PA_FX_FAST);
        assert!(methods.0[0].padata_value.is_empty());
        assert_eq!(methods.0[1].padata_type, PA_FX_COOKIE);
        assert!(!methods.0[1].padata_value.is_empty());
    }
    assert!(f.keyd_records().is_empty(), "keyd is never called");
    for event in f.events() {
        assert_eq!(event.reason, AuditReason::FastRequired);
        assert_eq!(event.armor.principal, None);
    }
}

/// docs/48 §7.2 layer 1; Q-125 item 11: an unarmored TGS-REQ is
/// KDC_ERR_POLICY, unarmored, before keyd is asked.
#[test]
fn unarmored_tgs_is_policy() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let before = f.keyd_records().len();
    let mut spec = TgsReqSpec::service();
    spec.armored = false;
    let error = error_of(f.send(&spec.encode(&tgt).0));
    assert_eq!(error.error_code, KDC_ERR_POLICY);
    assert!(error.e_data.is_none());
    assert_eq!(f.keyd_records().len(), before, "keyd is not asked");
    assert_eq!(f.events().last().unwrap().reason, AuditReason::FastRequired);
}

/// docs/48 §7.3 (the bootstrap is "only TGT"): an unarmored AS of the
/// computer account for a service other than this realm's TGS is refused
/// (KDC_ERR_POLICY), before keyd.
#[test]
fn unarmored_computer_as_for_non_tgt_target_is_refused() {
    let mut f = Fixture::new();
    let mut spec = AsReqSpec::machine().with_timestamp(&machine_key(AES256));
    spec.sname = Some(service_name());
    assert_eq!(code_of(f.send(&spec.encode())), KDC_ERR_POLICY);
    assert_eq!(f.events()[0].reason, AuditReason::AsServerNotTgs);
    assert!(f.keyd_records().is_empty());
}

/// D126; docs/48 §3.1 (option (b)); Q-125 item 6: a user's TGT is no armor
/// ticket — the armor opens (keyd verifies it cryptographically), then the
/// KDC refuses the armor principal with an ARMORED KDC_ERR_POLICY, before any
/// pre-authentication.
#[test]
fn armor_from_a_user_tgt_is_refused() {
    let mut f = Fixture::new();
    let alice = obtain_tgt(&mut f);
    let armor = f.armor_on(&alice, now());
    let mut spec = AsReqSpec::alice();
    spec.cname = Some(bob_name());
    spec.challenge = None;
    let reply = f.send(&spec.encode_armored(&armor, now()));
    let error = open_fast_error(reply, &armor.key);
    assert_eq!(error.outer.error_code, KDC_ERR_POLICY);
    assert_eq!(f.events()[1].reason, AuditReason::ArmorNotComputer);
    assert_eq!(
        f.keyd_ops()[f.keyd_ops().len() - 2..],
        [
            keyd::Operation::OpenFastArmor,
            keyd::Operation::SealFastError
        ]
    );
}

/// D53; docs/48 §3.1 ("a machine that was removed stops armoring at once,
/// not when its TGT expires"); RFC 4120 3.3.3.1; Q-125 item 6: the armor
/// principal is re-read at use — disabled, locked, expired, revoked after
/// the armor TGT's authtime, or gone → ARMORED KDC_ERR_POLICY.
#[test]
fn armor_from_a_disabled_or_revoked_computer_is_refused() {
    for change in 0..5 {
        let mut f = Fixture::new();
        match change {
            4 => {
                f.accounts().remove_client(&realm(), &machine_name());
            }
            _ => {
                let m = f.accounts().client_mut(&realm(), &machine_name()).unwrap();
                match change {
                    0 => m.state.enabled = false,
                    1 => m.state.locked = true,
                    2 => m.state.expires = Some(now()),
                    _ => m.state.revoked_before = Some(at(1)),
                }
            }
        }
        let fast = f.send_fast(&AsReqSpec::alice().with_challenge(&alice_key(AES256)));
        let error = open_fast_error(fast.reply, &fast.armor_key);
        assert_eq!(error.outer.error_code, KDC_ERR_POLICY, "case {change}");
        let expected = if change == 4 {
            AuditReason::ArmorPrincipalUnknown
        } else {
            AuditReason::ArmorPrincipalRevoked
        };
        assert_eq!(f.events()[0].reason, expected, "case {change}");
        assert!(!f.keyd_ops().contains(&keyd::Operation::VerifyPreauth));
    }
}

/// A-25 (Q-033); RFC 6113 5.4.2 ("If the KDC does not support a critical
/// option, it MUST fail the request with
/// KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS"; "KDCs conforming to this
/// specification ignore unknown non-critical options"), 7.3 ("Bits 0-15 are
/// critical"); docs/48 §8 (hide-client-names refused): in the AS and the TGS,
/// bits 0, 1 (hide-client-names) and 15 → 93, armored (Q-125 item 7); bits 16
/// and 31 are ignored and the ticket is issued.
#[test]
fn fast_options_critical_bits_are_refused_others_ignored() {
    let mut f = Fixture::new();
    let key = alice_key(AES256);
    for bit in [0, 1, 15] {
        let mut spec = AsReqSpec::alice().with_challenge(&key);
        spec.fast_options = fast_options(&[bit]);
        let fast = f.send_fast(&spec);
        let error = open_fast_error(fast.reply, &fast.armor_key);
        assert_eq!(
            error.outer.error_code, KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
            "bit {bit}"
        );
        assert_eq!(
            f.events().last().unwrap().reason,
            AuditReason::UnknownCriticalFastOption
        );
    }
    let mut spec = AsReqSpec::alice().with_challenge(&key);
    spec.fast_options = fast_options(&[16, 31]);
    let fast = f.send_fast(&spec);
    let tgt = open_fast_as_rep(&sent(fast.reply), &fast.armor_key, &key);

    for (cusec, bit) in [(1, 0), (2, 1), (3, 15)] {
        let mut spec = TgsReqSpec::service();
        spec.cusec = cusec;
        spec.fast_options = fast_options(&[bit]);
        let reply = f.send(&spec.encode(&tgt).0);
        let error = open_fast_error(reply, &spec.armor_key(&tgt.session));
        assert_eq!(
            error.outer.error_code, KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
            "bit {bit}"
        );
    }
    let mut spec = TgsReqSpec::service();
    spec.cusec = 4;
    spec.fast_options = fast_options(&[16, 31]);
    let (request, _) = spec.encode(&tgt);
    open_tgs_rep(&sent(f.send(&request)), &tgt, &spec);
}

/// RFC 6113 5.4.6 ("The KDC confirms that the timestamp falls within its
/// current clock skew returning KRB_APP_ERR_SKEW if not" — RFC 4120 7.5.9's
/// KRB_AP_ERR_SKEW, Q-125 item 8); docs/48 R48-6, §6.3; A-26: an encrypted
/// challenge that decrypts but is out of skew is an ARMORED KRB_AP_ERR_SKEW
/// whose integrity-protected stime is the KDC's time, with the cookie; a
/// wrong key with a skewed timestamp never decrypts — PREAUTH_FAILED (no
/// oracle).
#[test]
fn skewed_challenge_is_armored_skew() {
    let mut f = Fixture::new();
    let mut spec = AsReqSpec::alice().with_challenge(&alice_key(AES256));
    spec.challenge_at = Some(at(-400));
    let fast = f.send_fast(&spec);
    let error = open_fast_error(fast.reply, &fast.armor_key);
    assert_eq!(error.outer.error_code, KRB_AP_ERR_SKEW);
    assert_eq!(error.inner.stime, now());
    assert_eq!(error.padata_types(), vec![PA_FX_COOKIE, PA_FX_ERROR]);
    assert_eq!(f.events()[0].reason, AuditReason::PreauthSkew);

    let mut spec = AsReqSpec::alice().with_challenge(&password_key(AES256, "wrong", ALICE_SALT));
    spec.challenge_at = Some(at(-400));
    let fast = f.send_fast(&spec);
    let error = open_fast_error(fast.reply, &fast.armor_key);
    assert_eq!(error.outer.error_code, KDC_ERR_PREAUTH_FAILED);
    assert_eq!(f.events()[1].reason, AuditReason::PreauthDenied);
}

/// An armored AS-REQ whose req-checksum covers `checksummed` instead of the
/// outer body that is sent (RFC 6113 5.4.2).
fn mismatched_checksum_request(spec: &AsReqSpec, armor: &Armor, checksummed: &[u8]) -> Vec<u8> {
    let fast_req = spec.fast_req(&armor.key, now());
    let armored = armored_req(
        &armor.key,
        Some(armor.armor_field()),
        checksummed,
        &fast_req,
    );
    AsReq(KdcReq {
        padata: Some(vec![fx_fast_padata(&armored)]),
        req_body: spec.body(),
    })
    .encode()
    .unwrap()
}

/// docs/48 §6.2 (what goes out unarmored: everything before the armor key
/// exists); RFC 6113 5.4.1, 5.4.2, 5.4.4; Q-125 items 1-5 (A-32); A-26:
/// - an undecodable PA-FX-FAST → KDC_ERR_PREAUTH_FAILED;
/// - two PA-FX-FAST → KRB_ERR_GENERIC;
/// - no armor ("MUST be present in AS-REQ") → KDC_ERR_PREAUTH_FAILED;
/// - an unknown armor type → KDC_ERR_PREAUTH_FAILED ("MUST respond with
///   KDC_ERR_PREAUTH_FAILED");
/// - a req-checksum over another body → KDC_ERR_PREAUTH_FAILED (keyd's
///   uniform `Denied`);
/// - an armor authenticator out of skew → KRB_AP_ERR_SKEW; a replayed armor
///   AP-REQ → KRB_AP_ERR_REPEAT; an expired armor TGT →
///   KRB_AP_ERR_TKT_EXPIRED (classes after keyd's chain completed);
///
/// all without e-data, none sealed, no armor principal in audit.
#[test]
fn errors_before_the_armor_are_unarmored() {
    let mut f = Fixture::new();
    let spec = AsReqSpec::alice().with_challenge(&alice_key(AES256));
    let outer_with = |padata: Vec<PaData>| {
        AsReq(KdcReq {
            padata: Some(padata),
            req_body: AsReqSpec::alice().body(),
        })
        .encode()
        .unwrap()
    };
    let garbage = PaData {
        padata_type: PA_FX_FAST,
        padata_value: vec![0x30, 0x00],
    };
    let armor = f.next_armor(now());
    let fast_req = spec.fast_req(&armor.key, now());
    let body_octets = spec.body().encode().unwrap();
    let valid = fx_fast_padata(&armored_req(
        &armor.key,
        Some(armor.armor_field()),
        &body_octets,
        &fast_req,
    ));
    let no_armor = fx_fast_padata(&armored_req(&armor.key, None, &body_octets, &fast_req));
    let other_type = fx_fast_padata(&armored_req(
        &armor.key,
        Some(KrbFastArmor {
            armor_type: 2,
            armor_value: armor.ap_req.encode().unwrap(),
        }),
        &body_octets,
        &fast_req,
    ));
    let cases: Vec<(Vec<u8>, i32, AuditReason)> = vec![
        (
            outer_with(vec![garbage]),
            KDC_ERR_PREAUTH_FAILED,
            AuditReason::FastMalformed,
        ),
        (
            outer_with(vec![valid.clone(), valid]),
            KRB_ERR_GENERIC,
            AuditReason::FastPadataAmbiguous,
        ),
        (
            outer_with(vec![no_armor]),
            KDC_ERR_PREAUTH_FAILED,
            AuditReason::FastArmorMissing,
        ),
        (
            outer_with(vec![other_type]),
            KDC_ERR_PREAUTH_FAILED,
            AuditReason::FastArmorTypeUnsupported,
        ),
    ];
    for (request, code, reason) in cases {
        let error = error_of(f.send(&request));
        assert_eq!(error.error_code, code);
        assert!(error.e_data.is_none());
        assert_eq!(f.events().last().unwrap().reason, reason);
    }
    assert!(f.keyd_records().is_empty(), "none of these reached keyd");

    // A req-checksum over another body.
    let armor = f.next_armor(now());
    let mut other = spec.body();
    other.nonce = 1;
    let request = mismatched_checksum_request(&spec, &armor, &other.encode().unwrap());
    let error = error_of(f.send(&request));
    assert_eq!(error.error_code, KDC_ERR_PREAUTH_FAILED);
    assert!(error.e_data.is_none());
    assert_eq!(f.events().last().unwrap().reason, AuditReason::ArmorDenied);

    // An armor authenticator 400 s in the past.
    f.armor_counter += 1;
    let skewed = Armor::new(&f.machine_tgt, at(-400), f.armor_counter);
    let error = error_of(f.send(&spec.encode_armored(&skewed, now())));
    assert_eq!(error.error_code, KRB_AP_ERR_SKEW);
    assert!(error.e_data.is_none());
    assert_eq!(f.events().last().unwrap().reason, AuditReason::ArmorSkew);

    // A replayed armor AP-REQ in another request.
    let armor = f.next_armor(now());
    let first = f.send(&AsReqSpec::alice().encode_armored(&armor, now()));
    assert_eq!(code_of(first), KDC_ERR_PREAUTH_REQUIRED);
    let mut second = AsReqSpec::alice();
    second.nonce = 9;
    let error = error_of(f.send(&second.encode_armored(&armor, now())));
    assert_eq!(error.error_code, KRB_AP_ERR_REPEAT);
    assert!(error.e_data.is_none());
    assert_eq!(f.events().last().unwrap().reason, AuditReason::ArmorReplay);

    // An expired armor TGT: the computer's TGT until 10:10, used at 10:15:01.
    let mut short = AsReqSpec::machine().with_timestamp(&machine_key(AES256));
    short.till = kt("20261113101000Z");
    short.nonce = 3;
    let machine = open_as_rep(&sent(f.send(&short.encode())), &machine_key(AES256));
    let armor = f.armor_on(&machine, at(901));
    let error = error_of(f.send_at(
        &spec.encode_armored(&armor, at(901)),
        Transport::Tcp,
        at(901),
    ));
    assert_eq!(error.error_code, KRB_AP_ERR_TKT_EXPIRED);
    assert_eq!(f.events().last().unwrap().reason, AuditReason::ArmorExpired);

    // Only the first request of the replay pair opened an armor and had its
    // PREAUTH_REQUIRED sealed; every refusal above is unarmored, with no armor
    // principal.
    let sealed = f
        .keyd_ops()
        .iter()
        .filter(|op| **op == keyd::Operation::SealFastError)
        .count();
    assert_eq!(sealed, 1);
    for event in f.events() {
        let refused_before_armor = !matches!(event.reason, AuditReason::PreauthRequired)
            && matches!(event.outcome, AuditOutcome::Refused { .. });
        if refused_before_armor {
            assert!(!event.armor.reply_armored, "{:?}", event.reason);
            assert_eq!(event.armor.principal, None, "{:?}", event.reason);
        }
    }
}

/// The marker principals of the recording policy.
fn armored_marker() -> dtyp::Sid {
    nt_sid(&[21, 7, 8, 9, 9001])
}
fn unarmored_marker() -> dtyp::Sid {
    nt_sid(&[21, 7, 8, 9, 9002])
}

/// An Allow rule for every Kerberos action whose `auth` is `auth`, with a
/// RateLimit obligation on `marker` — the test's rate limiter records it.
fn recording_rule(id: u32, auth: AuthMatch, marker: dtyp::Sid) -> Rule {
    Rule {
        id: RuleId(id),
        effect: Effect::Allow,
        when: Match {
            action: ActionMatch::Class(ActionClass::Kerberos),
            resource: ResourceMatch::Any,
            subject: SubjectMatch::Any,
            context: ContextMatch::ANY,
            auth,
        },
        obligations: vec![Obligation::RateLimit(RlKey {
            principal: marker,
            class: ActionClass::Kerberos,
        })],
    }
}

/// docs/48 §4.2 (R48-10: `armored = true` exactly when keyd verified the
/// armor and the inner request is the one processed); docs/11 P3; Q-130 item
/// 5: through a recording policy — one Allow per value of `armored`, each
/// leaving a marker with the rate limiter — the PDP sees `armored = false`
/// for the bootstrap, `true` for the armored AS and the armored TGS, and is
/// not asked at all when the armor or the challenge failed.
#[test]
fn pdp_sees_armored_exactly_when_armor_was_verified() {
    let mut setup = Setup::new();
    setup.rules = vec![
        recording_rule(1, AuthMatch::ARMORED, armored_marker()),
        recording_rule(2, AuthMatch::UNARMORED, unarmored_marker()),
    ];
    let mut f = setup.build();
    let marks = |f: &mut Fixture| -> Vec<bool> {
        f.kdc
            .rate_limiter_mut()
            .seen
            .iter()
            .filter_map(|k| {
                if k.principal == armored_marker() {
                    Some(true)
                } else if k.principal == unarmored_marker() {
                    Some(false)
                } else {
                    None
                }
            })
            .collect()
    };

    let mut boot = AsReqSpec::machine().with_timestamp(&machine_key(AES256));
    boot.nonce = 11;
    sent(f.send(&boot.encode()));
    assert_eq!(marks(&mut f), vec![false]);

    let tgt = obtain_tgt(&mut f);
    assert_eq!(marks(&mut f), vec![false, true]);

    let spec = TgsReqSpec::service();
    let (request, _) = spec.encode(&tgt);
    open_tgs_rep(&sent(f.send(&request)), &tgt, &spec);
    assert_eq!(marks(&mut f), vec![false, true, true]);

    // A wrong challenge, and an armor whose req-checksum fails: no decision.
    let wrong =
        f.send_fast(&AsReqSpec::alice().with_challenge(&password_key(AES256, "wrong", ALICE_SALT)));
    assert_eq!(code_of(wrong.reply), KDC_ERR_PREAUTH_FAILED);
    let armor = f.next_armor(now());
    let spec = AsReqSpec::alice().with_challenge(&alice_key(AES256));
    let request = mismatched_checksum_request(&spec, &armor, b"another body");
    assert_eq!(code_of(f.send(&request)), KDC_ERR_PREAUTH_FAILED);
    assert_eq!(marks(&mut f), vec![false, true, true]);
}

/// docs/48 §4.5, §9.2 item 5; RFC 6113 2.4 ("MAY ignore padata that are
/// inappropriate"): a PA-ENC-TIMESTAMP inside FAST is not verified — the
/// request gets the armored PREAUTH_REQUIRED that offers the encrypted
/// challenge, and keyd is not asked to verify anything.
#[test]
fn encrypted_timestamp_inside_fast_is_ignored() {
    let mut f = Fixture::new();
    let mut spec = AsReqSpec::alice();
    spec.inner_padata = vec![pa_enc_timestamp(&alice_key(AES256), now())];
    let fast = f.send_fast(&spec);
    let error = open_fast_error(fast.reply, &fast.armor_key);
    assert_eq!(error.outer.error_code, KDC_ERR_PREAUTH_REQUIRED);
    assert!(error.padata(PA_ENCRYPTED_CHALLENGE).is_some());
    assert!(!f.keyd_ops().contains(&keyd::Operation::VerifyPreauth));
}

/// RFC 6113 2.4 ("If a PA-FX-COOKIE ... is present, it is processed first"),
/// 5.2 ("The client MUST copy the exact cookie"; KDC_ERR_PREAUTH_EXPIRED);
/// docs/48 §6.4; docs/questions/Q-126 (a): the cookie the KDC sent, echoed in
/// the next request, is accepted; another value or two cookies →
/// KDC_ERR_PREAUTH_EXPIRED — armored inside FAST, unarmored in the bootstrap.
#[test]
fn cookie_is_processed_first() {
    let mut f = Fixture::new();
    let key = alice_key(AES256);
    let fast = f.send_fast(&AsReqSpec::alice());
    let required = open_fast_error(fast.reply, &fast.armor_key);
    let cookie = required.padata(PA_FX_COOKIE).unwrap().clone();

    let mut spec = AsReqSpec::alice().with_challenge(&key);
    spec.inner_padata = vec![cookie.clone()];
    let fast = f.send_fast(&spec);
    open_fast_as_rep(&sent(fast.reply), &fast.armor_key, &key);

    let wrong_cookie = PaData {
        padata_type: PA_FX_COOKIE,
        padata_value: b"not-this-kdc's-cookie".to_vec(),
    };
    for padata in [vec![wrong_cookie.clone()], vec![cookie.clone(), cookie]] {
        let mut spec = AsReqSpec::alice().with_challenge(&key);
        spec.inner_padata = padata;
        let fast = f.send_fast(&spec);
        let error = open_fast_error(fast.reply, &fast.armor_key);
        assert_eq!(error.outer.error_code, KDC_ERR_PREAUTH_EXPIRED);
        assert_eq!(
            f.events().last().unwrap().reason,
            AuditReason::CookieMismatch
        );
    }

    let mut boot = AsReqSpec::machine().with_timestamp(&machine_key(AES256));
    boot.nonce = 12;
    boot.padata.as_mut().unwrap().push(wrong_cookie);
    let error = error_of(f.send(&boot.encode()));
    assert_eq!(error.error_code, KDC_ERR_PREAUTH_EXPIRED);
    assert!(error.e_data.is_none());
}

/// RFC 6113 5.4.2 ("A conforming KDC ignores the outer KDC-REQ-BODY field";
/// "ignores the client principal name in the outer KDC-REQ-BODY field"),
/// 5.4.3 (nonce "from the client request"), 5.4.5 ("the KDC MUST ignore the
/// outer request body and any padata besides PA-FX-FAST"); docs/48 §4.1 A1,
/// A8, §8: the outer body names bob, another nonce, a service as target and
/// only RC4, and the outer padata carries a junk PA-ENC-TIMESTAMP — all
/// ignored: alice gets her TGT for the inner nonce. An inner refusal names
/// the inner client.
#[test]
fn only_the_inner_request_is_processed() {
    let mut f = Fixture::new();
    let key = alice_key(AES256);
    let mut spec = AsReqSpec::alice().with_challenge(&key);
    let mut outer = AsReqSpec::alice().body();
    outer.cname = Some(bob_name());
    outer.nonce = 1;
    outer.sname = Some(service_name());
    outer.etype = vec![RC4_HMAC];
    spec.outer = Some(outer.clone());
    spec.padata = Some(vec![PaData {
        padata_type: krb_proto::constants::PA_ENC_TIMESTAMP,
        padata_value: vec![0x30, 0x00],
    }]);
    let fast = f.send_fast(&spec);
    let tgt = open_fast_as_rep(&sent(fast.reply), &fast.armor_key, &key);
    assert_eq!(tgt.rep.0.cname, alice_name());
    assert_eq!(tgt.part.0.nonce, spec.nonce);
    assert_eq!(tgt.fast.as_ref().unwrap().nonce, spec.nonce);
    assert!(f.events()[0]
        .client
        .as_ref()
        .unwrap()
        .is(&realm(), &alice_name()));

    let mut spec = AsReqSpec::alice();
    spec.cname = Some(name(1, &["nobody"]));
    spec.outer = Some(outer);
    let fast = f.send_fast(&spec);
    let error = open_fast_error(fast.reply, &fast.armor_key);
    assert_eq!(error.outer.error_code, KDC_ERR_C_PRINCIPAL_UNKNOWN);
    assert_eq!(error.outer.cname, Some(name(1, &["nobody"])));
    assert!(f.events()[1]
        .client
        .as_ref()
        .unwrap()
        .is(&realm(), &name(1, &["nobody"])));
}

/// RFC 6113 5.4.2 (the KrbFastReq req-body "is preferred over the outer
/// field"), 5.4.4; docs/48 §5.2, §6.1; docs/questions/Q-150 item 5: the TGS
/// issues for the INNER sname and nonce while the outer body names an
/// unknown service; a refusal after keyd opened the armored context (an
/// unknown inner service) is ARMORED — it opens only with the implicit armor
/// key — and names the TGT's client and the inner sname.
#[test]
fn tgs_processes_the_inner_request() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let mut spec = TgsReqSpec::service();
    let mut outer = spec.body();
    outer.sname = Some(name(3, &["host", "nowhere.example.org"]));
    outer.nonce = 77;
    spec.outer = Some(outer);
    let (request, _) = spec.encode(&tgt);
    let (rep, part) = open_tgs_rep(&sent(f.send(&request)), &tgt, &spec);
    assert_eq!(rep.0.ticket.sname, service_name());
    assert_eq!(part.0.nonce, spec.nonce);

    let mut spec = TgsReqSpec::service();
    spec.cusec = 2;
    spec.sname = Some(name(3, &["host", "nowhere.example.org"]));
    let reply = f.send(&spec.encode(&tgt).0);
    let outer = error_of(reply.clone());
    let fx_fast = error_fx_fast(&outer);
    assert!(!fast_response_opens_with(&fx_fast, &tgt.session));
    assert!(!fast_response_opens_with(&fx_fast, &aes256(&TGS_SUBKEY)));
    let error = open_fast_error(reply, &spec.armor_key(&tgt.session));
    assert_eq!(error.outer.error_code, KDC_ERR_S_PRINCIPAL_UNKNOWN);
    assert_eq!(error.inner.cname, Some(alice_name()));
    assert_eq!(error.inner.sname, name(3, &["host", "nowhere.example.org"]));
    assert_eq!(error.response.nonce, spec.nonce);
    assert_eq!(error.padata_types(), vec![PA_FX_ERROR]);
    let event = f.events().last().unwrap();
    assert!(event.armor.reply_armored);
    assert!(event
        .armor
        .principal
        .as_ref()
        .unwrap()
        .is(&realm(), &alice_name()));
}

/// RFC 6113 5.4.1.1 ("This armor type is only valid for AS requests;
/// implicit armor ... is the only supported way to establish an armor key
/// for the TGS"); docs/questions/Q-124 item 2: an armored TGS-REQ with an
/// explicit armor field → KDC_ERR_PREAUTH_FAILED, unarmored, before keyd.
#[test]
fn tgs_explicit_armor_is_refused() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let before = f.keyd_records().len();
    let spec = TgsReqSpec::service();
    let body_octets = spec.body().encode().unwrap();
    let ap_req = krb_proto::ApReq {
        ap_options: krb_proto::ApOptions::empty(),
        ticket: tgt.rep.0.ticket.clone(),
        authenticator: authenticator(&tgt.session, &spec, &body_octets),
    };
    let ap_req_octets = ap_req.encode().unwrap();
    let fast_req = KrbFastReq {
        fast_options: krb_proto::FastOptions::empty(),
        padata: Vec::new(),
        req_body: spec.body(),
    };
    let explicit = f.next_armor(now());
    let armored = armored_req(
        &spec.armor_key(&tgt.session),
        Some(explicit.armor_field()),
        &ap_req_octets,
        &fast_req,
    );
    let request = TgsReq(KdcReq {
        padata: Some(vec![
            PaData {
                padata_type: PA_TGS_REQ,
                padata_value: ap_req_octets,
            },
            fx_fast_padata(&armored),
        ]),
        req_body: spec.body(),
    })
    .encode()
    .unwrap();
    let error = error_of(f.send(&request));
    assert_eq!(error.error_code, KDC_ERR_PREAUTH_FAILED);
    assert!(error.e_data.is_none());
    assert_eq!(
        f.events().last().unwrap().reason,
        AuditReason::TgsExplicitArmor
    );
    assert_eq!(f.keyd_records().len(), before);
}

/// RFC 6113 5.4.2 ("a subkey MUST be included in the PA-TGS-REQ
/// authenticator"); A-26: an armored TGS-REQ without a subkey is refused by
/// keyd before its chain completes → KRB_AP_ERR_BAD_INTEGRITY, unarmored.
#[test]
fn tgs_without_subkey_is_refused() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let mut spec = TgsReqSpec::service();
    spec.subkey = None;
    let error = error_of(f.send(&spec.encode(&tgt).0));
    assert_eq!(error.error_code, KRB_AP_ERR_BAD_INTEGRITY);
    assert!(error.e_data.is_none());
    assert_eq!(
        f.keyd_records().last().unwrap().reason,
        keyd::AuditReason::ArmorSubkeyMissing
    );
}

/// docs/questions/Q-125 item 10; docs/48 §6.2 item 3: when keyd cannot seal
/// an armored refusal (its conversation token is gone), the KDC sends the
/// same code unarmored rather than nothing — a PREAUTH_REQUIRED then carries
/// only the FAST advertisement and the cookie — and its audit event names
/// the armor principal with `reply_armored = false`.
#[test]
fn unsealable_refusal_goes_out_unarmored() {
    let mut f = Fixture::new();
    f.kdc.custody_mut().refuse_seal = true;
    let fast = f.send_fast(&AsReqSpec::alice());
    let error = error_of(fast.reply);
    assert_eq!(error.error_code, KDC_ERR_PREAUTH_REQUIRED);
    assert_eq!(method_types(&error), vec![PA_FX_FAST, PA_FX_COOKIE]);
    let event = &f.events()[0];
    assert!(event
        .armor
        .principal
        .as_ref()
        .unwrap()
        .is(&realm(), &machine_name()));
    assert!(!event.armor.reply_armored);

    let mut spec = AsReqSpec::alice();
    spec.etypes = vec![RC4_HMAC];
    let error = error_of(f.send_fast(&spec).reply);
    assert_eq!(error.error_code, krb_proto::constants::KDC_ERR_ETYPE_NOSUPP);
    assert!(error.e_data.is_none());
}

/// docs/48 §4.3 (the reply key is always strengthened), §9.2 items 3 and 6;
/// RFC 6113 5.4.3: the armored AS-REP's enc-part does not open under alice's
/// key alone; its KrbFastResponse does not open under her key or the armor
/// TGT's session key; strengthen-key and finished are present in the reply
/// (and absent in errors — checked by every `open_fast_error`).
#[test]
fn armored_reply_needs_the_armor_and_the_strengthen_key() {
    let mut f = Fixture::new();
    let key = alice_key(AES256);
    let fast = f.send_fast(&AsReqSpec::alice().with_challenge(&key));
    let bytes = sent(fast.reply);
    let rep = krb_proto::AsRep::decode(&bytes).unwrap();
    let fx_fast = &rep.0.padata.as_ref().unwrap()[0];
    assert!(!fast_response_opens_with(fx_fast, &key));
    assert!(!fast_response_opens_with(fx_fast, &f.machine_tgt.session));
    assert!(krb_crypto::decrypt(&key, usage(3), &rep.0.enc_part.cipher).is_err());
    let tgt = open_fast_as_rep(&bytes, &fast.armor_key, &key);
    let response = tgt.fast.as_ref().unwrap();
    assert!(response.strengthen_key.is_some());
    assert!(response.finished.is_some());
    // The enc-part opens under the strengthened key (and decodes).
    let strengthen = key_from(response.strengthen_key.as_ref().unwrap());
    let reply_key = strengthened(&strengthen, &key);
    EncAsRepPart::decode(&open(&reply_key, 3, &rep.0.enc_part)).unwrap();
}

/// The armored PREAUTH_FAILED / PREAUTH_REQUIRED carry PA-ETYPE-INFO2 for the
/// enctype keyd will use, also when that is not the client's first offer
/// (docs/questions/Q-123: the first of the inner etype list ∩ configured ∩
/// the client's keys) — here alice has only an aes128 key on record.
#[test]
fn single_etype_info2_entry_follows_the_account_keys() {
    let mut f = Fixture::new();
    f.accounts()
        .client_mut(&realm(), &alice_name())
        .unwrap()
        .etype_info
        .retain(|e| e.etype == AES128);
    let fast = f.send_fast(&AsReqSpec::alice());
    let error = open_fast_error(fast.reply, &fast.armor_key);
    let entries =
        krb_proto::EtypeInfo2::decode(&error.padata(PA_ETYPE_INFO2).unwrap().padata_value).unwrap();
    assert_eq!(entries.0.len(), 1);
    assert_eq!(entries.0[0].etype, AES128);
}
