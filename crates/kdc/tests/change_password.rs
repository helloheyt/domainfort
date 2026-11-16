//! The change-password service's ticket in the KDC (task K5): the AS for
//! `kadmin/changepw` — armored only, users only, under the ticket profile —
//! and the TGS that refuses the name, through `Kdc::handle` with the real
//! keyd and the real PDP.
//!
//! Sources (named per test): RFC 3244 §2 (the service principal
//! `kadmin/changepw@REALM`; a password-changing service may require
//! INITIAL); RFC 4120 2.1 (INITIAL: "issued using the AS protocol, rather
//! than issued based on a TGT"), 3.1.3 (the server principal's maximum
//! lifetime; flags "if they have been requested and if the policy of the
//! local realm allows"; the session-key type and "acceptable encryption
//! methods for the application server"; KDC_ERR_NEVER_VALID below the site
//! minimum), 6.2 (the name-type is not significant), §8.2 (5-minute minimum
//! lifetime); RFC 6113 Abstract and 5.4 (FAST "eliminate[s] offline
//! dictionary attacks"), 5.2 / 5.4.2 (PA-FX-FAST advertised empty);
//! [MS-KILE] 3.3.5.1.2 (no canonicalisation of `kadmin/changepw`); docs/53
//! R53-1, R53-6, §5.2, §10 (the attack list); docs/48 §7.2; A-117, A-139,
//! A-142 (no FAST exception for the AS to `kadmin/changepw`, ever);
//! docs/research/r3-e R3E-2; task K3b (docs/questions/Q-915: keyd issues the
//! ticket only armored and enforces the profile itself). All values
//! hand-made; no vector or fixture from any other implementation.
//!
//! The KDC's half of the contract — the server key set, the armor and the
//! template it hands keyd — is recorded by the test custody
//! (`issue_as_rep_calls`); keyd's half (task K3b) is checked on the ticket
//! itself, opened by the client (the strengthened reply key) and by the
//! service (its key, usage 2).

mod common;

use common::*;
use kdc::{AccountKind, AuditOutcome, AuditReason};
use keyd::KeyPurpose;
use krb_proto::constants::{
    KDC_ERR_NEVER_VALID, KDC_ERR_POLICY, KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_SERVICE_REVOKED,
    KDC_ERR_S_PRINCIPAL_UNKNOWN, KRB_AP_ERR_BAD_INTEGRITY, KRB_AP_ERR_NOT_US, KRB_ERR_GENERIC,
    KRB_NT_PRINCIPAL, KRB_NT_SRV_INST, PA_FX_COOKIE, PA_FX_FAST,
};
use krb_proto::{MethodData, TicketFlags};
use pdp::{
    ActionClass, ActionMatch, AuthMatch, ContextMatch, Effect, KerbResKind, Match, Obligation,
    ReasonCode, ResourceMatch, RlKey, Rule, RuleId, SubjectMatch,
};

/// The first id of the deployment's default Kerberos rules in these tests.
const FAST_RULES: u32 = 100;
/// The change-password service's AS rules follow the mandatory-FAST set.
const CHANGE_PASSWORD_RULES: u32 = FAST_RULES + pdp::MANDATORY_FAST_RULE_COUNT;

/// The policy of a deployment (policy-store's snapshot order): the
/// mandatory-FAST set and the change-password set for the bootstrap group,
/// then a broad grant — the explicit Denies must win over it (docs/48 §7.2).
fn deployment_setup() -> Setup {
    let mut setup = Setup::new();
    setup.rules = pdp::mandatory_fast_rules(bootstrap_group(), RuleId(FAST_RULES)).unwrap();
    setup.rules.extend(
        pdp::change_password_as_rules(bootstrap_group(), RuleId(CHANGE_PASSWORD_RULES)).unwrap(),
    );
    setup.rules.push(allow_kerberos());
    setup
}

/// alice asks for a ticket to `kadmin/changepw` (8 hours asked).
fn alice_for_change_password() -> AsReqSpec {
    AsReqSpec {
        sname: Some(change_password_name()),
        ..AsReqSpec::alice()
    }
}

/// The flags of every change-password ticket: INITIAL and PRE-AUTHENT, set
/// by keyd, and nothing else (RFC 4120 2.1; docs/53 §5.2).
fn profile_flags() -> TicketFlags {
    TicketFlags::INITIAL.union(TicketFlags::PRE_AUTHENT)
}

/// The change-password service's key (aes256, the first configured
/// enctype — the ticket is sealed under the service key's preferred type,
/// RFC 4120 3.1.3).
fn change_password_key() -> krb_crypto::ProtocolKey {
    aes256(&CHANGEPW_KEY)
}

/// alice's change-password ticket through the KDC, opened by her (the
/// armored AS-REP, RFC 6113 5.4.3).
fn obtain_change_password_ticket(f: &mut Fixture, spec: AsReqSpec) -> Tgt {
    let key = alice_key(AES256);
    let fast = f.send_fast(&spec.with_challenge(&key));
    open_fast_as_rep(&sent(fast.reply), &fast.armor_key, &key)
}

/// The METHOD-DATA padata types of an unarmored KRB-ERROR's e-data, each
/// with whether its value is empty.
fn methods(error: &krb_proto::KrbError) -> Vec<(i32, bool)> {
    MethodData::decode(error.e_data.as_deref().unwrap())
        .unwrap()
        .0
        .iter()
        .map(|p| (p.padata_type, p.padata_value.is_empty()))
        .collect()
}

// ---------------------------------------------------- unarmored AS ----

/// A-142 (the AS to `kadmin/changepw` is never unarmored — R3E-2: an
/// unarmored AS would let a passive observer guess the old password offline
/// and read the new one); docs/53 §5.2 ("refused for every principal"),
/// §10 ("unarmored AS to changepw ⇒ PREAUTH_REQUIRED without keyd"); RFC
/// 6113 5.2, 5.4.2; docs/48 §7.2 layer 1: an unarmored AS for the
/// change-password service — by a user with or without PA-ENC-TIMESTAMP, by
/// the computer that may bootstrap its own TGT unarmored, by an unknown
/// client, under either name-type (RFC 4120 6.2) — gets the FAST-only
/// KDC_ERR_PREAUTH_REQUIRED, even under an allow-everything policy; keyd is
/// never called and no account is looked at (the unknown client gets the
/// same answer).
#[test]
fn unarmored_as_for_change_password_is_fast_required_for_every_client() {
    let mut f = Fixture::new(); // the policy allows every Kerberos request
    let unknown = name(KRB_NT_PRINCIPAL, &["nobody"]);
    let mut requests = Vec::new();
    for name_type in [KRB_NT_SRV_INST, KRB_NT_PRINCIPAL] {
        let sname = Some(name(name_type, &["kadmin", "changepw"]));
        requests.push(AsReqSpec {
            sname: sname.clone(),
            ..AsReqSpec::alice()
        });
        requests.push(
            AsReqSpec {
                sname: sname.clone(),
                ..AsReqSpec::alice()
            }
            .with_timestamp(&alice_key(AES256)),
        );
        requests.push(
            AsReqSpec {
                sname: sname.clone(),
                ..AsReqSpec::machine()
            }
            .with_timestamp(&machine_key(AES256)),
        );
        requests.push(AsReqSpec {
            sname,
            ..AsReqSpec::for_client(realm(), unknown.clone())
        });
    }
    for spec in &requests {
        let error = error_of(f.send(&spec.encode()));
        assert_eq!(error.error_code, KDC_ERR_PREAUTH_REQUIRED);
        assert_eq!(
            methods(&error),
            vec![(PA_FX_FAST, true), (PA_FX_COOKIE, false)]
        );
    }
    assert!(f.keyd_records().is_empty(), "keyd is never called");
    assert_eq!(f.events().len(), requests.len());
    for event in f.events() {
        assert_eq!(event.reason, AuditReason::FastRequired);
        assert_eq!(event.armor.principal, None);
        assert!(!event.armor.reply_armored);
    }
    // The same computer still bootstraps its TGT unarmored (docs/48 §7.3):
    // only the server differs.
    let mut boot = AsReqSpec::machine().with_timestamp(&machine_key(AES256));
    boot.nonce = 12;
    let tgt = open_as_rep(&sent(f.send(&boot.encode())), &machine_key(AES256));
    assert_eq!(tgt.rep.0.ticket.sname, krbtgt_name());
}

// ------------------------------------------------------ armored AS ----

/// The full round trip (task K3b). docs/53 §5.2 (the ticket only from an
/// armored AS; keyd `issue_as_rep` with the ChangePasswordService key set;
/// INITIAL and PRE-AUTHENT set by keyd; lifetime ≤ 300 s; no renewable /
/// forwardable / proxiable); RFC 4120 2.1 (INITIAL), 3.1.3 (the server
/// principal's maximum lifetime; the session-key type from the client's
/// list and the service's; the ticket sealed under "the encryption key
/// extracted from the server principal's record"), 3.1.5 (the client checks
/// sname / srealm and the nonce), 5.3 (usage 2); RFC 6113 5.4.3 (the
/// strengthened reply key, KrbFastFinished); RFC 3244 §2 (the service
/// principal `kadmin/changepw@REALM`); docs/53 §5.2 and U7 (the requested
/// sname, never canonicalised); A-117; Q-915: alice's armored AS for
/// `kadmin/changepw`, asking 8 hours, passes the PDP of a deployment and
/// reaches keyd's `issue_as_rep` exactly once — armored, server = the
/// change-password key set, template sname = the requested name, starting
/// now, ending at now + 300 s, no flag requested, no renew-till, aes256 —
/// after keyd verified her encrypted challenge; keyd issues: the AS-REP
/// opens under her strengthened reply key, names `kadmin/changepw` in this
/// realm, ends at now + 300 s with exactly INITIAL | PRE-AUTHENT; the
/// ticket opens under the change-password service key (not under krbtgt)
/// with the same facts and session key; both audits record the issuance —
/// keyd's with the ChangePasswordService key set as the server.
#[test]
fn armored_user_as_hands_keyd_the_profile() {
    let mut f = deployment_setup().build();
    let spec = alice_for_change_password().with_challenge(&alice_key(AES256));
    let fast = f.send_fast(&spec);

    let calls = f.issue_as_rep_calls().to_vec();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.client, ALICE);
    assert_eq!(call.server, CHANGEPW);
    assert!(call.armored);
    let t = &call.template;
    assert_eq!(t.crealm, realm());
    assert_eq!(t.cname, alice_name());
    assert_eq!(t.sname, change_password_name());
    assert_eq!(t.starttime, None);
    assert_eq!(t.endtime, at(300));
    assert_eq!(t.renew_till, None);
    assert_eq!(t.flags, TicketFlags::empty());
    assert_eq!(t.session_enctype.number(), AES256);
    assert_eq!(t.nonce, spec.nonce);
    // Task PN11 (docs/59 §7.2, §7.5): the KDC forwards both records'
    // resolutions as dird sent them — alice's, and the change-password
    // service's, which keyd binds that key set by.
    assert_eq!(call.client_resolution.name_as_sent(), &alice_name());
    assert_eq!(call.client_resolution.principal(), ALICE.principal);
    let server = call.server_resolution.as_ref().expect("the service's");
    assert_eq!(server.canonical_name(), &change_password_name());
    assert_eq!(server.key_purpose(), KeyPurpose::ChangePasswordService);
    assert_eq!(
        f.keyd_ops()[..3],
        [
            keyd::Operation::OpenFastArmor,
            keyd::Operation::VerifyPreauth,
            keyd::Operation::IssueAsRep,
        ]
    );

    // keyd's half (task K3b): the reply, as alice opens it.
    let issued = open_fast_as_rep(&sent(fast.reply), &fast.armor_key, &alice_key(AES256));
    let rep = &issued.rep.0;
    assert_eq!(rep.crealm, realm());
    assert_eq!(rep.cname, alice_name());
    assert_eq!(rep.ticket.realm, realm());
    assert_eq!(rep.ticket.sname, change_password_name());
    let part = &issued.part.0;
    assert_eq!(part.nonce, spec.nonce);
    assert_eq!(part.srealm, realm());
    assert_eq!(part.sname, change_password_name());
    assert_eq!(part.flags, profile_flags());
    assert_eq!(part.authtime, now());
    assert_eq!(part.starttime, None);
    assert_eq!(part.endtime, at(300));
    assert_eq!(part.renew_till, None);
    assert_eq!(part.key.keytype, AES256);

    // The ticket, as the service opens it: under its own key, never krbtgt.
    assert_eq!(rep.ticket.enc_part.etype, AES256);
    let ticket = open_ticket(&rep.ticket, &change_password_key());
    assert_eq!(ticket.flags, profile_flags());
    assert_eq!(ticket.crealm, realm());
    assert_eq!(ticket.cname, alice_name());
    assert_eq!(ticket.authtime, now());
    assert_eq!(ticket.starttime, None);
    assert_eq!(ticket.endtime, at(300));
    assert_eq!(ticket.renew_till, None);
    assert_eq!(ticket.caddr, None);
    assert_eq!(ticket.key.keyvalue, part.key.keyvalue);
    assert!(krb_crypto::decrypt(&krbtgt_key(), usage(2), &rep.ticket.enc_part.cipher).is_err());

    // One audit event each.
    assert_eq!(f.events().len(), 1);
    assert_eq!(f.events()[0].outcome, AuditOutcome::Issued);
    assert!(f.events()[0].armor.reply_armored);
    let issue = f
        .keyd_records()
        .iter()
        .find(|r| r.op == keyd::Operation::IssueAsRep)
        .expect("keyd's issue record");
    assert_eq!(issue.result, keyd::AuditOutcome::Success);
    assert_eq!(issue.principal, Some(ALICE.principal));
    let server = issue.secondary.expect("the server key set");
    assert_eq!(server.principal, CHANGEPW.principal);
    assert_eq!(server.purpose, KeyPurpose::ChangePasswordService);
}

/// RFC 4120 6.2 (the name-type is a hint) and [MS-KILE] 3.3.5.1.2 (no
/// canonicalisation): under NT-PRINCIPAL the name is the same service and
/// the template keeps the name as asked; a case variant or a third
/// component is an ordinary service — not the change-password service —
/// and the AS refuses it as any non-TGS service (KDC_ERR_POLICY,
/// `AsServerNotTgs`), armored, before pre-authentication (A-139: one name
/// rule, no second matching path).
#[test]
fn only_the_exact_name_is_the_change_password_service() {
    let mut f = deployment_setup().build();
    let as_principal = name(KRB_NT_PRINCIPAL, &["kadmin", "changepw"]);
    let spec = AsReqSpec {
        sname: Some(as_principal.clone()),
        ..AsReqSpec::alice()
    }
    .with_challenge(&alice_key(AES256));
    let _ = f.send_fast(&spec);
    assert_eq!(f.issue_as_rep_calls()[0].template.sname, as_principal);
    assert_eq!(f.issue_as_rep_calls()[0].server, CHANGEPW);

    for parts in [
        &["KADMIN", "changepw"][..],
        &["kadmin", "changepw", "x"],
        &["kadmin/changepw"],
    ] {
        let mut f = deployment_setup().build();
        let spec = AsReqSpec {
            sname: Some(name(KRB_NT_SRV_INST, parts)),
            ..AsReqSpec::alice()
        }
        .with_challenge(&alice_key(AES256));
        let fast = f.send_fast(&spec);
        let error = open_fast_error(fast.reply, &fast.armor_key);
        assert_eq!(error.outer.error_code, KDC_ERR_POLICY, "{parts:?}");
        assert_eq!(f.events()[0].reason, AuditReason::AsServerNotTgs);
        assert!(f.issue_as_rep_calls().is_empty());
        assert!(!f.keyd_ops().contains(&keyd::Operation::VerifyPreauth));
    }
}

/// docs/53 §5.2 (lifetime ≤ 300 s; no renewable, forwardable, proxiable);
/// RFC 4120 3.1.3 (the endtime is the earliest of the requested one, the
/// server principal's maximum and the principal-specific limits; the flags
/// only "if the policy of the local realm allows" — the service's profile
/// does not; below the site minimum → KDC_ERR_NEVER_VALID), 5.4.1 (till
/// 19700101000000Z = the maximum the policy permits), §8.2 (5-minute
/// minimum): with a realm policy that allows forwardable, proxiable and
/// renewable tickets and the client asking for all of them and for the
/// maximum life, the template still ends at now + 300 s with no flag and no
/// renew-till — and the ticket keyd issues for it (task K3b) is INITIAL |
/// PRE-AUTHENT only, ending at now + 300 s; asking 10 or exactly 5 minutes
/// → now + 300 s; asking 2 minutes is below the realm's 5-minute minimum →
/// KDC_ERR_NEVER_VALID, keyd not asked to issue. With a 1-minute realm
/// minimum, 2 minutes asked → now + 120 s, and an account expiring at
/// now + 200 s caps it there.
#[test]
fn lifetime_and_flags_follow_the_profile() {
    let generous = |min: u32| {
        deployment_setup().ticket_policy(move |p| {
            p.allowed_flags = p
                .allowed_flags
                .union(TicketFlags::FORWARDABLE)
                .union(TicketFlags::PROXIABLE)
                .union(TicketFlags::RENEWABLE);
            p.min_lifetime_secs = min;
        })
    };
    let issued = |f: &mut Fixture, spec: AsReqSpec| {
        let before = f.issue_as_rep_calls().len();
        let fast = f.send_fast(&spec.with_challenge(&alice_key(AES256)));
        let calls = f.issue_as_rep_calls();
        (fast, calls.get(before).map(|c| c.template.clone()))
    };

    let mut f = generous(300).build();
    let all = AsReqSpec {
        options: options(&[1, 3, 8, 27]), // forwardable, proxiable, renewable, renewable-ok
        till: till_max(),
        rtime: Some(kt("20261120100000Z")),
        ..alice_for_change_password()
    };
    let (fast, template) = issued(&mut f, all);
    let template = template.expect("keyd asked");
    assert_eq!(template.endtime, at(300));
    assert_eq!(template.flags, TicketFlags::empty());
    assert_eq!(template.renew_till, None);
    // ... and the ticket keyd issued (task K3b): capped at now + 300 s, the
    // asked-for flags dropped, only INITIAL | PRE-AUTHENT.
    let key = alice_key(AES256);
    let opened = open_fast_as_rep(&sent(fast.reply), &fast.armor_key, &key);
    let ticket = open_ticket(&opened.rep.0.ticket, &change_password_key());
    assert_eq!(ticket.flags, profile_flags());
    assert_eq!(ticket.endtime, at(300));
    assert_eq!(ticket.renew_till, None);
    assert_eq!(opened.part.0.flags, profile_flags());
    for till in [at(600), at(300)] {
        let (_, template) = issued(
            &mut f,
            AsReqSpec {
                till,
                nonce: 77,
                ..alice_for_change_password()
            },
        );
        assert_eq!(template.expect("keyd asked").endtime, at(300));
    }
    let (fast, template) = issued(
        &mut f,
        AsReqSpec {
            till: at(120),
            nonce: 78,
            ..alice_for_change_password()
        },
    );
    assert!(template.is_none(), "keyd not asked to issue");
    let error = open_fast_error(fast.reply, &fast.armor_key);
    assert_eq!(error.outer.error_code, KDC_ERR_NEVER_VALID);

    let mut f = generous(60).build();
    let short = AsReqSpec {
        till: at(120),
        ..alice_for_change_password()
    };
    let (_, template) = issued(&mut f, short.clone());
    assert_eq!(template.expect("keyd asked").endtime, at(120));
    f.accounts()
        .client_mut(&realm(), &alice_name())
        .unwrap()
        .state
        .expires = Some(at(200));
    let (_, template) = issued(
        &mut f,
        AsReqSpec {
            till: till_max(),
            nonce: 79,
            ..short
        },
    );
    assert_eq!(template.expect("keyd asked").endtime, at(200));
}

// --------------------------------------------------- users only ----

/// docs/53 R53-1 ("users only — a computer account is refused"), §5.2; A-117:
/// the computer account's armored AS for `kadmin/changepw` (its own TGT as
/// the armor, its key for the challenge) is refused with an ARMORED
/// KDC_ERR_POLICY before pre-authentication — keyd opens the armor and seals
/// the error, nothing else.
#[test]
fn a_computer_is_refused_before_preauthentication() {
    let mut f = deployment_setup().build();
    let spec = AsReqSpec {
        sname: Some(change_password_name()),
        ..AsReqSpec::machine()
    }
    .with_challenge(&machine_key(AES256));
    let fast = f.send_fast(&spec);
    let error = open_fast_error(fast.reply, &fast.armor_key);
    assert_eq!(error.outer.error_code, KDC_ERR_POLICY);
    assert_eq!(f.events()[0].reason, AuditReason::ChangePasswordNotUser);
    assert_eq!(
        f.keyd_ops(),
        vec![
            keyd::Operation::OpenFastArmor,
            keyd::Operation::SealFastError
        ]
    );
    assert!(f.issue_as_rep_calls().is_empty());
}

/// docs/53 §5.2 ("users only (a data rule)"); docs/48 §7.2 (two layers; a
/// mismatch can only refuse more): with alice's account misreported as a
/// user that is a member of the computer group, the KDC's layer passes and
/// the PDP's explicit Deny (the change-password set's second rule) refuses
/// — KDC_ERR_POLICY, armored, keyd not asked to issue; her TGT stays
/// available.
#[test]
fn the_pdp_denies_the_computer_group_too() {
    let mut f = deployment_setup().build();
    {
        let alice = f.accounts().client_mut(&realm(), &alice_name()).unwrap();
        assert_eq!(alice.kind, AccountKind::User);
        alice.groups.insert(bootstrap_group());
    }
    let fast = f.send_fast(&alice_for_change_password().with_challenge(&alice_key(AES256)));
    let error = open_fast_error(fast.reply, &fast.armor_key);
    assert_eq!(error.outer.error_code, KDC_ERR_POLICY);
    assert_eq!(
        f.events()[0].reason,
        AuditReason::PolicyDenied(ReasonCode::CoarseDeny(RuleId(CHANGE_PASSWORD_RULES + 1)))
    );
    assert!(f.issue_as_rep_calls().is_empty());
    obtain_tgt(&mut f);
}

/// docs/53 §5.2; RFC 4120 3.1.3 ("looks up the client and server
/// principals"): the change-password service object is resolved before
/// pre-authentication — absent → KDC_ERR_S_PRINCIPAL_UNKNOWN; disabled →
/// KDC_ERR_SERVICE_REVOKED; a record whose key set — the one its resolution
/// names, the record's only statement of it (task PN10c; Q-1060 item 1 (e))
/// — is not the change-password one (the one derivation,
/// `KeyPurpose::of_service_name`) → KRB_ERR_GENERIC (fail closed); each
/// armored, keyd never asked to verify or issue.
#[test]
fn the_service_object_must_resolve_to_its_own_key_set() {
    for case in 0..3 {
        let mut f = deployment_setup().build();
        match case {
            0 => {
                let mut accounts = kdc::InMemoryAccounts::new();
                accounts
                    .insert_client(&realm(), &alice_name(), alice_account())
                    .unwrap();
                accounts
                    .insert_client(&realm(), &machine_name(), machine_account())
                    .unwrap();
                f.accounts = accounts;
            }
            1 => {
                f.accounts()
                    .service_mut(&realm(), &change_password_name())
                    .unwrap()
                    .state
                    .enabled = false;
            }
            _ => {
                // dird resolved the name to a plain Service key set — the
                // record's one statement of its key set (task PN10c).
                f.accounts()
                    .service_mut(&realm(), &change_password_name())
                    .unwrap()
                    .resolution = test_resolution(&change_password_name(), SERVICE);
            }
        }
        let fast = f.send_fast(&alice_for_change_password().with_challenge(&alice_key(AES256)));
        let error = open_fast_error(fast.reply, &fast.armor_key);
        let (code, reason) = [
            (KDC_ERR_S_PRINCIPAL_UNKNOWN, AuditReason::ServiceUnknown),
            (KDC_ERR_SERVICE_REVOKED, AuditReason::ServiceRevoked),
            (KRB_ERR_GENERIC, AuditReason::AccountRecordInvalid),
        ][case];
        assert_eq!(error.outer.error_code, code, "case {case}");
        assert_eq!(f.events()[0].reason, reason, "case {case}");
        assert!(!f.keyd_ops().contains(&keyd::Operation::VerifyPreauth));
        assert!(f.issue_as_rep_calls().is_empty());
    }
}

/// docs/53 §5.2 ("`KdcAs` on this service's resource, `armored` required");
/// docs/48 §4.2 (R48-10); A-139: through a recording policy — one Allow for
/// `KdcAs` on `KerbResKind::ChangePassword` with `armored`, leaving a marker
/// with the rate limiter — the PDP is asked about the change-password
/// resource (not an SPN) with `armored = true`; a policy whose only grant
/// names the resource unarmored grants nothing.
#[test]
fn the_pdp_sees_the_change_password_resource_armored() {
    let marker = nt_sid(&[21, 7, 8, 9, 9101]);
    let recording = |auth: AuthMatch| Rule {
        id: RuleId(1),
        effect: Effect::Allow,
        when: Match {
            action: ActionMatch::Exact(pdp::Action::KdcAs),
            resource: ResourceMatch::Kerberos {
                kind: Some(KerbResKind::ChangePassword),
            },
            subject: SubjectMatch::Any,
            context: ContextMatch::ANY,
            auth,
        },
        obligations: vec![Obligation::RateLimit(RlKey {
            principal: marker,
            class: ActionClass::Kerberos,
        })],
    };
    let mut setup = Setup::new();
    setup.rules = vec![recording(AuthMatch::ARMORED)];
    let mut f = setup.build();
    let _ = f.send_fast(&alice_for_change_password().with_challenge(&alice_key(AES256)));
    assert!(f
        .kdc
        .rate_limiter_mut()
        .seen
        .iter()
        .any(|k| k.principal == marker));
    assert_eq!(f.issue_as_rep_calls().len(), 1);

    let mut setup = Setup::new();
    setup.rules = vec![recording(AuthMatch::UNARMORED)];
    let mut f = setup.build();
    let fast = f.send_fast(&alice_for_change_password().with_challenge(&alice_key(AES256)));
    let error = open_fast_error(fast.reply, &fast.armor_key);
    assert_eq!(error.outer.error_code, KDC_ERR_POLICY);
    assert_eq!(
        f.events()[0].reason,
        AuditReason::PolicyDenied(ReasonCode::NoGrant)
    );
    assert!(f.issue_as_rep_calls().is_empty());
}

// ------------------------------------------------------------ TGS ----

/// docs/53 §5.2 ("the TGS refuses the name (KDC_ERR_POLICY, as R4)"), §10
/// ("TGS to changepw ⇒ POLICY"); RFC 4120 2.1 (INITIAL only from the AS); RFC
/// 3244 §2 (a password-changing service may insist on INITIAL): alice's
/// armored TGS for `kadmin/changepw` — under either name-type, under an
/// allow-everything policy, the service object present — is refused with
/// an ARMORED KDC_ERR_POLICY before the PDP and keyd's `issue_tgs_rep`: a
/// stolen TGT is never a ticket to change the password.
#[test]
fn tgs_for_change_password_is_refused() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    for (i, name_type) in [KRB_NT_SRV_INST, KRB_NT_PRINCIPAL].into_iter().enumerate() {
        let before = f.events().len();
        let mut spec = TgsReqSpec::service();
        spec.sname = Some(name(name_type, &["kadmin", "changepw"]));
        spec.nonce = 0x5150 + i as u32;
        spec.cusec = 10 + i as u32;
        let (request, _) = spec.encode(&tgt);
        let error = open_fast_error(f.send(&request), &spec.armor_key(&tgt.session));
        assert_eq!(error.outer.error_code, KDC_ERR_POLICY);
        assert_eq!(f.events()[before].reason, AuditReason::TgsForChangePassword);
        assert!(f.events()[before].armor.reply_armored);
    }
    assert!(!f.keyd_ops().contains(&keyd::Operation::IssueTgsRep));
}

/// The change-password ticket is not a TGT (RFC 4120 3.3.2: the TGS uses a
/// ticket "for the TGS"; 5.3: a ticket is sealed in "the server's secret
/// key"; task K3b, Q-915: the real ticket keyd issued). alice's own
/// change-password ticket, from her armored AS, presented in a TGS-REQ with
/// its session key: as issued (sname `kadmin/changepw`) it is
/// KRB_AP_ERR_NOT_US before keyd — the name never counts as this realm's
/// TGS; with the sname rewritten to `krbtgt/REALM` it reaches keyd, whose
/// krbtgt key does not open it (it is sealed under the change-password
/// service key) — KRB_AP_ERR_BAD_INTEGRITY (A-26), no TGS ticket issued.
#[test]
fn a_change_password_ticket_is_no_tgt() {
    let mut f = deployment_setup().build();
    let issued = obtain_change_password_ticket(&mut f, alice_for_change_password());
    let mut ticket = issued.rep.0.ticket.clone();
    assert_eq!(ticket.sname, change_password_name());

    let before = f.keyd_records().len();
    let (request, _) = TgsReqSpec::service().encode_with_ticket(&ticket, &issued.session);
    assert_eq!(code_of(f.send(&request)), KRB_AP_ERR_NOT_US);
    assert_eq!(f.keyd_records().len(), before, "keyd is not asked");

    ticket.sname = krbtgt_name();
    let mut spec = TgsReqSpec::service();
    spec.cusec += 1;
    let (request, _) = spec.encode_with_ticket(&ticket, &issued.session);
    assert_eq!(code_of(f.send(&request)), KRB_AP_ERR_BAD_INTEGRITY);
    let opened = f
        .keyd_records()
        .iter()
        .rev()
        .find(|r| r.op == keyd::Operation::OpenAndVerifyTgt)
        .expect("keyd tried the krbtgt key");
    assert_eq!(opened.result, keyd::AuditOutcome::Denied);
    assert!(!f.keyd_ops().contains(&keyd::Operation::IssueTgsRep));
}
