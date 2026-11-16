//! The KDC and dird's attested name resolutions (task PN11; docs/59 §7.2,
//! §7.5; docs/questions/Q-1009 items 4-5, Q-1011 items 7-8, A-173): the KDC
//! forwards the resolution each account record carries to keyd — the
//! client's with every AS issuance, the change-password service's with its
//! AS, the service's with every TGS — and keyd binds the keys only through
//! it; which kind of server a looked-up name is, and the name the PDP
//! judges, come from the resolution (the key set's purpose, the canonical
//! name), never from the request's spelling; and the key set the KDC asks
//! keyd for is the one the resolution names — the record's only statement
//! of it (task PN10c; docs/questions/Q-1060 item 1 (e)).
//!
//! Sources: docs/59 §4.7 (`key_purpose` from the stored name and the claim),
//! §6.1 step 6, §7.2 (keyd verifies; the ticket's names ∈ {as sent,
//! canonical}), §7.5; docs/questions/Q-1009 item 4 ("Classify from the
//! resolution (its purpose / claim), not the string"), item 5 ("The resource
//! string is the resolved object's stored canonical SPN"), Q-1011 item 7 (no
//! client resolution at TGS); RFC 4120 §3.3.3 (the TGS-REP), §6.2 (the
//! name-type is not significant); RFC 3244 §2 (`kadmin/changepw`); docs/53
//! §5.2 (no change-password ticket from a TGT); main-session decision 3 (an
//! inconsistent record fails closed, KRB_ERR_GENERIC); docs/59 §9 S5 (a
//! false mapping stated by dird), docs/questions/Q-1060 item 1 (e). Every
//! value is made up here; no vector comes from any other implementation.

mod common;

use common::*;
use kdc::{AuditReason, Peer, PolicyInputs, Transport};
use keyd::{KeyHandle, KeyPurpose};
use keyd_types::{AttestedNameResolution, NameResolution, NameResolutionFields};
use krb_proto::constants::{KDC_ERR_POLICY, KRB_NT_SRV_HST};
use krb_proto::PrincipalName;
use name_attestation::AttestationKey;
use pdp::{
    ActionMatch, AuthMatch, ContextMatch, Effect, IpScope, KerbResKind, Match, ResourceMatch, Rule,
    RuleId, Spn, SubjectMatch,
};

/// dird's resolution of `name_as_sent` to `key`, whose canonical name is
/// `canonical`, issued at [`now`], under the fixtures' attestation key.
fn resolution(
    name_as_sent: &PrincipalName,
    canonical: &PrincipalName,
    key: KeyHandle,
) -> AttestedNameResolution {
    let resolution = NameResolution::new(NameResolutionFields {
        realm_as_sent: realm(),
        name_as_sent: name_as_sent.clone(),
        canonical_realm: realm(),
        canonical_name: canonical.clone(),
        principal: key.principal,
        key_purpose: key.purpose,
        snapshot: 1,
        issued_at: now(),
    })
    .unwrap();
    name_attestation::tag(
        &AttestationKey::from_bytes(&TEST_ATTESTATION_KEY).unwrap(),
        &resolution,
    )
    .unwrap()
}

/// `host/files.example.org` spelled `HOST/files.example.org` (RFC 4120
/// §6.2.1: the service class is not the host; a case variant of it).
fn upper_service_name() -> PrincipalName {
    name(KRB_NT_SRV_HST, &["HOST", "files.example.org"])
}

/// Whether keyd was asked to issue a service ticket since the fixture was
/// built.
fn issued_tgs(f: &Fixture) -> bool {
    f.keyd_records()
        .iter()
        .any(|r| r.op == keyd::Operation::IssueTgsRep)
}

/// docs/59 §7.5 ("`IssueAsRep` + `client_resolution`"): the TGT's
/// `issue_as_rep` carries alice's record's resolution — her name as sent,
/// her key set — and no server resolution (the krbtgt is bound by its exact
/// stored binding, docs/59 §7.2); keyd verified it and issued.
#[test]
fn the_tgt_carries_the_clients_resolution_and_no_other() {
    let mut f = Fixture::new();
    let _tgt = obtain_tgt(&mut f);
    let call = f.issue_as_rep_calls().last().unwrap().clone();
    assert_eq!(call.server, KRBTGT);
    assert_eq!(call.client_resolution.name_as_sent(), &alice_name());
    assert_eq!(call.client_resolution.canonical_name(), &alice_name());
    assert_eq!(call.client_resolution.principal(), ALICE.principal);
    assert_eq!(
        call.client_resolution.key_purpose(),
        KeyPurpose::PrincipalLongterm
    );
    assert!(call.server_resolution.is_none());
    let issue = f
        .keyd_records()
        .iter()
        .find(|r| r.op == keyd::Operation::IssueAsRep)
        .unwrap();
    assert_eq!(issue.result, keyd::AuditOutcome::Success);
}

/// docs/59 §7.1 (the resolution's `principal` and `key_purpose`), §7.2
/// step 4, §9 S5; docs/questions/Q-1060 item 1 (e) (task PN10c): a record
/// states its key set once — in dird's resolution — so the key set the KDC
/// asks keyd for is always the one the resolution it forwards names (the
/// TGT's client key set is the client resolution's `(principal, purpose)`).
/// A resolution mapping alice's name to bob's key set (S5: a false mapping
/// dird would have to state) therefore makes the KDC ask for bob's key set
/// — there is no second statement left to disagree with — and keyd, which
/// binds bob's key set to bob's name only (`bound_by`), refuses the
/// issuance even to a client that proves bob's key: no ticket names alice
/// under bob's key (`NameResolutionMismatch`).
#[test]
fn the_key_set_the_kdc_asks_for_is_the_one_the_resolution_names() {
    let mut f = Fixture::new();
    let _tgt = obtain_tgt(&mut f);
    let call = f.issue_as_rep_calls().last().unwrap().clone();
    assert_eq!(
        call.client,
        KeyHandle::new(
            call.client_resolution.principal(),
            call.client_resolution.key_purpose()
        )
    );
    assert_eq!(call.client, ALICE);

    let mut f = Fixture::new();
    f.accounts()
        .client_mut(&realm(), &alice_name())
        .unwrap()
        .resolution = test_resolution(&alice_name(), BOB);
    let bob_key = password_key(AES256, BOB_PASSWORD, BOB_SALT);
    let spec = AsReqSpec::alice().with_challenge(&bob_key);
    let _ = f.send_fast(&spec);
    let call = f.issue_as_rep_calls().last().unwrap().clone();
    assert_eq!(call.client, BOB);
    assert_eq!(call.client_resolution.principal(), BOB.principal);
    let issue = f
        .keyd_records()
        .iter()
        .rfind(|r| r.op == keyd::Operation::IssueAsRep)
        .unwrap();
    assert_eq!(issue.result, keyd::AuditOutcome::Denied);
    assert_eq!(issue.reason, keyd::AuditReason::NameResolutionMismatch);
}

/// Q-1009 item 4 (A-173): which kind of server a name is comes from the key
/// set dird resolved it to — a service record found under another spelling
/// whose resolution names the change-password service's key set is the
/// change-password service, and the TGS refuses it (KDC_ERR_POLICY,
/// `TgsForChangePassword` — its tickets come only from an armored AS,
/// docs/53 §5.2), although the request's spelling is not `kadmin/changepw`.
#[test]
fn the_server_kind_comes_from_the_resolution() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f);
    let alias = name(KRB_NT_SRV_HST, &["kpw", "dc01.example.org"]);
    let mut record = f
        .accounts()
        .service_mut(&realm(), &change_password_name())
        .unwrap()
        .clone();
    record.resolution = resolution(&alias, &change_password_name(), CHANGEPW);
    f.accounts()
        .insert_service(&realm(), &alias, record)
        .unwrap();
    let mut spec = TgsReqSpec::service();
    spec.sname = Some(alias);
    let (request, _) = spec.encode(&tgt);
    let error = error_of(f.send(&request));
    assert_eq!(error.error_code, KDC_ERR_POLICY);
    assert_eq!(
        f.events().last().unwrap().reason,
        AuditReason::TgsForChangePassword
    );
    assert!(!issued_tgs(&f));
}

/// Q-1009 item 5 (A-173): the PDP judges the service as dird resolved it —
/// its canonical (stored) name. A request spelled `HOST/files.example.org`
/// that dird resolved to the stored `host/files.example.org` is denied by a
/// rule written for `host/files.example.org`; without the rule it is issued,
/// and the ticket carries the name as sent — one of the resolution's two
/// names (docs/59 §7.2 step 5) — under the service's key.
#[test]
fn the_pdp_judges_the_canonical_name() {
    let alias_record = |f: &mut Fixture| {
        let mut record = f
            .accounts()
            .service_mut(&realm(), &service_name())
            .unwrap()
            .clone();
        record.resolution = resolution(&upper_service_name(), &service_name(), SERVICE);
        f.accounts()
            .insert_service(&realm(), &upper_service_name(), record)
            .unwrap();
    };
    let mut spec = TgsReqSpec::service();
    spec.sname = Some(upper_service_name());

    let mut setup = Setup::new();
    setup.rules.insert(
        0,
        Rule {
            id: RuleId(9),
            effect: Effect::Deny,
            when: Match {
                action: ActionMatch::Exact(pdp::Action::KdcTgs),
                resource: ResourceMatch::Kerberos {
                    kind: Some(KerbResKind::Service(Spn("host/files.example.org".into()))),
                },
                subject: SubjectMatch::Any,
                context: ContextMatch::ANY,
                auth: AuthMatch::ANY,
            },
            obligations: Vec::new(),
        },
    );
    let mut f = setup.build();
    alias_record(&mut f);
    let tgt = obtain_tgt(&mut f);
    let (request, _) = spec.encode(&tgt);
    assert_eq!(error_of(f.send(&request)).error_code, KDC_ERR_POLICY);
    assert_eq!(
        f.events().last().unwrap().reason,
        AuditReason::PolicyDenied(pdp::ReasonCode::CoarseDeny(RuleId(9)))
    );
    assert!(!issued_tgs(&f));

    let mut f = Fixture::new();
    alias_record(&mut f);
    let tgt = obtain_tgt(&mut f);
    let (request, _) = spec.encode(&tgt);
    let bytes = sent(f.send(&request));
    let (rep, part) = open_tgs_rep(&bytes, &tgt, &spec);
    assert_eq!(rep.0.ticket.sname, upper_service_name());
    assert_eq!(part.0.sname, upper_service_name());
    let ticket = open_ticket(&rep.0.ticket, &service_key());
    assert_eq!(ticket.cname, alice_name());
}

/// docs/59 §7.2 step 3 (keyd judges freshness on its own clock, 30 s): an
/// account source whose resolution is older than the window — here the
/// record's resolution issued at [`now`], the request handled 40 s later
/// without dird stating it again — gets no ticket: keyd refuses the
/// issuance (`NameResolutionStale`), the KDC answers KRB_ERR_GENERIC
/// (`IssueDenied`), sealed under the armor.
#[test]
fn a_stale_resolution_issues_nothing() {
    let mut f = Fixture::new();
    let when = at(40);
    let spec = AsReqSpec::alice().with_challenge(&alice_key(AES256));
    let (request, _armor) = f.fast_as_request(&spec, when);
    let inputs = PolicyInputs {
        snapshot: &f.snapshot,
        pip: &f.pip,
    };
    let _ = f.kdc.handle(
        &request,
        Peer {
            transport: Transport::Tcp,
            src_net: IpScope::Internal,
        },
        when,
        &inputs,
        &f.accounts,
    );
    let issue = f
        .keyd_records()
        .iter()
        .find(|r| r.op == keyd::Operation::IssueAsRep)
        .expect("keyd was asked");
    assert_eq!(issue.result, keyd::AuditOutcome::Denied);
    assert_eq!(issue.reason, keyd::AuditReason::NameResolutionStale);
    assert_eq!(f.events().last().unwrap().reason, AuditReason::IssueDenied);
}
