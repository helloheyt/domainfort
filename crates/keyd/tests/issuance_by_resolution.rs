//! AS and TGS issuance through dird's attested name resolution (task PN11;
//! docs/59 §7.2, §10.1): keyd reaches a client or service key only through
//! a resolution it verified — dird's tag under the attestation key keyd's
//! ceremony installed, keyd's realm, issued within 30 s of keyd's own
//! clock — that names exactly that key set (principal and purpose), whose
//! canonical name is the key set's bound name in the namespace's one
//! equivalence, and that holds the very (realm, name) the ticket will carry.
//! Every refusal is the uniform `Denied` with one audit record naming the
//! reason; the issuance that follows a valid resolution is unchanged.
//!
//! Sources: docs/59 §7.1 (the fields), §7.2 steps 1-5 (the checks and their
//! order; "the krbtgt check stays against the stored binding, exact"), §9
//! (S4: a true, fresh resolution replayed within its window — a residual;
//! S5: a compromised dird — narrowed by the binding compare), §10.1 (the
//! attacks: a wrong tag, a stale resolution, another principal, another
//! purpose, a name not in the resolution); docs/questions/Q-1011 items 3, 4,
//! 7 (A-173: W = 30 s on keyd's clock; no client resolution at TGS), Q-1034
//! (A-177: the binding compare kept through PN11); RFC 4120 §3.1.5 (the
//! client checks that the reply's cname / crealm are what it requested),
//! §6.2 (the name-type is not significant), §7.3 (the TGS name); [MS-KILE]
//! v20261110 3.3.5.1.2 (the KDC returns krbtgt/FQDN for a TGT). Every value
//! is made up here; no vector comes from any other implementation.

mod common;

use common::*;
use keyd::{
    AsResolutions, AttestedNameResolution, AuditReason, AuthnProof, IssueError, KeyPurpose,
    TgtContext,
};
use keyd_types::NameResolutionFields;
use krb_crypto::EncType;
use krb_proto::constants::KRB_NT_PRINCIPAL;
use krb_proto::{EncAsRepPart, EncTicketPart, KerberosTime, PrincipalName, Realm};

/// alice's proof of `verify_preauth` at `when` (PA-ENC-TIMESTAMP).
fn alice_proof(f: &mut Fixture, when: &KerberosTime) -> AuthnProof {
    f.keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), *when),
            None,
            when,
        )
        .unwrap()
}

/// bob's proof of `verify_preauth` at [`now`].
fn bob_proof(f: &mut Fixture) -> AuthnProof {
    let key = password_key(EncType::Aes256CtsHmacSha196, BOB_PASSWORD, BOB_SALT);
    f.keyd
        .verify_preauth(
            &KDC,
            &BOB,
            &pa_enc_timestamp(&key, Some(1), now()),
            None,
            &now(),
        )
        .unwrap()
}

/// alice's TGT request at `when` with `client` as dird's resolution.
fn issue_alice_tgt(
    f: &mut Fixture,
    client: &AttestedNameResolution,
    when: &KerberosTime,
) -> Result<keyd::AsRepParts, IssueError> {
    let proof = alice_proof(f, when);
    f.keyd.issue_as_rep(
        &KDC,
        &ALICE,
        &KRBTGT,
        &proof,
        None,
        &as_template(),
        AsResolutions {
            client,
            server: None,
        },
        when,
    )
}

/// The reason of the last audit record.
fn last_reason(f: &Fixture) -> AuditReason {
    f.records().last().unwrap().reason
}

/// alice's resolution fields (dird's honest statement), issued at [`now`].
fn alice_fields() -> NameResolutionFields {
    resolution_fields(&realm(), &alice_name(), &ALICE, &now())
}

/// The service's resolution fields, issued at [`now`].
fn service_fields() -> NameResolutionFields {
    resolution_fields(&realm(), &service_name(), &SERVICE, &now())
}

/// A TGS context of alice's TGT for `sname` (nonce and cusec `nonce`).
fn context_for(f: &mut Fixture, tgt: &Tgt, sname: PrincipalName, nonce: u32) -> TgtContext {
    let (_, body) = tgs_req_body(nonce, sname);
    let auth = authenticator(&tgt.session, &AuthenticatorSpec::new(now(), nonce, &body));
    f.keyd
        .open_and_verify_tgt(
            &KDC,
            &KRBTGT,
            &ap_req(&tgt.parts.ticket, auth),
            &body,
            None,
            &now(),
        )
        .unwrap()
}

/// keyd's TGS issuance for SERVICE with `resolution` (template for the
/// service's own name).
fn issue_service(
    f: &mut Fixture,
    tgt: &Tgt,
    resolution: &AttestedNameResolution,
    nonce: u32,
) -> Result<keyd::TgsRepParts, IssueError> {
    let ctx = context_for(f, tgt, service_name(), nonce);
    f.keyd.issue_tgs_rep(
        &KDC,
        &SERVICE,
        resolution,
        &ctx.ctx_id,
        &tgs_template(nonce),
        &now(),
    )
}

/// docs/59 §7.2 (a valid resolution issues; R47-1's behaviour unchanged):
/// with dird's resolution of `alice` keyd issues her TGT — the ticket names
/// her as resolved and opens under krbtgt; with the service's resolution it
/// issues the service ticket — sname as resolved, under the service key.
/// RFC 4120 §3.1.5: the reply's cname / crealm are what she asked.
#[test]
fn a_verified_resolution_issues_the_tgt_and_the_service_ticket() {
    let mut f = Fixture::new();
    let alice = signed(alice_fields(), &ATTESTATION_KEY);
    let parts = issue_alice_tgt(&mut f, &alice, &now()).unwrap();
    let ticket = EncTicketPart::decode(&open(&krbtgt_key(), 2, &parts.ticket.enc_part)).unwrap();
    assert_eq!(ticket.cname, alice_name());
    assert_eq!(ticket.crealm, realm());
    assert_eq!(parts.ticket.sname, krbtgt_name());
    let rep = EncAsRepPart::decode(&open(&alice_key(), 3, &parts.enc_part)).unwrap();
    assert_eq!(rep.0.sname, krbtgt_name());
    assert_eq!(last_reason(&f), AuditReason::None);

    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let service = signed(service_fields(), &ATTESTATION_KEY);
    let tgs = issue_service(&mut f, &tgt, &service, 70).unwrap();
    assert_eq!(tgs.ticket.sname, service_name());
    let issued = EncTicketPart::decode(&open(&service_key(), 2, &tgs.ticket.enc_part)).unwrap();
    assert_eq!(issued.cname, alice_name());
    assert_eq!(last_reason(&f), AuditReason::None);
}

/// docs/59 §7.2 step 1, §10.1 ("a resolution with a wrong tag ⇒ Denied"):
/// a resolution tagged with another key, or with one tag bit flipped, is
/// not dird's statement — `NameResolutionInvalid`, at AS and at TGS, and
/// nothing is issued.
#[test]
fn a_forged_tag_is_refused() {
    let mut f = Fixture::new();
    let forged = signed(alice_fields(), &FORGED_ATTESTATION_KEY);
    assert_eq!(
        issue_alice_tgt(&mut f, &forged, &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameResolutionInvalid);
    let genuine = signed(alice_fields(), &ATTESTATION_KEY);
    let mut tag = *genuine.tag();
    tag[31] ^= 0x01;
    let flipped = AttestedNameResolution::new(genuine.resolution().clone(), tag);
    assert_eq!(
        issue_alice_tgt(&mut f, &flipped, &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameResolutionInvalid);

    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let forged = signed(service_fields(), &FORGED_ATTESTATION_KEY);
    assert_eq!(
        issue_service(&mut f, &tgt, &forged, 71),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameResolutionInvalid);
}

/// docs/59 §7.2 step 2: a resolution whose canonical realm is not keyd's
/// is refused (`WrongRealm`) — even one dird tagged.
#[test]
fn a_resolution_of_another_realm_is_refused() {
    let mut f = Fixture::new();
    let mut fields = alice_fields();
    fields.canonical_realm = Realm::new("EXAMPLE.NET").unwrap();
    let other = signed(fields, &ATTESTATION_KEY);
    assert_eq!(
        issue_alice_tgt(&mut f, &other, &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::WrongRealm);
}

/// docs/59 §7.2 step 3; Q-1011 item 3 (A-173: W = 30 s on keyd's own
/// clock): a resolution issued more than 30 s before or after keyd's `now`
/// is stale (`NameResolutionStale`); at exactly 30 s either side it issues.
#[test]
fn a_stale_or_future_resolution_is_refused() {
    let mut f = Fixture::new();
    for (offset, fresh) in [(-31, false), (31, false), (-30, true), (30, true)] {
        let mut fields = alice_fields();
        fields.issued_at = at(offset);
        let resolution = signed(fields, &ATTESTATION_KEY);
        let result = issue_alice_tgt(&mut f, &resolution, &now());
        if fresh {
            assert!(result.is_ok(), "{offset}");
        } else {
            assert_eq!(result, Err(IssueError::Denied), "{offset}");
            assert_eq!(last_reason(&f), AuditReason::NameResolutionStale);
        }
    }
    // keyd's clock is the call's `now` (R50-5): the same resolution is
    // fresh at its issue time and stale 31 s later.
    let resolution = signed(alice_fields(), &ATTESTATION_KEY);
    assert_eq!(
        issue_alice_tgt(&mut f, &resolution, &at(31)),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameResolutionStale);
}

/// docs/59 §7.2 step 4, §10.1 ("`principal` of another object ⇒ Denied"):
/// bob's genuine resolution presented with alice's key set and proof, and
/// another service's presented with this service's key set, are refused
/// (`NameResolutionMismatch`): a resolution opens only the key set it names.
#[test]
fn a_resolution_of_another_principal_is_refused() {
    let mut f = Fixture::new();
    let bob = resolution_at(&bob_name(), &BOB, &now());
    assert_eq!(
        issue_alice_tgt(&mut f, &bob, &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameResolutionMismatch);

    add_ldap_service(&mut f);
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let ldap = resolution_at(&ldap_service_name(), &LDAP_SERVICE, &now());
    assert_eq!(
        issue_service(&mut f, &tgt, &ldap, 72),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameResolutionMismatch);
}

/// docs/59 §7.2 step 4, §10.1 ("purpose other ⇒ Denied"): a resolution of
/// the right principal with another key purpose is refused — at AS (alice's
/// principal as a Service key set) and at TGS (the service's principal as
/// its AdminService or PrincipalLongterm key set).
#[test]
fn a_resolution_of_another_purpose_is_refused() {
    let mut f = Fixture::new();
    let mut fields = alice_fields();
    fields.key_purpose = KeyPurpose::Service;
    let resolution = signed(fields, &ATTESTATION_KEY);
    assert_eq!(
        issue_alice_tgt(&mut f, &resolution, &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameResolutionMismatch);

    let tgt = obtain_tgt(&mut f, now(), &as_template());
    for (nonce, purpose) in [
        (73, KeyPurpose::AdminService),
        (74, KeyPurpose::PrincipalLongterm),
    ] {
        let mut fields = service_fields();
        fields.key_purpose = purpose;
        let resolution = signed(fields, &ATTESTATION_KEY);
        assert_eq!(
            issue_service(&mut f, &tgt, &resolution, nonce),
            Err(IssueError::Denied),
            "{purpose:?}"
        );
        assert_eq!(last_reason(&f), AuditReason::NameResolutionMismatch);
    }
}

/// docs/59 §7.2 step 5, §10.1 ("a name in the template that is not in the
/// resolution ⇒ Denied"); docs/59 §9 S4: a KDC that replays alice's true,
/// fresh resolution for bob's request (bob's key set, bob's proof, a
/// template naming bob) is refused, and so is the service's resolution
/// replayed for a request for another service — the resolution must name
/// the key set used **and** the name written.
#[test]
fn a_resolution_replayed_for_another_request_is_refused() {
    let mut f = Fixture::new();
    let alice = resolution_at(&alice_name(), &ALICE, &now());
    let proof = bob_proof(&mut f);
    let mut bob_template = as_template();
    bob_template.client = BOB_ID;
    bob_template.cname = bob_name();
    assert_eq!(
        f.keyd.issue_as_rep(
            &KDC,
            &BOB,
            &KRBTGT,
            &proof,
            None,
            &bob_template,
            AsResolutions {
                client: &alice,
                server: None
            },
            &now(),
        ),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameResolutionMismatch);
    // alice's resolution with alice's key set, but the template naming bob
    // (the KDC choosing the name): refused too.
    let proof = alice_proof(&mut f, &now());
    let mut t = as_template();
    t.cname = bob_name();
    assert_eq!(
        f.keyd.issue_as_rep(
            &KDC,
            &ALICE,
            &KRBTGT,
            &proof,
            None,
            &t,
            AsResolutions {
                client: &alice,
                server: None
            },
            &now(),
        ),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameResolutionMismatch);

    // The service's resolution replayed for a request for the LDAP service
    // under the LDAP key set.
    add_ldap_service(&mut f);
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let service = resolution_at(&service_name(), &SERVICE, &now());
    let ctx = context_for(&mut f, &tgt, ldap_service_name(), 75);
    let mut template = tgs_template(75);
    template.sname = ldap_service_name();
    assert_eq!(
        f.keyd.issue_tgs_rep(
            &KDC,
            &LDAP_SERVICE,
            &service,
            &ctx.ctx_id,
            &template,
            &now()
        ),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameResolutionMismatch);
}

/// docs/59 §7.2 step 5 (the ticket's names ∈ {as sent, canonical}, exactly
/// — keyd does not fold, dird chose); docs/59 §4.5: when dird resolved a
/// spelling other than the stored one, keyd writes either the name as sent
/// or the canonical name — and nothing else: not another spelling, not
/// another name-type of them (an identity check, not keyd's own
/// equivalence).
#[test]
fn the_ticket_carries_a_name_the_resolution_holds_and_no_other() {
    let mut f = Fixture::new();
    let sent = PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("ALICE")],
    };
    let mut fields = alice_fields();
    fields.name_as_sent = sent.clone();
    let resolution = signed(fields, &ATTESTATION_KEY);
    let other_type = PrincipalName {
        name_type: 10,
        name_string: vec![kstr("alice")],
    };
    let other_spelling = PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("Alice")],
    };
    for (cname, accepted) in [
        (alice_name(), true),
        (sent, true),
        (other_spelling, false),
        (other_type, false),
    ] {
        let proof = alice_proof(&mut f, &now());
        let mut t = as_template();
        t.cname = cname.clone();
        let result = f.keyd.issue_as_rep(
            &KDC,
            &ALICE,
            &KRBTGT,
            &proof,
            None,
            &t,
            AsResolutions {
                client: &resolution,
                server: None,
            },
            &now(),
        );
        if accepted {
            let parts = result.unwrap();
            let ticket =
                EncTicketPart::decode(&open(&krbtgt_key(), 2, &parts.ticket.enc_part)).unwrap();
            assert_eq!(ticket.cname, cname);
        } else {
            assert_eq!(result, Err(IssueError::Denied), "{cname:?}");
            assert_eq!(last_reason(&f), AuditReason::NameResolutionMismatch);
        }
    }
}

/// docs/59 §7.2 step 1, §7.4; Q-1011 item 2: a keyd whose ceremony
/// installed no attestation key verifies no resolution, so it issues
/// nothing — `AttestationKeyMissing`, fail closed — at AS and at TGS.
#[test]
fn without_the_attestation_key_nothing_is_issued() {
    let mut f = Fixture::without_attestation_key();
    let alice = resolution_at(&alice_name(), &ALICE, &now());
    assert_eq!(
        issue_alice_tgt(&mut f, &alice, &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::AttestationKeyMissing);
}

/// docs/59 §7.2 ("the krbtgt check stays against the stored binding, exact
/// — without resolution"); RFC 4120 §7.3; [MS-KILE] 3.3.5.1.2: a TGT takes
/// no server resolution — one offered is refused (`NameResolutionMismatch`),
/// even dird's genuine statement of the krbtgt's own handle and name.
#[test]
fn the_krbtgt_is_never_bound_by_a_resolution() {
    let mut f = Fixture::new();
    let alice = resolution_at(&alice_name(), &ALICE, &now());
    let krbtgt = resolution_at(&krbtgt_name(), &KRBTGT, &now());
    let proof = alice_proof(&mut f, &now());
    assert_eq!(
        f.keyd.issue_as_rep(
            &KDC,
            &ALICE,
            &KRBTGT,
            &proof,
            None,
            &as_template(),
            AsResolutions {
                client: &alice,
                server: Some(&krbtgt)
            },
            &now(),
        ),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameResolutionMismatch);
}

/// docs/59 §9 S5 (a compromised dird signs a false resolution) and
/// Q-1034 (A-177: `bound_by` also compares the canonical name with the key
/// set's stored binding, through PN11): a tagged resolution stating that
/// `alice` is bob's key set — presented with bob's key set, bob's proof and
/// a template naming alice — is refused, because bob's key set is not bound
/// to `alice`. The binding compare narrows what a false statement can map.
#[test]
fn a_resolution_mapping_a_name_to_a_key_set_not_bound_to_it_is_refused() {
    let mut f = Fixture::new();
    let mut fields = alice_fields();
    fields.principal = BOB_ID;
    let lie = signed(fields, &ATTESTATION_KEY);
    let proof = bob_proof(&mut f);
    let mut t = as_template();
    t.client = BOB_ID;
    assert_eq!(
        f.keyd.issue_as_rep(
            &KDC,
            &BOB,
            &KRBTGT,
            &proof,
            None,
            &t,
            AsResolutions {
                client: &lie,
                server: None
            },
            &now(),
        ),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameResolutionMismatch);
}

/// docs/59 §9 S4 (residual, documented): a true, fresh resolution can be
/// replayed within its 30 s window for the same names and key set — keyd
/// cannot tell a replay of a true statement from a second request; what it
/// stops is any other mapping (the tests above). Each issuance still needs
/// its own one-time proof (I4).
#[test]
fn residual_a_true_resolution_replayed_within_its_window_issues_again() {
    let mut f = Fixture::new();
    let alice = resolution_at(&alice_name(), &ALICE, &now());
    assert!(issue_alice_tgt(&mut f, &alice, &now()).is_ok());
    assert!(issue_alice_tgt(&mut f, &alice, &at(30)).is_ok());
    assert_eq!(
        issue_alice_tgt(&mut f, &alice, &at(31)),
        Err(IssueError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameResolutionStale);
}

/// docs/10 §12 I8 (one record per operation), AGENTS.md §6: a refused
/// issuance leaves exactly one record, naming the operation's key set and
/// the reason, and nothing of the resolution's tag.
#[test]
fn a_refusal_is_one_record_without_the_tag() {
    let mut f = Fixture::new();
    let forged = signed(alice_fields(), &FORGED_ATTESTATION_KEY);
    let proof = alice_proof(&mut f, &now());
    let before = f.records().len();
    let _ = f.keyd.issue_as_rep(
        &KDC,
        &ALICE,
        &KRBTGT,
        &proof,
        None,
        &as_template(),
        AsResolutions {
            client: &forged,
            server: None,
        },
        &now(),
    );
    assert_eq!(f.records().len(), before + 1);
    let record = f.records().last().unwrap();
    assert_eq!(record.op, keyd::Operation::IssueAsRep);
    assert_eq!(record.principal, Some(ALICE_ID));
    let text = format!("{record:?}");
    let tag_hex: String = forged.tag().iter().map(|b| format!("{b:02x}")).collect();
    assert!(!text.contains(&tag_hex[..16]));
}
