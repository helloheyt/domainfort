//! The ticket-subject lookup (task PN10b; docs/59 §6.2, §6.4; decision
//! A-187 on docs/questions/Q-1047): the subject checks of the admin plane,
//! kpasswd, the DNS update and the LDAP session read the facts of a ticket's
//! client through the one lookup path in the `TicketClient` context, with
//! no name resolution — so they need no signer, while the KDC's account
//! source of the same view answers no record without one (PN10's rule,
//! tests/name_resolution.rs `without_an_attestation_no_record_is_answered`,
//! kept). Over a real dirstore with the phase-1 schema.
//!
//! Sources, named on each test: docs/59 §6.1-§6.3 (the one lookup path;
//! `TicketClient` accepts what `AsClient` accepts; wave 2's acceptance),
//! §7.5 (only the KDC's records carry a resolution); docs/47 §1.3 (R47-1),
//! §4 (state), §5.3 (R47-8, a cycle is an error), §6.3 (R47-9), §8.1
//! (R47-11: one view, the same facts); docs/11 P3; docs/51 §5.3; docs/49
//! §3.2; AGENTS.md §6 (fail closed; nothing in errors). The directory is the
//! shared fixture of tests/common (its test data, made up there). No vector
//! or fixture comes from any other implementation.

mod common;

use ad_schema::flags::user_account_control as uac;
use common::*;
use directory_pip::{
    DirectoryContext, LookupCtx, PepView, TicketSubjectError, TicketSubjects, TierMap,
};
use dtyp::Guid;
use kdc::{AccountSource, AccountSourceError};
use krb_proto::constants::{KRB_NT_ENTERPRISE, KRB_NT_PRINCIPAL, KRB_NT_SRV_HST, KRB_NT_SRV_INST};
use krb_proto::{PrincipalName, Realm};
use pdp::{Pip, Tier};
use std::collections::{BTreeMap, BTreeSet};

/// The tier map of these tests: allstaff Tier1, staff Tier2, tier0 Tier0
/// (docs/47 §6.3 — the most privileged of `{p} ∪ g` wins).
fn tiers() -> TierMap {
    TierMap::new(
        BTreeMap::from([
            (sid_of(ALLSTAFF), Tier::Tier1),
            (sid_of(STAFF), Tier::Tier2),
            (sid_of(TIER0), Tier::Tier0),
        ]),
        Vec::new(),
    )
    .unwrap()
}

/// A context of the fixture's realm with **no** name-resolution signer — as
/// dird's admin, kpasswd, DNS and LDAP contexts are built (task PN10b).
fn unsigned(d: &Dir) -> DirectoryContext {
    DirectoryContext::new(d.p1.clone(), &keyd_config(), naming_context()).unwrap()
}

fn client(sam: &str) -> PrincipalName {
    name(KRB_NT_PRINCIPAL, &[sam])
}

/// docs/59 §6.2 (`TicketClient`), §7.5 (only the KDC channel's records carry
/// a resolution); docs/47 §8.1 (R47-11: one view, the same facts); docs/11
/// P3 (the Subject's tier is `tier_of`); docs/51 §5.3: on a context with no
/// signer the subject lookup answers every client — the same objectGUID,
/// objectSid, state, expansion and tier the KDC's record of the same name
/// carries on a signed context, and the PIP's own answers — through the
/// view and through a PEP's `PepView::subjects`; the KDC's account source of
/// that unsigned view answers `Failed` for the very same names.
#[test]
fn a_subject_check_needs_no_signer() {
    let d = Dir::standard("subject-unsigned");
    let tiers = tiers();
    let ctx = unsigned(&d);
    let view = ctx.view(&d.store, &tiers).unwrap();
    let signed = d.view_with(&tiers);
    for sam in ["alice", "bob", "rootadmin", "ws01$", "dc01$"] {
        let n = client(sam);
        let subject = view.ticket_subject(&realm(), &n).unwrap().expect(sam);
        let record = signed.client(&realm(), &n).unwrap().expect(sam);
        assert_eq!(
            subject.guid,
            Guid::from_packet(record.key().principal.as_bytes()),
            "{sam}"
        );
        assert_eq!(subject.sid, record.sid, "{sam}");
        assert_eq!(subject.state, record.state, "{sam}");
        assert_eq!(subject.groups, record.groups, "{sam}");
        assert_eq!(subject.tier, record.tier, "{sam}");
        assert_eq!(
            view.tier_of(&subject.sid, &subject.groups),
            Ok(subject.tier),
            "{sam}"
        );
        assert_eq!(
            view.expand_groups(&subject.sid),
            Ok(subject.groups.clone()),
            "{sam}"
        );
        assert_eq!(
            PepView::new(&view).subjects().ticket_subject(&realm(), &n),
            Ok(Some(subject)),
            "{sam}"
        );
        // The KDC's account source of the unsigned view: no record.
        assert_eq!(
            found(&view.client(&realm(), &n)),
            Err(AccountSourceError::Failed),
            "{sam}"
        );
    }
    // The values themselves (tests/common's standard directory): alice ∈
    // staff ∈ allstaff (docs/47 §5.3) ⇒ Tier1; rootadmin ∈ tier0 ⇒ Tier0;
    // dc01$ is a DC account (ST) ⇒ Tier0 with no map entry (docs/47 §6.3).
    let alice = view
        .ticket_subject(&realm(), &client("alice"))
        .unwrap()
        .unwrap();
    assert_eq!(alice.guid, guid(ALICE));
    assert_eq!(alice.sid, sid_of(ALICE));
    assert_eq!(
        alice.groups,
        BTreeSet::from([sid_of(STAFF), sid_of(ALLSTAFF)])
    );
    assert_eq!(alice.tier, Tier::Tier1);
    let root = view
        .ticket_subject(&realm(), &client("rootadmin"))
        .unwrap()
        .unwrap();
    assert_eq!(root.tier, Tier::Tier0);
    let dc = view
        .ticket_subject(&realm(), &client("dc01$"))
        .unwrap()
        .unwrap();
    assert_eq!(dc.groups, BTreeSet::new());
    assert_eq!(dc.tier, Tier::Tier0);
}

/// docs/59 §6.2 (`TicketClient` accepts what `AsClient` accepts — "the name
/// in the ticket is what our KDC wrote"), §6.3 (wave 2: the configured realm
/// octet for octet, one component, the stored sAMAccountName octet for
/// octet; no base name, UPN or SPN); docs/47 §1.3 (R47-1), §1.4 (R47-2:
/// never krbtgt); Q-1007 item 7 (never a group); RFC 4120 §6.2 (the
/// name-type is not significant): over every request below, the subject
/// lookup finds exactly the object the AS client context resolves, and
/// nothing where it resolves nothing.
#[test]
fn the_ticket_client_context_accepts_what_the_as_client_context_accepts() {
    let d = Dir::standard("subject-acceptance");
    let tiers = tiers();
    let ctx = unsigned(&d);
    let view = ctx.view(&d.store, &tiers).unwrap();
    let other = |r: &str| Realm::new(r).unwrap();
    let requests: Vec<(Realm, PrincipalName)> = vec![
        (realm(), client("alice")),
        (realm(), name(KRB_NT_ENTERPRISE, &["alice"])),
        (realm(), client("ALICE")),
        (realm(), client("ws01$")),
        (realm(), client("ws01")),
        (
            realm(),
            name(KRB_NT_SRV_HST, &["host", "ws01.example.test"]),
        ),
        (realm(), client("krbtgt")),
        (realm(), name(KRB_NT_SRV_INST, &["krbtgt", REALM])),
        (realm(), client("staff")),
        (realm(), client("nobody")),
        (realm(), name(KRB_NT_ENTERPRISE, &["alice@example.test"])),
        (other("OTHER.TEST"), client("alice")),
        (other("example.test"), client("alice")),
    ];
    let mut accepted = Vec::new();
    for (r, n) in &requests {
        let as_client = view
            .canonical_principal(r, n, LookupCtx::AsClient)
            .unwrap()
            .map(|p| p.guid());
        let subject = view.ticket_subject(r, n).unwrap().map(|s| s.guid);
        assert_eq!(subject, as_client, "{r:?} {n:?}");
        if let Some(found) = subject {
            accepted.push(found);
        }
    }
    // Positive control: alice under both name-types, and ws01$ — nothing else.
    assert_eq!(accepted, vec![guid(ALICE), guid(ALICE), guid(WS01)]);
}

/// AGENTS.md §6 (fail closed); docs/47 §5.3 item 4 (A-37: a cycle among
/// security groups is an error); docs/59 §6.1 step 3 (a stored name the
/// namespace refuses is a fault): a client whose expansion cannot be
/// computed, or whose stored names the namespace refuses, is "cannot tell"
/// — `Err`, never "no such principal" and never a partial record — while a
/// client the fault does not touch is answered. The error carries nothing.
#[test]
fn a_directory_that_cannot_tell_fails_closed() {
    let d = Dir::standard("subject-fails-closed");
    let normal = || vec![bits(uac::ADS_UF_NORMAL_ACCOUNT)];
    // bob ∈ c1 ∈ c2 ∈ c1 (written beneath the checker, which refuses it —
    // tests/groups_and_tiers.rs `cycle_is_an_error`).
    d.create_all(vec![
        d.group(80, STAFF_OU, "c1", GLOBAL_SECURITY, &[BOB]),
        d.group(81, STAFF_OU, "c2", GLOBAL_SECURITY, &[80]),
        d.user(60, STAFF_OU, "carol", &[("userAccountControl", normal())]),
    ]);
    d.set(80, "member", vec![ref_to(BOB), ref_to(81)]);
    // carol's userPrincipalName with a foreign suffix, beneath the checker
    // (tests/canonical_principal.rs `stored_names_the_namespace_refuses_fail_closed`).
    d.set(
        60,
        "userPrincipalName",
        vec![b"carol@foreign.test".to_vec()],
    );
    let tiers = tiers();
    let ctx = unsigned(&d);
    let view = ctx.view(&d.store, &tiers).unwrap();
    for sam in ["bob", "carol"] {
        assert_eq!(
            view.ticket_subject(&realm(), &client(sam)),
            Err(TicketSubjectError),
            "{sam}"
        );
    }
    assert!(view
        .ticket_subject(&realm(), &client("alice"))
        .unwrap()
        .is_some());
    assert_eq!(format!("{:?}", TicketSubjectError), "TicketSubjectError");
    assert_eq!(
        TicketSubjectError.to_string(),
        "ticket subject lookup failed"
    );
}
