//! The one principal namespace on the admin plane (task PN5; docs/59 §5.1,
//! §6.4, §10.1; A-173): `prepare` judges a create by the write checker's own
//! rules and probes the keys the new object will hold — every form of every
//! name (sAMAccountName, a computer's base name, a UPN's local part, an SPN,
//! a dNSHostName) in one key space, folded — and `Lookup` probes that key
//! space once.
//!
//! - Attacks (docs/59 §10.1): a name another object holds in another form
//!   or case is a `Conflict` at `prepare` — a computer `bob$` beside the user
//!   `bob` (noPac's shape), a user `ws01` beside the computer `ws01$`, a UPN
//!   `bob@<realm>` beside the user `bob`, a group named like a computer, a
//!   user named like the DC's host name, an SPN in another case — and nothing
//!   is written.
//! - Reserved names in any case (class C49; Q-1009 items 1-2): `ADMIND/…`,
//!   `KRBTGT/…`, `KADMIN/changepw` (`ValueInvalid`), the TGS's name or the
//!   realm alias as an account name (`AccountNameInvalid`) — refused at
//!   `prepare`.
//! - A computer names only its own host, `<computerName>.<realm DNS name>`
//!   (task PN6, rule N6): another host is `ValueInvalid`, a computerName
//!   that is no DNS label `AccountNameInvalid` — at `prepare`.
//! - A create stores exactly the keys its names produce (docs/59 N7).
//! - `Lookup` finds by one namespace probe and the exact stored value (R47-1
//!   kept); an object written beneath the checker without keys is not found
//!   through the per-attribute index any more (docs/59 §5.3).
//!
//! Sources: docs/59 §4.1-§4.4, §5.1, §5.3, §6.4, §10.1; RFC 4120 §6.2 ("The
//! name type does not partition the name space. Ignoring the name type, no
//! two names can be the same"; "Names of any type with an initial component
//! of 'krbtgt' are reserved"); [MS-SAMR] 3.1.1.8.4 item 2; [MS-ADTS]
//! 3.1.1.5.1.3, 3.1.1.5.3.1.1.2; RFC 1035 §2.3.1; RFC 3244 §2; docs/54
//! §5.3; docs/questions/Q-994 item 1, Q-1007 items 2, 3, 7, 8, Q-1009 items
//! 1-2, Q-1010 items 1-2, Q-1018 item 5. Fixtures: tests/common; names and
//! values are this project's own test data.

mod common;

use common::*;
use directory_admin::{
    CreateComputer, CreateContainerLike, CreateGroup, CreateUser, LookupKey, Operation,
    RefusalStatus, Reply,
};
use dirstore::{NewObject, Origin};
use ipc_audit::{AdminRefusal, DecisionResult, DirAdminStage};

/// The refusal code of a `prepare` refusal.
fn refusal_code(r: &directory_admin::Refusal) -> AdminRefusal {
    match r.event().stage {
        DirAdminStage::Decision(DecisionResult::Refused(code)) => code,
        other => panic!("not a decision refusal: {other:?}"),
    }
}

fn create_user(parent: u32, sam: &str, upn: Option<&str>) -> Operation {
    Operation::CreateUser(CreateUser {
        parent: guid(parent),
        sam: sam.to_owned(),
        upn: upn.map(str::to_owned),
        description: None,
    })
}

fn create_computer(parent: u32, name: &str, host: &str, spn: Option<&str>) -> Operation {
    Operation::CreateComputer(CreateComputer {
        parent: guid(parent),
        name: name.to_owned(),
        dns_host_name: host.to_owned(),
        spn: spn.map(str::to_owned),
    })
}

fn create_group(parent: u32, sam: &str) -> Operation {
    Operation::CreateGroup(CreateGroup {
        parent: guid(parent),
        sam: sam.to_owned(),
        group_type: None,
    })
}

/// The change-seq counter's next value (nothing written ⇒ unmoved).
fn change_seq(d: &Domain) -> u64 {
    d.counter_next(directory_admin::CHANGE_SEQ_COUNTER)
}

/// The namespace keys stored on `g`, as text, in the store's order.
fn keys_of(d: &Domain, g: dtyp::Guid) -> Vec<String> {
    d.object(g)
        .expect("live object")
        .attribute(ad_schema::PRINCIPAL_NAME_KEY)
        .map(|a| {
            a.values
                .iter()
                .map(|v| String::from_utf8(v.value.clone()).unwrap())
                .collect()
        })
        .unwrap_or_default()
}

/// The GUID a create's reply names.
fn created(reply: &Reply) -> dtyp::Guid {
    match reply {
        Reply::Created { guid, .. } => *guid,
        other => panic!("not a create reply: {other:?}"),
    }
}

/// docs/59 §10.1 (the attacks); RFC 4120 §6.2; [MS-SAMR] 3.1.1.8.4 item 2;
/// [MS-ADTS] 3.1.1.5.1.3; Q-1007 items 2, 7, 8: a name another object holds
/// in any form or case is a `Conflict` at `prepare`. The second holders are
/// created under ou=Managed, so no RDN is shared with the first: what
/// refuses them is the namespace. Nothing is written; a free name under the
/// same OU is created.
#[test]
fn a_name_taken_in_any_form_is_a_conflict() {
    let mut d = Domain::new("namespace-conflict");
    let before = change_seq(&d);
    let taken = [
        // noPac's shape: the computer `bob$` — base name `bob`, the user's.
        create_computer(MANAGED_OU, "bob", "bob.example.test", None),
        // The reverse: a user named like the computer `ws01$`'s base name.
        create_user(MANAGED_OU, "ws01", None),
        create_user(MANAGED_OU, "WS01", None),
        // A UPN whose local part is another object's sAMAccountName.
        create_user(MANAGED_OU, "carol", Some("bob@example.test")),
        create_user(MANAGED_OU, "carol", Some("Alice@EXAMPLE.TEST")),
        // A group named like a computer, like a user (another case).
        create_group(MANAGED_OU, "ws01"),
        create_group(MANAGED_OU, "Alice"),
        // A user named like the DC's dNSHostName.
        create_user(MANAGED_OU, "dc01.example.test", None),
        // (A computer carrying the LDAP service object's SPN in another case
        // — on the DC's host — was a `Conflict` here until task PN6; it now
        // names a host not its own, refused as a value before any key is
        // probed: `create_computer_names_only_its_own_host`.)
    ];
    for op in taken {
        let r = d.run(op.clone(), "admin1", &[]).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::Conflict, "{op:?}");
        assert_eq!(r.status(), RefusalStatus::Conflict, "{op:?}");
    }
    assert_eq!(change_seq(&d), before, "nothing written");
    let snapshot = d.store.snapshot().unwrap();
    for rdn in ["bob", "ws01", "WS01", "carol", "Alice", "dc01.example.test"] {
        assert_eq!(
            snapshot
                .lookup_child(Some(guid(MANAGED_OU)), rdn.as_bytes())
                .unwrap(),
            None,
            "{rdn}"
        );
    }
    drop(snapshot);
    // Control: a free name, with a UPN whose local part is its own name.
    let (_, applied) = d
        .run(
            create_user(MANAGED_OU, "carol", Some("carol@example.test")),
            "admin1",
            &[],
        )
        .applied();
    assert_eq!(keys_of(&d, created(applied.reply())), ["carol"]);
}

/// Task PN6, rule N6 (docs/59 §4.4, §10.1: "dNSHostName = `<base>.<realm>`;
/// other ⇒ refused"); [MS-ADTS] 3.1.1.5.3.1.1.2 ("computerName.
/// fullDomainDnsName, where computerName is the current sAMAccountName of
/// the object (without the final "$" character)"); RFC 1035 §2.3.1 (one
/// label: a letter first, letters, digits and hyphen); docs/54 §5.3;
/// docs/questions/Q-994 item 1, Q-1010 items 1-2: `CreateComputer` names
/// only the computer's own host. A dNSHostName naming another host — the
/// DC's (with the LDAP service object's SPN in another case: a `Conflict`
/// before task PN6, now a value refused before any key is probed), another
/// computer's, another domain, the realm itself, a bare label — is
/// `ValueInvalid` at `prepare`; a computerName that is not one RFC 1035
/// label (digit first, "_", ".") has no host name at all
/// (`AccountNameInvalid`). Nothing is written. Its own host, with the name
/// in another case, is created, and the host is one of its keys.
#[test]
fn create_computer_names_only_its_own_host() {
    let mut d = Domain::new("namespace-host-name");
    let before = change_seq(&d);
    let other_hosts = [
        create_computer(
            MANAGED_OU,
            "ws20",
            "dc01.example.test",
            Some("LDAP/dc01.example.test"),
        ),
        create_computer(MANAGED_OU, "ws20", "dc01.example.test", None),
        create_computer(MANAGED_OU, "ws20", "ws01.example.test", None),
        create_computer(MANAGED_OU, "ws20", "ws20.other.test", None),
        create_computer(MANAGED_OU, "ws20", "example.test", None),
        create_computer(MANAGED_OU, "ws20", "ws20", None),
    ];
    for op in other_hosts {
        let r = d.run(op.clone(), "admin1", &[]).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::ValueInvalid, "{op:?}");
    }
    for (name, host) in [
        ("1ws", "1ws.example.test"),
        ("w_s", "w_s.example.test"),
        ("w.s", "w.s.example.test"),
    ] {
        let op = create_computer(MANAGED_OU, name, host, None);
        let r = d.run(op.clone(), "admin1", &[]).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::AccountNameInvalid, "{op:?}");
    }
    assert_eq!(change_seq(&d), before, "nothing written");
    let (_, applied) = d
        .run(
            create_computer(
                MANAGED_OU,
                "WS20",
                "ws20.example.test",
                Some("host/ws20.example.test"),
            ),
            "admin1",
            &[],
        )
        .applied();
    assert_eq!(
        keys_of(&d, created(applied.reply())),
        [
            "host/ws20.example.test",
            "ws20",
            "ws20$",
            "ws20.example.test"
        ]
    );
}

/// Class C49 (docs/59 §3 M3); Q-1009 items 1-2 (decided A-173); A-163; RFC
/// 4120 §6.2, §7.3; RFC 3244 §2; docs/59 §4.4 N2, N3, N5; Q-1007 item 3: a
/// reserved name in any case is refused at `prepare` by the checker's rule on
/// the folded key — an SPN that spells the admin service's, the TGS's or the
/// change-password service's name (`ValueInvalid`; before task PN5 a case
/// variant passed), the TGS's name or the realm alias as a user, group or
/// computer name (`AccountNameInvalid`); and the namespace's syntax: an "@"
/// in a sAMAccountName (`AccountNameInvalid`), a UPN suffix that is not the
/// realm (`ValueInvalid`). Nothing is written.
#[test]
fn reserved_names_in_any_case_are_refused() {
    let mut d = Domain::new("namespace-reserved");
    let before = change_seq(&d);
    let invalid_values = [
        create_computer(
            STAFF_OU,
            "ws21",
            "ws21.example.test",
            Some("ADMIND/ws21.example.test"),
        ),
        create_computer(
            STAFF_OU,
            "ws21",
            "ws21.example.test",
            Some("KRBTGT/ws21.example.test"),
        ),
        create_computer(STAFF_OU, "ws21", "changepw", Some("KADMIN/changepw")),
        create_user(STAFF_OU, "carol", Some("carol@foreign.example")),
    ];
    for op in invalid_values {
        let r = d.run(op.clone(), "admin1", &[]).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::ValueInvalid, "{op:?}");
    }
    let invalid_names = [
        create_user(STAFF_OU, "KrbTgt", None),
        create_user(STAFF_OU, "Example.Test", None),
        create_group(STAFF_OU, "KRBTGT"),
        create_computer(STAFF_OU, "Krbtgt", "krbtgt.example.test", None),
        create_user(STAFF_OU, "a@b", None),
    ];
    for op in invalid_names {
        let r = d.run(op.clone(), "admin1", &[]).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::AccountNameInvalid, "{op:?}");
    }
    assert_eq!(change_seq(&d), before, "nothing written");
}

/// docs/59 §4.1, §4.3, §4.4 N7, §4.6; Q-1007 item 4; Q-1008 item 2; Q-1020
/// item 7: a create stores exactly the keys its names produce, folded, each
/// once and within the count bound (user ≤ 2, computer ≤ 3 + SPNs + 1) — a
/// user with a UPN, a computer with an SPN and its host, a group; an OU none
/// — and those keys are live at once: the next create of one of them, in
/// another form, is a `Conflict`.
#[test]
fn a_create_stores_the_keys_its_names_produce() {
    let mut d = Domain::new("namespace-stored");
    let create = |d: &mut Domain, op: Operation| {
        let (_, applied) = d.run(op, "admin1", &[]).applied();
        created(applied.reply())
    };
    let carol = create(
        &mut d,
        create_user(STAFF_OU, "Carol", Some("Carol.S@example.test")),
    );
    let ws22 = create(
        &mut d,
        create_computer(
            STAFF_OU,
            "ws22",
            "ws22.example.test",
            Some("HOST/ws22.example.test"),
        ),
    );
    let grp = create(&mut d, create_group(STAFF_OU, "Grp1"));
    let ou = create(
        &mut d,
        Operation::CreateOu(CreateContainerLike {
            parent: guid(STAFF_OU),
            name: "Keys".into(),
        }),
    );
    assert_eq!(keys_of(&d, carol), ["carol", "carol.s"]);
    assert_eq!(
        keys_of(&d, ws22),
        [
            "host/ws22.example.test",
            "ws22",
            "ws22$",
            "ws22.example.test"
        ]
    );
    assert_eq!(keys_of(&d, grp), ["grp1"]);
    assert!(keys_of(&d, ou).is_empty());
    for op in [
        create_user(MANAGED_OU, "GRP1", None),
        create_user(MANAGED_OU, "carol.s", None),
        create_group(MANAGED_OU, "WS22"),
    ] {
        let r = d.run(op.clone(), "admin1", &[]).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::Conflict, "{op:?}");
    }
}

/// docs/59 §5.3, §6.4 ("`Lookup {sam | spn}` ⇒ a probe in
/// `PRINCIPAL_NAME_KEY` + the kind filter + the comparison with the stored
/// value"); docs/47 §1.3 step 4 (R47-1, kept in wave 2 — docs/59 §6.3);
/// Q-1018 item 5 (no request's key reaches the krbtgt account): `Lookup`
/// finds an object by its exact stored sAMAccountName or SPN; another case,
/// another form of the name (a computer's base name, a UPN-shaped value) and
/// the krbtgt account's name find nothing (`NotFound`); an object written
/// beneath the checker without keys is not found by name — the
/// per-attribute index is no longer how a principal name is looked up.
#[test]
fn lookup_probes_the_namespace_once() {
    let mut d = Domain::new("namespace-lookup");
    let found = |d: &mut Domain, key: LookupKey| {
        let prepared = d.run(Operation::Lookup(key), "admin1", &[]).read();
        match prepared.reply() {
            Some(Reply::Found(result)) => result.guid,
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(
        found(&mut d, LookupKey::SamAccountName("alice".into())),
        guid(ALICE)
    );
    assert_eq!(
        found(&mut d, LookupKey::SamAccountName("ws01$".into())),
        guid(WS01)
    );
    assert_eq!(
        found(
            &mut d,
            LookupKey::ServicePrincipalName("host/ws01.example.test".into())
        ),
        guid(WS01)
    );
    // A user written beneath the checker, without its keys (as in a store
    // from before the namespace — dird refuses such a store, task PN10).
    let ghost = guid(91);
    {
        let alice = d.object(guid(ALICE)).unwrap();
        let replaced = |name: &str| -> Option<Vec<Vec<u8>>> {
            match name {
                "cn" | "sAMAccountName" => Some(vec![b"ghost".to_vec()]),
                "objectSid" => Some(vec![account_sid(FIRST_ADMIN_RID).encode()]),
                _ => None,
            }
        };
        let attributes = alice
            .attributes
            .iter()
            .filter(|a| a.id != ad_schema::PRINCIPAL_NAME_KEY)
            .map(|a| {
                let named = ["cn", "sAMAccountName", "objectSid"]
                    .into_iter()
                    .find(|n| d.attr(n) == a.id);
                let values = named
                    .and_then(replaced)
                    .unwrap_or_else(|| a.values.iter().map(|v| v.value.clone()).collect());
                (a.id, values)
            })
            .collect();
        let mut txn = d.store.begin_write().unwrap();
        let origin = Origin {
            wall_clock: directory_admin::wall_clock(&now()).unwrap(),
            origin_node: dirstore::NodeId([0x91; 16]),
            origin_seq: txn
                .take_counter_value(directory_admin::CHANGE_SEQ_COUNTER)
                .unwrap(),
        };
        txn.create_object(
            NewObject {
                guid: ghost,
                parent: alice.parent,
                classes: alice.classes.clone(),
                attributes,
            },
            &origin,
        )
        .unwrap();
        txn.commit().unwrap();
    }
    for key in [
        LookupKey::SamAccountName("ALICE".into()),
        LookupKey::SamAccountName("ws01".into()),
        LookupKey::SamAccountName("alice@example.test".into()),
        LookupKey::SamAccountName("krbtgt".into()),
        LookupKey::SamAccountName("example.test".into()),
        LookupKey::SamAccountName("ghost".into()),
        LookupKey::ServicePrincipalName("HOST/ws01.example.test".into()),
        LookupKey::ServicePrincipalName("host/ws01.example.test/x".into()),
        LookupKey::ServicePrincipalName("ws01.example.test".into()),
    ] {
        let r = d
            .run(Operation::Lookup(key.clone()), "admin1", &[])
            .refused();
        assert_eq!(r.status(), RefusalStatus::NotFound, "{key:?}");
    }
    // The ghost exists — by DN it is found.
    assert_eq!(
        found(
            &mut d,
            LookupKey::Dn(dn(&["cn=ghost", "ou=Staff", "dc=example", "dc=test"]))
        ),
        ghost
    );
}
