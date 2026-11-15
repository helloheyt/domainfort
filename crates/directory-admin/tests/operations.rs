//! Each operation of docs/51 §5.2 / §7.3 end to end over a real dirstore:
//! allowed, denied by the PDP, denied for tier, the semantic refusals of
//! docs/51 §11, protected objects, and `Lookup` without an existence oracle.
//!
//! Sources (named per test): docs/51 §5.2, §7.3, §7.4, §11 (decided A-72,
//! A-79 / Q-298); [MS-SAMR] v20260427 3.1.1.6 items 8-13, 22, 3.1.1.8.1,
//! 3.1.1.8.4, 3.1.1.8.9, 3.1.1.9.2; [MS-ADTS] v20261026 3.1.1.5.2.4, 6.1.3;
//! docs/46 §2.3, §8.4; docs/11 §4, §7; A-18, A-19, A-35, A-55, A-76.
//! Fixtures: tests/common (this project's own test data).

mod common;

use common::*;
use directory_admin::{
    CreateComputer, CreateContainerLike, CreateGroup, CreateUser, LookupKey, Membership, Operation,
    RefusalStatus, Reply, SetAccountExpires, SetEnabled,
};
use ipc_audit::{AccountExpiresValue, AdminRefusal, DecisionResult, DirAdminStage, PdpReasonCode};

fn create_user(parent: u32, sam: &str) -> Operation {
    Operation::CreateUser(CreateUser {
        parent: guid(parent),
        sam: sam.to_owned(),
        upn: None,
        description: None,
    })
}

fn create_group(parent: u32, sam: &str, group_type: Option<u32>) -> Operation {
    Operation::CreateGroup(CreateGroup {
        parent: guid(parent),
        sam: sam.to_owned(),
        group_type,
    })
}

/// The refusal code of a `prepare` refusal.
fn refusal_code(r: &directory_admin::Refusal) -> AdminRefusal {
    match r.event().stage {
        DirAdminStage::Decision(DecisionResult::Refused(code)) => code,
        other => panic!("not a decision refusal: {other:?}"),
    }
}

fn created(reply: &Reply) -> (dtyp::Guid, Option<dtyp::Sid>) {
    match reply {
        Reply::Created { guid, sid } => (*guid, *sid),
        other => panic!("not a create reply: {other:?}"),
    }
}

/// docs/51 §5.2 row 1 (cn = sam, UAC = N|D, accountExpires "never", no
/// pwdLastSet, SD per §10); [MS-SAMR] 3.1.1.8.1 items 1.1-1.2, 3.1.1.9.2
/// (objectSid = domain SID ‖ RID); [MS-ADTS] 3.1.1.5.2.4 (a new
/// objectGUID; whenCreated = now); A-75 (RID from the counter); A-76 (owner
/// = requester); A-79 (never NR).
#[test]
fn create_user_writes_the_object_the_spec_describes() {
    let mut d = Domain::new("create-user");
    let op = Operation::CreateUser(CreateUser {
        parent: guid(STAFF_OU),
        sam: "carol".into(),
        upn: Some("carol@example.test".into()),
        description: Some("Carol, accounts".into()),
    });
    let (_, applied) = d.run(op, "admin1", &[]).applied();
    let (g, sid) = created(applied.reply());
    assert_eq!(g, drawn_guid(1));
    assert_eq!(sid, Some(account_sid(FIRST_ADMIN_RID)));
    let obj = d.object(g).expect("created");
    assert_eq!(obj.parent, Some(guid(STAFF_OU)));
    let value = |name: &str| {
        obj.attribute(d.attr(name))
            .map(|a| a.values[0].value.clone())
    };
    assert_eq!(value("cn"), Some(b"carol".to_vec()));
    assert_eq!(value("sAMAccountName"), Some(b"carol".to_vec()));
    assert_eq!(
        value("userAccountControl"),
        Some(flags(0x0000_0200 | 0x0000_0002))
    );
    assert_eq!(value("accountExpires"), Some(int64(i64::MAX)));
    assert_eq!(value("pwdLastSet"), None);
    assert_eq!(value("whenCreated"), Some(int64(NOW_DSTIME)));
    assert_eq!(value("whenChanged"), Some(int64(NOW_DSTIME)));
    assert_eq!(
        value("objectSid"),
        Some(account_sid(FIRST_ADMIN_RID).encode())
    );
    assert_eq!(
        value("userPrincipalName"),
        Some(b"carol@example.test".to_vec())
    );
    assert_eq!(value("description"), Some(b"Carol, accounts".to_vec()));
    let sd = dtyp::SecurityDescriptor::decode(&value("nTSecurityDescriptor").unwrap()).unwrap();
    assert_eq!(sd.owner_sid, Some(sid_of(ADMIN1)));
    assert_eq!(sd.group_sid, Some(sid_of(ADMIN1)));
    assert!(sd.dacl.is_some());
    assert_eq!(
        d.counter_next(directory_admin::RID_COUNTER),
        u64::from(FIRST_ADMIN_RID) + 1
    );
}

/// docs/51 §5.2 rows 2-4: a computer (sAMAccountName = name ‖ "$", cn =
/// name, UAC = WT|D, one SPN), a group (default groupType 0x80000002 —
/// [MS-SAMR] 3.1.1.8.1 item 2.2 — or one of the six), an OU and a
/// container; RIDs only for the principals (docs/51 §8.3).
#[test]
fn create_computer_group_ou_and_container() {
    let mut d = Domain::new("create-others");
    let computer = Operation::CreateComputer(CreateComputer {
        parent: guid(STAFF_OU),
        name: "ws02".into(),
        dns_host_name: "ws02.example.test".into(),
        spn: Some("host/ws02.example.test".into()),
    });
    let (_, applied) = d.run(computer, "admin1", &[]).applied();
    let (g, sid) = created(applied.reply());
    assert_eq!(sid, Some(account_sid(FIRST_ADMIN_RID)));
    let obj = d.object(g).unwrap();
    let value = |name: &str| {
        obj.attribute(d.attr(name))
            .map(|a| a.values[0].value.clone())
    };
    assert_eq!(value("cn"), Some(b"ws02".to_vec()));
    assert_eq!(value("sAMAccountName"), Some(b"ws02$".to_vec()));
    assert_eq!(
        value("userAccountControl"),
        Some(flags(0x0000_1000 | 0x0000_0002))
    );
    assert_eq!(value("dNSHostName"), Some(b"ws02.example.test".to_vec()));
    assert_eq!(
        value("servicePrincipalName"),
        Some(b"host/ws02.example.test".to_vec())
    );

    let (_, applied) = d
        .run(create_group(STAFF_OU, "ops", None), "admin1", &[])
        .applied();
    let (g, sid) = created(applied.reply());
    assert_eq!(sid, Some(account_sid(FIRST_ADMIN_RID + 1)));
    let obj = d.object(g).unwrap();
    assert_eq!(
        obj.attribute(d.attr("groupType")).unwrap().values[0].value,
        flags(0x8000_0002)
    );
    let (_, applied) = d
        .run(
            create_group(STAFF_OU, "all", Some(0x8000_0008)),
            "admin1",
            &[],
        )
        .applied();
    let (g, _) = created(applied.reply());
    assert_eq!(
        d.object(g)
            .unwrap()
            .attribute(d.attr("groupType"))
            .unwrap()
            .values[0]
            .value,
        flags(0x8000_0008)
    );

    let ou = Operation::CreateOu(CreateContainerLike {
        parent: guid(STAFF_OU),
        name: "Lab".into(),
    });
    let (_, applied) = d.run(ou, "admin1", &[]).applied();
    let (g, sid) = created(applied.reply());
    assert_eq!(sid, None);
    assert!(d
        .object(g)
        .unwrap()
        .attribute(d.attr("objectSid"))
        .is_none());
    let container = Operation::CreateContainer(CreateContainerLike {
        parent: guid(STAFF_OU),
        name: "Printers".into(),
    });
    let (_, applied) = d.run(container, "admin1", &[]).applied();
    let (g, sid) = created(applied.reply());
    assert_eq!(sid, None);
    assert_eq!(
        d.object(g).unwrap().attribute(d.attr("cn")).unwrap().values[0].value,
        b"Printers".to_vec()
    );
    // Three principals took three consecutive RIDs; OU and container none.
    assert_eq!(
        d.counter_next(directory_admin::RID_COUNTER),
        u64::from(FIRST_ADMIN_RID) + 3
    );
}

/// docs/51 §7.4 step 3: `decide` Deny ⇒ refused; the PDP's reason is in the
/// event. bob may read (rule 3) but no rule grants him `DirAddChild`
/// (docs/11 §4 layer 3: no Allow ⇒ NoGrant).
#[test]
fn a_create_the_pdp_denies_is_refused() {
    let mut d = Domain::new("create-denied");
    let r = d.run(create_user(STAFF_OU, "carol"), "bob", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::PolicyDenied);
    assert_eq!(r.status(), RefusalStatus::Denied);
    assert_eq!(r.event().pdp.unwrap().code, PdpReasonCode::NoGrant);
    assert!(d.object(drawn_guid(1)).is_none());
}

/// docs/11 §4 layer 4 (P5) through the write PEP: helper is Tier1
/// (helpdesk → Tier1 in the tier map); ou=Staff is unclassified, hence
/// Tier0 for writes (A-36) ⇒ TierViolation; ou=Managed is Tier1 ⇒ allowed.
#[test]
fn a_tier1_subject_writes_only_below_its_tier() {
    let mut d = Domain::new("create-tier");
    let r = d
        .run(create_user(STAFF_OU, "carol"), "helper", &[])
        .refused();
    assert_eq!(refusal_code(&r), AdminRefusal::PolicyDenied);
    assert_eq!(r.event().pdp.unwrap().code, PdpReasonCode::TierViolation);
    let (_, applied) = d
        .run(create_user(MANAGED_OU, "carol"), "helper", &[])
        .applied();
    assert!(matches!(applied.reply(), Reply::Created { .. }));
}

/// docs/51 §5.3 (A-73): the Subject comes from the directory; an unknown
/// name, a disabled account, and the krbtgt name are all refused with the
/// same `Unauthenticated` (A-26: uniform), and no requester SID is recorded.
#[test]
fn unknown_or_unusable_requesters_are_refused_uniformly() {
    let mut d = Domain::new("unauthenticated");
    for who in ["nobody", "disabled", "krbtgt"] {
        let r = d.run(create_user(STAFF_OU, "carol"), who, &[]).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::Unauthenticated, "{who}");
        assert_eq!(r.status(), RefusalStatus::Denied, "{who}");
        assert_eq!(r.event().requester, None, "{who}");
        assert_eq!(r.event().pdp, None, "{who}");
    }
}

/// R51-10 (docs/51 §5.5): `ticket_age` above the configured threshold (600
/// s in the fixture) is refused; exactly the threshold is accepted.
#[test]
fn a_ticket_older_than_the_threshold_is_refused() {
    let mut d = Domain::new("ticket-age");
    let mut request = d.request(create_user(STAFF_OU, "carol"), "admin1");
    // 601 s before now (10:00:00 − 10 min 1 s = 09:49:59).
    request.requester.authtime = kt(2026, 11, 13, 9, 49, 59);
    let r = d.run_request(&request).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::TicketAge);
    assert_eq!(r.status(), RefusalStatus::Denied);
    // Exactly 600 s: accepted.
    request.requester.authtime = kt(2026, 11, 13, 9, 50, 0);
    request.operation_id += 100;
    assert!(matches!(d.run_request(&request), Ran::Applied { .. }));
}

/// docs/51 §11 rows 1-3, [MS-SAMR] 3.1.1.6 items 8-13 (A-79: ≤ 20 for
/// user and computer including "$", ≤ 256 for a group, bounded by cn's 64 —
/// Q-355 item 1); P-6 (printable ASCII).
#[test]
fn account_name_rules_are_enforced() {
    let mut d = Domain::new("names");
    for sam in [
        "",
        "   ",
        "carol.",
        "car/ol",
        "car\"ol",
        "car[ol]",
        "c:a",
        "c|a",
        "c<a>",
        "c+a",
        "c=a",
        "c;a",
        "c?a",
        "c,a",
        "c*a",
        "c\\a",
        "c\ta",
        "carol$",
        "abcdefghijklmnopqrstu",
        "caf\u{e9}",
    ] {
        let r = d.run(create_user(STAFF_OU, sam), "admin1", &[]).refused();
        assert_eq!(
            refusal_code(&r),
            AdminRefusal::AccountNameInvalid,
            "{sam:?}"
        );
        assert_eq!(r.status(), RefusalStatus::Invalid);
    }
    // Exactly 20 characters is accepted.
    let ok = d.run(create_user(STAFF_OU, "abcdefghijklmnopqrst"), "admin1", &[]);
    assert!(matches!(ok, Ran::Applied { .. }));
    // A computer: 19 + "$" = 20 is the most; a name ending in "$" is not a
    // single "$" (item 11).
    for (name, accepted) in [
        ("w234567890123456789", true),
        ("w2345678901234567890", false),
        ("ws09$", false),
    ] {
        let op = Operation::CreateComputer(CreateComputer {
            parent: guid(STAFF_OU),
            name: name.into(),
            dns_host_name: "ws09.example.test".into(),
            spn: None,
        });
        let ran = d.run(op, "admin1", &[]);
        if accepted {
            assert!(matches!(ran, Ran::Applied { .. }), "{name}");
        } else {
            assert_eq!(
                refusal_code(&ran.refused()),
                AdminRefusal::AccountNameInvalid
            );
        }
    }
    // A group: 64 characters is the most (cn).
    let long = "g".repeat(64);
    assert!(matches!(
        d.run(create_group(STAFF_OU, &long, None), "admin1", &[]),
        Ran::Applied { .. }
    ));
    let too_long = "h".repeat(65);
    let r = d
        .run(create_group(STAFF_OU, &too_long, None), "admin1", &[])
        .refused();
    assert_eq!(refusal_code(&r), AdminRefusal::AccountNameInvalid);
}

/// [MS-SAMR] 3.1.1.8.4 item 2 (sAMAccountName unique in the domain; the
/// index folds A-Z, Q-080), docs/46 §8.5 (UPN, SPN unique), §8.3 item 3
/// (one RDN per parent) — refused before anything is written.
#[test]
fn values_already_taken_are_conflicts() {
    let mut d = Domain::new("unique");
    for sam in ["bob", "BOB"] {
        let r = d.run(create_user(MANAGED_OU, sam), "admin1", &[]).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::Conflict, "{sam}");
        assert_eq!(r.status(), RefusalStatus::Conflict);
    }
    let first = Operation::CreateUser(CreateUser {
        parent: guid(STAFF_OU),
        sam: "carol".into(),
        upn: Some("c@example.test".into()),
        description: None,
    });
    assert!(matches!(d.run(first, "admin1", &[]), Ran::Applied { .. }));
    let second = Operation::CreateUser(CreateUser {
        parent: guid(STAFF_OU),
        sam: "carol2".into(),
        upn: Some("c@example.test".into()),
        description: None,
    });
    assert_eq!(
        refusal_code(&d.run(second, "admin1", &[]).refused()),
        AdminRefusal::Conflict
    );
    let spn_taken = Operation::CreateComputer(CreateComputer {
        parent: guid(STAFF_OU),
        name: "ws09".into(),
        dns_host_name: "ws01.example.test".into(),
        spn: Some("host/ws01.example.test".into()),
    });
    assert_eq!(
        refusal_code(&d.run(spn_taken, "admin1", &[]).refused()),
        AdminRefusal::Conflict
    );
    // A container named like an existing child of ou=Staff (cn=helper).
    let rdn_taken = Operation::CreateContainer(CreateContainerLike {
        parent: guid(STAFF_OU),
        name: "helper".into(),
    });
    assert_eq!(
        refusal_code(&d.run(rdn_taken, "admin1", &[]).refused()),
        AdminRefusal::Conflict
    );
}

/// docs/51 §5.2 rows 2-3, §11: groupType only from the six phase-1 values
/// (docs/46 §8.2); an SPN only `service/host` with the computer's own
/// lower-case dNSHostName (RFC 4120 §6.2.1; Q-355 item 3); no "krbtgt"
/// service (RFC 4120 §7.3).
#[test]
fn value_rules_are_enforced() {
    let mut d = Domain::new("values");
    for gt in [0x8000_0001u32, 0x10, 0x20, 0, 0x8000_0006, 0x8000_0000] {
        let r = d
            .run(create_group(STAFF_OU, "g1", Some(gt)), "admin1", &[])
            .refused();
        assert_eq!(refusal_code(&r), AdminRefusal::ValueInvalid, "{gt:#x}");
        // The event records no group type for a value outside the six
        // (A-85, Q-340 item 5).
        assert_eq!(r.event().group_type, None);
    }
    for (dns, spn) in [
        ("WS09.example.test", None),
        ("ws09.example.test", Some("host/ws08.example.test")),
        ("ws09.example.test", Some("krbtgt/ws09.example.test")),
        ("ws09.example.test", Some("host")),
        ("ws 09.example.test", None),
    ] {
        let op = Operation::CreateComputer(CreateComputer {
            parent: guid(STAFF_OU),
            name: "ws09".into(),
            dns_host_name: dns.into(),
            spn: spn.map(str::to_owned),
        });
        let r = d.run(op, "admin1", &[]).refused();
        assert_eq!(
            refusal_code(&r),
            AdminRefusal::ValueInvalid,
            "{dns} {spn:?}"
        );
    }
    // accountExpires 0 is refused (docs/51 §5.2 row 7; R47-5b).
    let op = Operation::SetAccountExpires(SetAccountExpires {
        target: guid(BOB),
        value: AccountExpiresValue::at(0),
    });
    assert_eq!(
        refusal_code(&d.run(op, "admin1", &[]).refused()),
        AdminRefusal::ValueInvalid
    );
    // A FILETIME beyond i64 cannot be stored (docs/46 §5.4: 0..i64::MAX).
    let op = Operation::SetAccountExpires(SetAccountExpires {
        target: guid(BOB),
        value: AccountExpiresValue::at(0x8000_0000_0000_0000),
    });
    assert_eq!(
        refusal_code(&d.run(op, "admin1", &[]).refused()),
        AdminRefusal::ValueInvalid
    );
}

/// docs/51 §5.2 rows 5, 6, 9 and A-18 / A-19 / A-35: krbtgt, the DC
/// account, the service objects, the NC root, the groups the policy names
/// (tier-map principals, the bootstrap group) and a tier-map subtree base
/// are never deleted; krbtgt / DC / service objects are never disabled,
/// expired, password-set or made members ([MS-SAMR] 3.1.1.6 item 22).
#[test]
fn protected_objects_are_refused() {
    let mut d = Domain::new("protected");
    let refused = |d: &mut Domain, op: Operation, approvers: &[&str]| {
        let r = d.run(op, "admin1", approvers).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::TargetProtected);
        assert_eq!(r.status(), RefusalStatus::Denied);
    };
    for target in [KRBTGT, DC01, LDAP_SVC, ADMIND_SVC] {
        refused(
            &mut d,
            Operation::SetEnabled(SetEnabled {
                target: guid(target),
                enabled: false,
            }),
            &["admin2"],
        );
        refused(
            &mut d,
            Operation::SetAccountExpires(SetAccountExpires {
                target: guid(target),
                value: AccountExpiresValue::NEVER,
            }),
            &["admin2"],
        );
        refused(
            &mut d,
            Operation::BeginPasswordSet {
                target: guid(target),
            },
            &["admin2"],
        );
        refused(
            &mut d,
            Operation::AddMember(Membership {
                group: guid(READERS),
                member: guid(target),
            }),
            &[],
        );
    }
    for target in [
        KRBTGT,
        DC01,
        LDAP_SVC,
        ADMIND_SVC,
        ROOT,
        TIER0_GROUP,
        HELPDESK,
        BOOTSTRAP,
        TIER0_OU,
        MANAGED_OU,
    ] {
        refused(
            &mut d,
            Operation::Delete {
                target: guid(target),
            },
            &["admin2"],
        );
    }
}

/// docs/51 §5.2 row 6: only the D bit changes — a computer stays WT, so ST
/// can never be set through the admin plane (A-79); enabling and disabling
/// round-trip.
#[test]
fn set_enabled_changes_only_the_disable_bit() {
    let mut d = Domain::new("enable");
    let uac_of = |d: &Domain, id: u32| {
        d.object(guid(id))
            .unwrap()
            .attribute(d.attr("userAccountControl"))
            .unwrap()
            .values[0]
            .value
            .clone()
    };
    let set = |target: u32, enabled: bool| {
        Operation::SetEnabled(SetEnabled {
            target: guid(target),
            enabled,
        })
    };
    let (_, applied) = d.run(set(WS01, false), "admin1", &[]).applied();
    assert_eq!(applied.reply(), &Reply::Done);
    assert_eq!(uac_of(&d, WS01), flags(0x0000_1000 | 0x0000_0002));
    d.run(set(WS01, true), "admin1", &[]).applied();
    assert_eq!(uac_of(&d, WS01), flags(0x0000_1000));
    d.run(set(BOB, false), "admin1", &[]).applied();
    assert_eq!(uac_of(&d, BOB), flags(0x0000_0200 | 0x0000_0002));
    // A group has no userAccountControl to toggle.
    let r = d.run(set(READERS, false), "admin1", &[]).refused();
    assert_eq!(refusal_code(&r), AdminRefusal::ValueInvalid);
}

/// docs/51 §5.2 row 7: "never" is written as 0x7FFFFFFFFFFFFFFF only
/// (R47-5b); a FILETIME is stored as given.
#[test]
fn set_account_expires_writes_never_or_the_filetime() {
    let mut d = Domain::new("expires");
    let value_of = |d: &Domain| {
        d.object(guid(BOB))
            .unwrap()
            .attribute(d.attr("accountExpires"))
            .unwrap()
            .values[0]
            .value
            .clone()
    };
    // 2027-01-01T00:00:00Z: 1970 → 2027 = 20 819 days = 1 798 761 600 s;
    // + 11 644 473 600 = 13 443 235 200 s; × 10^7.
    let in_2027: u64 = 134_432_352_000_000_000;
    let op = Operation::SetAccountExpires(SetAccountExpires {
        target: guid(BOB),
        value: AccountExpiresValue::at(in_2027),
    });
    d.run(op, "admin1", &[]).applied();
    assert_eq!(value_of(&d), int64(i64::try_from(in_2027).unwrap()));
    let op = Operation::SetAccountExpires(SetAccountExpires {
        target: guid(BOB),
        value: AccountExpiresValue::NEVER,
    });
    d.run(op, "admin1", &[]).applied();
    assert_eq!(value_of(&d), int64(i64::MAX));
}

/// [MS-SAMR] 3.1.1.8.9 (native mode) as decided in docs/51 §11 (Q-356 item
/// 1): an account group holds accounts and account groups of its security
/// kind; a resource group adds resource groups; a universal group holds
/// accounts, account and universal groups; nothing else is a member. Plus
/// the cycle refusal (docs/47 §5.3 item 4), "already a member" and "not a
/// member".
#[test]
fn membership_rules_are_enforced() {
    let mut d = Domain::new("membership");
    let new_group = |d: &mut Domain, sam: &str, gt: u32| {
        let (_, applied) = d
            .run(create_group(STAFF_OU, sam, Some(gt)), "admin1", &[])
            .applied();
        created(applied.reply()).0
    };
    let sec_account = new_group(&mut d, "sa", 0x8000_0002);
    let sec_account2 = new_group(&mut d, "sa2", 0x8000_0002);
    let dist_account = new_group(&mut d, "da", 0x0000_0002);
    let sec_resource = new_group(&mut d, "sr", 0x8000_0004);
    let sec_universal = new_group(&mut d, "su", 0x8000_0008);
    let add =
        |group: dtyp::Guid, member: dtyp::Guid| Operation::AddMember(Membership { group, member });
    let invalid = |d: &mut Domain, op: Operation| {
        let r = d.run(op, "admin1", &[]).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::MembershipInvalid);
        assert_eq!(r.status(), RefusalStatus::Invalid);
    };
    // Accounts (user, computer) everywhere.
    d.run(add(sec_account, guid(ALICE)), "admin1", &[])
        .applied();
    d.run(add(sec_account, guid(WS01)), "admin1", &[]).applied();
    d.run(add(sec_universal, guid(ALICE)), "admin1", &[])
        .applied();
    // Account group: account groups of its kind only.
    d.run(add(sec_account, sec_account2), "admin1", &[])
        .applied();
    invalid(&mut d, add(sec_account, dist_account));
    invalid(&mut d, add(sec_account, sec_resource));
    invalid(&mut d, add(sec_account, sec_universal));
    // Resource group: account and resource groups.
    d.run(add(sec_resource, sec_account), "admin1", &[])
        .applied();
    // Universal group: account or universal groups, never resource groups.
    d.run(add(sec_universal, sec_account), "admin1", &[])
        .applied();
    invalid(&mut d, add(sec_universal, sec_resource));
    // Not an account or a group.
    invalid(&mut d, add(sec_account, guid(STAFF_OU)));
    // Already a member; not a member.
    invalid(&mut d, add(sec_account, guid(ALICE)));
    invalid(
        &mut d,
        Operation::RemoveMember(Membership {
            group: sec_account,
            member: guid(BOB),
        }),
    );
    // Cycles: sa ∋ sa2, so sa2 ∋ sa closes one; a group in itself is one.
    invalid(&mut d, add(sec_account2, sec_account));
    invalid(&mut d, add(sec_account, sec_account));
    // The membership was written: alice is in sa.
    let members = d.object(sec_account).unwrap();
    let values = &members.attribute(d.attr("member")).unwrap().values;
    assert!(values.iter().any(|v| v.value == ref_to(ALICE)));
    // Removing works and leaves the rest.
    d.run(
        Operation::RemoveMember(Membership {
            group: sec_account,
            member: guid(ALICE),
        }),
        "admin1",
        &[],
    )
    .applied();
    let members = d.object(sec_account).unwrap();
    let values = &members.attribute(d.attr("member")).unwrap().values;
    assert!(!values.iter().any(|v| v.value == ref_to(ALICE)));
    assert!(values.iter().any(|v| v.value == ref_to(WS01)));
}

/// docs/51 §5.2 row 9 (A-18: a tombstone; references removed in the same
/// transaction — docs/46 §8.4); a container with live children cannot be
/// deleted.
#[test]
fn delete_tombstones_and_removes_references() {
    let mut d = Domain::new("delete");
    d.run(Operation::Delete { target: guid(BOB) }, "admin1", &[])
        .applied();
    assert!(d.object(guid(BOB)).is_none());
    let tombstone = d
        .store
        .snapshot()
        .unwrap()
        .get_tombstone(guid(BOB))
        .unwrap();
    assert!(tombstone.is_some());
    let readers = d.object(guid(READERS)).unwrap();
    assert!(!readers
        .attribute(d.attr("member"))
        .unwrap()
        .values
        .iter()
        .any(|v| v.value == ref_to(BOB)));
    let r = d
        .run(
            Operation::Delete {
                target: guid(STAFF_OU),
            },
            "admin1",
            &[],
        )
        .refused();
    assert_eq!(refusal_code(&r), AdminRefusal::Conflict);
}

/// docs/51 §5.2 row 10, §7.3: `Lookup` returns {GUID, DN, class, SID} when
/// `DirRead` allows; an object the requester cannot read is answered
/// exactly like an absent one (A-55: no existence oracle) — the event keeps
/// `NotVisible` apart from `NotFound` (crate ipc-audit, Q-340).
#[test]
fn lookup_finds_visible_objects_and_hides_the_rest() {
    let mut d = Domain::new("lookup");
    let found = |d: &mut Domain, key: LookupKey, who: &str| {
        let prepared = d.run(Operation::Lookup(key), who, &[]).read();
        assert!(!prepared.writes());
        match prepared.reply() {
            Some(Reply::Found(result)) => result.clone(),
            other => panic!("{other:?}"),
        }
    };
    let alice = found(&mut d, LookupKey::SamAccountName("alice".into()), "bob");
    assert_eq!(alice.guid, guid(ALICE));
    assert_eq!(
        alice.dn,
        dn(&["cn=alice", "ou=Staff", "dc=example", "dc=test"])
    );
    assert_eq!(alice.class, "user");
    assert_eq!(alice.sid, Some(sid_of(ALICE)));
    let ws01 = found(
        &mut d,
        LookupKey::ServicePrincipalName("host/ws01.example.test".into()),
        "bob",
    );
    assert_eq!(ws01.guid, guid(WS01));
    assert_eq!(ws01.class, "computer");
    let staff = found(&mut d, LookupKey::Dn(ou_dn("Staff")), "bob");
    assert_eq!(staff.guid, guid(STAFF_OU));
    assert_eq!(staff.sid, None);
    // The sAMAccountName is compared octet for octet after the index
    // (docs/47 §1.3 step 4): "ALICE" names nothing.
    let upper = d
        .run(
            Operation::Lookup(LookupKey::SamAccountName("ALICE".into())),
            "bob",
            &[],
        )
        .refused();
    assert_eq!(upper.status(), RefusalStatus::NotFound);
    // An administrator sees the hidden account.
    let secret = found(&mut d, LookupKey::SamAccountName("secret".into()), "admin1");
    assert_eq!(secret.guid, guid(SECRET));
    // bob cannot read it: the same NotFound as for a name nobody has.
    let hidden = d
        .run(
            Operation::Lookup(LookupKey::SamAccountName("secret".into())),
            "bob",
            &[],
        )
        .refused();
    let absent = d
        .run(
            Operation::Lookup(LookupKey::SamAccountName("nosuch".into())),
            "bob",
            &[],
        )
        .refused();
    assert_eq!(hidden.status(), RefusalStatus::NotFound);
    assert_eq!(absent.status(), hidden.status());
    assert_eq!(refusal_code(&hidden), AdminRefusal::NotVisible);
    assert_eq!(refusal_code(&absent), AdminRefusal::NotFound);
    // A write naming an invisible object is answered the same way.
    let r = d
        .run(
            Operation::SetEnabled(SetEnabled {
                target: guid(SECRET),
                enabled: false,
            }),
            "bob",
            &[],
        )
        .refused();
    assert_eq!(r.status(), RefusalStatus::NotFound);
    let r = d
        .run(
            Operation::SetEnabled(SetEnabled {
                target: guid(9999),
                enabled: false,
            }),
            "bob",
            &[],
        )
        .refused();
    assert_eq!(r.status(), RefusalStatus::NotFound);
}
