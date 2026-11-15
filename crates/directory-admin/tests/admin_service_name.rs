//! The admin service's name is a state rule of the directory (docs/52 R2b
//! follow-up; docs/questions/Q-541): no object but the admin service
//! object may carry a principal name from which the `AdminService` key-set
//! purpose derives (`admind/<host>`, by the one derivation
//! `KeyPurpose::of_service_name` — Q-491 item 1). Before, an ordinary
//! `CreateComputer` could create such an object; it failed closed only
//! because keyd would not make a key for it.
//!
//! - Attack: `CreateComputer` with the SPN `admind/<its host>` through the
//!   admin plane is refused at `prepare` (`ValueInvalid` — the code of the
//!   SPN rule, as for `krbtgt/<host>`) and nothing is stored. The write
//!   checker refuses the same object on the online path's call (no
//!   provisioning role): crate::invariants unit tests,
//!   `the_admin_service_name_is_the_admin_service_objects_alone`.
//! - Second line: a store that already holds such a computer (written
//!   beneath the checker, as a store from before the rule would) still gets
//!   no password-set target for it (`TargetProtected`, the R2b guard).
//!
//! Sources: docs/52 R2b; docs/questions/Q-491 items 1, 3, Q-541; docs/51
//! §5.2 row 2 (one SPN, `service "/" host`); A-73 (`admind/<fqdn>`).
//! Fixtures: tests/common; names and values are this project's test data.

mod common;

use common::*;
use directory_admin::{CreateComputer, Operation, RefusalStatus};
use dirstore::{NewObject, Origin};
use ipc_audit::{AdminRefusal, DecisionResult, DirAdminStage};

fn refusal_code(r: &directory_admin::Refusal) -> AdminRefusal {
    match r.event().stage {
        DirAdminStage::Decision(DecisionResult::Refused(code)) => code,
        other => panic!("not a decision refusal: {other:?}"),
    }
}

fn create_computer(name: &str, class: &str) -> Operation {
    let host = format!("{name}.example.test");
    Operation::CreateComputer(CreateComputer {
        parent: guid(STAFF_OU),
        name: name.into(),
        dns_host_name: host.clone(),
        spn: Some(format!("{class}/{host}")),
    })
}

/// Attack (Q-541): a computer named like the admin service is refused at
/// `prepare` with the SPN rule's code, like a `krbtgt/<host>` SPN; nothing
/// is stored — no object under the parent, no SPN in the unique index, the
/// change-seq counter unmoved. Another class on the same host is created.
#[test]
fn a_computer_cannot_take_the_admin_service_name() {
    let mut d = Domain::new("admind-name-create");
    let seq = |d: &Domain| {
        d.store
            .snapshot()
            .unwrap()
            .counter(directory_admin::CHANGE_SEQ_COUNTER)
            .unwrap()
            .unwrap()
            .next_value
    };
    let before = seq(&d);
    for (name, class) in [("ws07", "admind"), ("ws08", "krbtgt")] {
        let r = d.run(create_computer(name, class), "admin1", &[]).refused();
        assert_eq!(refusal_code(&r), AdminRefusal::ValueInvalid, "{class}");
        assert_eq!(r.status(), RefusalStatus::Invalid);
        let snapshot = d.store.snapshot().unwrap();
        assert_eq!(
            snapshot
                .lookup_child(Some(guid(STAFF_OU)), name.as_bytes())
                .unwrap(),
            None
        );
        assert_eq!(
            snapshot
                .lookup_unique(
                    d.attr("servicePrincipalName"),
                    format!("{class}/{name}.example.test").as_bytes()
                )
                .unwrap(),
            None
        );
    }
    assert_eq!(seq(&d), before, "nothing written");
    // The name is reserved, not the host: another class there is created.
    let (_, applied) = d
        .run(create_computer("ws07", "host"), "admin1", &[])
        .applied();
    assert!(matches!(
        applied.reply(),
        directory_admin::Reply::Created { .. }
    ));
}

/// Second line (docs/52 R2b; Q-491 item 3): a computer carrying the admin
/// service's name that is already in the store — written here beneath the
/// checker, as in a store from before the rule — gets no password-set
/// target: its service key set would be the `AdminService` one, never a
/// `set_secret` target, so `BeginPasswordSet` is `TargetProtected`.
#[test]
fn a_stored_admin_named_computer_gets_no_password_target() {
    let mut d = Domain::new("admind-name-stored");
    // ws01$ with another identity and the admin service's name.
    let ws01 = d.object(guid(WS01)).unwrap();
    let impostor = guid(90);
    let replaced = |name: &str| -> Option<Vec<Vec<u8>>> {
        let value = |s: &str| Some(vec![s.as_bytes().to_vec()]);
        match name {
            "cn" => value("ws09"),
            "sAMAccountName" => value("ws09$"),
            "dNSHostName" => value("ws09.example.test"),
            "servicePrincipalName" => value("admind/ws09.example.test"),
            "objectSid" => Some(vec![account_sid(FIRST_ADMIN_RID).encode()]),
            _ => None,
        }
    };
    let names = [
        "cn",
        "sAMAccountName",
        "dNSHostName",
        "servicePrincipalName",
        "objectSid",
    ];
    // A store from before the rule predates the principal namespace too
    // (task PN5): the copy holds no namespace key — ws01's would collide.
    let attributes = ws01
        .attributes
        .iter()
        .filter(|a| a.id != ad_schema::PRINCIPAL_NAME_KEY)
        .map(|a| {
            let named = names.iter().find(|n| d.attr(n) == a.id);
            let values = named
                .and_then(|n| replaced(n))
                .unwrap_or_else(|| a.values.iter().map(|v| v.value.clone()).collect());
            (a.id, values)
        })
        .collect();
    {
        let mut txn = d.store.begin_write().unwrap();
        let origin = Origin {
            wall_clock: directory_admin::wall_clock(&now()).unwrap(),
            origin_node: dirstore::NodeId([0x90; 16]),
            origin_seq: txn
                .take_counter_value(directory_admin::CHANGE_SEQ_COUNTER)
                .unwrap(),
        };
        txn.create_object(
            NewObject {
                guid: impostor,
                parent: ws01.parent,
                classes: ws01.classes.clone(),
                attributes,
            },
            &origin,
        )
        .unwrap();
        txn.commit().unwrap();
    }
    let r = d
        .run(
            Operation::BeginPasswordSet { target: impostor },
            "admin1",
            &[],
        )
        .refused();
    assert_eq!(refusal_code(&r), AdminRefusal::TargetProtected);
}
