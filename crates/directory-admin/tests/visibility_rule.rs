//! The admin plane's visibility rule (docs/questions/Q-485, decided): an
//! object a request names must be visible by [MS-ADTS] 5.1.3.3.6 — the
//! requester may list its parent, the LDAP search's rule — **and** readable
//! as a whole (`DirRead`, docs/51 §5.2 row 10). An object the LDAP search
//! would hide is answered exactly like an absent one, by `Lookup` and by
//! every operation that names it (A-55; docs/52 R10).
//!
//! The standard domain (tests/common), with two descriptors replaced
//! (this project's own test data): ou=Hidden grants the readers group read
//! (RP, RC) but **not** list (LC); secret, inside it, grants the readers
//! group read and list. bob (a reader) can therefore read secret's own
//! descriptor-protected data, but may not list its container: secret is not
//! visible to bob ([MS-ADTS] 5.1.3.3.6: "no child object of that container
//! is visible to the user").
//!
//! Sources: [MS-ADTS] v20261026 5.1.3.3.6; docs/51 §5.2 rows 6, 10, §7.3;
//! docs/11 §7; docs/49 §6.1 item 2; docs/questions/Q-485; A-55.

mod common;

use common::*;
use directory_admin::{
    wall_clock, LookupKey, Operation, RefusalStatus, Reply, SetEnabled, CHANGE_SEQ_COUNTER,
};
use dirstore::{AttributeChange, Origin};
use ipc_audit::{AdminRefusal, DecisionResult, DirAdminStage, PdpReasonCode};
use pdp::access_check::rights::{
    RIGHT_DS_LIST_CONTENTS, RIGHT_DS_READ_PROPERTY, RIGHT_READ_CONTROL,
};

fn refusal_code(r: &directory_admin::Refusal) -> AdminRefusal {
    match r.event().stage {
        DirAdminStage::Decision(DecisionResult::Refused(code)) => code,
        other => panic!("not a decision refusal: {other:?}"),
    }
}

/// Replace ou=Hidden's and secret's descriptors (module documentation),
/// in one committed transaction taking a change-seq like every writer.
fn readable_but_not_listable(d: &Domain) {
    let hidden_sd = sd_with(
        sid_of(TIER0_GROUP),
        vec![
            inheritable_allow(ADMIN_RIGHTS, sid_of(TIER0_GROUP)),
            inheritable_allow(RIGHT_DS_READ_PROPERTY | RIGHT_READ_CONTROL, sid_of(READERS)),
        ],
    );
    let secret_sd = sd_with(
        sid_of(TIER0_GROUP),
        vec![
            inheritable_allow(ADMIN_RIGHTS, sid_of(TIER0_GROUP)),
            inheritable_allow(
                RIGHT_DS_READ_PROPERTY | RIGHT_DS_LIST_CONTENTS | RIGHT_READ_CONTROL,
                sid_of(READERS),
            ),
        ],
    );
    let mut txn = d.store.begin_write().unwrap();
    for (id, descriptor) in [(HIDDEN_OU, hidden_sd), (SECRET, secret_sd)] {
        let origin = Origin {
            wall_clock: wall_clock(&now()).unwrap(),
            origin_node: NODE_ID,
            origin_seq: txn.take_counter_value(CHANGE_SEQ_COUNTER).unwrap(),
        };
        txn.modify_object(
            guid(id),
            vec![AttributeChange::Replace {
                id: d.attr("nTSecurityDescriptor"),
                values: vec![descriptor.encode().unwrap()],
            }],
            &origin,
        )
        .unwrap();
    }
    txn.commit().unwrap();
}

/// Q-485: `Lookup` of an object bob may read but whose container he may not
/// list is `NotFound` — the event says `NotVisible` with the PDP's reason
/// for the list question (`Acl` on ou=Hidden) — exactly as for a name nobody
/// has; the container itself, listable through the NC root, is found.
#[test]
fn lookup_hides_an_object_the_ldap_search_hides() {
    let mut d = Domain::new("visibility-rule-lookup");
    readable_but_not_listable(&d);
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
    assert_eq!(hidden.event().pdp.unwrap().code, PdpReasonCode::Acl);
    assert_eq!(refusal_code(&absent), AdminRefusal::NotFound);
    let container = d
        .run(
            Operation::Lookup(LookupKey::Dn(ou_dn("Hidden"))),
            "bob",
            &[],
        )
        .read();
    match container.reply() {
        Some(Reply::Found(found)) => assert_eq!(found.guid, guid(HIDDEN_OU)),
        other => panic!("{other:?}"),
    }
    // The Tier-0 administrators, who may list ou=Hidden, still find it.
    let secret = d
        .run(
            Operation::Lookup(LookupKey::SamAccountName("secret".into())),
            "admin1",
            &[],
        )
        .read();
    match secret.reply() {
        Some(Reply::Found(found)) => assert_eq!(found.guid, guid(SECRET)),
        other => panic!("{other:?}"),
    }
}

/// Q-485 ("and to every named-object check"): a write naming that object is
/// answered `NotFound` (`NotVisible` in the event) before its own decision,
/// exactly like a write naming an absent object — not `PolicyDenied`, which
/// would confirm that it exists.
#[test]
fn a_write_naming_it_is_not_found_before_its_own_decision() {
    let mut d = Domain::new("visibility-rule-write");
    readable_but_not_listable(&d);
    let set = |target: u32| {
        Operation::SetEnabled(SetEnabled {
            target: guid(target),
            enabled: false,
        })
    };
    let hidden = d.run(set(SECRET), "bob", &[]).refused();
    let absent = d.run(set(9999), "bob", &[]).refused();
    assert_eq!(hidden.status(), RefusalStatus::NotFound);
    assert_eq!(absent.status(), RefusalStatus::NotFound);
    assert_eq!(refusal_code(&hidden), AdminRefusal::NotVisible);
    assert_eq!(hidden.event().pdp.unwrap().code, PdpReasonCode::Acl);
    assert_eq!(refusal_code(&absent), AdminRefusal::NotFound);
}
