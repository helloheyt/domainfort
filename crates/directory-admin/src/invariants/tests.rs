//! Unit tests of the write invariants (docs/52 R13): the named exceptions
//! exist only in the provisioning session and only on an empty store; the
//! ordinary rules refuse every exception state; a checked write commits
//! only against the state it was checked on; a link proof is accepted only
//! for that state; the closure bound holds on the provisioning-style check
//! (`check_create` against the transaction, as `Provisioning::create` and
//! the online `apply` call it); structural objects are never changed.
//!
//! Sources: docs/52 §3.14, §7 (R13); docs/51 §4.3 step 5, §5.2 row 9, §8.3,
//! §11; [MS-SAMR] v20260427 2.2.1.14, 3.1.1.6 items 14, 20-23, 3.1.1.9.2;
//! docs/47 §5.3 items 3-4 (MAX_EXPANDED_GROUPS = 1024, cycle refusal);
//! A-83. Fixtures are written here, some beneath the checker (this file is
//! test code — tests/single_write_path.rs does not scan it). The SID layout
//! S-1-5-21-1-2-3-<RID> is this project's test layout; names and values are
//! this project's own test data.

use std::path::PathBuf;

use ad_schema::flags::group_type::{GROUP_TYPE_ACCOUNT_GROUP, GROUP_TYPE_SECURITY_ENABLED};
use ad_schema::flags::user_account_control::{
    ADS_UF_ACCOUNT_DISABLE, ADS_UF_NORMAL_ACCOUNT, ADS_UF_SERVER_TRUST_ACCOUNT,
    ADS_UF_WORKSTATION_TRUST_ACCOUNT,
};
use ad_schema::{phase1, Phase1Schema};
use dirstore::{AttributeChange, IntegrityKey, NewObject, NodeId, Origin, Store, Timestamp};
use dtyp::{
    AccessMask, Ace, Acl, Control, Guid, MaskSidAce, SecurityDescriptor, Sid, ACL_REVISION_DS,
    SECURITY_NT_AUTHORITY,
};

use super::*;
use crate::record::{encode_flags, encode_int64, encode_ref};

/// A store file under the system's temporary directory, removed on drop.
struct TempStore {
    dir: PathBuf,
    store: Store,
}

impl TempStore {
    fn new(tag: &str) -> TempStore {
        let dir = std::env::temp_dir().join(format!(
            "directory-admin-invariants-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(
            dir.join("store.redb"),
            IntegrityKey::from_bytes(&[0x5C; 32]),
            p1().schema().clone(),
        )
        .unwrap();
        TempStore { dir, store }
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn p1() -> Phase1Schema {
    phase1().unwrap()
}

fn ids() -> Ids {
    Ids::resolve(&p1()).unwrap()
}

fn guid(n: u8) -> Guid {
    Guid::from_packet(&[n; 16])
}

fn domain() -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3]).unwrap()
}

fn sid(rid: u32) -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, rid]).unwrap()
}

const WALL: Timestamp = Timestamp(13_400_000_000);
const NODE: NodeId = NodeId([0x5C; 16]);

fn text(s: &str) -> Vec<Vec<u8>> {
    vec![s.as_bytes().to_vec()]
}

/// A minimal self-relative descriptor (owner = group = a test SID, one
/// allow ACE) — the checker has no descriptor rule; dirstore checks its
/// form. Spec: [MS-DTYP] 2.4.6 (as crate dtyp implements it).
fn descriptor() -> Vec<u8> {
    let owner = sid(1000);
    SecurityDescriptor {
        sbz1: 0,
        control: Control(Control::SELF_RELATIVE | Control::DACL_PRESENT),
        owner_sid: Some(owner),
        group_sid: Some(owner),
        sacl: None,
        dacl: Some(Acl {
            acl_revision: ACL_REVISION_DS,
            aces: vec![Ace::AccessAllowed(MaskSidAce {
                ace_flags: 0,
                mask: AccessMask(0x10),
                sid: owner,
            })],
        }),
    }
    .encode()
    .unwrap()
}

/// The values every object of these tests carries: the stamps and a
/// descriptor.
fn common(ids: &Ids) -> Vec<(AttrId, Vec<Vec<u8>>)> {
    vec![
        (ids.when_created, vec![encode_int64(1)]),
        (ids.when_changed, vec![encode_int64(1)]),
        (ids.nt_security_descriptor, vec![descriptor()]),
    ]
}

fn root(ids: &Ids) -> NewObject {
    let mut attributes = vec![
        (ids.dc, text("example")),
        (ids.object_sid, vec![domain().encode()]),
    ];
    attributes.extend(common(ids));
    NewObject {
        guid: guid(1),
        parent: None,
        classes: ids.domain_dns.chain.clone(),
        attributes,
    }
}

fn ou(ids: &Ids, g: Guid, parent: Guid, name: &str) -> NewObject {
    let mut attributes = vec![(ids.ou, text(name))];
    attributes.extend(common(ids));
    NewObject {
        guid: g,
        parent: Some(parent),
        classes: ids.organizational_unit.chain.clone(),
        attributes,
    }
}

fn user(ids: &Ids, g: Guid, parent: Guid, sam: &str, uac: u32) -> NewObject {
    let mut attributes = vec![
        (ids.cn, text(sam)),
        (ids.sam_account_name, text(sam)),
        (ids.user_account_control, vec![encode_flags(uac)]),
        (ids.account_expires, vec![encode_int64(i64::MAX)]),
    ];
    attributes.extend(common(ids));
    NewObject {
        guid: g,
        parent: Some(parent),
        classes: ids.user.chain.clone(),
        attributes,
    }
}

fn computer(ids: &Ids, g: Guid, parent: Guid, name: &str, uac: u32) -> NewObject {
    let mut attributes = vec![
        (ids.cn, text(name)),
        (ids.sam_account_name, text(&format!("{name}$"))),
        (ids.user_account_control, vec![encode_flags(uac)]),
        (ids.account_expires, vec![encode_int64(i64::MAX)]),
        (ids.dns_host_name, text("dc01.example.test")),
    ];
    attributes.extend(common(ids));
    NewObject {
        guid: g,
        parent: Some(parent),
        classes: ids.computer.chain.clone(),
        attributes,
    }
}

fn group(ids: &Ids, g: Guid, parent: Guid, sam: &str, members: &[Guid]) -> NewObject {
    let mut attributes = vec![
        (ids.cn, text(sam)),
        (ids.sam_account_name, text(sam)),
        (
            ids.group_type,
            vec![encode_flags(
                GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_ACCOUNT_GROUP,
            )],
        ),
    ];
    if !members.is_empty() {
        attributes.push((ids.member, members.iter().map(|m| encode_ref(*m)).collect()));
    }
    attributes.extend(common(ids));
    NewObject {
        guid: g,
        parent: Some(parent),
        classes: ids.group.chain.clone(),
        attributes,
    }
}

const OU: u8 = 2;

/// A session with the NC root and one OU.
fn begin<'t, 's>(txn: &'t mut WriteTxn<'s>) -> Provisioning<'t, 's> {
    let ids = ids();
    let mut session = Provisioning::begin(txn, &p1(), WALL, NODE).unwrap();
    session
        .create(Some(ProvisioningRole::NamingContextRoot), root(&ids))
        .unwrap();
    session
        .create(None, ou(&ids, guid(OU), guid(1), "Staff"))
        .unwrap();
    session
}

fn rule(r: Result<(), ProvisioningError>) -> InvariantViolation {
    match r {
        Err(ProvisioningError::Invariant(v)) => v,
        other => panic!("{other:?}"),
    }
}

/// A-83; module provisioning: a store that already holds a counter (any
/// provisioned store) cannot open a session — no exception can be claimed
/// against it.
#[test]
fn provisioning_needs_an_empty_store() {
    let t = TempStore::new("empty");
    {
        let mut txn = t.store.begin_write().unwrap();
        txn.create_counter(CHANGE_SEQ_COUNTER, 1, u64::MAX).unwrap();
        txn.commit().unwrap();
    }
    let mut txn = t.store.begin_write().unwrap();
    assert!(matches!(
        Provisioning::begin(&mut txn, &p1(), WALL, NODE),
        Err(ProvisioningError::NotEmpty)
    ));
}

/// docs/51 §11; [MS-SAMR] 3.1.1.6 items 14, 20-23; docs/46 §4.4: without a
/// claim — the ordinary rules, exactly what the online `apply` asks — the
/// states only provisioning creates are refused: a domainDNS, ST, the name
/// "krbtgt", RID 502; and a claim must fit its class.
#[test]
fn the_exception_states_are_refused_without_their_claim() {
    let ids = ids();
    let t = TempStore::new("exceptions");
    let mut txn = t.store.begin_write().unwrap();
    let mut s = begin(&mut txn);
    let mut second_root = root(&ids);
    second_root.guid = guid(9);
    second_root.parent = Some(guid(OU));
    assert_eq!(rule(s.create(None, second_root)), InvariantViolation::Class);
    let dc = computer(
        &ids,
        guid(10),
        guid(OU),
        "dc01",
        ADS_UF_SERVER_TRUST_ACCOUNT,
    );
    assert_eq!(rule(s.create(None, dc)), InvariantViolation::AccountControl);
    let named = user(&ids, guid(11), guid(OU), "krbtgt", ADS_UF_NORMAL_ACCOUNT);
    assert_eq!(
        rule(s.create(None, named)),
        InvariantViolation::ReservedName
    );
    let mut rid_502 = user(&ids, guid(12), guid(OU), "tgs", ADS_UF_NORMAL_ACCOUNT);
    rid_502
        .attributes
        .push((ids.object_sid, vec![sid(0x1F6).encode()]));
    assert!(matches!(
        s.create(None, rid_502),
        Err(ProvisioningError::SidMismatch)
    ));
    let wrong_class = computer(
        &ids,
        guid(13),
        guid(OU),
        "tgs",
        ADS_UF_WORKSTATION_TRUST_ACCOUNT,
    );
    assert_eq!(
        rule(s.create(Some(ProvisioningRole::Krbtgt), wrong_class)),
        InvariantViolation::Exception
    );
    // With their claims they pass, each once.
    let krbtgt = user(&ids, guid(14), guid(OU), "krbtgt", ADS_UF_NORMAL_ACCOUNT);
    s.create(Some(ProvisioningRole::Krbtgt), krbtgt).unwrap();
    let dc = computer(
        &ids,
        guid(15),
        guid(OU),
        "dc01",
        ADS_UF_SERVER_TRUST_ACCOUNT,
    );
    s.create(Some(ProvisioningRole::DcAccount), dc).unwrap();
    let dc2 = computer(
        &ids,
        guid(16),
        guid(OU),
        "dc02",
        ADS_UF_SERVER_TRUST_ACCOUNT,
    );
    assert_eq!(
        rule(s.create(Some(ProvisioningRole::DcAccount), dc2)),
        InvariantViolation::Exception
    );
}

/// docs/51 §8.3; [MS-SAMR] 3.1.1.9.2: the commit takes the RID and the
/// change-seq; the objectSid is the domain SID ‖ the RID handed out; the
/// write's stamp carries the change-seq taken.
#[test]
fn the_commit_takes_the_rid_and_the_change_seq() {
    let ids = ids();
    let t = TempStore::new("allocate");
    let mut txn = t.store.begin_write().unwrap();
    begin(&mut txn);
    let inv = Invariants::new(&p1(), BTreeSet::new()).unwrap();
    let seq = txn.counter(CHANGE_SEQ_COUNTER).unwrap().unwrap().next_value;
    let checked = inv
        .check_create(
            &txn,
            user(&ids, guid(20), guid(OU), "alice", ADS_UF_NORMAL_ACCOUNT),
            None,
            &[],
        )
        .unwrap();
    let committed = checked.commit(&mut txn, WALL, NODE).unwrap();
    assert_eq!(committed.rid, Some(1101));
    assert_eq!(committed.sid, Some(sid(1101)));
    let alice = txn.get_object(guid(20)).unwrap().unwrap();
    assert_eq!(
        record::sid(&alice, ids.object_sid).unwrap(),
        Some(sid(1101))
    );
    let stamp = alice.attribute(ids.cn).unwrap().values[0].stamp;
    assert_eq!(stamp.origin_seq, seq);
    assert_eq!(stamp.origin_node, NODE);
}

/// Module documentation: a checked write commits only against the state it
/// was checked on — another write in between makes it stale.
#[test]
fn a_checked_write_is_stale_after_another_write() {
    let ids = ids();
    let t = TempStore::new("stale");
    let mut txn = t.store.begin_write().unwrap();
    begin(&mut txn);
    let inv = Invariants::new(&p1(), BTreeSet::new()).unwrap();
    let first = inv
        .check_create(&txn, ou(&ids, guid(30), guid(1), "A"), None, &[])
        .unwrap();
    let second = inv
        .check_create(&txn, ou(&ids, guid(31), guid(1), "B"), None, &[])
        .unwrap();
    second.commit(&mut txn, WALL, NODE).unwrap();
    assert!(matches!(
        first.commit(&mut txn, WALL, NODE),
        Err(CommitError::Stale)
    ));
    assert!(txn.get_object(guid(30)).unwrap().is_none());
}

/// docs/47 §5.3 item 4; module documentation ("Links checked once"): a
/// link proof answers only for the state it was taken in — after
/// `g2 ∋ g1` is written, the proof of `g1 ∋ g2` taken before is not
/// accepted, the walks run again, and the cycle is refused.
#[test]
fn a_link_proof_of_another_state_is_not_accepted() {
    let ids = ids();
    let t = TempStore::new("proof");
    let mut txn = t.store.begin_write().unwrap();
    {
        let mut s = begin(&mut txn);
        s.create(None, group(&ids, guid(40), guid(OU), "g1", &[]))
            .unwrap();
        s.create(None, group(&ids, guid(41), guid(OU), "g2", &[]))
            .unwrap();
    }
    let inv = Invariants::new(&p1(), BTreeSet::new()).unwrap();
    let g1 = txn.get_object(guid(40)).unwrap().unwrap();
    let g2 = txn.get_object(guid(41)).unwrap().unwrap();
    let group_type = GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_ACCOUNT_GROUP;
    let proof = inv
        .check_link(
            &txn,
            End {
                guid: guid(40),
                obj: &g1,
            },
            group_type,
            End {
                guid: guid(41),
                obj: &g2,
            },
            ids.group.id,
            0,
        )
        .unwrap()
        .unwrap();
    let member = |g: Guid| {
        vec![AttributeChange::Replace {
            id: ids.member,
            values: vec![encode_ref(g)],
        }]
    };
    inv.check_modify(&txn, guid(41), member(guid(40)), &[])
        .unwrap()
        .commit(&mut txn, WALL, NODE)
        .unwrap();
    assert!(matches!(
        inv.check_modify(&txn, guid(40), member(guid(41)), &[proof]),
        Err(Refused::Rule(InvariantViolation::Membership))
    ));
}

/// docs/47 §5.3 items 1, 3 (MAX_EXPANDED_GROUPS = 1024; A-95): on the
/// provisioning-style check (`check_create` against the transaction), a
/// new group that would be the 1024th in an account's closure is admitted
/// and the 1025th refused. The 1023 groups are written beneath the checker.
#[test]
fn the_closure_bound_holds_at_the_write() {
    let ids = ids();
    let t = TempStore::new("closure");
    let mut txn = t.store.begin_write().unwrap();
    {
        let mut s = begin(&mut txn);
        s.create(
            None,
            user(&ids, guid(50), guid(OU), "alice", ADS_UF_NORMAL_ACCOUNT),
        )
        .unwrap();
    }
    let packet = |n: u32| {
        let mut p = [0x77u8; 16];
        p[12..].copy_from_slice(&n.to_be_bytes());
        Guid::from_packet(&p)
    };
    let beneath = |txn: &mut WriteTxn<'_>, n: u32| {
        let mut g = group(&ids, packet(n), guid(OU), &format!("g{n}"), &[guid(50)]);
        g.attributes
            .push((ids.object_sid, vec![sid(20_000 + n).encode()]));
        let origin = Origin {
            wall_clock: WALL,
            origin_node: NODE,
            origin_seq: txn.take_counter_value(CHANGE_SEQ_COUNTER).unwrap(),
        };
        txn.create_object(g, &origin).unwrap();
    };
    for n in 1..=1022 {
        beneath(&mut txn, n);
    }
    let inv = Invariants::new(&p1(), BTreeSet::new()).unwrap();
    // 1022 groups + the new one = 1023 ≤ 1024.
    inv.check_create(
        &txn,
        group(&ids, packet(5000), guid(OU), "x", &[guid(50)]),
        None,
        &[],
    )
    .unwrap();
    beneath(&mut txn, 1023);
    // 1023 + the new one = 1024: admitted (exactly at the bound).
    inv.check_create(
        &txn,
        group(&ids, packet(5001), guid(OU), "y", &[guid(50)]),
        None,
        &[],
    )
    .unwrap();
    beneath(&mut txn, 1024);
    // 1024 + the new one = 1025: refused.
    assert!(matches!(
        inv.check_create(
            &txn,
            group(&ids, packet(5002), guid(OU), "z", &[guid(50)]),
            None,
            &[],
        ),
        Err(Refused::Rule(InvariantViolation::Membership))
    ));
}

/// docs/51 §5.2 rows 6-9; [MS-SAMR] 3.1.1.6 items 21-22; Q-356 item 2: a
/// structural object is never changed or deleted; a change names only the
/// attributes an operation writes, and userAccountControl changes in
/// ACCOUNTDISABLE only.
#[test]
fn structural_objects_and_unwritten_attributes_are_refused() {
    let ids = ids();
    let t = TempStore::new("structural");
    let mut txn = t.store.begin_write().unwrap();
    {
        let mut s = begin(&mut txn);
        s.create(
            Some(ProvisioningRole::Krbtgt),
            user(&ids, guid(60), guid(OU), "krbtgt", ADS_UF_NORMAL_ACCOUNT),
        )
        .unwrap();
        s.create(
            Some(ProvisioningRole::DcAccount),
            computer(
                &ids,
                guid(61),
                guid(OU),
                "dc01",
                ADS_UF_SERVER_TRUST_ACCOUNT,
            ),
        )
        .unwrap();
        s.create(
            None,
            user(
                &ids,
                guid(62),
                guid(OU),
                "bob",
                ADS_UF_NORMAL_ACCOUNT | ADS_UF_ACCOUNT_DISABLE,
            ),
        )
        .unwrap();
    }
    let inv = Invariants::new(&p1(), BTreeSet::new()).unwrap();
    let uac = |v: u32| {
        vec![AttributeChange::Replace {
            id: ids.user_account_control,
            values: vec![encode_flags(v)],
        }]
    };
    let is = |r: Result<CheckedWrite, Refused>, v: InvariantViolation| {
        assert!(matches!(r, Err(Refused::Rule(got)) if got == v), "{r:?}");
    };
    is(
        inv.check_modify(
            &txn,
            guid(60),
            uac(ADS_UF_NORMAL_ACCOUNT | ADS_UF_ACCOUNT_DISABLE),
            &[],
        ),
        InvariantViolation::Protected,
    );
    is(
        inv.check_delete(&txn, guid(61)),
        InvariantViolation::Protected,
    );
    is(
        inv.check_delete(&txn, guid(1)),
        InvariantViolation::Protected,
    );
    is(
        inv.check_modify(&txn, guid(62), uac(ADS_UF_WORKSTATION_TRUST_ACCOUNT), &[]),
        InvariantViolation::AccountControl,
    );
    is(
        inv.check_modify(
            &txn,
            guid(62),
            vec![AttributeChange::Replace {
                id: ids.sam_account_name,
                values: text("robert"),
            }],
            &[],
        ),
        InvariantViolation::NotModifiable,
    );
    // Enabling bob changes ACCOUNTDISABLE only: admitted.
    inv.check_modify(&txn, guid(62), uac(ADS_UF_NORMAL_ACCOUNT), &[])
        .unwrap();
}

/// A computer `name$` on `host`, WT without pwdLastSet (a service object's
/// shape), with the servicePrincipalName `spn` if any.
fn service(ids: &Ids, g: Guid, name: &str, host: &str, spn: Option<&str>) -> NewObject {
    let mut object = computer(ids, g, guid(OU), name, ADS_UF_WORKSTATION_TRUST_ACCOUNT);
    for (id, values) in &mut object.attributes {
        if *id == ids.dns_host_name {
            *values = text(host);
        }
    }
    if let Some(spn) = spn {
        object
            .attributes
            .push((ids.service_principal_name, text(spn)));
    }
    object
}

/// docs/52 R2b follow-up; docs/questions/Q-491 item 1, Q-541; A-73: a
/// principal name from which the admin service's key-set purpose derives
/// (`admind/<host>`) is the admin service object's alone. On the online
/// path's call (no role — what `apply` asks) and under the plain
/// service-object claim it is refused (`Value`, the SPN rule's code); a
/// user carrying it is refused too (the rule is judged on every object);
/// the admin service's claim on an object without that name is
/// `Exception`; the claim with it passes once — a second admin service
/// object is `Exception`; the LDAP service object is unaffected; no write
/// path changes an SPN afterwards (`NotModifiable`). Nothing refused is
/// written.
#[test]
fn the_admin_service_name_is_the_admin_service_objects_alone() {
    let ids = ids();
    let t = TempStore::new("admind-name");
    let mut txn = t.store.begin_write().unwrap();
    let host = "dc01.example.test";
    let admind = "admind/dc01.example.test";
    {
        let mut s = begin(&mut txn);
        assert_eq!(
            rule(s.create(None, service(&ids, guid(70), "ws70", host, Some(admind)))),
            InvariantViolation::Value
        );
        assert_eq!(
            rule(s.create(
                Some(ProvisioningRole::ServiceObject),
                service(&ids, guid(70), "ws70", host, Some(admind))
            )),
            InvariantViolation::Value
        );
        let mut named_user = user(&ids, guid(71), guid(OU), "carol", ADS_UF_NORMAL_ACCOUNT);
        named_user
            .attributes
            .push((ids.service_principal_name, text(admind)));
        assert_eq!(rule(s.create(None, named_user)), InvariantViolation::Value);
        for spn in [Some("ldap/dc01.example.test"), None] {
            assert_eq!(
                rule(s.create(
                    Some(ProvisioningRole::AdminServiceObject),
                    service(&ids, guid(72), "adm72", host, spn)
                )),
                InvariantViolation::Exception
            );
        }
        // The two real service objects.
        s.create(
            Some(ProvisioningRole::ServiceObject),
            service(
                &ids,
                guid(73),
                "ldap-svc",
                host,
                Some("ldap/dc01.example.test"),
            ),
        )
        .unwrap();
        s.create(
            Some(ProvisioningRole::AdminServiceObject),
            service(&ids, guid(74), "admind-svc", host, Some(admind)),
        )
        .unwrap();
        // A second admin service object, even on another host.
        assert_eq!(
            rule(s.create(
                Some(ProvisioningRole::AdminServiceObject),
                service(
                    &ids,
                    guid(75),
                    "admind2",
                    "dc02.example.test",
                    Some("admind/dc02.example.test")
                )
            )),
            InvariantViolation::Exception
        );
        s.create(
            None,
            service(&ids, guid(76), "ws76", host, Some("host/dc01.example.test")),
        )
        .unwrap();
    }
    for refused in [70, 71, 72, 75] {
        assert_eq!(StoreRead::object(&txn, guid(refused)).unwrap(), None);
    }
    assert!(StoreRead::object(&txn, guid(74)).unwrap().is_some());
    let inv = Invariants::new(&p1(), BTreeSet::new()).unwrap();
    let renamed = inv.check_modify(
        &txn,
        guid(76),
        vec![AttributeChange::Replace {
            id: ids.service_principal_name,
            values: text(admind),
        }],
        &[],
    );
    assert!(
        matches!(
            renamed,
            Err(Refused::Rule(InvariantViolation::NotModifiable))
        ),
        "{renamed:?}"
    );
}

/// Task K9 (docs/53 R53-6, §5.2, §10; RFC 3244 §2 "the service principal
/// kadmin/changepw@REALM"; docs/questions/Q-964 item 13, Q-972): the
/// change-password service's name is the change-password service object's
/// alone, as the admin service's is the admin service object's (Q-541). On
/// the online path's call (no role) it is refused (`Value`) even on a
/// computer whose dNSHostName is "changepw" (the one host its shape would
/// fit), under the plain service-object and the admin-service claims too;
/// the claim on an object without that name (another SPN, `kadmin/<host>`,
/// none) is `Exception`; the claim with it passes once — the object's
/// dNSHostName is the DC's host, the SPN's second component a fixed instance
/// (RFC 4120 §6.2) — and a second claim is `Exception`. The admin service
/// object still passes beside it. Nothing refused is written.
#[test]
fn the_change_password_service_name_is_its_objects_alone() {
    let ids = ids();
    let t = TempStore::new("changepw-name");
    let mut txn = t.store.begin_write().unwrap();
    let host = "dc01.example.test";
    let changepw = "kadmin/changepw";
    {
        let mut s = begin(&mut txn);
        assert_eq!(
            rule(s.create(
                None,
                service(&ids, guid(80), "ws80", "changepw", Some(changepw))
            )),
            InvariantViolation::Value
        );
        for claim in [
            ProvisioningRole::ServiceObject,
            ProvisioningRole::AdminServiceObject,
        ] {
            assert_eq!(
                rule(s.create(
                    Some(claim),
                    service(&ids, guid(80), "ws80", host, Some(changepw))
                )),
                InvariantViolation::Value,
                "{claim:?}"
            );
        }
        for spn in [
            Some("ldap/dc01.example.test"),
            Some("kadmin/dc01.example.test"),
            None,
        ] {
            assert_eq!(
                rule(s.create(
                    Some(ProvisioningRole::ChangePasswordServiceObject),
                    service(&ids, guid(81), "cpw81", host, spn)
                )),
                InvariantViolation::Exception,
                "{spn:?}"
            );
        }
        s.create(
            Some(ProvisioningRole::ChangePasswordServiceObject),
            service(&ids, guid(82), "changepw-svc", host, Some(changepw)),
        )
        .unwrap();
        s.create(
            Some(ProvisioningRole::AdminServiceObject),
            service(
                &ids,
                guid(83),
                "admind-svc",
                host,
                Some("admind/dc01.example.test"),
            ),
        )
        .unwrap();
        assert_eq!(
            rule(s.create(
                Some(ProvisioningRole::ChangePasswordServiceObject),
                service(&ids, guid(84), "changepw2", host, Some(changepw))
            )),
            InvariantViolation::Exception
        );
    }
    for refused in [80, 81, 84] {
        assert_eq!(StoreRead::object(&txn, guid(refused)).unwrap(), None);
    }
    assert!(StoreRead::object(&txn, guid(82)).unwrap().is_some());
    assert!(StoreRead::object(&txn, guid(83)).unwrap().is_some());
}
