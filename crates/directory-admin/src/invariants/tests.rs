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
use crate::config::{
    PRINCIPAL_NAMESPACE_COUNTER, PRINCIPAL_NAMESPACE_END_EXCLUSIVE, PRINCIPAL_NAMESPACE_FIRST,
};
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
/// The stamp of every object write committed here.
const STAMP: Option<WriteStamp> = Some(WriteStamp {
    wall_clock: WALL,
    origin_node: NODE,
});

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

/// The naming context dc=example,dc=test (A-53): the realm EXAMPLE.TEST,
/// whose one namespace alias is `example.test` (task PN5).
fn naming_context() -> directory_pip::NamingContext {
    directory_pip::NamingContext::new(&["example", "test"]).unwrap()
}

/// The principal namespace of [`naming_context`] (task PN5).
fn names() -> Option<NameContext> {
    Some(directory_pip::name_context_of(&naming_context()).unwrap())
}

/// A session in [`naming_context`]'s namespace (no zone) with the NC root
/// and one OU.
fn begin<'t, 's>(txn: &'t mut WriteTxn<'s>) -> Provisioning<'t, 's> {
    let ids = ids();
    let mut session = Provisioning::begin(txn, &p1(), WALL, NODE)
        .unwrap()
        .with_naming_context(&naming_context());
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
    let inv = Invariants::new(&p1(), BTreeSet::new(), None, names()).unwrap();
    let seq = txn.counter(CHANGE_SEQ_COUNTER).unwrap().unwrap().next_value;
    let checked = inv
        .check_create(
            &txn,
            user(&ids, guid(20), guid(OU), "alice", ADS_UF_NORMAL_ACCOUNT),
            None,
            &[],
        )
        .unwrap();
    let committed = checked.commit(&mut txn, STAMP).unwrap();
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
    let inv = Invariants::new(&p1(), BTreeSet::new(), None, names()).unwrap();
    let first = inv
        .check_create(&txn, ou(&ids, guid(30), guid(1), "A"), None, &[])
        .unwrap();
    let second = inv
        .check_create(&txn, ou(&ids, guid(31), guid(1), "B"), None, &[])
        .unwrap();
    second.commit(&mut txn, STAMP).unwrap();
    assert!(matches!(
        first.commit(&mut txn, STAMP),
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
    let inv = Invariants::new(&p1(), BTreeSet::new(), None, names()).unwrap();
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
        .commit(&mut txn, STAMP)
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
    let inv = Invariants::new(&p1(), BTreeSet::new(), None, names()).unwrap();
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
    let inv = Invariants::new(&p1(), BTreeSet::new(), None, names()).unwrap();
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

/// The DC account `dc01$` on `dc01.example.test` (ST, the `DcAccount`
/// claim's shape): its dNSHostName is `<computerName>.<realm DNS name>`
/// (task PN6, rule N6) and the one host name the session's service objects
/// may carry (Q-1010 item 3).
fn dc_account(ids: &Ids, g: Guid) -> NewObject {
    computer(ids, g, guid(OU), "dc01", ADS_UF_SERVER_TRUST_ACCOUNT)
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
        // The DC account whose host name the service objects carry (task
        // PN6: the session's rule — Q-1010 item 3).
        s.create(
            Some(ProvisioningRole::DcAccount),
            dc_account(&ids, guid(77)),
        )
        .unwrap();
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
            service(
                &ids,
                guid(76),
                "ws76",
                "ws76.example.test",
                Some("host/ws76.example.test"),
            ),
        )
        .unwrap();
    }
    for refused in [70, 71, 72, 75] {
        assert_eq!(StoreRead::object(&txn, guid(refused)).unwrap(), None);
    }
    assert!(StoreRead::object(&txn, guid(74)).unwrap().is_some());
    let inv = Invariants::new(&p1(), BTreeSet::new(), None, names()).unwrap();
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
        // The DC account whose host name the service objects carry (task
        // PN6: the session's rule — Q-1010 item 3).
        s.create(
            Some(ProvisioningRole::DcAccount),
            dc_account(&ids, guid(85)),
        )
        .unwrap();
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

/// Task DN6; docs/54 §5.4, R54-12; A-83: the provisioning session creates
/// the zone serial counter with the other two (first value 1), and refuses
/// a store that already holds it.
#[test]
fn provisioning_creates_the_zone_serial_counter() {
    let t = TempStore::new("zone-serial");
    {
        let mut txn = t.store.begin_write().unwrap();
        begin(&mut txn);
        let state = txn.counter(DNS_ZONE_SERIAL_COUNTER).unwrap().unwrap();
        assert_eq!(state.first_value, 1);
        assert_eq!(state.next_value, 1);
        assert_eq!(state.end_exclusive, u64::MAX);
        txn.commit().unwrap();
    }
    let t = TempStore::new("zone-serial-only");
    {
        let mut txn = t.store.begin_write().unwrap();
        txn.create_counter(DNS_ZONE_SERIAL_COUNTER, 1, u64::MAX)
            .unwrap();
        txn.commit().unwrap();
    }
    let mut txn = t.store.begin_write().unwrap();
    assert!(matches!(
        Provisioning::begin(&mut txn, &p1(), WALL, NODE),
        Err(ProvisioningError::NotEmpty)
    ));
}

/// The zone of the host-record tests: example.test, 192.0.2.0/24 (this
/// project's test data).
fn zone() -> HostZone {
    HostZone {
        zone: "example.test".into(),
        networks: vec![config::Network::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 0)),
            24,
        )
        .unwrap()],
    }
}

/// A computer named `name` with dNSHostName `host` (online shape, WT).
fn host_computer(ids: &Ids, g: Guid, name: &str, host: &str) -> NewObject {
    let mut c = computer(ids, g, guid(OU), name, ADS_UF_WORKSTATION_TRUST_ACCOUNT);
    for (id, values) in c.attributes.iter_mut() {
        if *id == ids.dns_host_name {
            *values = text(host);
        }
    }
    c
}

/// Task DN6 (docs/54 §5.2, §5.3, §5.5; Q-614 items 2, 3, 8; [MS-ADTS]
/// 3.1.1.5.3.1.1.2; RFC 1035 §2.3.1, §3.4.1): the host-record state rule
/// on the record a create would produce — a computer whose names give one
/// LDH host label `<computerName>.<zone>`, at most eight registrable 4-octet
/// addresses, never on a user or a service object, and never without a
/// zone (the provisioning session has none yet: fail closed).
#[test]
fn the_host_record_rule() {
    let ids = ids();
    let hosts = zone();
    let addr = |last: u8| vec![192, 0, 2, last];
    let names = names();
    let check = |obj: &NewObject, role: Option<ProvisioningRole>, hosts: Option<&HostZone>| {
        let draft = draft(obj.guid, obj.parent, &obj.classes, &obj.attributes).unwrap();
        let class = p1().schema().most_specific_class(&draft.classes).unwrap();
        object::check_new(&ids, &draft, class, role, hosts, names.as_ref()).map(|_| ())
    };
    let with = |mut obj: NewObject, values: Vec<Vec<u8>>| {
        obj.attributes.push((ids.host_address, values));
        obj
    };
    let ws = |values| {
        with(
            host_computer(&ids, guid(90), "ws01", "ws01.example.test"),
            values,
        )
    };
    // Accepted: one and eight addresses; the DC's claim too.
    assert_eq!(check(&ws(vec![addr(10)]), None, Some(&hosts)), Ok(()));
    assert_eq!(
        check(&ws((1..=8).map(addr).collect()), None, Some(&hosts)),
        Ok(())
    );
    let dc = with(
        computer(
            &ids,
            guid(91),
            guid(OU),
            "dc01",
            ADS_UF_SERVER_TRUST_ACCOUNT,
        ),
        vec![addr(1)],
    );
    assert_eq!(
        check(&dc, Some(ProvisioningRole::DcAccount), Some(&hosts)),
        Ok(())
    );
    // No zone: nothing is written.
    assert_eq!(
        check(&ws(vec![addr(10)]), None, None),
        Err(InvariantViolation::Value)
    );
    // Values: nine, a loopback / multicast / foreign address, 3 octets.
    for values in [
        (1..=9).map(addr).collect::<Vec<_>>(),
        vec![vec![127, 0, 0, 1]],
        vec![vec![224, 0, 0, 1]],
        vec![vec![198, 51, 100, 1]],
        vec![vec![0, 0, 0, 0]],
    ] {
        assert_eq!(
            check(&ws(values.clone()), None, Some(&hosts)),
            Err(InvariantViolation::Value),
            "{values:?}"
        );
    }
    // Names: not `<computerName>.<zone>`, not an LDH label.
    for (name, host) in [
        ("ws01", "web.example.test"),
        ("ws01", "ws01.other.test"),
        ("w_1", "w_1.example.test"),
        ("1ws", "1ws.example.test"),
    ] {
        let obj = with(host_computer(&ids, guid(92), name, host), vec![addr(10)]);
        assert_eq!(
            check(&obj, None, Some(&hosts)),
            Err(InvariantViolation::Name),
            "{name} {host}"
        );
    }
    // A service object's claim never holds one; a user never does.
    let svc = with(
        host_computer(&ids, guid(93), "ldap-svc", "dc01.example.test"),
        vec![addr(10)],
    );
    assert_eq!(
        check(&svc, Some(ProvisioningRole::ServiceObject), Some(&hosts)),
        Err(InvariantViolation::Exception)
    );
    let alice = with(
        user(&ids, guid(94), guid(OU), "alice", ADS_UF_NORMAL_ACCOUNT),
        vec![addr(10)],
    );
    assert_eq!(
        check(&alice, None, Some(&hosts)),
        Err(InvariantViolation::NotModifiable)
    );
}

/// Task DN6 (RFC 2136 §3.6; docs/54 §5.4): the one commit takes the zone
/// serial for every write that changes the zone's content — a host record's
/// write, a change or a delete of an object holding one — and not for one
/// that does not; a host record's write keeps the per-object rule
/// (`Protected` for a structural target, the values judged).
#[test]
fn the_commit_takes_the_zone_serial_for_zone_changes() {
    let ids = ids();
    let t = TempStore::new("zone-commit");
    let mut txn = t.store.begin_write().unwrap();
    begin(&mut txn);
    let inv = Invariants::new(&p1(), BTreeSet::new(), Some(zone()), names()).unwrap();
    let serial = |txn: &WriteTxn<'_>| {
        txn.counter(DNS_ZONE_SERIAL_COUNTER)
            .unwrap()
            .unwrap()
            .next_value
    };
    // A computer without a record: created, no serial.
    let checked = inv
        .check_create(
            &txn,
            host_computer(&ids, guid(95), "ws01", "ws01.example.test"),
            None,
            &[],
        )
        .unwrap();
    let committed = checked.commit(&mut txn, STAMP).unwrap();
    assert_eq!(committed.zone_serial, None);
    assert_eq!(serial(&txn), 1);
    // Its record: the serial moves; SERIAL = the counter's next value.
    let when = encode_int64(2);
    let checked = inv
        .check_host_record(
            &txn,
            guid(95),
            vec![vec![192, 0, 2, 10]],
            vec![],
            when.clone(),
        )
        .unwrap();
    assert_eq!(
        checked.commit(&mut txn, STAMP).unwrap().zone_serial,
        Some(2)
    );
    assert_eq!(serial(&txn), 2);
    // A plain change of the holder (whenChanged): the serial moves.
    let checked = inv
        .check_modify(
            &txn,
            guid(95),
            vec![AttributeChange::Replace {
                id: ids.when_changed,
                values: vec![encode_int64(3)],
            }],
            &[],
        )
        .unwrap();
    assert_eq!(
        checked.commit(&mut txn, STAMP).unwrap().zone_serial,
        Some(3)
    );
    // A change of an object without one: it does not.
    let checked = inv
        .check_modify(
            &txn,
            guid(OU),
            vec![AttributeChange::Replace {
                id: ids.when_changed,
                values: vec![encode_int64(3)],
            }],
            &[],
        )
        .unwrap();
    assert_eq!(checked.commit(&mut txn, STAMP).unwrap().zone_serial, None);
    assert_eq!(serial(&txn), 3);
    // Values and targets are judged at the check.
    assert!(matches!(
        inv.check_host_record(
            &txn,
            guid(95),
            vec![vec![10, 0, 0, 1]],
            vec![],
            when.clone()
        ),
        Err(Refused::Rule(InvariantViolation::Value))
    ));
    assert!(matches!(
        inv.check_host_record(
            &txn,
            guid(95),
            vec![vec![192, 0, 2, 10]],
            vec![vec![192, 0, 2, 11]],
            when.clone()
        ),
        Err(Refused::Rule(InvariantViolation::Value))
    ));
    assert!(matches!(
        inv.check_host_record(&txn, guid(1), vec![], vec![], when.clone()),
        Err(Refused::Rule(InvariantViolation::Protected))
    ));
    // The generic modify never writes a host record.
    assert!(matches!(
        inv.check_modify(
            &txn,
            guid(95),
            vec![AttributeChange::Replace {
                id: ids.host_address,
                values: vec![vec![192, 0, 2, 12]],
            }],
            &[]
        ),
        Err(Refused::Rule(InvariantViolation::NotModifiable))
    ));
    // Deleting the holder: the serial moves, the record goes with it.
    let checked = inv.check_delete(&txn, guid(95)).unwrap();
    assert_eq!(
        checked.commit(&mut txn, STAMP).unwrap().zone_serial,
        Some(4)
    );
    assert_eq!(StoreRead::object(&txn, guid(95)).unwrap(), None);
}

/// Task DN10b (docs/questions/Q-1002 item 2, A-172; RFC 2136 §3.6): the
/// serial-only write commits through the one commit — it takes the zone
/// serial exactly once, writes no object, takes no change-seq (it has no
/// `Origin`: docs/51 §8.3); its check is bound to the change-seq state like
/// every other (another write committed in between ⇒ `Stale`); and an
/// object write without its stamp is refused (`Unstamped`), never stamped
/// with a stand-in.
#[test]
fn the_serial_only_write_takes_the_zone_serial_alone() {
    let ids = ids();
    let t = TempStore::new("zone-serial-write");
    let mut txn = t.store.begin_write().unwrap();
    begin(&mut txn);
    let inv = Invariants::new(&p1(), BTreeSet::new(), None, names()).unwrap();
    let counter = |txn: &WriteTxn<'_>, name: &str| txn.counter(name).unwrap().unwrap();
    let seq = counter(&txn, CHANGE_SEQ_COUNTER);
    let root = StoreRead::object(&txn, guid(1)).unwrap();
    let checked = inv.check_zone_serial(&txn).unwrap();
    assert_eq!(
        checked.commit(&mut txn, None).unwrap(),
        Committed {
            rid: None,
            sid: None,
            zone_serial: Some(2)
        }
    );
    assert_eq!(counter(&txn, CHANGE_SEQ_COUNTER), seq, "no change-seq");
    assert_eq!(StoreRead::object(&txn, guid(1)).unwrap(), root);
    assert_eq!(counter(&txn, DNS_ZONE_SERIAL_COUNTER).next_value, 2);
    // Checked, then another write commits: the serial-only write is stale.
    let stale = inv.check_zone_serial(&txn).unwrap();
    let ou2 = inv
        .check_create(&txn, ou(&ids, guid(96), guid(1), "Other"), None, &[])
        .unwrap();
    ou2.commit(&mut txn, STAMP).unwrap();
    assert!(matches!(
        stale.commit(&mut txn, None),
        Err(CommitError::Stale)
    ));
    assert_eq!(counter(&txn, DNS_ZONE_SERIAL_COUNTER).next_value, 2);
    // An object write without its stamp: refused, nothing written.
    let unstamped = inv
        .check_create(&txn, ou(&ids, guid(97), guid(1), "Third"), None, &[])
        .unwrap();
    assert!(matches!(
        unstamped.commit(&mut txn, None),
        Err(CommitError::Unstamped)
    ));
    assert_eq!(StoreRead::object(&txn, guid(97)).unwrap(), None);
}

/// Task DN10b; RFC 2136 §7.11 ("if the result of the increment is zero …
/// increment it again"); A-83: the serial-only write never shows SERIAL 0
/// (from a counter whose next value is 2³² − 1 it takes twice: SERIAL 1),
/// and without the zone serial counter it is refused at the commit (the
/// counter is never created at run time).
#[test]
fn the_serial_only_write_skips_zero_and_needs_the_counter() {
    let t = TempStore::new("zone-serial-zero");
    let mut txn = t.store.begin_write().unwrap();
    txn.create_counter(CHANGE_SEQ_COUNTER, 1, u64::MAX).unwrap();
    txn.create_counter(DNS_ZONE_SERIAL_COUNTER, (1u64 << 32) - 1, u64::MAX)
        .unwrap();
    let inv = Invariants::new(&p1(), BTreeSet::new(), None, names()).unwrap();
    // The counter's next value 2³² − 1 shows SERIAL 2³² − 1; one take would
    // show 0, so the commit takes once more.
    let checked = inv.check_zone_serial(&txn).unwrap();
    assert_eq!(checked.commit(&mut txn, None).unwrap().zone_serial, Some(1));
    assert_eq!(
        txn.counter(DNS_ZONE_SERIAL_COUNTER)
            .unwrap()
            .unwrap()
            .next_value,
        (1u64 << 32) + 1
    );
    drop(txn);
    let t = TempStore::new("zone-serial-missing");
    let mut txn = t.store.begin_write().unwrap();
    txn.create_counter(CHANGE_SEQ_COUNTER, 1, u64::MAX).unwrap();
    let checked = inv.check_zone_serial(&txn).unwrap();
    assert!(matches!(
        checked.commit(&mut txn, None),
        Err(CommitError::ZoneSerial(_))
    ));
    // Without the change-seq counter there is no basis: refused at the
    // check (a store not provisioned).
    drop(txn);
    let t = TempStore::new("zone-serial-no-seq");
    let txn = t.store.begin_write().unwrap();
    assert!(matches!(
        inv.check_zone_serial(&txn),
        Err(Refused::Fault(Fault::Missing))
    ));
}

/// Task DN10b (docs/54 §3.1; docs/questions/Q-1003 item 2, A-172): given the
/// zone (`with_dns_registration` — the naming context's DNS name and the
/// registrable networks), the provisioning session writes the DC account
/// with its host record under the `DcAccount` claim, and that commit takes
/// the zone serial; without the zone the same create is refused (`Value` —
/// no host address can be written: fail closed).
#[test]
fn the_provisioning_session_writes_the_dc_host_record_only_with_the_zone() {
    let ids = ids();
    // dc01$, dNSHostName dc01.example.test (the helper's), ST, one address.
    let dc = |g: Guid| {
        let mut c = computer(&ids, g, guid(OU), "dc01", ADS_UF_SERVER_TRUST_ACCOUNT);
        c.attributes
            .push((ids.host_address, vec![vec![192, 0, 2, 1]]));
        c
    };
    let naming_context = naming_context();
    let registration = crate::config::DnsRegistration::new(zone().networks).unwrap();
    let t = TempStore::new("provision-dc-host");
    let mut txn = t.store.begin_write().unwrap();
    {
        let mut session = begin(&mut txn).with_dns_registration(&naming_context, &registration);
        session
            .create(Some(ProvisioningRole::DcAccount), dc(guid(98)))
            .unwrap();
    }
    assert_eq!(
        txn.counter(DNS_ZONE_SERIAL_COUNTER)
            .unwrap()
            .unwrap()
            .next_value,
        2
    );
    let stored = StoreRead::object(&txn, guid(98)).unwrap().unwrap();
    assert_eq!(
        stored.attribute(ids.host_address).map(|a| a
            .values
            .iter()
            .map(|v| v.value.clone())
            .collect::<Vec<_>>()),
        Some(vec![vec![192, 0, 2, 1]])
    );
    drop(txn);
    let t = TempStore::new("provision-dc-host-no-zone");
    let mut txn = t.store.begin_write().unwrap();
    let mut session = begin(&mut txn);
    assert_eq!(
        rule(session.create(Some(ProvisioningRole::DcAccount), dc(guid(98)))),
        InvariantViolation::Value
    );
}

// ---------------------------------------------------------------------------
// The one principal namespace (task PN5; docs/59 §4-§5, §10.1; A-173).
// ---------------------------------------------------------------------------

/// The namespace keys stored on `g`, as text, in the store's (octet) order.
fn stored_keys(txn: &WriteTxn<'_>, g: Guid) -> Vec<String> {
    let ids = ids();
    StoreRead::object(txn, g)
        .unwrap()
        .unwrap()
        .attribute(ids.principal_name_key)
        .map(|a| {
            a.values
                .iter()
                .map(|v| String::from_utf8(v.value.clone()).unwrap())
                .collect()
        })
        .unwrap_or_default()
}

/// `new` with the extra values `extra`.
fn with_values(mut new: NewObject, extra: Vec<(AttrId, Vec<Vec<u8>>)>) -> NewObject {
    new.attributes.extend(extra);
    new
}

/// The online computer `name` on `host` (WT), with the SPN `spn` if any.
fn online_computer(ids: &Ids, g: Guid, name: &str, host: &str, spn: Option<&str>) -> NewObject {
    let mut c = host_computer(ids, g, name, host);
    if let Some(spn) = spn {
        c.attributes.push((ids.service_principal_name, text(spn)));
    }
    c
}

/// The checker's commit of `new` (claim `role`) in `txn`: `Ok` when written,
/// the rule when the checker refused, and `None` for a commit the store
/// refused because another live object holds one of its namespace keys
/// (`ValueNotUnique` on the namespace attribute — and on nothing else).
fn write(
    inv: &Invariants,
    txn: &mut WriteTxn<'_>,
    new: NewObject,
    role: Option<ProvisioningRole>,
) -> Result<(), Option<InvariantViolation>> {
    let ids = ids();
    match inv.check_create(txn, new, role, &[]) {
        Err(Refused::Rule(v)) => Err(Some(v)),
        Err(other) => panic!("{other:?}"),
        Ok(checked) => match checked.commit(txn, STAMP) {
            Ok(_) => Ok(()),
            Err(CommitError::Write(dirstore::Error::ValueNotUnique(id)))
                if id == ids.principal_name_key =>
            {
                Err(None)
            }
            Err(other) => panic!("{other:?}"),
        },
    }
}

/// docs/59 §4.3, §4.4 N5, N7, §4.6; Q-1007 item 4; Q-1008 items 2, 6;
/// Q-1010 item 3; Q-1020 item 7; [MS-ADTS] 3.1.1.5.3.1.1.2: every principal
/// the provisioning session creates — the krbtgt account, the DC account, a
/// service object, an online computer, users (one with a UPN whose local
/// part is its sAMAccountName in another case) and a group — holds exactly
/// the keys `keys_of_names` derives from its own names, folded, each once
/// (stored = derived; the caller supplied none), within the count bound
/// (user ≤ 2, computer ≤ 3 + SPNs + 1, krbtgt 1 + the alias); the krbtgt
/// account holds the realm alias; the service object carries the DC's host
/// name without its key; an OU holds none.
#[test]
fn the_checker_writes_every_principals_keys() {
    let ids = ids();
    let t = TempStore::new("namespace-keys");
    let mut txn = t.store.begin_write().unwrap();
    let upn = |s: &str| (ids.user_principal_name, text(s));
    {
        let mut s = begin(&mut txn);
        s.create(
            Some(ProvisioningRole::Krbtgt),
            user(&ids, guid(100), guid(OU), "krbtgt", ADS_UF_NORMAL_ACCOUNT),
        )
        .unwrap();
        s.create(
            Some(ProvisioningRole::DcAccount),
            computer(
                &ids,
                guid(101),
                guid(OU),
                "dc01",
                ADS_UF_SERVER_TRUST_ACCOUNT,
            ),
        )
        .unwrap();
        s.create(
            Some(ProvisioningRole::ServiceObject),
            service(
                &ids,
                guid(102),
                "ldap-svc",
                "dc01.example.test",
                Some("ldap/dc01.example.test"),
            ),
        )
        .unwrap();
        s.create(
            None,
            online_computer(
                &ids,
                guid(103),
                "ws01",
                "ws01.example.test",
                Some("HOST/ws01.example.test"),
            ),
        )
        .unwrap();
        s.create(
            None,
            with_values(
                user(&ids, guid(104), guid(OU), "Carol", ADS_UF_NORMAL_ACCOUNT),
                vec![upn("carol@EXAMPLE.TEST")],
            ),
        )
        .unwrap();
        s.create(
            None,
            with_values(
                user(&ids, guid(105), guid(OU), "dave", ADS_UF_NORMAL_ACCOUNT),
                vec![upn("D.Smith@example.test")],
            ),
        )
        .unwrap();
        s.create(None, group(&ids, guid(106), guid(OU), "Staff-G", &[]))
            .unwrap();
    }
    let expected: [(u8, &[&str]); 7] = [
        (100, &["example.test", "krbtgt"]),
        (101, &["dc01", "dc01$", "dc01.example.test"]),
        (102, &["ldap-svc", "ldap-svc$", "ldap/dc01.example.test"]),
        (
            103,
            &[
                "host/ws01.example.test",
                "ws01",
                "ws01$",
                "ws01.example.test",
            ],
        ),
        (104, &["carol"]),
        (105, &["d.smith", "dave"]),
        (106, &["staff-g"]),
    ];
    for (n, keys) in expected {
        assert_eq!(stored_keys(&txn, guid(n)), keys, "object {n}");
    }
    // Stored = derived: the one derivation the lookup re-derives with.
    let ctx = names().unwrap();
    let derived = |names: principal_names::PrincipalNames<'_>| -> Vec<String> {
        principal_names::keys_of_names(&names, &ctx)
            .unwrap()
            .keys()
            .map(|k| k.as_str().to_owned())
            .collect()
    };
    assert_eq!(
        derived(principal_names::PrincipalNames {
            class: principal_names::PrincipalClass::DomainController,
            sam_account_name: "dc01$",
            user_principal_name: None,
            service_principal_names: vec![],
            dns_host_name: Some("dc01.example.test"),
        }),
        stored_keys(&txn, guid(101))
    );
    assert_eq!(
        derived(principal_names::PrincipalNames {
            class: principal_names::PrincipalClass::User,
            sam_account_name: "dave",
            user_principal_name: Some("D.Smith@example.test"),
            service_principal_names: vec![],
            dns_host_name: None,
        }),
        stored_keys(&txn, guid(105))
    );
    // The count bound of Q-1008 item 2 (decided A-173).
    assert!(stored_keys(&txn, guid(104)).len() <= 2);
    assert!(stored_keys(&txn, guid(105)).len() <= 2);
    assert!(stored_keys(&txn, guid(103)).len() <= 3 + 1 + 1);
    assert_eq!(stored_keys(&txn, guid(100)).len(), 1 + 1);
    // No key outside the namespace.
    assert!(stored_keys(&txn, guid(OU)).is_empty());
    assert!(stored_keys(&txn, guid(1)).is_empty());
}

/// docs/59 §4.4 N7, §5.1; Q-1008 item 6: only the checker writes the
/// namespace keys — a caller that supplies them is refused (`NotModifiable`)
/// even with exactly the right keys or an empty value set, on a principal or
/// any other object; no change can write or remove them; an object outside
/// the namespace carries no name of it. Nothing refused is written.
#[test]
fn a_caller_cannot_supply_or_change_the_keys() {
    let ids = ids();
    let t = TempStore::new("namespace-n7");
    let mut txn = t.store.begin_write().unwrap();
    {
        let mut s = begin(&mut txn);
        for keys in [vec!["eve"], vec!["mallory"], vec![]] {
            let supplied = with_values(
                user(&ids, guid(110), guid(OU), "eve", ADS_UF_NORMAL_ACCOUNT),
                vec![(
                    ids.principal_name_key,
                    keys.iter().map(|k| k.as_bytes().to_vec()).collect(),
                )],
            );
            assert_eq!(
                rule(s.create(None, supplied)),
                InvariantViolation::NotModifiable,
                "{keys:?}"
            );
        }
        // Nothing was written: the same GUID is created now, with the
        // checker's own keys.
        s.create(
            None,
            user(&ids, guid(110), guid(OU), "eve", ADS_UF_NORMAL_ACCOUNT),
        )
        .unwrap();
        let ou_with_key = with_values(
            ou(&ids, guid(111), guid(1), "Keys"),
            vec![(ids.principal_name_key, text("keys"))],
        );
        assert_eq!(
            rule(s.create(None, ou_with_key)),
            InvariantViolation::NotModifiable
        );
        let ou_with_name = with_values(
            ou(&ids, guid(112), guid(1), "Named"),
            vec![(ids.sam_account_name, text("named"))],
        );
        assert_eq!(
            rule(s.create(None, ou_with_name)),
            InvariantViolation::NotModifiable
        );
    }
    for refused in [111, 112] {
        assert_eq!(StoreRead::object(&txn, guid(refused)).unwrap(), None);
    }
    assert_eq!(stored_keys(&txn, guid(110)), ["eve"]);
    let inv = Invariants::new(&p1(), BTreeSet::new(), None, names()).unwrap();
    for values in [text("mallory"), text("eve"), vec![]] {
        let change = inv.check_modify(
            &txn,
            guid(110),
            vec![AttributeChange::Replace {
                id: ids.principal_name_key,
                values,
            }],
            &[],
        );
        assert!(
            matches!(
                change,
                Err(Refused::Rule(InvariantViolation::NotModifiable))
            ),
            "{change:?}"
        );
    }
    assert_eq!(stored_keys(&txn, guid(110)), ["eve"]);
}

/// docs/59 §3 (M2), §4.4 N1, §10.1 (the attacks); RFC 4120 §6.2 ("Ignoring
/// the name type, no two names can be the same"); [MS-SAMR] 3.1.1.8.4 item 2
/// (sAMAccountName unique over the union); [MS-ADTS] 3.1.1.5.1.3 (SPN, UPN
/// "MUST be unique"); Q-1007 items 2, 7, 8: one name, in any of its forms,
/// is one object's only — each second holder below passes every rule of the
/// checker and (but for the SPN, whose own index folds case too) every
/// per-attribute index, and the store's index on the one namespace
/// attribute refuses it at the commit (the same transaction):
/// noPac — a computer `dc$` beside a user `dc`, and a user `ws9` (any case)
/// beside a computer `ws9$`; a UPN `bob@<realm>` (any case) beside another
/// object's sAMAccountName `bob`; a group beside a computer of its name; one
/// SPN in two spellings on two service objects (neither claims the host);
/// a user named like a computer's dNSHostName. Nothing refused is written.
#[test]
fn one_name_is_one_objects_in_every_form() {
    let ids = ids();
    let t = TempStore::new("namespace-union");
    let mut txn = t.store.begin_write().unwrap();
    begin(&mut txn);
    let inv = Invariants::new(&p1(), BTreeSet::new(), None, names()).unwrap();
    let n = ADS_UF_NORMAL_ACCOUNT;
    let upn = |s: &str| (ids.user_principal_name, text(s));
    // The second holders live under another OU, so that no RDN is shared:
    // what refuses them is the namespace alone.
    const OTHER: u8 = 3;
    write(
        &inv,
        &mut txn,
        ou(&ids, guid(OTHER), guid(1), "Other"),
        None,
    )
    .unwrap();
    let elsewhere = |mut new: NewObject| {
        new.parent = Some(guid(OTHER));
        new
    };
    // noPac, both orders.
    write(
        &inv,
        &mut txn,
        user(&ids, guid(120), guid(OU), "dc", n),
        None,
    )
    .unwrap();
    assert_eq!(
        write(
            &inv,
            &mut txn,
            elsewhere(online_computer(
                &ids,
                guid(121),
                "dc",
                "dc.example.test",
                None
            )),
            None
        ),
        Err(None)
    );
    write(
        &inv,
        &mut txn,
        online_computer(&ids, guid(122), "ws9", "ws9.example.test", None),
        None,
    )
    .unwrap();
    for (g, sam) in [(123, "ws9"), (124, "WS9"), (125, "ws9.example.test")] {
        assert_eq!(
            write(
                &inv,
                &mut txn,
                elsewhere(user(&ids, guid(g), guid(OU), sam, n)),
                None
            ),
            Err(None),
            "{sam}"
        );
    }
    // A UPN's local part beside another object's sAMAccountName.
    write(
        &inv,
        &mut txn,
        user(&ids, guid(126), guid(OU), "bob", n),
        None,
    )
    .unwrap();
    for (g, value) in [(127, "bob@example.test"), (128, "BOB@Example.Test")] {
        let carol = with_values(user(&ids, guid(g), guid(OU), "carol", n), vec![upn(value)]);
        assert_eq!(write(&inv, &mut txn, carol, None), Err(None), "{value}");
    }
    // A group and a computer of one name.
    write(
        &inv,
        &mut txn,
        group(&ids, guid(129), guid(OU), "staff", &[]),
        None,
    )
    .unwrap();
    assert_eq!(
        write(
            &inv,
            &mut txn,
            elsewhere(online_computer(
                &ids,
                guid(130),
                "staff",
                "staff.example.test",
                None
            )),
            None
        ),
        Err(None)
    );
    // One SPN in two spellings (service objects claim no host key).
    write(
        &inv,
        &mut txn,
        service(
            &ids,
            guid(131),
            "svc1",
            "dc01.example.test",
            Some("ldap/dc01.example.test"),
        ),
        Some(ProvisioningRole::ServiceObject),
    )
    .unwrap();
    // The per-attribute index of servicePrincipalName folds case too
    // (dirstore's comparison key): both indexes are enforced in the one
    // commit, either may answer first.
    let second = inv
        .check_create(
            &txn,
            service(
                &ids,
                guid(132),
                "svc2",
                "dc01.example.test",
                Some("LDAP/dc01.example.test"),
            ),
            Some(ProvisioningRole::ServiceObject),
            &[],
        )
        .unwrap();
    let refused = second.commit(&mut txn, STAMP);
    assert!(
        matches!(
            refused,
            Err(CommitError::Write(dirstore::Error::ValueNotUnique(id)))
                if id == ids.principal_name_key || id == ids.service_principal_name
        ),
        "{refused:?}"
    );
    for refused in [121, 123, 124, 125, 127, 128, 130, 132] {
        assert_eq!(
            StoreRead::object(&txn, guid(refused)).unwrap(),
            None,
            "{refused}"
        );
    }
    // Controls: other names are free.
    write(
        &inv,
        &mut txn,
        user(&ids, guid(133), guid(OU), "dc2", n),
        None,
    )
    .unwrap();
    write(
        &inv,
        &mut txn,
        with_values(
            user(&ids, guid(134), guid(OU), "carol", n),
            vec![upn("carol@example.test")],
        ),
        None,
    )
    .unwrap();
}

/// Class C49 (docs/52; docs/59 §3 M3); Q-1009 items 1-2 (decided A-173);
/// A-163; RFC 4120 §6.2 ("Names of any type with an initial component of
/// 'krbtgt' are reserved"), §7.3; RFC 3244 §2; docs/59 §4.4 N4, N5, §10.1:
/// a reserved name in any case is judged on the folded key. Without the
/// claim that owns it — `ADMIND/<host>`, `KADMIN/changepw`, `KRBTGT/<host>`
/// (accepted before task PN5: their octets differed) — the SPN is refused
/// (`Value`); the TGS's name or the realm alias as an account name, in any
/// case, or as a computer's base name, is refused (`ReservedName`); as a
/// UPN's local part or a host name (`Value`). The admin service's claim must
/// spell its own name exactly (`Value` for a case variant). `kadmin/<host>`
/// is not reserved (Q-1009 item 7 undecided). Nothing refused is written.
#[test]
fn reserved_names_are_judged_on_the_folded_key() {
    let ids = ids();
    let t = TempStore::new("namespace-reserved");
    let mut txn = t.store.begin_write().unwrap();
    begin(&mut txn);
    let inv = Invariants::new(&p1(), BTreeSet::new(), None, names()).unwrap();
    let n = ADS_UF_NORMAL_ACCOUNT;
    let spn_cases = [
        ("ws10.example.test", "ADMIND/ws10.example.test"),
        ("ws10.example.test", "Admind/ws10.example.test"),
        ("ws10.example.test", "KRBTGT/ws10.example.test"),
        ("ws10.example.test", "krbtgt/ws10.example.test"),
        ("changepw", "KADMIN/changepw"),
        ("changepw", "Kadmin/changepw"),
    ];
    for (host, spn) in spn_cases {
        assert_eq!(
            write(
                &inv,
                &mut txn,
                online_computer(&ids, guid(140), "ws10", host, Some(spn)),
                None
            ),
            Err(Some(InvariantViolation::Value)),
            "{spn}"
        );
        assert_eq!(
            write(
                &inv,
                &mut txn,
                online_computer(&ids, guid(140), "ws10", host, Some(spn)),
                Some(ProvisioningRole::ServiceObject)
            ),
            Err(Some(InvariantViolation::Value)),
            "{spn} as a service object"
        );
    }
    let account_names = [
        user(&ids, guid(141), guid(OU), "KRBTGT", n),
        user(&ids, guid(141), guid(OU), "KrbTgt", n),
        user(&ids, guid(141), guid(OU), "example.test", n),
        user(&ids, guid(141), guid(OU), "Example.Test", n),
        group(&ids, guid(141), guid(OU), "Krbtgt", &[]),
        online_computer(&ids, guid(141), "KRBTGT", "krbtgt.example.test", None),
    ];
    for new in account_names {
        assert_eq!(
            write(&inv, &mut txn, new, None),
            Err(Some(InvariantViolation::ReservedName))
        );
    }
    let other_names = [
        with_values(
            user(&ids, guid(142), guid(OU), "tgs", n),
            vec![(ids.user_principal_name, text("krbtgt@example.test"))],
        ),
        online_computer(&ids, guid(142), "ws11", "example.test", None),
        online_computer(&ids, guid(142), "ws11", "krbtgt", None),
    ];
    for new in other_names {
        assert_eq!(
            write(&inv, &mut txn, new, None),
            Err(Some(InvariantViolation::Value))
        );
    }
    // The owning claim spells its name exactly.
    assert_eq!(
        write(
            &inv,
            &mut txn,
            service(
                &ids,
                guid(143),
                "admind-svc",
                "dc01.example.test",
                Some("ADMIND/dc01.example.test")
            ),
            Some(ProvisioningRole::AdminServiceObject)
        ),
        Err(Some(InvariantViolation::Value))
    );
    for refused in [140, 141, 142, 143] {
        assert_eq!(StoreRead::object(&txn, guid(refused)).unwrap(), None);
    }
    // Not reserved: `kadmin/<host>` (Q-1009 item 7 undecided).
    write(
        &inv,
        &mut txn,
        online_computer(
            &ids,
            guid(144),
            "ws12",
            "ws12.example.test",
            Some("kadmin/ws12.example.test"),
        ),
        None,
    )
    .unwrap();
}

/// docs/59 §4.4 N2-N4 (the namespace's syntax, crate principal-names —
/// Q-1018 item 2); Q-1007 item 3 (a UPN suffix that is not a realm alias is
/// refused — stricter than [MS-DRSR] 4.1.4.2.22, which takes the part before
/// the "@" whatever the domain); [MS-ADTS] 3.1.1.5.3.1.1.4 ("The SPN (2)
/// MUST NOT contain an ":instancename" component"): an "@" in a
/// sAMAccountName is a name rule (`Name`); a UPN of a foreign suffix, without
/// exactly one "@", or whose local part ends with "$" or holds "/", an "@"
/// in a dNSHostName, an SPN host part with an instance name — value rules
/// (`Value`). A numeric port is not an instance name ([MS-ADTS] 2.2.21) —
/// the namespace accepts it (crates/principal-names `port_and_instancename`)
/// — but since task PN6 no computer reaches the store with one: its SPN's
/// host part is its dNSHostName (`names::spn_ok`), which is exactly
/// `<computerName>.<realm DNS name>` (rule N6; [MS-ADTS] 3.1.1.5.3.1.1.2), so
/// a dNSHostName with ":8080" names no host of its own (`Value`).
#[test]
fn the_namespace_syntax_is_the_checkers() {
    let ids = ids();
    let t = TempStore::new("namespace-syntax");
    let mut txn = t.store.begin_write().unwrap();
    begin(&mut txn);
    let inv = Invariants::new(&p1(), BTreeSet::new(), None, names()).unwrap();
    let n = ADS_UF_NORMAL_ACCOUNT;
    assert_eq!(
        write(
            &inv,
            &mut txn,
            user(&ids, guid(150), guid(OU), "a@b", n),
            None
        ),
        Err(Some(InvariantViolation::Name))
    );
    for value in [
        "alice@foreign.example",
        "alice",
        "alice@example.test@example.test",
        "alice$@example.test",
        "al/ice@example.test",
        "@example.test",
    ] {
        let alice = with_values(
            user(&ids, guid(151), guid(OU), "alice", n),
            vec![(ids.user_principal_name, text(value))],
        );
        assert_eq!(
            write(&inv, &mut txn, alice, None),
            Err(Some(InvariantViolation::Value)),
            "{value}"
        );
    }
    let at_host = online_computer(&ids, guid(152), "ws13", "ws13@example.test", None);
    assert_eq!(
        write(&inv, &mut txn, at_host, None),
        Err(Some(InvariantViolation::Value))
    );
    let instance = online_computer(
        &ids,
        guid(153),
        "ws14",
        "ws14.example.test:inst",
        Some("host/ws14.example.test:inst"),
    );
    assert_eq!(
        write(&inv, &mut txn, instance, None),
        Err(Some(InvariantViolation::Value))
    );
    let port = online_computer(
        &ids,
        guid(154),
        "ws15",
        "ws15.example.test:8080",
        Some("http/ws15.example.test:8080"),
    );
    assert_eq!(
        write(&inv, &mut txn, port, None),
        Err(Some(InvariantViolation::Value))
    );
    for refused in [150, 151, 152, 153, 154] {
        assert_eq!(StoreRead::object(&txn, guid(refused)).unwrap(), None);
    }
    write(
        &inv,
        &mut txn,
        online_computer(
            &ids,
            guid(154),
            "ws15",
            "ws15.example.test",
            Some("http/ws15.example.test"),
        ),
        None,
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// Which host a computer names — rule N6 (task PN6; docs/59 §4.4; Q-1010).
// ---------------------------------------------------------------------------

/// `new` with its dNSHostName replaced by `host`.
fn on_host(ids: &Ids, mut new: NewObject, host: &str) -> NewObject {
    for (id, values) in new.attributes.iter_mut() {
        if *id == ids.dns_host_name {
            *values = text(host);
        }
    }
    new
}

/// Task PN6, rule N6 (docs/59 §4.4, §10.1: "dNSHostName = `<base>.<realm>`;
/// other ⇒ refused"); [MS-ADTS] 3.1.1.5.3.1.1.2 ("computerName.
/// fullDomainDnsName, where computerName is the current sAMAccountName of
/// the object (without the final "$" character), and the fullDomainDnsName
/// is the DNS name of the domain NC"); RFC 1035 §2.3.1; docs/54 §5.3;
/// docs/questions/Q-994 item 1, Q-1010 items 1-2; A-172: every computer that
/// holds a `HostName` key names exactly its own host, on every write path.
/// The DC account under its claim: another host is refused (`Value`), its
/// own (`dc-fqdn` = `<dc-name>.<zone>`) passes. An online computer (the
/// checker as `apply` calls it): the DC's host (Q-994 item 1's case),
/// another computer's, another domain, a deeper name, the realm, a bare
/// label — `Value`; a computerName that is not one RFC 1035 label — no host
/// name at all (`Name`); an upper-case host keeps the form rule's code
/// (`Value`, RFC 4120 §6.2.1). Its own host, the name in another case,
/// passes, and its `HostName` key is the fold of `<computerName>.<realm>` —
/// a function of its `ComputerBase` key. Nothing refused is written.
#[test]
fn every_host_name_holder_names_its_own_host() {
    let ids = ids();
    let t = TempStore::new("host-name-n6");
    let mut txn = t.store.begin_write().unwrap();
    {
        let mut s = begin(&mut txn);
        for host in ["dc02.example.test", "dc01.other.test", "dc01"] {
            assert_eq!(
                rule(s.create(
                    Some(ProvisioningRole::DcAccount),
                    on_host(&ids, dc_account(&ids, guid(170)), host)
                )),
                InvariantViolation::Value,
                "{host}"
            );
        }
        s.create(
            Some(ProvisioningRole::DcAccount),
            dc_account(&ids, guid(170)),
        )
        .unwrap();
    }
    let inv = Invariants::new(&p1(), BTreeSet::new(), None, names()).unwrap();
    for host in [
        "dc01.example.test",
        "ws02.example.test",
        "ws21.other.test",
        "x.ws21.example.test",
        "ws21.example.test.other",
        "example.test",
        "ws21",
    ] {
        assert_eq!(
            write(
                &inv,
                &mut txn,
                online_computer(&ids, guid(171), "ws21", host, None),
                None
            ),
            Err(Some(InvariantViolation::Value)),
            "{host}"
        );
    }
    for name in ["1ws", "w_s", "w.s", "ws-"] {
        let host = format!("{name}.example.test");
        assert_eq!(
            write(
                &inv,
                &mut txn,
                online_computer(&ids, guid(171), name, &host, None),
                None
            ),
            Err(Some(InvariantViolation::Name)),
            "{name}"
        );
    }
    assert_eq!(
        write(
            &inv,
            &mut txn,
            online_computer(&ids, guid(171), "ws21", "WS21.example.test", None),
            None
        ),
        Err(Some(InvariantViolation::Value))
    );
    assert_eq!(StoreRead::object(&txn, guid(171)).unwrap(), None);
    write(
        &inv,
        &mut txn,
        online_computer(
            &ids,
            guid(172),
            "WS21",
            "ws21.example.test",
            Some("host/ws21.example.test"),
        ),
        None,
    )
    .unwrap();
    assert_eq!(
        stored_keys(&txn, guid(172)),
        [
            "host/ws21.example.test",
            "ws21",
            "ws21$",
            "ws21.example.test"
        ]
    );
    let base = principal_names::fold("WS21").unwrap();
    let realm = names()
        .unwrap()
        .realm_aliases()
        .next()
        .unwrap()
        .as_str()
        .to_owned();
    assert!(stored_keys(&txn, guid(172)).contains(&format!("{base}.{realm}")));
    assert!(stored_keys(&txn, guid(170)).contains(&"dc01.example.test".to_owned()));
}

/// Task PN6; docs/59 §4.3, §4.4 N6; docs/questions/Q-1010 item 3 (decided
/// A-173: "the provisioned service objects keep dNSHostName = dc_fqdn and
/// claim no `HostName` key; the session checker requires it to equal the DC
/// account's"): each of the three service-object claims, before the DC
/// account exists in the session, borrows a host nobody holds (`Exception`);
/// after it, a dNSHostName other than the DC account's — another DC name,
/// the object's own `<computerName>.<realm>`, another computer's — is
/// refused (`Value`); the DC account's host passes, for each claim, and the
/// service objects hold no `HostName` key — the DC account does. Nothing
/// refused is written (the same GUIDs are created afterwards).
#[test]
fn the_service_objects_carry_the_dc_accounts_host_name() {
    let ids = ids();
    let t = TempStore::new("service-host-name");
    let mut txn = t.store.begin_write().unwrap();
    let ldap = |host: &str| {
        service(
            &ids,
            guid(180),
            "ldap-svc",
            host,
            Some(&format!("ldap/{host}")),
        )
    };
    let admind = |host: &str| {
        service(
            &ids,
            guid(181),
            "admind-svc",
            host,
            Some(&format!("admind/{host}")),
        )
    };
    let changepw = |host: &str| {
        service(
            &ids,
            guid(182),
            "changepw-svc",
            host,
            Some("kadmin/changepw"),
        )
    };
    let dc_host = "dc01.example.test";
    {
        let mut s = begin(&mut txn);
        for (claim, new) in [
            (ProvisioningRole::ServiceObject, ldap(dc_host)),
            (ProvisioningRole::AdminServiceObject, admind(dc_host)),
            (
                ProvisioningRole::ChangePasswordServiceObject,
                changepw(dc_host),
            ),
        ] {
            assert_eq!(
                rule(s.create(Some(claim), new)),
                InvariantViolation::Exception,
                "{claim:?} before the DC account"
            );
        }
        s.create(
            Some(ProvisioningRole::DcAccount),
            dc_account(&ids, guid(183)),
        )
        .unwrap();
        for (claim, new) in [
            (ProvisioningRole::ServiceObject, ldap("dc02.example.test")),
            (
                ProvisioningRole::ServiceObject,
                ldap("ldap-svc.example.test"),
            ),
            (
                ProvisioningRole::AdminServiceObject,
                admind("dc02.example.test"),
            ),
            (
                ProvisioningRole::ChangePasswordServiceObject,
                changepw("ws01.example.test"),
            ),
        ] {
            assert_eq!(
                rule(s.create(Some(claim), new)),
                InvariantViolation::Value,
                "{claim:?}"
            );
        }
        // Nothing refused was written: the same GUIDs are created now.
        s.create(Some(ProvisioningRole::ServiceObject), ldap(dc_host))
            .unwrap();
        s.create(Some(ProvisioningRole::AdminServiceObject), admind(dc_host))
            .unwrap();
        s.create(
            Some(ProvisioningRole::ChangePasswordServiceObject),
            changepw(dc_host),
        )
        .unwrap();
    }
    for (n, keys) in [
        (
            180,
            &["ldap-svc", "ldap-svc$", "ldap/dc01.example.test"][..],
        ),
        (
            181,
            &["admind-svc", "admind-svc$", "admind/dc01.example.test"][..],
        ),
        (
            182,
            &["changepw-svc", "changepw-svc$", "kadmin/changepw"][..],
        ),
        (183, &["dc01", "dc01$", "dc01.example.test"][..]),
    ] {
        assert_eq!(stored_keys(&txn, guid(n)), keys, "object {n}");
    }
}

/// docs/59 §5.1, §5.2, §5.5; Q-1008 item 5 (decided A-173); A-83: the
/// provisioning session creates the `principal-namespace` marker counter
/// with the others (its one value, never taken) and refuses a store that
/// holds it; without a naming context it creates no security principal
/// (fail closed: the keys cannot be derived) while other objects pass;
/// given one through `with_dns_registration` (task DN10b's naming context),
/// it does.
#[test]
fn provisioning_marks_the_namespace_and_needs_its_naming_context() {
    let ids = ids();
    let t = TempStore::new("namespace-marker");
    {
        let mut txn = t.store.begin_write().unwrap();
        {
            let mut s = Provisioning::begin(&mut txn, &p1(), WALL, NODE).unwrap();
            s.create(Some(ProvisioningRole::NamingContextRoot), root(&ids))
                .unwrap();
            s.create(None, ou(&ids, guid(OU), guid(1), "Staff"))
                .unwrap();
            assert!(matches!(
                s.create(
                    None,
                    user(&ids, guid(160), guid(OU), "alice", ADS_UF_NORMAL_ACCOUNT)
                ),
                Err(ProvisioningError::Store("principal namespace"))
            ));
            assert!(matches!(
                s.create(None, group(&ids, guid(161), guid(OU), "g1", &[])),
                Err(ProvisioningError::Store("principal namespace"))
            ));
            let registration = crate::config::DnsRegistration::new(zone().networks).unwrap();
            let mut s = s.with_dns_registration(&naming_context(), &registration);
            s.create(
                None,
                user(&ids, guid(160), guid(OU), "alice", ADS_UF_NORMAL_ACCOUNT),
            )
            .unwrap();
            s.create(None, group(&ids, guid(161), guid(OU), "g1", &[]))
                .unwrap();
        }
        let state = txn.counter(PRINCIPAL_NAMESPACE_COUNTER).unwrap().unwrap();
        assert_eq!(state.first_value, PRINCIPAL_NAMESPACE_FIRST);
        assert_eq!(state.next_value, PRINCIPAL_NAMESPACE_FIRST);
        assert_eq!(state.end_exclusive, PRINCIPAL_NAMESPACE_END_EXCLUSIVE);
        assert_eq!(stored_keys(&txn, guid(160)), ["alice"]);
        txn.commit().unwrap();
    }
    let t = TempStore::new("namespace-marker-only");
    {
        let mut txn = t.store.begin_write().unwrap();
        txn.create_counter(
            PRINCIPAL_NAMESPACE_COUNTER,
            PRINCIPAL_NAMESPACE_FIRST,
            PRINCIPAL_NAMESPACE_END_EXCLUSIVE,
        )
        .unwrap();
        txn.commit().unwrap();
    }
    let mut txn = t.store.begin_write().unwrap();
    assert!(matches!(
        Provisioning::begin(&mut txn, &p1(), WALL, NODE),
        Err(ProvisioningError::NotEmpty)
    ));
}
