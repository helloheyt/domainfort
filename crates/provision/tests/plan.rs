//! The plan of `provision domain` (pure: no filesystem effect): the object
//! table, the root security descriptor, the child descriptors, the policy,
//! the configuration files and the manifest — and the input refusals that
//! stop the run before anything is written.
//!
//! Sources: docs/51 §4.3 steps 1-8 (the object table of step 5), §8.3,
//! §10, §11; [MS-SAMR] v20260427 2.2.1.14 (RID 0x1F6), 3.1.1.6 items 11,
//! 14, 20, 22-24, 3.1.1.8.1 items 1.2, 2.2; [MS-DTYP] v20241119 2.4.2.4
//! (`S-1-5-21-r1-r2-r3`), 2.4.4.1-2.4.4.3, 2.4.5, 2.4.6; [MS-ADTS]
//! v20261026 3.1.1.5.2.4, 5.1.3.2, 6.1.3, 6.1.3.1; A-75, A-76, A-79, A-84
//! (Q-335/Q-336: no INHERIT_ONLY, no CREATOR_*, no generic bit on the
//! root), A-86, P-22. Fixtures: tests/common (obviously fake values).

mod common;

use common::*;

use ad_schema::flags::user_account_control::{
    ADS_UF_ACCOUNT_DISABLE, ADS_UF_NORMAL_ACCOUNT, ADS_UF_SERVER_TRUST_ACCOUNT,
    ADS_UF_WORKSTATION_TRUST_ACCOUNT,
};
use directory_admin::{
    new_object_descriptor, ACCOUNT_EXPIRES_NEVER, USER_CHANGE_PASSWORD, USER_FORCE_CHANGE_PASSWORD,
};
use dtyp::{ace_flags, Ace, Sid, ACL_REVISION_DS, SECURITY_NT_AUTHORITY};
use pdp::access_check::rights::{
    RIGHT_DELETE, RIGHT_DS_CONTROL_ACCESS, RIGHT_DS_CREATE_CHILD, RIGHT_DS_LIST_CONTENTS,
    RIGHT_DS_READ_PROPERTY, RIGHT_DS_WRITE_PROPERTY,
};
use pdp::{
    Action, ActionClass, ActionMatch, ControlRightId, IpScope, ResourceMatch, SubjectMatch, Tier,
    TransportSec,
};
use provision::input::InputErrorKind;
use provision::plan::{
    CHANGE_SEQ_END_EXCLUSIVE, CHANGE_SEQ_FIRST, DOMAIN_USER_RID_KRBTGT, PROVISIONED_GROUP_TYPE,
    SECURITY_NT_NON_UNIQUE,
};
use provision::{
    ObjectRole, Plan, PlanError, RidSource, DIRD_ADMIN_CHANNEL_KEYS, PRINCIPAL_SELF_RID,
};
use provision_manifest::Manifest;

fn plan(input: &provision::DomainInput) -> Plan {
    Plan::build(input, now(), &mut CountingRandom::default()).unwrap()
}

fn schema() -> ad_schema::Phase1Schema {
    ad_schema::phase1().unwrap()
}

/// The single stored value of `name` on `object`.
fn value<'a>(object: &'a provision::PlannedObject, name: &str) -> Option<&'a [u8]> {
    let id = schema().attribute_by_name(name).unwrap();
    object
        .attributes
        .iter()
        .find(|(a, _)| *a == id)
        .map(|(_, values)| {
            assert_eq!(values.len(), 1, "{name} single-valued");
            values[0].as_slice()
        })
}

fn values<'a>(object: &'a provision::PlannedObject, name: &str) -> Vec<&'a [u8]> {
    let id = schema().attribute_by_name(name).unwrap();
    object
        .attributes
        .iter()
        .find(|(a, _)| *a == id)
        .map(|(_, v)| v.iter().map(Vec::as_slice).collect())
        .unwrap_or_default()
}

fn flags(object: &provision::PlannedObject, name: &str) -> u32 {
    u32::from_be_bytes(value(object, name).unwrap().try_into().unwrap())
}

fn int64(object: &provision::PlannedObject, name: &str) -> i64 {
    i64::from_be_bytes(value(object, name).unwrap().try_into().unwrap())
}

fn class_guid(name: &str) -> dtyp::Guid {
    let p1 = schema();
    p1.class(p1.class_by_name(name).unwrap())
        .unwrap()
        .schema_id_guid
}

fn attr_guid(name: &str) -> dtyp::Guid {
    let p1 = schema();
    p1.attribute_schema_id_guid(p1.attribute_by_name(name).unwrap())
        .unwrap()
}

/// docs/51 §4.3 step 5 (the table); [MS-SAMR] 2.2.1.14, 3.1.1.6 items 11,
/// 14, 20, 22, 23; 3.1.1.8.1 item 1.2 (accountExpires default), item 2.2
/// (0x80000002); A-75 (counter RIDs from 1101; 502 the only fixed RID);
/// A-79 (no 500/501/512).
#[test]
fn the_object_table_is_docs_51_step_5() {
    let dir = TempDir::new();
    let input = input(&dir, 61002, 61007);
    let p = plan(&input);
    let roles: Vec<ObjectRole> = p.objects.iter().map(|o| o.role).collect();
    assert_eq!(
        roles,
        vec![
            ObjectRole::NamingContextRoot,
            ObjectRole::Tier0Ou,
            ObjectRole::WorkstationsOu,
            ObjectRole::Krbtgt,
            ObjectRole::DcComputer,
            ObjectRole::LdapService,
            ObjectRole::AdminService,
            ObjectRole::ChangePasswordService,
            ObjectRole::FirstAdmin(0),
            ObjectRole::FirstAdmin(1),
            ObjectRole::Tier0Group,
            ObjectRole::BootstrapGroup,
        ]
    );
    // The domain SID: S-1-5-21-r1-r2-r3 ([MS-DTYP] 2.4.2.4).
    assert_eq!(p.domain_sid.identifier_authority(), SECURITY_NT_AUTHORITY);
    assert_eq!(p.domain_sid.sub_authority().len(), 4);
    assert_eq!(p.domain_sid.sub_authority()[0], SECURITY_NT_NON_UNIQUE);
    let rid_of = |role| {
        p.object(role)
            .unwrap()
            .sid
            .map(|s: Sid| *s.sub_authority().last().unwrap())
    };
    let root = p.object(ObjectRole::NamingContextRoot).unwrap();
    assert_eq!(root.parent, None);
    assert_eq!(root.class_name, "domainDNS");
    assert_eq!(root.sid, Some(p.domain_sid));
    assert_eq!(value(root, "dc"), Some(&b"example"[..]));
    assert_eq!(
        value(root, "objectSid"),
        Some(p.domain_sid.encode().as_slice())
    );
    assert_eq!(root.dn.rdns(), ["dc=example", "dc=test"]);
    let tier0 = p.object(ObjectRole::Tier0Ou).unwrap();
    assert_eq!(tier0.parent, Some(root.guid));
    assert_eq!(tier0.dn.rdns(), ["ou=Tier0", "dc=example", "dc=test"]);
    assert_eq!(tier0.sid, None);
    // krbtgt: RID 502, cn = sAMAccountName = "krbtgt", N without D,
    // accountExpires never, no pwdLastSet.
    let krbtgt = p.object(ObjectRole::Krbtgt).unwrap();
    assert_eq!(krbtgt.parent, Some(tier0.guid));
    assert_eq!(krbtgt.rid, RidSource::Fixed(DOMAIN_USER_RID_KRBTGT));
    assert_eq!(rid_of(ObjectRole::Krbtgt), Some(0x1F6));
    assert_eq!(value(krbtgt, "cn"), Some(&b"krbtgt"[..]));
    assert_eq!(value(krbtgt, "sAMAccountName"), Some(&b"krbtgt"[..]));
    assert_eq!(flags(krbtgt, "userAccountControl"), ADS_UF_NORMAL_ACCOUNT);
    assert_eq!(int64(krbtgt, "accountExpires"), ACCOUNT_EXPIRES_NEVER);
    assert_eq!(value(krbtgt, "pwdLastSet"), None);
    // The DC: ST, <NAME>$, dNSHostName, no SPN, counter RID 1101.
    let dc = p.object(ObjectRole::DcComputer).unwrap();
    assert_eq!(dc.class_name, "computer");
    assert_eq!(dc.rid, RidSource::Counter(1101));
    assert_eq!(value(dc, "sAMAccountName"), Some(&b"DC1$"[..]));
    assert_eq!(flags(dc, "userAccountControl"), ADS_UF_SERVER_TRUST_ACCOUNT);
    assert_eq!(value(dc, "dNSHostName"), Some(&b"dc1.example.test"[..]));
    assert_eq!(value(dc, "servicePrincipalName"), None);
    assert_eq!(value(dc, "pwdLastSet"), None);
    // The service objects: WT, one SPN each (ldap/, admind/ — A-73).
    let ldap = p.object(ObjectRole::LdapService).unwrap();
    assert_eq!(ldap.rid, RidSource::Counter(1102));
    assert_eq!(
        flags(ldap, "userAccountControl"),
        ADS_UF_WORKSTATION_TRUST_ACCOUNT
    );
    assert_eq!(
        value(ldap, "servicePrincipalName"),
        Some(&b"ldap/dc1.example.test"[..])
    );
    let admin = p.object(ObjectRole::AdminService).unwrap();
    assert_eq!(admin.rid, RidSource::Counter(1103));
    assert_eq!(
        value(admin, "servicePrincipalName"),
        Some(&b"admind/dc1.example.test"[..])
    );
    assert_eq!(value(admin, "sAMAccountName"), Some(&b"adminsvc$"[..]));
    // Task K9 — the change-password service object (RFC 3244 §2; docs/53
    // §5.2): WT, the DC's dNSHostName, its one SPN `kadmin/changepw`, no
    // pwdLastSet (its key comes from the ceremony), counter RID 1104.
    let changepw = p.object(ObjectRole::ChangePasswordService).unwrap();
    assert_eq!(changepw.class_name, "computer");
    assert_eq!(changepw.parent, Some(tier0.guid));
    assert_eq!(changepw.rid, RidSource::Counter(1104));
    assert_eq!(
        flags(changepw, "userAccountControl"),
        ADS_UF_WORKSTATION_TRUST_ACCOUNT
    );
    assert_eq!(
        value(changepw, "servicePrincipalName"),
        Some(&b"kadmin/changepw"[..])
    );
    assert_eq!(
        value(changepw, "sAMAccountName"),
        Some(&b"changepwsvc$"[..])
    );
    assert_eq!(
        value(changepw, "dNSHostName"),
        Some(&b"dc1.example.test"[..])
    );
    assert_eq!(value(changepw, "pwdLastSet"), None);
    // The first administrators: N enabled (no D), pwdLastSet = the
    // provisioning time (FILETIME), accountExpires never.
    let expected_pwd = directory_admin::filetime(&now()).unwrap();
    for (i, name) in ["alice", "bob"].iter().enumerate() {
        let a = p.object(ObjectRole::FirstAdmin(i)).unwrap();
        assert_eq!(a.parent, Some(tier0.guid));
        assert_eq!(a.rid, RidSource::Counter(1105 + i as u32));
        assert_eq!(value(a, "sAMAccountName"), Some(name.as_bytes()));
        let uac = flags(a, "userAccountControl");
        assert_eq!(uac, ADS_UF_NORMAL_ACCOUNT);
        assert_eq!(uac & ADS_UF_ACCOUNT_DISABLE, 0);
        assert_eq!(int64(a, "pwdLastSet"), expected_pwd);
        assert_eq!(int64(a, "accountExpires"), ACCOUNT_EXPIRES_NEVER);
    }
    // The groups: 0x80000002; Tier-0 = the first administrators; the
    // bootstrap group empty, in the workstations OU.
    let group = p.object(ObjectRole::Tier0Group).unwrap();
    assert_eq!(group.rid, RidSource::Counter(1107));
    assert_eq!(flags(group, "groupType"), PROVISIONED_GROUP_TYPE);
    assert_eq!(PROVISIONED_GROUP_TYPE, 0x8000_0002);
    let members: Vec<&[u8]> = values(group, "member");
    let admins: Vec<[u8; 16]> = (0..2)
        .map(|i| {
            p.object(ObjectRole::FirstAdmin(i))
                .unwrap()
                .guid
                .to_packet()
        })
        .collect();
    assert_eq!(members, admins.iter().map(|g| &g[..]).collect::<Vec<_>>());
    let bootstrap = p.object(ObjectRole::BootstrapGroup).unwrap();
    assert_eq!(bootstrap.rid, RidSource::Counter(1108));
    assert_eq!(
        bootstrap.parent,
        Some(p.object(ObjectRole::WorkstationsOu).unwrap().guid)
    );
    assert!(values(bootstrap, "member").is_empty());
    // No predefined RID other than 502 (A-79: no 500 / 501 / 512).
    for o in &p.objects {
        if let Some(sid) = o.sid {
            if o.role != ObjectRole::NamingContextRoot {
                let rid = *sid.sub_authority().last().unwrap();
                assert!(rid == 502 || rid >= 1101, "{:?} rid {rid}", o.role);
            }
        }
    }
    // Every GUID distinct and non-NULL; whenCreated = whenChanged = now.
    let mut guids: Vec<[u8; 16]> = p.objects.iter().map(|o| o.guid.to_packet()).collect();
    assert!(guids.iter().all(|g| *g != [0u8; 16]));
    guids.sort();
    guids.dedup();
    assert_eq!(guids.len(), p.objects.len());
    let dstime = directory_pip::dstime_of(&now()).unwrap();
    for o in &p.objects {
        assert_eq!(int64(o, "whenCreated"), dstime, "{:?}", o.role);
        assert_eq!(int64(o, "whenChanged"), dstime, "{:?}", o.role);
    }
    assert_eq!(p.counter_rids(), 8);
    assert_eq!((CHANGE_SEQ_FIRST, CHANGE_SEQ_END_EXCLUSIVE), (1, u64::MAX));
}

/// docs/51 §4.3 step 5: without a workstations OU the bootstrap group sits
/// under the NC root (Q-376 item 1).
#[test]
fn without_a_workstations_ou_the_bootstrap_group_is_under_the_root() {
    let dir = TempDir::new();
    let mut input = input(&dir, 61002, 61007);
    input.names.workstations_ou = None;
    let p = plan(&input);
    assert!(p.object(ObjectRole::WorkstationsOu).is_none());
    let root = p.object(ObjectRole::NamingContextRoot).unwrap();
    assert_eq!(
        p.object(ObjectRole::BootstrapGroup).unwrap().parent,
        Some(root.guid)
    );
}

/// docs/51 §10; A-76; A-84 (no INHERIT_ONLY_ACE, no CREATOR_* ACE, no
/// generic bit on the root); [MS-DTYP] 2.4.4.1 (CONTAINER_INHERIT_ACE),
/// 2.4.4.2, 2.4.4.3, 2.4.5 (ACL_REVISION_DS), 2.4.6 (SR | DP); [MS-ADTS]
/// 5.1.3.2 (the right values), 6.1.3.1 (regular before object ACEs,
/// object ACEs in octet order); crates/pdp `desired_right`.
#[test]
fn the_root_descriptor_grants_the_tier0_group_exactly_the_operations_rights() {
    let dir = TempDir::new();
    let p = plan(&input(&dir, 61002, 61007));
    let tier0 = p.object(ObjectRole::Tier0Group).unwrap().sid.unwrap();
    let sd = &p.object(ObjectRole::NamingContextRoot).unwrap().descriptor;
    assert_eq!(sd.owner_sid, Some(tier0));
    assert_eq!(sd.group_sid, Some(tier0));
    assert_eq!(sd.control.0, 0x8000 | 0x0004);
    assert!(sd.sacl.is_none());
    let dacl = sd.dacl.as_ref().unwrap();
    assert_eq!(dacl.acl_revision, ACL_REVISION_DS);
    assert_eq!(dacl.aces.len(), 11);
    // Every ACE: an allow, CONTAINER_INHERIT_ACE only, no generic bit; the
    // Tier-0 group's for every ACE but the PRINCIPAL_SELF one of task K9
    // (checked below), which alone names an InheritedObjectType.
    let generic = 0xF000_0000u32;
    let principal_self = Sid::new(SECURITY_NT_AUTHORITY, &[PRINCIPAL_SELF_RID]).unwrap();
    for ace in &dacl.aces {
        assert_eq!(ace.ace_flags(), ace_flags::CONTAINER_INHERIT_ACE, "{ace:?}");
        assert_eq!(ace.mask().unwrap().0 & generic, 0, "{ace:?}");
        match ace {
            Ace::AccessAllowed(a) => assert_eq!(a.sid, tier0),
            Ace::AccessAllowedObject(a) if a.sid == principal_self => {}
            Ace::AccessAllowedObject(a) => {
                assert_eq!(a.sid, tier0);
                assert!(a.object_type.is_some());
                assert!(a.inherited_object_type.is_none());
            }
            other => panic!("unexpected ACE {other:?}"),
        }
    }
    // The simple ACE first: RP | LC | DE.
    match &dacl.aces[0] {
        Ace::AccessAllowed(a) => assert_eq!(
            a.mask.0,
            RIGHT_DS_READ_PROPERTY | RIGHT_DS_LIST_CONTENTS | RIGHT_DELETE
        ),
        other => panic!("first ACE {other:?}"),
    }
    assert_eq!(provision::ROOT_OBJECT_RIGHTS, 0x0001_0014);
    // The Tier-0 group's object ACEs: exactly these (mask, ObjectType) pairs.
    let mut grants: Vec<(u32, dtyp::Guid)> = dacl.aces[1..]
        .iter()
        .filter_map(|ace| match ace {
            Ace::AccessAllowedObject(a) if a.sid == principal_self => None,
            Ace::AccessAllowedObject(a) => Some((a.mask.0, a.object_type.unwrap())),
            other => panic!("{other:?}"),
        })
        .collect();
    let mut expected = vec![
        (RIGHT_DS_CREATE_CHILD, class_guid("user")),
        (RIGHT_DS_CREATE_CHILD, class_guid("computer")),
        (RIGHT_DS_CREATE_CHILD, class_guid("group")),
        (RIGHT_DS_CREATE_CHILD, class_guid("organizationalUnit")),
        (RIGHT_DS_CREATE_CHILD, class_guid("container")),
        (RIGHT_DS_WRITE_PROPERTY, attr_guid("userAccountControl")),
        (RIGHT_DS_WRITE_PROPERTY, attr_guid("accountExpires")),
        (RIGHT_DS_WRITE_PROPERTY, attr_guid("member")),
        (RIGHT_DS_CONTROL_ACCESS, USER_FORCE_CHANGE_PASSWORD),
    ];
    grants.sort_by_key(|(m, g)| (*m, g.to_packet()));
    expected.sort_by_key(|(m, g)| (*m, g.to_packet()));
    assert_eq!(grants, expected);
    // [MS-ADTS] 6.1.3.1 rule 4: the object ACEs in ascending octet order.
    let encoded: Vec<Vec<u8>> = dacl.aces[1..].iter().map(|a| a.encode().unwrap()).collect();
    let mut sorted = encoded.clone();
    sorted.sort();
    assert_eq!(encoded, sorted);
    // Task K9 — exactly one PRINCIPAL_SELF ACE ([MS-DTYP] 2.4.2.4: S-1-5-10;
    // [MS-ADTS] 5.1.3.3): CONTROL_ACCESS for User-Change-Password
    // ([MS-ADTS] 6.1.1.2.7.52, "on itself" — 3.1.1.3.1.5.1), inherited as
    // effective by user objects only (InheritedObjectType = the user class,
    // [MS-DTYP] 2.4.4.3).
    let selves: Vec<&dtyp::ObjectAce> = dacl
        .aces
        .iter()
        .filter_map(|ace| match ace {
            Ace::AccessAllowedObject(a) if a.sid == principal_self => Some(a),
            _ => None,
        })
        .collect();
    assert_eq!(selves.len(), 1);
    assert_eq!(selves[0].mask.0, RIGHT_DS_CONTROL_ACCESS);
    assert_eq!(selves[0].object_type, Some(USER_CHANGE_PASSWORD));
    assert_eq!(selves[0].inherited_object_type, Some(class_guid("user")));
    assert_eq!(
        USER_CHANGE_PASSWORD.to_text(),
        "ab721a53-1e2f-11d0-9819-00aa0040529b"
    );
    assert_eq!(principal_self.to_sid_string(), "S-1-5-10");
    // The values pdp checks, as [MS-ADTS] 5.1.3.2 gives them.
    assert_eq!(
        (
            RIGHT_DS_CREATE_CHILD,
            RIGHT_DS_LIST_CONTENTS,
            RIGHT_DS_READ_PROPERTY,
            RIGHT_DS_WRITE_PROPERTY,
            RIGHT_DS_CONTROL_ACCESS,
            RIGHT_DELETE
        ),
        (0x1, 0x4, 0x10, 0x20, 0x100, 0x1_0000)
    );
}

/// docs/51 §10 ("provisioning and runtime agree"); A-84: every child's
/// descriptor is directory-admin's `new_object_descriptor` of its parent's
/// descriptor and its class, the Tier-0 group as the token owner.
#[test]
fn every_child_descriptor_is_the_runtime_computation() {
    let dir = TempDir::new();
    let p = plan(&input(&dir, 61002, 61007));
    let tier0 = p.object(ObjectRole::Tier0Group).unwrap().sid.unwrap();
    for o in &p.objects {
        let Some(parent) = o.parent else { continue };
        let parent = p.objects.iter().find(|x| x.guid == parent).unwrap();
        let expected =
            new_object_descriptor(&parent.descriptor, class_guid(o.class_name), &tier0).unwrap();
        assert_eq!(o.descriptor, expected, "{:?}", o.role);
        assert_eq!(o.descriptor.owner_sid, Some(tier0));
        // Every inherited copy is effective (INHERITED_ACE) or inheritable
        // (INHERITED_ACE | INHERIT_ONLY_ACE | CONTAINER_INHERIT_ACE): the
        // root's 11 ACEs as inheritable copies, its 10 Tier-0 ACEs as
        // effective copies, and — on a user object only — the PRINCIPAL_SELF
        // ACE of task K9 as an effective copy too (its InheritedObjectType
        // is the user class: [MS-DTYP] 2.4.4.3, 2.5.3.4).
        let dacl = o.descriptor.dacl.as_ref().unwrap();
        let expected = if o.class_name == "user" { 22 } else { 21 };
        assert_eq!(dacl.aces.len(), expected, "{:?}", o.role);
    }
}

/// Task K9 — docs/53 §5.6 step 4 (layer 5 takes the grant from a
/// PRINCIPAL_SELF ACE inherited from the domain root); [MS-ADTS]
/// 3.1.1.3.1.5.1 (User-Change-Password "on itself"), 5.1.3.3 (S-1-5-10
/// replaced by O!objectSid at the access check); [MS-DTYP] 2.4.4.1
/// (INHERIT_ONLY_ACE), 2.4.4.3 (InheritedObjectType): every user object —
/// the first administrators here — holds an effective (not inherit-only)
/// copy of the PRINCIPAL_SELF User-Change-Password ACE; every other object
/// holds only an inherit-only copy, so the right is effective nowhere else.
#[test]
fn every_user_holds_user_change_password_for_itself() {
    let dir = TempDir::new();
    let p = plan(&input(&dir, 61002, 61007));
    let principal_self = Sid::new(SECURITY_NT_AUTHORITY, &[PRINCIPAL_SELF_RID]).unwrap();
    let mut users = 0;
    for o in &p.objects {
        let Some(_) = o.parent else { continue };
        let copies: Vec<&dtyp::ObjectAce> = o
            .descriptor
            .dacl
            .as_ref()
            .unwrap()
            .aces
            .iter()
            .filter_map(|ace| match ace {
                Ace::AccessAllowedObject(a)
                    if a.sid == principal_self && a.object_type == Some(USER_CHANGE_PASSWORD) =>
                {
                    Some(a)
                }
                _ => None,
            })
            .collect();
        let effective = copies
            .iter()
            .filter(|a| a.ace_flags & ace_flags::INHERIT_ONLY_ACE == 0)
            .count();
        if o.class_name == "user" {
            users += 1;
            assert_eq!(effective, 1, "{:?}", o.role);
        } else {
            assert_eq!(effective, 0, "{:?}", o.role);
        }
        // The inheritable copy passes the grant on to the users below.
        assert_eq!(copies.len() - effective, 1, "{:?}", o.role);
    }
    // krbtgt and the two first administrators.
    assert_eq!(users, 3);
}

/// Task K9 — layer 5 (crates/pdp `acl_grants`, [MS-DTYP] 2.5.3.2 with the
/// [MS-DTYP] 2.5.3.1.1 PRINCIPAL_SELF substitution; [MS-ADTS] 5.1.3.3,
/// 5.1.3.3.4) over the planned descriptors: a user is granted
/// User-Change-Password on its **own** object ([MS-ADTS] 3.1.1.3.1.5.1, "on
/// itself") by the PRINCIPAL_SELF ACE alone (no group in its token), never on
/// another user's object, never User-Force-Change-Password; a computer (the
/// change-password service object) is not granted it on itself (the ACE is
/// effective on user objects only — docs/53 R53-1). The Tier-0 group keeps
/// its User-Force-Change-Password (docs/51 §10).
#[test]
fn the_self_ace_grants_the_change_on_the_own_object_only() {
    let dir = TempDir::new();
    let p = plan(&input(&dir, 61002, 61007));
    let subject = |sid: Sid, groups: &[Sid]| pdp::Subject {
        principal: sid,
        groups: groups.iter().copied().collect(),
        claims: std::collections::BTreeMap::new(),
        auth: pdp::AuthContext {
            strength: pdp::AuthStrength::KerberosFast,
            armored: true,
            ticket_age: core::time::Duration::ZERO,
            ticket_verified: true,
        },
        tier: Tier::Tier2,
    };
    let context = |o: &provision::PlannedObject| pdp::DirObjectContext {
        object_class: class_guid(o.class_name),
        superclasses: Vec::new(),
        object_sid: o.sid,
    };
    let change = pdp::Right::ControlAccess {
        right: USER_CHANGE_PASSWORD,
    };
    let force = pdp::Right::ControlAccess {
        right: USER_FORCE_CHANGE_PASSWORD,
    };
    let alice = p.object(ObjectRole::FirstAdmin(0)).unwrap();
    let bob = p.object(ObjectRole::FirstAdmin(1)).unwrap();
    let alice_subject = subject(alice.sid.unwrap(), &[]);
    assert!(pdp::acl_grants(
        &alice_subject,
        &alice.descriptor,
        &context(alice),
        &change
    ));
    assert!(!pdp::acl_grants(
        &alice_subject,
        &bob.descriptor,
        &context(bob),
        &change
    ));
    assert!(!pdp::acl_grants(
        &alice_subject,
        &alice.descriptor,
        &context(alice),
        &force
    ));
    let changepw = p.object(ObjectRole::ChangePasswordService).unwrap();
    assert!(!pdp::acl_grants(
        &subject(changepw.sid.unwrap(), &[]),
        &changepw.descriptor,
        &context(changepw),
        &change
    ));
    let tier0 = p.object(ObjectRole::Tier0Group).unwrap().sid.unwrap();
    assert!(pdp::acl_grants(
        &subject(bob.sid.unwrap(), &[tier0]),
        &alice.descriptor,
        &context(alice),
        &force
    ));
}

/// docs/51 §4.3 step 6: format 2, version 1, the tier map, the bootstrap
/// group, the Kerberos rule narrowed to the phase-1 KDC's actions (Q-377),
/// the rootDSE rule, the Tier-0 directory and policy grants; policy-store
/// decodes it back.
#[test]
fn the_policy_is_docs_51_step_6() {
    let dir = TempDir::new();
    let p = plan(&input(&dir, 61002, 61007));
    let tier0 = p.object(ObjectRole::Tier0Group).unwrap().sid.unwrap();
    let bootstrap = p.object(ObjectRole::BootstrapGroup).unwrap().sid.unwrap();
    assert_eq!(p.policy.version.0, 1);
    assert_eq!(
        p.policy.principals.iter().collect::<Vec<_>>(),
        vec![(&tier0, &Tier::Tier0)]
    );
    assert_eq!(p.policy.subtrees.len(), 1);
    assert_eq!(
        p.policy.subtrees[0].0.rdns(),
        ["ou=Tier0", "dc=example", "dc=test"]
    );
    assert_eq!(p.policy.subtrees[0].1, Tier::Tier0);
    assert_eq!(p.policy.mandatory_fast.bootstrap_group, bootstrap);
    assert_eq!(p.policy.mandatory_fast.first_rule_id.0, 100);
    let ids: Vec<u32> = p.policy.rules.iter().map(|r| r.id.0).collect();
    assert_eq!(ids, vec![1, 2, 3, 4, 5]);
    let r = &p.policy.rules;
    // Rule 1: exactly the Kerberos actions the phase-1 KDC asks the PDP for
    // (crates/kdc as_exchange.rs `Action::KdcAs`, tgs_exchange.rs
    // `Action::KdcTgs`) — not the whole Kerberos class (Q-377).
    assert_eq!(
        r[0].when.action,
        ActionMatch::AnyOf(vec![Action::KdcAs, Action::KdcTgs])
    );
    assert_ne!(r[0].when.action, ActionMatch::Class(ActionClass::Kerberos));
    assert_eq!(r[0].when.resource, ResourceMatch::Kerberos { kind: None });
    assert_eq!(r[1].when.action, ActionMatch::Exact(Action::DirRead));
    assert_eq!(r[1].when.resource, ResourceMatch::RootDse);
    // No rule names S4U, and no separate admin-SPN rule (rule 1 covers
    // KdcTgs for every service — Q-377).
    for rule in r {
        for s4u in [Action::KdcS4u2Self, Action::KdcS4u2Proxy] {
            assert!(!rule.when.action.matches(&s4u), "rule {}", rule.id.0);
        }
    }
    assert_eq!(r[2].when.subject, SubjectMatch::MemberOf(tier0));
    match &r[2].when.resource {
        ResourceMatch::DirSubtree { base } => {
            assert_eq!(base.dn().rdns(), ["dc=example", "dc=test"]);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(r[3].when.action, ActionMatch::Exact(Action::PolicyAdmin));
    assert_eq!(r[3].when.subject, SubjectMatch::MemberOf(tier0));
    // Rule 5 (task K9; docs/53 §5.6 step 4): exactly
    // `DirControlRight(User-Change-Password)` under the NC root, any
    // subject (the PRINCIPAL_SELF ACE decides), the kpasswd PEP's transport
    // `{encrypted, sealed, channel_bound}` from the internal network.
    assert_eq!(
        r[4].when.action,
        ActionMatch::Exact(Action::DirControlRight(ControlRightId(
            USER_CHANGE_PASSWORD
        )))
    );
    assert_eq!(r[4].when.subject, SubjectMatch::Any);
    assert_eq!(r[4].effect, pdp::Effect::Allow);
    match &r[4].when.resource {
        ResourceMatch::DirSubtree { base } => {
            assert_eq!(base.dn().rdns(), ["dc=example", "dc=test"]);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        r[4].when.context.min_transport,
        TransportSec {
            encrypted: true,
            sealed: true,
            channel_bound: true
        }
    );
    assert_eq!(r[4].when.context.src_net, Some(IpScope::Internal));
    // No rule but 5 names User-Change-Password, and rule 5 names nothing
    // else (in particular not User-Force-Change-Password).
    for rule in &r[..4] {
        assert!(!rule
            .when
            .action
            .matches(&Action::DirControlRight(ControlRightId(
                USER_CHANGE_PASSWORD
            ))));
    }
    assert!(!r[4]
        .when
        .action
        .matches(&Action::DirControlRight(ControlRightId(
            USER_FORCE_CHANGE_PASSWORD
        ))));
    assert_eq!(p.policy.anonymous.len(), 1);
    let decoded = policy_store::DevelopmentPolicy::decode(&p.policy_file).unwrap();
    assert_eq!(decoded, p.policy);
}

/// docs/51 §4.3 step 7; docs/50 §7.1: every configuration file parses with
/// its own schema; keyd's `uid_roles` (A-73), auditd's `uid_sources`,
/// admind's new keys, dird's A8 keys emitted; no secret value.
#[test]
fn every_configuration_parses_with_its_schema() {
    let dir = TempDir::new();
    let input = input(&dir, 61002, 61007);
    let p = plan(&input);
    assert_eq!(p.configs.len(), 9);
    for file in &p.configs {
        file.parse_back().unwrap();
        let text = file.text();
        assert!(text.ends_with('\n'));
        assert!(text
            .bytes()
            .all(|b| b == b'\n' || (0x20..=0x7E).contains(&b)));
    }
    let text_of = |d: provision::Daemon| p.configs.iter().find(|f| f.daemon == d).unwrap().text();
    let keyd = config::KeydSettings::parse(text_of(provision::Daemon::Keyd).as_bytes()).unwrap();
    use config::RoleName;
    assert_eq!(keyd.uid_roles().role_of(61003), Some(RoleName::Kdc));
    assert_eq!(keyd.uid_roles().role_of(61006), Some(RoleName::Directory));
    assert_eq!(keyd.uid_roles().role_of(61007), Some(RoleName::Admin));
    assert_eq!(keyd.uid_roles().role_of(61002), Some(RoleName::Ldap));
    assert_eq!(keyd.uid_roles().len(), 4);
    // Task K9: neither front is mapped in keyd (docs/53 R53-4: the front has
    // no keyd channel; docs/54 §4.3: dnsd is not mapped in keyd).
    assert_eq!(keyd.uid_roles().role_of(61008), None);
    assert_eq!(keyd.uid_roles().role_of(61009), None);
    let auditd =
        config::AuditdSettings::parse(text_of(provision::Daemon::Auditd).as_bytes()).unwrap();
    assert_eq!(auditd.uid_sources().len(), 7);
    // Task K9 (A-160; docs/questions/Q-960 item 6): auditd maps the two
    // fronts' uids to their sources.
    assert_eq!(
        auditd.uid_sources().source_of(61008),
        Some(config::AuditSource::KpasswdFront)
    );
    assert_eq!(
        auditd.uid_sources().source_of(61009),
        Some(config::AuditSource::Dnsd)
    );
    let admind =
        config::AdmindSettings::parse(text_of(provision::Daemon::Admind).as_bytes()).unwrap();
    assert_eq!(admind.admin_socket_group(), 61010);
    // A-102 (docs/52 §4.6): admind's file names no keyadm uid any more.
    assert!(!text_of(provision::Daemon::Admind)
        .lines()
        .any(|l| l.starts_with("keyadm_uid")));
    // A9 made `min_password_length` required (A-79): provisioning emits the
    // floor — the owner's 8 (docs/56 §7 P-24; A-92, docs/questions/Q-378
    // item 3).
    assert_eq!(admind.min_password_length(), 8);
    assert_eq!(
        provision::configs::MIN_PASSWORD_LENGTH,
        admind.min_password_length()
    );
    assert!(text_of(provision::Daemon::Admind)
        .lines()
        .any(|l| l == "min_password_length = 8"));
    let dird = text_of(provision::Daemon::Dird);
    for key in DIRD_ADMIN_CHANNEL_KEYS {
        assert!(dird.contains(&format!("\n{key} = ")), "{key}");
    }
    // A8's admin-channel keys (the main session's coordination note):
    // keyd's socket and uid as in keyd's own file; node_id 32 lower-case
    // hex digits, not all zero; admin_ticket_age_max inside 60s..=3600s;
    // admin_quorum 2 (P-22); provision_manifest = the manifest's path; and
    // the admin channel itself, which all of them require.
    let node = provision::configs::node_id_text(&p.node_id);
    assert_eq!(node.len(), 32);
    assert!(node
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    assert_ne!(node, "0".repeat(32));
    let expected = [
        format!(
            "dird_admin_socket = {}",
            input.paths.dird_admin_socket.as_str()
        ),
        "admind_uid = 61006".to_owned(),
        format!("keyd_socket = {}", input.paths.keyd_socket.as_str()),
        "keyd_uid = 61001".to_owned(),
        format!("node_id = {node}"),
        "admin_ticket_age_max = 600s".to_owned(),
        "admin_quorum = 2".to_owned(),
        format!("provision_manifest = {}", input.paths.manifest.as_str()),
        // Task A16 (docs/51 §5.10): where dird writes `policy.next`.
        format!("policy_next_path = {}", input.paths.policy_next.as_str()),
    ];
    for line in expected {
        assert!(dird.lines().any(|l| l == line), "{line}");
    }
    assert!((60..=3600).contains(&provision::configs::ADMIN_TICKET_AGE_MAX_SECS));
    // dird matches the manifest against its realm, naming context and host
    // name (A8): the same values here.
    let m = &p.manifest;
    assert!(dird
        .lines()
        .any(|l| l == format!("realm = {}", m.realm().as_str())));
    assert!(dird
        .lines()
        .any(|l| l == format!("dns_host_name = {}", m.dc_fqdn())));
    assert!(dird
        .lines()
        .any(|l| l == "naming_context = dc=example,dc=test"));
    assert_eq!(m.naming_context_labels(), ["example", "test"]);
}

/// docs/51 §6 ("keyadm talks to keyd only"); A-102 (docs/52 §4.6): keyadm's
/// file parses back with keyadm's own schema and names keyd's socket and uid
/// — and nothing of admind (the A-97 `admin_socket` + `admind_uid` pair went
/// with the keyadm channel).
#[test]
fn keyadms_configuration_names_keyd_only() {
    let dir = TempDir::new();
    let input = input(&dir, 61002, 61007);
    let p = plan(&input);
    let text_of = |d: provision::Daemon| p.configs.iter().find(|f| f.daemon == d).unwrap().text();
    let keyadm =
        config::KeyadmSettings::parse(text_of(provision::Daemon::Keyadm).as_bytes()).unwrap();
    assert_eq!(
        keyadm.keyd().socket().as_str(),
        input.paths.keyd_socket.as_str()
    );
    assert_eq!(keyadm.keyd().uid(), 61001);
    let text = text_of(provision::Daemon::Keyadm);
    assert_eq!(text.lines().filter(|l| l.contains(" = ")).count(), 2);
    assert!(!text.lines().any(|l| l.starts_with("admin_socket")));
    assert!(!text.lines().any(|l| l.starts_with("admind_uid")));
}

/// docs/51 §4.3 step 8; A-86: the manifest parses back, and names the
/// planned GUIDs and SID.
#[test]
fn the_manifest_parses_back() {
    let dir = TempDir::new();
    let p = plan(&input(&dir, 61002, 61007));
    let m = Manifest::parse(p.manifest.encode().as_bytes()).unwrap();
    assert_eq!(m, p.manifest);
    assert_eq!(m.domain_sid(), &p.domain_sid);
    assert_eq!(
        m.krbtgt().handle.principal.as_bytes(),
        &p.object(ObjectRole::Krbtgt).unwrap().guid.to_packet()
    );
    assert_eq!(m.first_admins().len(), 2);
    assert_eq!(m.first_admins()[0].sam_account_name(), "alice");
}

/// docs/52 §2 row 37 (N4, A-102): the manifest carries each first
/// administrator's salt, and it is exactly what the directory's salt
/// function gives (`directory_pip::account_salt`, R47-4) — the salt
/// `first-admin-secret` presents and keyadm's ceremony grant binds.
#[test]
fn the_manifest_carries_the_directorys_salts() {
    let dir = TempDir::new();
    let p = plan(&input(&dir, 61002, 61007));
    for admin in p.manifest.first_admins() {
        let expected = directory_pip::account_salt(
            p.manifest.realm(),
            directory_pip::AccountKind::User,
            admin.sam_account_name(),
        )
        .unwrap();
        assert_eq!(
            admin.salt(),
            expected.as_str(),
            "{}",
            admin.sam_account_name()
        );
    }
    assert!(p
        .manifest
        .encode()
        .lines()
        .any(|l| l.starts_with("first_admin_salts = ")));
}

/// docs/CLEAN-ROOM.md: the plan's debug output never shows the integrity key.
#[test]
fn the_integrity_key_is_redacted_in_debug_output() {
    let dir = TempDir::new();
    let p = plan(&input(&dir, 61002, 61007));
    let debug = format!("{p:?}");
    assert!(debug.contains("<redacted>"));
}

fn refused(input: &provision::DomainInput) -> PlanError {
    Plan::build(input, now(), &mut CountingRandom::default()).unwrap_err()
}

/// docs/52 §7 R14; A-102 on docs/questions/Q-469 (b) ("one front per zone;
/// external LDAP connections are not in phase 1"): the zone table goes to
/// ldap-front's file (required there — every LDAP listener inside it) and
/// no longer to dird's (dird derives the LDAP zone from the front's peer
/// uid); without an internal network provisioning refuses; an LDAP listener
/// outside the internal networks fails the parse-back by ldap-front's own
/// schema. Addresses are test data.
#[test]
fn the_zone_table_is_ldap_fronts() {
    let dir = TempDir::new();
    let input = input(&dir, 61002, 61007);
    let p = plan(&input);
    let text_of = |d: provision::Daemon| p.configs.iter().find(|f| f.daemon == d).unwrap().text();
    let front =
        config::LdapFrontSettings::parse(text_of(provision::Daemon::LdapFront).as_bytes()).unwrap();
    assert_eq!(front.internal_networks().len(), 2);
    assert!(text_of(provision::Daemon::LdapFront)
        .lines()
        .any(|l| l == "internal_networks = 10.0.0.0/8, 127.0.0.0/8"));
    assert!(!text_of(provision::Daemon::Dird)
        .lines()
        .any(|l| l.starts_with("internal_networks")));

    let mut none = input.clone();
    none.network.internal_networks.clear();
    let error = match refused(&none) {
        PlanError::Input(error) => error,
        other => panic!("not an input error: {other:?}"),
    };
    assert_eq!(error.kind, InputErrorKind::MissingInternalNetwork);
    assert_eq!(error.field, "internal-network");

    // The kdc's listener moved inside 10.0.0.0/8 (task R15b: the kdc's file
    // has the same rule), so only the LDAP listener is outside.
    let mut outside = input.clone();
    outside.network.internal_networks = vec!["10.0.0.0/8".to_owned()];
    outside.network.kdc_listen = vec!["10.0.0.5:88".to_owned()];
    match refused(&outside) {
        PlanError::Config(daemon, error) => {
            assert_eq!(daemon, provision::Daemon::LdapFront);
            assert_eq!(error.kind(), config::ErrorKind::ListenerNotInternal);
        }
        other => panic!("{other:?}"),
    }
}

/// docs/50 R50-9 ("binding to internal interfaces only"), §4.1; task R15b
/// (docs/questions/Q-632): the zone table goes to the kdc's file too —
/// always, since provisioning requires one network — and a kdc listener
/// outside the internal networks fails the parse-back by the kdc's own
/// schema. Addresses are test data.
#[test]
fn the_kdc_file_carries_the_zone_table_and_listens_inside_it() {
    let dir = TempDir::new();
    let input = input(&dir, 61002, 61007);
    let p = plan(&input);
    let kdc_text = p
        .configs
        .iter()
        .find(|f| f.daemon == provision::Daemon::Kdc)
        .unwrap()
        .text();
    let kdc = config::KdcSettings::parse(kdc_text.as_bytes()).unwrap();
    assert_eq!(kdc.internal_networks().len(), 2);
    assert!(kdc_text
        .lines()
        .any(|l| l == "internal_networks = 10.0.0.0/8, 127.0.0.0/8"));

    let mut outside = input.clone();
    outside.network.kdc_listen = vec!["192.0.2.7:88".to_owned()];
    match refused(&outside) {
        PlanError::Config(daemon, error) => {
            assert_eq!(daemon, provision::Daemon::Kdc);
            assert_eq!(error.kind(), config::ErrorKind::ListenerNotInternal);
        }
        other => panic!("{other:?}"),
    }
}

/// Task K9 — the two network fronts' files (docs/53 R53-3, R53-4, §3.3,
/// §5.7; docs/54 §4.3, §4.6, §4.7; A-117, A-119) and dird's kpasswd channel
/// (docs/53 §5.6 step 1; docs/questions/Q-955 item 13, Q-964 item 12): each
/// file parses with its own schema; kpasswd-front listens on its TCP 464
/// address inside the internal networks, names dird's realm, dird's
/// `dird-kpasswd.sock` and uid and auditd; dnsd names `dird-dns.sock`, dird's
/// uid and auditd; dird's file admits exactly the front's uid on the same
/// socket; neither front file carries a key or a keyd endpoint (docs/50
/// §7.1; R53-4; docs/54 §4.3). Addresses and ids are test data.
#[test]
fn the_fronts_files_parse_and_name_dird_and_auditd() {
    let dir = TempDir::new();
    let input = input(&dir, 61002, 61007);
    let p = plan(&input);
    let text_of = |d: provision::Daemon| p.configs.iter().find(|f| f.daemon == d).unwrap().text();

    let front_text = text_of(provision::Daemon::KpasswdFront);
    let front = config::KpasswdFrontSettings::parse(front_text.as_bytes()).unwrap();
    assert_eq!(front.run_as().uid(), 61008);
    assert_eq!(front.run_as().gid(), 61008);
    assert_eq!(
        front.listen(),
        ["127.0.0.1:464".parse::<core::net::SocketAddr>().unwrap()]
    );
    assert_eq!(front.internal_networks().len(), 2);
    assert_eq!(front.realm(), "EXAMPLE.TEST");
    assert_eq!(
        front.dird().socket().as_str(),
        input.paths.dird_kpasswd_socket.as_str()
    );
    assert_eq!(front.dird().uid(), 61002);
    assert_eq!(
        front.audit().socket().as_str(),
        input.paths.audit_socket.as_str()
    );
    assert_eq!(front.audit().uid(), 61005);

    let dnsd_text = text_of(provision::Daemon::Dnsd);
    let dnsd = config::DnsdSettings::parse(dnsd_text.as_bytes()).unwrap();
    assert_eq!(dnsd.run_as().uid(), 61009);
    assert_eq!(
        dnsd.listen(),
        ["127.0.0.1:53".parse::<core::net::SocketAddr>().unwrap()]
    );
    assert_eq!(dnsd.internal_networks().len(), 2);
    assert_eq!(
        dnsd.dird().socket().as_str(),
        input.paths.dird_dns_socket.as_str()
    );
    assert_eq!(dnsd.dird().uid(), 61002);
    assert_eq!(dnsd.audit().uid(), 61005);

    for text in [&front_text, &dnsd_text] {
        assert!(!text.lines().any(|l| l.starts_with("keyd_")), "{text}");
        assert!(!text.contains("key_path"), "{text}");
    }

    let dird_text = text_of(provision::Daemon::Dird);
    let dird = config::DirdSettings::parse(dird_text.as_bytes()).unwrap();
    let channel = dird.kpasswd_channel().expect("the kpasswd channel");
    assert_eq!(
        channel.socket().as_str(),
        input.paths.dird_kpasswd_socket.as_str()
    );
    assert_eq!(channel.peer_uid(), 61008);
    for key in provision::configs::DIRD_KPASSWD_CHANNEL_KEYS {
        assert!(dird_text.contains(&format!("\n{key} = ")), "{key}");
    }
    // dird does not serve `dird-dns.sock` before task DN10: its file names
    // no DNS key (docs/questions/Q-973).
    assert!(!dird_text.contains("dns_socket"));
    assert!(!dird_text.contains("dnsd_uid"));
}

/// Task K9 — the fronts' listeners lie inside the internal networks
/// (docs/53 §3.3; docs/54 §4.7; A-114): one outside fails the parse-back by
/// the front's own schema (`ListenerNotInternal`); a front without a
/// listener is refused before anything is built (`MissingListener`).
#[test]
fn a_front_listener_outside_the_internal_networks_or_missing_is_refused() {
    let dir = TempDir::new();
    let base = input(&dir, 61002, 61007);
    for (daemon, change) in [
        (
            provision::Daemon::KpasswdFront,
            Box::new(|i: &mut provision::DomainInput| {
                i.network.kpasswd_listen = vec!["192.0.2.7:464".to_owned()];
            }) as Box<dyn Fn(&mut provision::DomainInput)>,
        ),
        (
            provision::Daemon::Dnsd,
            Box::new(|i: &mut provision::DomainInput| {
                i.network.dnsd_listen = vec!["192.0.2.7:53".to_owned()];
            }),
        ),
    ] {
        let mut i = base.clone();
        change(&mut i);
        match refused(&i) {
            PlanError::Config(refused_daemon, error) => {
                assert_eq!(refused_daemon, daemon);
                assert_eq!(error.kind(), config::ErrorKind::ListenerNotInternal);
            }
            other => panic!("{other:?}"),
        }
    }
    for (field, clear) in [
        (
            "kpasswd-listen",
            Box::new(|i: &mut provision::DomainInput| i.network.kpasswd_listen.clear())
                as Box<dyn Fn(&mut provision::DomainInput)>,
        ),
        (
            "dnsd-listen",
            Box::new(|i: &mut provision::DomainInput| i.network.dnsd_listen.clear()),
        ),
    ] {
        let mut i = base.clone();
        clear(&mut i);
        match refused(&i) {
            PlanError::Input(error) => {
                assert_eq!(error.kind, InputErrorKind::MissingListener);
                assert_eq!(error.field, field);
            }
            other => panic!("{other:?}"),
        }
    }
}

fn input_kind(e: PlanError) -> InputErrorKind {
    match e {
        PlanError::Input(i) => i.kind,
        other => panic!("not an input error: {other:?}"),
    }
}

/// P-22 item 3: at least two first administrators — no single-administrator
/// mode; the manifest's 8 at most (A-86).
#[test]
fn fewer_than_two_first_administrators_is_refused() {
    let dir = TempDir::new();
    let mut i = input(&dir, 61002, 61007);
    i.names.first_admins = vec!["alice".into()];
    assert_eq!(input_kind(refused(&i)), InputErrorKind::TooFewFirstAdmins);
    i.names.first_admins = Vec::new();
    assert_eq!(input_kind(refused(&i)), InputErrorKind::TooFewFirstAdmins);
    i.names.first_admins = (0..9).map(|n| format!("admin{n}")).collect();
    assert_eq!(input_kind(refused(&i)), InputErrorKind::TooManyFirstAdmins);
}

/// docs/50 §2.4 (one account per process), R50-3 (uid 0 never mapped).
#[test]
fn duplicate_and_root_uids_are_refused() {
    let dir = TempDir::new();
    let mut i = input(&dir, 61002, 61007);
    i.accounts.kdc.uid = 61002;
    assert_eq!(input_kind(refused(&i)), InputErrorKind::DuplicateUid);
    let mut i = input(&dir, 61002, 61007);
    i.accounts.keyadm_uid = 61006;
    assert_eq!(input_kind(refused(&i)), InputErrorKind::DuplicateUid);
    let mut i = input(&dir, 61002, 61007);
    i.accounts.auditd.uid = 0;
    assert_eq!(input_kind(refused(&i)), InputErrorKind::ReservedId);
    let mut i = input(&dir, 61002, 61007);
    i.accounts.keyd.gid = 0;
    assert_eq!(input_kind(refused(&i)), InputErrorKind::ReservedId);
    let mut i = input(&dir, 61002, 61007);
    i.accounts.admin_socket_group = u32::MAX;
    assert_eq!(input_kind(refused(&i)), InputErrorKind::ReservedId);
    // Task K9: each front its own uid (docs/53 §4.3; docs/54 §4.3), never 0.
    let mut i = input(&dir, 61002, 61007);
    i.accounts.kpasswd_front.uid = 61004;
    assert_eq!(input_kind(refused(&i)), InputErrorKind::DuplicateUid);
    let mut i = input(&dir, 61002, 61007);
    i.accounts.dnsd.uid = i.accounts.kpasswd_front.uid;
    assert_eq!(input_kind(refused(&i)), InputErrorKind::DuplicateUid);
    let mut i = input(&dir, 61002, 61007);
    i.accounts.dnsd.uid = 0;
    assert_eq!(input_kind(refused(&i)), InputErrorKind::ReservedId);
    let mut i = input(&dir, 61002, 61007);
    i.accounts.kpasswd_front.gid = 0;
    assert_eq!(input_kind(refused(&i)), InputErrorKind::ReservedId);
}

/// docs/47 §3.3 item 3; A-55: the realm is the NC's DNS name in upper
/// case; the NC labels pass `NamingContext::new`.
#[test]
fn a_bad_realm_or_naming_context_is_refused() {
    let dir = TempDir::new();
    let mut i = input(&dir, 61002, 61007);
    i.realm = "example.test".into();
    assert_eq!(input_kind(refused(&i)), InputErrorKind::RealmMismatch);
    i.realm = "OTHER.TEST".into();
    assert_eq!(input_kind(refused(&i)), InputErrorKind::RealmMismatch);
    i.realm = String::new();
    assert!(matches!(
        input_kind(refused(&i)),
        InputErrorKind::Realm | InputErrorKind::RealmMismatch
    ));
    let mut i = input(&dir, 61002, 61007);
    i.naming_context = vec!["exa.mple".into(), "test".into()];
    assert_eq!(input_kind(refused(&i)), InputErrorKind::NamingContext);
    i.naming_context = Vec::new();
    assert_eq!(input_kind(refused(&i)), InputErrorKind::NamingContext);
    let mut i = input(&dir, 61002, 61007);
    i.dc_fqdn = "DC1.example.test".into();
    assert_eq!(input_kind(refused(&i)), InputErrorKind::HostName);
}

/// docs/51 §11 (A-79, through directory-admin's checks); [MS-SAMR]
/// 3.1.1.6 items 8-14; Q-345 item 6 (no space in a first administrator's
/// name); docs/46 §8.3 item 3, §8.5 (one RDN per parent; one
/// sAMAccountName).
#[test]
fn names_breaking_their_rules_are_refused() {
    let dir = TempDir::new();
    let base = input(&dir, 61002, 61007);
    type Change = Box<dyn Fn(&mut provision::DomainInput)>;
    let cases: Vec<(Change, InputErrorKind)> = vec![
        (
            Box::new(|i| i.names.first_admins[0] = "al ice".into()),
            InputErrorKind::Name,
        ),
        (
            Box::new(|i| i.names.first_admins[0] = "alice$".into()),
            InputErrorKind::Name,
        ),
        (
            Box::new(|i| i.names.first_admins[0] = "a".repeat(21)),
            InputErrorKind::Name,
        ),
        (
            Box::new(|i| i.names.first_admins[0] = "KRBTGT".into()),
            InputErrorKind::ReservedName,
        ),
        (
            Box::new(|i| i.names.tier0_group = "krbtgt".into()),
            InputErrorKind::ReservedName,
        ),
        (
            Box::new(|i| i.names.first_admins[1] = "ALICE".into()),
            InputErrorKind::DuplicateAccountName,
        ),
        (
            Box::new(|i| i.names.tier0_group = "Bob".into()),
            InputErrorKind::DuplicateAccountName,
        ),
        (
            Box::new(|i| i.names.dc_name = "dc1$".into()),
            InputErrorKind::Name,
        ),
        (
            Box::new(|i| i.names.dc_name = "w".repeat(20)),
            InputErrorKind::Name,
        ),
        (
            Box::new(|i| i.names.tier0_ou = String::new()),
            InputErrorKind::Name,
        ),
        (
            Box::new(|i| i.names.workstations_ou = Some("tier0".into())),
            InputErrorKind::DuplicateRdn,
        ),
        (
            Box::new(|i| i.names.tier0_group = "a,b".into()),
            InputErrorKind::Name,
        ),
        // Task K9: the change-password service object's name — a computer
        // name (A-79), one sAMAccountName, one RDN under the Tier-0 OU.
        (
            Box::new(|i| i.names.change_password_service_name = "cpw$".into()),
            InputErrorKind::Name,
        ),
        (
            Box::new(|i| i.names.change_password_service_name = "c".repeat(20)),
            InputErrorKind::Name,
        ),
        (
            Box::new(|i| i.names.change_password_service_name = "ADMINSVC".into()),
            InputErrorKind::DuplicateAccountName,
        ),
        (
            Box::new(|i| i.names.change_password_service_name = "LdapSvc".into()),
            InputErrorKind::DuplicateAccountName,
        ),
    ];
    for (n, (change, kind)) in cases.into_iter().enumerate() {
        let mut i = base.clone();
        change(&mut i);
        assert_eq!(input_kind(refused(&i)), kind, "case {n}");
    }
}

/// docs/50 §3.1 (each socket in its own directory); docs/51 §4.3 step 9
/// (distinct targets).
#[test]
fn shared_paths_and_socket_directories_are_refused() {
    let dir = TempDir::new();
    let mut i = input(&dir, 61002, 61007);
    i.paths.manifest = i.paths.policy.clone();
    assert_eq!(input_kind(refused(&i)), InputErrorKind::DuplicatePath);
    let mut i = input(&dir, 61002, 61007);
    i.paths.admin_socket = path(&dir, "run/keyd/admin.sock");
    assert_eq!(
        input_kind(refused(&i)),
        InputErrorKind::SharedSocketDirectory
    );
    let mut i = input(&dir, 61002, 61007);
    i.paths.manifest = path(&dir, "etc/provision-staging/manifest");
    assert_eq!(input_kind(refused(&i)), InputErrorKind::DuplicatePath);
    // Task A16 (docs/51 §5.10; docs/questions/Q-591): `policy.next` lives
    // in a directory of dird's own — not root's policy directory (A-113),
    // not a socket's directory, not the same path as another.
    for shared in ["etc/policy.next", "run/dird-admin/policy.next"] {
        let mut i = input(&dir, 61002, 61007);
        i.paths.policy_next = path(&dir, shared);
        assert_eq!(
            input_kind(refused(&i)),
            InputErrorKind::SharedPolicyNextDirectory,
            "{shared}"
        );
    }
    let mut i = input(&dir, 61002, 61007);
    i.paths.policy_next = i.paths.policy.clone();
    assert_eq!(input_kind(refused(&i)), InputErrorKind::DuplicatePath);
    // Task K9: the two new sockets each in a directory of its own (docs/50
    // §3.1), the two new files distinct targets.
    let mut i = input(&dir, 61002, 61007);
    i.paths.dird_kpasswd_socket = path(&dir, "run/dird-admin/dird-kpasswd.sock");
    assert_eq!(
        input_kind(refused(&i)),
        InputErrorKind::SharedSocketDirectory
    );
    let mut i = input(&dir, 61002, 61007);
    i.paths.dird_dns_socket = path(&dir, "run/dird-kpasswd/dird-dns.sock");
    assert_eq!(
        input_kind(refused(&i)),
        InputErrorKind::SharedSocketDirectory
    );
    let mut i = input(&dir, 61002, 61007);
    i.paths.dnsd_config = i.paths.kpasswd_front_config.clone();
    assert_eq!(input_kind(refused(&i)), InputErrorKind::DuplicatePath);
}

/// A-15 / A-77: a CSPRNG failure at any draw stops the plan; a broken
/// source (NULL GUIDs) too.
#[test]
fn a_csprng_failure_stops_the_plan() {
    let dir = TempDir::new();
    let i = input(&dir, 61002, 61007);
    // 1 SID draw + 11 GUIDs + node id + key = 14 fills.
    for fail_at in 1..=14 {
        let mut rng = FailingRandom {
            fail_at,
            inner: CountingRandom::default(),
        };
        assert_eq!(
            Plan::build(&i, now(), &mut rng).unwrap_err(),
            PlanError::Random,
            "fill {fail_at}"
        );
    }
    assert_eq!(
        Plan::build(&i, now(), &mut ZeroRandom).unwrap_err(),
        PlanError::RandomUnusable
    );
}

/// A generated configuration refused by its schema stops the plan (the
/// kdc's listener must name one interface — crates/config).
#[test]
fn a_configuration_its_schema_refuses_stops_the_plan() {
    let dir = TempDir::new();
    let mut i = input(&dir, 61002, 61007);
    i.network.kdc_listen = vec!["0.0.0.0:88".into()];
    match refused(&i) {
        PlanError::Config(provision::Daemon::Kdc, _) => {}
        other => panic!("{other:?}"),
    }
}
