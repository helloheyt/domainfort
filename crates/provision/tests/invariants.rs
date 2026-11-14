//! The write invariants on the provisioning path (docs/52 R13, class C14):
//! `provision domain` writes the domain through directory-admin's
//! provisioning session — the same checker the online write PEP's `apply`
//! goes through — so a plan holding anything the online path would refuse
//! is refused before anything is installed. Each test builds a valid plan,
//! breaks one invariant in it, and runs the installer: the store write
//! fails with that invariant, the transaction is dropped, nothing is
//! renamed into place.
//!
//! Sources: docs/52 §3.14, §7 (R13); docs/51 §4.3 step 5, §5.2, §11
//! (A-79 / docs/questions/Q-298); [MS-SAMR] v20260427 3.1.1.6 items 8-14,
//! 20-24, 3.1.1.8.9, 3.1.1.9.2; docs/46 §8.2; docs/47 §4.2, §5.3 (the
//! nesting bound, 16); docs/questions/Q-355, Q-356, Q-376, Q-505..Q-507.
//! Fixtures: tests/common (obviously fake names; every value built here).

mod common;

use common::*;

use ad_schema::flags::group_type::{
    GROUP_TYPE_ACCOUNT_GROUP, GROUP_TYPE_APP_BASIC_GROUP, GROUP_TYPE_RESOURCE_GROUP,
    GROUP_TYPE_SECURITY_ENABLED,
};
use ad_schema::flags::user_account_control::{
    ADS_UF_ACCOUNT_DISABLE, ADS_UF_NORMAL_ACCOUNT, ADS_UF_SERVER_TRUST_ACCOUNT,
};
use directory_admin::InvariantViolation as V;
use dirstore::AttrId;
use dtyp::{Guid, Sid};
use provision::install::InstallCause;
use provision::{install, InstallError, InstallState, ObjectRole, Plan, StoreError};

/// The attribute id of `name` in the phase-1 schema.
fn attr(name: &str) -> AttrId {
    ad_schema::phase1()
        .unwrap()
        .attribute_by_name(name)
        .unwrap()
}

/// The planned object of `role`.
fn object(plan: &mut Plan, role: ObjectRole) -> &mut provision::PlannedObject {
    plan.objects.iter_mut().find(|o| o.role == role).unwrap()
}

/// Replace (or add) the values of `name` on `object`.
fn set(object: &mut provision::PlannedObject, name: &str, values: Vec<Vec<u8>>) {
    let id = attr(name);
    object.attributes.retain(|(a, _)| *a != id);
    object.attributes.push((id, values));
}

/// Remove `name` from `object`.
fn remove(object: &mut provision::PlannedObject, name: &str) {
    let id = attr(name);
    object.attributes.retain(|(a, _)| *a != id);
}

fn flags(v: u32) -> Vec<Vec<u8>> {
    vec![v.to_be_bytes().to_vec()]
}

fn int64(v: i64) -> Vec<Vec<u8>> {
    vec![v.to_be_bytes().to_vec()]
}

fn text(s: &str) -> Vec<Vec<u8>> {
    vec![s.as_bytes().to_vec()]
}

fn refs(guids: &[Guid]) -> Vec<Vec<u8>> {
    guids.iter().map(|g| g.to_packet().to_vec()).collect()
}

/// Build a valid plan, apply `mutate`, install it: the installer's error
/// (`None` when the test cannot run — as root). A valid plan installs.
fn install_mutated(mutate: impl FnOnce(&mut Plan)) -> Option<Result<(), InstallError>> {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return None;
    }
    let input = input(&dir, uid, 61007);
    let mut plan = Plan::build(&input, now(), &mut CountingRandom::default()).unwrap();
    mutate(&mut plan);
    Some(install(&plan, &mut Recorder::new(uid), &mut HaltAt::never()).map(|_| ()))
}

/// The plan, broken by `mutate`, is refused by the store write with
/// `expected`; nothing is installed (the staging directory only).
fn refused_with(expected: StoreError, mutate: impl FnOnce(&mut Plan)) {
    let Some(result) = install_mutated(mutate) else {
        return;
    };
    let error = result.unwrap_err();
    assert_eq!(error.cause, InstallCause::Store(expected));
    assert_eq!(error.state, InstallState::StagingOnly);
}

fn violates(rule: V, mutate: impl FnOnce(&mut Plan)) {
    refused_with(StoreError::Invariant(rule), mutate);
}

/// Positive control: the plan as built passes every invariant (docs/52
/// R13: "provision's output must be accepted by the checker").
#[test]
fn the_plan_as_built_passes_the_checker() {
    if let Some(result) = install_mutated(|_| {}) {
        result.unwrap();
    }
}

// --- Per-object rules ------------------------------------------------------

/// [MS-SAMR] 3.1.1.6 item 12 (A-79: ≤ 20 characters for a user).
#[test]
fn a_user_name_over_20_characters_is_refused() {
    violates(V::Name, |plan| {
        let admin = object(plan, ObjectRole::FirstAdmin(0));
        let long = "a".repeat(21);
        set(admin, "cn", text(&long));
        set(admin, "sAMAccountName", text(&long));
    });
}

/// docs/51 §5.2 row 1: a user's cn is its sAMAccountName.
#[test]
fn a_user_whose_cn_is_not_its_name_is_refused() {
    violates(V::Name, |plan| {
        set(object(plan, ObjectRole::FirstAdmin(0)), "cn", text("other"));
    });
}

/// [MS-SAMR] 3.1.1.6 items 8-10 (A-79): a group name with a forbidden
/// character.
#[test]
fn a_group_name_breaking_samr_is_refused() {
    violates(V::Name, |plan| {
        let group = object(plan, ObjectRole::BootstrapGroup);
        set(group, "cn", text("boot*strap"));
        set(group, "sAMAccountName", text("boot*strap"));
    });
}

/// [MS-SAMR] 3.1.1.6 item 14; RFC 4120 §7.3: "krbtgt" belongs to RID 502
/// only — refused on any other object, whatever its case (before the
/// unique index would see it).
#[test]
fn the_name_krbtgt_on_another_user_is_refused() {
    violates(V::ReservedName, |plan| {
        let admin = object(plan, ObjectRole::FirstAdmin(1));
        set(admin, "cn", text("KrbTgt"));
        set(admin, "sAMAccountName", text("KrbTgt"));
    });
}

/// [MS-SAMR] 3.1.1.6 items 19-20 (A-79, docs/46 §8.2: no
/// DONT_REQUIRE_PREAUTH): only N or N|D on a user.
#[test]
fn a_user_with_another_account_control_bit_is_refused() {
    violates(V::AccountControl, |plan| {
        let admin = object(plan, ObjectRole::FirstAdmin(0));
        set(
            admin,
            "userAccountControl",
            flags(ADS_UF_NORMAL_ACCOUNT | 0x0040_0000),
        );
    });
}

/// [MS-SAMR] 3.1.1.6 item 22: krbtgt is never disabled — even the
/// provisioning exception keeps it.
#[test]
fn a_disabled_krbtgt_is_refused() {
    violates(V::AccountControl, |plan| {
        let krbtgt = object(plan, ObjectRole::Krbtgt);
        set(
            krbtgt,
            "userAccountControl",
            flags(ADS_UF_NORMAL_ACCOUNT | ADS_UF_ACCOUNT_DISABLE),
        );
    });
}

/// A-79 / Q-298 item 2: ST only for the DC account — a service object
/// claiming it is refused.
#[test]
fn st_on_a_service_object_is_refused() {
    violates(V::AccountControl, |plan| {
        let ldap = object(plan, ObjectRole::LdapService);
        set(
            ldap,
            "userAccountControl",
            flags(ADS_UF_SERVER_TRUST_ACCOUNT),
        );
    });
}

/// docs/46 §8.2: groupType is one of the six phase-1 values
/// (APP_BASIC is "not used by Active Directory").
#[test]
fn a_group_type_outside_phase_1_is_refused() {
    violates(V::Value, |plan| {
        let group = object(plan, ObjectRole::BootstrapGroup);
        set(group, "groupType", flags(GROUP_TYPE_APP_BASIC_GROUP));
    });
}

/// docs/47 §4.2 (R47-5b): accountExpires 0 is refused.
#[test]
fn account_expires_zero_is_refused() {
    violates(V::Value, |plan| {
        set(
            object(plan, ObjectRole::FirstAdmin(0)),
            "accountExpires",
            int64(0),
        );
    });
}

/// docs/questions/Q-355 item 3 (RFC 4120 §6.2.1; docs/47 §1.3): the SPN's
/// host is the object's own dNSHostName.
#[test]
fn an_spn_naming_another_host_is_refused() {
    violates(V::Value, |plan| {
        set(
            object(plan, ObjectRole::LdapService),
            "servicePrincipalName",
            text("ldap/other.example.test"),
        );
    });
}

/// No attribute without a rule reaches the store: a Secret attribute is
/// refused by the checker before dirstore would see it (D44).
#[test]
fn an_attribute_without_a_rule_is_refused() {
    violates(V::NotModifiable, |plan| {
        set(
            object(plan, ObjectRole::FirstAdmin(0)),
            "unicodePwd",
            vec![vec![0x11; 16]],
        );
    });
}

/// docs/46 §4.4: a domainDNS only as the NC root (the provisioning
/// exception); an ordinary object of that class is refused.
#[test]
fn a_second_domain_dns_is_refused() {
    violates(V::Class, |plan| {
        let classes = object(plan, ObjectRole::NamingContextRoot).classes.clone();
        object(plan, ObjectRole::WorkstationsOu).classes = classes;
    });
}

// --- The named exceptions --------------------------------------------------

/// Each exception once: a first administrator claiming the DC account's
/// exception (already claimed, and a user besides) is refused.
#[test]
fn an_exception_claimed_twice_or_by_the_wrong_class_is_refused() {
    violates(V::Exception, |plan| {
        object(plan, ObjectRole::FirstAdmin(0)).role = ObjectRole::DcComputer;
    });
}

/// The krbtgt exception keeps the name "krbtgt" (item 14).
#[test]
fn the_krbtgt_exception_without_its_name_is_refused() {
    violates(V::ReservedName, |plan| {
        let krbtgt = object(plan, ObjectRole::Krbtgt);
        set(krbtgt, "cn", text("tgs"));
        set(krbtgt, "sAMAccountName", text("tgs"));
    });
}

/// [MS-SAMR] 3.1.1.9.2: a principal's objectSid is the domain SID ‖ the RID
/// the counter hands out — a planned objectSid with another RID is refused.
#[test]
fn a_planned_rid_the_counter_did_not_hand_out_is_refused() {
    refused_with(StoreError::RidMismatch, |plan| {
        let domain = plan.domain_sid;
        let mut sub = domain.sub_authority().to_vec();
        sub.push(0x0000_2000);
        let sid = Sid::new(domain.identifier_authority(), &sub).unwrap();
        set(
            object(plan, ObjectRole::FirstAdmin(0)),
            "objectSid",
            vec![sid.encode()],
        );
    });
}

// --- Store-wide rules: the links ------------------------------------------

/// docs/51 §5.2 row 9; docs/questions/Q-356 item 2: krbtgt, the DC account
/// and the service objects are never members.
#[test]
fn a_structural_object_as_a_member_is_refused() {
    for role in [
        ObjectRole::Krbtgt,
        ObjectRole::DcComputer,
        ObjectRole::AdminService,
    ] {
        violates(V::Protected, |plan| {
            let guid = object(plan, role).guid;
            let admin = object(plan, ObjectRole::FirstAdmin(0)).guid;
            set(
                object(plan, ObjectRole::Tier0Group),
                "member",
                refs(&[admin, guid]),
            );
        });
    }
}

/// [MS-SAMR] 3.1.1.8.9 item 2.2 (native mode): a security ACCOUNT group
/// holds accounts and security ACCOUNT groups only — not a RESOURCE group.
#[test]
fn a_member_the_group_type_does_not_admit_is_refused() {
    violates(V::Membership, |plan| {
        let tier0 = object(plan, ObjectRole::Tier0Group);
        set(
            tier0,
            "groupType",
            flags(GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_RESOURCE_GROUP),
        );
        let tier0 = tier0.guid;
        set(
            object(plan, ObjectRole::BootstrapGroup),
            "member",
            refs(&[tier0]),
        );
    });
}

/// docs/47 §5.3 item 4: a group cannot name itself (on the create-only
/// provisioning path the only cycle a write could name — the group does not
/// exist yet, so it is no member at all).
#[test]
fn a_group_naming_itself_is_refused() {
    violates(V::NoSuchObject, |plan| {
        let tier0 = object(plan, ObjectRole::Tier0Group);
        let own = tier0.guid;
        set(tier0, "member", refs(&[own]));
    });
}

/// docs/47 §5.3 item 3 (R47-8: MAX_NESTING_DEPTH = 16; A-89): a chain of
/// 16 nested security groups above an account is created; the 17th level
/// is refused — exactly the online path's bound (tests/nesting.rs of crate
/// directory-admin).
#[test]
fn a_seventeenth_nesting_level_is_refused() {
    for (levels, expected) in [(16usize, None), (17, Some(V::Membership))] {
        let Some(result) = install_mutated(|plan| {
            let template = object(plan, ObjectRole::Tier0Group).clone();
            let mut below = object(plan, ObjectRole::FirstAdmin(0)).guid;
            for level in 1..=levels {
                let mut group = template.clone();
                let mut packet = [0xC7u8; 16];
                packet[15] = u8::try_from(level).unwrap();
                group.guid = Guid::from_packet(&packet);
                let name = format!("nest{level}");
                set(&mut group, "cn", text(&name));
                set(&mut group, "sAMAccountName", text(&name));
                set(
                    &mut group,
                    "groupType",
                    flags(GROUP_TYPE_SECURITY_ENABLED | GROUP_TYPE_ACCOUNT_GROUP),
                );
                set(&mut group, "member", refs(&[below]));
                // The session forms the objectSid from the RID it takes.
                remove(&mut group, "objectSid");
                below = group.guid;
                plan.objects.push(group);
            }
        }) else {
            return;
        };
        match expected {
            // 16 levels: installed (each extra group is a copy of the
            // Tier-0 group's plan entry, so the staged store's counter
            // check counts it too).
            None => result.unwrap(),
            Some(rule) => {
                let error = result.unwrap_err();
                assert_eq!(
                    error.cause,
                    InstallCause::Store(StoreError::Invariant(rule))
                );
            }
        }
    }
}
