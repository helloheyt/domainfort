//! CreateSecurityDescriptor tests.
//!
//! Sources: [MS-DTYP] v20241119 2.5.3.4.1-2.5.3.4.4 and 2.5.3.4.7 (the
//! pseudocode; each case is worked by hand from the step its comment names),
//! the 2.5.3.4.4 flag table, 2.4.4.1, 2.4.4.3, 2.4.2.4, 2.5.2; the
//! self-relative descriptor of the worked example in [MS-DTYP] 2.5.1.4, used
//! as a parent; [MS-ADTS] v20261026 5.1.3.2 and 6.1.3 item 5.6 (the generic
//! mapping table). Where the pseudocode and other text disagree, the case
//! pins the built reading — decision A-84 (Q-335 option (b), Q-336 item 2) or
//! a Q-336 reading — and names it. SIDs are hand-made in the
//! layout of [MS-DTYP] 2.4.2.4; GUIDs are arbitrary labels. No vector comes
//! from any other implementation.

use dtyp::{
    ace_flags, create_security_descriptor, AccessMask, Ace, Acl, AutoInheritFlags, Control, Error,
    GenericMapping, Guid, MaskSidAce, ObjectAce, SecurityDescriptor, Sid, Token, UnsupportedAce,
    ACL_REVISION, ACL_REVISION_DS,
};

const CI: u8 = ace_flags::CONTAINER_INHERIT_ACE;
const OI: u8 = ace_flags::OBJECT_INHERIT_ACE;
const NP: u8 = ace_flags::NO_PROPAGATE_INHERIT_ACE;
const IO: u8 = ace_flags::INHERIT_ONLY_ACE;
const ID: u8 = ace_flags::INHERITED_ACE;
const SA: u8 = ace_flags::SUCCESSFUL_ACCESS_ACE_FLAG;
const FA: u8 = ace_flags::FAILED_ACCESS_ACE_FLAG;

const RP: u32 = AccessMask::ADS_RIGHT_DS_READ_PROP;
const WP: u32 = AccessMask::ADS_RIGHT_DS_WRITE_PROP;
const GR: u32 = AccessMask::GENERIC_READ;
const GW: u32 = AccessMask::GENERIC_WRITE;
const GX: u32 = AccessMask::GENERIC_EXECUTE;
const GA: u32 = AccessMask::GENERIC_ALL;

/// [MS-DTYP] 2.5.1.4: the self-relative encoding of
/// "O:BAG:BAD:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)S:P(AU;FA;GR;;;WD)".
const EXAMPLE: [u8; 0xb0] = [
    0x01, 0x00, 0x14, 0xb0, 0x90, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
    0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x80, 0x14, 0x00,
    0x00, 0x00, 0x00, 0x80, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x60, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0xa0,
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00, 0x00,
    0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00, 0x00, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x03, 0x14, 0x00,
    0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
    0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
];

// ------------------------------------------------------------- fixtures ----

fn sid(text: &str) -> Sid {
    Sid::parse_sid_string(text).unwrap()
}

/// Token.Sids[Token.OwnerIndex] of the creator (hand-made domain SID in the
/// S-1-5-21-<domain>-RID layout of [MS-DTYP] 2.4.2.4).
fn owner() -> Sid {
    sid("S-1-5-21-1-2-3-1000")
}
/// Token.Sids[Token.PrimaryGroup] of the creator.
fn primary_group() -> Sid {
    sid("S-1-5-21-1-2-3-513")
}
/// A trustee named by parent ACEs.
fn x() -> Sid {
    sid("S-1-5-21-1-2-3-1101")
}
/// Another trustee.
fn y() -> Sid {
    sid("S-1-5-21-1-2-3-1102")
}
/// CREATOR_OWNER. Spec: [MS-DTYP] 2.4.2.4.
fn creator_owner() -> Sid {
    sid("S-1-3-0")
}
/// CREATOR_GROUP. Spec: [MS-DTYP] 2.4.2.4.
fn creator_group() -> Sid {
    sid("S-1-3-1")
}
/// OWNER_SERVER, S-1-3-2 — a placeholder 2.5.3.4.7 does not substitute.
fn owner_server() -> Sid {
    sid("S-1-3-2")
}

fn guid(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0x0101,
        data3: 0x0202,
        data4: [3, 3, 3, 3, 3, 3, 3, (n & 0xFF) as u8],
    }
}
/// The class of the object being created.
fn class_a() -> Guid {
    guid(0xA)
}
/// Another class.
fn class_b() -> Guid {
    guid(0xB)
}
/// An attribute (an ObjectType GUID).
fn attr() -> Guid {
    guid(0xC)
}

fn allow(flags: u8, mask: u32, trustee: Sid) -> Ace {
    Ace::AccessAllowed(MaskSidAce {
        ace_flags: flags,
        mask: AccessMask(mask),
        sid: trustee,
    })
}
fn deny(flags: u8, mask: u32, trustee: Sid) -> Ace {
    Ace::AccessDenied(MaskSidAce {
        ace_flags: flags,
        mask: AccessMask(mask),
        sid: trustee,
    })
}
fn audit(flags: u8, mask: u32, trustee: Sid) -> Ace {
    Ace::SystemAudit(MaskSidAce {
        ace_flags: flags,
        mask: AccessMask(mask),
        sid: trustee,
    })
}
fn object(flags: u8, mask: u32, object_type: Option<Guid>, iot: Option<Guid>, s: Sid) -> ObjectAce {
    ObjectAce {
        ace_flags: flags,
        mask: AccessMask(mask),
        object_type,
        inherited_object_type: iot,
        sid: s,
    }
}
fn allow_obj(flags: u8, mask: u32, ot: Option<Guid>, iot: Option<Guid>, s: Sid) -> Ace {
    Ace::AccessAllowedObject(object(flags, mask, ot, iot, s))
}
fn deny_obj(flags: u8, mask: u32, ot: Option<Guid>, iot: Option<Guid>, s: Sid) -> Ace {
    Ace::AccessDeniedObject(object(flags, mask, ot, iot, s))
}
fn unsupported(ace_type: u8, flags: u8) -> Ace {
    Ace::Unsupported(UnsupportedAce {
        ace_type,
        ace_flags: flags,
        body: vec![0; 12],
    })
}

fn acl(aces: Vec<Ace>) -> Acl {
    Acl {
        acl_revision: ACL_REVISION_DS,
        aces,
    }
}

/// A parent descriptor (owner and group present; DP / SP per presence).
/// Spec: [MS-DTYP] 2.4.6.
fn parent(dacl: Option<Vec<Ace>>, sacl: Option<Vec<Ace>>) -> SecurityDescriptor {
    let mut control = Control::SELF_RELATIVE;
    if dacl.is_some() {
        control |= Control::DACL_PRESENT;
    }
    if sacl.is_some() {
        control |= Control::SACL_PRESENT;
    }
    SecurityDescriptor {
        sbz1: 0,
        control: Control(control),
        owner_sid: Some(sid("S-1-5-32-544")),
        group_sid: Some(sid("S-1-5-32-545")),
        sacl: sacl.map(acl),
        dacl: dacl.map(acl),
    }
}

fn token() -> Token {
    Token {
        owner: owner(),
        primary_group: primary_group(),
        default_dacl: None,
    }
}

/// Assert the canonical round trip with dtyp's own strict codec: encode,
/// decode back to the same value, re-encode to the same bytes.
fn assert_round_trip(sd: &SecurityDescriptor) {
    let bytes = sd.encode().expect("the computed descriptor must encode");
    let again = SecurityDescriptor::decode(&bytes).expect("and decode strictly");
    assert_eq!(&again, sd);
    assert_eq!(again.encode().unwrap(), bytes);
}

/// CreateSecurityDescriptor with CreatorDescriptor NULL, the default
/// AutoInheritFlags, `token()` and the [MS-ADTS] 6.1.3 mapping; every result
/// is round-tripped.
fn create_with(
    parent: Option<&SecurityDescriptor>,
    container: bool,
    types: Option<&[Guid]>,
    token: &Token,
) -> SecurityDescriptor {
    let sd = create_security_descriptor(
        parent,
        None,
        container,
        types,
        AutoInheritFlags::default(),
        token,
        &GenericMapping::ACTIVE_DIRECTORY,
    )
    .expect("CreateSecurityDescriptor succeeds");
    assert_round_trip(&sd);
    sd
}

fn create(
    parent: &SecurityDescriptor,
    container: bool,
    types: Option<&[Guid]>,
) -> SecurityDescriptor {
    create_with(Some(parent), container, types, &token())
}

fn dacl(sd: &SecurityDescriptor) -> &[Ace] {
    &sd.dacl.as_ref().expect("DACL present").aces
}

// ------------------------------------------------ the 2.5.1.4 example ----

/// Parent: the [MS-DTYP] 2.5.1.4 descriptor (four CI|OI allow ACEs: GR|GX to
/// BU, GA to BA, SY and CREATOR_OWNER; a SACL whose only ACE is FA, not
/// inheritable; PD and PS set). Child: a container.
///
/// Worked from: 2.5.3.4.1 Steps 1-2 (owner / group from the token); Step 3 →
/// 2.5.3.4.3 (TRUE: CI|OI) → 2.5.3.4.4 (ExplicitACL: all four with flags =
/// INHERITED_ACE; InheritableACL: all four with ID and IO added) → 2.5.3.4.7
/// as decided in A-84 (CopyInheritedAces keeps all eight; in the four
/// effective copies CO → owner, GR|GX → GENERIC_READ_MAPPING 0x20094 ∪
/// GENERIC_EXECUTE_MAPPING 0x20004 = 0x20094 and GA → GENERIC_ALL_MAPPING
/// 0xF01FF, the generic bits cleared (2.4.3, [MS-ADTS] 5.1.3.2); the four
/// inherit-only copies keep CREATOR_OWNER and their generic bits ([MS-ADTS]
/// 6.1.3 item 6; 2.5.3.4.4 closing paragraph)); Step 4 → 2.5.3.4.3 (FALSE: FA
/// only) → SACL "left as NULL"; ComputedControl NULL ⇒ Control = SR | DP.
#[test]
fn worked_example_parent_container_child() {
    let parent = SecurityDescriptor::decode(&EXAMPLE).unwrap();
    let child = create(&parent, true, None);
    let bu = sid("S-1-5-32-545");
    let ba = sid("S-1-5-32-544");
    let sy = sid("S-1-5-18");
    let inh = CI | OI | IO | ID;
    let expected = Acl {
        acl_revision: ACL_REVISION,
        aces: vec![
            allow(ID, 0x0002_0094, bu),
            allow(ID, 0x000F_01FF, ba),
            allow(ID, 0x000F_01FF, sy),
            allow(ID, 0x000F_01FF, owner()),
            allow(inh, GR | GX, bu),
            allow(inh, GA, ba),
            allow(inh, GA, sy),
            allow(inh, GA, creator_owner()),
        ],
    };
    assert_eq!(child.dacl, Some(expected));
    assert_eq!(child.sacl, None);
    assert_eq!(child.owner_sid, Some(owner()));
    assert_eq!(child.group_sid, Some(primary_group()));
    assert_eq!(
        child.control,
        Control(Control::SELF_RELATIVE | Control::DACL_PRESENT)
    );
}

/// The same parent, a non-container child: 2.5.3.4.4 ExplicitACL takes the
/// four ACEs through "OBJECT_INHERIT_ACE AND IsContainerObject = FALSE"; no
/// InheritableACL for a leaf. All four are effective: substituted and mapped
/// (A-84).
#[test]
fn worked_example_parent_leaf_child() {
    let parent = SecurityDescriptor::decode(&EXAMPLE).unwrap();
    let child = create(&parent, false, None);
    assert_eq!(
        dacl(&child),
        [
            allow(ID, 0x0002_0094, sid("S-1-5-32-545")),
            allow(ID, 0x000F_01FF, sid("S-1-5-32-544")),
            allow(ID, 0x000F_01FF, sid("S-1-5-18")),
            allow(ID, 0x000F_01FF, owner()),
        ]
    );
    assert_eq!(child.sacl, None);
}

// ------------------------------------------- 2.5.3.4.4: inheritance flags ----

/// Each row of the 2.5.3.4.4 flag table, run through the pseudocode, for a
/// container and a leaf child. `None` = no DACL at all (2.5.3.4.3 FALSE ⇒
/// Token.DefaultDACL, here NULL); `Some(flags)` = the DACL's ACEs' flags.
/// Two container rows differ from the table: "CI" gives CI and "CI,OI" gives
/// IO,CI,OI in the table, but the pseudocode always makes an effective copy
/// plus an inherit-only copy — the paragraph after the table names that split
/// for ACEs with generic rights only (Q-335). And A-84: adding IO to any row
/// changes nothing ("An ACE that has the IO flag can be inherited, but the
/// decision is based on other flags").
#[test]
fn flag_table_rows_as_the_pseudocode_computes_them() {
    /// The AceFlags of a computed DACL's ACEs; `None` = no DACL.
    type DaclFlags = Option<Vec<u8>>;
    // (parent flags, container child, leaf child)
    let rows: [(u8, DaclFlags, DaclFlags); 8] = [
        // "No Flags, IO": No Inheritance / No Inheritance.
        (0, None, None),
        (IO, None, None),
        // "OI": IO,OI / Inherited, No flags.
        (OI, Some(vec![OI | IO | ID]), Some(vec![ID])),
        // "OI,NP": No Inheritance / Inherited, No flags.
        (OI | NP, Some(vec![]), Some(vec![ID])),
        // "CI": table CI (pseudocode: effective + inherit-only, Q-335) /
        // No Inheritance.
        (CI, Some(vec![ID, CI | IO | ID]), Some(vec![])),
        // "CI,NP": Inherited, No flags / No Inheritance.
        (CI | NP, Some(vec![ID]), Some(vec![])),
        // "CI,OI": table IO,CI,OI (pseudocode: effective + inherit-only,
        // Q-335) / Inherited, No flags.
        (CI | OI, Some(vec![ID, CI | OI | IO | ID]), Some(vec![ID])),
        // "CI,OI,NP": Inherited, No flags / Inherited, No flags.
        (CI | OI | NP, Some(vec![ID]), Some(vec![ID])),
    ];
    for (flags, container, leaf) in rows {
        for parent_flags in [flags, flags | IO] {
            let p = parent(Some(vec![allow(parent_flags, RP, x())]), None);
            for (is_container, expected) in [(true, &container), (false, &leaf)] {
                let child = create(&p, is_container, None);
                let got = child
                    .dacl
                    .as_ref()
                    .map(|a| a.aces.iter().map(Ace::ace_flags).collect::<Vec<_>>());
                assert_eq!(
                    &got, expected,
                    "flags {parent_flags:#04x}, container {is_container}"
                );
                // Every computed ACE keeps the parent's mask and trustee.
                for ace in child.dacl.iter().flat_map(|a| a.aces.iter()) {
                    assert_eq!(ace.mask(), Some(AccessMask(RP)));
                }
            }
        }
    }
}

/// 2.5.3.4.4: "IF (... CONTAINER_INHERIT_ACE) AND (IsContainerObject =
/// TRUE)) OR (... OBJECT_INHERIT_ACE) AND (IsContainerObject = FALSE))" —
/// only inheritable ACEs reach the child; a non-inheritable parent ACE (no
/// CI / OI) is copied in neither list.
#[test]
fn only_inheritable_aces_are_copied() {
    let p = parent(
        Some(vec![
            allow(0, WP, y()),
            allow(CI, RP, x()),
            deny(IO, WP, y()),
        ]),
        None,
    );
    assert_eq!(
        dacl(&create(&p, true, None)),
        [allow(ID, RP, x()), allow(CI | IO | ID, RP, x())]
    );
}

/// A leaf child of a parent whose only inheritable ACE is CI: 2.5.3.4.3 is
/// TRUE, so the DACL comes from 2.5.3.4.4 — which yields nothing for a leaf —
/// and NOT from Token.DefaultDACL: the child gets an empty DACL (DP set).
#[test]
fn leaf_child_of_container_inherit_only_parent_gets_an_empty_dacl() {
    let p = parent(Some(vec![allow(CI, RP, x())]), None);
    let t = Token {
        default_dacl: Some(acl(vec![allow(0, WP, y())])),
        ..token()
    };
    let child = create_with(Some(&p), false, None, &t);
    assert_eq!(child.dacl, Some(acl(vec![])));
    assert!(child.control.contains(Control::DACL_PRESENT));
}

/// A-84 (Q-335 (b)): a parent ACE with INHERIT_ONLY_ACE is inherited by its
/// other flags — "An ACE that has the IO flag can be inherited, but the
/// decision is based on other flags" (2.5.3.4.4, paragraph after the
/// pseudocode); 2.4.4.1 ("Both effective and inherit-only ACEs can be
/// inherited"). CI|IO gives a container an effective copy and an inherit-only
/// copy; OI|IO gives a leaf an effective copy and a container an inherit-only
/// copy.
#[test]
fn inherit_only_parent_ace_is_inherited_by_its_other_flags_a84() {
    let p = parent(
        Some(vec![allow(CI | IO, RP, x()), allow(OI | IO, WP, y())]),
        None,
    );
    assert_eq!(
        dacl(&create(&p, true, None)),
        [
            allow(ID, RP, x()),
            allow(CI | IO | ID, RP, x()),
            allow(OI | IO | ID, WP, y()),
        ]
    );
    assert_eq!(dacl(&create(&p, false, None)), [allow(ID, WP, y())]);
}

/// A-84 over generations: root → OU → user (all containers, [MS-ADTS] 6.1.3
/// item 5.3). The OU's inherit-only copy (CI|IO|ID) is inherited again by its
/// CI flag, so the ACE is effective on the OU and on the user, and each level
/// passes an inherit-only copy on.
#[test]
fn inheritable_ace_is_effective_at_every_depth_a84() {
    let root = parent(Some(vec![allow(CI, RP, x())]), None);
    let ou = create(&root, true, Some(&[class_b()]));
    let user = create(&ou, true, Some(&[class_a()]));
    let expected = [allow(ID, RP, x()), allow(CI | IO | ID, RP, x())];
    assert_eq!(dacl(&ou), expected);
    assert_eq!(dacl(&user), expected);
    // One more level: unchanged (a fixed point of the procedure).
    assert_eq!(dacl(&create(&user, true, Some(&[class_a()]))), expected);
}

/// A-84 + [MS-ADTS] 6.1.3 item 6: the OU's inherit-only copy keeps
/// CREATOR_OWNER, so a user created under the OU by another requester grants
/// that requester — the OU's owner (the intermediate owner) gets nothing on
/// the user.
#[test]
fn creator_owner_resolves_to_each_generation_own_creator_a84() {
    let root = parent(Some(vec![allow(CI, RP | WP, creator_owner())]), None);
    let ou_creator = owner();
    let user_creator = y();
    let ou = create_with(Some(&root), true, None, &token());
    assert_eq!(
        dacl(&ou),
        [
            allow(ID, RP | WP, ou_creator),
            allow(CI | IO | ID, RP | WP, creator_owner()),
        ]
    );
    let user_token = Token {
        owner: user_creator,
        ..token()
    };
    let user = create_with(Some(&ou), true, None, &user_token);
    assert_eq!(user.owner_sid, Some(user_creator));
    assert_eq!(
        dacl(&user),
        [
            allow(ID, RP | WP, user_creator),
            allow(CI | IO | ID, RP | WP, creator_owner()),
        ]
    );
    assert!(dacl(&user).iter().all(|ace| match ace {
        Ace::AccessAllowed(a) => a.sid != ou_creator,
        _ => false,
    }));
}

/// NO_PROPAGATE_INHERIT_ACE stops at depth 1 (root → OU → user): the OU gets
/// the effective copy and no inherit-only copy, so the user has no
/// inheritable source and no DACL (2.5.3.4.3 FALSE, Token.DefaultDACL NULL).
#[test]
fn no_propagate_inherit_stops_at_depth_one() {
    let root = parent(Some(vec![allow(CI | NP, RP, x())]), None);
    let ou = create(&root, true, Some(&[class_b()]));
    assert_eq!(dacl(&ou), [allow(ID, RP, x())]);
    assert_eq!(create(&ou, true, Some(&[class_a()])).dacl, None);
}

/// An InheritedObjectType mismatch at depth 2: the root's ACE is scoped to
/// `class_a`. The OU (`class_b`) gets only the inherit-only copy; under the OU
/// a `class_a` object gets the effective copy (A-84: the IO copy is inherited
/// by its CI flag, then the InheritedObjectType decides), a `class_b` object
/// again only the inherit-only copy ([MS-ADTS] 6.1.3 item 4).
#[test]
fn inherited_object_type_mismatch_at_depth_two() {
    let ace = |flags| allow_obj(flags, WP, Some(attr()), Some(class_a()), x());
    let root = parent(Some(vec![ace(CI)]), None);
    let ou = create(&root, true, Some(&[class_b()]));
    assert_eq!(dacl(&ou), [ace(CI | IO | ID)]);
    assert_eq!(
        dacl(&create(&ou, true, Some(&[class_a()]))),
        [ace(ID), ace(CI | IO | ID)]
    );
    assert_eq!(
        dacl(&create(&ou, true, Some(&[class_b()]))),
        [ace(CI | IO | ID)]
    );
}

/// 2.5.3.4.4 second loop: "IF ACE.AceFlags does not contain
/// NO_PROPAGATE_INHERIT_ACE" — NP stops the inherit-only copy; the effective
/// copy carries INHERITED_ACE only, so NP itself is cleared (2.4.4.1: NP
/// "clears the OBJECT_INHERIT_ACE and CONTAINER_INHERIT_ACE flags in the
/// inherited ACE").
#[test]
fn no_propagate_inherit_stops_further_inheritance() {
    let p = parent(
        Some(vec![allow(CI | NP, RP, x()), allow(OI | NP, WP, y())]),
        None,
    );
    let child = create(&p, true, None);
    assert_eq!(dacl(&child), [allow(ID, RP, x())]);
    // The child's ACE is no longer inheritable: its own children get nothing
    // from it (2.5.3.4.3 FALSE ⇒ Token.DefaultDACL, NULL here).
    assert_eq!(create(&child, true, None).dacl, None);
    assert_eq!(dacl(&create(&p, false, None)), [allow(ID, WP, y())]);
}

/// 2.5.3.4.4: the effective copy — "Clear NewACE.AceFlags – no flags set;
/// NewACE.AceFlags = INHERITED_ACE"; the inherit-only copy — "Set NewACE to
/// ACE; Add INHERITED_ACE ...; Add INHERIT_ONLY_ACE" (every other flag kept).
/// A parent ACE that is itself inherited (ID set) is inherited again.
#[test]
fn inherited_ace_flag_is_set_and_other_flags_follow_the_two_copies() {
    let p = parent(Some(vec![allow(CI | OI | ID, RP, x())]), None);
    assert_eq!(
        dacl(&create(&p, true, None)),
        [allow(ID, RP, x()), allow(CI | OI | ID | IO, RP, x())]
    );
}

/// Output order: 2.5.3.4.4 "RETURN concatenation of ExplicitACL and
/// InheritableACL", each built in parent order.
#[test]
fn output_is_effective_copies_then_inherit_only_copies_in_parent_order() {
    let a = sid("S-1-5-21-1-2-3-2001");
    let b = sid("S-1-5-21-1-2-3-2002");
    let c = sid("S-1-5-21-1-2-3-2003");
    let d = sid("S-1-5-21-1-2-3-2004");
    let p = parent(
        Some(vec![
            allow(CI, RP, a),
            deny(OI, WP, b),
            allow(CI | OI, RP, c),
            deny(CI | NP, WP, d),
        ]),
        None,
    );
    assert_eq!(
        dacl(&create(&p, true, None)),
        [
            // ExplicitACL: CI on a container (b's OI-only ACE is not).
            allow(ID, RP, a),
            allow(ID, RP, c),
            deny(ID, WP, d),
            // InheritableACL: CI or OI, without NP.
            allow(CI | ID | IO, RP, a),
            deny(OI | ID | IO, WP, b),
            allow(CI | OI | ID | IO, RP, c),
        ]
    );
}

// --------------------------------------- 2.5.3.4.4: object-specific ACEs ----

/// 2.5.3.4.4 "IF (ObjectTypes contains ACE.ObjectGUID)", read as the
/// InheritedObjectType ("identifies the type of child object that can inherit
/// the ACE", 2.4.4.3; Q-336): a match gives the effective copy; no match, or
/// ObjectTypes NULL (an object without a GUID), gives only the inherit-only
/// copy (the second loop has no type test).
#[test]
fn inherited_object_type_selects_the_child_class() {
    let ace = |flags| allow_obj(flags, WP, Some(attr()), Some(class_a()), x());
    let p = parent(Some(vec![ace(CI)]), None);
    let both = [ace(ID), ace(CI | IO | ID)];
    let inherit_only = [ace(CI | IO | ID)];
    assert_eq!(dacl(&create(&p, true, Some(&[class_a()]))), both);
    // [MS-ADTS] 6.1.3 item 4: the dynamic auxiliary classes are in
    // ObjectTypes too — any element may match.
    assert_eq!(dacl(&create(&p, true, Some(&[class_b(), class_a()]))), both);
    assert_eq!(dacl(&create(&p, true, Some(&[class_b()]))), inherit_only);
    assert_eq!(dacl(&create(&p, true, None)), inherit_only);
    assert_eq!(dacl(&create(&p, true, Some(&[]))), inherit_only);
}

/// The same rule for ACCESS_DENIED_OBJECT_ACE_TYPE (same CASE arm), on a leaf
/// with OBJECT_INHERIT_ACE.
#[test]
fn inherited_object_type_on_a_deny_object_ace() {
    let ace = |flags| deny_obj(flags, RP, None, Some(class_b()), y());
    let p = parent(Some(vec![ace(OI)]), None);
    assert_eq!(dacl(&create(&p, false, Some(&[class_b()]))), [ace(ID)]);
    assert_eq!(dacl(&create(&p, false, Some(&[class_a()]))), []);
}

/// An object ACE without InheritedObjectType: "If this value is not
/// specified, all types of child objects can inherit the ACE" (2.4.4.3,
/// ACE_INHERITED_OBJECT_TYPE_PRESENT; Q-336). ObjectType does not take part
/// in inheritance.
#[test]
fn object_ace_without_inherited_object_type_is_inherited_by_every_class() {
    let ace = |flags| allow_obj(flags, WP, Some(class_a()), None, x());
    let p = parent(Some(vec![ace(CI)]), None);
    let both = [ace(ID), ace(CI | IO | ID)];
    assert_eq!(dacl(&create(&p, true, Some(&[class_b()]))), both);
    assert_eq!(dacl(&create(&p, true, None)), both);
}

// ------------------------------------------------------ 2.5.3.4.7 PostProcessACL ----

/// A-84 (Q-336 item 2): on an effective copy each generic right in the mask
/// adds its mapping — GR / GW / GX as 2.5.3.4.7 says, GA too as 2.4.3 says —
/// and the generic bits are cleared (2.4.3: "During this translation, the GR
/// bit is cleared"; [MS-ADTS] 5.1.3.2: the "GENERIC" bits "are never stored").
/// With the [MS-ADTS] 6.1.3 item 5.6 table: GR → 0x20094, GW → 0x20028,
/// GX → 0x20004, GA → 0xF01FF; other bits are kept. The inherit-only copy
/// keeps the generic bits unmapped (2.5.3.4.4 closing paragraph: "an ACE with
/// an additional IO flag with generic information and an effective-only ACE in
/// which the generic information has been mapped").
#[test]
fn generic_rights_are_mapped_and_cleared_on_effective_copies() {
    let de = AccessMask::DELETE;
    for (generic, mapped) in [
        (GR, 0x0002_0094),
        (GW, 0x0002_0028),
        (GX, 0x0002_0004),
        (GA, 0x000F_01FF),
        (GR | GW | GX | GA, 0x000F_01FF),
        (GR | de, 0x0002_0094 | de),
    ] {
        let p = parent(Some(vec![allow(CI, generic, x())]), None);
        assert_eq!(
            dacl(&create(&p, true, None)),
            [allow(ID, mapped, x()), allow(CI | IO | ID, generic, x())],
            "mask {generic:#010x}"
        );
    }
    // A mask without generic bits is unchanged.
    let q = parent(Some(vec![allow(CI, RP | WP, x())]), None);
    assert_eq!(dacl(&create(&q, false, None)), []);
    assert_eq!(dacl(&create(&q, true, None))[0], allow(ID, RP | WP, x()));
}

/// The child's inherit-only copy still carries the generic bits, so the
/// grandchild's effective copy is mapped in its turn (A-84).
#[test]
fn generic_rights_are_mapped_again_at_the_next_generation() {
    let root = parent(Some(vec![allow(CI, GR, x())]), None);
    let child = create(&root, true, None);
    assert_eq!(
        dacl(&create(&child, true, None)),
        [allow(ID, 0x0002_0094, x()), allow(CI | IO | ID, GR, x())]
    );
}

/// 2.5.3.4.7 tests ACE.Mask — the original — so a mapping that adds a generic
/// bit does not trigger that bit's own mapping; the added generic bit is then
/// cleared with the others (A-84).
#[test]
fn generic_mapping_tests_the_original_mask() {
    let mapping = GenericMapping {
        generic_read: GW | 0x1,
        generic_write: 0x2,
        generic_execute: 0x4,
        generic_all: 0x8,
    };
    let p = parent(Some(vec![allow(CI, GR, x())]), None);
    let child = create_security_descriptor(
        Some(&p),
        None,
        true,
        None,
        AutoInheritFlags::default(),
        &token(),
        &mapping,
    )
    .unwrap();
    assert_round_trip(&child);
    // GR → GW | 0x1; GW is not mapped (not in ACE.Mask) and is cleared.
    assert_eq!(dacl(&child)[0], allow(ID, 0x1, x()));
}

/// The [MS-ADTS] 6.1.3 item 5.6 table, with the values [MS-ADTS] 5.1.3.2
/// prints for each right: GR = RC|LC|RP|LO = 0x20000|0x4|0x10|0x80;
/// GW = RC|VW|WP = 0x20000|0x8|0x20; GX = RC|LC; GA = DE|RC|WD|WO|CC|DC|DT|
/// RP|WP|LC|LO|CR|VW = 0x10000|0x20000|0x40000|0x80000|0x1|0x2|0x40|0x10|
/// 0x20|0x4|0x80|0x100|0x8.
#[test]
fn active_directory_generic_mapping_table() {
    assert_eq!(
        GenericMapping::ACTIVE_DIRECTORY,
        GenericMapping {
            generic_read: 0x0002_0094,
            generic_write: 0x0002_0028,
            generic_execute: 0x0002_0004,
            generic_all: 0x000F_01FF,
        }
    );
}

/// 2.5.3.4.7: "CASE ACE.Sid OF CREATOR_OWNER: NewACE.Sid = Owner;
/// CREATOR_GROUP: NewACE.Sid = Group" (Owner / Group = NewDescriptor's, from
/// the token here) — in the effective copies only; the inherit-only copies
/// keep the placeholder (A-84; [MS-ADTS] 6.1.3 item 6: "Any CREATOR/OWNER
/// ineffective ACE has a matching effective ACE granted to the current
/// owner"). Other SIDs, OWNER_SERVER included, are not substituted.
#[test]
fn creator_owner_and_creator_group_are_substituted_in_effective_copies() {
    let p = parent(
        Some(vec![
            allow(CI, RP, creator_owner()),
            allow(CI, WP, creator_group()),
            allow(CI, RP, owner_server()),
        ]),
        None,
    );
    let inh = CI | IO | ID;
    assert_eq!(
        dacl(&create(&p, true, None)),
        [
            allow(ID, RP, owner()),
            allow(ID, WP, primary_group()),
            allow(ID, RP, owner_server()),
            allow(inh, RP, creator_owner()),
            allow(inh, WP, creator_group()),
            allow(inh, RP, owner_server()),
        ]
    );
}

/// A-21: nothing grants the owner anything implicitly — without a
/// CREATOR_OWNER ACE in the parent, no computed ACE names the owner.
#[test]
fn no_ace_is_added_for_the_owner() {
    let p = parent(Some(vec![allow(CI | OI, RP | WP, x())]), None);
    for container in [true, false] {
        let child = create(&p, container, None);
        assert_eq!(child.owner_sid, Some(owner()));
        assert!(dacl(&child).iter().all(|ace| match ace {
            Ace::AccessAllowed(a) | Ace::AccessDenied(a) => a.sid != owner(),
            _ => false,
        }));
    }
}

// ------------------------------- 2.5.3.4.2: no inheritable ACEs / no parent ----

/// 2.5.3.4.2 ELSE branch, "IF CreatorACL = NULL ... Set TmpACL to
/// Token.DefaultDACL", then PostProcessACL with CopyAllAces (flags kept;
/// effective ACEs substituted and mapped, an inherit-only one kept as is —
/// A-84). The parent's DACL is absent (DP clear).
#[test]
fn absent_parent_dacl_takes_the_token_default_dacl() {
    let p = parent(None, None);
    let t = Token {
        default_dacl: Some(Acl {
            acl_revision: ACL_REVISION,
            aces: vec![
                allow(0, GR, creator_owner()),
                allow(CI, RP, x()),
                allow(CI | IO, GR, creator_owner()),
            ],
        }),
        ..token()
    };
    let child = create_with(Some(&p), true, None, &t);
    assert_eq!(
        child.dacl,
        Some(Acl {
            acl_revision: ACL_REVISION,
            aces: vec![
                allow(0, 0x0002_0094, owner()),
                allow(CI, RP, x()),
                allow(CI | IO, GR, creator_owner()),
            ],
        })
    );
}

/// The same branch with Token.DefaultDACL NULL: the DACL stays NULL (DP
/// clear) — the access check then denies (A-13), and [MS-ADTS] 6.1.3 item 7
/// is the caller's check (Q-336).
#[test]
fn no_inheritable_ace_and_no_default_dacl_gives_no_dacl() {
    for p in [
        parent(None, None),
        parent(Some(vec![]), None),
        parent(Some(vec![allow(0, RP, x()), allow(IO, WP, y())]), None),
    ] {
        let child = create(&p, true, Some(&[class_a()]));
        assert_eq!(child.dacl, None);
        assert_eq!(child.sacl, None);
        assert_eq!(child.control, Control(Control::SELF_RELATIVE));
    }
}

/// An empty parent DACL has no inheritable ACE (2.5.3.4.3 FALSE) ⇒
/// Token.DefaultDACL.
#[test]
fn empty_parent_dacl_takes_the_token_default_dacl() {
    let p = parent(Some(vec![]), None);
    let t = Token {
        default_dacl: Some(acl(vec![allow(0, RP, y())])),
        ..token()
    };
    assert_eq!(
        dacl(&create_with(Some(&p), false, None, &t)),
        [allow(0, RP, y())]
    );
}

/// ParentDescriptor NULL ("If the object has no parent, this parameter is
/// null"): ParentACL is NULL for both lists ⇒ DACL from Token.DefaultDACL,
/// SACL "left as NULL".
#[test]
fn no_parent_descriptor() {
    let t = Token {
        default_dacl: Some(acl(vec![allow(0, RP, x())])),
        ..token()
    };
    let sd = create_with(None, true, None, &t);
    assert_eq!(dacl(&sd), [allow(0, RP, x())]);
    assert_eq!(sd.sacl, None);
    assert_eq!(sd.owner_sid, Some(owner()));
    assert_eq!(sd.group_sid, Some(primary_group()));
    assert_eq!(create_with(None, false, None, &token()).dacl, None);
}

// ---------------------------------------------------------- control bits ----

/// The parent's PD / PS / DI / SI bits do not stop inheritance — ParentControl
/// is passed to 2.5.3.4.2 but never read — and none reaches the child:
/// ComputedControl stays NULL without a CreatorACL, so the child's Control is
/// SR plus DP / SP (2.4.6).
#[test]
fn parent_protected_and_auto_inherited_bits_do_not_reach_the_child() {
    let mut p = parent(
        Some(vec![allow(CI, RP, x())]),
        Some(vec![audit(CI | SA, WP, y())]),
    );
    p.control = Control(
        p.control.0
            | Control::DACL_PROTECTED
            | Control::SACL_PROTECTED
            | Control::DACL_AUTO_INHERITED
            | Control::SACL_AUTO_INHERITED,
    );
    let child = create(&p, true, None);
    assert_eq!(
        dacl(&child),
        [allow(ID, RP, x()), allow(CI | IO | ID, RP, x())]
    );
    assert_eq!(
        child.control,
        Control(Control::SELF_RELATIVE | Control::DACL_PRESENT | Control::SACL_PRESENT)
    );
}

/// DACL_AUTO_INHERIT, SACL_AUTO_INHERIT and DEFAULT_DESCRIPTOR_FOR_OBJECT are
/// read by 2.5.3.4.2 only when a CreatorACL is present: with
/// CreatorDescriptor NULL they change nothing (in particular DI / SI are not
/// set).
#[test]
fn auto_inherit_flags_have_no_effect_without_a_creator_descriptor() {
    let p = parent(
        Some(vec![allow(CI, RP, x())]),
        Some(vec![audit(CI | FA, WP, y())]),
    );
    let flags = AutoInheritFlags {
        dacl_auto_inherit: true,
        sacl_auto_inherit: true,
        default_descriptor_for_object: true,
        default_owner_from_parent: false,
        default_group_from_parent: false,
    };
    let with_flags = create_security_descriptor(
        Some(&p),
        None,
        true,
        None,
        flags,
        &token(),
        &GenericMapping::ACTIVE_DIRECTORY,
    )
    .unwrap();
    assert_eq!(with_flags, create(&p, true, None));
    assert!(!with_flags.control.contains(Control::DACL_AUTO_INHERITED));
    assert!(!with_flags.control.contains(Control::SACL_AUTO_INHERITED));
}

// ------------------------------------------------------- owner and group ----

/// 2.5.3.4.1 Steps 1-2: CreatorDescriptor.Owner / .Group are NULL, so
/// DEFAULT_OWNER_FROM_PARENT / DEFAULT_GROUP_FROM_PARENT choose the parent's
/// Owner / Group, and otherwise Token.Sids[Token.OwnerIndex] /
/// Token.Sids[Token.PrimaryGroup] (note <96>).
#[test]
fn owner_and_group_from_the_token_or_the_parent() {
    let p = parent(Some(vec![allow(CI, RP, x())]), None);
    let from_token = create(&p, true, None);
    assert_eq!(from_token.owner_sid, Some(owner()));
    assert_eq!(from_token.group_sid, Some(primary_group()));

    let run = |flags: AutoInheritFlags| {
        create_security_descriptor(
            Some(&p),
            None,
            true,
            None,
            flags,
            &token(),
            &GenericMapping::ACTIVE_DIRECTORY,
        )
    };
    let owner_only = run(AutoInheritFlags {
        default_owner_from_parent: true,
        ..AutoInheritFlags::default()
    })
    .unwrap();
    assert_eq!(owner_only.owner_sid, p.owner_sid);
    assert_eq!(owner_only.group_sid, Some(primary_group()));
    let group_only = run(AutoInheritFlags {
        default_group_from_parent: true,
        ..AutoInheritFlags::default()
    })
    .unwrap();
    assert_eq!(group_only.owner_sid, Some(owner()));
    assert_eq!(group_only.group_sid, p.group_sid);
    // CREATOR_OWNER resolves to NewDescriptor.Owner (2.5.3.4.1 Step 3 passes
    // "Owner set to NewDescriptor.Owner").
    let q = parent(Some(vec![allow(CI, RP, creator_owner())]), None);
    let child = create_security_descriptor(
        Some(&q),
        None,
        false,
        None,
        AutoInheritFlags {
            default_owner_from_parent: true,
            ..AutoInheritFlags::default()
        },
        &token(),
        &GenericMapping::ACTIVE_DIRECTORY,
    )
    .unwrap();
    assert_eq!(dacl(&child), []);
    let child = create_security_descriptor(
        Some(&q),
        None,
        true,
        None,
        AutoInheritFlags {
            default_owner_from_parent: true,
            ..AutoInheritFlags::default()
        },
        &token(),
        &GenericMapping::ACTIVE_DIRECTORY,
    )
    .unwrap();
    assert_eq!(dacl(&child)[0], allow(ID, RP, sid("S-1-5-32-544")));
}

/// Fail closed: "Set NewDescriptor.Owner to ParentDescriptor.Owner" with no
/// parent, or a parent without an owner, would leave the owner NULL
/// ([MS-ADTS] 6.1.3 item 1: "The owner SID cannot be NULL"); likewise the
/// group.
#[test]
fn owner_or_group_from_an_absent_parent_value_is_refused() {
    let owner_flag = AutoInheritFlags {
        default_owner_from_parent: true,
        ..AutoInheritFlags::default()
    };
    let group_flag = AutoInheritFlags {
        default_group_from_parent: true,
        ..AutoInheritFlags::default()
    };
    let mut ownerless = parent(Some(vec![]), None);
    ownerless.owner_sid = None;
    ownerless.group_sid = None;
    ownerless.control =
        Control(ownerless.control.0 | Control::OWNER_DEFAULTED | Control::GROUP_DEFAULTED);
    let run = |p: Option<&SecurityDescriptor>, flags| {
        create_security_descriptor(
            p,
            None,
            true,
            None,
            flags,
            &token(),
            &GenericMapping::ACTIVE_DIRECTORY,
        )
    };
    assert_eq!(run(None, owner_flag), Err(Error::NewDescriptorOwnerAbsent));
    assert_eq!(
        run(Some(&ownerless), owner_flag),
        Err(Error::NewDescriptorOwnerAbsent)
    );
    assert_eq!(run(None, group_flag), Err(Error::NewDescriptorGroupAbsent));
    assert_eq!(
        run(Some(&ownerless), group_flag),
        Err(Error::NewDescriptorGroupAbsent)
    );
}

/// A-76: CreatorDescriptor must be NULL; a supplied one is refused (the
/// creator branches of 2.5.3.4.2 are not built — Q-336).
#[test]
fn a_creator_descriptor_is_refused() {
    let p = parent(Some(vec![allow(CI, RP, x())]), None);
    let creator = parent(Some(vec![allow(0, WP, y())]), None);
    assert_eq!(
        create_security_descriptor(
            Some(&p),
            Some(&creator),
            true,
            None,
            AutoInheritFlags::default(),
            &token(),
            &GenericMapping::ACTIVE_DIRECTORY,
        ),
        Err(Error::CreatorDescriptorNotSupported)
    );
}

// ------------------------------------------------------------------ SACL ----

/// 2.5.3.4.1 Step 4 runs the same procedures on the SACL. The CASE of
/// 2.5.3.4.4 has no arm for the audit types, so they get no effective copy
/// (literal; Q-336); a container still gets the inherit-only copy, which
/// keeps SUCCESSFUL_ACCESS_ACE_FLAG / FAILED_ACCESS_ACE_FLAG. A leaf gets an
/// empty SACL (2.5.3.4.3 TRUE).
#[test]
fn sacl_inheritance() {
    let sacl_ace = |flags| audit(flags, WP, y());
    let obj_audit = |flags| Ace::SystemAuditObject {
        ace: object(flags, RP, Some(attr()), None, x()),
        application_data: vec![],
    };
    let p = parent(
        Some(vec![allow(CI, RP, x())]),
        Some(vec![
            sacl_ace(CI | SA),
            obj_audit(CI | OI | FA),
            sacl_ace(FA),
        ]),
    );
    let container = create(&p, true, None);
    assert_eq!(
        container.sacl,
        Some(acl(vec![
            sacl_ace(CI | SA | ID | IO),
            obj_audit(CI | OI | FA | ID | IO),
        ]))
    );
    assert!(container.control.contains(Control::SACL_PRESENT));
    let leaf = create(&p, false, None);
    assert_eq!(leaf.sacl, Some(acl(vec![])));
    assert!(leaf.control.contains(Control::SACL_PRESENT));
    // A SACL with no inheritable ACE: "No default for SACL; left as NULL".
    let q = parent(
        Some(vec![allow(CI, RP, x())]),
        Some(vec![sacl_ace(SA | FA)]),
    );
    let child = create(&q, true, None);
    assert_eq!(child.sacl, None);
    assert!(!child.control.contains(Control::SACL_PRESENT));
}

// ------------------------------------------------------ fail closed, bounds ----

/// DELIBERATE (fail closed): an inheritable ACE kept as `Ace::Unsupported`
/// cannot go through 2.5.3.4.7 (its Sid and Mask are not interpreted) and is
/// refused, in the DACL (SYSTEM_ALARM_ACE_TYPE 0x03, reserved, valid in a
/// DACL by 2.4.5) and in the SACL (SYSTEM_MANDATORY_LABEL_ACE_TYPE 0x11).
/// A non-inheritable one takes no part and is ignored.
#[test]
fn an_inheritable_uninterpreted_ace_is_refused() {
    let run = |p: &SecurityDescriptor, t: &Token| {
        create_security_descriptor(
            Some(p),
            None,
            true,
            None,
            AutoInheritFlags::default(),
            t,
            &GenericMapping::ACTIVE_DIRECTORY,
        )
    };
    let in_dacl = parent(Some(vec![allow(CI, RP, x()), unsupported(0x03, CI)]), None);
    assert_eq!(
        run(&in_dacl, &token()),
        Err(Error::UnsupportedAceInComputedAcl)
    );
    let in_sacl = parent(Some(vec![]), Some(vec![unsupported(0x11, OI)]));
    assert_eq!(
        run(&in_sacl, &token()),
        Err(Error::UnsupportedAceInComputedAcl)
    );
    // Inherit-only and inheritable is still inheritable (2.5.3.4.3).
    let io = parent(Some(vec![unsupported(0x03, CI | IO)]), None);
    assert_eq!(run(&io, &token()), Err(Error::UnsupportedAceInComputedAcl));

    let ignored = parent(Some(vec![unsupported(0x03, 0), allow(CI, RP, x())]), None);
    assert_eq!(
        dacl(&create(&ignored, true, None)),
        [allow(ID, RP, x()), allow(CI | IO | ID, RP, x())]
    );
    // Token.DefaultDACL goes through PostProcessACL (CopyAllAces) too.
    let t = Token {
        default_dacl: Some(acl(vec![unsupported(0x03, 0)])),
        ..token()
    };
    assert_eq!(
        run(&parent(None, None), &t),
        Err(Error::UnsupportedAceInComputedAcl)
    );
}

/// [MS-DTYP] 2.4.5: AclSize is 16-bit. A container child doubles each
/// inheritable ACE (2.5.3.4.4), so 1000 CI|OI ACEs of 36 bytes (36 008-byte
/// parent DACL) give 72 008 bytes ⇒ Error::AclTooLarge, never truncation; the
/// leaf child (one copy each) fits.
#[test]
fn inheritance_beyond_the_acl_size_bound_is_an_error() {
    let aces: Vec<Ace> = (0..1000)
        .map(|i| allow(CI | OI, RP, sid(&format!("S-1-5-21-1-2-3-{}", 10_000 + i))))
        .collect();
    assert_eq!(aces[0].encoded_len().unwrap(), 36);
    let p = parent(Some(aces), None);
    p.encode().expect("the parent itself fits");
    let run = |container| {
        create_security_descriptor(
            Some(&p),
            None,
            container,
            None,
            AutoInheritFlags::default(),
            &token(),
            &GenericMapping::ACTIVE_DIRECTORY,
        )
    };
    assert_eq!(run(true), Err(Error::AclTooLarge));
    let leaf = run(false).unwrap();
    assert_eq!(dacl(&leaf).len(), 1000);
    assert_round_trip(&leaf);
}

/// The CREATOR_OWNER substitution of 2.5.3.4.7 can grow an ACE: 3000 OI
/// ACEs for S-1-3-0 (20 bytes each) fit, but with an owner of 15
/// SubAuthorities (68-byte SID, 2.4.2.2) each copy is 76 bytes ⇒
/// Error::AclTooLarge; with a one-SubAuthority owner it fits.
#[test]
fn substitution_beyond_the_acl_size_bound_is_an_error() {
    let aces: Vec<Ace> = (0..3000).map(|_| allow(OI, RP, creator_owner())).collect();
    let p = parent(Some(aces), None);
    p.encode().expect("the parent itself fits");
    let big_owner = sid("S-1-5-21-1-2-3-4-5-6-7-8-9-10-11-12-13-14");
    assert_eq!(big_owner.encoded_len(), 68);
    let run = |owner_sid: Sid| {
        create_security_descriptor(
            Some(&p),
            None,
            false,
            None,
            AutoInheritFlags::default(),
            &Token {
                owner: owner_sid,
                ..token()
            },
            &GenericMapping::ACTIVE_DIRECTORY,
        )
    };
    assert_eq!(run(big_owner), Err(Error::AclTooLarge));
    let fits = run(sid("S-1-5-18")).unwrap();
    assert_eq!(dacl(&fits).len(), 3000);
}

/// An over-bound input is refused before anything is built: a parent DACL
/// that does not itself encode (over 65535 bytes).
#[test]
fn an_unencodable_parent_is_refused() {
    let aces: Vec<Ace> = (0..2000).map(|_| allow(CI, RP, x())).collect();
    let p = parent(Some(aces), None);
    assert_eq!(
        create_security_descriptor(
            Some(&p),
            None,
            false,
            None,
            AutoInheritFlags::default(),
            &token(),
            &GenericMapping::ACTIVE_DIRECTORY,
        ),
        Err(Error::AclTooLarge)
    );
}

/// The computed ACL keeps its source's AclRevision (Q-336): ACL_REVISION for
/// the 2.5.1.4 parent (above), ACL_REVISION_DS for a DS parent with object
/// ACEs; the result always encodes (round trip in `create`).
#[test]
fn computed_acl_keeps_the_parent_acl_revision() {
    let p = parent(Some(vec![allow_obj(CI, WP, Some(attr()), None, x())]), None);
    assert_eq!(
        create(&p, true, None).dacl.unwrap().acl_revision,
        ACL_REVISION_DS
    );
}

/// The computed descriptor of the 2.5.1.4 parent, encoded and decoded by the
/// strict codec, and its bytes re-decoded as the parent of a grandchild.
#[test]
fn computed_descriptor_round_trips_through_the_codec() {
    let parent = SecurityDescriptor::decode(&EXAMPLE).unwrap();
    for container in [true, false] {
        let child = create(&parent, container, Some(&[class_a()]));
        let bytes = child.encode().unwrap();
        let decoded = SecurityDescriptor::decode(&bytes).unwrap();
        assert_eq!(decoded, child);
        let grandchild = create(&decoded, container, Some(&[class_a()]));
        assert_round_trip(&grandchild);
    }
}
