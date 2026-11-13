//! Shared test fixtures.
//!
//! Source of every value here: hand-made for these tests. SIDs use the
//! layout of [MS-DTYP] 2.4.2 (well-known SIDs from the 2.4.2.4 table:
//! Everyone S-1-1-0, PRINCIPAL_SELF S-1-5-10, OWNER_RIGHTS S-1-3-4); GUIDs are
//! arbitrary distinct labels. No value comes from another implementation.

#![allow(dead_code)] // each test file uses a different subset

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};

use dtyp::{
    ace_flags, Ace, Acl, Control, Guid, MaskSidAce, ObjectAce, SecurityDescriptor, Sid,
    UnsupportedAce, ACL_REVISION_DS, CREATOR_SID_AUTHORITY, SECURITY_NT_AUTHORITY,
    WORLD_SID_AUTHORITY,
};
use pdp::{
    AccessRequest, Action, ActionMatch, AttrClass, AttrId, AuthContext, AuthStrength, Context,
    ContextMatch, Dn, Effect, Instant, IpScope, Match, ObjClass, ObjClassChain, Pip, PipError,
    PolicySnapshot, PolicyVersion, PropertySet, Resource, ResourceMatch, Rule, RuleId, Subject,
    SubjectMatch, Tier, Transport, TransportSec,
};

// ---------------------------------------------------------------- SIDs ----

/// A SID under SECURITY_NT_AUTHORITY ([MS-DTYP] 2.4.1, 2.4.2).
pub fn nt_sid(sub: &[u32]) -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, sub).expect("at most 15 sub-authorities")
}

/// The requesting user (hand-made domain-style SID).
pub fn user() -> Sid {
    nt_sid(&[21, 100, 200, 300, 1001])
}

/// Another user.
pub fn other_user() -> Sid {
    nt_sid(&[21, 100, 200, 300, 1002])
}

/// A group the user may belong to.
pub fn group() -> Sid {
    nt_sid(&[21, 100, 200, 300, 1101])
}

/// A second group.
pub fn other_group() -> Sid {
    nt_sid(&[21, 100, 200, 300, 1102])
}

/// Everyone, S-1-1-0. Spec: [MS-DTYP] 2.4.2.4.
pub fn everyone() -> Sid {
    Sid::new(WORLD_SID_AUTHORITY, &[0]).expect("valid")
}

/// PRINCIPAL_SELF, S-1-5-10. Spec: [MS-DTYP] 2.4.2.4.
pub fn principal_self() -> Sid {
    nt_sid(&[10])
}

/// OWNER_RIGHTS, S-1-3-4. Spec: [MS-DTYP] 2.4.2.4.
pub fn owner_rights() -> Sid {
    Sid::new(CREATOR_SID_AUTHORITY, &[4]).expect("valid")
}

// --------------------------------------------------------------- GUIDs ----

/// An arbitrary GUID label.
pub fn guid(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0x0101,
        data3: 0x0202,
        data4: [3, 3, 3, 3, 3, 3, 3, (n & 0xFF) as u8],
    }
}

/// The class of the object under test.
pub fn class_user() -> Guid {
    guid(0x10)
}
/// Another class (a possible child class).
pub fn class_group() -> Guid {
    guid(0x11)
}
/// A property set.
pub fn propset() -> Guid {
    guid(0x20)
}
/// An attribute that belongs to `propset()`.
pub fn attr_in_set() -> Guid {
    guid(0x30)
}
/// An attribute that belongs to no property set.
pub fn attr_alone() -> Guid {
    guid(0x31)
}
/// A second attribute of `propset()`.
pub fn attr_in_set_2() -> Guid {
    guid(0x32)
}
/// A control access right.
pub fn right_a() -> Guid {
    guid(0x40)
}
/// Another control access right.
pub fn right_b() -> Guid {
    guid(0x41)
}

// A class chain and a shared GUID (A-28, Q-081). The shapes follow
// [MS-ADTS] 3.1.1.2.4.3 (an objectClass chain: top first, the most specific
// class last) and Q-081 (a property set GUID equal to one member attribute's
// schemaIDGUID); the GUID values are arbitrary labels.

/// The root class of every chain (`top`'s role).
pub fn class_top() -> Guid {
    guid(0x13)
}
/// An intermediate class of a chain.
pub fn class_person() -> Guid {
    guid(0x14)
}
/// A class whose chain is `class_top`, `class_person`, `class_user`,
/// `class_computer` (most specific last).
pub fn class_computer() -> Guid {
    guid(0x15)
}
/// A GUID that is both a property set's GUID and the schemaIDGUID of one
/// member attribute of that set.
pub fn shared_guid() -> Guid {
    guid(0x22)
}
/// Another member attribute of the `shared_guid()` property set.
pub fn attr_in_shared_set() -> Guid {
    guid(0x34)
}

/// The property set `propset()` (its GUID names no attribute).
pub fn plain_set() -> PropertySet {
    PropertySet {
        guid: propset(),
        is_attribute_guid: false,
    }
}

/// The property set `shared_guid()` (its GUID is also an attribute's).
pub fn shared_set() -> PropertySet {
    PropertySet {
        guid: shared_guid(),
        is_attribute_guid: true,
    }
}

/// The class chain of a `class_computer()` object.
pub fn computer_chain() -> ObjClassChain {
    ObjClassChain {
        most_specific: ObjClass(class_computer()),
        superclasses: vec![
            ObjClass(class_top()),
            ObjClass(class_person()),
            ObjClass(class_user()),
        ],
    }
}

/// The class chain of the default object: `class_user()`, no other class
/// listed.
pub fn user_chain() -> ObjClassChain {
    ObjClassChain {
        most_specific: ObjClass(class_user()),
        superclasses: Vec::new(),
    }
}

// ---------------------------------------------------------------- ACEs ----

/// ACCESS_ALLOWED_ACE. Spec: [MS-DTYP] 2.4.4.2.
pub fn allow(mask: u32, sid: Sid) -> Ace {
    Ace::AccessAllowed(MaskSidAce {
        ace_flags: 0,
        mask: dtyp::AccessMask(mask),
        sid,
    })
}

/// ACCESS_DENIED_ACE. Spec: [MS-DTYP] 2.4.4.4.
pub fn deny(mask: u32, sid: Sid) -> Ace {
    Ace::AccessDenied(MaskSidAce {
        ace_flags: 0,
        mask: dtyp::AccessMask(mask),
        sid,
    })
}

/// ACCESS_ALLOWED_OBJECT_ACE. Spec: [MS-DTYP] 2.4.4.3.
pub fn allow_obj(mask: u32, object_type: Option<Guid>, sid: Sid) -> Ace {
    Ace::AccessAllowedObject(ObjectAce {
        ace_flags: 0,
        mask: dtyp::AccessMask(mask),
        object_type,
        inherited_object_type: None,
        sid,
    })
}

/// ACCESS_DENIED_OBJECT_ACE. Spec: [MS-DTYP] 2.4.4.5.
pub fn deny_obj(mask: u32, object_type: Option<Guid>, sid: Sid) -> Ace {
    Ace::AccessDeniedObject(ObjectAce {
        ace_flags: 0,
        mask: dtyp::AccessMask(mask),
        object_type,
        inherited_object_type: None,
        sid,
    })
}

/// The same ACE with INHERIT_ONLY_ACE set. Spec: [MS-DTYP] 2.4.4.1.
pub fn inherit_only(ace: Ace) -> Ace {
    with_flags(ace, ace_flags::INHERIT_ONLY_ACE)
}

/// The same ACE with the given AceFlags. Spec: [MS-DTYP] 2.4.4.1.
pub fn with_flags(ace: Ace, flags: u8) -> Ace {
    match ace {
        Ace::AccessAllowed(mut a) => {
            a.ace_flags = flags;
            Ace::AccessAllowed(a)
        }
        Ace::AccessDenied(mut a) => {
            a.ace_flags = flags;
            Ace::AccessDenied(a)
        }
        Ace::AccessAllowedObject(mut a) => {
            a.ace_flags = flags;
            Ace::AccessAllowedObject(a)
        }
        Ace::AccessDeniedObject(mut a) => {
            a.ace_flags = flags;
            Ace::AccessDeniedObject(a)
        }
        Ace::Unsupported(mut u) => {
            u.ace_flags = flags;
            Ace::Unsupported(u)
        }
        other => other,
    }
}

/// An ACE of a type the crate keeps as `Ace::Unsupported`, with an
/// uninterpreted body. Spec: [MS-DTYP] 2.4.4.1 (AceType table).
pub fn unsupported(ace_type: u8) -> Ace {
    Ace::Unsupported(UnsupportedAce {
        ace_type,
        ace_flags: 0,
        body: vec![0; 12],
    })
}

// ----------------------------------------------------------------- SDs ----

/// A self-relative descriptor with a DACL (DP set) of the given ACEs and the
/// given owner. Spec: [MS-DTYP] 2.4.6 (SR MUST be set; DP iff a DACL; OD when
/// there is no owner; GD — no group).
pub fn sd(owner: Option<Sid>, aces: Vec<Ace>) -> SecurityDescriptor {
    let mut control = Control::SELF_RELATIVE | Control::DACL_PRESENT | Control::GROUP_DEFAULTED;
    if owner.is_none() {
        control |= Control::OWNER_DEFAULTED;
    }
    SecurityDescriptor {
        sbz1: 0,
        control: Control(control),
        owner_sid: owner,
        group_sid: None,
        sacl: None,
        dacl: Some(Acl {
            acl_revision: ACL_REVISION_DS,
            aces,
        }),
    }
}

/// A self-relative descriptor WITHOUT a DACL (DP clear). Spec: [MS-DTYP]
/// 2.4.6.
pub fn sd_without_dacl(owner: Option<Sid>) -> SecurityDescriptor {
    let mut control = Control::SELF_RELATIVE | Control::GROUP_DEFAULTED;
    if owner.is_none() {
        control |= Control::OWNER_DEFAULTED;
    }
    SecurityDescriptor {
        sbz1: 0,
        control: Control(control),
        owner_sid: owner,
        group_sid: None,
        sacl: None,
        dacl: None,
    }
}

// ------------------------------------------------------------ subjects ----

/// An authenticated subject (Kerberos, verified ticket).
pub fn subject(principal: Sid, groups: &[Sid], tier: Tier) -> Subject {
    Subject {
        principal,
        groups: groups.iter().copied().collect::<BTreeSet<_>>(),
        claims: BTreeMap::new(),
        auth: AuthContext {
            strength: AuthStrength::Kerberos,
            armored: true,
            ticket_age: Duration::from_secs(60),
            ticket_verified: true,
        },
        tier,
    }
}

/// The plain test user: member of `group()`, Tier 1.
pub fn the_user() -> Subject {
    subject(user(), &[group()], Tier::Tier1)
}

/// A context with every transport property.
pub fn strong_context() -> Context {
    Context {
        src_net: IpScope::Internal,
        time: Instant(1_000_000),
        transport: Transport::Ldaps,
        transport_sec: TransportSec {
            encrypted: true,
            sealed: true,
            channel_bound: true,
        },
    }
}

// ------------------------------------------------------------- policy ----

/// An Allow rule that matches every request.
pub fn allow_everything(id: u32) -> Rule {
    Rule {
        id: RuleId(id),
        effect: Effect::Allow,
        when: match_all(),
        obligations: vec![],
    }
}

/// A matcher that matches every request.
pub fn match_all() -> Match {
    Match {
        action: ActionMatch::Any,
        resource: ResourceMatch::Any,
        subject: SubjectMatch::Any,
        context: ContextMatch::ANY,
    }
}

/// A snapshot with these rules and no anonymous allowlist.
pub fn policy(rules: Vec<Rule>) -> PolicySnapshot {
    PolicySnapshot::new(PolicyVersion(1), rules, vec![])
}

// ---------------------------------------------------------------- PIP ----

/// The DN of the object under test.
pub fn obj_dn() -> Dn {
    Dn::new(vec!["cn=obj".into(), "ou=unit".into(), "dc=test".into()])
}

/// The DN of its parent.
pub fn parent_dn() -> Dn {
    Dn::new(vec!["ou=unit".into(), "dc=test".into()])
}

/// Which PIP method fails, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failing {
    None,
    TierOf,
    ObjectTier,
    SecurityDescriptor,
    AttrClass,
    ObjectClasses,
    ObjectSid,
    PropertySet,
}

/// A table-driven PIP for tests.
#[derive(Debug, Clone)]
pub struct MockPip {
    /// Security descriptors by DN (missing ⇒ NotFound).
    pub sds: BTreeMap<Dn, SecurityDescriptor>,
    /// Class chains by DN (missing ⇒ `user_chain()`).
    pub classes: BTreeMap<Dn, ObjClassChain>,
    /// objectSid by DN (missing ⇒ none).
    pub object_sids: BTreeMap<Dn, Sid>,
    /// Object tiers by DN; every other resource has `default_object_tier`.
    pub object_tiers: BTreeMap<Dn, Tier>,
    /// Tier of non-listed resources.
    pub default_object_tier: Tier,
    /// Attribute classes (missing ⇒ Normal).
    pub attr_classes: BTreeMap<AttrId, AttrClass>,
    /// Property sets (missing ⇒ none).
    pub property_sets: BTreeMap<AttrId, PropertySet>,
    /// Principal tiers (missing ⇒ Tier1).
    pub tiers: BTreeMap<Sid, Tier>,
    /// A method that fails.
    pub failing: Failing,
}

impl MockPip {
    /// A PIP knowing one object (`obj_dn()`) with the given descriptor.
    pub fn with_sd(sd: SecurityDescriptor) -> MockPip {
        let mut sds = BTreeMap::new();
        sds.insert(obj_dn(), sd);
        let mut property_sets = BTreeMap::new();
        property_sets.insert(AttrId(attr_in_set()), plain_set());
        property_sets.insert(AttrId(attr_in_set_2()), plain_set());
        property_sets.insert(AttrId(shared_guid()), shared_set());
        property_sets.insert(AttrId(attr_in_shared_set()), shared_set());
        MockPip {
            sds,
            classes: BTreeMap::new(),
            object_sids: BTreeMap::new(),
            object_tiers: BTreeMap::new(),
            default_object_tier: Tier::Tier1,
            attr_classes: BTreeMap::new(),
            property_sets,
            tiers: BTreeMap::new(),
            failing: Failing::None,
        }
    }

    fn fails(&self, which: Failing) -> bool {
        self.failing == which
    }
}

impl Pip for MockPip {
    fn expand_groups(&self, _p: &Sid) -> Result<BTreeSet<Sid>, PipError> {
        Ok(BTreeSet::new())
    }

    fn tier_of(&self, p: &Sid, _g: &BTreeSet<Sid>) -> Result<Tier, PipError> {
        if self.fails(Failing::TierOf) {
            return Err(PipError::Unavailable);
        }
        Ok(self.tiers.get(p).copied().unwrap_or(Tier::Tier1))
    }

    fn object_tier(&self, r: &Resource) -> Result<Tier, PipError> {
        if self.fails(Failing::ObjectTier) {
            return Err(PipError::Unavailable);
        }
        Ok(match r {
            Resource::DirObject { dn, .. } => self
                .object_tiers
                .get(dn)
                .copied()
                .unwrap_or(self.default_object_tier),
            _ => self.default_object_tier,
        })
    }

    fn security_descriptor(&self, dn: &Dn) -> Result<SecurityDescriptor, PipError> {
        if self.fails(Failing::SecurityDescriptor) {
            return Err(PipError::Unavailable);
        }
        self.sds.get(dn).cloned().ok_or(PipError::NotFound)
    }

    fn attr_class(&self, a: &AttrId) -> Result<AttrClass, PipError> {
        if self.fails(Failing::AttrClass) {
            return Err(PipError::Unavailable);
        }
        Ok(self
            .attr_classes
            .get(a)
            .copied()
            .unwrap_or(AttrClass::Normal))
    }

    fn object_classes(&self, dn: &Dn) -> Result<ObjClassChain, PipError> {
        if self.fails(Failing::ObjectClasses) {
            return Err(PipError::Unavailable);
        }
        Ok(self.classes.get(dn).cloned().unwrap_or_else(user_chain))
    }

    fn object_sid(&self, dn: &Dn) -> Result<Option<Sid>, PipError> {
        if self.fails(Failing::ObjectSid) {
            return Err(PipError::Unavailable);
        }
        Ok(self.object_sids.get(dn).copied())
    }

    fn property_set(&self, a: &AttrId) -> Result<Option<PropertySet>, PipError> {
        if self.fails(Failing::PropertySet) {
            return Err(PipError::Unavailable);
        }
        Ok(self.property_sets.get(a).copied())
    }
}

// ------------------------------------------------------------ requests ----

/// A directory request on `obj_dn()` by `subject` in `strong_context()`.
pub fn dir_request(subject: Subject, action: Action, attr: Option<Guid>) -> AccessRequest {
    AccessRequest {
        subject,
        resource: Resource::DirObject {
            dn: obj_dn(),
            attr: attr.map(AttrId),
        },
        action,
        context: strong_context(),
    }
}

/// `true` if the decision carries exactly one Audit obligation (P7).
pub fn exactly_one_audit(d: &pdp::Decision) -> bool {
    d.obligations
        .iter()
        .filter(|o| matches!(o, pdp::Obligation::Audit))
        .count()
        == 1
}
