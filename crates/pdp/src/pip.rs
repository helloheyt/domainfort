//! The Policy Information Point interface.
//!
//! Spec: docs/11 §6 (`trait Pip`: `expand_groups`, `tier_of`, `object_tier`,
//! `security_descriptor`, `attr_class`; snapshot semantics), D40 ("PDP returns
//! Deny on every internal error / timeout"); docs/06 §1, §9.
//!
//! Every method returns `Result`: an `Err` (lookup failed, timed out, or the
//! item is absent) makes the decision Deny with [`ReasonCode::PipFailure`]
//! (D40, fail closed). A PIP implementation reports problems through `Err`;
//! it must not panic.
//!
//! Extension to docs/11 §6 (three methods): the object type tree of
//! [MS-ADTS] 5.1.3.3.3 needs the object's classes (`Guid(c) =
//! c!schemaIDGUID` for the root, and — A-28 (Q-081) — the rest of the
//! superclass chain, which deny object ACEs may name) and each attribute's
//! property set (`ai.attributeSecurityGUID`, and whether that GUID is also an
//! attribute's schemaIDGUID — A-28 item 2), and the Principal Self
//! substitution of [MS-ADTS] 5.1.3.3 / [MS-DTYP] 2.5.3.2
//! (`PrincipalSelfSubst`) needs the object's `objectSid`. These are
//! [`Pip::object_classes`], [`Pip::property_set`] and [`Pip::object_sid`].
//!
//! Snapshot semantics (docs/11 §6, P9): all answers for one decision must come
//! from one consistent view (policy version + directory read view), so that
//! two identical requests against the same snapshot get the same decision.
//!
//! [`ReasonCode::PipFailure`]: crate::model::ReasonCode::PipFailure

use std::collections::BTreeSet;

use dtyp::{SecurityDescriptor, Sid};

use crate::model::{
    AttrId, ControlRightId, Dn, ObjClassChain, PrincipalId, PropertySet, Resource, Tier,
};

/// Why a PIP lookup produced no answer. Either variant yields Deny (D40).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PipError {
    /// The item does not exist in the snapshot.
    NotFound,
    /// The PIP could not answer (error, timeout, inconsistent view).
    Unavailable,
}

/// The class of an attribute for layer 5. Spec: docs/11 §4 (layer 5), §6
/// (`Normal | Sensitive | Secret`); docs/05 §4-§5; docs/06 §5 item 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttrClass {
    /// No additional requirement beyond the ACL.
    Normal,
    /// Requires, in addition to the ACL, the control access right named here
    /// (docs/11 §4: `Sensitive if !has_control_right(..)`). The PIP chooses
    /// the right from the project's tight list (docs/05 §5); for an attribute
    /// marked confidential in the schema, [MS-ADTS] 3.1.1.4.4 requires
    /// RIGHT_DS_CONTROL_ACCESS on the attribute, i.e. the PIP names the
    /// attribute's own schemaIDGUID here.
    Sensitive {
        /// The control access right (rightsGuid) that must also be granted.
        control_access_right: ControlRightId,
    },
    /// Secret material: no action may reach it (P6, docs/05 §4).
    Secret,
}

/// The PIP: authoritative data for decisions. Spec: docs/11 §6.
pub trait Pip {
    /// Expanded (nested) group membership of a principal. Spec: docs/11 §6.
    ///
    /// Not called by [`crate::decide`]: docs/11 §1 takes `Subject.groups`
    /// from the verified PAC ("not reloaded"). Provided for the PEP that
    /// builds the `Subject` (docs/06 §8: token construction is a PIP
    /// operation).
    fn expand_groups(&self, p: &PrincipalId) -> Result<BTreeSet<PrincipalId>, PipError>;

    /// The tier of a principal with the given groups. Spec: docs/11 §6.
    /// `decide` requires it to equal `Subject.tier` (P3).
    fn tier_of(&self, p: &PrincipalId, g: &BTreeSet<PrincipalId>) -> Result<Tier, PipError>;

    /// The tier of a resource (layer 4, P5). Spec: docs/11 §4, §6.
    fn object_tier(&self, r: &Resource) -> Result<Tier, PipError>;

    /// The security descriptor (nTSecurityDescriptor) of a directory object.
    /// Spec: docs/11 §6; [MS-ADTS] 5.1.3.1 ("Every object in Active Directory
    /// has an nTSecurityDescriptor attribute").
    fn security_descriptor(&self, dn: &Dn) -> Result<SecurityDescriptor, PipError>;

    /// The class of an attribute (layer 5). Spec: docs/11 §6.
    fn attr_class(&self, a: &AttrId) -> Result<AttrClass, PipError>;

    /// Extension: the schemaIDGUIDs of every class of the object's objectClass
    /// chain, naming the most specific one (the last objectClass value).
    ///
    /// Spec: [MS-ADTS] 3.1.1.2.4.3 (objectClass, "the most specific class");
    /// 5.1.3.3.3 ("Add c to V as the root node of the tree and set Guid(c) to
    /// c!schemaIDGUID"); A-28 (Q-081): the most specific class is `c`, the
    /// root; an allow object ACE matches the root only for it; a deny object
    /// ACE whose ObjectType is any class of the chain applies at the root.
    /// Listing a class the object is not an instance of can only add denies;
    /// naming the wrong most specific class can grant wrongly — the PIP takes
    /// it from the object's stored classes and the schema.
    fn object_classes(&self, dn: &Dn) -> Result<ObjClassChain, PipError>;

    /// Extension: the object's objectSid, or `Ok(None)` if the object has
    /// none; substituted for PRINCIPAL_SELF. Spec: [MS-ADTS] 5.1.3.3 ("the
    /// server replaces them with O!objectSid"); [MS-DTYP] 2.5.3.2
    /// (`PrincipalSelfSubst` "can be null").
    fn object_sid(&self, dn: &Dn) -> Result<Option<Sid>, PipError>;

    /// Extension: the property set (attributeSecurityGUID) the attribute
    /// belongs to, or `Ok(None)` if none; with it, whether that GUID is also
    /// the schemaIDGUID of an attribute ([`PropertySet::is_attribute_guid`]).
    /// Spec: [MS-ADTS] 5.1.3.3.3 ("if ai.attributeSecurityGUID ≠ NULL, then
    /// let pi denote the property set of which ai is a member"), 3.1.1.2.3.3;
    /// A-28 (Q-081) item 2.
    fn property_set(&self, a: &AttrId) -> Result<Option<PropertySet>, PipError>;
}
