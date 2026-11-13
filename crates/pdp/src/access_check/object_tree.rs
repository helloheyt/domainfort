//! The object type tree of an access check.
//!
//! Spec: [MS-DTYP] 2.3.9 (OBJECT_TYPE_LIST: `Level` — "Level zero indicates
//! the object itself. Level one indicates a sub-object of the object, such as
//! a property set. Level two indicates a sub-object of the level one
//! sub-object, such as a property"; `ObjectType` GUID); [MS-ADTS] 5.1.3.3.3
//! (the object type tree: root `c` with `Guid(c) = c!schemaIDGUID`, property
//! set nodes `Guid(pi) = ai.attributeSecurityGUID`, attribute nodes
//! `Guid(ai) = ai!schemaIDGUID`; an attribute is a child of its property set,
//! otherwise of `c`; "The object type tree used during an access check can
//! include only a subset of the property set ... nodes and a subset of the
//! attribute nodes that the requester is interested in").
//!
//! This crate only builds the subset that one request is about, which is
//! always a chain: the object class at level 0, then optionally one node at
//! level 1 and one at level 2. The node a request targets is the last one.
//! In a chain, the ancestors of node `i` are the nodes before it and its
//! descendants are the nodes after it, and no node has a sibling.
//!
//! # Which node an object ACE names — A-28 (Q-081)
//!
//! [MS-ADTS] 5.1.3.3.3 says "Let O be an object of class c" and assumes "the
//! unique node such that Guid(v) = g"; it says neither which of the object's
//! classes `c` is nor what happens when one GUID labels two nodes. Project
//! decision A-28 (Q-081) settles both, and this module applies it for both
//! evaluators (the [MS-DTYP] 2.5.3.2 leg and the [MS-ADTS] 5.1.3.3.3 leg), so
//! the conjunction of P-8 / Q-051 keeps holding:
//!
//! 1. **Which class is `c`.** The root is the most specific class (the last
//!    objectClass value, [MS-ADTS] 3.1.1.2.4.3). An *allow* object ACE matches
//!    the root only when its ObjectType is that class's schemaIDGUID; a *deny*
//!    object ACE matches the root when its ObjectType is the schemaIDGUID of
//!    *any* class of the object's superclass chain.
//! 2. **A GUID that labels two nodes** (a property set GUID equal to the
//!    schemaIDGUID of one of its member attributes — dNSHostName in the
//!    pinned schema — or a child class equal to the object's own class): a
//!    *deny* applies at the higher node, which also covers the lower one; an
//!    *allow* applies only at the lower node. A property set whose GUID is
//!    also an attribute's schemaIDGUID ([`PropertySet::is_attribute_guid`])
//!    never takes an allow, even when that attribute is not in this chain:
//!    the allow belongs to the attribute node, which a request about another
//!    member of the set does not contain.
//!
//! [`ObjectTypeList::locate_allow`] and [`ObjectTypeList::locate_deny`] are the
//! two lookups. Each result is unique by construction — never "pick one
//! arbitrarily": for a given GUID at most one node takes allows (the lowest
//! node it labels, if that node may take allows at all), and a deny takes the
//! highest node it labels.
//!
//! Neither rule ever grants more than the earlier single-label tree did (the
//! invariant is stated and argued in the module documentation of
//! `access_check`, and tested in `tests/properties.rs`).
//!
//! [`PropertySet::is_attribute_guid`]: crate::model::PropertySet::is_attribute_guid

use dtyp::Guid;

use crate::model::PropertySet;

/// One node of the chain. Spec: [MS-DTYP] 2.3.9; [MS-ADTS] 5.1.3.3.3.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjectTypeNode {
    /// `Guid(v)` / OBJECT_TYPE_LIST.ObjectType.
    object_type: Guid,
    /// Whether an allow object ACE whose ObjectType is `object_type` applies
    /// at this node. `false` when the GUID also labels a lower node — of this
    /// chain, or (for a property set, [`PropertySet::is_attribute_guid`]) an
    /// attribute node of the object's full tree. Spec: A-28 (Q-081) item 2.
    allow_applies: bool,
}

/// A chain of object types, index = Level. Never empty (the root is always
/// present). Spec: [MS-DTYP] 2.3.9; [MS-ADTS] 5.1.3.3.3; A-28 (Q-081).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObjectTypeList {
    nodes: Vec<ObjectTypeNode>,
    /// The schemaIDGUIDs of the object's other classes (its superclass
    /// chain): a deny object ACE naming one of them applies at the root.
    /// Spec: A-28 (Q-081) item 1.
    superclasses: Vec<Guid>,
}

impl ObjectTypeList {
    /// Only the object itself (level 0): a whole-object request.
    /// Spec: [MS-ADTS] 5.1.3.3.3 ("If the requested access is for the entire
    /// object, check ... Grant(r)").
    pub(crate) fn object(class: Guid, superclasses: &[Guid]) -> ObjectTypeList {
        ObjectTypeList::chain(class, superclasses, &[])
    }

    /// The object, and one sub-object at level 1 (a child class for
    /// RIGHT_DS_CREATE_CHILD, or a control access right).
    /// Spec: [MS-DTYP] 2.3.9, 2.4.4.3 (ObjectType identifies "a type of child
    /// object" / "an extended access right").
    pub(crate) fn object_and(
        class: Guid,
        superclasses: &[Guid],
        sub_object: Guid,
    ) -> ObjectTypeList {
        ObjectTypeList::chain(class, superclasses, &[(sub_object, true)])
    }

    /// The object, the attribute's property set (if any) and the attribute.
    /// Spec: [MS-ADTS] 5.1.3.3.3 ("if there exists a property set pi ... of
    /// which ai is a member then add an edge (pi, ai) ...; otherwise add an
    /// edge (c, ai)"); A-28 (Q-081) item 2 for a property set whose GUID is
    /// also an attribute's schemaIDGUID.
    pub(crate) fn property(
        class: Guid,
        superclasses: &[Guid],
        property_set: Option<PropertySet>,
        attribute: Guid,
    ) -> ObjectTypeList {
        match property_set {
            Some(set) => ObjectTypeList::chain(
                class,
                superclasses,
                &[(set.guid, !set.is_attribute_guid), (attribute, true)],
            ),
            None => ObjectTypeList::chain(class, superclasses, &[(attribute, true)]),
        }
    }

    /// Build the chain: the most specific class at the root, then `below` in
    /// level order, each with whether the schema lets it take an allow. A
    /// node whose GUID labels a lower node of the chain takes no allow (A-28
    /// item 2: "an allow ACE applies only at the lower node").
    fn chain(class: Guid, superclasses: &[Guid], below: &[(Guid, bool)]) -> ObjectTypeList {
        let mut labels = Vec::with_capacity(below.len() + 1);
        // The root takes allows for the most specific class (A-28 item 1).
        labels.push((class, true));
        labels.extend_from_slice(below);
        let mut nodes = Vec::with_capacity(labels.len());
        for (index, (object_type, schema_allows)) in labels.iter().enumerate() {
            let labels_lower_node = labels
                .iter()
                .skip(index + 1)
                .any(|(lower, _)| lower == object_type);
            nodes.push(ObjectTypeNode {
                object_type: *object_type,
                allow_applies: *schema_allows && !labels_lower_node,
            });
        }
        ObjectTypeList {
            nodes,
            superclasses: superclasses.to_vec(),
        }
    }

    /// Number of nodes (1 to 3).
    pub(crate) fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The node at which an allow object ACE with ObjectType `g` applies, if
    /// any.
    ///
    /// Spec: [MS-DTYP] 2.5.3.2 ("CASE Object Allow Access ... Locate node n in
    /// LocalTree such that n.GUID is the same as ACE.Object"); [MS-ADTS]
    /// 5.1.3.3.3 step 5 ("let v ... be the unique node such that Guid(v) =
    /// g"); A-28 (Q-081): the root only for the most specific class, and for
    /// a GUID that labels two nodes only the lower one — so the node is
    /// unique. `None` also when the only node `g` labels here is a property
    /// set whose GUID belongs to an attribute outside this chain: the ACE is
    /// then skipped, as for a GUID outside the tree.
    pub(crate) fn locate_allow(&self, g: &Guid) -> Option<usize> {
        self.nodes
            .iter()
            .position(|node| node.allow_applies && node.object_type == *g)
    }

    /// The node at which a deny object ACE with ObjectType `g` applies, if
    /// any: the highest node `g` labels, where the root is labelled by every
    /// class of the object's superclass chain.
    ///
    /// Spec: [MS-DTYP] 2.5.3.2 ("CASE Object Deny Access ... Locate node n in
    /// LocalTree such that n.GUID is the same as ACE.Object"); [MS-ADTS]
    /// 5.1.3.3.3 step 8 ("let v be the unique node in P such that Guid(v) = g
    /// if any such node exists. If no such node exists, let v be the unique
    /// node in A" — a property set before an attribute; a class GUID, in
    /// neither P nor A, gives the root: Q-051 case 4); A-28 (Q-081): any
    /// class of the chain names the root, and for a GUID that labels two
    /// nodes the higher one. For the [MS-ADTS] steps the effect on the target
    /// (the last node, a descendant of every match) is the same for any
    /// matching node; for the [MS-DTYP] "Object Deny Access" case the highest
    /// node has the most Remaining bits (deeper nodes only ever lose more), so
    /// it is also the strictest choice.
    pub(crate) fn locate_deny(&self, g: &Guid) -> Option<usize> {
        if self.superclasses.contains(g) {
            return Some(0);
        }
        self.nodes.iter().position(|node| node.object_type == *g)
    }
}

#[cfg(test)]
mod tests {
    //! Source: A-28 (Q-081); [MS-ADTS] 5.1.3.3.3. Hand-made GUID labels.

    use super::*;

    fn g(n: u32) -> Guid {
        Guid {
            data1: n,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        }
    }

    const MOST_SPECIFIC: u32 = 1;
    const SUPERCLASS: u32 = 2;
    const SET: u32 = 3;
    const ATTRIBUTE: u32 = 4;
    const OTHER_MEMBER: u32 = 5;

    /// A-28 item 1: the root takes allows only for the most specific class,
    /// and denies for every class of the chain.
    #[test]
    fn root_labels() {
        let tree = ObjectTypeList::object(g(MOST_SPECIFIC), &[g(SUPERCLASS)]);
        assert_eq!(tree.locate_allow(&g(MOST_SPECIFIC)), Some(0));
        assert_eq!(tree.locate_allow(&g(SUPERCLASS)), None);
        assert_eq!(tree.locate_deny(&g(MOST_SPECIFIC)), Some(0));
        assert_eq!(tree.locate_deny(&g(SUPERCLASS)), Some(0));
        assert_eq!(tree.locate_deny(&g(SET)), None);
    }

    /// A-28 item 2, both nodes in the chain (a request about the attribute
    /// whose schemaIDGUID is its own property set's GUID): allow at the
    /// attribute, deny at the property set.
    #[test]
    fn shared_guid_in_the_chain() {
        let set = PropertySet {
            guid: g(ATTRIBUTE),
            is_attribute_guid: true,
        };
        let tree = ObjectTypeList::property(g(MOST_SPECIFIC), &[], Some(set), g(ATTRIBUTE));
        assert_eq!(tree.node_count(), 3);
        assert_eq!(tree.locate_allow(&g(ATTRIBUTE)), Some(2));
        assert_eq!(tree.locate_deny(&g(ATTRIBUTE)), Some(1));
        // The same holds if the PIP did not flag the set: the duplicate is
        // visible in the chain itself.
        let unflagged = PropertySet {
            guid: g(ATTRIBUTE),
            is_attribute_guid: false,
        };
        let tree = ObjectTypeList::property(g(MOST_SPECIFIC), &[], Some(unflagged), g(ATTRIBUTE));
        assert_eq!(tree.locate_allow(&g(ATTRIBUTE)), Some(2));
        assert_eq!(tree.locate_deny(&g(ATTRIBUTE)), Some(1));
    }

    /// A-28 item 2, only the property set node in the chain (a request about
    /// another member of the set): the allow is skipped, the deny applies.
    #[test]
    fn shared_guid_outside_the_chain() {
        let set = PropertySet {
            guid: g(SET),
            is_attribute_guid: true,
        };
        let tree = ObjectTypeList::property(g(MOST_SPECIFIC), &[], Some(set), g(OTHER_MEMBER));
        assert_eq!(tree.locate_allow(&g(SET)), None);
        assert_eq!(tree.locate_deny(&g(SET)), Some(1));
        assert_eq!(tree.locate_allow(&g(OTHER_MEMBER)), Some(2));
        // An ordinary property set takes both.
        let plain = PropertySet {
            guid: g(SET),
            is_attribute_guid: false,
        };
        let tree = ObjectTypeList::property(g(MOST_SPECIFIC), &[], Some(plain), g(OTHER_MEMBER));
        assert_eq!(tree.locate_allow(&g(SET)), Some(1));
        assert_eq!(tree.locate_deny(&g(SET)), Some(1));
    }

    /// A-28 item 2 for a child class equal to the object's own class, and
    /// items 1 + 2 for a child class equal to one of its superclasses.
    #[test]
    fn child_class_labels() {
        let same = ObjectTypeList::object_and(g(MOST_SPECIFIC), &[g(SUPERCLASS)], g(MOST_SPECIFIC));
        assert_eq!(same.locate_allow(&g(MOST_SPECIFIC)), Some(1));
        assert_eq!(same.locate_deny(&g(MOST_SPECIFIC)), Some(0));
        let superclass =
            ObjectTypeList::object_and(g(MOST_SPECIFIC), &[g(SUPERCLASS)], g(SUPERCLASS));
        assert_eq!(superclass.locate_allow(&g(SUPERCLASS)), Some(1));
        assert_eq!(superclass.locate_deny(&g(SUPERCLASS)), Some(0));
    }
}
