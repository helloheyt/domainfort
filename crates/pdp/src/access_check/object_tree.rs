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

use dtyp::Guid;

/// A chain of object types, index = Level. Never empty (the root is always
/// present). Spec: [MS-DTYP] 2.3.9; [MS-ADTS] 5.1.3.3.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObjectTypeList {
    object_types: Vec<Guid>,
}

impl ObjectTypeList {
    /// Only the object itself (level 0): a whole-object request.
    /// Spec: [MS-ADTS] 5.1.3.3.3 ("If the requested access is for the entire
    /// object, check ... Grant(r)").
    pub(crate) fn object(class: Guid) -> ObjectTypeList {
        ObjectTypeList {
            object_types: vec![class],
        }
    }

    /// The object, and one sub-object at level 1 (a child class for
    /// RIGHT_DS_CREATE_CHILD, or a control access right).
    /// Spec: [MS-DTYP] 2.3.9, 2.4.4.3 (ObjectType identifies "a type of child
    /// object" / "an extended access right").
    pub(crate) fn object_and(class: Guid, sub_object: Guid) -> ObjectTypeList {
        ObjectTypeList {
            object_types: vec![class, sub_object],
        }
    }

    /// The object, the attribute's property set (if any) and the attribute.
    /// Spec: [MS-ADTS] 5.1.3.3.3 ("if there exists a property set pi ... of
    /// which ai is a member then add an edge (pi, ai) ...; otherwise add an
    /// edge (c, ai)").
    pub(crate) fn property(
        class: Guid,
        property_set: Option<Guid>,
        attribute: Guid,
    ) -> ObjectTypeList {
        let mut object_types = vec![class];
        if let Some(set) = property_set {
            object_types.push(set);
        }
        object_types.push(attribute);
        ObjectTypeList { object_types }
    }

    /// Number of nodes (1 to 3).
    pub(crate) fn node_count(&self) -> usize {
        self.object_types.len()
    }

    /// The node `g` labels, if any.
    ///
    /// Spec: [MS-DTYP] 2.5.3.2 ("Locate node n in LocalTree such that n.GUID
    /// is the same as ACE.Object"); [MS-ADTS] 5.1.3.3.3 steps 5 and 8 ("the
    /// unique node such that Guid(v) = g"; for a deny, a property set node is
    /// preferred over an attribute node). When one GUID labels several nodes
    /// of the chain (e.g. a child class equal to the object's own class), the
    /// shallowest node is taken: it is the first one found and it is the
    /// property set before the attribute. For the [MS-ADTS] 5.1.3.3.3 steps
    /// the effect on the target node (the last one, a descendant of every
    /// match) is the same for any choice; for the [MS-DTYP] 2.5.3.2 "Object
    /// Deny Access" case the shallowest node has the most Remaining bits
    /// (deeper nodes only ever lose more), so it is the stricter choice.
    pub(crate) fn locate(&self, g: &Guid) -> Option<usize> {
        self.object_types.iter().position(|t| t == g)
    }
}
