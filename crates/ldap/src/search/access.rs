//! The PDP questions of a search: may the requester list a container, may it
//! read an attribute of an object.
//!
//! Every question is one `pdp::decide` with all five layers (docs/11 §4),
//! asked of the request's directory view as the PIP — the same snapshot the
//! candidates come from (docs/11 §6 P9; docs/49 §6.1). The rule is
//! `pdp::decide_visibility`'s (pdp visibility.rs, [MS-ADTS] 3.1.1.4.3,
//! 5.1.3.3.6): an object is visible iff `DirList` is allowed on its parent —
//! on the object itself for the naming-context root (pdp's choice: no
//! object is visible without a positive decision) — and an attribute is
//! readable iff `DirRead(attr)` is allowed on the object. The engine asks
//! these questions itself rather than through `decide_visibility` so that a
//! container's list decision, which is the same for all its children (the
//! same request against the same snapshot — `decide` is a pure function,
//! P9), is taken once per container, and so that the read decisions of the
//! filter are taken lazily, only for the attributes a filter item actually
//! reaches.
//!
//! The per-object and per-attribute decisions are not audited one by one
//! and their obligations are not applied (pdp visibility.rs: "Visibility
//! filtering is not itself an access decision"); the search operation is
//! authorised and audited by the base's visibility decision (crate::search).
//!
//! Spec: docs/11 §4, §6, §7; docs/49 §6.1 items 2-4 (R49-9); [MS-ADTS]
//! v20261026 3.1.1.4.3, 5.1.3.3.6; pdp `decide_visibility`.

use std::collections::BTreeMap;

use directory_pip::DirectoryView;
use dtyp::Guid;
use pdp::{
    decide, AccessRequest, Action, AttrId, Context, Decision, Dn, Effect, PolicySnapshot, Resource,
    Subject,
};

/// The PDP questions of one search (module documentation).
pub(crate) struct Access<'r> {
    subject: Subject,
    context: Context,
    policy: &'r PolicySnapshot,
    pip: &'r DirectoryView<'r>,
    /// `DirList` effect per container DN (the directory's canonical DN).
    lists: BTreeMap<Dn, bool>,
}

impl<'r> Access<'r> {
    pub(crate) fn new(
        subject: Subject,
        context: Context,
        policy: &'r PolicySnapshot,
        pip: &'r DirectoryView<'r>,
    ) -> Access<'r> {
        Access {
            subject,
            context,
            policy,
            pip,
            lists: BTreeMap::new(),
        }
    }

    fn request(&self, action: Action, dn: Dn, attr: Option<AttrId>) -> AccessRequest {
        AccessRequest {
            subject: self.subject.clone(),
            resource: Resource::DirObject { dn, attr },
            action,
            context: self.context.clone(),
        }
    }

    /// `DirList` on the container `dn`: the full decision (for the
    /// operation-level decision and its obligations), remembered.
    /// Spec: [MS-ADTS] 3.1.1.4.3 ("RIGHT_DS_LIST_CONTENTS ... on OP"),
    /// 5.1.3.3.6; docs/49 §6.1 item 2.
    pub(crate) fn decide_list(&mut self, dn: &Dn) -> Decision {
        let decision = decide(
            &self.request(Action::DirList, dn.clone(), None),
            self.policy,
            self.pip,
        );
        self.lists
            .insert(dn.clone(), decision.effect == Effect::Allow);
        decision
    }

    /// May the requester list the container `dn` — i.e. are its children
    /// visible? Spec: [MS-ADTS] 5.1.3.3.6; docs/49 §6.1 items 3-4.
    pub(crate) fn may_list(&mut self, dn: &Dn) -> bool {
        match self.lists.get(dn) {
            Some(allowed) => *allowed,
            None => self.decide_list(dn).effect == Effect::Allow,
        }
    }

    /// Is the object `dn` visible? The list decision on its parent, or on
    /// itself for the NC root (module documentation).
    /// Spec: [MS-ADTS] 5.1.3.3.6; pdp visibility.rs.
    pub(crate) fn visible(&mut self, dn: &Dn, is_nc_root: bool) -> bool {
        let target = list_target(dn, is_nc_root);
        self.may_list(&target)
    }

    /// May the requester read the attribute `attr` (its schemaIDGUID) of
    /// the object `dn`? Spec: [MS-ADTS] 3.1.1.4.3 ("RIGHT_DS_READ_PROPERTY
    /// on OA"), 3.1.1.4.4 (Sensitive: the control right, pdp layer 5);
    /// docs/49 §6.1 item 4.
    pub(crate) fn may_read(&self, dn: &Dn, attr: Guid) -> bool {
        decide(
            &self.request(Action::DirRead, dn.clone(), Some(AttrId(attr))),
            self.policy,
            self.pip,
        )
        .effect
            == Effect::Allow
    }
}

/// The container whose `DirList` decides the visibility of the object `dn`:
/// its parent (its DN without the leaf RDN), or the object itself when it
/// is the NC root. Spec: [MS-ADTS] 3.1.1.4.3 (OP = O!parent), 5.1.3.3.6;
/// pdp visibility.rs (the NC root decides on itself).
pub(crate) fn list_target(dn: &Dn, is_nc_root: bool) -> Dn {
    if is_nc_root {
        return dn.clone();
    }
    Dn::new(
        dn.rdns()
            .get(1..)
            .map(<[String]>::to_vec)
            .unwrap_or_default(),
    )
}
