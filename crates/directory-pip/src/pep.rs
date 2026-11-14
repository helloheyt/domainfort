//! The directory as a PEP receives it: [`PepView`] — the visibility gate,
//! the locators that name the candidates the gate decides on, and the PIP /
//! account-source traits a PEP needs to build its Subject and ask the PDP —
//! and **no** raw read of an object (docs/52 R-a; decision A-103 on
//! docs/questions/Q-486: "PEPs will receive only a gate, and `snapshot()`
//! will not be public").
//!
//! # The class it closes (docs/52 §3.6, class C6, through a new PEP)
//!
//! The visibility gate (module `visible`, task U) made every typed content
//! function of the LDAP engine and the admin plane take a
//! [`VisibleObject`], which only the gate builds. But the raw snapshot was
//! still public on [`DirectoryView`], so a *new* PEP — or a new path in an
//! existing one — could read an object from it and put it on the wire
//! without asking the gate: an existence oracle that compiles
//! (docs/questions/Q-486 R-a).
//!
//! # How it is impossible by construction
//!
//! - A PEP is handed a `PepView` at wiring time (dird builds it from the
//!   request's view: `PepView::new(&view)`), never the `DirectoryView`
//!   itself. `PepView` keeps the view in a private field and has no
//!   accessor back to it, to its snapshot, or to any `dirstore::Object`.
//! - Every way a `PepView` hands out directory **content** (an object's
//!   attributes, its DN) goes through the gate: [`PepView::gate`] →
//!   [`crate::VisibilityGate::visible`] / [`crate::VisibilityGate::child`] →
//!   [`VisibleObject`] (absent and hidden answered alike, A-55).
//! - What it hands out besides is **locating**, not reading: a GUID found by
//!   a DN, a unique value, a parent pointer, a visible container's
//!   children or a visible object's back links — the inputs of a gate
//!   question. The two that act on an object take its [`VisibleObject`].
//! - `DirectoryView::snapshot` is not public any more. The authority's own
//!   reads (docs/questions/Q-486 items 1-6: the KDC's account source and
//!   the PIP inside this crate; the admin plane's write invariants and
//!   internal checks; provision verifying its own store) use
//!   [`DirectoryView::authority_snapshot`], on the view a PEP never
//!   receives.
//!
//! # Residuals (documented, not hidden — docs/questions/Q-540)
//!
//! - Rust cannot restrict a public item to named crates: a crate that holds
//!   a `DirectoryView` can call `authority_snapshot`. The PEP crate `ldap`
//!   never holds one (its inputs carry a `PepView`), and the callers of
//!   `authority_snapshot` are pinned by a source scan
//!   (crates/directory-pip/tests/pep_receives_only_the_gate.rs). Inside
//!   crate directory-admin — a PEP and the write path in one crate — the
//!   raw view is a private field of `checks::Cx`, so its request-facing
//!   code reaches only the `PepView` (module privacy, compile time).
//! - A located GUID is not content, but a PEP that wrote one it did not get
//!   through the gate to the wire would reveal existence; no PEP does (the
//!   LDAP engine renders only `VisibleObject`s).
//! - The PIP and account-source traits ([`PepView::pip`],
//!   [`PepView::accounts`]) answer for any principal or DN they are asked
//!   about — Q-486's accepted scope ("the account-source / PIP traits they
//!   need"); they were handed to the PEPs before (crate ldap's
//!   `RequestInputs`).
//!
//! Spec: docs/52 §3.6 (C6), §7 (R10); docs/questions/Q-486 (R-a, A-103),
//! Q-485, Q-487, Q-488; docs/11 §2 (the PEP), §6 (snapshot semantics), §7
//! ("filter, do not fail"), §8; docs/49 §6.1; docs/51 §5.2 row 10;
//! docs/questions/Q-485 (the visibility rule, as quoted there); A-55.

use dirstore::{AttrId, ChildCursor, ChildPage};
use dtyp::Guid;
use kdc::AccountSource;
use pdp::{Context, Pip, PipError, PolicySnapshot, Subject};

use crate::view::{DirectoryContext, DirectoryView};
use crate::visible::{VisibilityGate, VisibilityRule, VisibleObject};

/// One request's directory as a PEP receives it (module documentation):
/// the gate, the locators, the PIP and the account source over ONE view —
/// never the view's raw snapshot. `Copy`: it is a borrow of the view.
/// Spec: docs/52 R-a; docs/questions/Q-486 (A-103); docs/11 §2, §6.
#[derive(Clone, Copy)]
pub struct PepView<'v, 'a> {
    view: &'v DirectoryView<'a>,
}

impl<'v, 'a> PepView<'v, 'a> {
    /// The PEP's view of `view` — built by the wiring (dird) that owns the
    /// view, and handed to the PEP instead of it.
    /// Spec: docs/52 R-a; docs/questions/Q-486 (A-103).
    #[must_use]
    pub fn new(view: &'v DirectoryView<'a>) -> PepView<'v, 'a> {
        PepView { view }
    }

    /// The directory context (schema, naming context, realm) — configuration,
    /// not directory content. Spec: docs/47 §8.1.
    #[must_use]
    pub fn context(&self) -> &'v DirectoryContext {
        self.view.context()
    }

    /// The visibility gate of `subject` in `context` over this view and the
    /// policy of the same version — the only way a PEP obtains an object
    /// ([`VisibleObject`]). Spec: docs/52 R10; docs/11 §1, §2, §6, §7.
    #[must_use]
    pub fn gate(
        &self,
        policy: &'v PolicySnapshot,
        subject: Subject,
        context: Context,
        rule: VisibilityRule,
    ) -> VisibilityGate<'v, 'a> {
        VisibilityGate::new(self.view, policy, subject, context, rule)
    }

    /// The PIP of this view (the same snapshot the gate reads — docs/11 §6
    /// P9), for the PEP's own `decide` calls and its Subject's tier.
    /// Spec: docs/11 §6; docs/47 §8.1 (R47-11).
    #[must_use]
    pub fn pip(&self) -> &'v dyn Pip {
        self.view
    }

    /// The account source of this view, for the Subject of a verified
    /// identity (docs/51 §5.3; docs/49 §4.4, R49-15).
    /// Spec: docs/47 §1.3, §8.1.
    #[must_use]
    pub fn accounts(&self) -> &'v dyn AccountSource {
        self.view
    }

    /// Locate the object a client's DN names (its RDNs leaf first, as
    /// spelled): its GUID, or `None` — for a gate question, never content.
    /// Spec: docs/49 §7 (R49-11); [`DirectoryView::lookup_dn`].
    pub fn lookup_dn(&self, rdns: &[(&str, &str)]) -> Result<Option<Guid>, PipError> {
        self.view.lookup_dn(rdns)
    }

    /// `true` if a live object of the naming context has this GUID (the
    /// `<GUID=…>` form of a DN crate ldap resolves) — for a gate
    /// question, never its DN.
    /// Spec: docs/47 §8.2 (`dn_of`); crate ldap `resolve_ldap_dn`.
    pub fn names_object(&self, guid: Guid) -> Result<bool, PipError> {
        Ok(self.view.dn_of(guid)?.is_some())
    }

    /// Locate the object holding `value` in the unique attribute `attr`
    /// (dirstore's index: the comparison key of docs/46 §8.5).
    /// Spec: docs/49 §6.1 item 3 (the unique fast path); dirstore
    /// `Snapshot::lookup_unique`.
    pub fn lookup_unique(&self, attr: AttrId, value: &[u8]) -> dirstore::Result<Option<Guid>> {
        self.view.snapshot().lookup_unique(attr, value)
    }

    /// The parent pointer of the live object `guid`: `Ok(None)` when no live
    /// object has it, `Ok(Some(None))` for a parentless one — the walk from
    /// a located object up to a search base (docs/49 §6.1 item 3), nothing
    /// else of the object.
    /// Spec: docs/49 §6.1 item 3.
    pub fn parent_of(&self, guid: Guid) -> dirstore::Result<Option<Option<Guid>>> {
        Ok(self
            .view
            .snapshot()
            .get_object(guid)?
            .map(|object| object.parent))
    }

    /// One page of the children of the **visible** container `container`
    /// (A-49: authenticated, cross-checked, complete on the final page);
    /// each child is a gate question ([`crate::VisibilityGate::child`]).
    /// Spec: docs/49 §6.1 item 3; docs/questions/Q-485; dirstore
    /// `Snapshot::children`.
    pub fn children(
        &self,
        container: &VisibleObject<'v>,
        after: Option<&ChildCursor>,
        limit: usize,
    ) -> dirstore::Result<ChildPage> {
        self.view
            .snapshot()
            .children(Some(container.guid()), after, limit)
    }

    /// The sources of the back links of `back_attr` to the **visible**
    /// object `object` (memberOf of a candidate); each is a gate question.
    /// Spec: docs/46 R46-2; docs/49 §6.4, §6.5; dirstore
    /// `Snapshot::back_links`.
    pub fn back_links(
        &self,
        object: &VisibleObject<'v>,
        back_attr: AttrId,
    ) -> dirstore::Result<Vec<Guid>> {
        self.view.snapshot().back_links(object.guid(), back_attr)
    }
}
