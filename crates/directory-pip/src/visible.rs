//! The visibility gate: the one way a PEP obtains a directory object it may
//! show to, or act on for, a requester (docs/52 R10, decision A-102).
//!
//! # The class it closes (docs/52 §3.6, class C6)
//!
//! "The error class, or the order of the checks, reveals what the authority
//! would hide." A directory object the requester may not see must be
//! answered exactly like an object that does not exist (docs/11 §7: "filter,
//! do not fail — otherwise we would confirm existence"; §8: "no permission =
//! does not exist"; docs/49 §9 R49-13; docs/51 §5.2 row 10; A-55). Before
//! this gate the rule was written twice — in the LDAP search and in the
//! admin plane — and a new read path could forget it.
//!
//! # How the gate makes it impossible by construction
//!
//! - [`VisibleObject`] has **no public constructor**. Only
//!   [`VisibilityGate::visible`] and [`VisibilityGate::child`] build one,
//!   and only after the PDP allowed the rule's question for this
//!   requester. A function that takes a `VisibleObject` therefore cannot be
//!   reached with an object that skipped the check — such a call does not
//!   compile.
//! - The verdict is a [`Visibility`] in which "absent" and "present but not
//!   visible" are **one variant**, [`Visibility::NotFound`]. What it was is
//!   kept in [`Unseen`] for the audit record only (the audit is internal,
//!   docs/11 §1b); the client answer of both is the same.
//! - A refusal that is not a verdict on the object — the PDP layers that
//!   precede the object (authentication, transport), the subject's tier, a
//!   malformed request, a PIP failure (fail closed) — is
//!   [`Visibility::Refused`]; the classification lives here, once
//!   ([`hides`]), instead of in each PEP (docs/questions/Q-200 item 5;
//!   Q-169 item 3, as cited in crate ldap).
//! - A `VisibleObject<'v>` carries the lifetime of the view it was read
//!   from, so it cannot outlive that view's snapshot (docs/11 §6 P9: one
//!   snapshot per decision).
//!
//! # One visibility rule, and what a PEP adds to it (docs/questions/Q-485)
//!
//! - [`VisibilityRule::ListParent`] — **the** visibility rule, [MS-ADTS]
//!   5.1.3.3.6 (the default mode): "If a user is granted the
//!   RIGHT_DS_LIST_CONTENTS access right on a container, all child objects
//!   of that container are visible to the user", i.e. `DirList` on the
//!   parent; on the object itself for the root of the naming context (pdp
//!   `decide_visibility`'s choice — no object is visible without a positive
//!   decision). The LDAP search (docs/49 §6.1 item 2; [MS-ADTS] 3.1.1.4.3:
//!   RIGHT_DS_LIST_CONTENTS "on OP").
//! - [`VisibilityRule::ListAndRead`] — the same rule **and** `DirRead` on
//!   the whole object (docs/51 §5.2 row 10, citing docs/11 §7;
//!   docs/questions/Q-358 item 3): the admin plane's, for an object a
//!   request names. Both questions are one rule of the gate, so a PEP
//!   cannot ask one and forget the other. Every object visible under it is
//!   visible under `ListParent` — the admin plane can never name an object
//!   the LDAP search hides (decision on Q-485).
//!
//! Every question is a PDP decision with all five layers (docs/11 §4) over
//! the view that is also the PIP (docs/11 §6, P9).
//!
//! # Decisions taken once
//!
//! A container's `DirList` decision is the same for all its children (the
//! same request against the same snapshot — `decide` is pure, P1/P9), so it
//! is taken once per gate and remembered, as are whole-object `DirRead`
//! decisions. The per-object decisions are not audited one by one and their
//! obligations are the PEP's to honour or not (pdp visibility.rs:
//! "Visibility filtering is not itself an access decision"); the decision
//! that made an object visible is handed back with it.
//!
//! # Out of scope (documented, not hidden)
//!
//! - The raw snapshot is not public (docs/52 R-a; A-103 on
//!   docs/questions/Q-486): a PEP receives a [`crate::PepView`] — this gate,
//!   the locators of its questions, the PIP — never the view's snapshot.
//!   The authority's own reads (the PDP's PIP, the KDC's account source,
//!   the admin plane's membership-graph invariants and internal checks,
//!   provision) use [`DirectoryView::authority_snapshot`] on the view a PEP
//!   never receives; none of them hands directory content to a requester
//!   (module `pep`).
//! - A `VisibleObject` is bound to its view, not to one gate: two gates for
//!   two subjects over the same view could exchange objects. No PEP builds
//!   two gates over one view (Q-486).
//! - The timing side channel (docs/49 §6.6; A-55 residual) is unchanged.
//!
//! Spec: docs/52 §3.6, §7 (R10); docs/11 §4, §6, §7, §8; docs/49 §6.1 items
//! 2-4, §9 (R49-13); docs/51 §5.2 row 10; [MS-ADTS] v20261026 3.1.1.4.3,
//! 5.1.3.3.6; A-55; docs/questions/Q-200 item 5, Q-358 item 3.

use core::marker::PhantomData;
use std::collections::BTreeMap;

use dirstore::Object;
use dtyp::Guid;
use pdp::{
    decide, AccessRequest, Action, AttrId, Context, Decision, Dn, Effect, PolicySnapshot,
    ReasonCode, Resource, Subject,
};

use crate::view::{DirectoryView, MAX_DN_DEPTH};

/// Which PDP questions decide that an object is visible (module
/// documentation). Spec: [MS-ADTS] 5.1.3.3.6; docs/51 §5.2 row 10;
/// docs/questions/Q-485.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VisibilityRule {
    /// `DirList` (RIGHT_DS_LIST_CONTENTS) on the object's parent; on the
    /// object itself for the naming-context root. "List Object" mode is not
    /// implemented (pdp: "The default setting is '0'"; fewer objects, never
    /// more). Spec: [MS-ADTS] 5.1.3.3.6, 3.1.1.4.3; docs/49 §6.1 item 2.
    ListParent,
    /// [`VisibilityRule::ListParent`] first, then `DirRead` on the whole
    /// object (`attr: None`); both must allow. The decision handed back with
    /// a visible object is the `DirRead` one (it authorises reading the
    /// object — the admin plane's `Lookup`). Spec: [MS-ADTS] 5.1.3.3.6;
    /// docs/51 §5.2 row 10 (docs/11 §7 as cited there); docs/questions/Q-485.
    ListAndRead,
}

/// A live object of the naming context that the gate's requester may see,
/// read from one view. No public constructor: only the gate builds one, and
/// only after the PDP allowed it (module documentation).
/// Spec: docs/52 R10; [MS-ADTS] 5.1.3.3.6 ("visible ... if the requester
/// can see the name of the object and thus learn of its existence").
#[derive(Debug, PartialEq, Eq)]
pub struct VisibleObject<'v> {
    object: Object,
    dn: Dn,
    /// Invariant in `'v`: the object belongs to exactly the view it was
    /// read from and cannot outlive it.
    _view: PhantomData<fn(&'v ()) -> &'v ()>,
}

impl<'v> VisibleObject<'v> {
    /// The objectGUID. Spec: [MS-ADTS] 3.1.1.1.3.
    #[must_use]
    pub fn guid(&self) -> Guid {
        self.object.guid
    }

    /// The object as the view's snapshot holds it.
    #[must_use]
    pub fn object(&self) -> &Object {
        &self.object
    }

    /// The directory's canonical DN of the object
    /// ([`DirectoryView::dn_of`]). Spec: docs/47 §8.2; A-53.
    #[must_use]
    pub fn dn(&self) -> &Dn {
        &self.dn
    }

    /// `true` for the root of the naming context (the only live object of
    /// the NC without a parent, A-53). Spec: [MS-ADTS] 3.1.1.1.5.
    #[must_use]
    pub fn is_nc_root(&self) -> bool {
        self.object.parent.is_none()
    }

    /// Take the object apart, keeping the proof that it passed the gate in
    /// view `'v` — for a PEP that keeps its own record of a visible object
    /// (crate directory-admin's `Resolved`).
    #[must_use]
    pub fn into_parts(self) -> (Object, Dn, VisibilityProof<'v>) {
        let proof = VisibilityProof {
            guid: self.object.guid,
            _view: PhantomData,
        };
        (self.object, self.dn, proof)
    }
}

/// Proof that the object [`VisibilityProof::guid`] passed the visibility
/// gate in view `'v`. No public constructor: only
/// [`VisibleObject::into_parts`] makes one. Spec: docs/52 R10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibilityProof<'v> {
    guid: Guid,
    _view: PhantomData<fn(&'v ()) -> &'v ()>,
}

impl VisibilityProof<'_> {
    /// The objectGUID of the object that passed the gate.
    #[must_use]
    pub fn guid(&self) -> Guid {
        self.guid
    }
}

/// Absent, or present and not visible to the requester — one answer to the
/// client (module documentation). Spec: docs/11 §7, §8; docs/49 §9; A-55.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unseen {
    cause: UnseenCause,
}

/// What an [`Unseen`] was. **For the audit record only**: the client answer
/// must be the same for every cause (docs/11 §1b: the reason is internal,
/// for audit). Spec: docs/49 §10.1 (the audit keeps an invisible target);
/// ipc-audit `AdminRefusal::NotVisible` / `NotFound` (Q-340).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnseenCause {
    /// No live object of the naming context has this identity.
    Absent,
    /// The object exists; the PDP refused the rule's question with this
    /// reason, which depends on the object ([`hides`]).
    Hidden(ReasonCode),
}

impl Unseen {
    /// The cause, for the audit record only ([`UnseenCause`]).
    #[must_use]
    pub fn audit_cause(&self) -> UnseenCause {
        self.cause
    }
}

/// The gate's verdict on one object (module documentation).
/// Spec: docs/52 R10; docs/11 §7, §8; docs/49 §9.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub enum Visibility<'v> {
    /// The requester may see the object; `decision` is the PDP decision
    /// that made it visible (its obligations are the PEP's to honour where
    /// that decision authorises the operation).
    Visible {
        object: VisibleObject<'v>,
        decision: Decision,
    },
    /// Absent, or not visible — the same answer.
    NotFound(Unseen),
    /// The PDP refused the question for a reason that is not a verdict on
    /// the object ([`hides`] is false): the request itself is refused.
    Refused(Decision),
}

/// The view could not answer. Never carries a name or a value (docs/CLEAN-ROOM.md
/// §6; crate error.rs).
#[derive(Debug)]
pub enum GateFault {
    /// Reading the object failed (dirstore's error — the caller classifies
    /// integrity versus storage failures for its audit record).
    Store(dirstore::Error),
    /// The object's DN could not be computed (an inconsistent record, or a
    /// bound exceeded inside [`DirectoryView::dn_of`]).
    Name,
    /// A child's DN would exceed [`MAX_DN_DEPTH`] components.
    TooDeep,
}

/// `true` if a PDP denial for `reason` is a verdict on the object — the
/// global rules (which match the resource's DN), the tier invariant, the
/// object's ACL and the attribute class — so the object is answered as not
/// found. Every other reason (malformed request, layers 1-2, the subject's
/// tier, a PIP failure) refuses the request itself.
/// Spec: docs/11 §4 (layers 1-2 and the tier check precede the object);
/// docs/49 §9 (R49-13: "PDP Deny on an invisible target → noSuchObject";
/// `PipFailure` / `InvalidRequest` / `SubjectMismatch` → other);
/// docs/questions/Q-200 item 5.
#[must_use]
pub fn hides(reason: ReasonCode) -> bool {
    matches!(
        reason,
        ReasonCode::CoarseDeny(_)
            | ReasonCode::NoGrant
            | ReasonCode::TierViolation
            | ReasonCode::Acl
            | ReasonCode::NoSuchPath
            | ReasonCode::Sensitive
    )
}

/// The container whose `DirList` decides the visibility of the object `dn`
/// under [`VisibilityRule::ListParent`]: its parent (its DN without the leaf
/// RDN), or the object itself when it is the NC root.
/// Spec: [MS-ADTS] 3.1.1.4.3 (OP = O!parent), 5.1.3.3.6; pdp
/// `decide_visibility` (the NC root decides on itself).
fn list_target(dn: &Dn, is_nc_root: bool) -> Dn {
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

/// The visibility gate of one requester over one view (module
/// documentation). Spec: docs/52 R10.
pub struct VisibilityGate<'v, 'a> {
    view: &'v DirectoryView<'a>,
    policy: &'v PolicySnapshot,
    subject: Subject,
    context: Context,
    rule: VisibilityRule,
    /// `DirList` decisions per container DN (the directory's canonical DN).
    lists: BTreeMap<Dn, Decision>,
    /// Whole-object `DirRead` decisions per object DN.
    reads: BTreeMap<Dn, Decision>,
}

impl<'v, 'a> VisibilityGate<'v, 'a> {
    /// The gate of `subject` (built by the PEP from the verified identity
    /// only, docs/11 P3) in `context`, over `view` and the policy of the
    /// same version (docs/47 §8.1). Spec: docs/11 §1, §2, §6.
    #[must_use]
    pub fn new(
        view: &'v DirectoryView<'a>,
        policy: &'v PolicySnapshot,
        subject: Subject,
        context: Context,
        rule: VisibilityRule,
    ) -> VisibilityGate<'v, 'a> {
        VisibilityGate {
            view,
            policy,
            subject,
            context,
            rule,
            lists: BTreeMap::new(),
            reads: BTreeMap::new(),
        }
    }

    /// The rule this gate decides by.
    #[must_use]
    pub fn rule(&self) -> VisibilityRule {
        self.rule
    }

    /// One `decide` for the gate's subject and context.
    /// Spec: docs/11 §1, §4; docs/47 §8.1 (the view is the PIP).
    fn decide(&self, action: Action, dn: Dn, attr: Option<AttrId>) -> Decision {
        let request = AccessRequest {
            subject: self.subject.clone(),
            resource: Resource::DirObject { dn, attr },
            action,
            context: self.context.clone(),
        };
        decide(&request, self.policy, self.view)
    }

    /// `DirList` on the container `dn`, decided once and remembered
    /// (module documentation). Spec: [MS-ADTS] 3.1.1.4.3, 5.1.3.3.6; docs/11
    /// P1, P9.
    fn list_decision(&mut self, dn: &Dn) -> Decision {
        if let Some(known) = self.lists.get(dn) {
            return known.clone();
        }
        let decision = self.decide(Action::DirList, dn.clone(), None);
        self.lists.insert(dn.clone(), decision.clone());
        decision
    }

    /// Whole-object `DirRead` on `dn`, decided once and remembered.
    /// Spec: docs/51 §5.2 row 10; docs/11 P1, P9.
    fn read_decision(&mut self, dn: &Dn) -> Decision {
        if let Some(known) = self.reads.get(dn) {
            return known.clone();
        }
        let decision = self.decide(Action::DirRead, dn.clone(), None);
        self.reads.insert(dn.clone(), decision.clone());
        decision
    }

    /// The rule's decision on the object `dn` (module documentation): the
    /// parent's `DirList` (the object's own for the NC root); under
    /// [`VisibilityRule::ListAndRead`], when that allows, the object's
    /// whole-object `DirRead`. A denial of the first question is returned
    /// as it is — the second is not asked.
    fn rule_decision(&mut self, dn: &Dn, is_nc_root: bool) -> Decision {
        let listed = self.list_decision(&list_target(dn, is_nc_root));
        match self.rule {
            VisibilityRule::ListParent => listed,
            VisibilityRule::ListAndRead if listed.effect != Effect::Allow => listed,
            VisibilityRule::ListAndRead => self.read_decision(dn),
        }
    }

    /// The verdict for `object` (with its canonical `dn`) given the rule's
    /// decision. The only place a [`VisibleObject`] is built.
    fn verdict(object: Object, dn: Dn, decision: Decision) -> Visibility<'v> {
        if decision.effect == Effect::Allow {
            Visibility::Visible {
                object: VisibleObject {
                    object,
                    dn,
                    _view: PhantomData,
                },
                decision,
            }
        } else {
            Self::denied(decision)
        }
    }

    /// The verdict of a denial: never a [`VisibleObject`] ([`hides`]).
    fn denied(decision: Decision) -> Visibility<'v> {
        if hides(decision.reason) {
            Visibility::NotFound(Unseen {
                cause: UnseenCause::Hidden(decision.reason),
            })
        } else {
            Visibility::Refused(decision)
        }
    }

    /// The refusal of the request itself, decided **before any object is
    /// looked up**: the rule's decision on the root of the naming context
    /// (which the view always names, A-53), when the PDP denies it for a
    /// reason that is not a verdict on that object ([`hides`] is false).
    /// `None` otherwise — including a denial that hides the root, which the
    /// object's own verdict will report. Without this, a refusal that does
    /// not depend on the object would come only after the lookup, and an
    /// absent object (not found) would differ from a present one (refused).
    /// Spec: docs/questions/Q-200 item 5 (A-55); docs/49 §6.1 item 2, §9;
    /// docs/11 §4 (layers 1-2 precede the object).
    pub fn request_refusal(&mut self) -> Option<Decision> {
        let root = self.view.context().naming_context().dn().clone();
        let decision = self.rule_decision(&root, true);
        (decision.effect != Effect::Allow && !hides(decision.reason)).then_some(decision)
    }

    /// The verdict on the object `guid`: read it and its canonical DN from
    /// the view, then the rule's decision. No live object of the naming
    /// context with this GUID ⇒ [`Visibility::NotFound`], exactly as for a
    /// hidden one.
    /// Spec: docs/52 R10; docs/11 §7; docs/49 §6.1 item 2; docs/51 §5.2 row
    /// 10; docs/47 §8.2 (`dn_of`).
    pub fn visible(&mut self, guid: Guid) -> Result<Visibility<'v>, GateFault> {
        let Some(object) = self
            .view
            .snapshot()
            .get_object(guid)
            .map_err(GateFault::Store)?
        else {
            return Ok(absent());
        };
        let Some(dn) = self.view.dn_of(guid).map_err(|_| GateFault::Name)? else {
            return Ok(absent());
        };
        let decision = self.rule_decision(&dn, object.parent.is_none());
        Ok(Self::verdict(object, dn, decision))
    }

    /// The verdict on `guid` as a child of the visible container `parent`
    /// (the walk of a search). Its DN is its RDN followed by the parent's
    /// DN ([MS-ADTS] 3.1.1.1.4). An object that is not a live child of
    /// `parent` ⇒ [`Visibility::NotFound`].
    ///
    /// Under both rules the parent's `DirList` decision is taken **first**,
    /// so a child of a container the requester may not list is not even
    /// read; under [`VisibilityRule::ListAndRead`] the child's own `DirRead`
    /// follows, after it is read.
    /// Spec: [MS-ADTS] 5.1.3.3.6 ("all child objects of that container are
    /// visible to the user"), 3.1.1.1.4; docs/49 §6.1 item 3; docs/51 §5.2
    /// row 10.
    pub fn child(
        &mut self,
        parent: &VisibleObject<'v>,
        guid: Guid,
    ) -> Result<Visibility<'v>, GateFault> {
        let listed = self.list_decision(parent.dn());
        if listed.effect != Effect::Allow {
            // The object is not read.
            return Ok(Self::denied(listed));
        }
        let Some(object) = self
            .view
            .snapshot()
            .get_object(guid)
            .map_err(GateFault::Store)?
        else {
            return Ok(absent());
        };
        if object.parent != Some(parent.guid()) {
            return Ok(absent());
        }
        let component = self
            .view
            .rdn_component(&object)
            .map_err(|_| GateFault::Name)?;
        if parent.dn().rdns().len() >= MAX_DN_DEPTH {
            return Err(GateFault::TooDeep);
        }
        let mut rdns = Vec::with_capacity(parent.dn().rdns().len() + 1);
        rdns.push(component);
        rdns.extend(parent.dn().rdns().iter().cloned());
        let dn = Dn::new(rdns);
        let decision = match self.rule {
            VisibilityRule::ListParent => listed,
            VisibilityRule::ListAndRead => self.read_decision(&dn),
        };
        Ok(Self::verdict(object, dn, decision))
    }

    /// May the requester list the container `dn` — i.e. do its children
    /// pass the visibility rule's first question? For pruning a walk
    /// before reading any child; [`VisibilityGate::child`] decides again
    /// (from the same remembered decision) whatever the caller did.
    /// Spec: [MS-ADTS] 5.1.3.3.6; docs/49 §6.1 item 3.
    pub fn may_list(&mut self, dn: &Dn) -> bool {
        self.list_decision(dn).effect == Effect::Allow
    }

    /// May the requester read the attribute `attribute` (its
    /// schemaIDGUID) of the visible object `object`? Not remembered (the
    /// PEP asks each question at most once per object).
    /// Spec: [MS-ADTS] 3.1.1.4.3 ("RIGHT_DS_READ_PROPERTY on OA"),
    /// 3.1.1.4.4 (Sensitive — pdp layer 5); docs/49 §6.1 item 4.
    #[must_use]
    pub fn may_read(&self, object: &VisibleObject<'v>, attribute: Guid) -> bool {
        self.decide(
            Action::DirRead,
            object.dn().clone(),
            Some(AttrId(attribute)),
        )
        .effect
            == Effect::Allow
    }
}

/// The verdict on an identity no live object of the naming context has.
fn absent<'v>() -> Visibility<'v> {
    Visibility::NotFound(Unseen {
        cause: UnseenCause::Absent,
    })
}
