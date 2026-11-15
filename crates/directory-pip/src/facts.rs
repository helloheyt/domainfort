//! What the PIP will answer about a principal once an admin write is
//! committed — the reads an effect plan is built from (task MA3;
//! docs/research/r5-a-admin-model.md §3.3, §11 MA3).
//!
//! # The rule: the same functions that enforce
//!
//! r5-a §3.3: the effect closure of an operation is computed "by the same
//! functions that enforce (`expand_groups`, `tier_of`, policy resolution,
//! `decide`)"; a preview computed by separate code would be an instance of
//! class C14. So every fact here is one of the view's own functions:
//!
//! | fact | function (the one the KDC / PDP use) |
//! |---|---|
//! | groups | crate::groups `expand_with` — `expand` (R47-8) with an optional [`MemberChange`] on the reverse links it reads |
//! | subject tier | `subject_tier_in` — `Pip::tier_of` / `ClientAccount.tier` (R47-9), under the view's or a candidate tier map |
//! | object tier | `classified_tier_of` — `Pip::object_tier` before the A-36 default (R47-9), with the groups above |
//! | account state | `state_of` — the KDC's `AccountState` (R47-5..R47-7), of a stored or hypothetical record |
//!
//! The only "hypothesis" inputs are data the write itself determines: the
//! member set `apply` writes ([`MemberChange`]), the candidate tier map a
//! `ChangePolicy` writes (crate policy-store's one edit), and the record
//! `apply` writes (the caller passes it). Which principals to ask about is
//! [`DirectoryView::member_closure`] / [`DirectoryView::principals_under`]
//! — reads of the same graph (docs/questions/Q-984).
//!
//! These are authority reads (like the snapshot behind them): a PEP that
//! shows any of it to a requester passes every principal through its
//! visibility gate first (docs/52 R10, A-103; crates/directory-admin
//! `PlanNotVisible`).
//!
//! Spec: docs/research/r5-a-admin-model.md §3.3; docs/47 §4-§6, §8.2;
//! docs/11 §6; A-36; docs/questions/Q-874, Q-984.

use crate::error::Fault;
use crate::groups::{self, MemberChange};
use crate::record;
use crate::tier::TierMap;
use crate::view::DirectoryView;
use dirstore::Object;
use dtyp::{Guid, Sid};
use kdc::AccountState;
use pdp::{Dn, PipError, Tier};
use std::collections::{BTreeSet, VecDeque};

/// Most objects [`DirectoryView::principals_under`] reads (project choice:
/// the bound of the other bounded walks of this workspace).
const MAX_SUBTREE_STEPS: usize = 4096;

/// The kind of a security principal, from its most specific class.
/// Spec: docs/46 §4 (user, computer ⊂ user, group); docs/47 §1.3 step 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PrincipalKind {
    /// A user account.
    User,
    /// A computer account.
    Computer,
    /// A group.
    Group,
}

/// One principal as the PIP sees it (module docs).
/// Spec: docs/47 §5.3, §6.3; docs/research/r5-a-admin-model.md §3.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalFacts {
    /// The objectGUID.
    pub guid: Guid,
    /// The objectSid.
    pub sid: Sid,
    /// User, computer or group.
    pub kind: PrincipalKind,
    /// The sAMAccountName (the canonical ASCII name, P-6).
    pub name: String,
    /// The expansion: every security group it is a member of, directly or
    /// nested (R47-8).
    pub groups: BTreeSet<Sid>,
    /// The tier it gets as a Subject (R47-9; `Untiered` without one).
    pub subject_tier: Tier,
    /// Its explicit object tier for writes (`None`: unclassified — Tier0 for
    /// writes by A-36, yet needing no approver, P-22).
    pub object_tier: Option<Tier>,
}

impl DirectoryView<'_> {
    /// The facts of the principal `guid` — under `change` (the member set a
    /// write gives one group) and `tiers` (a candidate tier map) when given,
    /// else as the snapshot and the view's map stand. `Ok(None)` when no
    /// live user, computer or group has that objectGUID.
    ///
    /// # Errors
    /// `PipError` on an inconsistent record, a store failure, or an
    /// expansion beyond its bounds (`Unavailable`) — the caller refuses.
    ///
    /// Spec: module docs; docs/47 §5.3 (R47-8), §6.3 (R47-9), §8.2.
    pub fn principal_facts(
        &self,
        guid: Guid,
        change: Option<&MemberChange>,
        tiers: Option<&TierMap>,
    ) -> Result<Option<PrincipalFacts>, PipError> {
        Ok(self.facts(guid, change, tiers)?)
    }

    /// [`DirectoryView::principal_facts`] with internal faults.
    fn facts(
        &self,
        guid: Guid,
        change: Option<&MemberChange>,
        tiers: Option<&TierMap>,
    ) -> Result<Option<PrincipalFacts>, Fault> {
        let ids = self.ctx.ids;
        let Some(obj) = self.snapshot.get_object(guid)? else {
            return Ok(None);
        };
        let class = self.most_specific_class(&obj)?;
        let kind = if class == ids.user {
            PrincipalKind::User
        } else if class == ids.computer {
            PrincipalKind::Computer
        } else if class == ids.group {
            PrincipalKind::Group
        } else {
            return Ok(None);
        };
        // objectSid and sAMAccountName are musts of all three classes
        // (docs/46 §4.4).
        let sid = record::sid(&obj, ids.object_sid)?.ok_or(Fault::Unavailable)?;
        let name = record::text(&obj, ids.sam_account_name)?
            .ok_or(Fault::Unavailable)?
            .to_owned();
        let map = tiers.unwrap_or(self.tiers);
        let groups = groups::expand_with(self, &obj, change)?;
        let subject_tier = self.subject_tier_in(map, &sid, &groups)?;
        let dn = self
            .dn_of(guid)
            .map_err(|_| Fault::Unavailable)?
            .ok_or(Fault::Unavailable)?;
        let object_tier = self.classified_tier_of(map, &dn, &obj, Some(&groups))?;
        Ok(Some(PrincipalFacts {
            guid,
            sid,
            kind,
            name,
            groups,
            subject_tier,
            object_tier,
        }))
    }

    /// The principals whose expansion passes through one of `roots` — the
    /// roots and everything below them through the `member` links of
    /// security-enabled groups (crate::groups `member_closure`). `Ok(None)`
    /// when more than `limit` objects are found: the caller refuses.
    ///
    /// # Errors
    /// `PipError` on a store failure or an inconsistent record.
    ///
    /// Spec: docs/47 §5.3; docs/questions/Q-984.
    pub fn member_closure(
        &self,
        roots: &[Guid],
        limit: usize,
    ) -> Result<Option<BTreeSet<Guid>>, PipError> {
        Ok(groups::member_closure(self, roots, limit)?)
    }

    /// The live user, computer and group objects at or below the object the
    /// canonical DN `base` names (a tier-map subtree's base), breadth first
    /// through the child lists. `Ok(Some(empty))` when `base` names no
    /// object; `Ok(None)` when more than `limit` principals are found or
    /// more than [`MAX_SUBTREE_STEPS`] objects read — the caller refuses.
    ///
    /// # Errors
    /// `PipError` on a store failure or an inconsistent record.
    ///
    /// Spec: docs/47 §6.3 ("DN subtree → Tier"); pdp `Dn::is_within`;
    /// dirstore `Snapshot::children`; docs/questions/Q-984.
    pub fn principals_under(
        &self,
        base: &Dn,
        limit: usize,
    ) -> Result<Option<BTreeSet<Guid>>, PipError> {
        Ok(self.under(base, limit)?)
    }

    /// [`DirectoryView::principals_under`] with internal faults.
    fn under(&self, base: &Dn, limit: usize) -> Result<Option<BTreeSet<Guid>>, Fault> {
        let ids = self.ctx.ids;
        let root = match self.resolve(base) {
            Ok(obj) => obj.guid,
            Err(Fault::NotFound) => return Ok(Some(BTreeSet::new())),
            Err(fault) => return Err(fault),
        };
        let mut queue: VecDeque<Guid> = VecDeque::from([root]);
        let mut found = BTreeSet::new();
        let mut steps = 0usize;
        while let Some(guid) = queue.pop_front() {
            steps += 1;
            if steps > MAX_SUBTREE_STEPS {
                return Ok(None);
            }
            let Some(obj) = self.snapshot.get_object(guid)? else {
                continue;
            };
            let class = self.most_specific_class(&obj)?;
            if class == ids.user || class == ids.computer || class == ids.group {
                found.insert(guid);
                if found.len() > limit {
                    return Ok(None);
                }
            }
            let mut after = None;
            loop {
                let page = self.snapshot.children(Some(guid), after.as_ref(), 64)?;
                for child in page.children {
                    if queue.len() + steps > MAX_SUBTREE_STEPS {
                        return Ok(None);
                    }
                    queue.push_back(child);
                }
                match page.next {
                    Some(next) => after = Some(next),
                    None => break,
                }
            }
        }
        Ok(Some(found))
    }

    /// The KDC's account state of `obj` — a stored record, or (task MA3) the
    /// record an admin write is about to store: the same derivation the
    /// account source gives the KDC (`state_of`, R47-5..R47-7). `Ok(None)`
    /// when `obj` is not a user or computer.
    ///
    /// # Errors
    /// `PipError` on an inconsistent record.
    ///
    /// Spec: docs/47 §4 (R47-5, R47-6, R47-7); A-162 (`revoked_before`).
    pub fn account_state_of(&self, obj: &Object) -> Result<Option<AccountState>, PipError> {
        let Some(account) = self.account(obj).map_err(PipError::from)? else {
            return Ok(None);
        };
        Ok(Some(self.state_of(obj, &account)?))
    }
}
