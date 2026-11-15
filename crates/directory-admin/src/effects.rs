//! **Effect-plan builders** (task MA3; docs/research/r5-a-admin-model.md
//! §3.3, §11 MA3): the effect closure of an operation, as an
//! `ipc_dird_admin::EffectPlan`, built from the same evaluation that decides
//! the operation and read through the same functions that enforce it.
//!
//! # The class this closes (AGENTS.md §6.1): C46
//!
//! "The approved effect is smaller than the executed one": a decision and an
//! approval covered the request — "AddMember(H, G)" — while its effect
//! closure (forty members of H entering Tier 0) was neither shown nor bound
//! (PENDING-OWNER A-147; r5-a U4, U18). **The root change:** a planned
//! operation (`Operation::requires_plan`, docs/questions/Q-982) is decided
//! only together with its plan; the plan's digest is a field of the
//! operation the AP-REQs bind (crate ipc-dird-admin `Commit`); and the plan
//! is computed **here, from the `Handled` of the very `evaluate` that
//! decides the operation**, over directory-pip's enforcing functions — so it
//! is recomputed, never remembered, at every `Propose`, `Approve` and
//! execution, and a difference refuses (`PlanChanged`). There is no second
//! estimate to drift (C14).
//!
//! | effect | builder input | enforcing function |
//! |---|---|---|
//! | `MembershipDelta` | the member set the write gives the group (`WriteKind::SetMembers`), or the deleted group | directory-pip `expand_with` (= `Pip::expand_groups`, R47-8) under a `MemberChange` |
//! | `TierDelta` | the same, or a `ChangePolicy`'s candidate map (crate policy-store's one edit) | `subject_tier_in` (= `Pip::tier_of`), `classified_tier_of` (= `object_tier` before A-36's default) |
//! | `PolicyReference` | the groups gained or lost | the request's tier map and the policy principals — the same data `is_policy_named` reads |
//! | `TicketsRevoked` | the record the write stores | the KDC's `AccountState` (`usable_at`, `revokes`; directory-pip `state_of`, A-162) |
//! | `ProtectedDataLoss` | an administrator's password set of a user | — (a declared consequence outside the model, P-68: DPAPI secrets) |
//! | `KeyDestruction` | a `Delete` of a user / computer; a `RetireKvno` | the same predicate as the destroy decision after a `Delete` (crate::key_requests, A-105); the key operation itself |
//!
//! # Which principals
//!
//! A membership change can only change the expansion of principals that
//! reach the changed edge going up through security groups: the changed
//! member and everything below it through security groups
//! (directory-pip `member_closure`); a policy row, the principal of its SID
//! and its closure, or the principals under its subtree. Every candidate's
//! "before" and "after" come from the enforcing functions; only those whose
//! facts differ enter the plan (docs/questions/Q-984).
//!
//! # Visibility (docs/questions/Q-874 item 4, Q-983)
//!
//! The plan is computed only after the operation's own checks passed (the
//! PDP's Allow first — a refusal is the same uniform answer as before, A-26,
//! so a plan is never an oracle); then every principal it names must be
//! visible to the requester (and, at an `Approve` / `ShowRequest`, to that
//! approver) through the visibility gate, else `PlanNotVisible`: whoever
//! cannot see the results of an operation does not perform or approve it.
//! A key operation's plan names its key target, read after `PolicyAdmin` on
//! `keys` outside the gate (docs/questions/Q-486), and is not gated again.
//!
//! Spec: docs/research/r5-a-admin-model.md §3.3, §8.1 (U4, U17, U18), §8.3
//! (C46), §9, §10 (RS4, RS9); docs/questions/Q-874, Q-117 (A-36); docs/47
//! §4-§6; docs/51 §5.6; P-22; P-68; A-105; A-147; A-162.

use std::collections::{BTreeMap, BTreeSet};

use directory_pip::{MemberChange, PrincipalFacts, PrincipalKind, TierMap, Visibility};
use dirstore::{AttrId, AttrStamp, Attribute, NodeId, Object, StampedValue, Timestamp};
use dtyp::{Guid, Sid};
use ipc_audit::{AdminFailure, AdminRefusal};
use ipc_dird_admin::channel::MAX_PLAN_PRINCIPALS;
use ipc_dird_admin::{
    Effect, EffectPlan, PlanError, PlanPrincipal, PlanPrincipalKind, PlanTier, PolicyReferenceKind,
    RevocationKind,
};
use pdp::{Subject, Tier};
use policy_store::{edit_tier_map, DevelopmentPolicy, TierChange};

use crate::admin::{DirectoryAdmin, Plan, WriteKind, WritePlan};
use crate::audit::Stop;
use crate::checks::{malformed, Cx, KeyTargetRecord};
use crate::key_requests::KeyOperation;
use crate::operation::Operation;
use crate::random::RandomSource;
use crate::record;
use crate::time;

/// Most principals one plan's candidate walk may find: the plan's own bound
/// (crate ipc-dird-admin `MAX_PLAN_PRINCIPALS`). Beyond it ⇒ `PlanTooLarge`.
/// Spec: docs/questions/Q-981.
const PLAN_LIMIT: usize = MAX_PLAN_PRINCIPALS as usize;

/// A plan the PEP built: the plan and its digest.
/// Spec: docs/research/r5-a-admin-model.md §3.3 (`EffectPlan {…, digest}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BuiltPlan {
    pub(crate) plan: EffectPlan,
    pub(crate) digest: [u8; 32],
}

/// A plan error as the PEP reports it: beyond the bounds ⇒ `PlanTooLarge`
/// (the closure cannot be shown, so it is not performed); anything else is a
/// builder fault ⇒ `InternalFailure` (fail closed).
/// Spec: docs/questions/Q-981.
fn plan_stop(error: PlanError) -> Stop {
    match error {
        PlanError::TooLarge => Stop::Refused(AdminRefusal::PlanTooLarge),
        PlanError::Malformed => Stop::Failed(AdminFailure::InternalFailure),
    }
}

/// `pdp::Tier` of a Subject → its plan form.
fn subject_tier(tier: Tier) -> PlanTier {
    match tier {
        Tier::Tier0 => PlanTier::Tier0,
        Tier::Tier1 => PlanTier::Tier1,
        Tier::Tier2 => PlanTier::Tier2,
        Tier::Untiered => PlanTier::None,
    }
}

/// An explicit object tier (`None`: unclassified) → its plan form.
fn object_tier(tier: Option<Tier>) -> PlanTier {
    tier.map_or(PlanTier::None, subject_tier)
}

/// The plan identity of a principal's facts (SID, GUID, kind, name —
/// R5A-10).
fn identity(facts: &PrincipalFacts) -> PlanPrincipal {
    PlanPrincipal {
        sid: facts.sid,
        guid: facts.guid,
        kind: match facts.kind {
            PrincipalKind::User => PlanPrincipalKind::User,
            PrincipalKind::Computer => PlanPrincipalKind::Computer,
            PrincipalKind::Group => PlanPrincipalKind::Group,
        },
        name: facts.name.clone(),
    }
}

/// A tier change: the subject tier and the object tier, each before and
/// after.
type TierChangeKey = ((PlanTier, PlanTier), (PlanTier, PlanTier));

/// The effects being collected, grouped by their shared change.
#[derive(Default)]
struct Collector {
    principals: BTreeMap<Sid, PlanPrincipal>,
    membership: BTreeMap<(BTreeSet<Sid>, BTreeSet<Sid>), BTreeSet<Sid>>,
    tiers: BTreeMap<TierChangeKey, BTreeSet<Sid>>,
    references: BTreeMap<PolicyReferenceKind, BTreeSet<Sid>>,
    revoked: BTreeMap<RevocationKind, BTreeSet<Sid>>,
    data_loss: BTreeSet<Sid>,
    destroyed: BTreeMap<Option<u32>, BTreeSet<Sid>>,
}

impl Collector {
    /// Record what changes between `before` and `after` of one principal:
    /// its expansion and its tiers (both from the enforcing functions).
    fn compare(&mut self, before: &PrincipalFacts, after: &PrincipalFacts) {
        let gained: BTreeSet<Sid> = after.groups.difference(&before.groups).copied().collect();
        let lost: BTreeSet<Sid> = before.groups.difference(&after.groups).copied().collect();
        let subject = (
            subject_tier(before.subject_tier),
            subject_tier(after.subject_tier),
        );
        let object = (
            object_tier(before.object_tier),
            object_tier(after.object_tier),
        );
        let mut changed = false;
        if !gained.is_empty() || !lost.is_empty() {
            self.membership
                .entry((gained, lost))
                .or_default()
                .insert(before.sid);
            changed = true;
        }
        if subject.0 != subject.1 || object.0 != object.1 {
            self.tiers
                .entry((subject, object))
                .or_default()
                .insert(before.sid);
            changed = true;
        }
        if changed {
            self.principals.insert(before.sid, identity(before));
        }
    }

    /// Every group SID a membership delta names.
    fn changed_groups(&self) -> BTreeSet<Sid> {
        self.membership
            .keys()
            .flat_map(|(gained, lost)| gained.iter().chain(lost))
            .copied()
            .collect()
    }

    /// The plan.
    fn build(self) -> Result<BuiltPlan, Stop> {
        let mut effects = Vec::new();
        for ((gained, lost), principals) in self.membership {
            effects.push(Effect::MembershipDelta {
                gained,
                lost,
                principals,
            });
        }
        for ((subject, object), principals) in self.tiers {
            effects.push(Effect::TierDelta {
                subject,
                object,
                principals,
            });
        }
        for (reference, principals) in self.references {
            effects.push(Effect::PolicyReference {
                reference,
                principals,
            });
        }
        for (kind, principals) in self.revoked {
            effects.push(Effect::TicketsRevoked { kind, principals });
        }
        if !self.data_loss.is_empty() {
            effects.push(Effect::ProtectedDataLoss {
                principals: self.data_loss,
            });
        }
        for (kvno, principals) in self.destroyed {
            effects.push(Effect::KeyDestruction { kvno, principals });
        }
        let plan = EffectPlan::new(self.principals.into_values(), effects).map_err(plan_stop)?;
        let digest = plan.digest().map_err(plan_stop)?;
        Ok(BuiltPlan { plan, digest })
    }
}

/// `obj` with the single value `value` in `attr` — the record a write of
/// that value stores (the values `apply` writes; stamps play no part in an
/// account's state). The attributes stay in ascending id order, the
/// record's canonical order (`Object::attribute` searches it).
/// Spec: docs/32 §2 (the record); crate::apply (the values written).
fn with_value(obj: &Object, attr: AttrId, value: Vec<u8>) -> Object {
    let mut after = obj.clone();
    let stamped = StampedValue {
        value,
        stamp: AttrStamp {
            version: 0,
            wall_clock: Timestamp(0),
            origin_node: NodeId([0; 16]),
            origin_seq: 0,
        },
    };
    match after.attributes.binary_search_by_key(&attr, |a| a.id) {
        Ok(index) => {
            if let Some(attribute) = after.attributes.get_mut(index) {
                attribute.values = vec![stamped];
            }
        }
        Err(index) => after.attributes.insert(
            index,
            Attribute {
                id: attr,
                values: vec![stamped],
            },
        ),
    }
    after
}

impl<R: RandomSource> DirectoryAdmin<R> {
    /// The plan identity of the account record `obj` (`guid`, `class`): a
    /// user or computer read by the operation's own checks.
    fn account_identity(
        &self,
        cx: &Cx<'_, '_, '_>,
        guid: Guid,
        obj: &Object,
    ) -> Result<PlanPrincipal, Stop> {
        let integrity = Stop::Failed(AdminFailure::IntegrityFailure);
        let class = cx.class_of(obj)?;
        let kind = if class == self.ids.computer.id {
            PlanPrincipalKind::Computer
        } else if class == self.ids.user.id {
            PlanPrincipalKind::User
        } else if class == self.ids.group.id {
            PlanPrincipalKind::Group
        } else {
            return Err(integrity);
        };
        Ok(PlanPrincipal {
            sid: record::sid(obj, self.ids.object_sid)
                .map_err(malformed)?
                .ok_or(integrity)?,
            guid,
            kind,
            name: record::text(obj, self.ids.sam_account_name)
                .map_err(malformed)?
                .ok_or(integrity)?
                .to_owned(),
        })
    }

    /// The effect plan of a directory operation, from the `Plan` its own
    /// checks produced (module documentation). An operation that requires
    /// no plan has the empty one.
    /// Spec: docs/research/r5-a-admin-model.md §3.3, §8.2; docs/questions/
    /// Q-982.
    pub(crate) fn directory_effects(
        &self,
        cx: &Cx<'_, '_, '_>,
        operation: &Operation,
        plan: &Plan,
    ) -> Result<BuiltPlan, Stop> {
        let Plan::Write(write) = plan else {
            return Collector::default().build();
        };
        match (&write.kind, operation) {
            (
                WriteKind::SetMembers { group, members, .. },
                Operation::AddMember(m) | Operation::RemoveMember(m),
            ) => self.membership_effects(
                cx,
                &MemberChange::set(*group, members.iter().copied()),
                &[m.member],
                Collector::default(),
            ),
            (WriteKind::Delete { target }, Operation::Delete { .. }) => {
                self.delete_effects(cx, *target, write)
            }
            (
                WriteKind::SetUac { .. }
                | WriteKind::SetAccountExpires { .. }
                | WriteKind::PasswordSet { .. },
                Operation::SetEnabled(_)
                | Operation::SetAccountExpires(_)
                | Operation::BeginPasswordSet { .. },
            ) => self.account_effects(cx, write),
            _ => Collector::default().build(),
        }
    }

    /// `MembershipDelta`, `TierDelta` and `PolicyReference` of a change of
    /// one group's members (module documentation): every principal whose
    /// expansion passes through a root, before and under `change`.
    /// Spec: docs/47 §5.3, §6.3; r5-a §3.3; docs/questions/Q-984.
    fn membership_effects(
        &self,
        cx: &Cx<'_, '_, '_>,
        change: &MemberChange,
        roots: &[Guid],
        mut collector: Collector,
    ) -> Result<BuiltPlan, Stop> {
        let candidates = cx
            .member_closure(roots, PLAN_LIMIT)?
            .ok_or(Stop::Refused(AdminRefusal::PlanTooLarge))?;
        for guid in candidates {
            let before = cx.principal_facts(guid, None, None)?;
            let after = cx.principal_facts(guid, Some(change), None)?;
            if let (Some(before), Some(after)) = (before, after) {
                collector.compare(&before, &after);
            }
        }
        self.policy_references(cx, &mut collector)?;
        collector.build()
    }

    /// `PolicyReference` for every group a membership delta names that the
    /// policy names: a tier-map row of its SID, or a policy principal (the
    /// bootstrap group) — the data `Cx::is_policy_named` reads.
    /// Spec: r5-a §3.3 (`PolicyReference`), §8.2; docs/47 §6.3; A-39 / A-44.
    fn policy_references(
        &self,
        cx: &Cx<'_, '_, '_>,
        collector: &mut Collector,
    ) -> Result<(), Stop> {
        let tiers = cx.tier_map();
        for sid in collector.changed_groups() {
            if let Some((_, tier)) = tiers.principals().find(|(s, _)| **s == sid) {
                collector
                    .references
                    .entry(PolicyReferenceKind::TierMap(subject_tier(tier)))
                    .or_default()
                    .insert(sid);
            }
            if self.config.protected().policy_principals.contains(&sid) {
                collector
                    .references
                    .entry(PolicyReferenceKind::PolicyPrincipal)
                    .or_default()
                    .insert(sid);
            }
            // Every group a delta names is named in the plan (R5A-10).
            self.name_group(cx, &sid, collector)?;
        }
        Ok(())
    }

    /// Add the group of `sid` to the plan's principals (its identity read
    /// through the enforcing facts).
    fn name_group(
        &self,
        cx: &Cx<'_, '_, '_>,
        sid: &Sid,
        collector: &mut Collector,
    ) -> Result<(), Stop> {
        if collector.principals.contains_key(sid) {
            return Ok(());
        }
        let guid = cx
            .guid_of_sid(sid)?
            .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?;
        let facts = cx
            .principal_facts(guid, None, None)?
            .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?;
        collector.principals.insert(*sid, identity(&facts));
        Ok(())
    }

    /// The plan of a `Delete`: a group's members lose it (and what they
    /// reached only through it); an account's tickets are revoked (it can no
    /// longer be used) and its key sets destroyed by dird's destroy decision
    /// (A-105); an empty container has no effect beyond itself.
    /// Spec: docs/51 §5.2 row 9, §6, §9; docs/46 §8.4; A-105; r5-a §8.2.
    fn delete_effects(
        &self,
        cx: &Cx<'_, '_, '_>,
        target: Guid,
        write: &WritePlan,
    ) -> Result<BuiltPlan, Stop> {
        let Some((_, obj)) = write.seen.iter().find(|(g, _)| *g == target) else {
            return Err(Stop::Failed(AdminFailure::InternalFailure));
        };
        let class = cx.class_of(obj)?;
        let mut collector = Collector::default();
        if class == self.ids.group.id {
            let members = record::refs(obj, self.ids.member).map_err(malformed)?;
            return self.membership_effects(
                cx,
                &MemberChange::deleted(target),
                &members,
                collector,
            );
        }
        if cx.is_account(class) {
            let identity = self.account_identity(cx, target, obj)?;
            let usable = cx
                .account_state_of(obj)?
                .is_some_and(|state| state.usable_at(&cx.now));
            if usable {
                collector
                    .revoked
                    .entry(RevocationKind::AccountUnusable)
                    .or_default()
                    .insert(identity.sid);
            }
            // The destroy decision dird registers after a committed `Delete`
            // of a user or computer (crate::key_requests, A-105).
            collector
                .destroyed
                .entry(None)
                .or_default()
                .insert(identity.sid);
            collector.principals.insert(identity.sid, identity);
        }
        collector.build()
    }

    /// The plan of an account write — `SetEnabled`, `SetAccountExpires`,
    /// `BeginPasswordSet`: the KDC's account state of the record before and
    /// of the record the write stores.
    /// Spec: docs/47 §4 (R47-5..R47-7); A-162; D53; P-68; r5-a §3.3, §8.2.
    fn account_effects(&self, cx: &Cx<'_, '_, '_>, write: &WritePlan) -> Result<BuiltPlan, Stop> {
        let internal = Stop::Failed(AdminFailure::InternalFailure);
        let (target, after_value) = match &write.kind {
            WriteKind::SetUac { target, uac } => (
                *target,
                (self.ids.user_account_control, record::encode_flags(*uac)),
            ),
            WriteKind::SetAccountExpires { target, value } => (
                *target,
                (self.ids.account_expires, record::encode_int64(*value)),
            ),
            WriteKind::PasswordSet { target, .. } => {
                let filetime = time::filetime(&cx.now).ok_or(internal)?;
                (
                    *target,
                    (self.ids.pwd_last_set, record::encode_int64(filetime)),
                )
            }
            _ => return Err(internal),
        };
        let Some((_, obj)) = write.seen.iter().find(|(g, _)| *g == target) else {
            return Err(internal);
        };
        let after = with_value(obj, after_value.0, after_value.1);
        let (Some(before_state), Some(after_state)) =
            (cx.account_state_of(obj)?, cx.account_state_of(&after)?)
        else {
            return Err(internal);
        };
        let identity = self.account_identity(cx, target, obj)?;
        let mut collector = Collector::default();
        let now = cx.now;
        if before_state.usable_at(&now) && !after_state.usable_at(&now) {
            collector
                .revoked
                .entry(RevocationKind::AccountUnusable)
                .or_default()
                .insert(identity.sid);
        }
        if after_state.revokes(&now) && !before_state.revokes(&now) {
            collector
                .revoked
                .entry(RevocationKind::PasswordSet)
                .or_default()
                .insert(identity.sid);
        }
        // An administrator's password set of a user: the user's secrets
        // protected under the old password are lost (P-68) — outside the
        // model, declared.
        if matches!(write.kind, WriteKind::PasswordSet { .. })
            && identity.kind == PlanPrincipalKind::User
        {
            collector.data_loss.insert(identity.sid);
        }
        if !collector.revoked.is_empty() || !collector.data_loss.is_empty() {
            collector.principals.insert(identity.sid, identity);
        }
        collector.build()
    }

    /// The plan of a `ChangePolicy`: everyone whose subject or object tier
    /// the candidate map changes — the candidate built by crate policy-store's
    /// one tier-map edit of the loaded policy (the edit `policy.next` is
    /// written with), read through the PIP's tier functions under it.
    /// Spec: docs/51 §5.10; docs/47 §6.3 (R47-9); r5-a §8.2 ("`ChangePolicy`
    /// ⇒ everyone whose tier changes"); docs/questions/Q-984.
    pub(crate) fn policy_effects(
        &self,
        cx: &Cx<'_, '_, '_>,
        installed: &DevelopmentPolicy,
        changes: &[TierChange],
    ) -> Result<BuiltPlan, Stop> {
        let (next, _) = edit_tier_map(installed, changes)
            .map_err(|_| Stop::Refused(AdminRefusal::ValueInvalid))?;
        let candidate = TierMap::new(next.principals.clone(), next.subtrees.clone())
            .map_err(|_| Stop::Refused(AdminRefusal::ValueInvalid))?;
        let mut candidates: BTreeSet<Guid> = BTreeSet::new();
        for change in changes {
            let found = match change {
                TierChange::AddPrincipal(sid, _) | TierChange::RemovePrincipal(sid) => {
                    match cx.guid_of_sid(sid)? {
                        Some(guid) => cx.member_closure(&[guid], PLAN_LIMIT)?,
                        None => Some(BTreeSet::new()),
                    }
                }
                TierChange::AddSubtree(dn, _) | TierChange::RemoveSubtree(dn) => {
                    cx.principals_under(dn, PLAN_LIMIT)?
                }
            };
            candidates.extend(found.ok_or(Stop::Refused(AdminRefusal::PlanTooLarge))?);
            if candidates.len() > PLAN_LIMIT {
                return Err(Stop::Refused(AdminRefusal::PlanTooLarge));
            }
        }
        let mut collector = Collector::default();
        for guid in candidates {
            let before = cx.principal_facts(guid, None, None)?;
            let after = cx.principal_facts(guid, None, Some(&candidate))?;
            if let (Some(before), Some(after)) = (before, after) {
                collector.compare(&before, &after);
            }
        }
        collector.build()
    }

    /// The plan of a key operation: a `RetireKvno` destroys that key version
    /// of its key set; a rotation keeps every key version (no effect beyond
    /// its target — the empty plan).
    /// Spec: docs/51 §6; docs/10 §7; docs/33 §5; r5-a §3.3 (`KeyDestruction`).
    pub(crate) fn key_effects(
        &self,
        cx: &Cx<'_, '_, '_>,
        operation: &KeyOperation,
        target: &KeyTargetRecord,
    ) -> Result<BuiltPlan, Stop> {
        let mut collector = Collector::default();
        if let KeyOperation::RetireKvno { kvno, .. } = operation {
            let identity = self.account_identity(cx, target.guid, &target.obj)?;
            collector
                .destroyed
                .entry(Some(*kvno))
                .or_default()
                .insert(identity.sid);
            collector.principals.insert(identity.sid, identity);
        }
        collector.build()
    }

    /// Every principal `plan` names must be visible to `subject` through the
    /// visibility gate (module documentation) — else `PlanNotVisible`.
    /// Spec: docs/questions/Q-874 item 4, Q-983; docs/52 R10; A-55.
    pub(crate) fn plan_visible(
        &self,
        cx: &Cx<'_, '_, '_>,
        subject: &Subject,
        plan: &EffectPlan,
    ) -> Result<(), Stop> {
        let mut gate = cx.gate(subject);
        for principal in plan.principals() {
            match gate.visible(principal.guid) {
                Ok(Visibility::Visible { .. }) => {}
                Ok(Visibility::NotFound(_) | Visibility::Refused(_)) => {
                    return Err(Stop::Refused(AdminRefusal::PlanNotVisible))
                }
                Err(_) => return Err(Stop::Failed(AdminFailure::StoreFailure)),
            }
        }
        Ok(())
    }
}
