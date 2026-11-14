//! The store-wide rules of a `member` link — what the object being written
//! cannot tell alone: which objects are protected (structural), the
//! membership rule of the group's type, the cycle refusal and the two bounds
//! of group expansion (nesting depth and closure size).
//!
//! Every function here reads through [`StoreRead`] — a committed snapshot
//! (the online PEP's `prepare`) or the write transaction itself, its own
//! earlier writes included (`provision domain`, and the online `apply`) —
//! so both write paths run exactly the same walks (docs/52 R13).
//!
//! The walks were moved here unchanged from crate::checks (tasks A3, F5;
//! docs/questions/Q-356 items 4-5, Q-357 item 8, Q-416); only the reader
//! and the error type are generic now.
//!
//! Spec: docs/47 §5.3 items 1, 3, 4 (R47-8); docs/51 §5.2 rows 5, 6, 8, 9,
//! §11; [MS-SAMR] v20260427 2.2.1.14, 3.1.1.6 items 14, 20, 22, 3.1.1.8.9
//! items 2-4; crate directory-pip `MAX_NESTING_DEPTH`,
//! `MAX_EXPANDED_GROUPS`, `groups::expand`; A-79; A-89; A-95;
//! docs/questions/Q-356, Q-416.

use std::collections::{BTreeMap, BTreeSet};

use ad_schema::flags::group_type::{
    GROUP_TYPE_ACCOUNT_GROUP, GROUP_TYPE_RESOURCE_GROUP, GROUP_TYPE_SECURITY_ENABLED,
    GROUP_TYPE_UNIVERSAL_GROUP,
};
use ad_schema::flags::user_account_control::ADS_UF_SERVER_TRUST_ACCOUNT;
use directory_pip::{MAX_EXPANDED_GROUPS, MAX_NESTING_DEPTH};
use dirstore::{ClassId, Object, Schema};
use dtyp::Guid;

use super::{Fault, StoreRead};
use crate::ids::Ids;
use crate::record;

/// DOMAIN_USER_RID_KRBTGT. Spec: [MS-SAMR] 2.2.1.14 (0x000001F6).
pub(crate) const DOMAIN_USER_RID_KRBTGT: u32 = 0x0000_01F6;

/// Most references one walk over the membership graph may follow — the
/// self-lockout count, the cycle check, the nesting-depth check and the
/// closure-size check alike. Every reference followed (a tier-map root, a
/// `member` value, a memberOf back link) counts once, also when it leads to
/// an object already seen, so the bound caps the work as well as the
/// objects read. Project choice (AGENTS.md §6); a walk that exceeds it
/// refuses the operation (docs/questions/Q-357 item 8; Q-356 items 4-5;
/// Q-416).
pub(crate) const MAX_WALK_STEPS: usize = 16_384;

/// Why a membership walk stopped before an answer: the store failed, or
/// the walk must refuse (a chain already too deep, a cycle, or the step
/// bound exceeded — fail closed).
enum Walked {
    Refuse,
    Fault(Fault),
}

impl From<Fault> for Walked {
    fn from(fault: Fault) -> Walked {
        Walked::Fault(fault)
    }
}

/// The state of one nesting-depth check: the steps taken, the memoised
/// heights below and above, the objects on the current path, and the
/// objects met below that expansion does not enter (accounts, groups that
/// are not security-enabled) — starts the closure-size check reuses.
#[derive(Default)]
struct DepthWalk {
    steps: usize,
    below: BTreeMap<Guid, usize>,
    above: BTreeMap<Guid, usize>,
    path: BTreeSet<Guid>,
    leaves: BTreeSet<Guid>,
}

impl DepthWalk {
    /// Count one reference followed; over [`MAX_WALK_STEPS`] ⇒ refuse.
    fn step(&mut self) -> Result<(), Walked> {
        self.steps += 1;
        if self.steps > MAX_WALK_STEPS {
            return Err(Walked::Refuse);
        }
        Ok(())
    }
}

/// The state of one closure-size check: its own steps (the same bound,
/// [`MAX_WALK_STEPS`]) and the objects already classified as
/// security-enabled groups (`true`) or not (`false`).
/// Spec: as [`Graph::closure_fits`].
#[derive(Default)]
struct ClosureWalk {
    steps: usize,
    security: BTreeMap<Guid, bool>,
}

impl ClosureWalk {
    /// Count one reference followed; over [`MAX_WALK_STEPS`] ⇒ refuse.
    fn step(&mut self) -> Result<(), Walked> {
        self.steps += 1;
        if self.steps > MAX_WALK_STEPS {
            return Err(Walked::Refuse);
        }
        Ok(())
    }
}

/// One end of a `member` link: the object's GUID and its record (for a
/// group being created, the record it will have).
#[derive(Clone, Copy)]
pub(crate) struct End<'e> {
    pub(crate) guid: Guid,
    pub(crate) obj: &'e Object,
}

/// The rules of this module over one reader: the schema identifiers, the
/// schema (the most specific class of a record), the protected service
/// objects, and the store.
pub(crate) struct Graph<'g, R: ?Sized> {
    pub(crate) ids: &'g Ids,
    pub(crate) schema: &'g Schema,
    pub(crate) service_objects: &'g BTreeSet<Guid>,
    pub(crate) store: &'g R,
}

impl<R: StoreRead + ?Sized> Graph<'_, R> {
    /// The most specific class of a record. Spec: docs/46 §8.3 item 1;
    /// [MS-ADTS] 3.1.1.2.4.3 (as cited there).
    pub(crate) fn class_of(&self, obj: &Object) -> Result<ClassId, Fault> {
        self.schema
            .most_specific_class(&obj.classes)
            .ok_or(Fault::Integrity)
    }

    /// `true` if `class` is user or derived from it (user, computer).
    /// Spec: [MS-SAMR] 3.1.1.8.9 items 2.2.1, 4.1 ("a user object (or an
    /// object derived from user)"); docs/46 §4.2 (computer ⊂ user).
    pub(crate) fn is_account(&self, class: ClassId) -> bool {
        class == self.ids.user.id || class == self.ids.computer.id
    }

    /// `true` if the object `guid` (record `obj`, most specific class
    /// `class`) is structural — never deleted, never changed by any write
    /// path, never a member: the krbtgt account (RID 502), a DC account
    /// (userAccountControl ST), a service object, the NC root.
    /// Spec: docs/51 §5.2 rows 5, 6, 9, §4.3 step 5; [MS-SAMR] 3.1.1.6 items
    /// 14, 22; A-18, A-19, A-35; docs/47 §6.3 (ST ⇒ the DC);
    /// docs/questions/Q-356 item 2.
    pub(crate) fn is_structural(
        &self,
        guid: Guid,
        obj: &Object,
        class: ClassId,
    ) -> Result<bool, Fault> {
        if obj.parent.is_none() || class == self.ids.domain_dns.id {
            return Ok(true);
        }
        if self.service_objects.contains(&guid) {
            return Ok(true);
        }
        if let Some(sid) = record::sid(obj, self.ids.object_sid).map_err(|_| Fault::Integrity)? {
            if sid.sub_authority().last() == Some(&DOMAIN_USER_RID_KRBTGT) {
                return Ok(true);
            }
        }
        if self.is_account(class) {
            let uac =
                record::flags(obj, self.ids.user_account_control).map_err(|_| Fault::Integrity)?;
            if uac.is_some_and(|u| u & ADS_UF_SERVER_TRUST_ACCOUNT != 0) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The membership rule of a group of type `group_type` for a member
    /// whose record is `member` and most specific class `member_class`.
    ///
    /// Read from [MS-SAMR] 3.1.1.8.9 (native mode — phase 1 has no mixed
    /// mode) and docs/51 §11 ("ACCOUNT: users + ACCOUNT; RESOURCE: +
    /// RESOURCE; UNIVERSAL: users + ACCOUNT/UNIVERSAL"):
    /// - ACCOUNT scope: an account, or a group of ACCOUNT scope — security
    ///   enabled when the group is (item 2.2: "a group account whose
    ///   groupType is GROUP_TYPE_SECURITY_ACCOUNT");
    /// - RESOURCE scope: an account, or a group of ACCOUNT or RESOURCE scope
    ///   — security enabled when the group is (items 3.1, 3.2);
    /// - UNIVERSAL scope: an account, or a group whose groupType contains
    ///   ACCOUNT or UNIVERSAL (item 4).
    ///
    /// The text constrains only security-enabled ACCOUNT / RESOURCE groups;
    /// docs/51 §11 applies the scope rule to their distribution counterparts
    /// too (stricter; docs/questions/Q-356 item 1). Anything that is neither
    /// an account nor a group is refused.
    pub(crate) fn member_allowed(
        &self,
        group_type: u32,
        member: &Object,
        member_class: ClassId,
    ) -> Result<bool, Fault> {
        if self.is_account(member_class) {
            return Ok(true);
        }
        if member_class != self.ids.group.id {
            return Ok(false);
        }
        let member_type = record::flags(member, self.ids.group_type)
            .map_err(|_| Fault::Integrity)?
            .ok_or(Fault::Integrity)?;
        let has = |value: u32, bit: u32| value & bit != 0;
        let security_ok = !has(group_type, GROUP_TYPE_SECURITY_ENABLED)
            || has(member_type, GROUP_TYPE_SECURITY_ENABLED);
        Ok(if has(group_type, GROUP_TYPE_ACCOUNT_GROUP) {
            security_ok && has(member_type, GROUP_TYPE_ACCOUNT_GROUP)
        } else if has(group_type, GROUP_TYPE_RESOURCE_GROUP) {
            security_ok
                && (has(member_type, GROUP_TYPE_ACCOUNT_GROUP)
                    || has(member_type, GROUP_TYPE_RESOURCE_GROUP))
        } else if has(group_type, GROUP_TYPE_UNIVERSAL_GROUP) {
            has(member_type, GROUP_TYPE_ACCOUNT_GROUP)
                || has(member_type, GROUP_TYPE_UNIVERSAL_GROUP)
        } else {
            // A groupType outside the six phase-1 values cannot be stored
            // (docs/46 §8.2); refuse.
            false
        })
    }

    /// `true` if adding `member` to `group` closes a cycle: `member` is
    /// `group`, or `group` is reachable from `member` through `member`
    /// links (any group type — a cycle through distribution groups is a
    /// cycle too). The walk is bounded — at most `MAX_EXPANDED_GROUPS`
    /// groups expanded and [`MAX_WALK_STEPS`] references followed; a walk
    /// that exceeds either is treated as a cycle (fail closed). Accounts
    /// below are read (to learn they are not groups) but do not count
    /// toward the group bound. A group being created is reachable from
    /// nothing (no record references it yet).
    /// Spec: docs/47 §5.3 items 3-4 ("the management plane refuses a
    /// `member` write that closes a cycle"); docs/51 §5.2 row 8, §11; A-79;
    /// docs/questions/Q-356 item 4.
    pub(crate) fn closes_cycle(&self, group: Guid, member: Guid) -> Result<bool, Fault> {
        let mut expanded = BTreeSet::new();
        let mut steps = 0usize;
        let mut stack = vec![member];
        while let Some(current) = stack.pop() {
            if current == group {
                return Ok(true);
            }
            if expanded.contains(&current) {
                continue;
            }
            let Some(obj) = self.store.object(current).map_err(Fault::Store)? else {
                continue;
            };
            if self.class_of(&obj)? != self.ids.group.id {
                continue;
            }
            expanded.insert(current);
            if expanded.len() > MAX_EXPANDED_GROUPS {
                return Ok(true);
            }
            for next in record::refs(&obj, self.ids.member).map_err(|_| Fault::Integrity)? {
                steps += 1;
                if steps > MAX_WALK_STEPS {
                    return Ok(true);
                }
                stack.push(next);
            }
        }
        Ok(false)
    }

    /// `true` if `obj` is a group whose groupType has
    /// GROUP_TYPE_SECURITY_ENABLED — the only groups group expansion enters.
    /// Spec: docs/47 §5.3 item 1; crate directory-pip `is_security_group`
    /// ([MS-ADTS] 2.2.12, [MS-DRSR] 4.1.8.2.6 as cited there).
    fn is_security_group(&self, obj: &Object) -> Result<bool, Fault> {
        if self.class_of(obj)? != self.ids.group.id {
            return Ok(false);
        }
        let group_type = record::flags(obj, self.ids.group_type)
            .map_err(|_| Fault::Integrity)?
            .ok_or(Fault::Integrity)?;
        Ok(group_type & GROUP_TYPE_SECURITY_ENABLED != 0)
    }

    /// `true` if adding `member` to `group` keeps every closure that
    /// directory-pip's group expansion computes within both of its bounds:
    /// no nesting chain deeper than `MAX_NESTING_DEPTH` (16 levels —
    /// [`Graph::nesting_walk`]) and no closure of more than
    /// `MAX_EXPANDED_GROUPS` (1024 groups — [`Graph::closure_fits`]). Beyond
    /// either, expansion fails (docs/47 §5.3 item 3: exceeding a bound ⇒
    /// `Err`, never a partial set) and the affected account can no longer
    /// log in; the write is refused instead. A link into a group that is not
    /// security-enabled is never climbed by expansion, so it changes no
    /// closure and is allowed.
    /// Spec: docs/47 §5.3 items 1, 3 (R47-8); crate directory-pip
    /// `MAX_NESTING_DEPTH`, `MAX_EXPANDED_GROUPS`, `groups::expand`; docs/51
    /// §11; docs/questions/Q-356 item 5 (A-89), Q-416.
    pub(crate) fn expansion_allowed(&self, group: End<'_>, member: End<'_>) -> Result<bool, Fault> {
        if !self.is_security_group(group.obj)? {
            return Ok(true);
        }
        let Some(depth) = self.nesting_walk(group, member)? else {
            return Ok(false);
        };
        self.closure_fits(&depth, group.guid, member)
    }

    /// The nesting-depth check of adding `member` to the security-enabled
    /// `group`: the finished walk when every nesting chain stays within the
    /// depth group expansion honours, `None` when the link must be refused.
    ///
    /// The bound is directory-pip's: `MAX_NESTING_DEPTH` = 16, "most levels
    /// of group nesting on any path from the start: a direct membership is
    /// level 1"; its expansion (`groups::expand`, `Walk::visit`) climbs from
    /// any start object through security-enabled groups only and fails —
    /// the account cannot log in, the PIP denies — when a level would exceed
    /// it (docs/47 §5.3 item 3, R47-8: `MAX_NESTING_DEPTH = 16`, exceeding it
    /// ⇒ `Err`, never a partial set).
    ///
    /// Every chain the new link adds runs from some start up to `member`,
    /// over the link, and on above `group`; its length is
    /// `below(member) + 1 + above(group)` levels, where `below(x)` is the
    /// longest climb from any start up to `x` (0 unless `x` is a
    /// security-enabled group — expansion enters nothing else) and
    /// `above(g)` the longest climb above `g` through security-enabled
    /// groups. The walks share [`MAX_WALK_STEPS`]; exceeding it, meeting a
    /// cycle, or reaching a level that alone exceeds the bound refuses (fail
    /// closed). The finished walk holds what the closure-size check reuses:
    /// `above` = `group` and every security-enabled group above it, `below`
    /// = `member` (when security-enabled) and every security-enabled group
    /// below it, `leaves` = the other objects below.
    ///
    /// Spec: docs/47 §5.3 items 1, 3 (R47-8); crate directory-pip
    /// `MAX_NESTING_DEPTH` and `groups::expand`; docs/51 §11 (membership
    /// rules refused at the write); docs/questions/Q-356 item 5.
    fn nesting_walk(&self, group: End<'_>, member: End<'_>) -> Result<Option<DepthWalk>, Fault> {
        let mut walk = DepthWalk::default();
        let below = match self.levels_below(&mut walk, member.guid, member.obj, 0) {
            Ok(levels) => levels,
            Err(Walked::Refuse) => return Ok(None),
            Err(Walked::Fault(fault)) => return Err(fault),
        };
        walk.path.clear();
        let above = match self.levels_above(&mut walk, group.guid, 0) {
            Ok(levels) => levels,
            Err(Walked::Refuse) => return Ok(None),
            Err(Walked::Fault(fault)) => return Err(fault),
        };
        Ok((below + 1 + above <= MAX_NESTING_DEPTH).then_some(walk))
    }

    /// `true` if, after `group ∋ member`, no closure group expansion computes
    /// holds more than `MAX_EXPANDED_GROUPS` groups.
    ///
    /// The bound is directory-pip's: `MAX_EXPANDED_GROUPS` = 1024, "most
    /// groups one expansion may return"; its expansion climbs from a start
    /// through the memberOf back links into security-enabled groups only,
    /// does not count the start, and fails on the 1025th group (docs/47 §5.3
    /// items 1, 3: exceeding ⇒ `Err`).
    ///
    /// The link changes the closure of exactly the starts whose climb
    /// reaches `member`: `member` itself, and — when `member` is a
    /// security-enabled group — every object below it through
    /// security-enabled groups (the depth walk's `below` and `leaves`). For
    /// each of them the new closure is its old one ∪ `U`, where `U` =
    /// `group` and every security-enabled group above it (the depth walk's
    /// `above`). Every start is checked, a group too — expansion may start
    /// anywhere, as the depth check reads "from any start". Measured as:
    ///
    /// 1. `member`'s closure: `U` ∪ the groups above `member` (a climb that
    ///    does not enter `U`, which is closed upward);
    /// 2. a start below `member` has those groups and `member` itself, plus
    ///    the groups it reaches without entering them (`beyond`). One shared
    ///    climb from all such starts gives the union of `beyond`; if even
    ///    the sum fits, every start fits;
    /// 3. otherwise each start's own `beyond` is counted exactly, over the
    ///    links the shared climb read (no second store read).
    ///
    /// Every reference followed — a memberOf back link read, a link
    /// re-traversed in step 3 — is a step of this check's own
    /// [`MAX_WALK_STEPS`]; exceeding it refuses (fail closed), as does a
    /// closure over the bound. The references the depth walk already
    /// followed are not followed again (its memoised results are reused).
    ///
    /// Spec: docs/47 §5.3 items 1, 3 (R47-8); crate directory-pip
    /// `MAX_EXPANDED_GROUPS` and `groups::expand`; docs/51 §11;
    /// docs/questions/Q-356 item 5 (A-89 residual), Q-416.
    fn closure_fits(&self, depth: &DepthWalk, group: Guid, member: End<'_>) -> Result<bool, Fault> {
        let mut walk = ClosureWalk::default();
        match self.closure_walk(&mut walk, depth, group, member) {
            Ok(fits) => Ok(fits),
            Err(Walked::Refuse) => Ok(false),
            Err(Walked::Fault(fault)) => Err(fault),
        }
    }

    /// The steps of [`Graph::closure_fits`].
    fn closure_walk(
        &self,
        walk: &mut ClosureWalk,
        depth: &DepthWalk,
        group: Guid,
        member: End<'_>,
    ) -> Result<bool, Walked> {
        // U: `group` and every security-enabled group above it.
        let mut counted: BTreeSet<Guid> = depth.above.keys().copied().collect();
        counted.insert(group);
        if counted.len() > MAX_EXPANDED_GROUPS {
            return Ok(false);
        }
        // 1. `member`'s own closure after the link.
        let own = self.climb(walk, &[member.guid], &counted, None)?;
        counted.extend(own);
        if counted.len() > MAX_EXPANDED_GROUPS {
            return Ok(false);
        }
        // Expansion enters nothing below a member that is not a
        // security-enabled group: no other closure changes.
        if !depth.below.contains_key(&member.guid) {
            return Ok(true);
        }
        // 2. Every start below `member` has `counted` and `member` itself.
        counted.insert(member.guid);
        let starts: Vec<Guid> = depth
            .below
            .keys()
            .chain(depth.leaves.iter())
            .copied()
            .filter(|start| *start != member.guid)
            .collect();
        if starts.is_empty() {
            return Ok(true);
        }
        // `member` itself may be the 1025th group of every start below it.
        let Some(room) = MAX_EXPANDED_GROUPS.checked_sub(counted.len()) else {
            return Ok(false);
        };
        let mut links = BTreeMap::new();
        let beyond = self.climb(walk, &starts, &counted, Some(&mut links))?;
        if beyond.len() <= room {
            return Ok(true);
        }
        // 3. Each start exactly.
        for start in starts {
            if Self::reached(walk, &links, start, room)? > room {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Climb from `starts` over the memberOf back links into
    /// security-enabled groups, never entering `counted`; every group
    /// reached. With `links`, the groups each climbed object leads to are
    /// kept for [`Graph::reached`]. Each back link read is a step.
    /// Spec: as [`Graph::closure_fits`]; docs/47 §5.3 item 1.
    fn climb(
        &self,
        walk: &mut ClosureWalk,
        starts: &[Guid],
        counted: &BTreeSet<Guid>,
        mut links: Option<&mut BTreeMap<Guid, Vec<Guid>>>,
    ) -> Result<BTreeSet<Guid>, Walked> {
        let mut reached = BTreeSet::new();
        let mut climbed = BTreeSet::new();
        let mut pending = starts.to_vec();
        while let Some(x) = pending.pop() {
            if !climbed.insert(x) {
                continue;
            }
            let mut up = Vec::new();
            let sources = self
                .store
                .back_links(x, self.ids.member_of)
                .map_err(Fault::Store)?;
            for source in sources {
                walk.step()?;
                if counted.contains(&source) || !self.entered(walk, source)? {
                    continue;
                }
                up.push(source);
                if reached.insert(source) {
                    pending.push(source);
                }
            }
            if let Some(links) = links.as_deref_mut() {
                links.insert(x, up);
            }
        }
        Ok(reached)
    }

    /// `true` if expansion enters `guid`: a security-enabled group
    /// (classified once per check).
    /// Spec: docs/47 §5.3 item 1; [`Graph::is_security_group`].
    fn entered(&self, walk: &mut ClosureWalk, guid: Guid) -> Result<bool, Walked> {
        if let Some(known) = walk.security.get(&guid) {
            return Ok(*known);
        }
        let entered = match self.store.object(guid).map_err(Fault::Store)? {
            Some(obj) => self.is_security_group(&obj)?,
            None => false,
        };
        walk.security.insert(guid, entered);
        Ok(entered)
    }

    /// How many groups `start` reaches over `links` (the groups beyond the
    /// counted ones), stopping once more than `room`. Each link traversed is
    /// a step. Spec: as [`Graph::closure_fits`].
    fn reached(
        walk: &mut ClosureWalk,
        links: &BTreeMap<Guid, Vec<Guid>>,
        start: Guid,
        room: usize,
    ) -> Result<usize, Walked> {
        let mut seen = BTreeSet::new();
        let mut pending = vec![start];
        while let Some(x) = pending.pop() {
            for next in links.get(&x).map(Vec::as_slice).unwrap_or_default() {
                walk.step()?;
                if seen.insert(*next) {
                    if seen.len() > room {
                        return Ok(seen.len());
                    }
                    pending.push(*next);
                }
            }
        }
        Ok(seen.len())
    }

    /// `below(x)`: the longest climb from any start up to `x`, which sits
    /// `level` member links below the new link's member. A security-enabled
    /// group at `level` ≥ 16 is itself a start 16 or more levels below, so
    /// the new link would exceed the bound: refuse at once (this also bounds
    /// the recursion). An object expansion does not enter is kept in
    /// `leaves` (a start for the closure-size check). Spec: as
    /// [`Graph::nesting_walk`].
    fn levels_below(
        &self,
        walk: &mut DepthWalk,
        x: Guid,
        obj: &Object,
        level: usize,
    ) -> Result<usize, Walked> {
        if !self.is_security_group(obj)? {
            walk.leaves.insert(x);
            return Ok(0);
        }
        if level >= MAX_NESTING_DEPTH {
            return Err(Walked::Refuse);
        }
        if let Some(levels) = walk.below.get(&x) {
            return Ok(*levels);
        }
        if !walk.path.insert(x) {
            return Err(Walked::Refuse);
        }
        let mut best = 0usize;
        for next in record::refs(obj, self.ids.member).map_err(|_| Fault::Integrity)? {
            walk.step()?;
            if walk.path.contains(&next) {
                return Err(Walked::Refuse);
            }
            // Already measured: no need to read it again (still a step).
            if let Some(levels) = walk.below.get(&next) {
                best = best.max(levels + 1);
                continue;
            }
            let Some(child) = self.store.object(next).map_err(Fault::Store)? else {
                continue;
            };
            let levels = self.levels_below(walk, next, &child, level + 1)?;
            best = best.max(levels + 1);
        }
        walk.path.remove(&x);
        walk.below.insert(x, best);
        Ok(best)
    }

    /// `above(g)`: the longest climb above `g`, which sits `level` links
    /// above the new link's group, through security-enabled groups (the
    /// memberOf back links, as expansion climbs). A group `level` ≥ 16 above
    /// makes the new link's chain longer than the bound: refuse at once.
    /// Spec: as [`Graph::nesting_walk`].
    fn levels_above(&self, walk: &mut DepthWalk, g: Guid, level: usize) -> Result<usize, Walked> {
        if level >= MAX_NESTING_DEPTH {
            return Err(Walked::Refuse);
        }
        if let Some(levels) = walk.above.get(&g) {
            return Ok(*levels);
        }
        if !walk.path.insert(g) {
            return Err(Walked::Refuse);
        }
        let mut best = 0usize;
        let parents = self
            .store
            .back_links(g, self.ids.member_of)
            .map_err(Fault::Store)?;
        for parent in parents {
            walk.step()?;
            if walk.path.contains(&parent) {
                return Err(Walked::Refuse);
            }
            // Already measured (so a security-enabled group): no need to
            // read it again (still a step).
            if let Some(levels) = walk.above.get(&parent) {
                best = best.max(levels + 1);
                continue;
            }
            let Some(obj) = self.store.object(parent).map_err(Fault::Store)? else {
                continue;
            };
            if !self.is_security_group(&obj)? {
                continue;
            }
            let levels = self.levels_above(walk, parent, level + 1)?;
            best = best.max(levels + 1);
        }
        walk.path.remove(&g);
        walk.above.insert(g, best);
        Ok(best)
    }
}
