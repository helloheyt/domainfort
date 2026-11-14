//! The checks `prepare` runs against ONE directory view: resolving the
//! objects a request names, visibility, the PDP decisions, protected
//! objects, the membership rules, the cycle refusal, the bounds of group
//! expansion (nesting depth and closure size), and the count the
//! self-lockout guard needs.
//!
//! Spec: docs/51 §7.4 steps 2-4 (one view: snapshot + tier map of the same
//! policy version, docs/47 §8.1), §5.2, §5.6, §11; docs/11 §4, §7; A-55;
//! [MS-SAMR] 3.1.1.8.9; docs/47 §5.3 items 1, 3, 4; Q-295 item 4 (P-22);
//! docs/questions/Q-356 item 5, Q-416.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ad_schema::flags::group_type::{
    GROUP_TYPE_ACCOUNT_GROUP, GROUP_TYPE_RESOURCE_GROUP, GROUP_TYPE_SECURITY_ENABLED,
    GROUP_TYPE_UNIVERSAL_GROUP,
};
use ad_schema::flags::user_account_control::ADS_UF_SERVER_TRUST_ACCOUNT;
use directory_pip::{DirectoryView, MAX_EXPANDED_GROUPS, MAX_NESTING_DEPTH};
use dirstore::{ClassId, Object};
use dtyp::{Guid, Sid};
use ipc_audit::{AdminFailure, AdminRefusal};
use kdc::AccountSource;
use krb_proto::constants::KRB_NT_PRINCIPAL;
use krb_proto::{KerberosString, KerberosTime, PrincipalName};
use pdp::{
    AccessRequest, Action, Context, Decision, Dn, Instant, IpScope, PolicySnapshot, Resource,
    Subject, Tier, Transport, TransportSec,
};

use crate::audit::Stop;
use crate::config::AdminConfig;
use crate::ids::Ids;
use crate::record;

/// DOMAIN_USER_RID_KRBTGT. Spec: [MS-SAMR] 2.2.1.14 (0x000001F6).
const DOMAIN_USER_RID_KRBTGT: u32 = 0x0000_01F6;

/// The transport security of the admin plane's local socket: the bytes
/// never leave the host's kernel, and the AP-REQ is not yet bound to the
/// operation (no channel binding until task A15).
/// Spec: docs/51 §5.4 (R51-9); Q-292 / A-74 option (a).
pub(crate) const LOCAL_IPC_SECURITY: TransportSec = TransportSec {
    encrypted: true,
    sealed: true,
    channel_bound: false,
};

/// Most references one walk over the membership graph may follow — the
/// self-lockout count, the cycle check, the nesting-depth check and the
/// closure-size check alike. Every reference followed (a tier-map root, a
/// `member` value, a memberOf back link) counts once, also when it leads to
/// an object already seen, so the bound caps the work as well as the
/// objects read. Project choice (AGENTS.md §6); a walk that exceeds it
/// refuses the operation (docs/questions/Q-357 item 8; Q-356 items 4-5;
/// Q-416).
pub(crate) const MAX_WALK_STEPS: usize = 16_384;

/// Why a nesting-depth walk stopped before an answer: the store failed, or
/// the walk must refuse (a chain already too deep, a cycle, or the step
/// bound exceeded — fail closed).
enum Walked {
    Refuse,
    Stop(Stop),
}

impl From<Stop> for Walked {
    fn from(stop: Stop) -> Walked {
        Walked::Stop(stop)
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
/// Spec: as [`Cx::closure_fits`].
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

/// The inputs every check reads: the configuration, the schema ids, ONE
/// view, the policy of the same version, and the caller's `now`.
pub(crate) struct Cx<'c, 'v, 'a> {
    pub(crate) config: &'c AdminConfig,
    pub(crate) ids: &'c Ids,
    pub(crate) view: &'v DirectoryView<'a>,
    pub(crate) policy: &'v PolicySnapshot,
    pub(crate) now: KerberosTime,
    pub(crate) instant: Instant,
}

/// An object a request names, read from the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub(crate) guid: Guid,
    pub(crate) obj: Object,
    pub(crate) dn: Dn,
    pub(crate) class: ClassId,
}

/// A store read failed: the record did not verify or the store could not
/// answer. Spec: crate ipc-audit `AdminFailure` (IntegrityFailure /
/// StoreFailure).
pub(crate) fn store_failure(e: &dirstore::Error) -> Stop {
    match e {
        dirstore::Error::Tamper(_)
        | dirstore::Error::RecordMalformed(..)
        | dirstore::Error::Inconsistent(_)
        | dirstore::Error::StoredObjectRejected(_) => Stop::Failed(AdminFailure::IntegrityFailure),
        _ => Stop::Failed(AdminFailure::StoreFailure),
    }
}

/// A stored value that does not decode: an inconsistent record.
pub(crate) fn malformed(_: record::Malformed) -> Stop {
    Stop::Failed(AdminFailure::IntegrityFailure)
}

impl Cx<'_, '_, '_> {
    /// The most specific class of a stored object. Spec: docs/46 §8.3 item
    /// 1; [MS-ADTS] 3.1.1.2.4.3 (as cited there).
    pub(crate) fn class_of(&self, obj: &Object) -> Result<ClassId, Stop> {
        self.view
            .context()
            .schema()
            .schema()
            .most_specific_class(&obj.classes)
            .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))
    }

    /// The live object `guid` with its canonical DN; absent, or outside
    /// the naming context ⇒ `NotFound`.
    /// Spec: docs/51 §5.2 row 10 ("not found"); docs/47 §8.2 (`dn_of`).
    pub(crate) fn resolve(&self, guid: Guid) -> Result<Resolved, Stop> {
        let obj = self
            .view
            .snapshot()
            .get_object(guid)
            .map_err(|e| store_failure(&e))?
            .ok_or(Stop::Refused(AdminRefusal::NotFound))?;
        let dn = self
            .view
            .dn_of(guid)
            .map_err(|_| Stop::Failed(AdminFailure::StoreFailure))?
            .ok_or(Stop::Refused(AdminRefusal::NotFound))?;
        let class = self.class_of(&obj)?;
        Ok(Resolved {
            guid,
            obj,
            dn,
            class,
        })
    }

    /// `pdp::decide` for `subject` on the admin plane's local socket.
    /// Spec: docs/11 §1 (the PEP builds the request from the verified
    /// identity and the wire only), §4; docs/51 §5.4 (`Transport::LocalIpc`,
    /// `{encrypted, sealed}`, no channel binding — A-74); docs/11 P9 (the
    /// PEP supplies the time).
    pub(crate) fn decide(&self, subject: &Subject, action: Action, resource: Resource) -> Decision {
        let request = AccessRequest {
            subject: subject.clone(),
            resource,
            action,
            context: Context {
                src_net: IpScope::Internal,
                time: self.instant,
                transport: Transport::LocalIpc,
                transport_sec: LOCAL_IPC_SECURITY,
            },
        };
        pdp::decide(&request, self.policy, self.view)
    }

    /// The whole-object read decision on `r` (its visibility).
    /// Spec: docs/11 §7 (as cited in docs/51 §5.2 row 10: `DirRead` on the
    /// object = its visibility).
    pub(crate) fn read_decision(&self, subject: &Subject, r: &Resolved) -> Decision {
        self.decide(
            subject,
            Action::DirRead,
            Resource::DirObject {
                dn: r.dn.clone(),
                attr: None,
            },
        )
    }

    /// The classification of `dn` before the A-36 default: `Some(Tier0)`
    /// only when something explicitly makes it Tier0.
    /// Spec: docs/47 §6.3; A-36; P-22 (Q-295 item 1).
    pub(crate) fn explicit_tier(&self, dn: &Dn) -> Result<Option<Tier>, Stop> {
        self.view
            .classified_object_tier(dn)
            .map_err(|_| Stop::Failed(AdminFailure::StoreFailure))
    }

    /// `true` if `r` must never be deleted or changed by the admin plane
    /// beyond what its operation allows: the krbtgt account (RID 502), a
    /// DC account (userAccountControl ST), a service object, the NC root.
    /// Spec: docs/51 §5.2 rows 5, 6, 9, §4.3 step 5; [MS-SAMR] 3.1.1.6 items
    /// 14, 22; A-18, A-19, A-35; docs/47 §6.3 (ST ⇒ the DC).
    pub(crate) fn is_structural(&self, r: &Resolved) -> Result<bool, Stop> {
        if r.obj.parent.is_none() || r.class == self.ids.domain_dns.id {
            return Ok(true);
        }
        if self.config.protected().service_objects.contains(&r.guid) {
            return Ok(true);
        }
        if let Some(sid) = record::sid(&r.obj, self.ids.object_sid).map_err(malformed)? {
            if sid.sub_authority().last() == Some(&DOMAIN_USER_RID_KRBTGT) {
                return Ok(true);
            }
        }
        if r.class == self.ids.user.id || r.class == self.ids.computer.id {
            let uac = record::flags(&r.obj, self.ids.user_account_control).map_err(malformed)?;
            if uac.is_some_and(|u| u & ADS_UF_SERVER_TRUST_ACCOUNT != 0) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `true` if the policy names `r`: its objectSid is a tier-map
    /// principal or a policy principal (the bootstrap group), or its DN is a
    /// tier-map subtree base. Such an object is never deleted.
    /// Spec: docs/51 §5.2 row 9 ("groups the policy references"); docs/47
    /// §6.3; A-39 / A-44 (bootstrap group).
    pub(crate) fn is_policy_named(&self, r: &Resolved) -> Result<bool, Stop> {
        let tiers = self.view.tier_map();
        if tiers.subtrees().any(|(base, _)| *base == r.dn) {
            return Ok(true);
        }
        if let Some(sid) = record::sid(&r.obj, self.ids.object_sid).map_err(malformed)? {
            if self.config.protected().policy_principals.contains(&sid)
                || tiers.principals().any(|(s, _)| *s == sid)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `true` if `class` is user or derived from it (user, computer).
    /// Spec: [MS-SAMR] 3.1.1.8.9 items 2.2.1, 4.1 ("a user object (or an
    /// object derived from user)"); docs/46 §4.2 (computer ⊂ user).
    pub(crate) fn is_account(&self, class: ClassId) -> bool {
        class == self.ids.user.id || class == self.ids.computer.id
    }

    /// The membership rule of a group of type `group_type` for `member`.
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
    pub(crate) fn member_allowed(&self, group_type: u32, member: &Resolved) -> Result<bool, Stop> {
        if self.is_account(member.class) {
            return Ok(true);
        }
        if member.class != self.ids.group.id {
            return Ok(false);
        }
        let member_type = record::flags(&member.obj, self.ids.group_type)
            .map_err(malformed)?
            .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?;
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
    /// toward the group bound.
    /// Spec: docs/47 §5.3 items 3-4 ("the management plane refuses a
    /// `member` write that closes a cycle"); docs/51 §5.2 row 8, §11; A-79;
    /// docs/questions/Q-356 item 4.
    pub(crate) fn closes_cycle(&self, group: Guid, member: Guid) -> Result<bool, Stop> {
        let snapshot = self.view.snapshot();
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
            let Some(obj) = snapshot
                .get_object(current)
                .map_err(|e| store_failure(&e))?
            else {
                continue;
            };
            if self.class_of(&obj)? != self.ids.group.id {
                continue;
            }
            expanded.insert(current);
            if expanded.len() > MAX_EXPANDED_GROUPS {
                return Ok(true);
            }
            for next in record::refs(&obj, self.ids.member).map_err(malformed)? {
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
    fn is_security_group(&self, obj: &Object) -> Result<bool, Stop> {
        if self.class_of(obj)? != self.ids.group.id {
            return Ok(false);
        }
        let group_type = record::flags(obj, self.ids.group_type)
            .map_err(malformed)?
            .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?;
        Ok(group_type & GROUP_TYPE_SECURITY_ENABLED != 0)
    }

    /// `true` if adding `member` to `group` keeps every closure that
    /// directory-pip's group expansion computes within both of its bounds:
    /// no nesting chain deeper than `MAX_NESTING_DEPTH` (16 levels —
    /// [`Cx::nesting_walk`]) and no closure of more than
    /// `MAX_EXPANDED_GROUPS` (1024 groups — [`Cx::closure_fits`]). Beyond
    /// either, expansion fails (docs/47 §5.3 item 3: exceeding a bound ⇒
    /// `Err`, never a partial set) and the affected account can no longer
    /// log in; the write is refused instead. A link into a group that is not
    /// security-enabled is never climbed by expansion, so it changes no
    /// closure and is allowed.
    /// Spec: docs/47 §5.3 items 1, 3 (R47-8); crate directory-pip
    /// `MAX_NESTING_DEPTH`, `MAX_EXPANDED_GROUPS`, `groups::expand`; docs/51
    /// §11; docs/questions/Q-356 item 5 (A-89), Q-416.
    pub(crate) fn expansion_allowed(
        &self,
        group: &Resolved,
        member: &Resolved,
    ) -> Result<bool, Stop> {
        if !self.is_security_group(&group.obj)? {
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
    fn nesting_walk(&self, group: &Resolved, member: &Resolved) -> Result<Option<DepthWalk>, Stop> {
        let mut walk = DepthWalk::default();
        let below = match self.levels_below(&mut walk, member.guid, &member.obj, 0) {
            Ok(levels) => levels,
            Err(Walked::Refuse) => return Ok(None),
            Err(Walked::Stop(stop)) => return Err(stop),
        };
        walk.path.clear();
        let above = match self.levels_above(&mut walk, group.guid, 0) {
            Ok(levels) => levels,
            Err(Walked::Refuse) => return Ok(None),
            Err(Walked::Stop(stop)) => return Err(stop),
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
    fn closure_fits(
        &self,
        depth: &DepthWalk,
        group: Guid,
        member: &Resolved,
    ) -> Result<bool, Stop> {
        let mut walk = ClosureWalk::default();
        match self.closure_walk(&mut walk, depth, group, member) {
            Ok(fits) => Ok(fits),
            Err(Walked::Refuse) => Ok(false),
            Err(Walked::Stop(stop)) => Err(stop),
        }
    }

    /// The steps of [`Cx::closure_fits`].
    fn closure_walk(
        &self,
        walk: &mut ClosureWalk,
        depth: &DepthWalk,
        group: Guid,
        member: &Resolved,
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
    /// kept for [`Cx::reached`]. Each back link read is a step.
    /// Spec: as [`Cx::closure_fits`]; docs/47 §5.3 item 1.
    fn climb(
        &self,
        walk: &mut ClosureWalk,
        starts: &[Guid],
        counted: &BTreeSet<Guid>,
        mut links: Option<&mut BTreeMap<Guid, Vec<Guid>>>,
    ) -> Result<BTreeSet<Guid>, Walked> {
        let snapshot = self.view.snapshot();
        let mut reached = BTreeSet::new();
        let mut climbed = BTreeSet::new();
        let mut pending = starts.to_vec();
        while let Some(x) = pending.pop() {
            if !climbed.insert(x) {
                continue;
            }
            let mut up = Vec::new();
            let sources = snapshot
                .back_links(x, self.ids.member_of)
                .map_err(|e| store_failure(&e))?;
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
    /// Spec: docs/47 §5.3 item 1; [`Cx::is_security_group`].
    fn entered(&self, walk: &mut ClosureWalk, guid: Guid) -> Result<bool, Walked> {
        if let Some(known) = walk.security.get(&guid) {
            return Ok(*known);
        }
        let entered = match self
            .view
            .snapshot()
            .get_object(guid)
            .map_err(|e| store_failure(&e))?
        {
            Some(obj) => self.is_security_group(&obj)?,
            None => false,
        };
        walk.security.insert(guid, entered);
        Ok(entered)
    }

    /// How many groups `start` reaches over `links` (the groups beyond the
    /// counted ones), stopping once more than `room`. Each link traversed is
    /// a step. Spec: as [`Cx::closure_fits`].
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
    /// [`Cx::nesting_walk`].
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
        let snapshot = self.view.snapshot();
        let mut best = 0usize;
        for next in record::refs(obj, self.ids.member).map_err(malformed)? {
            walk.step()?;
            if walk.path.contains(&next) {
                return Err(Walked::Refuse);
            }
            // Already measured: no need to read it again (still a step).
            if let Some(levels) = walk.below.get(&next) {
                best = best.max(levels + 1);
                continue;
            }
            let Some(child) = snapshot.get_object(next).map_err(|e| store_failure(&e))? else {
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
    /// Spec: as [`Cx::nesting_walk`].
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
        let snapshot = self.view.snapshot();
        let mut best = 0usize;
        let parents = snapshot
            .back_links(g, self.ids.member_of)
            .map_err(|e| store_failure(&e))?;
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
            let Some(obj) = snapshot.get_object(parent).map_err(|e| store_failure(&e))? else {
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

    /// The number of enabled Tier-0 administrators, optionally under one
    /// hypothetical change: the user accounts reachable downward from a SID
    /// the tier map makes Tier0, through `member` links of security-enabled
    /// groups (the subgraph group expansion walks, docs/47 §5.3), up to
    /// [`MAX_NESTING_DEPTH`] levels, that are usable now (`usable_at`, the
    /// same account state the requester's Subject needs).
    ///
    /// Computers are not counted (an administrator is a person's account).
    /// Spec: Q-295 item 4 (P-22: "not below the quorum of enabled Tier-0
    /// administrators"); docs/47 §5.3, §6.3, §4; docs/51 §5.6.
    pub(crate) fn enabled_tier0_admins(
        &self,
        change: Option<&LockoutChange>,
    ) -> Result<usize, Stop> {
        let snapshot = self.view.snapshot();
        // Breadth first, so every object is first reached at its smallest
        // depth (a deeper first visit would cut its subtree short).
        let mut queue: VecDeque<(Guid, usize)> = VecDeque::new();
        for (sid, tier) in self.view.tier_map().principals() {
            if tier != Tier::Tier0 {
                continue;
            }
            if let Some(guid) = snapshot
                .lookup_unique(self.ids.object_sid, &sid.encode())
                .map_err(|e| store_failure(&e))?
            {
                queue.push_back((guid, 0));
            }
        }
        let mut seen: BTreeSet<Guid> = BTreeSet::new();
        let mut groups = 0usize;
        let mut admins = 0usize;
        let mut steps = 0usize;
        while let Some((guid, depth)) = queue.pop_front() {
            steps += 1;
            if steps > MAX_WALK_STEPS {
                return Err(Stop::Failed(AdminFailure::InternalFailure));
            }
            if change.is_some_and(|c| c.deletes(guid)) || !seen.insert(guid) {
                continue;
            }
            let Some(obj) = snapshot.get_object(guid).map_err(|e| store_failure(&e))? else {
                continue;
            };
            let class = self.class_of(&obj)?;
            if class == self.ids.user.id {
                if !change.is_some_and(|c| c.disables(guid)) && self.usable_now(&obj)? {
                    admins += 1;
                }
            } else if class == self.ids.group.id && depth < MAX_NESTING_DEPTH {
                groups += 1;
                if groups > MAX_EXPANDED_GROUPS {
                    return Err(Stop::Failed(AdminFailure::InternalFailure));
                }
                let group_type = record::flags(&obj, self.ids.group_type)
                    .map_err(malformed)?
                    .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?;
                if group_type & GROUP_TYPE_SECURITY_ENABLED == 0 {
                    continue;
                }
                for member in record::refs(&obj, self.ids.member).map_err(malformed)? {
                    if change.is_some_and(|c| c.removes_edge(guid, member)) {
                        continue;
                    }
                    queue.push_back((member, depth + 1));
                }
            }
        }
        Ok(admins)
    }

    /// `true` if the user account `obj` could authenticate now: the account
    /// source finds it by its sAMAccountName and its state is usable.
    /// Spec: docs/47 §1.3, §4 (`usable_at`); docs/51 §5.3.
    fn usable_now(&self, obj: &Object) -> Result<bool, Stop> {
        let Some(sam) = record::text(obj, self.ids.sam_account_name).map_err(malformed)? else {
            return Ok(false);
        };
        let Ok(component) = KerberosString::new(sam) else {
            return Ok(false);
        };
        let name = PrincipalName {
            name_type: KRB_NT_PRINCIPAL,
            name_string: vec![component],
        };
        match self.view.client(self.config.realm(), &name) {
            Ok(Some(account)) => Ok(account.state.usable_at(&self.now)),
            Ok(None) => Ok(false),
            Err(_) => Err(Stop::Failed(AdminFailure::StoreFailure)),
        }
    }
}

/// The change whose effect on the enabled Tier-0 administrators the
/// self-lockout guard weighs. Spec: Q-295 item 4 (P-22: "a disable, delete,
/// or removal from the Tier-0 group").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockoutChange {
    /// The account becomes unusable (disabled, or expired now).
    Unusable(Guid),
    /// The object is deleted (with every membership it takes part in).
    Deleted(Guid),
    /// `member` leaves `group`.
    EdgeRemoved {
        /// The group.
        group: Guid,
        /// The member.
        member: Guid,
    },
}

impl LockoutChange {
    fn deletes(&self, guid: Guid) -> bool {
        matches!(self, LockoutChange::Deleted(g) if *g == guid)
    }

    fn disables(&self, guid: Guid) -> bool {
        matches!(self, LockoutChange::Unusable(g) if *g == guid)
    }

    fn removes_edge(&self, from: Guid, to: Guid) -> bool {
        matches!(self, LockoutChange::EdgeRemoved { group, member } if *group == from && *member == to)
    }
}

/// The objectSid of `domain_root`, the naming-context root.
/// Spec: docs/51 §8.3 ("objectSid = the domain SID (from the NC root's
/// objectSid) ‖ RID"); [MS-SAMR] 3.1.1.9.2 ("concatenating that value with
/// the account domain security identifier").
pub(crate) fn domain_sid(ids: &Ids, domain_root: &Object) -> Result<Sid, Stop> {
    record::sid(domain_root, ids.object_sid)
        .map_err(malformed)?
        .ok_or(Stop::Failed(AdminFailure::StoreFailure))
}
