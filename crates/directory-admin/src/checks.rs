//! The checks `prepare` runs against ONE directory view: resolving the
//! objects a request names, visibility, the PDP decisions, protected
//! objects, and the count the self-lockout guard needs. The membership
//! rules, the cycle refusal and the bounds of group expansion (nesting
//! depth and closure size) are the write invariants' (crate::invariants,
//! docs/52 R13): `prepare` asks the same checker every write path passes.
//!
//! # Visibility (docs/52 R10, A-102)
//!
//! Every object a request names is a [`Resolved`], which can be built only
//! from the visibility gate's `directory_pip::VisibleObject` (rule
//! `ListAndRead`: `DirList` on the parent as [MS-ADTS] 5.1.3.3.6 — the LDAP
//! search's rule — **and** `DirRead` on the whole object, docs/51 §5.2 row
//! 10; docs/questions/Q-485) — so every check here that takes a `Resolved`
//! runs on an object the requester may see, the admin plane never names an
//! object the LDAP search hides, and "absent" and "not visible" were
//! answered alike before (A-55; docs/questions/Q-358 item 3). The membership walks read further
//! objects the requester may not see — they check invariants of the whole
//! directory and hand nothing back; their refusal codes are a residual
//! (docs/questions/Q-487). [`Cx::resolve`] reads a key-operation target for
//! crate::key_requests, after its `PolicyAdmin` decision (Q-486).
//!
//! Spec: docs/51 §7.4 steps 2-4 (one view: snapshot + tier map of the same
//! policy version, docs/47 §8.1), §5.2, §5.6, §11; docs/11 §4, §7; A-55;
//! docs/52 R10, R13; Q-295 item 4 (P-22).

use std::collections::{BTreeSet, VecDeque};

use ad_schema::flags::group_type::GROUP_TYPE_SECURITY_ENABLED;
use directory_pip::{
    DirectoryView, VisibilityGate, VisibilityProof, VisibilityRule, VisibleObject,
    MAX_EXPANDED_GROUPS, MAX_NESTING_DEPTH,
};
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
use crate::invariants::{Fault, Graph, MAX_WALK_STEPS};
use crate::record;

/// The transport security of the admin plane's local socket: the bytes
/// never leave the host's kernel, and the AP-REQ is not yet bound to the
/// operation (no channel binding until task A15).
/// Spec: docs/51 §5.4 (R51-9); Q-292 / A-74 option (a).
pub(crate) const LOCAL_IPC_SECURITY: TransportSec = TransportSec {
    encrypted: true,
    sealed: true,
    channel_bound: false,
};

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

/// An object a request names that the requester may see, read from the
/// view. Built only by [`Resolved::from_visible`], from the visibility
/// gate's `VisibleObject` (module documentation): the proof field has no
/// constructor outside directory-pip.
/// Spec: docs/52 R10; docs/51 §5.2 row 10; A-55.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Resolved<'v> {
    pub(crate) guid: Guid,
    pub(crate) obj: Object,
    pub(crate) dn: Dn,
    pub(crate) class: ClassId,
    _visible: VisibilityProof<'v>,
}

impl<'v> Resolved<'v> {
    /// The record of a visible object, with its most specific class.
    /// Spec: docs/46 §8.3 item 1; docs/52 R10.
    pub(crate) fn from_visible(
        cx: &Cx<'_, 'v, '_>,
        visible: VisibleObject<'v>,
    ) -> Result<Resolved<'v>, Stop> {
        let class = cx.class_of(visible.object())?;
        let (obj, dn, proof) = visible.into_parts();
        Ok(Resolved {
            guid: proof.guid(),
            obj,
            dn,
            class,
            _visible: proof,
        })
    }
}

/// A key-operation target read for crate::key_requests: the manifest's
/// krbtgt account or one of its service objects, read only after the
/// requester's `PolicyAdmin` decision on the `keys` scope (docs/51 §5.2 row
/// 11). Not a [`Resolved`]: no check that needs a visible object accepts it
/// (docs/questions/Q-486).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyTargetRecord {
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

/// A fault of the write invariants' checks, as the PEP reports it: a store
/// failure as [`store_failure`], an inconsistent record as
/// `IntegrityFailure`, something the store must hold (the change-seq
/// counter, the NC root's domain SID) missing as `StoreFailure` — the
/// mapping these checks had before they moved (crate::invariants).
/// Spec: crate ipc-audit `AdminFailure`; A-83 (missing counter ⇒
/// `Failed(StoreFailure)`); docs/51 §8.3.
pub(crate) fn fault_stop(fault: &Fault) -> Stop {
    match fault {
        Fault::Store(e) => store_failure(e),
        Fault::Integrity => Stop::Failed(AdminFailure::IntegrityFailure),
        Fault::Missing => Stop::Failed(AdminFailure::StoreFailure),
    }
}

impl<'v, 'a> Cx<'_, 'v, 'a> {
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

    /// The live key-operation target `guid` with its canonical DN; absent,
    /// or outside the naming context ⇒ `NotFound` ([`KeyTargetRecord`]).
    /// Spec: docs/51 §5.2 rows 10-11 ("not found"); docs/47 §8.2 (`dn_of`).
    pub(crate) fn resolve(&self, guid: Guid) -> Result<KeyTargetRecord, Stop> {
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
        Ok(KeyTargetRecord {
            guid,
            obj,
            dn,
            class,
        })
    }

    /// The `Context` of every PDP request on the admin plane's local socket.
    /// Spec: docs/51 §5.4 (`Transport::LocalIpc`, `{encrypted, sealed}`, no
    /// channel binding — A-74); docs/11 §1, P9 (the PEP supplies the time);
    /// docs/questions/Q-358 item 11.
    fn context(&self) -> Context {
        Context {
            src_net: IpScope::Internal,
            time: self.instant,
            transport: Transport::LocalIpc,
            transport_sec: LOCAL_IPC_SECURITY,
        }
    }

    /// `pdp::decide` for `subject` on the admin plane's local socket.
    /// Spec: docs/11 §1 (the PEP builds the request from the verified
    /// identity and the wire only), §4; docs/51 §5.4.
    pub(crate) fn decide(&self, subject: &Subject, action: Action, resource: Resource) -> Decision {
        let request = AccessRequest {
            subject: subject.clone(),
            resource,
            action,
            context: self.context(),
        };
        pdp::decide(&request, self.policy, self.view)
    }

    /// The visibility gate of `subject` over this view, in the same context
    /// as every other decision of the request: an object is visible when
    /// the requester may list its parent ([MS-ADTS] 5.1.3.3.6 — the LDAP
    /// search's rule) **and** read the whole object (docs/51 §5.2 row 10).
    /// Spec: [MS-ADTS] 5.1.3.3.6; docs/51 §5.2 row 10 (`DirRead` on the
    /// object, docs/11 §7); docs/52 R10; A-55; docs/questions/Q-485.
    pub(crate) fn gate(&self, subject: &Subject) -> VisibilityGate<'v, 'a> {
        VisibilityGate::new(
            self.view,
            self.policy,
            subject.clone(),
            self.context(),
            VisibilityRule::ListAndRead,
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
    /// DC account (userAccountControl ST), a service object, the NC root —
    /// the write invariants' rule (crate::invariants, `Graph::is_structural`;
    /// docs/52 R13), over this view.
    /// Spec: docs/51 §5.2 rows 5, 6, 9, §4.3 step 5; [MS-SAMR] 3.1.1.6 items
    /// 14, 22; A-18, A-19, A-35; docs/47 §6.3 (ST ⇒ the DC).
    pub(crate) fn is_structural(&self, r: &Resolved) -> Result<bool, Stop> {
        self.graph()
            .is_structural(r.guid, &r.obj, r.class)
            .map_err(|f| fault_stop(&f))
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

    /// `true` if `class` is user or derived from it (user, computer) — the
    /// write invariants' rule.
    /// Spec: [MS-SAMR] 3.1.1.8.9 items 2.2.1, 4.1 ("a user object (or an
    /// object derived from user)"); docs/46 §4.2 (computer ⊂ user).
    pub(crate) fn is_account(&self, class: ClassId) -> bool {
        self.graph().is_account(class)
    }

    /// The rules of crate::invariants's `graph` over this view's snapshot:
    /// the schema of the view's context, the configuration's protected
    /// service objects (docs/52 R13 — one implementation for every write
    /// path).
    fn graph(&self) -> Graph<'_, dirstore::Snapshot<'_>> {
        Graph {
            ids: self.ids,
            schema: self.view.context().schema().schema(),
            service_objects: &self.config.protected().service_objects,
            store: self.view.snapshot(),
        }
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
