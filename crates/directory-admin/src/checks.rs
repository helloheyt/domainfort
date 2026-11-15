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
//! # The raw view is this module's alone (docs/52 R-a; A-103)
//!
//! [`Cx`] holds the request's view twice: as a `directory_pip::PepView`
//! ([`Cx::pep`], public to the crate) — the gate, the locators, the PIP and
//! the account source, all the request-facing code (crate::admin,
//! crate::key_requests) can reach — and as the authority's
//! `DirectoryView`, a **private** field of `Cx`. Only this module reads the
//! raw snapshot (`DirectoryView::authority_snapshot`): the internal reads
//! docs/questions/Q-486 item 5 puts outside the gate — the write invariants'
//! graph, the self-lockout count, the counters, the name and uniqueness
//! checks of a create, the has-children probe of a delete, the NC root, the
//! exact-value locator of `Lookup`, the key-operation target, the
//! tombstones of dird's destroy decisions, and (task MA3) the effect-plan
//! facts of crate::effects (`directory_pip::PrincipalFacts`, the member
//! closure, the principals under a subtree, an account's state) — each a
//! named method here that hands back a verdict, a count, a GUID or an
//! internal record, never an object for a reply. An effect plan reaches a
//! reply only after every principal it names passed the requester's
//! visibility gate (crate::effects, `PlanNotVisible`). A new request-facing read that tried the raw view
//! would not compile outside this module.
//!
//! Spec: docs/51 §7.4 steps 2-4 (one view: snapshot + tier map of the same
//! policy version, docs/47 §8.1), §5.2, §5.6, §11; docs/11 §4, §7; A-55;
//! docs/52 R10, R13, R-a; Q-295 item 4 (P-22); docs/questions/Q-486
//! (A-103).

use std::collections::{BTreeSet, VecDeque};

use ad_schema::flags::group_type::GROUP_TYPE_SECURITY_ENABLED;
use directory_pip::{
    DirectoryView, MemberChange, PepView, PrincipalFacts, TierMap, VisibilityGate, VisibilityProof,
    VisibilityRule, VisibleObject, MAX_EXPANDED_GROUPS, MAX_NESTING_DEPTH,
};
use dirstore::{AttrId, ClassId, CounterState, Object, Tombstone, TombstonePage};
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
use crate::invariants::{End, Fault, Graph, Invariants, LinkProof, MAX_WALK_STEPS};
use crate::record;

/// The transport security of the admin plane's local socket: the bytes
/// never leave the host's kernel (`encrypted`, `sealed`), and
/// `channel_bound` exactly when keyd verified the request's AP-REQ bound
/// to its operation (R2 — `VerifiedTicket::bound_to`; a request carries one
/// AP-REQ since the in-request approvals were retired, docs/questions/
/// Q-882).
/// Spec: docs/51 §5.4 (R51-9); docs/52 §5 item 4; docs/questions/Q-463
/// (A-102, superseding Q-292 / A-74 option (a)).
pub(crate) const fn local_ipc_security(channel_bound: bool) -> TransportSec {
    TransportSec {
        encrypted: true,
        sealed: true,
        channel_bound,
    }
}

/// The transport security of a kpasswd request (task K6): `{encrypted,
/// sealed, channel_bound}` all true — **only** because keyd verified that
/// the request's KRB-PRIV is encrypted under the subkey of that very
/// request's AP-REQ (RFC 3244 §2; RFC 4120 §5.7.1, key usage 13): the new
/// password is confidential, integrity-protected and bound to the
/// authentication. A `ChangePasswordTicket` exists only for a request keyd
/// opened that way (crate::change_password), so this value is never
/// reported for anything else.
/// Spec: docs/53 §5.4 item 1, §5.6 step 4; docs/questions/Q-601 item 7
/// (A-117).
pub(crate) const KPASSWD_SECURITY: TransportSec = TransportSec {
    encrypted: true,
    sealed: true,
    channel_bound: true,
};

/// The inputs every check reads: the configuration, the schema ids, ONE
/// view, the policy of the same version, and the caller's `now`.
pub(crate) struct Cx<'c, 'v, 'a> {
    pub(crate) config: &'c AdminConfig,
    pub(crate) ids: &'c Ids,
    /// The view as the request-facing code receives it: the gate, the
    /// locators, the PIP, the account source — no raw read (module
    /// documentation; docs/52 R-a).
    pub(crate) pep: PepView<'v, 'a>,
    /// The authority's view of the same snapshot — private to this module,
    /// read only by its internal-read methods (module documentation;
    /// docs/questions/Q-486 item 5, A-103).
    view: &'v DirectoryView<'a>,
    pub(crate) policy: &'v PolicySnapshot,
    pub(crate) now: KerberosTime,
    pub(crate) instant: Instant,
    /// The request's transport security ([`local_ipc_security`]; R2 — or
    /// [`KPASSWD_SECURITY`]).
    pub(crate) transport_sec: TransportSec,
    /// The transport the request arrived on: `LocalIpc` (the admin plane's
    /// `dird-admin.sock`) or `Kpasswd` (task K6).
    transport: Transport,
}

impl<'c, 'v, 'a> Cx<'c, 'v, 'a> {
    /// The checks' inputs over `view` and the policy of the same version at
    /// `now`: the PEP's view of it ([`Cx::pep`]) and, kept here, the raw
    /// one. `now` outside the PDP's instant range ⇒ `InternalFailure`.
    /// Spec: docs/51 §7.4 steps 2-4; docs/11 P9; docs/52 R-a.
    pub(crate) fn new(
        config: &'c AdminConfig,
        ids: &'c Ids,
        view: &'v DirectoryView<'a>,
        policy: &'v PolicySnapshot,
        now: &KerberosTime,
        transport_sec: TransportSec,
    ) -> Result<Cx<'c, 'v, 'a>, Stop> {
        Cx::on(
            config,
            ids,
            view,
            policy,
            now,
            Transport::LocalIpc,
            transport_sec,
        )
    }

    /// The checks' inputs of a kpasswd request (task K6): the same view and
    /// policy, the transport `Kpasswd` with [`KPASSWD_SECURITY`].
    /// Spec: docs/53 §5.6 step 4; docs/questions/Q-601 item 7 (A-117).
    pub(crate) fn kpasswd(
        config: &'c AdminConfig,
        ids: &'c Ids,
        view: &'v DirectoryView<'a>,
        policy: &'v PolicySnapshot,
        now: &KerberosTime,
    ) -> Result<Cx<'c, 'v, 'a>, Stop> {
        Cx::on(
            config,
            ids,
            view,
            policy,
            now,
            Transport::Kpasswd,
            KPASSWD_SECURITY,
        )
    }

    /// The inputs on `transport` with `transport_sec`.
    /// Spec: docs/11 §1 (`Context.transport`, `transport_sec`).
    fn on(
        config: &'c AdminConfig,
        ids: &'c Ids,
        view: &'v DirectoryView<'a>,
        policy: &'v PolicySnapshot,
        now: &KerberosTime,
        transport: Transport,
        transport_sec: TransportSec,
    ) -> Result<Cx<'c, 'v, 'a>, Stop> {
        Ok(Cx {
            config,
            ids,
            pep: PepView::new(view),
            view,
            policy,
            now: *now,
            instant: crate::time::instant(now)
                .ok_or(Stop::Failed(AdminFailure::InternalFailure))?,
            transport_sec,
            transport,
        })
    }
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

/// The requester's own account of a kpasswd change, read for
/// crate::change_password after its Subject was built from the same view
/// ([`Cx::own_account`]). Not a [`Resolved`]: it is not an object the
/// request names (task K6; docs/questions/Q-963 item 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnAccount {
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
            .authority_snapshot()
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

    /// The requester's own account object of a kpasswd change (task K6):
    /// the record and the canonical DN of `guid` — the objectGUID of the
    /// account the request ticket's client resolved to through this view's
    /// account source (`AdminSubject::guid`). Internal read: the object is
    /// not named by the request, it **is** the authenticated requester, so
    /// the visibility gate (which answers "is the requester allowed to know
    /// this object exists", A-55) does not apply — nothing of it reaches a
    /// reply (docs/questions/Q-963 item 2). Gone, or outside the naming
    /// context ⇒ `Failed(IntegrityFailure)`: the account source found it in
    /// this very snapshot.
    /// Spec: docs/53 §5.6 step 4 (the PDP on "the account object itself");
    /// [MS-ADTS] 3.1.1.3.1.5.1 ("on itself"); docs/47 §1.3 (the handle's
    /// principal is the objectGUID); docs/52 R-a.
    pub(crate) fn own_account(&self, guid: Guid) -> Result<OwnAccount, Stop> {
        let integrity = Stop::Failed(AdminFailure::IntegrityFailure);
        let obj = self
            .view
            .authority_snapshot()
            .get_object(guid)
            .map_err(|e| store_failure(&e))?
            .ok_or(integrity)?;
        let dn = self
            .view
            .dn_of(guid)
            .map_err(|_| Stop::Failed(AdminFailure::StoreFailure))?
            .ok_or(integrity)?;
        let class = self.class_of(&obj)?;
        Ok(OwnAccount {
            guid,
            obj,
            dn,
            class,
        })
    }

    /// The `Context` of every PDP request of this request: on the admin
    /// plane's local socket, or — task K6 — through the kpasswd front, whose
    /// only zone is the internal one (docs/53 §3.3: `FrontZone::Internal`,
    /// derived by dird from the front's uid).
    /// Spec: docs/51 §5.4 (`Transport::LocalIpc`, `{encrypted, sealed}`);
    /// docs/52 §5 item 4 (`channel_bound` once keyd verified the binding);
    /// docs/53 §3.3, §5.6 step 4; docs/11 §1, P9 (the PEP supplies the
    /// time); docs/questions/Q-358 item 11.
    fn context(&self) -> Context {
        Context {
            src_net: IpScope::Internal,
            time: self.instant,
            transport: self.transport,
            transport_sec: self.transport_sec,
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
        self.pep.gate(
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

    /// The tier map of the request's policy version (policy data, not
    /// directory content). Spec: docs/47 §6.3, §8.1.
    pub(crate) fn tier_map(&self) -> &TierMap {
        self.view.tier_map()
    }

    // -- Internal reads (module documentation; docs/questions/Q-486 item 5).

    /// The effect-plan facts of the principal `guid` (task MA3): what the
    /// PIP answers now, or under `change` / `tiers` — the view's own
    /// functions (directory-pip `principal_facts`). Internal read: the caller
    /// shows a principal only after the visibility gate.
    /// Spec: docs/research/r5-a-admin-model.md §3.3; docs/47 §5.3, §6.3.
    pub(crate) fn principal_facts(
        &self,
        guid: Guid,
        change: Option<&MemberChange>,
        tiers: Option<&TierMap>,
    ) -> Result<Option<PrincipalFacts>, Stop> {
        self.view
            .principal_facts(guid, change, tiers)
            .map_err(|_| Stop::Failed(AdminFailure::StoreFailure))
    }

    /// The principals whose expansion passes through `roots` (task MA3;
    /// directory-pip `member_closure`); `None` beyond `limit`. Internal read.
    /// Spec: docs/47 §5.3; docs/questions/Q-984.
    pub(crate) fn member_closure(
        &self,
        roots: &[Guid],
        limit: usize,
    ) -> Result<Option<BTreeSet<Guid>>, Stop> {
        self.view
            .member_closure(roots, limit)
            .map_err(|_| Stop::Failed(AdminFailure::StoreFailure))
    }

    /// The principals at or below the subtree `base` (task MA3;
    /// directory-pip `principals_under`); `None` beyond `limit`. Internal
    /// read.
    /// Spec: docs/47 §6.3; docs/questions/Q-984.
    pub(crate) fn principals_under(
        &self,
        base: &Dn,
        limit: usize,
    ) -> Result<Option<BTreeSet<Guid>>, Stop> {
        self.view
            .principals_under(base, limit)
            .map_err(|_| Stop::Failed(AdminFailure::StoreFailure))
    }

    /// The KDC's account state of the record `obj` — stored, or the one a
    /// write is about to store (task MA3; directory-pip `account_state_of`).
    /// Spec: docs/47 §4; A-162.
    pub(crate) fn account_state_of(&self, obj: &Object) -> Result<Option<kdc::AccountState>, Stop> {
        self.view
            .account_state_of(obj)
            .map_err(|_| Stop::Failed(AdminFailure::IntegrityFailure))
    }

    /// The objectGUID of the live object whose objectSid is `sid`, if any
    /// (task MA3: a group an expansion names, a tier-map row's SID).
    /// Internal read.
    /// Spec: docs/47 §8.2 (`lookup_unique(objectSid, p)`).
    pub(crate) fn guid_of_sid(&self, sid: &Sid) -> Result<Option<Guid>, Stop> {
        self.view
            .authority_snapshot()
            .lookup_unique(self.ids.object_sid, &sid.encode())
            .map_err(|e| store_failure(&e))
    }

    /// The state of the counter `name` (the change-seq or RID counter —
    /// docs/51 §8.3). Internal read.
    /// Spec: docs/51 §8.3; A-75; A-83.
    pub(crate) fn counter(&self, name: &str) -> Result<Option<CounterState>, Stop> {
        self.view
            .authority_snapshot()
            .counter(name)
            .map_err(|e| store_failure(&e))
    }

    /// A create's name check: no live child of `parent` with the RDN value
    /// `rdn` (docs/46 §8.3 item 3; dirstore `NameExists`) — taken ⇒
    /// `Conflict`, a value no name can have ⇒ `ValueInvalid`. Internal read
    /// of the whole directory (its refusal is the residual of
    /// docs/questions/Q-487 item 1).
    /// Spec: docs/46 §8.3 item 3; docs/51 §5.2 rows 1-4.
    pub(crate) fn name_free(&self, parent: Guid, rdn: &str) -> Result<(), Stop> {
        match self
            .view
            .authority_snapshot()
            .lookup_child(Some(parent), rdn.as_bytes())
        {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(Stop::Refused(AdminRefusal::Conflict)),
            Err(dirstore::Error::Rejected(_)) => Err(Stop::Refused(AdminRefusal::ValueInvalid)),
            Err(e) => Err(store_failure(&e)),
        }
    }

    /// A create's uniqueness check: no object holds `value` in the unique
    /// attribute `attr` (docs/46 §8.5, the rule the create path cites) — taken ⇒
    /// `Conflict`, a value the index cannot hold ⇒ `ValueInvalid`. Internal
    /// read (docs/questions/Q-487 item 2).
    /// Spec: docs/46 §8.5; docs/questions/Q-487 item 2.
    pub(crate) fn unique_free(&self, attr: AttrId, value: &str) -> Result<(), Stop> {
        match self
            .view
            .authority_snapshot()
            .lookup_unique(attr, value.as_bytes())
        {
            Ok(None) => Ok(()),
            Ok(Some(_)) => Err(Stop::Refused(AdminRefusal::Conflict)),
            Err(dirstore::Error::Rejected(_)) => Err(Stop::Refused(AdminRefusal::ValueInvalid)),
            Err(e) => Err(store_failure(&e)),
        }
    }

    /// The NC root: the object the naming context's DN names — for the
    /// domain SID and the write's re-verification, never a reply. Internal
    /// read.
    /// Spec: A-53; docs/47 §8.2; docs/51 §8.3.
    pub(crate) fn domain_root(&self) -> Result<(Guid, Object), Stop> {
        let labels = self.config.naming_context().labels();
        let rdns: Vec<(&str, &str)> = labels
            .iter()
            .map(|l| (directory_pip::NC_RDN_ATTRIBUTE, l.as_str()))
            .collect();
        let guid = self
            .view
            .lookup_dn(&rdns)
            .map_err(|_| Stop::Failed(AdminFailure::StoreFailure))?
            .ok_or(Stop::Failed(AdminFailure::StoreFailure))?;
        let root = self
            .view
            .authority_snapshot()
            .get_object(guid)
            .map_err(|e| store_failure(&e))?
            .ok_or(Stop::Failed(AdminFailure::StoreFailure))?;
        Ok((guid, root))
    }

    /// `true` if the object `guid` has a live child (a delete's probe,
    /// docs/questions/Q-356 item 6). Internal read (Q-487 item 3).
    /// Spec: docs/51 §5.2 row 9; dirstore `Snapshot::children`.
    pub(crate) fn has_children(&self, guid: Guid) -> Result<bool, Stop> {
        let page = self
            .view
            .authority_snapshot()
            .children(Some(guid), None, 1)
            .map_err(|e| store_failure(&e))?;
        Ok(!page.children.is_empty())
    }

    /// The write invariants' link check of `group ∋ member` over this view
    /// (crate::invariants, docs/52 R13). Internal read of the whole
    /// membership graph (docs/questions/Q-487 item 4).
    /// Spec: as `Invariants::check_link`.
    pub(crate) fn check_link(
        &self,
        invariants: &Invariants,
        group: End<'_>,
        group_type: u32,
        member: End<'_>,
        member_class: ClassId,
        members_before: usize,
    ) -> Result<Option<LinkProof>, Stop> {
        invariants
            .check_link(
                self.view.authority_snapshot(),
                group,
                group_type,
                member,
                member_class,
                members_before,
            )
            .map_err(|f| fault_stop(&f))
    }

    /// `Lookup`'s locator: the object whose stored value of the unique
    /// attribute `attr` is `value` — through the unique index, then
    /// compared octet for octet (A-27, as the account source does). A value
    /// that cannot name anything (empty, longer than `max`, not printable
    /// ASCII) names nothing. Only a GUID comes back — the object itself
    /// reaches the reply only through the gate.
    /// Spec: docs/47 §1.3 steps 3-4 (R47-1); docs/46 §5.4 (bounds);
    /// docs/52 R-a.
    pub(crate) fn locate_exact(
        &self,
        attr: AttrId,
        value: &str,
        max: usize,
    ) -> Result<Option<Guid>, Stop> {
        if value.is_empty()
            || value.len() > max
            || !value.bytes().all(|b| (0x20..=0x7E).contains(&b))
        {
            return Ok(None);
        }
        let snapshot = self.view.authority_snapshot();
        let guid = match snapshot.lookup_unique(attr, value.as_bytes()) {
            Ok(Some(guid)) => guid,
            Ok(None) | Err(dirstore::Error::Rejected(_)) => return Ok(None),
            Err(e) => return Err(store_failure(&e)),
        };
        let Some(obj) = snapshot.get_object(guid).map_err(|e| store_failure(&e))? else {
            return Ok(None);
        };
        let stored = record::text(&obj, attr).map_err(malformed)?;
        Ok((stored == Some(value)).then_some(guid))
    }

    /// `true` if `r` must never be deleted or changed by the admin plane
    /// beyond what its operation allows: the krbtgt account (RID 502), a
    /// DC account (userAccountControl ST), a service object, the NC root —
    /// the write invariants' rule (crate::invariants, `Graph::is_structural`;
    /// docs/52 R13), over this view.
    /// Spec: docs/51 §5.2 rows 5, 6, 9, §4.3 step 5; [MS-SAMR] 3.1.1.6 items
    /// 14, 22; A-18, A-19, A-35; docs/47 §6.3 (ST ⇒ the DC).
    pub(crate) fn is_structural(&self, r: &Resolved) -> Result<bool, Stop> {
        self.is_structural_object(r.guid, &r.obj, r.class)
    }

    /// [`Cx::is_structural`] of an object given by its parts — a
    /// [`Resolved`]'s, or the requester's own account of a kpasswd change
    /// ([`OwnAccount`], task K6): the same rule, one implementation.
    /// Spec: as [`Cx::is_structural`].
    pub(crate) fn is_structural_object(
        &self,
        guid: Guid,
        obj: &Object,
        class: ClassId,
    ) -> Result<bool, Stop> {
        self.graph()
            .is_structural(guid, obj, class)
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
            store: self.view.authority_snapshot(),
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
        let snapshot = self.view.authority_snapshot();
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

/// The tombstone of `guid` in `view` — the source of dird's destroy
/// decision after a committed `Delete` (crate::key_requests,
/// `DirectoryAdmin::destruction_target`). Internal read: no requester.
/// Spec: docs/51 §6, §9; docs/52 §4.3; dirstore `Snapshot::get_tombstone`;
/// docs/questions/Q-486 (A-103).
pub(crate) fn tombstone(
    view: &DirectoryView<'_>,
    guid: Guid,
) -> dirstore::Result<Option<Tombstone>> {
    view.authority_snapshot().get_tombstone(guid)
}

/// One page of the tombstones in `view` after `after` (dird's
/// re-registration of destroy decisions, A-105). Internal read: no
/// requester.
/// Spec: docs/51 §6, §9; docs/52 §4.3; dirstore `Snapshot::tombstones`;
/// docs/questions/Q-470 item 4.
pub(crate) fn tombstones(
    view: &DirectoryView<'_>,
    after: Option<Guid>,
    limit: usize,
) -> dirstore::Result<TombstonePage> {
    view.authority_snapshot().tombstones(after, limit)
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
