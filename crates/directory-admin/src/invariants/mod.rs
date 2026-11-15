//! The write invariants: **one** checker every directory write passes — the
//! online write PEP's `apply` and `provision domain`'s store builder alike
//! (docs/52 §3.14, class C14; task R13, decision A-102).
//!
//! # The class and the root-level change (docs/CLEAN-ROOM.md)
//!
//! **Class C14 — a write invariant enforced on only one of the write
//! paths.** The [MS-SAMR] constraints (A-79), the name rules, the groupType
//! membership rules, the cycle refusal and the nesting-depth (≤ 16) and
//! closure (≤ 1024) bounds (A-89, A-95) were checks of the online PEP's
//! `prepare`; `provision domain` built its objects offline and called some
//! of the same helpers by hand. A second (or future) write path could skip
//! any of them.
//!
//! **The change.** dirstore's mutating calls — `create_object`,
//! `modify_object`, `delete_object`, `create_counter`,
//! `take_counter_value` — are reached, in this workspace's non-test code,
//! **only from this module** (pinned by `tests/single_write_path.rs`). An
//! object write is a [`CheckedWrite`], which only this module builds, after
//! every rule below passed against the write transaction's own state; it
//! commits only into a transaction whose change-seq counter is still the
//! state it was checked against, and it takes the write's change-seq — and
//! a security principal's RID — itself. So:
//!
//! - no write reaches the store without the checker: there is no other
//!   door, and the door asks for the proof;
//! - "every writer takes a change-seq" (A-89, docs/questions/Q-358 item 1 —
//!   what `apply`'s re-verification relies on) is no longer a convention:
//!   the one writer does it;
//! - "a RID is never used twice" ([MS-SAMR] 3.1.1.9.2.1 item 1.2) holds by
//!   construction: a principal's objectSid is always the domain SID ‖ a RID
//!   the counter just handed out (or the krbtgt exception's 502), and a
//!   supplied objectSid must be exactly that one;
//! - the provisioning exceptions exist only in the provisioning session
//!   ([`Provisioning`]), which can be opened on an **empty** store only and
//!   creates the counters itself (A-83: counters only at provisioning) — so
//!   no exception can ever be applied to a provisioned store.
//!
//! # The invariants
//!
//! **Per object** (module `object` — the record alone): the class (user,
//! computer, group, organizationalUnit, container; domainDNS only as the NC
//! root exception); the name rules (A-79: [MS-SAMR] 3.1.1.6 items 8-13, cn
//! = sAMAccountName, a computer's sAMAccountName = cn ‖ "$"); the reserved
//! name "krbtgt" (item 14); userAccountControl (items 20-24: N or N|D for a
//! user, WT or WT|D for a computer, krbtgt N alone, ST only as the DC
//! exception); accountExpires (R47-5b), pwdLastSet, groupType (docs/46
//! §8.2), userPrincipalName, dNSHostName, servicePrincipalName (Q-355),
//! description; only attributes the checker has a rule for; a change names
//! only the attributes an online operation writes, and userAccountControl
//! changes in ACCOUNTDISABLE only.
//!
//! **Store-wide** (module `graph` and this module — against the
//! transaction): a structural object (krbtgt, a DC account, a service
//! object, the NC root) is never changed, deleted or made a member; each
//! new `member` link obeys the membership rule of the group's type
//! ([MS-SAMR] 3.1.1.8.9), closes no cycle, keeps every nesting chain ≤ 16
//! and every closure ≤ 1024 groups (docs/47 §5.3); at most 4096 members; a
//! principal's objectSid extends the NC root's domain SID with a fresh RID.
//! **Left to dirstore** (already enforced at every write, by the store
//! itself): uniqueness of sAMAccountName / userPrincipalName /
//! servicePrincipalName / objectSid and of an RDN under its parent, the
//! parent's existence and class (possSuperiors), the schema's must / may
//! and value syntaxes.
//!
//! **Not here** (decisions of the requester's request, not invariants of
//! the store — they stay in the online PEP): visibility, the PDP decision,
//! dual control, the self-lockout guard, the policy-named objects (they
//! depend on the policy version, docs/47 §8.1).
//!
//! # Links checked once
//!
//! The online PEP's `prepare` runs the link walks against its snapshot and
//! keeps a [`LinkProof`] bound to that snapshot's change-seq state; at the
//! write, the same rules run again except the walks, which a proof for the
//! same link and the same state replaces (the state is unchanged, so their
//! answer is). Without a matching proof — `provision domain`, or a stale
//! state — the walks run against the transaction. Several new links of one
//! write all enter the same group, so each is checked against the store
//! without the others exactly: a chain or a closure through two new links
//! into one group would pass through that group twice, i.e. close a cycle.
//!
//! Spec: docs/52 §3.14, §7 (R13); docs/CLEAN-ROOM.md; A-79, A-83, A-89, A-92,
//! A-95, A-102; docs/51 §4.3 step 5, §5.2, §8.3, §11; docs/46 §4.4, §5.4,
//! §8.2-§8.5; docs/47 §5.3; [MS-SAMR] v20260427 2.2.1.14, 3.1.1.6,
//! 3.1.1.8.9, 3.1.1.9.2; docs/questions/Q-298, Q-355..Q-358, Q-376, Q-416,
//! Q-505..Q-507.

mod graph;
mod object;
mod provisioning;

use std::collections::BTreeSet;

use ad_schema::Phase1Schema;
use dirstore::{
    AttrId, AttrStamp, Attribute, AttributeChange, ChildPage, ClassId, CounterState, NewObject,
    NodeId, Object, Origin, Schema, Snapshot, StampedValue, Timestamp, WriteTxn,
    MAX_VALUES_PER_ATTRIBUTE,
};
use dtyp::{Guid, Sid, GUID_PACKET_LEN};

pub(crate) use graph::{End, Graph, MAX_WALK_STEPS};
pub use provisioning::{Provisioning, ProvisioningError, ProvisioningRole};

use crate::config::{ConfigError, CHANGE_SEQ_COUNTER, RID_COUNTER, RID_END_EXCLUSIVE, RID_FIRST};
use crate::ids::Ids;
use crate::record;

/// Why the checker refused a write: the invariant it broke. Names the rule,
/// never a value.
/// Spec: module documentation, "The invariants".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvariantViolation {
    /// A class no write path creates there (domainDNS outside the NC-root
    /// exception, an object without parent, a class outside phase 1).
    Class,
    /// A provisioning exception claimed by an object it does not fit, more
    /// than once, or outside the provisioning session.
    Exception,
    /// A name rule ([MS-SAMR] 3.1.1.6 items 8-13; A-79; Q-355).
    Name,
    /// The reserved name "krbtgt" on another object, or the krbtgt
    /// exception without it ([MS-SAMR] 3.1.1.6 item 14).
    ReservedName,
    /// userAccountControl ([MS-SAMR] 3.1.1.6 items 19-24; A-79).
    AccountControl,
    /// A value form (accountExpires, pwdLastSet, groupType,
    /// userPrincipalName, dNSHostName, servicePrincipalName, description).
    Value,
    /// objectSid: not the domain SID ‖ a RID the counter handed out
    /// ([MS-SAMR] 3.1.1.9.2).
    Sid,
    /// An attribute no write path writes there.
    NotModifiable,
    /// A structural object as the target of a change or a delete, or as a
    /// member (docs/51 §5.2 row 9; Q-356 item 2).
    Protected,
    /// A membership rule: the group's type ([MS-SAMR] 3.1.1.8.9), a
    /// repeated member, more than 4096 members, a cycle, a nesting chain
    /// over 16 or a closure over 1024 groups (docs/47 §5.3; A-89, A-95).
    Membership,
    /// The object written, or a member named, does not exist.
    NoSuchObject,
}

/// Why a check could not decide: a store read failed, a stored record is
/// inconsistent, or something the store must hold is missing.
#[derive(Debug)]
pub(crate) enum Fault {
    /// The store could not answer.
    Store(dirstore::Error),
    /// A stored record does not have the form its class requires.
    Integrity,
    /// The change-seq counter or the NC root's domain SID is missing.
    Missing,
}

/// A check that did not pass: a rule refused the write, or no decision was
/// possible (fail closed).
#[derive(Debug)]
pub(crate) enum Refused {
    /// An invariant refused it.
    Rule(InvariantViolation),
    /// The store failed.
    Fault(Fault),
}

impl From<Fault> for Refused {
    fn from(fault: Fault) -> Refused {
        Refused::Fault(fault)
    }
}

impl From<InvariantViolation> for Refused {
    fn from(rule: InvariantViolation) -> Refused {
        Refused::Rule(rule)
    }
}

/// What the checker reads: a committed snapshot or a write transaction
/// (its own earlier writes included). Not public — only this crate checks.
/// Spec: dirstore `Snapshot` / `WriteTxn` (the same read API).
pub(crate) trait StoreRead {
    /// The live object `guid`.
    fn object(&self, guid: Guid) -> dirstore::Result<Option<Object>>;
    /// The sources of the back links of `back_attr` to `target`.
    fn back_links(&self, target: Guid, back_attr: AttrId) -> dirstore::Result<Vec<Guid>>;
    /// The counter `name`.
    fn counter(&self, name: &str) -> dirstore::Result<Option<CounterState>>;
    /// The first `limit` live children of `parent` (`None`: the roots).
    fn children(&self, parent: Option<Guid>, limit: usize) -> dirstore::Result<ChildPage>;
}

impl StoreRead for Snapshot<'_> {
    fn object(&self, guid: Guid) -> dirstore::Result<Option<Object>> {
        self.get_object(guid)
    }
    fn back_links(&self, target: Guid, back_attr: AttrId) -> dirstore::Result<Vec<Guid>> {
        Snapshot::back_links(self, target, back_attr)
    }
    fn counter(&self, name: &str) -> dirstore::Result<Option<CounterState>> {
        Snapshot::counter(self, name)
    }
    fn children(&self, parent: Option<Guid>, limit: usize) -> dirstore::Result<ChildPage> {
        Snapshot::children(self, parent, None, limit)
    }
}

impl StoreRead for WriteTxn<'_> {
    fn object(&self, guid: Guid) -> dirstore::Result<Option<Object>> {
        self.get_object(guid)
    }
    fn back_links(&self, target: Guid, back_attr: AttrId) -> dirstore::Result<Vec<Guid>> {
        WriteTxn::back_links(self, target, back_attr)
    }
    fn counter(&self, name: &str) -> dirstore::Result<Option<CounterState>> {
        WriteTxn::counter(self, name)
    }
    fn children(&self, parent: Option<Guid>, limit: usize) -> dirstore::Result<ChildPage> {
        WriteTxn::children(self, parent, None, limit)
    }
}

/// The store as it is just before `creating` is created: nothing links to
/// `creating` yet (dirstore refuses an ObjectRef to an object that is not
/// live — docs/46 §8.4), so its back links are none, while dirstore itself
/// refuses to list the back links of an object it does not hold.
/// Spec: docs/46 §8.4 ("writing an ObjectRef: the target lives in the same
/// store, else Violation"); dirstore `back_links` (`NoSuchObject`).
struct Creating<'r, R: ?Sized> {
    store: &'r R,
    creating: Guid,
}

impl<R: StoreRead + ?Sized> StoreRead for Creating<'_, R> {
    fn object(&self, guid: Guid) -> dirstore::Result<Option<Object>> {
        self.store.object(guid)
    }
    fn back_links(&self, target: Guid, back_attr: AttrId) -> dirstore::Result<Vec<Guid>> {
        if target == self.creating {
            return Ok(Vec::new());
        }
        self.store.back_links(target, back_attr)
    }
    fn counter(&self, name: &str) -> dirstore::Result<Option<CounterState>> {
        self.store.counter(name)
    }
    fn children(&self, parent: Option<Guid>, limit: usize) -> dirstore::Result<ChildPage> {
        self.store.children(parent, limit)
    }
}

/// The answer of the link walks (cycle, nesting depth, closure size) for
/// `group ∋ member`, valid for the store state whose change-seq counter is
/// `basis`. Built only by [`Invariants::check_link`]; its fields have no
/// constructor outside this module.
/// Spec: module documentation, "Links checked once".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkProof {
    group: Guid,
    member: Guid,
    basis: Option<CounterState>,
}

/// Where a new principal's RID comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RidSource {
    /// The RID counter, taken at the commit.
    Counter,
    /// DOMAIN_USER_RID_KRBTGT (the krbtgt exception).
    Krbtgt,
}

/// The write a [`CheckedWrite`] carries.
#[derive(Debug)]
enum Op {
    Create {
        new: NewObject,
        /// For a security principal: the RID's source and the domain SID.
        principal: Option<(RidSource, Sid)>,
        object_sid: AttrId,
    },
    Modify {
        target: Guid,
        changes: Vec<AttributeChange>,
    },
    Delete {
        target: Guid,
    },
}

/// A write every rule passed, against the transaction state whose
/// change-seq counter is `basis` (module documentation). Built only by the
/// checks of [`Invariants`]; the only way to dirstore's object writes.
#[derive(Debug)]
pub(crate) struct CheckedWrite {
    basis: CounterState,
    op: Op,
}

/// What a commit allocated: the RID and objectSid of a new principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Committed {
    pub(crate) rid: Option<u32>,
    pub(crate) sid: Option<Sid>,
}

/// Why a checked write did not commit. Every variant leaves the
/// transaction to be aborted by the caller (dirstore: a failed step may
/// poison it; A-83: abort when the create is refused).
#[derive(Debug)]
pub(crate) enum CommitError {
    /// The change-seq counter moved since the check: not the checked state.
    Stale,
    /// The change-seq counter could not be read.
    Counter(dirstore::Error),
    /// The RID counter refused a take.
    Rid(dirstore::Error),
    /// The RID taken lies outside `[RID_FIRST, RID_END_EXCLUSIVE)`.
    RidRange,
    /// The objectSid could not be formed, or a supplied one is not the
    /// domain SID ‖ the RID this commit allocated.
    Sid,
    /// The change-seq counter refused a take.
    ChangeSeq(dirstore::Error),
    /// dirstore refused the write itself.
    Write(dirstore::Error),
}

impl CheckedWrite {
    /// Commit this write into `txn` — the transaction it was checked in:
    /// refused if the change-seq counter is no longer the checked state;
    /// for a security principal, the RID from the counter (or the krbtgt
    /// exception's 502) and the objectSid it forms; the change-seq of the
    /// write's `Origin` (with `wall_clock` and `origin_node`); then the one
    /// dirstore call.
    /// Spec: module documentation; docs/51 §8.3 (RID and change-seq from
    /// the counters, in the creation's own `WriteTxn`); A-75; A-83; A-89
    /// (Q-358 item 1); [MS-SAMR] 3.1.1.9.2, 3.1.1.9.2.1 item 1.2; docs/29 §2
    /// as cited in docs/51 §8.3.
    pub(crate) fn commit(
        self,
        txn: &mut WriteTxn<'_>,
        wall_clock: Timestamp,
        origin_node: NodeId,
    ) -> Result<Committed, CommitError> {
        let current = txn
            .counter(CHANGE_SEQ_COUNTER)
            .map_err(CommitError::Counter)?;
        if current != Some(self.basis) {
            return Err(CommitError::Stale);
        }
        match self.op {
            Op::Create {
                mut new,
                principal,
                object_sid,
            } => {
                let mut committed = Committed {
                    rid: None,
                    sid: None,
                };
                if let Some((source, domain)) = principal {
                    let rid = match source {
                        RidSource::Krbtgt => graph::DOMAIN_USER_RID_KRBTGT,
                        RidSource::Counter => {
                            let value = txn
                                .take_counter_value(RID_COUNTER)
                                .map_err(CommitError::Rid)?;
                            if !(RID_FIRST..RID_END_EXCLUSIVE).contains(&value) {
                                return Err(CommitError::RidRange);
                            }
                            u32::try_from(value).map_err(|_| CommitError::RidRange)?
                        }
                    };
                    let mut sub = domain.sub_authority().to_vec();
                    sub.push(rid);
                    let sid = Sid::new(domain.identifier_authority(), &sub)
                        .map_err(|_| CommitError::Sid)?;
                    let encoded = vec![sid.encode()];
                    match new.attributes.iter().find(|(id, _)| *id == object_sid) {
                        Some((_, supplied)) if *supplied == encoded => {}
                        Some(_) => return Err(CommitError::Sid),
                        None => new.attributes.push((object_sid, encoded)),
                    }
                    committed = Committed {
                        rid: Some(rid),
                        sid: Some(sid),
                    };
                }
                let origin = take_origin(txn, wall_clock, origin_node)?;
                txn.create_object(new, &origin)
                    .map_err(CommitError::Write)?;
                Ok(committed)
            }
            Op::Modify { target, changes } => {
                let origin = take_origin(txn, wall_clock, origin_node)?;
                txn.modify_object(target, changes, &origin)
                    .map_err(CommitError::Write)?;
                Ok(Committed {
                    rid: None,
                    sid: None,
                })
            }
            Op::Delete { target } => {
                let origin = take_origin(txn, wall_clock, origin_node)?;
                txn.delete_object(target, &origin)
                    .map_err(CommitError::Write)?;
                Ok(Committed {
                    rid: None,
                    sid: None,
                })
            }
        }
    }
}

/// The `Origin` of one write: the next change-seq, taken in `txn`.
/// Spec: docs/51 §8.3 ("change-seq — the same mechanism"); docs/29 §2 as
/// cited there; A-89 (every writer takes a change-seq); dirstore `Origin`.
fn take_origin(
    txn: &mut WriteTxn<'_>,
    wall_clock: Timestamp,
    origin_node: NodeId,
) -> Result<Origin, CommitError> {
    let origin_seq = txn
        .take_counter_value(CHANGE_SEQ_COUNTER)
        .map_err(CommitError::ChangeSeq)?;
    Ok(Origin {
        wall_clock,
        origin_node,
        origin_seq,
    })
}

/// The record a write will produce, for the rules that read it: the new
/// object's values (or the current record with the changes applied), each
/// stamped with a placeholder the rules never read, attributes and values
/// in the store's canonical order (so `record`'s readers find them).
/// Repeated attribute ids are refused (no write path writes one twice).
/// Spec: dirstore `Object` (attributes ascending by id, values ascending,
/// classes ascending); `NewObject`.
fn draft(
    guid: Guid,
    parent: Option<Guid>,
    classes: &[ClassId],
    attributes: &[(AttrId, Vec<Vec<u8>>)],
) -> Result<Object, InvariantViolation> {
    let stamp = AttrStamp {
        version: 0,
        wall_clock: Timestamp(0),
        origin_node: NodeId([0; 16]),
        origin_seq: 0,
    };
    let mut classes = classes.to_vec();
    classes.sort_unstable();
    classes.dedup();
    let mut out: Vec<Attribute> = Vec::with_capacity(attributes.len());
    for (id, values) in attributes {
        if values.is_empty() {
            continue;
        }
        let mut values: Vec<StampedValue> = values
            .iter()
            .map(|value| StampedValue {
                value: value.clone(),
                stamp,
            })
            .collect();
        values.sort_by(|a, b| a.value.cmp(&b.value));
        out.push(Attribute { id: *id, values });
    }
    out.sort_by_key(|a| a.id);
    if out.windows(2).any(|w| matches!(w, [a, b] if a.id == b.id)) {
        return Err(InvariantViolation::Value);
    }
    Ok(Object {
        guid,
        parent,
        rdn: Vec::new(),
        classes,
        attributes: out,
        tombstone: None,
    })
}

/// The members a `member` value set names, refused if a value is not a
/// GUID, if one repeats, or if there are more than the store holds.
/// Spec: docs/46 §2.3 item 1, §8.1 (ObjectRef = the 16-octet GUID); dirstore
/// `MAX_VALUES_PER_ATTRIBUTE` (4096 — docs/46 §2.3, docs/51 §11);
/// docs/questions/Q-356 item 3 (a member is not added twice).
fn member_set(values: &[Vec<u8>]) -> Result<Vec<Guid>, InvariantViolation> {
    if values.len() > MAX_VALUES_PER_ATTRIBUTE {
        return Err(InvariantViolation::Membership);
    }
    let mut seen = BTreeSet::new();
    let mut members = Vec::with_capacity(values.len());
    for value in values {
        let packet = <&[u8; GUID_PACKET_LEN]>::try_from(value.as_slice())
            .map_err(|_| InvariantViolation::Value)?;
        if !seen.insert(*packet) {
            return Err(InvariantViolation::Membership);
        }
        members.push(Guid::from_packet(packet));
    }
    Ok(members)
}

/// The checker: the schema identifiers, the schema, and the protected
/// service objects (the online PEP's configuration; the provisioning
/// session's own registrations).
#[derive(Debug, Clone)]
pub(crate) struct Invariants {
    ids: Ids,
    schema: Schema,
    service_objects: BTreeSet<Guid>,
}

impl Invariants {
    /// The checker for the phase-1 schema with these protected service
    /// objects. Fails closed if the schema lacks a name it needs.
    /// Spec: docs/46 §4.4, §5.4; docs/51 §5.2 row 9.
    pub(crate) fn new(
        schema: &Phase1Schema,
        service_objects: BTreeSet<Guid>,
    ) -> Result<Invariants, ConfigError> {
        Ok(Invariants {
            ids: Ids::resolve(schema)?,
            schema: schema.schema().clone(),
            service_objects,
        })
    }

    /// The rules of module `graph` over `store`.
    pub(crate) fn graph<'g, R: StoreRead + ?Sized>(&'g self, store: &'g R) -> Graph<'g, R> {
        Graph {
            ids: &self.ids,
            schema: &self.schema,
            service_objects: &self.service_objects,
            store,
        }
    }

    /// The change-seq counter's state: the basis of every proof.
    fn basis<R: StoreRead + ?Sized>(store: &R) -> Result<CounterState, Fault> {
        store
            .counter(CHANGE_SEQ_COUNTER)
            .map_err(Fault::Store)?
            .ok_or(Fault::Missing)
    }

    /// The domain SID: the objectSid of the one NC root.
    /// Spec: docs/51 §8.3 ("objectSid = the domain SID (from the NC root's
    /// objectSid) ‖ RID"); [MS-SAMR] 3.1.1.9.2; OD-2 (one domain, one NC).
    fn domain_sid<R: StoreRead + ?Sized>(&self, store: &R) -> Result<Sid, Fault> {
        let roots = store.children(None, 2).map_err(Fault::Store)?;
        let [root] = roots.children.as_slice() else {
            return Err(Fault::Missing);
        };
        let root = store
            .object(*root)
            .map_err(Fault::Store)?
            .ok_or(Fault::Missing)?;
        record::sid(&root, self.ids.object_sid)
            .map_err(|_| Fault::Integrity)?
            .ok_or(Fault::Missing)
    }

    /// The online PEP's link check of `group ∋ member` (`group_type` the
    /// group's groupType, `members_before` its member count), in the order
    /// `prepare` refuses: the membership rule of the group's type, the
    /// member limit, the cycle, the expansion bounds. `None` = refuse
    /// (`MembershipInvalid`); otherwise the walks' [`LinkProof`] for the
    /// write.
    /// Spec: [MS-SAMR] 3.1.1.8.9; docs/51 §5.2 row 8, §11; docs/46 §2.3
    /// item 5; docs/47 §5.3 items 1, 3-4; A-79; A-89; A-95;
    /// docs/questions/Q-356 items 4-5, Q-416.
    pub(crate) fn check_link<R: StoreRead + ?Sized>(
        &self,
        store: &R,
        group: End<'_>,
        group_type: u32,
        member: End<'_>,
        member_class: ClassId,
        members_before: usize,
    ) -> Result<Option<LinkProof>, Fault> {
        let graph = self.graph(store);
        if !graph.member_allowed(group_type, member.obj, member_class)?
            || members_before >= MAX_VALUES_PER_ATTRIBUTE
            || graph.closes_cycle(group.guid, member.guid)?
            || !graph.expansion_allowed(group, member)?
        {
            return Ok(None);
        }
        let basis = store.counter(CHANGE_SEQ_COUNTER).map_err(Fault::Store)?;
        Ok(Some(LinkProof {
            group: group.guid,
            member: member.guid,
            basis,
        }))
    }

    /// The rules of one new link `group ∋ member` at the write, against
    /// `txn` at `basis`: the member exists and is not structural, the
    /// group's type admits it, and — unless a proof for this link and this
    /// state is given — no cycle and both expansion bounds.
    /// Spec: as [`Invariants::check_link`]; docs/questions/Q-356 item 2.
    fn link_at_write<R: StoreRead + ?Sized>(
        &self,
        txn: &R,
        basis: CounterState,
        group: End<'_>,
        group_type: u32,
        member: Guid,
        proofs: &[LinkProof],
    ) -> Result<(), Refused> {
        let graph = self.graph(txn);
        let obj = txn
            .object(member)
            .map_err(Fault::Store)?
            .ok_or(InvariantViolation::NoSuchObject)?;
        let class = graph.class_of(&obj)?;
        if graph.is_structural(member, &obj, class)? {
            return Err(InvariantViolation::Protected.into());
        }
        if !graph.member_allowed(group_type, &obj, class)? {
            return Err(InvariantViolation::Membership.into());
        }
        let proved = proofs
            .iter()
            .any(|p| p.group == group.guid && p.member == member && p.basis == Some(basis));
        if !proved {
            let end = End {
                guid: member,
                obj: &obj,
            };
            if graph.closes_cycle(group.guid, member)? || !graph.expansion_allowed(group, end)? {
                return Err(InvariantViolation::Membership.into());
            }
        }
        Ok(())
    }

    /// The new links of a write to the group `group` (record `obj` as it
    /// will be, for its groupType), whose member values become `values`
    /// and were `before`: every value checked as a set (module
    /// documentation), every value not in `before` as a new link.
    fn new_links<R: StoreRead + ?Sized>(
        &self,
        txn: &R,
        basis: CounterState,
        group: End<'_>,
        before: &[Guid],
        values: &[Vec<u8>],
        proofs: &[LinkProof],
    ) -> Result<(), Refused> {
        let members = member_set(values)?;
        if members.iter().all(|m| before.contains(m)) {
            return Ok(());
        }
        let group_type = record::flags(group.obj, self.ids.group_type)
            .map_err(|_| Fault::Integrity)?
            .ok_or(InvariantViolation::Value)?;
        for member in members.into_iter().filter(|m| !before.contains(m)) {
            self.link_at_write(txn, basis, group, group_type, member, proofs)?;
        }
        Ok(())
    }

    /// Check the create of `new` in `txn` (module documentation): the
    /// per-object rules on the record it will have, for the exception
    /// `role` it claims (`None` except in the provisioning session), its
    /// `member` links against `txn` (`proofs` from the PEP, if any), and —
    /// for a security principal — the domain SID its objectSid will
    /// extend. A supplied objectSid is verified at the commit.
    /// Spec: module documentation; docs/51 §5.2 rows 1-4, §4.3 step 5, §8.3.
    pub(crate) fn check_create(
        &self,
        txn: &WriteTxn<'_>,
        new: NewObject,
        role: Option<ProvisioningRole>,
        proofs: &[LinkProof],
    ) -> Result<CheckedWrite, Refused> {
        let basis = Self::basis(txn)?;
        let obj = draft(new.guid, new.parent, &new.classes, &new.attributes)?;
        let class = self
            .schema
            .most_specific_class(&obj.classes)
            .ok_or(InvariantViolation::Class)?;
        object::check_new(&self.ids, &obj, class, role)?;
        let principal_class = [self.ids.user.id, self.ids.computer.id, self.ids.group.id];
        let principal = if principal_class.contains(&class) {
            let source = if role == Some(ProvisioningRole::Krbtgt) {
                RidSource::Krbtgt
            } else {
                RidSource::Counter
            };
            // A supplied objectSid must be exactly the one the commit forms
            // (verified there, after the RID is taken).
            Some((source, self.domain_sid(txn)?))
        } else {
            if class != self.ids.domain_dns.id && obj.attribute(self.ids.object_sid).is_some() {
                return Err(InvariantViolation::Sid.into());
            }
            None
        };
        if let Some(values) = obj.attribute(self.ids.member) {
            let values: Vec<Vec<u8>> = values.values.iter().map(|v| v.value.clone()).collect();
            let end = End {
                guid: new.guid,
                obj: &obj,
            };
            let before = Creating {
                store: txn,
                creating: new.guid,
            };
            self.new_links(&before, basis, end, &[], &values, proofs)?;
        }
        Ok(CheckedWrite {
            basis,
            op: Op::Create {
                new,
                principal,
                object_sid: self.ids.object_sid,
            },
        })
    }

    /// Check a change of `target` in `txn`: the target exists and is not
    /// structural, each change keeps the per-object rules of the attribute
    /// it changes, and a new `member` set's new links pass the store-wide
    /// rules (`proofs` from the PEP, if any).
    /// Spec: module documentation; docs/51 §5.2 rows 5-8.
    pub(crate) fn check_modify(
        &self,
        txn: &WriteTxn<'_>,
        target: Guid,
        changes: Vec<AttributeChange>,
        proofs: &[LinkProof],
    ) -> Result<CheckedWrite, Refused> {
        let basis = Self::basis(txn)?;
        let graph = self.graph(txn);
        let current = txn
            .get_object(target)
            .map_err(Fault::Store)?
            .ok_or(InvariantViolation::NoSuchObject)?;
        let class = graph.class_of(&current)?;
        if graph.is_structural(target, &current, class)? {
            return Err(InvariantViolation::Protected.into());
        }
        let mut named: BTreeSet<AttrId> = BTreeSet::new();
        for change in &changes {
            let AttributeChange::Replace { id, values } = change;
            if !named.insert(*id) {
                return Err(InvariantViolation::NotModifiable.into());
            }
            object::check_change(&self.ids, &current, class, *id, values)?;
            if *id == self.ids.member {
                let before =
                    record::refs(&current, self.ids.member).map_err(|_| Fault::Integrity)?;
                let end = End {
                    guid: target,
                    obj: &current,
                };
                self.new_links(txn, basis, end, &before, values, proofs)?;
            }
        }
        Ok(CheckedWrite {
            basis,
            op: Op::Modify { target, changes },
        })
    }

    /// Check the delete of `target` in `txn`: it exists and is not
    /// structural (dirstore refuses a delete with live children itself).
    /// Spec: docs/51 §5.2 row 9; A-18; docs/questions/Q-356 items 2, 6.
    pub(crate) fn check_delete(
        &self,
        txn: &WriteTxn<'_>,
        target: Guid,
    ) -> Result<CheckedWrite, Refused> {
        let basis = Self::basis(txn)?;
        let graph = self.graph(txn);
        let current = txn
            .get_object(target)
            .map_err(Fault::Store)?
            .ok_or(InvariantViolation::NoSuchObject)?;
        let class = graph.class_of(&current)?;
        if graph.is_structural(target, &current, class)? {
            return Err(InvariantViolation::Protected.into());
        }
        Ok(CheckedWrite {
            basis,
            op: Op::Delete { target },
        })
    }
}

#[cfg(test)]
mod tests;
