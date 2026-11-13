//! `apply`: the write of a prepared operation, inside the caller's
//! `WriteTxn`, after auditd acknowledged the decision event.
//!
//! # What `apply` re-verifies
//!
//! The caller holds dirstore's single writer (redb: "Only a single write
//! may be in progress at a time", as recorded in Q-330 item 9). `prepare`
//! read ONE snapshot; between that snapshot and this transaction another
//! write may have committed if the caller took the snapshot first. `apply`
//! therefore re-verifies, inside the transaction and before writing:
//!
//! 1. **Nothing was committed since `prepare`'s snapshot**: the change-seq
//!    counter's state equals the one `prepare` saw. Every directory write
//!    takes a change-seq value (this crate, and `provision domain` offline;
//!    phase 1 has no other writer — A-48), so equal states mean the
//!    transaction starts from exactly the state every `prepare` check read:
//!    the PDP inputs (descriptors, classes, the requester's and approvers'
//!    groups and tiers), the dual-control classification, the membership
//!    rules and the cycle refusal, the self-lockout count, and the
//!    uniqueness and name pre-checks. A difference ⇒ `Conflict`.
//! 2. **Every object the write depends on is unchanged**, compared as whole
//!    records including every attribute stamp (the target; the parent and
//!    the NC root of a create; the group and the member of a membership
//!    change) — a second guard that does not depend on the change-seq
//!    convention. Gone ⇒ `NotFound`; different ⇒ `Conflict`.
//! 3. **The counters**: the change-seq and (for a security principal) the
//!    RID counter exist, are not exhausted and verify (dirstore's tag); the
//!    RID lies in `[1101, 0x3FFFFFFF)`. Missing ⇒ `Failed(StoreFailure)`,
//!    tampered ⇒ `Failed(IntegrityFailure)`, RID range exhausted ⇒
//!    `RidExhausted` (A-83: refusal, never re-created).
//! 4. **The new object's descriptor** is recomputed from the parent read in
//!    this transaction and must still have a DACL ([MS-ADTS] 6.1.3 item 7).
//! 5. **Uniqueness and names**: dirstore's unique index (sAMAccountName,
//!    userPrincipalName, servicePrincipalName, objectSid) and name index
//!    refuse a duplicate in the same transaction (`Conflict`); a GUID held
//!    by any live object or tombstone is never reused.
//!
//! The policy version is not re-verified: the caller passes `apply` the
//! operation `prepare` decided against its policy snapshot, and a policy
//! change needs a restart in phase 1 (A-69, A-80).
//!
//! On `Err`, writes may already have been made in the transaction (counter
//! values taken, a partial plan applied): the caller must **abort** it
//! (drop it or call `abort`), never commit it — then nothing is consumed
//! (A-83: "abort the transaction when the object create is refused").
//!
//! Spec: docs/51 §7.4 step 5, §8.3, §10; A-75; A-83 (caller rules); A-84;
//! docs/questions/Q-358 items 1-2;
//! [MS-ADTS] 3.1.1.5.2.4 (objectGUID, never NULL; whenCreated = the current
//! time); [MS-SAMR] 3.1.1.9.2 (objectSid = domain SID ‖ RID), 3.1.1.9.2.1
//! item 1.2.

use dirstore::{AttributeChange, NewObject, Origin, WriteTxn};
use dtyp::{Guid, Sid, GUID_PACKET_LEN};
use ipc_audit::{AdminFailure, AdminRefusal, Allocation, DirAdminEvent};
use krb_proto::KerberosTime;

use crate::admin::{CreatePlan, DirectoryAdmin, Plan, Prepared, WriteKind, WritePlan};
use crate::audit::{Refusal, Stop};
use crate::checks::{domain_sid, store_failure};
use crate::config::{CHANGE_SEQ_COUNTER, RID_COUNTER, RID_END_EXCLUSIVE, RID_FIRST};
use crate::descriptor::new_object_sd;
use crate::random::RandomSource;
use crate::record;
use crate::reply::Reply;
use crate::time;

/// A write that was applied in the caller's transaction (not yet
/// committed): the outcome event to send **after** the commit, the event to
/// send instead if the commit fails, and the reply.
/// Spec: docs/51 §5.7 item 2, §7.4 steps 5-6; A-85.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    outcome: DirAdminEvent,
    commit_failure: DirAdminEvent,
    reply: Reply,
}

impl Applied {
    /// The `Outcome` event (`Committed`), to send after the commit.
    #[must_use]
    pub fn outcome_event(&self) -> &DirAdminEvent {
        &self.outcome
    }

    /// The `Outcome` event (`Failed(StoreFailure)`) to send instead when the
    /// commit fails.
    #[must_use]
    pub fn commit_failure_event(&self) -> &DirAdminEvent {
        &self.commit_failure
    }

    /// The reply.
    #[must_use]
    pub fn reply(&self) -> &Reply {
        &self.reply
    }
}

/// A write error of dirstore, as a refusal or failure of the outcome.
/// Spec: dirstore `Error`; crate ipc-audit `AdminRefusal` / `AdminFailure`.
fn write_failure(e: &dirstore::Error) -> Stop {
    match e {
        dirstore::Error::NameExists
        | dirstore::Error::ValueNotUnique(_)
        | dirstore::Error::HasChildren => Stop::Refused(AdminRefusal::Conflict),
        dirstore::Error::NoSuchParent
        | dirstore::Error::NoSuchObject
        | dirstore::Error::NoSuchTarget(_) => Stop::Refused(AdminRefusal::NotFound),
        dirstore::Error::Rejected(_) => Stop::Refused(AdminRefusal::ValueInvalid),
        dirstore::Error::ObjectExists => Stop::Failed(AdminFailure::InternalFailure),
        other => store_failure(other),
    }
}

/// A counter error. Spec: A-83 ("NoSuchCounter / CounterExhausted / Tamper
/// ⇒ refusal"); docs/51 §8.3.
fn counter_failure(e: &dirstore::Error, exhausted: Stop) -> Stop {
    match e {
        dirstore::Error::CounterExhausted => exhausted,
        dirstore::Error::NoSuchCounter => Stop::Failed(AdminFailure::StoreFailure),
        other => store_failure(other),
    }
}

impl<R: RandomSource> DirectoryAdmin<R> {
    /// Apply a prepared write inside `txn` (module documentation): the GUID
    /// from the random source, the RID and the change-seq from the
    /// counters, the security descriptor, then the create / modify /
    /// delete. `now` is the time of the write (whenCreated, whenChanged,
    /// pwdLastSet, the outcome event).
    ///
    /// Call it only after auditd acknowledged the decision event; commit
    /// `txn` on `Ok` and send [`Applied::outcome_event`] (or
    /// [`Applied::commit_failure_event`] if the commit fails); on `Err`
    /// abort `txn` and send the refusal's event. An operation that commits
    /// nothing (`Prepared::writes` is `false`) is refused here.
    ///
    /// Spec: docs/51 §7.4 step 5; A-75; A-83; A-84; A-85.
    pub fn apply(
        &mut self,
        prepared: Prepared,
        txn: &mut WriteTxn<'_>,
        now: &KerberosTime,
    ) -> Result<Applied, Refusal> {
        let Prepared {
            base,
            requester,
            plan,
            ..
        } = prepared;
        let Plan::Write(write) = plan else {
            return Err(base.outcome_refusal(now, Stop::Failed(AdminFailure::InternalFailure)));
        };
        match self.write(&requester, write, txn, now) {
            Ok((allocated, reply)) => Ok(Applied {
                outcome: base.committed(now, allocated),
                commit_failure: base
                    .outcome_refusal(now, Stop::Failed(AdminFailure::StoreFailure))
                    .into_event(),
                reply,
            }),
            Err(stop) => Err(base.outcome_refusal(now, stop)),
        }
    }

    /// Re-verify (module documentation, items 1-2) and write.
    fn write(
        &mut self,
        requester: &Sid,
        write: WritePlan,
        txn: &mut WriteTxn<'_>,
        now: &KerberosTime,
    ) -> Result<(Option<Allocation>, Reply), Stop> {
        // 1. Nothing committed since prepare's snapshot.
        let change_seq = txn
            .counter(CHANGE_SEQ_COUNTER)
            .map_err(|e| store_failure(&e))?
            .ok_or(Stop::Failed(AdminFailure::StoreFailure))?;
        if change_seq != write.change_seq {
            return Err(Stop::Refused(AdminRefusal::Conflict));
        }
        // 2. Every object the write depends on is unchanged.
        for (guid, seen) in &write.seen {
            match txn.get_object(*guid).map_err(|e| store_failure(&e))? {
                None => return Err(Stop::Refused(AdminRefusal::NotFound)),
                Some(current) if current != *seen => {
                    return Err(Stop::Refused(AdminRefusal::Conflict))
                }
                Some(_) => {}
            }
        }
        let dstime = time::dstime(now).ok_or(Stop::Failed(AdminFailure::InternalFailure))?;
        let when_changed = AttributeChange::Replace {
            id: self.ids.when_changed,
            values: vec![record::encode_int64(dstime)],
        };
        match write.kind {
            WriteKind::Create(plan) => {
                self.write_create(requester, plan, &write.seen, txn, now, dstime)
            }
            WriteKind::PasswordSet { target, reply } => {
                // pwdLastSet = now (A-79; docs/47 §9.2 step 2).
                let filetime =
                    time::filetime(now).ok_or(Stop::Failed(AdminFailure::InternalFailure))?;
                let changes = vec![
                    AttributeChange::Replace {
                        id: self.ids.pwd_last_set,
                        values: vec![record::encode_int64(filetime)],
                    },
                    when_changed,
                ];
                self.modify(txn, now, target, changes)?;
                Ok((None, Reply::PasswordSet(reply)))
            }
            WriteKind::SetUac { target, uac } => {
                let changes = vec![
                    AttributeChange::Replace {
                        id: self.ids.user_account_control,
                        values: vec![record::encode_flags(uac)],
                    },
                    when_changed,
                ];
                self.modify(txn, now, target, changes)?;
                Ok((None, Reply::Done))
            }
            WriteKind::SetAccountExpires { target, value } => {
                let changes = vec![
                    AttributeChange::Replace {
                        id: self.ids.account_expires,
                        values: vec![record::encode_int64(value)],
                    },
                    when_changed,
                ];
                self.modify(txn, now, target, changes)?;
                Ok((None, Reply::Done))
            }
            WriteKind::SetMembers { group, members } => {
                let changes = vec![
                    AttributeChange::Replace {
                        id: self.ids.member,
                        values: members.into_iter().map(record::encode_ref).collect(),
                    },
                    when_changed,
                ];
                self.modify(txn, now, group, changes)?;
                Ok((None, Reply::Done))
            }
            WriteKind::Delete { target } => {
                let origin = self.origin(txn, now)?;
                txn.delete_object(target, &origin)
                    .map_err(|e| write_failure(&e))?;
                Ok((None, Reply::Done))
            }
        }
    }

    /// The `Origin` of this write: `now`'s wall clock, this DC's node-id,
    /// and the next change-seq, taken in `txn`.
    /// Spec: docs/51 §8.3 ("change-seq — the same mechanism"); docs/29 §2
    /// as cited there; A-75; dirstore `Origin`.
    fn origin(&self, txn: &mut WriteTxn<'_>, now: &KerberosTime) -> Result<Origin, Stop> {
        let wall_clock =
            time::wall_clock(now).ok_or(Stop::Failed(AdminFailure::InternalFailure))?;
        let origin_seq = txn
            .take_counter_value(CHANGE_SEQ_COUNTER)
            .map_err(|e| counter_failure(&e, Stop::Failed(AdminFailure::StoreFailure)))?;
        Ok(Origin {
            wall_clock,
            origin_node: self.config.node_id(),
            origin_seq,
        })
    }

    /// One modify of `target`. Spec: dirstore `WriteTxn::modify_object`.
    fn modify(
        &self,
        txn: &mut WriteTxn<'_>,
        now: &KerberosTime,
        target: Guid,
        changes: Vec<AttributeChange>,
    ) -> Result<(), Stop> {
        let origin = self.origin(txn, now)?;
        txn.modify_object(target, changes, &origin)
            .map_err(|e| write_failure(&e))
    }

    /// A new objectGUID: 16 octets from the random source, never the NULL
    /// GUID, and never one any record — live or tombstone — holds.
    /// Spec: [MS-ADTS] 3.1.1.5.2.4; docs/51 R51-3, R51-17; A-15; docs/51 §9
    /// ("GUIDs are not recycled").
    fn new_guid(&mut self, txn: &WriteTxn<'_>) -> Result<Guid, Stop> {
        let mut packet = [0u8; GUID_PACKET_LEN];
        self.rng
            .fill(&mut packet)
            .map_err(|_| Stop::Failed(AdminFailure::InternalFailure))?;
        if packet == [0u8; GUID_PACKET_LEN] {
            return Err(Stop::Failed(AdminFailure::InternalFailure));
        }
        let guid = Guid::from_packet(&packet);
        let live = txn.get_object(guid).map_err(|e| store_failure(&e))?;
        let tombstone = txn.get_tombstone(guid).map_err(|e| store_failure(&e))?;
        if live.is_some() || tombstone.is_some() {
            return Err(Stop::Failed(AdminFailure::InternalFailure));
        }
        Ok(guid)
    }

    /// The next RID, taken in `txn`, checked against the range.
    /// Spec: docs/51 §8.3 (`[1101, 0x3FFFFFFF)`); A-75; [MS-SAMR] 3.1.1.9.2.
    fn new_rid(txn: &mut WriteTxn<'_>) -> Result<u32, Stop> {
        let value = txn
            .take_counter_value(RID_COUNTER)
            .map_err(|e| counter_failure(&e, Stop::Refused(AdminRefusal::RidExhausted)))?;
        if !(RID_FIRST..RID_END_EXCLUSIVE).contains(&value) {
            return Err(Stop::Failed(AdminFailure::InternalFailure));
        }
        u32::try_from(value).map_err(|_| Stop::Failed(AdminFailure::InternalFailure))
    }

    /// The create of a new object.
    /// Spec: [MS-ADTS] 3.1.1.5.2.4 (objectGUID; objectSid for a security
    /// principal; nTSecurityDescriptor per 6.1.3; whenCreated = the current
    /// time); [MS-SAMR] 3.1.1.9.2; docs/46 §5.4 (whenChanged set by every
    /// originating write); docs/51 §5.2 rows 1-4, §10.
    fn write_create(
        &mut self,
        requester: &Sid,
        plan: CreatePlan,
        seen: &[(Guid, dirstore::Object)],
        txn: &mut WriteTxn<'_>,
        now: &KerberosTime,
        dstime: i64,
    ) -> Result<(Option<Allocation>, Reply), Stop> {
        let read = |guid: Guid| {
            seen.iter()
                .find(|(g, _)| *g == guid)
                .map(|(_, obj)| obj)
                .ok_or(Stop::Failed(AdminFailure::InternalFailure))
        };
        let parent = read(plan.parent)?;
        let sd = new_object_sd(&self.ids, parent, plan.class.guid, requester)?;
        let sd = sd
            .encode()
            .map_err(|_| Stop::Failed(AdminFailure::InternalFailure))?;
        let guid = self.new_guid(txn)?;
        let mut attributes = plan.attributes;
        let (rid, sid) = match plan.domain_root {
            Some(root) => {
                let domain = domain_sid(&self.ids, read(root)?)?;
                let rid = Self::new_rid(txn)?;
                let mut sub = domain.sub_authority().to_vec();
                sub.push(rid);
                let sid = Sid::new(domain.identifier_authority(), &sub)
                    .map_err(|_| Stop::Failed(AdminFailure::InternalFailure))?;
                attributes.push((self.ids.object_sid, vec![sid.encode()]));
                (Some(rid), Some(sid))
            }
            None => (None, None),
        };
        attributes.push((self.ids.when_created, vec![record::encode_int64(dstime)]));
        attributes.push((self.ids.when_changed, vec![record::encode_int64(dstime)]));
        attributes.push((self.ids.nt_security_descriptor, vec![sd]));
        let origin = self.origin(txn, now)?;
        txn.create_object(
            NewObject {
                guid,
                parent: Some(plan.parent),
                classes: plan.class.chain,
                attributes,
            },
            &origin,
        )
        .map_err(|e| write_failure(&e))?;
        Ok((
            Some(Allocation {
                guid: guid.to_packet(),
                rid,
            }),
            Reply::Created { guid, sid },
        ))
    }
}
