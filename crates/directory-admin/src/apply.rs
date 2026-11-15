//! `apply`: the write of a prepared operation, inside the caller's
//! `WriteTxn`, after auditd acknowledged the decision event — `apply` takes
//! the prepared operation only with that proof
//! (`ipc_audit_client::AckedIntent<Prepared>`, docs/52 §3.11 R6 (a)): a write
//! whose decision is not durably recorded does not compile.
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
//! 6. **The write invariants** (crate::invariants, docs/52 R13): the write
//!    itself is a `CheckedWrite` of the one checker every write path passes
//!    — the per-object rules on the record it produces and, for a new
//!    `member` link, the store-wide rules (the link walks replaced by the
//!    proof `prepare` kept for the same state). The commit takes the
//!    write's change-seq and a new principal's RID itself. These rules ran
//!    in `prepare` against the same state, so they refuse nothing `prepare`
//!    passed; they are the door every write path must go through.
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
//! docs/52 R13 (A-102);
//! docs/questions/Q-358 items 1-2;
//! [MS-ADTS] 3.1.1.5.2.4 (objectGUID, never NULL; whenCreated = the current
//! time); [MS-SAMR] 3.1.1.9.2 (objectSid = domain SID ‖ RID), 3.1.1.9.2.1
//! item 1.2.

use dirstore::{AttributeChange, NewObject, WriteTxn};
use dtyp::{Guid, Sid, GUID_PACKET_LEN};
use ipc_audit::{AdminFailure, AdminRefusal, Allocation, DirAdminEvent};
use ipc_audit_client::AckedIntent;
use krb_proto::KerberosTime;

use crate::admin::{CreatePlan, DirectoryAdmin, Plan, Prepared, WriteKind, WritePlan};
use crate::audit::{Refusal, Stop};
use crate::checks::{domain_sid, fault_stop, store_failure};
use crate::config::CHANGE_SEQ_COUNTER;
use crate::descriptor::new_object_sd;
use crate::invariants::{
    CheckedWrite, CommitError, Committed, InvariantViolation, LinkProof, Refused as Unchecked,
};
use crate::random::RandomSource;
use crate::record;
use crate::reply::Reply;
use crate::time;

/// A write that was applied in the caller's transaction (not yet
/// committed): the outcome event to send **after** the commit, the event to
/// send instead if the commit fails, and the reply.
///
/// Made only by [`DirectoryAdmin::apply`] — that is, only for a prepared
/// operation whose decision event auditd acknowledged — and not `Clone`: a
/// step that must follow an acknowledged write (dird's registration of a
/// `BeginPasswordSet`'s set-secret decision) takes it as its evidence
/// (docs/52 §3.11 R6 (a)).
///
/// Spec: docs/51 §5.7 item 2, §7.4 steps 5-6; A-85.
#[derive(Debug, PartialEq, Eq)]
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

/// A refusal of the write invariants at the write, as the outcome reports
/// it — the code `prepare` gives the same rule (module documentation, item
/// 6: never reached by a write `prepare` passed).
/// Spec: crate::invariants `InvariantViolation`; crate ipc-audit
/// `AdminRefusal`; docs/51 §5.2.
fn invariant_stop(unchecked: Unchecked) -> Stop {
    match unchecked {
        Unchecked::Fault(fault) => fault_stop(&fault),
        Unchecked::Rule(rule) => Stop::Refused(match rule {
            InvariantViolation::Name | InvariantViolation::ReservedName => {
                AdminRefusal::AccountNameInvalid
            }
            InvariantViolation::Protected => AdminRefusal::TargetProtected,
            InvariantViolation::Membership => AdminRefusal::MembershipInvalid,
            InvariantViolation::NoSuchObject => AdminRefusal::NotFound,
            InvariantViolation::Class
            | InvariantViolation::Exception
            | InvariantViolation::AccountControl
            | InvariantViolation::Value
            | InvariantViolation::Sid
            | InvariantViolation::NotModifiable => AdminRefusal::ValueInvalid,
        }),
    }
}

/// A checked write that did not commit, as the outcome reports it — the
/// mapping of the RID, change-seq and write errors from before the write
/// went through crate::invariants.
/// Spec: A-83 ("NoSuchCounter / CounterExhausted / Tamper ⇒ refusal");
/// docs/51 §8.3 (`[1101, 0x3FFFFFFF)`; exhaustion ⇒ `RidExhausted`);
/// dirstore `Error`.
fn commit_stop(e: CommitError) -> Stop {
    match e {
        CommitError::Stale => Stop::Refused(AdminRefusal::Conflict),
        CommitError::Counter(e) => store_failure(&e),
        CommitError::Rid(e) => counter_failure(&e, Stop::Refused(AdminRefusal::RidExhausted)),
        CommitError::RidRange | CommitError::Sid => Stop::Failed(AdminFailure::InternalFailure),
        CommitError::ChangeSeq(e) => counter_failure(&e, Stop::Failed(AdminFailure::StoreFailure)),
        CommitError::Write(e) => write_failure(&e),
    }
}

impl<R: RandomSource> DirectoryAdmin<R> {
    /// Apply a prepared write inside `txn` (module documentation): the GUID
    /// from the random source, the RID and the change-seq from the
    /// counters, the security descriptor, then the create / modify /
    /// delete. `now` is the time of the write (whenCreated, whenChanged,
    /// pwdLastSet, the outcome event).
    ///
    /// `prepared` comes with its proof: auditd acknowledged its decision
    /// event (`ipc_audit_client::AuditGate::wait_acknowledged` is the only source
    /// of an `AckedIntent`; module documentation). Commit `txn` on `Ok` and
    /// send [`Applied::outcome_event`] (or [`Applied::commit_failure_event`]
    /// if the commit fails); on `Err` abort `txn` and send the refusal's
    /// event. An operation that commits nothing (`Prepared::writes` is
    /// `false`) is refused here.
    ///
    /// Spec: docs/51 §7.4 step 5; A-75; A-83; A-84; A-85; docs/52 §3.11 R6
    /// (a).
    pub fn apply(
        &mut self,
        prepared: AckedIntent<Prepared>,
        txn: &mut WriteTxn<'_>,
        now: &KerberosTime,
    ) -> Result<Applied, Refusal> {
        let Prepared {
            base,
            requester,
            plan,
            ..
        } = prepared.into_inner();
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
                self.modify(txn, now, target, changes, None)?;
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
                self.modify(txn, now, target, changes, None)?;
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
                self.modify(txn, now, target, changes, None)?;
                Ok((None, Reply::Done))
            }
            WriteKind::SetMembers {
                group,
                members,
                proof,
            } => {
                let changes = vec![
                    AttributeChange::Replace {
                        id: self.ids.member,
                        values: members.into_iter().map(record::encode_ref).collect(),
                    },
                    when_changed,
                ];
                self.modify(txn, now, group, changes, proof.as_ref())?;
                Ok((None, Reply::Done))
            }
            WriteKind::Delete { target } => {
                let checked = self
                    .invariants
                    .check_delete(txn, target)
                    .map_err(invariant_stop)?;
                self.commit(checked, txn, now)?;
                Ok((None, Reply::Done))
            }
        }
    }

    /// Commit a checked write (crate::invariants): `now`'s wall clock and
    /// this DC's node-id; the commit takes the write's change-seq (and a
    /// new principal's RID) itself, in `txn`.
    /// Spec: docs/51 §8.3 ("change-seq — the same mechanism"); docs/29 §2
    /// as cited there; A-75; A-89; docs/52 R13; dirstore `Origin`.
    fn commit(
        &self,
        checked: CheckedWrite,
        txn: &mut WriteTxn<'_>,
        now: &KerberosTime,
    ) -> Result<Committed, Stop> {
        let wall_clock =
            time::wall_clock(now).ok_or(Stop::Failed(AdminFailure::InternalFailure))?;
        checked
            .commit(txn, wall_clock, self.config.node_id())
            .map_err(commit_stop)
    }

    /// One modify of `target`, through the write invariants (`proof`: the
    /// link walks `prepare` ran for an `AddMember`).
    /// Spec: dirstore `WriteTxn::modify_object`; docs/52 R13.
    fn modify(
        &self,
        txn: &mut WriteTxn<'_>,
        now: &KerberosTime,
        target: Guid,
        changes: Vec<AttributeChange>,
        proof: Option<&LinkProof>,
    ) -> Result<(), Stop> {
        let proofs = proof.map(core::slice::from_ref).unwrap_or_default();
        let checked = self
            .invariants
            .check_modify(txn, target, changes, proofs)
            .map_err(invariant_stop)?;
        self.commit(checked, txn, now).map(|_| ())
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

    /// The create of a new object, through the write invariants (the
    /// commit takes the RID and forms the objectSid of a principal).
    /// Spec: [MS-ADTS] 3.1.1.5.2.4 (objectGUID; objectSid for a security
    /// principal; nTSecurityDescriptor per 6.1.3; whenCreated = the current
    /// time); [MS-SAMR] 3.1.1.9.2; docs/46 §5.4 (whenChanged set by every
    /// originating write); docs/51 §5.2 rows 1-4, §10; docs/52 R13.
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
        // A security principal: the NC root (unchanged since `prepare`)
        // must hold the domain SID its objectSid extends; the commit takes
        // the RID and forms the objectSid ([MS-SAMR] 3.1.1.9.2;
        // crate::invariants).
        if let Some(root) = plan.domain_root {
            domain_sid(&self.ids, read(root)?)?;
        }
        attributes.push((self.ids.when_created, vec![record::encode_int64(dstime)]));
        attributes.push((self.ids.when_changed, vec![record::encode_int64(dstime)]));
        attributes.push((self.ids.nt_security_descriptor, vec![sd]));
        let checked = self
            .invariants
            .check_create(
                txn,
                NewObject {
                    guid,
                    parent: Some(plan.parent),
                    classes: plan.class.chain,
                    attributes,
                },
                None,
                &[],
            )
            .map_err(invariant_stop)?;
        let Committed { rid, sid } = self.commit(checked, txn, now)?;
        Ok((
            Some(Allocation {
                guid: guid.to_packet(),
                rid,
            }),
            Reply::Created { guid, sid },
        ))
    }
}
