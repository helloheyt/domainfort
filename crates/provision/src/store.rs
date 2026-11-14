//! Step 5 of docs/51 §4.3: the database — **one** `WriteTxn` (D136) that
//! creates both named counters and every domain object; then a check of
//! the committed store as dird will read it.
//!
//! # The transaction
//!
//! 1. `create_counter(rid, 1101, 0x3FFFFFFF)` and `create_counter(
//!    change-seq, 1, u64::MAX)` — provisioning is the only creator of the
//!    counters (A-75, A-83; directory-admin `RID_COUNTER`,
//!    `CHANGE_SEQ_COUNTER`, `RID_FIRST`, `RID_END_EXCLUSIVE`).
//! 2. For each planned object, in order: for a principal other than
//!    krbtgt, `take_counter_value(rid)` — the value must be the one the
//!    plan derived its SID from (fail closed otherwise); then
//!    `take_counter_value(change-seq)` — **every** object write takes a
//!    change-seq value (the A-89 binding rule: directory-admin's `apply`
//!    re-verifies through it, Q-358 item 1); then `create_object` with
//!    `Origin = (wall_clock(now), node_id, change-seq)`
//!    (`directory_admin::wall_clock`: one unit for every writer, Q-358
//!    item 8).
//! 3. `commit`. Any error before it drops the transaction: nothing of it is
//!    kept (dirstore: "dropping it without commit aborts it").
//!
//! # The check after the commit
//!
//! The store is read back through directory-pip as dird reads it at start
//! (Q-270 item 3): the NC root has the domain SID as objectSid; the krbtgt
//! account (domain SID ‖ 502, sAMAccountName "krbtgt") resolves to the
//! planned object; the RID counter's next value follows the last planned
//! RID and the change-seq counter's follows the object count. A failure
//! here means the staged file is not installed.
//!
//! Spec: docs/51 §4.3 step 5, §8.3; docs/32 §7, §7.1; A-75; A-83; A-89
//! (Q-358 items 1, 8); Q-330 items 4-5; Q-270 item 3.

use core::fmt;

use directory_admin::{wall_clock, CHANGE_SEQ_COUNTER, RID_COUNTER, RID_END_EXCLUSIVE, RID_FIRST};
use directory_pip::{DirectoryContext, TierMap};
use dirstore::{NewObject, Origin, Store};
use keyd_types::KeydConfig;
use pdp::Pip;

use crate::plan::{Plan, RidSource, CHANGE_SEQ_END_EXCLUSIVE, CHANGE_SEQ_FIRST};

/// Why the store could not be written or did not check out. Carries no
/// key material and no attribute value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// A dirstore call failed (the transaction was dropped).
    Store(&'static str),
    /// A taken RID differs from the planned one.
    RidMismatch,
    /// The provisioning time has no wall-clock form.
    Time,
    /// The committed store does not resolve the NC root's domain SID.
    DomainSid,
    /// The committed store does not resolve the planned krbtgt account.
    Krbtgt,
    /// A counter's state after the commit is not the planned one.
    Counter,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Store(step) => write!(f, "directory store refused {step}"),
            StoreError::RidMismatch => {
                f.write_str("a RID taken from the counter is not the planned one")
            }
            StoreError::Time => f.write_str("the provisioning time has no wall-clock form"),
            StoreError::DomainSid => {
                f.write_str("the staged store has no domain SID on its NC root")
            }
            StoreError::Krbtgt => {
                f.write_str("the staged store does not resolve the krbtgt account")
            }
            StoreError::Counter => f.write_str("a counter of the staged store is not as planned"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Write the plan's counters and objects in one transaction and commit
/// (module documentation, "The transaction").
///
/// # Errors
/// [`StoreError`]; the transaction is dropped (aborted) on every error.
///
/// Spec: docs/51 §4.3 step 5; A-75; A-83; A-89; D136.
pub(crate) fn write_domain(store: &Store, plan: &Plan) -> Result<(), StoreError> {
    let wall = wall_clock(&plan.now).ok_or(StoreError::Time)?;
    let mut txn = store
        .begin_write()
        .map_err(|_| StoreError::Store("begin_write"))?;
    txn.create_counter(RID_COUNTER, RID_FIRST, RID_END_EXCLUSIVE)
        .map_err(|_| StoreError::Store("create_counter(rid)"))?;
    txn.create_counter(
        CHANGE_SEQ_COUNTER,
        CHANGE_SEQ_FIRST,
        CHANGE_SEQ_END_EXCLUSIVE,
    )
    .map_err(|_| StoreError::Store("create_counter(change-seq)"))?;
    for object in &plan.objects {
        if let RidSource::Counter(planned) = object.rid {
            let taken = txn
                .take_counter_value(RID_COUNTER)
                .map_err(|_| StoreError::Store("take_counter_value(rid)"))?;
            if taken != u64::from(planned) {
                return Err(StoreError::RidMismatch);
            }
        }
        let origin_seq = txn
            .take_counter_value(CHANGE_SEQ_COUNTER)
            .map_err(|_| StoreError::Store("take_counter_value(change-seq)"))?;
        let origin = Origin {
            wall_clock: wall,
            origin_node: plan.node_id,
            origin_seq,
        };
        txn.create_object(
            NewObject {
                guid: object.guid,
                parent: object.parent,
                classes: object.classes.clone(),
                attributes: object.attributes.clone(),
            },
            &origin,
        )
        .map_err(|_| StoreError::Store("create_object"))?;
    }
    txn.commit().map_err(|_| StoreError::Store("commit"))
}

/// Read the committed store back as dird does at start (module
/// documentation, "The check after the commit").
///
/// # Errors
/// [`StoreError`].
///
/// Spec: Q-270 item 3; docs/47 §1.4 (R47-2); A-53; A-83.
pub(crate) fn check_domain(store: &Store, plan: &Plan) -> Result<(), StoreError> {
    let schema = ad_schema::phase1().map_err(|_| StoreError::Store("schema"))?;
    let keyd = KeydConfig::new(plan.realm.clone());
    let ctx = DirectoryContext::new(schema, &keyd, plan.naming_context.clone())
        .map_err(|_| StoreError::Store("directory context"))?;
    let tiers = TierMap::empty();
    let view = ctx
        .view(store, &tiers)
        .map_err(|_| StoreError::Store("snapshot"))?;
    let domain_sid = view
        .object_sid(plan.naming_context.dn())
        .map_err(|_| StoreError::DomainSid)?
        .ok_or(StoreError::DomainSid)?;
    if domain_sid != plan.domain_sid {
        return Err(StoreError::DomainSid);
    }
    let krbtgt = view
        .krbtgt_handle(&domain_sid)
        .map_err(|_| StoreError::Krbtgt)?;
    let planned = plan
        .object(crate::plan::ObjectRole::Krbtgt)
        .ok_or(StoreError::Krbtgt)?;
    if krbtgt.principal.as_bytes() != &planned.guid.to_packet() {
        return Err(StoreError::Krbtgt);
    }
    let snapshot = view.snapshot();
    let rid = snapshot
        .counter(RID_COUNTER)
        .map_err(|_| StoreError::Counter)?
        .ok_or(StoreError::Counter)?;
    let takes = u64::try_from(plan.counter_rids()).map_err(|_| StoreError::Counter)?;
    if rid.first_value != RID_FIRST
        || rid.end_exclusive != RID_END_EXCLUSIVE
        || Some(rid.next_value) != RID_FIRST.checked_add(takes)
    {
        return Err(StoreError::Counter);
    }
    let seq = snapshot
        .counter(CHANGE_SEQ_COUNTER)
        .map_err(|_| StoreError::Counter)?
        .ok_or(StoreError::Counter)?;
    let writes = u64::try_from(plan.objects.len()).map_err(|_| StoreError::Counter)?;
    if seq.first_value != CHANGE_SEQ_FIRST
        || seq.end_exclusive != CHANGE_SEQ_END_EXCLUSIVE
        || Some(seq.next_value) != CHANGE_SEQ_FIRST.checked_add(writes)
    {
        return Err(StoreError::Counter);
    }
    Ok(())
}
