//! Step 5 of docs/51 §4.3: the database — **one** `WriteTxn` (D136) that
//! creates both named counters and every domain object; then a check of
//! the committed store as dird will read it.
//!
//! # The transaction — through the write invariants (docs/52 R13)
//!
//! This module never calls dirstore's mutating API itself: the domain is
//! written through directory-admin's [`Provisioning`] session, the one
//! checker every write path passes (crate directory-admin, module
//! `invariants`; pinned by its `tests/single_write_path.rs`).
//!
//! 1. `Provisioning::begin` — refused unless the new store is empty; it
//!    creates the RID counter `[1101, 0x3FFFFFFF)` and the change-seq
//!    counter `[1, u64::MAX)` (A-75, A-83: provisioning is their only
//!    creator).
//! 2. For each planned object, in order, `Provisioning::create` with its
//!    named exception, if any ([`exception_of`]: the NC root, krbtgt, the DC
//!    account, the two service objects) — every other object (the OUs, the
//!    first administrators, the Tier-0 group with its members, the bootstrap
//!    group) is checked exactly as the online PEP's writes are: the
//!    [MS-SAMR] constraints and name rules (A-79), the membership rules,
//!    the cycle refusal and the expansion bounds (A-89, A-95). The session
//!    takes each principal's RID from the counter — the planned objectSid
//!    must be the one it forms (fail closed otherwise) — and each write's
//!    change-seq (`Origin = (wall_clock(now), node_id, change-seq)`,
//!    `directory_admin::wall_clock`: one unit for every writer, Q-358 item
//!    8).
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
//! Spec: docs/51 §4.3 step 5, §8.3; docs/32 §7, §7.1; docs/52 R13 (A-102);
//! A-75; A-83; A-89 (Q-358 items 1, 8); Q-330 items 4-5; Q-270 item 3.

use core::fmt;

use directory_admin::{
    wall_clock, InvariantViolation, Provisioning, ProvisioningError, ProvisioningRole,
    CHANGE_SEQ_COUNTER, CHANGE_SEQ_END_EXCLUSIVE, CHANGE_SEQ_FIRST, RID_COUNTER, RID_END_EXCLUSIVE,
    RID_FIRST,
};
use directory_pip::{DirectoryContext, TierMap};
use dirstore::{NewObject, Store};
use keyd_types::KeydConfig;
use pdp::Pip;

use crate::plan::{ObjectRole, Plan};

/// Why the store could not be written or did not check out. Carries no
/// key material and no attribute value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// A dirstore call failed (the transaction was dropped).
    Store(&'static str),
    /// A taken RID differs from the planned one.
    RidMismatch,
    /// The staged store was not empty when the provisioning session began.
    NotEmpty,
    /// A write invariant refused a planned object (docs/52 R13): the plan
    /// holds something the online path would refuse.
    Invariant(InvariantViolation),
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
            StoreError::NotEmpty => f.write_str("the staged store is not empty"),
            StoreError::Invariant(v) => {
                write!(f, "a planned object breaks a write invariant ({v:?})")
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

/// The named provisioning exception a planned object claims (crate
/// directory-admin `ProvisioningRole`), or `None` for an object every write
/// path could create.
/// Spec: docs/51 §4.3 step 5 (the table); docs/52 R13; Q-376 items 5-6.
#[must_use]
pub(crate) fn exception_of(role: ObjectRole) -> Option<ProvisioningRole> {
    match role {
        ObjectRole::NamingContextRoot => Some(ProvisioningRole::NamingContextRoot),
        ObjectRole::Krbtgt => Some(ProvisioningRole::Krbtgt),
        ObjectRole::DcComputer => Some(ProvisioningRole::DcAccount),
        ObjectRole::LdapService | ObjectRole::AdminService => Some(ProvisioningRole::ServiceObject),
        ObjectRole::Tier0Ou
        | ObjectRole::WorkstationsOu
        | ObjectRole::FirstAdmin(_)
        | ObjectRole::Tier0Group
        | ObjectRole::BootstrapGroup => None,
    }
}

/// A refusal of the provisioning session, as this module reports it.
fn session_error(e: ProvisioningError) -> StoreError {
    match e {
        ProvisioningError::NotEmpty => StoreError::NotEmpty,
        ProvisioningError::Schema => StoreError::Store("schema"),
        ProvisioningError::Invariant(v) => StoreError::Invariant(v),
        ProvisioningError::SidMismatch => StoreError::RidMismatch,
        ProvisioningError::Store(step) => StoreError::Store(step),
    }
}

/// Write the plan's counters and objects in one transaction, through the
/// write invariants' provisioning session, and commit (module
/// documentation, "The transaction").
///
/// # Errors
/// [`StoreError`]; the transaction is dropped (aborted) on every error.
///
/// Spec: docs/51 §4.3 step 5; docs/52 R13; A-75; A-83; A-89; D136.
pub(crate) fn write_domain(store: &Store, plan: &Plan) -> Result<(), StoreError> {
    let wall = wall_clock(&plan.now).ok_or(StoreError::Time)?;
    let schema = ad_schema::phase1().map_err(|_| StoreError::Store("schema"))?;
    let mut txn = store
        .begin_write()
        .map_err(|_| StoreError::Store("begin_write"))?;
    {
        let mut session =
            Provisioning::begin(&mut txn, &schema, wall, plan.node_id).map_err(session_error)?;
        for object in &plan.objects {
            session
                .create(
                    exception_of(object.role),
                    NewObject {
                        guid: object.guid,
                        parent: object.parent,
                        classes: object.classes.clone(),
                        attributes: object.attributes.clone(),
                    },
                )
                .map_err(session_error)?;
        }
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
