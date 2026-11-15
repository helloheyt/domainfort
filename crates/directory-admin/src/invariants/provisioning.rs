//! The provisioning session: the only place the named provisioning
//! exceptions exist (docs/52 R13; task brief: "explicit, named exceptions
//! inside the checker, not a bypass").
//!
//! `provision domain` creates, in one transaction on a new store, objects
//! the online path can never create: the NC root (a domainDNS without
//! parent), the krbtgt account (RID 502, outside the RID counter's range),
//! the DC's computer account (userAccountControl ST — never set by the
//! admin plane, A-79), and the service objects, which become protected
//! (docs/51 §5.2 row 9) — among them the two that alone may carry a
//! reserved service name (`admind/<fqdn>`, Q-541; `kadmin/changepw`, task
//! K9 — docs/53 §5.2, Q-972). Everything else it writes — the OUs, the first
//! administrators, the two groups and the Tier-0 group's members — passes
//! exactly the rules of the online path.
//!
//! A session can be opened only on an **empty** store (no counter, no
//! object) and creates both named counters itself (A-83: counters are
//! created only by provisioning; A-75, docs/51 §8.3). A provisioned store
//! always has its counters, so no exception can ever be claimed against
//! it: the online PEP has no way to reach one, and a future write path
//! cannot either. Each exception is claimed at most once, the NC root
//! first.
//!
//! Spec: docs/51 §4.3 step 5 (the table), §8.3, §11; docs/52 R13; A-75;
//! A-79; A-83; A-92; [MS-SAMR] v20260427 2.2.1.14, 3.1.1.6 items 14, 20,
//! 22-24; docs/questions/Q-298 item 2, Q-376, Q-506.

use core::fmt;
use std::collections::BTreeSet;

use ad_schema::Phase1Schema;
use dirstore::{NewObject, NodeId, Timestamp, WriteTxn};
use dtyp::Guid;

use super::{CommitError, InvariantViolation, Invariants, Refused, StoreRead};
use crate::config::{
    CHANGE_SEQ_COUNTER, CHANGE_SEQ_END_EXCLUSIVE, CHANGE_SEQ_FIRST, RID_COUNTER, RID_END_EXCLUSIVE,
    RID_FIRST,
};

/// A named provisioning exception: what an object claims to be beyond the
/// rules every write path keeps.
/// Spec: docs/51 §4.3 step 5; module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProvisioningRole {
    /// The naming context's root: a domainDNS without parent, carrying the
    /// domain SID as its objectSid. First, once. Spec: docs/51 §4.3 step 5;
    /// docs/46 §4.4 ("NC root only").
    NamingContextRoot,
    /// The krbtgt account: a user, objectSid = domain ‖ 502,
    /// sAMAccountName "krbtgt", userAccountControl N without
    /// ACCOUNTDISABLE, no pwdLastSet. Once. Spec: [MS-SAMR] 2.2.1.14,
    /// 3.1.1.6 items 14, 20, 22; docs/51 §4.3 step 5; docs/47 §1.4.
    Krbtgt,
    /// The DC's computer account: userAccountControl ST without
    /// ACCOUNTDISABLE, no servicePrincipalName, no pwdLastSet. Once (one DC
    /// in phase 1, OD-2). Spec: [MS-SAMR] 3.1.1.6 items 20, 23; docs/51 §4.3
    /// step 5, §11 ("ST only in `provision`"); A-79 (Q-298 item 2); Q-376
    /// item 5.
    DcAccount,
    /// A service object (the LDAP service object): a computer as the online
    /// path creates one, WT without pwdLastSet, which becomes protected —
    /// never a member, never changed or deleted. It may not carry the admin
    /// service's name. Spec: docs/51 §4.3 step 5, §5.2 row 9; docs/10 §5ב;
    /// A-73; Q-376 item 6.
    ServiceObject,
    /// The admin service object: a service object (as
    /// [`ProvisioningRole::ServiceObject`], protected the same way) whose one
    /// servicePrincipalName is the admin service's name `admind/<fqdn>` —
    /// the name from which the `AdminService` key-set purpose derives. The
    /// only object that may carry such a name; once.
    /// Spec: A-73; docs/51 §4.3 step 5; docs/52 R2b; docs/questions/Q-491
    /// item 1, Q-541.
    AdminServiceObject,
    /// The change-password service object (task K9): a service object (as
    /// [`ProvisioningRole::ServiceObject`], protected the same way) whose one
    /// servicePrincipalName is `kadmin/changepw` — the name RFC 3244 §2 gives
    /// the service and from which the `ChangePasswordService` key-set purpose
    /// derives (keyd-types `KeyPurpose::of_service_name`). Its second
    /// component is a fixed instance, not the object's host (RFC 4120 §6.2,
    /// NT-SRV-INST). The only object that may carry that name; once.
    /// Spec: RFC 3244 §2; RFC 4120 §6.2; docs/53 R53-6, §5.2, §10 (K9);
    /// docs/52 R2b; docs/questions/Q-964 item 13, Q-972.
    ChangePasswordServiceObject,
}

impl ProvisioningRole {
    /// `true` for the exceptions one domain holds only once (every one but
    /// the plain service object).
    fn once(self) -> bool {
        !matches!(self, ProvisioningRole::ServiceObject)
    }
}

/// Why the provisioning session refused. Carries no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisioningError {
    /// The store already holds a counter or an object: provisioning (and
    /// its exceptions) exist only for a new store.
    NotEmpty,
    /// The phase-1 schema lacks a name the checker needs.
    Schema,
    /// An invariant refused the object.
    Invariant(InvariantViolation),
    /// A supplied objectSid is not the domain SID ‖ the RID the counter
    /// handed out (or 502 for krbtgt): the planned RID is not the taken one.
    SidMismatch,
    /// A dirstore step failed (named); the transaction must be dropped.
    Store(&'static str),
}

impl fmt::Display for ProvisioningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProvisioningError::NotEmpty => f.write_str("the store is not empty"),
            ProvisioningError::Schema => f.write_str("the schema lacks a definition"),
            ProvisioningError::Invariant(v) => write!(f, "write invariant refused: {v:?}"),
            ProvisioningError::SidMismatch => {
                f.write_str("an objectSid is not the one the RID counter allocated")
            }
            ProvisioningError::Store(step) => write!(f, "directory store refused {step}"),
        }
    }
}

impl std::error::Error for ProvisioningError {}

/// A check refusal, as the session reports it.
fn refused(r: Refused) -> ProvisioningError {
    match r {
        Refused::Rule(v) => ProvisioningError::Invariant(v),
        Refused::Fault(_) => ProvisioningError::Store("read"),
    }
}

/// A commit failure, as the session reports it.
fn commit_failed(e: CommitError) -> ProvisioningError {
    match e {
        CommitError::Stale => ProvisioningError::Store("change-seq moved"),
        CommitError::Counter(_) => ProvisioningError::Store("counter(change-seq)"),
        CommitError::Rid(_) => ProvisioningError::Store("take_counter_value(rid)"),
        CommitError::RidRange => ProvisioningError::Store("rid range"),
        CommitError::Sid => ProvisioningError::SidMismatch,
        CommitError::ChangeSeq(_) => ProvisioningError::Store("take_counter_value(change-seq)"),
        CommitError::Write(_) => ProvisioningError::Store("create_object"),
    }
}

/// The provisioning session over one write transaction (module
/// documentation). Dropping it leaves the transaction to its owner, who
/// commits it — or drops it on any error, which aborts everything.
pub struct Provisioning<'t, 's> {
    txn: &'t mut WriteTxn<'s>,
    invariants: Invariants,
    wall_clock: Timestamp,
    origin_node: NodeId,
    claimed: BTreeSet<ProvisioningRole>,
}

impl<'t, 's> Provisioning<'t, 's> {
    /// Open the session in `txn`: refused unless the store holds no counter
    /// and no object; then creates the RID counter `[RID_FIRST,
    /// RID_END_EXCLUSIVE)` and the change-seq counter `[CHANGE_SEQ_FIRST,
    /// CHANGE_SEQ_END_EXCLUSIVE)`. Every write of the session is stamped
    /// `wall_clock` (directory-admin `wall_clock`, one unit for every
    /// writer — Q-358 item 8) and `origin_node`.
    ///
    /// # Errors
    /// [`ProvisioningError::NotEmpty`], [`ProvisioningError::Schema`],
    /// [`ProvisioningError::Store`].
    ///
    /// Spec: docs/51 §4.3 step 5, §8.3; A-75; A-83; docs/questions/Q-376
    /// item 4.
    pub fn begin(
        txn: &'t mut WriteTxn<'s>,
        schema: &Phase1Schema,
        wall_clock: Timestamp,
        origin_node: NodeId,
    ) -> Result<Provisioning<'t, 's>, ProvisioningError> {
        let invariants =
            Invariants::new(schema, BTreeSet::new()).map_err(|_| ProvisioningError::Schema)?;
        let read = |_| ProvisioningError::Store("read");
        let roots = StoreRead::children(&*txn, None, 1).map_err(read)?;
        if StoreRead::counter(&*txn, RID_COUNTER)
            .map_err(read)?
            .is_some()
            || StoreRead::counter(&*txn, CHANGE_SEQ_COUNTER)
                .map_err(read)?
                .is_some()
            || !roots.children.is_empty()
        {
            return Err(ProvisioningError::NotEmpty);
        }
        txn.create_counter(RID_COUNTER, RID_FIRST, RID_END_EXCLUSIVE)
            .map_err(|_| ProvisioningError::Store("create_counter(rid)"))?;
        txn.create_counter(
            CHANGE_SEQ_COUNTER,
            CHANGE_SEQ_FIRST,
            CHANGE_SEQ_END_EXCLUSIVE,
        )
        .map_err(|_| ProvisioningError::Store("create_counter(change-seq)"))?;
        Ok(Provisioning {
            txn,
            invariants,
            wall_clock,
            origin_node,
            claimed: BTreeSet::new(),
        })
    }

    /// Create `new`, claiming the exception `role` (`None`: an ordinary
    /// object, checked exactly as the online path checks one): the checker,
    /// then the commit — a principal's RID from the counter (its supplied
    /// objectSid must be the one that RID forms), the write's change-seq.
    /// A service object's GUID is protected from then on.
    ///
    /// # Errors
    /// [`ProvisioningError::Invariant`] (an exception claimed twice, or the
    /// NC root after another root: `Exception`), [`ProvisioningError::
    /// SidMismatch`], [`ProvisioningError::Store`].
    ///
    /// Spec: module documentation; docs/51 §4.3 step 5; A-89 (every writer
    /// takes a change-seq).
    pub fn create(
        &mut self,
        role: Option<ProvisioningRole>,
        new: NewObject,
    ) -> Result<(), ProvisioningError> {
        let exception = ProvisioningError::Invariant(InvariantViolation::Exception);
        if let Some(role) = role {
            if role.once() && self.claimed.contains(&role) {
                return Err(exception);
            }
            if role == ProvisioningRole::NamingContextRoot {
                let roots = StoreRead::children(&*self.txn, None, 1)
                    .map_err(|_| ProvisioningError::Store("read"))?;
                if !roots.children.is_empty() {
                    return Err(exception);
                }
            }
        }
        let guid: Guid = new.guid;
        let checked = self
            .invariants
            .check_create(self.txn, new, role, &[])
            .map_err(refused)?;
        checked
            .commit(self.txn, self.wall_clock, self.origin_node)
            .map_err(commit_failed)?;
        match role {
            Some(ProvisioningRole::ServiceObject) => {
                self.invariants.service_objects.insert(guid);
            }
            Some(
                claim @ (ProvisioningRole::AdminServiceObject
                | ProvisioningRole::ChangePasswordServiceObject),
            ) => {
                self.invariants.service_objects.insert(guid);
                self.claimed.insert(claim);
            }
            Some(role) => {
                self.claimed.insert(role);
            }
            None => {}
        }
        Ok(())
    }
}
