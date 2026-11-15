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
//! Given the zone ([`Provisioning::with_dns_registration`], task DN10b), the
//! DC account's create also carries the DC's own host record — through the
//! same host-record rule an online host's record passes, and with the zone
//! serial taken in the same commit (docs/54 §3.1; docs/questions/Q-1003
//! item 2).
//!
//! A session can be opened only on an **empty** store (no counter, no
//! object) and creates the named counters itself (A-83: counters are
//! created only by provisioning; A-75, docs/51 §8.3). A provisioned store
//! always has its counters, so no exception can ever be claimed against
//! it: the online PEP has no way to reach one, and a future write path
//! cannot either. Each exception is claimed at most once, the NC root
//! first.
//!
//! # The principal namespace (task PN5)
//!
//! Every object the session creates passes the one checker, so every
//! security principal it writes — the krbtgt account, the DC account, the
//! service objects, the first administrators, the groups — gets its
//! namespace keys from the checker, in the realm of the naming context the
//! session is given ([`Provisioning::with_dns_registration`]: the same
//! `NamingContext` task DN10b passes for the zone — docs/59 §5.1, not a
//! parameter of its own). A session given none creates no principal (fail
//! closed). The krbtgt account holds the realm alias as a key (docs/59 N5);
//! the service objects carry the DC's dNSHostName without its key (Q-1010
//! item 3). [`Provisioning::begin`] also creates the `principal-namespace`
//! marker counter: the store it builds is one whose every principal got its
//! keys from the checker, and dird refuses a store without it (task PN10;
//! Q-1008 item 5).
//!
//! Spec: docs/51 §4.3 step 5 (the table), §8.3, §11; docs/52 R13; A-75;
//! A-79; A-83; A-92; [MS-SAMR] v20260427 2.2.1.14, 3.1.1.6 items 14, 20,
//! 22-24; docs/59 §4.3, §5.1, §5.2, §5.5; docs/questions/Q-298 item 2,
//! Q-376, Q-506, Q-1003 item 2, Q-1008 item 5, Q-1010 item 3.

use core::fmt;
use std::collections::BTreeSet;

use ad_schema::Phase1Schema;
use dirstore::{NewObject, NodeId, Timestamp, WriteTxn};
use dtyp::Guid;

use directory_pip::NamingContext;

use super::{
    CommitError, Fault, HostZone, InvariantViolation, Invariants, Refused, StoreRead, WriteStamp,
};
use crate::config::{
    DnsRegistration, CHANGE_SEQ_COUNTER, CHANGE_SEQ_END_EXCLUSIVE, CHANGE_SEQ_FIRST,
    DNS_ZONE_SERIAL_COUNTER, DNS_ZONE_SERIAL_END_EXCLUSIVE, DNS_ZONE_SERIAL_FIRST,
    PRINCIPAL_NAMESPACE_COUNTER, PRINCIPAL_NAMESPACE_END_EXCLUSIVE, PRINCIPAL_NAMESPACE_FIRST,
    RID_COUNTER, RID_END_EXCLUSIVE, RID_FIRST,
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
        // A principal in a session given no naming context (task PN5).
        Refused::Fault(Fault::Namespace) => ProvisioningError::Store("principal namespace"),
        Refused::Fault(Fault::Store(_) | Fault::Integrity | Fault::Missing) => {
            ProvisioningError::Store("read")
        }
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
        CommitError::ZoneSerial(_) => {
            ProvisioningError::Store("take_counter_value(dns-zone-serial)")
        }
        CommitError::Read(_) => ProvisioningError::Store("read"),
        // Cannot happen: the session stamps every write.
        CommitError::Unstamped => ProvisioningError::Store("stamp"),
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
    /// RID_END_EXCLUSIVE)`, the change-seq counter `[CHANGE_SEQ_FIRST,
    /// CHANGE_SEQ_END_EXCLUSIVE)`, the zone serial counter and the
    /// `principal-namespace` marker `[PRINCIPAL_NAMESPACE_FIRST,
    /// PRINCIPAL_NAMESPACE_END_EXCLUSIVE)` (never taken — module
    /// documentation). Every write of the session is stamped `wall_clock`
    /// (directory-admin `wall_clock`, one unit for every writer — Q-358 item
    /// 8) and `origin_node`. The session creates no security principal until
    /// it is given the naming context
    /// ([`Provisioning::with_dns_registration`]).
    ///
    /// # Errors
    /// [`ProvisioningError::NotEmpty`], [`ProvisioningError::Schema`],
    /// [`ProvisioningError::Store`].
    ///
    /// Spec: docs/51 §4.3 step 5, §8.3; A-75; A-83; docs/questions/Q-376
    /// item 4, Q-1008 item 5 (A-173).
    pub fn begin(
        txn: &'t mut WriteTxn<'s>,
        schema: &Phase1Schema,
        wall_clock: Timestamp,
        origin_node: NodeId,
    ) -> Result<Provisioning<'t, 's>, ProvisioningError> {
        // No zone yet: the session writes no host record unless it is given
        // one ([`Provisioning::with_dns_registration`], task DN10b) — fail
        // closed (docs/54 §3.1). No namespace yet either: no principal until
        // the naming context is given (task PN5).
        let invariants = Invariants::new(schema, BTreeSet::new(), None, None)
            .map_err(|_| ProvisioningError::Schema)?;
        let read = |_| ProvisioningError::Store("read");
        let roots = StoreRead::children(&*txn, None, 1).map_err(read)?;
        let mut any_counter = false;
        for name in [
            RID_COUNTER,
            CHANGE_SEQ_COUNTER,
            DNS_ZONE_SERIAL_COUNTER,
            PRINCIPAL_NAMESPACE_COUNTER,
        ] {
            any_counter |= StoreRead::counter(&*txn, name).map_err(read)?.is_some();
        }
        if any_counter || !roots.children.is_empty() {
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
        // The zone serial (task DN6; docs/54 §5.4, R54-12): created here,
        // with the other two, so every provisioned store has it — A-83:
        // counters only at provisioning.
        txn.create_counter(
            DNS_ZONE_SERIAL_COUNTER,
            DNS_ZONE_SERIAL_FIRST,
            DNS_ZONE_SERIAL_END_EXCLUSIVE,
        )
        .map_err(|_| ProvisioningError::Store("create_counter(dns-zone-serial)"))?;
        // The principal namespace's marker (task PN5; docs/59 §5.2 (c), §5.5;
        // Q-1008 item 5): this store's every principal gets its keys from the
        // one checker; a store without it predates the namespace and dird
        // refuses it (task PN10). Created here only (A-83), never taken.
        txn.create_counter(
            PRINCIPAL_NAMESPACE_COUNTER,
            PRINCIPAL_NAMESPACE_FIRST,
            PRINCIPAL_NAMESPACE_END_EXCLUSIVE,
        )
        .map_err(|_| ProvisioningError::Store("create_counter(principal-namespace)"))?;
        Ok(Provisioning {
            txn,
            invariants,
            wall_clock,
            origin_node,
            claimed: BTreeSet::new(),
        })
    }

    /// This session with the zone of host records: the naming context's DNS
    /// name and `dns`'s registrable networks — exactly as the online PEP
    /// derives its own (`DirectoryAdmin::new`, A-53) — so the DC's own host
    /// record (docs/54 §3.1: "written in `provision domain` only") passes the
    /// one checker's host-record rule under its `DcAccount` claim: the DC's
    /// names give one LDH label `<computerName>.<zone>`, at most eight
    /// addresses, each registrable (never loopback, unspecified or
    /// multicast; inside a registrable network). Without it the session
    /// writes no host address (fail closed). The commit that writes the
    /// record takes the zone serial in the same transaction, as every write
    /// that changes the zone (RFC 2136 §3.6).
    ///
    /// The same naming context is the session's principal namespace (task
    /// PN5; `Provisioning::with_naming_context`): every principal the
    /// session creates gets its keys in that realm — one `NamingContext`
    /// for the zone and the namespace, as the online PEP derives both from
    /// its `AdminConfig`.
    /// Spec: docs/54 §3.1, §5.3, §5.5; docs/questions/Q-994 item 6 (a),
    /// Q-1003 item 2 (A-172: task DN10b); A-53; docs/59 §5.1.
    #[must_use]
    pub fn with_dns_registration(
        mut self,
        naming_context: &NamingContext,
        dns: &DnsRegistration,
    ) -> Provisioning<'t, 's> {
        self.invariants.hosts = Some(HostZone {
            zone: naming_context.dns_name(),
            networks: dns.networks().to_vec(),
        });
        self.with_naming_context(naming_context)
    }

    /// This session in the principal namespace of `naming_context` (task
    /// PN5): its one realm alias is the NC's DNS name (directory-pip
    /// `name_context_of`; P-84 open). A naming context whose DNS name cannot
    /// be an alias leaves the session without a namespace, so it creates no
    /// principal (fail closed). A zone already given is re-derived from the
    /// same naming context, so the zone and the namespace never come from
    /// two different ones. Reached through
    /// [`Provisioning::with_dns_registration`] — the one public way, task
    /// DN10b's naming context (docs/59 §5.1: "not a parameter of its own");
    /// the unit tests call it directly for a session without a zone.
    /// Spec: docs/59 §4.2 (`NameContext` from `NamingContext`), §5.1; A-53;
    /// docs/questions/Q-1012 (P-84).
    #[must_use]
    pub(super) fn with_naming_context(
        mut self,
        naming_context: &NamingContext,
    ) -> Provisioning<'t, 's> {
        self.invariants.names = directory_pip::name_context_of(naming_context).ok();
        if let Some(hosts) = self.invariants.hosts.as_mut() {
            hosts.zone = naming_context.dns_name();
        }
        self
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
        let stamp = WriteStamp {
            wall_clock: self.wall_clock,
            origin_node: self.origin_node,
        };
        checked
            .commit(self.txn, Some(stamp))
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
