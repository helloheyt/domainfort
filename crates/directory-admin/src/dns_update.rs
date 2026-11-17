//! `DnsSelfUpdate` (task DN6): a member host's change of its **own** DNS
//! host record, decided by this PEP and written through the one write
//! checker — for dird's DNS PEP (task DN8, `dns-pep`), after keyd verified
//! the update's GSS-TSIG signature (docs/54 §4.5, §7.5).
//!
//! # The three steps (docs/54 §4.5 steps 3-7)
//!
//! 1. [`DirectoryAdmin::dns_update_host`] — from the signer's verified
//!    identity ([`DnsUpdateTicket`]) to its own host, decided: the Subject
//!    through the directory exactly as for an administrator
//!    (`AdminSubject::from_verified_ticket`: `usable_at`, `revokes`); the
//!    requester's **own** account, a computer (a user has no host name — a
//!    structural refusal); not structural (the DC, a service object); its
//!    host name by the one host-name rule (directory-pip `host_label`:
//!    `<computerName>.<zone>`, one LDH label); then
//!    `decide(DnsUpdate, Resource::Dns { zone, record: Some(label) })` on
//!    the transport `Dns` — layer 4 with the tier of the record's owning
//!    object (directory-pip `object_tier`, Q-614 item 6). The answer,
//!    [`DnsHost`], carries the host's name and current addresses: what the
//!    DNS PEP needs for its structural check (every name of the message =
//!    this host name, **before** anything is read about another — docs/54
//!    §5.5) and for RFC 2136's prerequisites and updates (§2.4, §2.5).
//! 2. [`DirectoryAdmin::prepare_dns_self_update`] — the new address set the
//!    DNS PEP computed, judged: at most eight, each registrable (never
//!    loopback, unspecified, multicast; inside the registrable networks);
//!    the counters present. Nothing to change ⇒ `Ok(None)`: no write, no
//!    SERIAL (docs/54 §5.5: a duplicate is "silently ignored", RFC 2136
//!    §2.5.1).
//! 3. [`DirectoryAdmin::apply_dns_self_update`] — inside dird's `WriteTxn`,
//!    only with the proof that auditd acknowledged the decision event
//!    (`ipc_audit_client::AckedIntent`, docs/52 R6; the event — the `Dns`
//!    shape of docs/54 §9, task DN12 — is the caller's, attached by
//!    [`PreparedDnsUpdate::with_intent`]): re-verifies that nothing changed
//!    since the view, then the `CheckedWrite` of the host record (crate
//!    `invariants`), whose commit takes the change-seq **and the zone
//!    serial in the same transaction** (RFC 2136 §3.6). The new SERIAL is
//!    returned for dnsd (docs/54 §4.6, `Forwarded { serial }`).
//!
//! # No target from the message (docs/54 §5.5; Q-614)
//!
//! No request type here names an object: the record written is always the
//! attribute of the signer's own computer object, found from its verified
//! identity. There is no code that maps a name from a DNS message to an
//! object to change — the ADIDNS-style hijack class has no path.
//!
//! # Not an admin-plane operation
//!
//! `DnsSelfUpdate` is a host's self-service, like a user's kpasswd change
//! (crate::change_password): no operation digest, so no `Plan → Commit`
//! (A-167 binds the admin plane's operations; Q-982 lists which), and no
//! approver (P-22 names no DNS operation; A-159's one dual-control mechanism
//! is for the admin plane). Ticket age is not bounded here: a host signs
//! its periodic updates with a service ticket that may be hours old; the
//! account's `usable_at` and the hot-list (`revokes(authtime)`) still apply
//! (docs/questions/Q-991 item 7).
//!
//! Spec: docs/54 §4.5, §5.2-§5.6, §7.5, §9; docs/40 §2 (D166); A-22, A-119;
//! RFC 2136 §2.4, §2.5, §3.3.1, §3.6, §7.11; docs/questions/Q-614, Q-615
//! item 1, Q-991.
//!
//! Written only from, opened in this session: docs/CLEAN-ROOM.md,
//! docs/54 (whole), docs/questions/Q-613..Q-616, Q-618, PENDING-OWNER
//! (A-111, A-119, A-153, A-159, A-163, A-167), docs/46 (§1, §3, §4, §5,
//! §8), the pinned [MS-ADTS] v20261026 3.1.1.2.2.2, 3.1.1.2.6,
//! 3.1.1.5.3.1.1.2, [MS-ADSC] v20240423 2.21, 2.67, [MS-ADA1] v20180912
//! 2.315, [MS-ADA3] v20180912 2.24, RFC 1035 §2.3.1, §2.3.3, §2.3.4,
//! §3.4.1, RFC 2136 §3.3, §3.4.2, §3.6, §3.7, §7.11, §7.12 and ITU-T X.680
//! (02/2021) clause 41 Table 8 (SHA-256 of each verified against
//! tools/spec-pin/manifest.json), and this repository's own code. No other
//! implementation was consulted or recalled (docs/CLEAN-ROOM.md).

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use directory_pip::{host_address_of, host_address_value, host_label, registrable, DirectoryView};
use dirstore::{CounterState, Object, WriteTxn};
use dtyp::{Guid, Sid};
use ipc_audit::{AdminFailure, AdminRefusal, EventBody};
use ipc_audit_client::{AckedIntent, IntentRecord};
use krb_proto::{KerberosTime, PrincipalName, Realm};
use pdp::{Action, Effect, Obligation, PolicySnapshot, ReasonCode, RecordKey, Resource, ZoneId};

use crate::admin::{subject_of_facts, DirectoryAdmin};
use crate::audit::Stop;
use crate::checks::{fault_stop, store_failure, Cx};
use crate::config::{CHANGE_SEQ_COUNTER, DNS_ZONE_SERIAL_COUNTER};
use crate::invariants::{InvariantViolation, Refused};
use crate::random::RandomSource;
use crate::record;
use crate::subject::SubjectError;
use crate::time;

/// The facts of a GSS-TSIG signer keyd verified: the context's client realm
/// and name and the ticket's authtime (RFC 4120 §5.3). The caller — dird's
/// DNS PEP — builds it **only** from its `TsigVerified` proof, made only
/// from keyd's successful MIC verification over the update message (A-22:
/// "an authenticated Subject for `DnsUpdate` may come only from a verified
/// GSS-TSIG signature"; docs/54 §7.5 step 2). Nothing the DNS message says
/// about who is asking reaches this crate.
/// Spec: docs/54 §4.5 steps 2-3, §7.5; A-22; RFC 3645 §5.1; crate keyd-types
/// (the GSS acceptance facts, task DN4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsUpdateTicket {
    /// The client realm of the GSS context's ticket.
    pub crealm: Realm,
    /// The client name of the GSS context's ticket.
    pub cname: PrincipalName,
    /// The time of the initial authentication (RFC 4120 §5.3 authtime).
    pub authtime: KerberosTime,
}

/// Why a DNS self-update was refused, or failed. No variant carries a name
/// or an address (docs/CLEAN-ROOM.md); the DNS PEP maps each to its RCODE (docs/54
/// §6.6: a refusal ⇒ REFUSED, signed; a failure ⇒ SERVFAIL) and records it
/// in its `Dns` event (docs/54 §9).
/// Spec: docs/54 §6.6, §9; RFC 2136 §3.3.1 ("signal REFUSED"), §3.4.2.1
/// (SERVFAIL).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsUpdateRefusal {
    /// The signer resolves to no account, to one not usable now, or the
    /// ticket predates the account's last password set or creation.
    Unauthenticated,
    /// The signer's account is not a computer: it has no host name (docs/54
    /// §5.5: "a user — never: it has no name of its own").
    NotAComputer,
    /// The signer's account is structural — the DC, a service object —
    /// whose record, if any, comes from provisioning only (docs/54 §3.1).
    Protected,
    /// The account's names do not give a host name: its computerName is not
    /// one LDH label, or its dNSHostName is not `<computerName>.<zone>`
    /// (docs/54 §5.3; Q-614 item 3).
    NoHostName,
    /// The PDP denied `DnsUpdate` on the record; the reason is for the
    /// audit event only (A-26).
    PolicyDenied(ReasonCode),
    /// An address is not registrable: loopback, unspecified, multicast, or
    /// outside every registrable network (docs/54 §5.5; Q-614 item 8).
    AddressNotAllowed,
    /// More than eight addresses (docs/54 §4.4, §5.5; Q-614 item 2).
    TooManyAddresses,
    /// The update is malformed: an address listed twice, or a renewed
    /// address that is not in the new set.
    RequestInvalid,
    /// The directory changed since the view the update was decided on.
    Conflict,
    /// The signer's account is gone since the view.
    NotFound,
    /// Something failed; nothing was decided against the signer.
    Failed(DnsUpdateFailure),
}

/// Why a DNS self-update could not be decided or written.
/// Spec: docs/54 §6.6 ("keyd / auditd / dirstore unavailable ⇒ SERVFAIL");
/// A-83 (a missing counter is a refusal, never created here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsUpdateFailure {
    /// DNS self-updates are not enabled in this PEP's configuration
    /// (`AdminConfig::with_dns_registration`).
    NotConfigured,
    /// The store could not answer, or a counter is missing or exhausted.
    Store,
    /// A stored record did not verify or is inconsistent.
    Integrity,
    /// An internal step failed (a misassembled caller, a time out of range).
    Internal,
}

impl From<Stop> for DnsUpdateRefusal {
    /// A check of the shared machinery (crate::checks), as this operation
    /// reports it.
    fn from(stop: Stop) -> DnsUpdateRefusal {
        match stop {
            Stop::Refused(AdminRefusal::Conflict) => DnsUpdateRefusal::Conflict,
            Stop::Refused(AdminRefusal::NotFound) => DnsUpdateRefusal::NotFound,
            Stop::Refused(AdminRefusal::TargetProtected) => DnsUpdateRefusal::Protected,
            Stop::Refused(_) => DnsUpdateRefusal::RequestInvalid,
            Stop::Failed(AdminFailure::IntegrityFailure) => {
                DnsUpdateRefusal::Failed(DnsUpdateFailure::Integrity)
            }
            Stop::Failed(AdminFailure::StoreFailure | AdminFailure::ViewUnavailable) => {
                DnsUpdateRefusal::Failed(DnsUpdateFailure::Store)
            }
            Stop::Failed(_) => DnsUpdateRefusal::Failed(DnsUpdateFailure::Internal),
        }
    }
}

/// The signer's own host, decided (step 1, module documentation): who it
/// is, its host name, its current addresses, and — private — the state the
/// write will be re-verified against. Not `Clone`: one decision, one write.
/// Spec: docs/54 §4.5 steps 3-5, §5.5.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsHost {
    requester: Sid,
    guid: Guid,
    label: String,
    host_name: String,
    addresses: Vec<Ipv4Addr>,
    obligations: Vec<Obligation>,
    reason: ReasonCode,
    seen: Object,
    change_seq: CounterState,
}

impl DnsHost {
    /// The signer's objectSid (the event's requester).
    #[must_use]
    pub fn requester(&self) -> &Sid {
        &self.requester
    }

    /// The signer's objectGUID — the record's owning object (the event's
    /// target).
    #[must_use]
    pub fn owner(&self) -> Guid {
        self.guid
    }

    /// The host label (the computerName, one LDH label).
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The host's fully qualified name as stored (its dNSHostName,
    /// `<label>.<zone>`): every name of the update message must equal it,
    /// compared without case (docs/54 §5.5; RFC 1035 §2.3.3).
    #[must_use]
    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    /// The host's current addresses (the A RRset the update's prerequisites
    /// and updates act on — RFC 2136 §2.4, §2.5), ascending.
    #[must_use]
    pub fn addresses(&self) -> &[Ipv4Addr] {
        &self.addresses
    }

    /// The obligations of the PDP's Allow other than the audit record
    /// (docs/11 §2: "the PEP must honour obligations").
    #[must_use]
    pub fn obligations(&self) -> &[Obligation] {
        &self.obligations
    }

    /// The PDP's reason code of the Allow (for the audit event).
    #[must_use]
    pub fn pdp_reason(&self) -> ReasonCode {
        self.reason
    }
}

/// The new state of the host record the DNS PEP computed from RFC 2136's
/// update section over [`DnsHost::addresses`].
/// Spec: docs/54 §4.5 step 6, §5.5; RFC 2136 §2.5, §3.4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHostUpdate {
    /// The record's complete new address set (empty: the record removed —
    /// RFC 2136 §2.5.2, §2.5.3 "Delete an RRset" / "all RRsets").
    pub addresses: Vec<Ipv4Addr>,
    /// The addresses of the new set this update registers (again) now —
    /// those an "Add to an RRset" (RFC 2136 §2.5.1) names. An address
    /// already registered and renewed here starts a new `dns_record_max_age`
    /// (docs/54 §5.2: "the client must re-register"); a new address is
    /// registered now whether listed or not.
    pub renewed: Vec<Ipv4Addr>,
}

/// A DNS self-update decided and ready for its decision event (step 2).
/// Not `Clone`. Attach the decision event with
/// [`PreparedDnsUpdate::with_intent`]; only its acknowledgement lets
/// [`DirectoryAdmin::apply_dns_self_update`] write.
/// Spec: docs/54 §4.5 steps 6-7, §9; docs/52 §3.11 R6.
#[derive(Debug, PartialEq, Eq)]
pub struct PreparedDnsUpdate {
    host: DnsHost,
    addresses: Vec<Ipv4Addr>,
    renewed: Vec<Ipv4Addr>,
    added: usize,
    removed: usize,
}

impl PreparedDnsUpdate {
    /// The decided host (requester, owner, name, the addresses before).
    #[must_use]
    pub fn host(&self) -> &DnsHost {
        &self.host
    }

    /// The record's new address set, ascending.
    #[must_use]
    pub fn addresses(&self) -> &[Ipv4Addr] {
        &self.addresses
    }

    /// How many addresses the write adds (docs/54 §9: the decision event
    /// records counts, not addresses as text).
    #[must_use]
    pub fn added(&self) -> usize {
        self.added
    }

    /// How many addresses the write removes.
    #[must_use]
    pub fn removed(&self) -> usize {
        self.removed
    }

    /// How many already registered addresses the write registers again.
    #[must_use]
    pub fn renewed(&self) -> usize {
        self.renewed.len()
    }

    /// This update with its decision event — the intent record auditd must
    /// acknowledge before the write (docs/52 R6; docs/54 §9: "audit decision
    /// acknowledged before the commit"). The event is the caller's (the
    /// `Dns` shape, task DN12); it must record this update.
    /// Spec: docs/54 §4.5 step 7, §9; docs/52 §3.11 R6 (a).
    #[must_use]
    pub fn with_intent(self, event: EventBody) -> RecordedDnsUpdate {
        RecordedDnsUpdate {
            prepared: self,
            event,
        }
    }
}

/// A prepared DNS self-update and its decision event: the
/// `ipc_audit_client::IntentRecord` whose acknowledgement
/// [`DirectoryAdmin::apply_dns_self_update`] requires. Not `Clone`: one
/// acknowledgement, one write.
/// Spec: docs/52 §3.11 R6 (a); docs/54 §9.
#[derive(Debug, PartialEq, Eq)]
pub struct RecordedDnsUpdate {
    prepared: PreparedDnsUpdate,
    event: EventBody,
}

impl RecordedDnsUpdate {
    /// The prepared update.
    #[must_use]
    pub fn prepared(&self) -> &PreparedDnsUpdate {
        &self.prepared
    }
}

impl IntentRecord for RecordedDnsUpdate {
    /// The decision event the caller attached.
    fn intent_event(&self) -> EventBody {
        self.event.clone()
    }
}

/// A DNS self-update written in the caller's transaction (not yet
/// committed): the zone's new SOA SERIAL, which dird hands dnsd once the
/// transaction commits (docs/54 §4.4 (a), §4.6 `Forwarded { serial }`).
/// Spec: docs/54 §4.5 step 7, §5.4; RFC 2136 §3.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppliedDnsUpdate {
    serial: u32,
}

impl AppliedDnsUpdate {
    /// The zone's SOA SERIAL after this write (never 0 — RFC 2136 §7.11).
    #[must_use]
    pub fn serial(&self) -> u32 {
        self.serial
    }
}

/// The addresses of a host record's stored values, ascending; a value that
/// is not four octets is an inconsistent record.
/// Spec: crate directory-pip `host`; RFC 1035 §3.4.1.
fn stored_addresses(obj: &Object, host_address: dirstore::AttrId) -> Result<Vec<Ipv4Addr>, Stop> {
    let mut addresses = match obj.attribute(host_address) {
        None => Vec::new(),
        Some(attribute) => attribute
            .values
            .iter()
            .map(|v| host_address_of(&v.value))
            .collect::<Option<Vec<_>>>()
            .ok_or(Stop::Failed(AdminFailure::IntegrityFailure))?,
    };
    addresses.sort_unstable();
    Ok(addresses)
}

/// A refusal of the write invariants at the write, as this operation
/// reports it.
/// Spec: crate::invariants `InvariantViolation`.
fn invariant_refusal(refused: Refused) -> DnsUpdateRefusal {
    match refused {
        Refused::Fault(fault) => DnsUpdateRefusal::from(fault_stop(&fault)),
        Refused::Rule(rule) => match rule {
            InvariantViolation::Protected => DnsUpdateRefusal::Protected,
            InvariantViolation::NoSuchObject => DnsUpdateRefusal::NotFound,
            InvariantViolation::Name => DnsUpdateRefusal::NoHostName,
            InvariantViolation::Class | InvariantViolation::NotModifiable => {
                DnsUpdateRefusal::NotAComputer
            }
            InvariantViolation::Value => DnsUpdateRefusal::AddressNotAllowed,
            InvariantViolation::Exception
            | InvariantViolation::ReservedName
            | InvariantViolation::AccountControl
            | InvariantViolation::Sid
            | InvariantViolation::Membership => DnsUpdateRefusal::RequestInvalid,
        },
    }
}

impl<R: RandomSource> DirectoryAdmin<R> {
    /// Step 1 (module documentation): the signer's own host, decided, from
    /// ONE view — taken after the caller began its `WriteTxn`, as for every
    /// write — and the policy of the same version, at `now`, in docs/54
    /// §4.5's order: Subject, own computer, not structural, host name, PDP.
    ///
    /// # Errors
    /// [`DnsUpdateRefusal`].
    ///
    /// Spec: docs/54 §4.5 steps 3-5, §5.3, §5.5, §5.6; A-22; docs/51 §5.3;
    /// docs/questions/Q-614 items 3, 5, 6.
    pub fn dns_update_host(
        &self,
        ticket: &DnsUpdateTicket,
        view: &DirectoryView<'_>,
        policy: &PolicySnapshot,
        now: &KerberosTime,
    ) -> Result<DnsHost, DnsUpdateRefusal> {
        // Enabled, and the view of this PEP's domain (fail closed).
        let hosts = self
            .invariants
            .hosts()
            .ok_or(DnsUpdateRefusal::Failed(DnsUpdateFailure::NotConfigured))?;
        if view.context().realm() != self.config.realm()
            || view.context().naming_context() != self.config.naming_context()
        {
            return Err(DnsUpdateRefusal::Failed(DnsUpdateFailure::Internal));
        }
        let cx = Cx::dns(&self.config, &self.ids, view, policy, now)?;
        // The Subject, from keyd's facts through the directory (A-22;
        // docs/51 §5.3: the same construction as an administrator's).
        let requester = subject_of_facts(&cx, &ticket.crealm, &ticket.cname, &ticket.authtime)
            .map_err(|e| match e {
                SubjectError::NotUsable => DnsUpdateRefusal::Unauthenticated,
                SubjectError::Unavailable => DnsUpdateRefusal::Failed(DnsUpdateFailure::Store),
            })?;
        // The requester's own account — a computer: the record is its
        // attribute, the target is the identity (docs/54 §5.5).
        let own = cx.own_account(requester.guid())?;
        if own.class != self.ids.computer.id {
            return Err(DnsUpdateRefusal::NotAComputer);
        }
        if cx.is_structural_object(own.guid, &own.obj, own.class)? {
            return Err(DnsUpdateRefusal::Protected);
        }
        // Its host name, by the one rule (docs/54 §5.3).
        let sam = record::text(&own.obj, self.ids.sam_account_name)
            .map_err(|_| DnsUpdateRefusal::Failed(DnsUpdateFailure::Integrity))?
            .ok_or(DnsUpdateRefusal::Failed(DnsUpdateFailure::Integrity))?;
        let host_name = record::text(&own.obj, self.ids.dns_host_name)
            .map_err(|_| DnsUpdateRefusal::Failed(DnsUpdateFailure::Integrity))?
            .ok_or(DnsUpdateRefusal::NoHostName)?;
        let label = host_label(sam, host_name, &hosts.zone)
            .ok_or(DnsUpdateRefusal::NoHostName)?
            .to_owned();
        let host_name = host_name.to_owned();
        // The PDP: `DnsUpdate` on this record, its tier the owner's (layer
        // 4; directory-pip `object_tier` — Q-614 item 6).
        let decision = cx.decide(
            requester.subject(),
            Action::DnsUpdate,
            Resource::Dns {
                zone: ZoneId(hosts.zone.clone()),
                record: Some(RecordKey(label.clone())),
            },
        );
        if decision.effect != Effect::Allow {
            return Err(DnsUpdateRefusal::PolicyDenied(decision.reason));
        }
        let addresses = stored_addresses(&own.obj, self.ids.host_address)?;
        // Both counters the write takes (A-83: never created here).
        let change_seq = self.change_seq(&cx)?;
        let serial = cx
            .counter(DNS_ZONE_SERIAL_COUNTER)?
            .ok_or(DnsUpdateRefusal::Failed(DnsUpdateFailure::Store))?;
        if serial.is_exhausted() {
            return Err(DnsUpdateRefusal::Failed(DnsUpdateFailure::Store));
        }
        Ok(DnsHost {
            requester: *requester.sid(),
            guid: own.guid,
            label,
            host_name,
            addresses,
            obligations: decision
                .obligations
                .into_iter()
                .filter(|o| !matches!(o, Obligation::Audit))
                .collect(),
            reason: decision.reason,
            seen: own.obj,
            change_seq,
        })
    }

    /// Step 2 (module documentation): the new state `update` of `host`'s
    /// record, judged — distinct addresses, at most eight, each
    /// registrable; renewed ⊆ the new set. `Ok(None)` when nothing would
    /// change (the same set, nothing renewed): no write, no SERIAL.
    ///
    /// # Errors
    /// [`DnsUpdateRefusal::RequestInvalid`],
    /// [`DnsUpdateRefusal::TooManyAddresses`],
    /// [`DnsUpdateRefusal::AddressNotAllowed`],
    /// [`DnsUpdateRefusal::Failed`] (not configured).
    ///
    /// Spec: docs/54 §5.5; RFC 2136 §2.5.1 (duplicates "silently ignored");
    /// docs/questions/Q-614 items 2, 8.
    pub fn prepare_dns_self_update(
        &self,
        host: DnsHost,
        update: &DnsHostUpdate,
    ) -> Result<Option<PreparedDnsUpdate>, DnsUpdateRefusal> {
        let hosts = self
            .invariants
            .hosts()
            .ok_or(DnsUpdateRefusal::Failed(DnsUpdateFailure::NotConfigured))?;
        let new: BTreeSet<Ipv4Addr> = update.addresses.iter().copied().collect();
        if new.len() != update.addresses.len() {
            return Err(DnsUpdateRefusal::RequestInvalid);
        }
        let renewed: BTreeSet<Ipv4Addr> = update.renewed.iter().copied().collect();
        if renewed.len() != update.renewed.len() || !renewed.is_subset(&new) {
            return Err(DnsUpdateRefusal::RequestInvalid);
        }
        if new.len() > directory_pip::MAX_HOST_ADDRESSES {
            return Err(DnsUpdateRefusal::TooManyAddresses);
        }
        if !new.iter().all(|a| registrable(*a, &hosts.networks)) {
            return Err(DnsUpdateRefusal::AddressNotAllowed);
        }
        let before: BTreeSet<Ipv4Addr> = host.addresses.iter().copied().collect();
        let renewed: Vec<Ipv4Addr> = renewed.intersection(&before).copied().collect();
        if new == before && renewed.is_empty() {
            return Ok(None);
        }
        Ok(Some(PreparedDnsUpdate {
            added: new.difference(&before).count(),
            removed: before.difference(&new).count(),
            addresses: new.into_iter().collect(),
            renewed,
            host,
        }))
    }

    /// Step 3 (module documentation): write `recorded` inside `txn`, the
    /// transaction the view of step 1 was taken in — only with auditd's
    /// acknowledgement of its decision event. Re-verifies that no write
    /// committed since (the change-seq state) and that the owner is
    /// unchanged; then the host record's `CheckedWrite`, whose commit takes
    /// the change-seq and the zone serial. Commit `txn` on `Ok`; on `Err`
    /// abort it (nothing is consumed — A-83).
    ///
    /// # Errors
    /// [`DnsUpdateRefusal::Conflict`], [`DnsUpdateRefusal::NotFound`], a
    /// refusal of the write invariants, [`DnsUpdateRefusal::Failed`].
    ///
    /// Spec: docs/54 §4.5 steps 6-7, §5.4; RFC 2136 §3.5 ("commit the change
    /// to nonvolatile storage before sending a response" — the caller's
    /// commit), §3.6, §3.7; docs/52 §3.11 R6 (a), R13; A-83.
    pub fn apply_dns_self_update(
        &self,
        recorded: AckedIntent<RecordedDnsUpdate>,
        txn: &mut WriteTxn<'_>,
        now: &KerberosTime,
    ) -> Result<AppliedDnsUpdate, DnsUpdateRefusal> {
        let RecordedDnsUpdate { prepared, .. } = recorded.into_inner();
        let PreparedDnsUpdate {
            host,
            addresses,
            renewed,
            ..
        } = prepared;
        // 1. Nothing committed since the view (crate::apply, item 1).
        let change_seq = txn
            .counter(CHANGE_SEQ_COUNTER)
            .map_err(|e| DnsUpdateRefusal::from(store_failure(&e)))?
            .ok_or(DnsUpdateRefusal::Failed(DnsUpdateFailure::Store))?;
        if change_seq != host.change_seq {
            return Err(DnsUpdateRefusal::Conflict);
        }
        // 2. The owner is unchanged (crate::apply, item 2).
        match txn
            .get_object(host.guid)
            .map_err(|e| DnsUpdateRefusal::from(store_failure(&e)))?
        {
            None => return Err(DnsUpdateRefusal::NotFound),
            Some(current) if current != host.seen => return Err(DnsUpdateRefusal::Conflict),
            Some(_) => {}
        }
        let dstime =
            time::dstime(now).ok_or(DnsUpdateRefusal::Failed(DnsUpdateFailure::Internal))?;
        let checked = self
            .invariants
            .check_host_record(
                txn,
                host.guid,
                addresses.iter().copied().map(host_address_value).collect(),
                renewed.iter().copied().map(host_address_value).collect(),
                record::encode_int64(dstime),
            )
            .map_err(invariant_refusal)?;
        let committed = self.commit(checked, txn, now)?;
        let serial = committed
            .zone_serial
            .ok_or(DnsUpdateRefusal::Failed(DnsUpdateFailure::Internal))?;
        Ok(AppliedDnsUpdate { serial })
    }
}
