//! The one lookup path from a requested principal name to a directory
//! object (task PN4; docs/59 §6, wave 2; decision A-173).
//!
//! # What it is
//!
//! [`DirectoryView::canonical_principal`] is the only place in this crate
//! that turns a name received in a request into an object: the KDC's
//! client and service lookups ([`kdc::AccountSource`], crate::view) and the
//! ticket-subject lookup of the admin plane's, kpasswd's, the DNS update's
//! and the LDAP session's subject checks (crate::subject, the
//! `TicketClient` context — task PN10b) are thin wrappers of it, and dird's
//! service-object checks call it directly, so every consumer that resolves
//! a principal by name passes through it (docs/59 §6.1, R59-5). The result
//! is a [`ResolvedPrincipal`], built only here.
//!
//! # The steps (docs/59 §6.1)
//!
//! 1. **The request's key**: `principal_names::key_of_request` — at most one
//!    key for any request; a foreign realm, a malformed name, `krbtgt/X` and
//!    every name that would reach the krbtgt account give none (the KDC
//!    names the TGS only through its configured handle — R47-2).
//! 2. **The request half of the phase-1 acceptance** (R47-1; docs/59 §6.3,
//!    wave 2): the realm is the configured realm octet for octet; a client
//!    name has one component, a service name two or more.
//! 3. **One probe** for that key (below, "The probe").
//! 4. **The class** of the object found, from authoritative data
//!    (crate::principal), filtered by the [`LookupCtx`]: a group, the krbtgt
//!    account (RID 502) or a non-principal is no client and no service; a
//!    service is a computer (R47-13).
//! 5. **Re-derivation**: `principal_names::keys_of_names` of the object's
//!    stored names, with the configured provisioned service objects (Q-1019
//!    (a)). A name the namespace refuses, or a probed key that is not one of
//!    the object's keys, is a fault (fail closed — docs/59 §6.1 step 3); the
//!    kinds of the probed key are what was matched, and a kind the context
//!    does not accept is "no such principal" (docs/59 §6.2).
//! 6. **The stored half of the acceptance**: the stored value of the
//!    accepted kind equals the request octet for octet (A-27) — the stored
//!    sAMAccountName for a client, a stored servicePrincipalName for a
//!    service. That stored value is the canonical name.
//! 7. **The key purpose**, from the canonical (stored) name and never from
//!    the request's spelling (docs/59 §6.1 step 6; Q-1009 item 3): the one
//!    derivation `KeyPurpose::of_service_name` (R2b) over the canonical name,
//!    cross-checked against the reserved-name predicate on the folded key
//!    (`principal_names::reserved_name_of`, Q-1009 items 1-2) — the two
//!    disagree only for a case variant of a reserved name, which is refused
//!    (class C49: one name, one equivalence).
//! 8. **The claim of a reserved purpose** (A-163 at the lookup; task PN10,
//!    docs/questions/Q-1027 item 6): an `AdminService` or
//!    `ChangePasswordService` key set resolves only on a provisioned service
//!    object (class `ProvisionedService`, from the configured set); on any
//!    other object it is a fault (fail closed).
//! 9. **The snapshot** (module documentation, "`snapshot`").
//!
//! # The probe — the union index (task PN4b; docs/questions/Q-1026)
//!
//! The probe is ONE lookup of the request's key in the namespace's own
//! unique index, `ad_schema::PRINCIPAL_NAME_KEY` (docs/59 §6.1 step 2): the
//! values the one checker writes for every principal it creates —
//! `principal_names::keys_of_names` of its stored names (N7, task PN5) —
//! unique over the union of every kind (task PN2). There is no second probe
//! in another name space when it finds nothing, and no per-kind index is
//! asked at all (class C31; docs/59 §5.3). Which kinds the found key
//! carries is re-derived from the object after the probe (step 5), and the
//! context keeps only the kind it accepts — so the per-kind probe of wave 2
//! (A-178) is gone without any change of what is accepted: on a store whose
//! principals carry their keys, an object holds key *K* with kind *k*
//! exactly when its *k* name folds to *K*, and at most one object holds *K*,
//! so the union probe finds the object the per-kind probe found whenever the
//! context accepts it (tests/canonical_principal.rs: the equivalence over
//! 19 requests × 4 contexts). A key is at most
//! `principal_names::MAX_KEY_OCTETS` octets by construction, and
//! [`crate::DirectoryContext::new`] requires the attribute to hold that many
//! (fail closed at setup), so the probe never asks the store an over-long
//! value.
//!
//! The same probe answers the one other question this crate asks by name:
//! which object holds a host name as its `HostName` key
//! (`DirectoryView::host_name_holder`, for crate::host's DNS record owner —
//! docs/questions/Q-1036 item 6). No lookup context accepts that kind
//! (docs/59 §6.2); the DNS owner rule keeps only it.
//!
//! # The classes (docs/CLEAN-ROOM.md)
//!
//! - **C31 (docs/59 §3 M1)** — an identity lookup through a fallback chain
//!   of name spaces: one key per request, one probe, the kind decided after
//!   the probe from the object; no "$", UPN, enterprise or one-component
//!   sname retry exists in code.
//! - **C49 (M3)** — name equivalence computed by more than one function:
//!   the key comes from crate `principal-names`, the purpose and the class
//!   from the resolved object (its stored canonical name, its class), and a
//!   stored name whose octet-defined purpose disagrees with its folded
//!   reservation is refused.
//! - **C3 on dird's side (M4; task PN10)** — the key that attests "name N
//!   is key set K" could be applied to a mapping no lookup made: the signer
//!   accepts only a [`ResolvedPrincipal`] (module documentation, "From a
//!   resolution to dird's statement").
//!
//! # Residuals (documented, not hidden)
//!
//! - An object reaches a name only through the keys the checker wrote. An
//!   object written beneath the checker without keys (a development store
//!   from before task PN5 — no product store: dird refuses one without the
//!   `principal-namespace` marker from task PN10 on) is no principal to
//!   this path (docs/questions/Q-1031). An object whose names changed
//!   beneath the checker after its keys were written is found by an old
//!   key and refused by the re-derivation (step 5 — fail closed).
//! - An object whose stored names the namespace refuses has no keys (the
//!   checker refuses it); if it holds keys written before such a name
//!   (beneath the checker), it is a fault when found: a userPrincipalName
//!   with a foreign suffix, a stored three-part SPN, `KRBTGT/…`, a case
//!   variant of a reserved name; a "@" in a sAMAccountName, or one equal to
//!   the realm alias, is a name no request can probe (Q-1026 item 3).
//! - Whether a resolved reserved purpose belongs to the provisioning claim
//!   that owns it (A-163) is first the writer's check (task PN5). The lookup
//!   knows the provisioned service objects only as a set (Q-1019), which
//!   dird passes from its manifest since task PN10 (docs/questions/Q-1027
//!   item 7, Q-1043): step 8 below refuses a reserved purpose on any other
//!   object. A context without the set (dird without its admin service,
//!   which has no manifest) therefore resolves no reserved name — fail
//!   closed (docs/questions/Q-1046).
//!
//! # From a resolution to dird's statement (task PN10; docs/59 §7)
//!
//! [`ResolvedPrincipal::name_resolution`] is the one conversion of a
//! resolution into the `keyd_types::NameResolution` keyd verifies (docs/59
//! §7.1): the request's realm and name, the canonical realm and name, the
//! principal and the key purpose — each the resolution's own — the
//! `snapshot` ([`ResolvedPrincipal::snapshot`]) and the issue time the
//! caller's clock gives. A [`NameResolutionSigner`] — dird's attestation
//! key, held by crates/ipc-directory-server — attests a resolution, and its
//! one method takes a [`ResolvedPrincipal`], the capability only this
//! module builds: dird's key tags only what the one lookup path resolved,
//! never a mapping some other code put together (class C3 on dird's side —
//! docs/59 §3 M4; docs/CLEAN-ROOM.md "a type that can only be built after the
//! check"). This crate links no MAC (A-63, D182): the signer is a trait
//! object the deployment installs (`DirectoryContext::
//! with_name_resolution_signer`).
//!
//! **`snapshot`.** dirstore exposes no change sequence of a snapshot (Q-1027
//! item 4 (b)); the value carried is the `origin_seq` — the change-seq of
//! docs/29 §2 — of the stamp on the probed `PRINCIPAL_NAME_KEY` value: the
//! write in which the one checker bound the requested key to this object.
//! Every object the probe reaches holds that stamped value (the probe found
//! it by it), so the field never needs a counter a store might lack, and a
//! key freed by a delete and bound again to another object later carries a
//! later sequence (docs/59 §9 S7). docs/questions/Q-1046 item 3 records the
//! choice.
//!
//! Spec: docs/59 §4.6, §4.7, §5.3, §6.1-§6.3, §7.1, §7.4, §10 (the PN4 and
//! PN10 rows); docs/47 §1.3 (R47-1), §1.4 (R47-2), R47-13;
//! docs/questions/Q-1007 items 1-4, 8, 10, Q-1009 items 1-3, Q-1011 items
//! 1, 2 (A-173), Q-1018 items 2, 5, Q-1019 (a), Q-1026 (the switch, task
//! PN4b), Q-1027 items 4, 6, 7 (A-178), Q-1036 item 6; A-27; A-163; A-178;
//! [MS-KILE] v20261110 3.1.5.7, 3.3.5.1.1, 3.3.5.1.2, 3.3.5.6.1; RFC 4120
//! §5.2.3, §6.2, §7.3; docs/29 §2 (change-seq).

use crate::error::Fault;
use crate::salt::AccountKind;
use crate::view::{principal_id, DirectoryView};
use ad_schema::{Phase1Schema, PRINCIPAL_NAME_KEY};
use dirstore::Object;
use dtyp::{Guid, Sid};
use kdc::AccountSourceError;
use keyd_types::{
    AttestedNameResolution, KeyHandle, KeyPurpose, NameResolution, NameResolutionError,
    NameResolutionFields, PrincipalId,
};
use krb_proto::constants::KRB_NT_UNKNOWN;
use krb_proto::{KerberosString, KerberosTime, PrincipalName, Realm};
use principal_names::{
    key_of_request, keys_of_names, reserved_name_of, KindSet, NameKind, PrincipalClass,
    PrincipalKey, RequestKey, ReservedName, MAX_KEY_OCTETS,
};

/// The separator of an SPN's parts in its stored single-string form.
/// Spec: [MS-ADTS] 2.2.21; [MS-KILE] 3.1.5.11.
const SPN_SEPARATOR: char = '/';

/// The context a requested name is looked up in: which kinds of name it
/// accepts and which objects it may resolve to (docs/59 §6.2).
///
/// In wave 2 (the phase-1 acceptance, docs/59 §6.3) the two client contexts
/// accept the same names, as do the two service contexts; they are kept
/// apart because their acceptance diverges when it widens (task PN14:
/// `TgsServer` takes a one-component name, `ServiceObject` never does).
/// Spec: docs/59 §6.2 (the table); docs/47 §1.3 (R47-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LookupCtx {
    /// The client name of an AS request (cname). Spec: docs/59 §6.2;
    /// [MS-KILE] 3.3.5.6.1; docs/47 §1.3 AS.
    AsClient,
    /// The client name in a ticket this realm's KDC issued — the admin
    /// plane's, kpasswd's and the DNS update's subject, the LDAP session
    /// check (crate::subject; task PN10b). Spec: docs/59 §6.2, §6.4;
    /// docs/questions/Q-1047 (A-187).
    TicketClient,
    /// The server name of a TGS request (sname). Spec: docs/59 §6.2;
    /// [MS-KILE] 3.3.5.1.1; docs/47 §1.3 TGS.
    TgsServer,
    /// A provisioned service object's own name (dird's admin and
    /// change-password service checks). Spec: docs/59 §6.2.
    ServiceObject,
}

/// The one kind of name a context accepts under the phase-1 acceptance
/// (R47-1: "AS = sAMAccountName, TGS = SPN"; docs/59 §6.3 wave 2).
/// Spec: docs/47 §1.3 (R47-1); docs/59 §6.3; docs/questions/Q-1007 item 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptedName {
    /// sAMAccountName, one component. Spec: docs/47 §1.3 AS steps 2-4.
    SamAccountName,
    /// servicePrincipalName, two or more components joined with "/".
    /// Spec: docs/47 §1.3 TGS steps 2-3.
    ServicePrincipalName,
}

impl AcceptedName {
    /// The namespace kind it is. Spec: docs/59 §4.1.
    const fn kind(self) -> NameKind {
        match self {
            AcceptedName::SamAccountName => NameKind::SamAccountName,
            AcceptedName::ServicePrincipalName => NameKind::ServicePrincipalName,
        }
    }

    /// `true` if the request's name has the shape this kind takes: one
    /// component for a sAMAccountName, two or more for an SPN.
    /// Spec: docs/47 §1.3 AS step 2, TGS step 2 (R47-1).
    fn takes_component_count(self, count: usize) -> bool {
        match self {
            AcceptedName::SamAccountName => count == 1,
            AcceptedName::ServicePrincipalName => count >= 2,
        }
    }
}

impl LookupCtx {
    /// The kind of name the context accepts in wave 2.
    /// Spec: docs/59 §6.3 (wave 2); docs/47 §1.3 (R47-1).
    const fn accepted(self) -> AcceptedName {
        match self {
            LookupCtx::AsClient | LookupCtx::TicketClient => AcceptedName::SamAccountName,
            LookupCtx::TgsServer | LookupCtx::ServiceObject => AcceptedName::ServicePrincipalName,
        }
    }

    /// `true` if an object of `class` may be what the context resolves to:
    /// a client is a user or a computer account, a service a computer
    /// account; never a group (Q-1007 item 7) and never the krbtgt account
    /// (R47-2 — the KDC reaches it through its configured handle only).
    /// Spec: docs/59 §6.1 step 4, §6.2; docs/47 §1.3 AS step 5, TGS step 4,
    /// §1.4 (R47-2), R47-13.
    const fn admits(self, class: PrincipalClass) -> bool {
        let computer = matches!(
            class,
            PrincipalClass::Computer
                | PrincipalClass::DomainController
                | PrincipalClass::ProvisionedService
        );
        match self.accepted() {
            AcceptedName::SamAccountName => computer || matches!(class, PrincipalClass::User),
            AcceptedName::ServicePrincipalName => computer,
        }
    }
}

/// A requested principal name resolved to one directory object — built only
/// by [`DirectoryView::canonical_principal`] (a capability type: holding one
/// means the one lookup path accepted the name; docs/59 §4.7).
///
/// It carries what the account records are built from (crate::view) and
/// what a `keyd_types::NameResolution` needs (task PN10): the request's
/// realm and name, the canonical realm and name, the principal and the key
/// purpose. Names are not secrets (docs/59 §4.6); `Debug` shows no
/// directory value beyond them.
/// Spec: docs/59 §4.7, §6.1, §7.1; docs/questions/Q-1011 item 1.
pub struct ResolvedPrincipal {
    /// The live object found (read from the view's one snapshot).
    object: Object,
    /// keyd's principal identifier: the objectGUID (R47-3).
    principal: PrincipalId,
    /// objectSid.
    sid: Sid,
    /// The salt rule's account kind (user / computer).
    account_kind: AccountKind,
    /// The class, from authoritative data and the configured provisioned
    /// service objects (crate::principal; Q-1019).
    class: PrincipalClass,
    /// The kinds of the key that was matched (docs/59 §4.7 `matched`).
    matched: KindSet,
    /// The context it was resolved in.
    lookup: LookupCtx,
    /// The realm the request carried.
    realm_as_sent: Realm,
    /// The name the request carried.
    name_as_sent: PrincipalName,
    /// The configured realm.
    canonical_realm: Realm,
    /// The stored name it resolved to: the sAMAccountName of a client, the
    /// servicePrincipalName of a service (the request's name-type kept).
    canonical_name: PrincipalName,
    /// The purpose of its key set, from the canonical name (Q-1009 item 3).
    key_purpose: KeyPurpose,
    /// The change-seq (`origin_seq`) of the write that bound the probed key
    /// to the object (module documentation, "`snapshot`").
    snapshot: u64,
}

impl ResolvedPrincipal {
    /// The object's GUID.
    #[must_use]
    pub fn guid(&self) -> Guid {
        self.object.guid
    }

    /// keyd's principal identifier (the objectGUID). Spec: docs/47 §2.3.
    #[must_use]
    pub fn principal(&self) -> PrincipalId {
        self.principal
    }

    /// The object's objectSid.
    #[must_use]
    pub fn sid(&self) -> &Sid {
        &self.sid
    }

    /// The account kind (user / computer).
    #[must_use]
    pub fn account_kind(&self) -> AccountKind {
        self.account_kind
    }

    /// The object's class (crate::principal).
    #[must_use]
    pub fn class(&self) -> PrincipalClass {
        self.class
    }

    /// The kinds of the matched key. Spec: docs/59 §4.7, §6.1 step 3.
    #[must_use]
    pub fn matched(&self) -> KindSet {
        self.matched
    }

    /// The context it was resolved in.
    #[must_use]
    pub fn lookup(&self) -> LookupCtx {
        self.lookup
    }

    /// The realm the request carried. Spec: docs/59 §4.7 (`realm_as_sent`).
    #[must_use]
    pub fn realm_as_sent(&self) -> &Realm {
        &self.realm_as_sent
    }

    /// The name the request carried. Spec: docs/59 §4.7 (`name_as_sent`).
    #[must_use]
    pub fn name_as_sent(&self) -> &PrincipalName {
        &self.name_as_sent
    }

    /// The configured realm. Spec: docs/59 §4.7 (`canonical_realm`).
    #[must_use]
    pub fn canonical_realm(&self) -> &Realm {
        &self.canonical_realm
    }

    /// The stored name it resolved to. Spec: docs/59 §4.7
    /// (`canonical_name`).
    #[must_use]
    pub fn canonical_name(&self) -> &PrincipalName {
        &self.canonical_name
    }

    /// The purpose of its key set. Spec: docs/59 §4.7, §6.1 step 6.
    #[must_use]
    pub fn key_purpose(&self) -> KeyPurpose {
        self.key_purpose
    }

    /// keyd's handle of its key set: `(objectGUID, key_purpose)`.
    /// Spec: docs/47 §2.3 (R47-3); docs/10 §1.
    #[must_use]
    pub fn key_handle(&self) -> KeyHandle {
        KeyHandle::new(self.principal, self.key_purpose)
    }

    /// The change-seq of the write that bound the probed key to the object
    /// — the `snapshot` of the resolution dird states (module documentation,
    /// "`snapshot`").
    /// Spec: docs/59 §4.7 (`snapshot`), §7.1; docs/29 §2 (change-seq);
    /// docs/questions/Q-1027 item 4 (b), Q-1046 item 3.
    #[must_use]
    pub fn snapshot(&self) -> u64 {
        self.snapshot
    }

    /// The resolution dird states for this lookup (docs/59 §7.1), issued at
    /// `issued_at` (the attesting process's clock — dird's; keyd checks it
    /// against its own, R50-5): the request's realm and name, the canonical
    /// realm and name, the principal and key purpose and the
    /// [`ResolvedPrincipal::snapshot`] — every field this resolution's own,
    /// none taken from the caller but the time. The one conversion
    /// (module documentation); a [`NameResolutionSigner`] tags its result.
    ///
    /// # Errors
    /// `NameResolutionError` if a name or realm is outside the bounds of a
    /// resolution (keyd-types: at most `MAX_NAME_COMPONENTS` components of
    /// at most `MAX_NAME_OCTETS` octets — the bounds of a key set's binding,
    /// so a name no key set can be bound to is never attested). The caller
    /// refuses then (fail closed).
    ///
    /// Spec: docs/59 §4.7, §7.1; docs/questions/Q-1011 item 1 (A-173),
    /// Q-1027 item 4; RFC 4120 §5.2.3; docs/CLEAN-ROOM.md.
    pub fn name_resolution(
        &self,
        issued_at: KerberosTime,
    ) -> Result<NameResolution, NameResolutionError> {
        NameResolution::new(NameResolutionFields {
            realm_as_sent: self.realm_as_sent.clone(),
            name_as_sent: self.name_as_sent.clone(),
            canonical_realm: self.canonical_realm.clone(),
            canonical_name: self.canonical_name.clone(),
            principal: self.principal,
            key_purpose: self.key_purpose,
            snapshot: self.snapshot,
            issued_at,
        })
    }

    /// The object itself, for the account records and the ticket-subject
    /// facts built in this crate (crate::view, crate::subject).
    pub(crate) fn object(&self) -> &Object {
        &self.object
    }
}

impl core::fmt::Debug for ResolvedPrincipal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResolvedPrincipal")
            .field("guid", &self.object.guid)
            .field("class", &self.class)
            .field("matched", &self.matched)
            .field("lookup", &self.lookup)
            .field("canonical_realm", &self.canonical_realm)
            .field("canonical_name", &self.canonical_name)
            .field("key_purpose", &self.key_purpose)
            .field("snapshot", &self.snapshot)
            .finish_non_exhaustive()
    }
}

/// A [`NameResolutionSigner`] did not attest a resolution: the clock could
/// not be read, a name is outside a resolution's bounds, or the MAC failed.
/// No data (nothing about the key can reach it). The lookup that asked for
/// the attestation refuses (fail closed).
/// Spec: docs/CLEAN-ROOM.md (fail closed; no secret in an error); A-145 RC-7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignerRefused;

impl core::fmt::Display for SignerRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("name resolution not attested")
    }
}

impl std::error::Error for SignerRefused {}

/// dird's attestation of what the one lookup path resolved (task PN10;
/// docs/59 §7.1, §7.4; decision A-173 — docs/questions/Q-1011 item 2): turn
/// a [`ResolvedPrincipal`] into the `keyd_types::AttestedNameResolution`
/// the KDC forwards to keyd — [`ResolvedPrincipal::name_resolution`] at the
/// attesting process's clock, tagged with dird's attestation key
/// (HMAC-SHA-256, crate `name-attestation`).
///
/// The implementation holds the key and the clock; this crate links neither
/// (A-63, D182). The one product implementation is crates/
/// ipc-directory-server's `ResolutionSigner`; tests implement it with a
/// test key. Taking a [`ResolvedPrincipal`] — built only by the one lookup
/// path — is what keeps the key from attesting anything else (module
/// documentation).
///
/// Spec: docs/59 §3 (M4), §7.1, §7.2 (what keyd checks: the tag, the
/// canonical realm, `|now − issued_at| ≤ 30 s`), §7.4; docs/questions/
/// Q-1011 items 1-3 (A-173); docs/CLEAN-ROOM.md.
pub trait NameResolutionSigner: Send + Sync {
    /// Attest `resolved` at the signer's clock.
    ///
    /// # Errors
    /// [`SignerRefused`].
    fn attest(&self, resolved: &ResolvedPrincipal)
        -> Result<AttestedNameResolution, SignerRefused>;
}

/// `true` if the stored SPN `stored` is the request's components joined
/// with "/", octet for octet (no allocation).
/// Spec: docs/47 §1.3 TGS step 3 (the stored SPN value equal byte for
/// byte); A-27.
fn spn_equals(stored: &str, components: &[KerberosString]) -> bool {
    let mut parts = stored.split(SPN_SEPARATOR);
    let all_equal = components
        .iter()
        .all(|component| parts.next() == Some(component.as_str()));
    all_equal && parts.next().is_none()
}

/// The canonical name of a stored value: its components (split at "/" for
/// an SPN; a sAMAccountName has none), with the request's name-type — in
/// wave 2 the canonical name equals the name as sent octet for octet.
/// Spec: docs/59 §4.5, §4.7; RFC 4120 §6.2 (the name-type a hint).
fn canonical_name_of(stored: &str, name_type: i32) -> Result<PrincipalName, Fault> {
    let name_string = stored
        .split(SPN_SEPARATOR)
        .map(KerberosString::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Fault::Unavailable)?;
    Ok(PrincipalName {
        name_type,
        name_string,
    })
}

/// The key purpose of a service's canonical name: the one derivation
/// (`KeyPurpose::of_service_name`, R2b), which must agree with the
/// reserved-name predicate on the folded key — a stored name that spells a
/// reserved name in another case (`ADMIND/…`, `KADMIN/changepw`) is refused
/// (`Fault`), as is a TGS name (never stored outside the krbtgt account —
/// `keys_of_names`).
/// Spec: docs/59 §6.1 step 6, §3 M3; docs/questions/Q-1009 items 1-3; A-73;
/// RFC 3244 §2; RFC 4120 §6.2.
fn service_purpose(canonical: &PrincipalName, key: &PrincipalKey) -> Result<KeyPurpose, Fault> {
    let purpose = KeyPurpose::of_service_name(canonical);
    let consistent = match reserved_name_of(key) {
        None => purpose == KeyPurpose::Service,
        Some(ReservedName::AdminService) => purpose == KeyPurpose::AdminService,
        Some(ReservedName::ChangePasswordService) => purpose == KeyPurpose::ChangePasswordService,
        Some(ReservedName::TicketGrantingService) => false,
    };
    if consistent {
        Ok(purpose)
    } else {
        Err(Fault::Unavailable)
    }
}

/// `true` if the schema's namespace attribute (`PRINCIPAL_NAME_KEY`) holds
/// values of `principal_names::MAX_KEY_OCTETS` octets — the longest key the
/// namespace builds — so the one probe never asks the store a value longer
/// than the attribute's bound (dirstore refuses such a probe). Checked once,
/// at [`crate::DirectoryContext::new`] (fail closed at setup).
/// Spec: docs/59 §4.6 (the 2048-octet bound); docs/questions/Q-1008 item 2,
/// Q-1026 item 4; ad-schema `PRINCIPAL_NAME_KEY_MAX_OCTETS`.
pub(crate) fn namespace_index_holds_every_key(schema: &Phase1Schema) -> bool {
    schema
        .schema()
        .attribute(PRINCIPAL_NAME_KEY)
        .is_some_and(|d| d.max_value_len >= MAX_KEY_OCTETS)
}

impl DirectoryView<'_> {
    /// Resolve the principal `name` in `realm` for the context `ctx` — the
    /// one lookup path by name (module documentation). `Ok(None)` is "no
    /// such principal" (the KDC answers KDC_ERR_C/S_PRINCIPAL_UNKNOWN);
    /// `Err` is "cannot tell" (the store failed or a record is inconsistent
    /// — always a refusal).
    ///
    /// # Errors
    /// `AccountSourceError::Failed` on a store failure or an inconsistent
    /// record, including a stored name the namespace refuses.
    ///
    /// Spec: docs/59 §6.1-§6.3; docs/47 §1.3 (R47-1); A-27; Q-1026.
    pub fn canonical_principal(
        &self,
        realm: &Realm,
        name: &PrincipalName,
        ctx: LookupCtx,
    ) -> Result<Option<ResolvedPrincipal>, AccountSourceError> {
        self.resolve_principal(realm, name, ctx)
            .map_err(AccountSourceError::from)
    }

    /// [`DirectoryView::canonical_principal`] with internal faults.
    /// Spec: docs/59 §6.1 steps 1-6 (module documentation).
    pub(crate) fn resolve_principal(
        &self,
        realm: &Realm,
        name: &PrincipalName,
        ctx: LookupCtx,
    ) -> Result<Option<ResolvedPrincipal>, Fault> {
        let accepted = ctx.accepted();
        // 1. The request's one key (docs/59 §4.2). `LocalTgs` is never
        //    resolved by name: the KDC uses its configured krbtgt handle
        //    (R47-2; Q-1018 item 5).
        let key = match key_of_request(name, realm, self.ctx.name_context()) {
            RequestKey::Key(key) => key,
            RequestKey::LocalTgs | RequestKey::Foreign | RequestKey::NoSuchPrincipal => {
                return Ok(None);
            }
        };
        // 2. The request half of the phase-1 acceptance: the configured
        //    realm octet for octet; one component for a client, two or more
        //    for a service (docs/47 §1.3 AS steps 1-2, TGS steps 1-2).
        if realm.as_bytes() != self.ctx.realm().as_bytes()
            || !accepted.takes_component_count(name.name_string.len())
        {
            return Ok(None);
        }
        // 3. One probe of the union index (module documentation, "The
        //    probe").
        let Some(guid) = self.probe(&key)? else {
            return Ok(None);
        };
        let Some(object) = self.snapshot.get_object(guid)? else {
            return Ok(None);
        };
        // 4. The class, filtered by the context.
        let names = match self.principal_names_of(&object, self.ctx.service_objects()) {
            Ok(Some(names)) => names,
            Ok(None) => return Ok(None),
            Err(_) => return Err(Fault::Unavailable),
        };
        if !ctx.admits(names.class) {
            return Ok(None);
        }
        // 5. Re-derive the object's keys; the probed key must be one of
        //    them (docs/59 §6.1 step 3); its kinds are what was matched.
        let keys =
            keys_of_names(&names, self.ctx.name_context()).map_err(|_| Fault::Unavailable)?;
        let matched = keys.kinds_of(&key);
        if matched.is_empty() {
            return Err(Fault::Unavailable);
        }
        if !matched.contains(accepted.kind()) {
            return Ok(None);
        }
        // 6. The stored half of the acceptance: the stored value equals the
        //    request octet for octet (A-27); it is the canonical name.
        let stored = match accepted {
            AcceptedName::SamAccountName => {
                let [component] = name.name_string.as_slice() else {
                    return Ok(None);
                };
                (names.sam_account_name.as_bytes() == component.as_bytes())
                    .then_some(names.sam_account_name)
            }
            AcceptedName::ServicePrincipalName => names
                .service_principal_names
                .iter()
                .copied()
                .find(|spn| spn_equals(spn, &name.name_string)),
        };
        let Some(stored) = stored else {
            return Ok(None);
        };
        let canonical_name = canonical_name_of(stored, name.name_type)?;
        // The admitted classes are user / computer accounts.
        let account = self.account(&object)?.ok_or(Fault::Unavailable)?;
        // 7. The key purpose, from the canonical name (Q-1009 item 3).
        let key_purpose = match accepted {
            AcceptedName::SamAccountName => KeyPurpose::PrincipalLongterm,
            AcceptedName::ServicePrincipalName => service_purpose(&canonical_name, &key)?,
        };
        // 8. A reserved purpose belongs only to the provisioning claim that
        //    owns it (A-163): the admin and change-password key sets are a
        //    provisioned service object's, never another computer's — a
        //    store holding one elsewhere was written beneath the checker
        //    (fail closed; docs/questions/Q-1027 item 6).
        if (key_purpose == KeyPurpose::AdminService
            || key_purpose == KeyPurpose::ChangePasswordService)
            && names.class != PrincipalClass::ProvisionedService
        {
            return Err(Fault::Unavailable);
        }
        // 9. The snapshot: the change-seq of the probed key's value (module
        //    documentation, "`snapshot`"); the probe found the object by it,
        //    so its absence is an inconsistency (fail closed).
        let snapshot = object
            .attribute(PRINCIPAL_NAME_KEY)
            .and_then(|attribute| {
                attribute
                    .values
                    .iter()
                    .find(|value| value.value == key.as_bytes())
            })
            .map(|value| value.stamp.origin_seq)
            .ok_or(Fault::Unavailable)?;
        Ok(Some(ResolvedPrincipal {
            principal: principal_id(object.guid),
            sid: account.sid,
            account_kind: account.kind,
            class: names.class,
            matched,
            lookup: ctx,
            realm_as_sent: realm.clone(),
            name_as_sent: name.clone(),
            canonical_realm: self.ctx.realm().clone(),
            canonical_name,
            key_purpose,
            snapshot,
            object,
        }))
    }

    /// The object holding the host name `host_name` as its `HostName` key
    /// (docs/59 §4.1: `fold(host)`), found through the one probe — never a
    /// per-kind index (docs/59 §5.3; docs/questions/Q-1036 item 6). The key
    /// is the request key of `host_name` as a one-component name in the
    /// configured realm: one component without "@" is its fold (docs/59
    /// §4.2) — the very key a holder stores for its dNSHostName (§4.1; the
    /// name-type is "not significant when checking for equivalence", RFC
    /// 4120 §6.2). After the probe the object's keys are re-derived as for
    /// a principal: a probed key that is not among them is a fault (fail
    /// closed — docs/59 §6.1 step 3); a key of another kind (a
    /// sAMAccountName spelled like a host name) holds no host name
    /// (`None`). What the DNS owner rule asks beyond that is crate::host's.
    /// Spec: docs/59 §4.1, §4.2, §5.3, §6.1 steps 2-3; docs/questions/Q-1007
    /// item 8, Q-1010 items 1-3, Q-1036 item 6; RFC 4120 §6.2; [MS-ADTS]
    /// 3.1.1.5.3.1.1.2.
    pub(crate) fn host_name_holder(&self, host_name: &str) -> Result<Option<Object>, Fault> {
        let Ok(component) = KerberosString::new(host_name) else {
            return Ok(None);
        };
        let name = PrincipalName {
            name_type: KRB_NT_UNKNOWN,
            name_string: vec![component],
        };
        let key = match key_of_request(&name, self.ctx.realm(), self.ctx.name_context()) {
            RequestKey::Key(key) => key,
            RequestKey::LocalTgs | RequestKey::Foreign | RequestKey::NoSuchPrincipal => {
                return Ok(None);
            }
        };
        let Some(guid) = self.probe(&key)? else {
            return Ok(None);
        };
        let Some(object) = self.snapshot.get_object(guid)? else {
            return Ok(None);
        };
        let names = match self.principal_names_of(&object, self.ctx.service_objects()) {
            Ok(Some(names)) => names,
            Ok(None) => return Ok(None),
            Err(_) => return Err(Fault::Unavailable),
        };
        let matched = keys_of_names(&names, self.ctx.name_context())
            .map_err(|_| Fault::Unavailable)?
            .kinds_of(&key);
        if matched.is_empty() {
            return Err(Fault::Unavailable);
        }
        Ok(matched.contains(NameKind::HostName).then_some(object))
    }

    /// The one probe (module documentation, "The probe"; docs/questions/
    /// Q-1026): the namespace's unique index `PRINCIPAL_NAME_KEY`, asked
    /// once with the key. The only lookup of a name in this crate (guard:
    /// tests/one_lookup_path.rs).
    /// Spec: docs/59 §4.6, §5.3, §6.1 step 2; docs/46 §8.5; A-173.
    fn probe(&self, key: &PrincipalKey) -> Result<Option<Guid>, Fault> {
        Ok(self
            .snapshot
            .lookup_unique(PRINCIPAL_NAME_KEY, key.as_bytes())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kstrs(parts: &[&str]) -> Vec<KerberosString> {
        parts
            .iter()
            .map(|p| KerberosString::new(p).unwrap())
            .collect()
    }

    /// docs/47 §1.3 TGS step 3 (octet for octet); Q-070 item 12 (one
    /// component list per joined form).
    #[test]
    fn spn_equality_is_octet_for_octet_per_component() {
        let stored = "host/ws01.example.test";
        assert!(spn_equals(stored, &kstrs(&["host", "ws01.example.test"])));
        assert!(!spn_equals(stored, &kstrs(&["HOST", "ws01.example.test"])));
        assert!(!spn_equals(stored, &kstrs(&["host"])));
        assert!(!spn_equals(
            stored,
            &kstrs(&["host", "ws01.example.test", "x"])
        ));
        assert!(!spn_equals(stored, &kstrs(&["host/ws01.example.test"])));
        assert!(!spn_equals(stored, &kstrs(&[])));
    }

    /// docs/59 §4.6 (the 2048-octet bound), Q-1008 item 2, Q-1026 item 4:
    /// the phase-1 schema's namespace attribute holds the longest key the
    /// namespace builds, so the one probe never asks an over-long value.
    #[test]
    fn the_namespace_index_holds_every_key() {
        let p1 = ad_schema::phase1().unwrap();
        assert!(namespace_index_holds_every_key(&p1));
        assert_eq!(
            p1.schema()
                .attribute(PRINCIPAL_NAME_KEY)
                .map(|d| d.max_value_len),
            Some(MAX_KEY_OCTETS)
        );
    }

    /// docs/47 §1.3 (R47-1: AS = one component; TGS = two or more); docs/59
    /// §6.2 (groups and the krbtgt account in no context; services are
    /// computers).
    #[test]
    fn contexts_accept_one_kind_and_admit_their_classes() {
        use PrincipalClass::*;
        for ctx in [LookupCtx::AsClient, LookupCtx::TicketClient] {
            assert_eq!(ctx.accepted(), AcceptedName::SamAccountName);
            assert!(ctx.accepted().takes_component_count(1));
            assert!(!ctx.accepted().takes_component_count(2));
            for class in [User, Computer, DomainController, ProvisionedService] {
                assert!(ctx.admits(class), "{ctx:?} {class:?}");
            }
            for class in [TicketGrantingService, Group] {
                assert!(!ctx.admits(class), "{ctx:?} {class:?}");
            }
        }
        for ctx in [LookupCtx::TgsServer, LookupCtx::ServiceObject] {
            assert_eq!(ctx.accepted(), AcceptedName::ServicePrincipalName);
            assert!(!ctx.accepted().takes_component_count(1));
            assert!(ctx.accepted().takes_component_count(2));
            assert!(ctx.accepted().takes_component_count(3));
            for class in [Computer, DomainController, ProvisionedService] {
                assert!(ctx.admits(class), "{ctx:?} {class:?}");
            }
            for class in [User, TicketGrantingService, Group] {
                assert!(!ctx.admits(class), "{ctx:?} {class:?}");
            }
        }
    }
}
