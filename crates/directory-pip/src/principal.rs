//! A stored object's principal names, read for the one namespace (task PN1;
//! docs/59 §4.3, §8).
//!
//! # What this module does
//!
//! [`DirectoryView::principal_names_of`] reads an object's names — its
//! sAMAccountName, userPrincipalName, servicePrincipalName and dNSHostName
//! — and decides its class for the derivation of crate `principal-names`
//! ([`principal_names::PrincipalClass`]); [`DirectoryView::principal_keys`]
//! returns the keys those names produce ([`principal_names::keys_of_names`]),
//! in the realm the view's naming context names ([`name_context_of`]).
//! The one lookup path (crate::resolve, task PN4) reads an object's names
//! and class here and re-derives its keys to check the key it probed
//! (docs/59 §6.1 step 3), with the provisioned service objects the
//! [`crate::DirectoryContext`] holds (Q-1019 option (a)).
//!
//! # The class, from authoritative data only
//!
//! | object | class |
//! |---|---|
//! | most specific class `group` | `Group` |
//! | `user` whose objectSid's RID is DOMAIN_USER_RID_KRBTGT (502) | `TicketGrantingService` |
//! | any other `user` | `User` |
//! | `computer` with ST in userAccountControl | `DomainController` |
//! | `computer` listed among the provisioned service objects | `ProvisionedService` |
//! | any other `computer` | `Computer` |
//! | anything else (domainDNS, organizationalUnit, container) | not a principal (`None`) |
//!
//! The RID and ST are the markers this crate already reads for the krbtgt
//! account ([MS-SAMR] 2.2.1.14; docs/47 §1.4, R47-2) and the DC's account
//! ([MS-ADTS] 2.2.16; docs/47 §6.3); the write checker sets them only under
//! the provisioning claims `Krbtgt` and `DcAccount` (docs/51 §4.3, §11).
//! The provisioned service objects carry no marker on the object: they are
//! WT computers that carry the DC's dNSHostName (crates/provision
//! `plan.rs` rows 6-8), told apart only by configuration — the manifest's
//! service objects, as crates/directory-admin's checker receives them
//! (`ProtectedObjects::service_objects`). So the caller passes that set
//! (docs/questions/Q-1019). An object listed there that is not a WT
//! computer is an inconsistency, refused (fail closed).
//!
//! # Fail closed
//!
//! An inconsistent record (a name that is not text, a single-valued name
//! with two values, a missing must, an inconsistent userAccountControl) is
//! [`PrincipalNamesError::Inconsistent`]; a stored name the namespace
//! refuses is [`PrincipalNamesError::Refused`]. Neither carries a name
//! (crate::error).
//!
//! Spec: docs/59 §4.2 (`NameContext`), §4.3, §6.1 step 3, §8 (the PN1
//! row); docs/questions/Q-1007, Q-1010 item 3, Q-1018, Q-1019; A-53;
//! [MS-SAMR] 2.2.1.14, 3.1.1.6 items 11, 14; [MS-ADTS] 2.2.16,
//! 3.1.1.1.5; docs/47 §1.4, §6.3.

use crate::error::{Fault, ViewError};
use crate::names::is_krbtgt_sid;
use crate::naming::NamingContext;
use crate::record;
use crate::salt::AccountKind;
use crate::state;
use crate::view::DirectoryView;
use dirstore::{Object, Store};
use dtyp::Guid;
use principal_names::{
    keys_of_names, KeySet, NameContext, NameRefused, PrincipalClass, PrincipalNames,
};
use std::collections::BTreeSet;

/// The marker of a store whose every principal got its namespace keys from
/// the one checker (task PN5): a named counter the provisioning session
/// creates with the other counters (A-83: counters only at provisioning) and
/// that nothing ever takes — its presence is the fact. dird refuses to open
/// a store without it (task PN10, [`principal_namespace_marked`]: fail
/// closed, re-provision; no migration tool, which would be a second writer
/// of the keys — docs/59 N7). Defined here, beside the namespace it marks,
/// so dird and every test fixture name the one definition; crates/
/// directory-admin's config re-exports it under the same name (as it does
/// the zone serial counter's — docs/questions/Q-1043 item 1, A-185).
/// Spec: docs/59 §5.2 (c), §5.5; docs/questions/Q-1008 item 5 (A-173),
/// Q-1043 item 1 (A-185); dirstore `MAX_COUNTER_NAME_LEN` (alphabet
/// `a-z 0-9 . - _`).
pub const PRINCIPAL_NAMESPACE_COUNTER: &str = "principal-namespace";

/// The first (and only) value of the marker counter's range: the counter is
/// a marker, never taken. Project choice (docs/questions/Q-1029 item 6).
/// Spec: docs/questions/Q-1008 item 5, Q-1043 item 1.
pub const PRINCIPAL_NAMESPACE_FIRST: u64 = 1;

/// One past the marker counter's only value. Spec: dirstore `CounterState`
/// (half-open range); docs/questions/Q-1029 item 6, Q-1043 item 1.
pub const PRINCIPAL_NAMESPACE_END_EXCLUSIVE: u64 = 2;

/// `true` if `store` carries the `principal-namespace` marker exactly as the
/// provisioning session creates it: the counter
/// [`PRINCIPAL_NAMESPACE_COUNTER`] with the range
/// `[PRINCIPAL_NAMESPACE_FIRST, PRINCIPAL_NAMESPACE_END_EXCLUSIVE)`, its one
/// value never taken. Any other shape — absent, another range, a value
/// taken — is `false`: a store dird must not open (docs/59 §5.5, fail
/// closed). Read from one snapshot.
///
/// # Errors
/// [`ViewError::Store`] if no snapshot could be taken or the counter could
/// not be read (dird then does not start either).
///
/// Spec: docs/59 §5.2 (c), §5.5; docs/questions/Q-1008 item 5 (A-173),
/// Q-1043 (A-185: "dird refuses a store without the marker"); docs/CLEAN-ROOM.md
/// (fail closed).
pub fn principal_namespace_marked(store: &Store) -> Result<bool, ViewError> {
    let snapshot = store.snapshot().map_err(|_| ViewError::Store)?;
    let marker = snapshot
        .counter(PRINCIPAL_NAMESPACE_COUNTER)
        .map_err(|_| ViewError::Store)?;
    Ok(marker.is_some_and(|state| {
        state.first_value == PRINCIPAL_NAMESPACE_FIRST
            && state.next_value == PRINCIPAL_NAMESPACE_FIRST
            && state.end_exclusive == PRINCIPAL_NAMESPACE_END_EXCLUSIVE
    }))
}

/// The lDAPDisplayName of userPrincipalName (not among the identifiers the
/// view resolves at construction, crate::record `Ids`; resolved here so
/// that this task changes no other module). Spec: docs/46 §5.4; [MS-ADA3]
/// 2.349 as cited there.
const USER_PRINCIPAL_NAME: &str = "userPrincipalName";

/// Why an object's principal names could not be read or have no keys.
/// Spec: docs/CLEAN-ROOM.md (fail closed; no value in an error).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PrincipalNamesError {
    /// The object's record is inconsistent (module documentation), or it is
    /// listed as a provisioned service object but is not a WT computer.
    Inconsistent,
    /// The schema lacks userPrincipalName.
    Schema,
    /// A stored name (or the naming context's DNS name) is refused by the
    /// namespace's rules (crate `principal-names`).
    Refused(NameRefused),
}

impl core::fmt::Display for PrincipalNamesError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PrincipalNamesError::Inconsistent => f.write_str("the object's record is inconsistent"),
            PrincipalNamesError::Schema => f.write_str("the schema lacks userPrincipalName"),
            PrincipalNamesError::Refused(refused) => {
                write!(f, "a stored name is refused: {refused}")
            }
        }
    }
}

impl std::error::Error for PrincipalNamesError {}

/// Every view fault is an inconsistency here (the object is in hand; no
/// lookup is made). Spec: docs/CLEAN-ROOM.md.
fn inconsistent(_: Fault) -> PrincipalNamesError {
    PrincipalNamesError::Inconsistent
}

/// The namespace's realm context of the naming context `naming_context`:
/// its one alias is the NC's DNS name (A-53: the realm is that name in upper
/// case; P-84 open — no flat-name alias, no further UPN suffix).
/// Spec: docs/59 §4.2 (`NameContext` from `NamingContext`, the PN1 row);
/// [MS-ADTS] 3.1.1.1.5 ("dc=n1,dc=n2, ... dc=nk" corresponds to the DNS
/// name n1.n2. ... .nk); A-53; Q-1012.
pub fn name_context_of(naming_context: &NamingContext) -> Result<NameContext, NameRefused> {
    NameContext::new(&naming_context.dns_name())
}

impl DirectoryView<'_> {
    /// The principal names of `obj` and its class (module documentation),
    /// or `None` if it is not a security principal. `service_objects` is
    /// the set of provisioned service objects (the manifest's — Q-1019).
    /// Spec: docs/59 §4.3; Q-1010 item 3; [MS-SAMR] 2.2.1.14; [MS-ADTS]
    /// 2.2.16; docs/47 §1.3 steps 5-7, §1.4, §6.3.
    pub fn principal_names_of<'o>(
        &self,
        obj: &'o Object,
        service_objects: &BTreeSet<Guid>,
    ) -> Result<Option<PrincipalNames<'o>>, PrincipalNamesError> {
        let ids = self.ctx.ids;
        let listed = service_objects.contains(&obj.guid);
        let (class, sam_account_name) =
            if self.most_specific_class(obj).map_err(inconsistent)? == ids.group {
                let sam = record::text(obj, ids.sam_account_name)
                    .map_err(inconsistent)?
                    .ok_or(PrincipalNamesError::Inconsistent)?;
                (PrincipalClass::Group, sam)
            } else {
                let Some(account) = self.account(obj).map_err(inconsistent)? else {
                    return if listed {
                        Err(PrincipalNamesError::Inconsistent)
                    } else {
                        Ok(None)
                    };
                };
                let class = match account.kind {
                    AccountKind::User if is_krbtgt_sid(&account.sid) => {
                        PrincipalClass::TicketGrantingService
                    }
                    AccountKind::User => PrincipalClass::User,
                    AccountKind::Computer if state::is_dc_account(account.uac) => {
                        PrincipalClass::DomainController
                    }
                    // A checked userAccountControl of a computer that is
                    // not ST is WT (crate::state `checked_uac`).
                    AccountKind::Computer if listed && account.uac.is_some() => {
                        PrincipalClass::ProvisionedService
                    }
                    AccountKind::Computer => PrincipalClass::Computer,
                };
                (class, account.sam_account_name)
            };
        if listed && class != PrincipalClass::ProvisionedService {
            return Err(PrincipalNamesError::Inconsistent);
        }
        let upn = self
            .ctx
            .schema
            .attribute_by_name(USER_PRINCIPAL_NAME)
            .ok_or(PrincipalNamesError::Schema)?;
        Ok(Some(PrincipalNames {
            class,
            sam_account_name,
            user_principal_name: record::text(obj, upn).map_err(inconsistent)?,
            // Single-valued in phase 1 (R47-13; crate::record `Ids::resolve`
            // checks it), so zero or one value.
            service_principal_names: record::text(obj, ids.service_principal_name)
                .map_err(inconsistent)?
                .into_iter()
                .collect(),
            dns_host_name: record::text(obj, ids.dns_host_name).map_err(inconsistent)?,
        }))
    }

    /// The keys of `obj` in the one namespace — `keys_of_names` of its
    /// principal names in the realm of this view's naming context (the
    /// context's one `NameContext`, built with it — task PN4) — or `None`
    /// if it is not a security principal.
    /// Spec: docs/59 §4.2, §4.3, §6.1 step 3; A-53.
    pub fn principal_keys(
        &self,
        obj: &Object,
        service_objects: &BTreeSet<Guid>,
    ) -> Result<Option<KeySet>, PrincipalNamesError> {
        let Some(names) = self.principal_names_of(obj, service_objects)? else {
            return Ok(None);
        };
        keys_of_names(&names, self.ctx.name_context())
            .map(Some)
            .map_err(PrincipalNamesError::Refused)
    }
}
