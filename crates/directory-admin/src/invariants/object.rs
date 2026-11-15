//! The per-object rules: what one record may hold, judged from the record
//! alone — its class, its names, its userAccountControl, its groupType and
//! its value forms — for a new object (every value) and for a change (the
//! values it changes).
//!
//! These are **state** rules — what may exist in the directory — not the
//! narrower shapes of the online PEP's operations: `CreateUser` always
//! writes `N | D` without pwdLastSet, but an enabled user with a pwdLastSet
//! is a state the online path reaches too (`BeginPasswordSet`, then
//! `SetEnabled`), so `provision domain`'s first administrators pass the
//! same rule without an exception. The states the online path can never
//! reach are the named provisioning exceptions ([`ProvisioningRole`]).
//!
//! The name rules are the online path's own functions (crate::names, A-79).
//! One of them is judged on every object whatever its class: no principal
//! name it forms may derive a reserved key-set purpose (by the one
//! derivation `KeyPurpose::of_service_name`: the admin service's
//! `admind/<host>`, the change-password service's `kadmin/changepw`),
//! except the claim of the one object that owns that name
//! (`ProvisioningRole::AdminServiceObject`,
//! `ProvisioningRole::ChangePasswordServiceObject`) — the privileged name is
//! a state rule of the directory, not only a key that keyd refuses to make
//! (docs/52 R2b follow-up; docs/questions/Q-541; task K9, Q-972).
//!
//! Spec: [MS-SAMR] v20260427 (pinned, sha256 083fe00a…8a4e) 3.1.1.6 items
//! 8-14, 20-24, 3.1.1.8.9; docs/51 §4.3 step 5, §5.2 rows 1-8, §11 (decided
//! A-79 / docs/questions/Q-298); docs/46 §4.4, §5.4, §8.2; docs/47 §4.2
//! (R47-5b); docs/questions/Q-355, Q-376 items 5-6.

use ad_schema::flags::group_type::ALLOWED_VALUES;
use ad_schema::flags::user_account_control::{
    ADS_UF_ACCOUNT_DISABLE, ADS_UF_NORMAL_ACCOUNT, ADS_UF_SERVER_TRUST_ACCOUNT,
    ADS_UF_WORKSTATION_TRUST_ACCOUNT,
};
use dirstore::{AttrId, ClassId, Object};
use keyd_types::KeyPurpose;

use super::{InvariantViolation as V, ProvisioningRole};
use crate::ids::Ids;
use crate::names;
use crate::record;

/// The reserved sAMAccountName of the krbtgt account (RID 502).
/// Spec: [MS-SAMR] 3.1.1.6 item 14 ("sAMAccountName MUST be the value
/// "krbtgt" … if the RID of the objectSid attribute is
/// DOMAIN_USER_RID_KRBTGT"); RFC 4120 §7.3 (as cited in docs/47 §1.4).
pub(crate) const KRBTGT_NAME: &str = "krbtgt";

/// `true` if `id` is an attribute the checker has a rule for. A new object
/// carries only these; anything else has no checked path to the store.
/// Spec: docs/46 §5.1, §5.4 (the phase-1 stored attributes); docs/51 §5.2
/// rows 1-4, §4.3 step 5 (what the two write paths write).
fn known(ids: &Ids, id: AttrId) -> bool {
    [
        ids.cn,
        ids.ou,
        ids.dc,
        ids.sam_account_name,
        ids.object_sid,
        ids.user_account_control,
        ids.account_expires,
        ids.pwd_last_set,
        ids.when_created,
        ids.when_changed,
        ids.nt_security_descriptor,
        ids.member,
        ids.group_type,
        ids.user_principal_name,
        ids.service_principal_name,
        ids.dns_host_name,
        ids.description,
    ]
    .contains(&id)
}

/// The attributes a change may name: exactly those an online operation
/// writes — `SetEnabled` (userAccountControl), `SetAccountExpires`
/// (accountExpires), `BeginPasswordSet` (pwdLastSet), `AddMember` /
/// `RemoveMember` (member) — and whenChanged, which every change sets. No
/// write path renames, re-types or re-identifies an object.
/// Spec: docs/51 §5.2 rows 5-8; docs/46 §5.4 (whenChanged set by every
/// originating write); [MS-SAMR] 3.1.1.6 item 21.
pub(crate) fn modifiable(ids: &Ids, id: AttrId) -> bool {
    [
        ids.user_account_control,
        ids.account_expires,
        ids.pwd_last_set,
        ids.member,
        ids.when_changed,
    ]
    .contains(&id)
}

/// A single text value of `id`, required.
fn text(obj: &Object, id: AttrId) -> Result<&str, V> {
    record::text(obj, id).map_err(|_| V::Value)?.ok_or(V::Value)
}

/// accountExpires: "never" is `0x7FFFFFFFFFFFFFFF`, any other value is a
/// FILETIME after 1601; `0` is refused (R47-5b), and so is a negative
/// value. Spec: [MS-SAMR] 3.1.1.8.1 item 1.2 (as cited in crate::admin);
/// docs/47 §4.2 (R47-5b).
fn account_expires_ok(value: i64) -> bool {
    value >= 1
}

/// pwdLastSet: a FILETIME after 1601 — the online path writes "now"
/// (A-79: always "now", never 0). Spec: docs/51 §11 (A-79 / Q-298 item 4);
/// docs/47 §4.3 (R47-5c: 0 makes the account unusable).
fn pwd_last_set_ok(value: i64) -> bool {
    value >= 1
}

/// A new account's userAccountControl: exactly `account_type` (one of the
/// item-20 bits), optionally with ACCOUNTDISABLE — the only bit any write
/// path sets beside the type (`CreateUser` N|D, `CreateComputer` WT|D,
/// `SetEnabled` toggles D). With `may_disable` false (krbtgt — item 22; the
/// DC account — docs/51 §4.3 step 5) the type bit alone.
/// Spec: [MS-SAMR] 3.1.1.6 items 19, 20, 22; docs/51 §5.2 rows 1, 2, 6,
/// §11 (A-79); docs/46 §8.2.
fn uac_ok(uac: u32, account_type: u32, may_disable: bool) -> bool {
    uac == account_type || (may_disable && uac == account_type | ADS_UF_ACCOUNT_DISABLE)
}

/// The rules of a new object (module documentation), on the record it will
/// have (`obj`, most specific class `class`), for the exception `role` it
/// claims (`None` on every path but the provisioning session's).
/// Spec: as the module; each branch cites its rule.
pub(crate) fn check_new(
    ids: &Ids,
    obj: &Object,
    class: ClassId,
    role: Option<ProvisioningRole>,
) -> Result<(), V> {
    if obj.attributes.iter().any(|a| !known(ids, a.id)) {
        return Err(V::NotModifiable);
    }
    // A name from which a reserved key-set purpose derives is the one
    // object's alone that claims it (docs/52 R2b follow-up; Q-541 for the
    // admin service's `admind/<host>`; task K9, Q-972 for the
    // change-password service's `kadmin/changepw`): carried by anything else
    // ⇒ the value is refused (`Value` — the code `prepare` gives for the same
    // SPN rule, `names::spn_ok`); a claim on an object that does not carry
    // its name ⇒ `Exception`.
    let formed = reserved_purposes_formed(ids, obj)?;
    let carried_by_its_claim = |purpose: &KeyPurpose| match claim_of_reserved_purpose(*purpose) {
        Some(claim) => Some(claim) == role,
        None => false,
    };
    if !formed.iter().all(carried_by_its_claim) {
        return Err(V::Value);
    }
    if claims_a_reserved_purpose(role) && !formed.iter().any(carried_by_its_claim) {
        return Err(V::Exception);
    }
    // The NC root: a domainDNS without parent, only as the provisioning
    // exception (docs/51 §4.3 step 5; docs/46 §4.4: "NC root only" — the
    // admin plane never creates a domainDNS).
    if class == ids.domain_dns.id {
        if role != Some(ProvisioningRole::NamingContextRoot) {
            return Err(V::Class);
        }
        if obj.parent.is_some() {
            return Err(V::Class);
        }
        return match record::sid(obj, ids.object_sid) {
            Ok(Some(_)) => Ok(()),
            _ => Err(V::Sid),
        };
    }
    if role == Some(ProvisioningRole::NamingContextRoot) {
        return Err(V::Exception);
    }
    // Every other object has a parent (docs/46 §8.3 item 2).
    if obj.parent.is_none() {
        return Err(V::Class);
    }
    if class == ids.user.id {
        check_user(ids, obj, role)
    } else if class == ids.computer.id {
        check_computer(ids, obj, role)
    } else if class == ids.group.id {
        check_group(ids, obj, role)
    } else if class == ids.organizational_unit.id || class == ids.container.id {
        // OU / container: the RDN value (ou / cn), 1..64 printable ASCII
        // (docs/46 §5.4; P-6); never an exception.
        if role.is_some() {
            return Err(V::Exception);
        }
        let rdn = if class == ids.organizational_unit.id {
            ids.ou
        } else {
            ids.cn
        };
        if !names::rdn_value_ok(text(obj, rdn)?) {
            return Err(V::Name);
        }
        check_description(ids, obj)
    } else {
        // Not a class any write path creates (docs/46 §4.1, §4.4).
        Err(V::Class)
    }
}

/// The reserved key-set purposes the principal names the object forms
/// derive by the one derivation (`keyd_types::KeyPurpose::of_service_name`,
/// through crate::names — every purpose but `Service`): from any of its
/// servicePrincipalName values (a service name — docs/47 §1.3 TGS), or from
/// its sAMAccountName as a one-component client name (docs/47 §1.3 AS).
/// Judged on every object of every class, whatever the class rules below
/// would say of the value. A value that is not UTF-8 ⇒ `Value`.
/// Spec: docs/52 R2b; docs/questions/Q-491 item 1, Q-541, Q-972; docs/47
/// §1.3.
fn reserved_purposes_formed(ids: &Ids, obj: &Object) -> Result<Vec<KeyPurpose>, V> {
    let values = |id: AttrId| {
        obj.attribute(id)
            .map(|a| {
                a.values
                    .iter()
                    .map(|v| v.value.as_slice())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let mut formed = Vec::new();
    for value in values(ids.service_principal_name) {
        let spn = core::str::from_utf8(value).map_err(|_| V::Value)?;
        formed.extend(names::reserved_purpose_of_spn(spn));
    }
    for value in values(ids.sam_account_name) {
        let sam = core::str::from_utf8(value).map_err(|_| V::Value)?;
        formed.extend(names::reserved_purpose_of_client_name(sam));
    }
    Ok(formed)
}

/// The provisioning claim that alone may carry a name from which the
/// reserved key-set purpose `purpose` derives: the admin service object for
/// `AdminService` (`admind/<fqdn>`, A-73, Q-541) and the change-password
/// service object for `ChangePasswordService` (`kadmin/changepw`, RFC 3244
/// §2, task K9). Every other purpose has no claim, so a name deriving it is
/// carried by nothing. Written as a match over the purposes (patterns, not a
/// purpose chosen by a literal — docs/52 R2b) and exhaustive over them, so a
/// purpose added to keyd-types later has no claim until one is written here
/// (fail closed).
/// Spec: docs/52 R2b; docs/53 §5.2, §10 (K9); docs/questions/Q-541, Q-972.
fn claim_of_reserved_purpose(purpose: KeyPurpose) -> Option<ProvisioningRole> {
    match purpose {
        KeyPurpose::AdminService => Some(ProvisioningRole::AdminServiceObject),
        KeyPurpose::ChangePasswordService => Some(ProvisioningRole::ChangePasswordServiceObject),
        KeyPurpose::PrincipalLongterm | KeyPurpose::Krbtgt | KeyPurpose::Service => None,
    }
}

/// `true` if the provisioning claim `role` exists to carry the name of a
/// reserved key-set purpose (so an object under it that carries none is an
/// `Exception`). Exhaustive over the claims, so a claim added later takes a
/// position here; kept consistent with [`claim_of_reserved_purpose`] by the
/// unit test `every_reserved_claim_has_its_purpose`.
/// Spec: docs/52 R2b; docs/questions/Q-541, Q-972.
fn claims_a_reserved_purpose(role: Option<ProvisioningRole>) -> bool {
    match role {
        Some(
            ProvisioningRole::AdminServiceObject | ProvisioningRole::ChangePasswordServiceObject,
        ) => true,
        Some(
            ProvisioningRole::NamingContextRoot
            | ProvisioningRole::Krbtgt
            | ProvisioningRole::DcAccount
            | ProvisioningRole::ServiceObject,
        )
        | None => false,
    }
}

/// description, when present: 1..1024 UTF-16 units, no control character.
/// Spec: docs/46 §5.4; docs/questions/Q-355 item 5.
fn check_description(ids: &Ids, obj: &Object) -> Result<(), V> {
    match record::text(obj, ids.description) {
        Ok(None) => Ok(()),
        Ok(Some(d)) if names::description_ok(d) => Ok(()),
        _ => Err(V::Value),
    }
}

/// The values every account (user, computer) holds: accountExpires
/// (required, R47-5b), pwdLastSet (optional — absent on the objects whose
/// keys never come from a password: krbtgt, the DC account, the service
/// objects), userPrincipalName (optional, 1..1024 printable ASCII),
/// description.
/// Spec: docs/47 §4.2, §4.3, §1.4; docs/51 §4.3 step 5, §5.2 rows 1-2;
/// docs/46 §5.4; docs/questions/Q-355 item 4, Q-376 items 5-6.
fn check_account_values(ids: &Ids, obj: &Object, password: bool) -> Result<(), V> {
    let expires = record::int64(obj, ids.account_expires)
        .map_err(|_| V::Value)?
        .ok_or(V::Value)?;
    if !account_expires_ok(expires) {
        return Err(V::Value);
    }
    match record::int64(obj, ids.pwd_last_set).map_err(|_| V::Value)? {
        None => {}
        Some(value) if password && pwd_last_set_ok(value) => {}
        Some(_) => return Err(V::Value),
    }
    match record::text(obj, ids.user_principal_name) {
        Ok(None) => {}
        Ok(Some(upn)) if names::upn_ok(upn) => {}
        _ => return Err(V::Value),
    }
    check_description(ids, obj)
}

/// The account-type bit and ACCOUNTDISABLE, read as one flag word.
fn uac_of(ids: &Ids, obj: &Object) -> Result<u32, V> {
    record::flags(obj, ids.user_account_control)
        .map_err(|_| V::AccountControl)?
        .ok_or(V::AccountControl)
}

/// A user: cn = sAMAccountName (docs/51 §5.2 row 1), the [MS-SAMR] name
/// rules (≤ 20 characters, A-79; no trailing "$", Q-355 item 2); the name
/// "krbtgt" only for the krbtgt exception and the exception only with that
/// name (item 14; RFC 4120 §7.3); userAccountControl N or N|D — krbtgt N
/// alone (item 22); never a DC or service-object exception (items 23-24:
/// ST and WT are computer bits).
/// Spec: [MS-SAMR] 3.1.1.6 items 8-12, 14, 20, 22-24; docs/51 §4.3 step 5,
/// §5.2 row 1, §11; A-79.
fn check_user(ids: &Ids, obj: &Object, role: Option<ProvisioningRole>) -> Result<(), V> {
    let krbtgt = match role {
        None => false,
        Some(ProvisioningRole::Krbtgt) => true,
        Some(_) => return Err(V::Exception),
    };
    let sam = text(obj, ids.sam_account_name)?;
    if text(obj, ids.cn)? != sam || !names::user_sam_ok(sam) {
        return Err(V::Name);
    }
    if krbtgt != sam.eq_ignore_ascii_case(KRBTGT_NAME) || (krbtgt && sam != KRBTGT_NAME) {
        return Err(V::ReservedName);
    }
    if !uac_ok(uac_of(ids, obj)?, ADS_UF_NORMAL_ACCOUNT, !krbtgt) {
        return Err(V::AccountControl);
    }
    check_account_values(ids, obj, !krbtgt)
}

/// A computer: sAMAccountName = cn ‖ "$" with cn a valid computer name
/// (items 8-12, A-79); dNSHostName required (printable, lower case — Q-355
/// item 3); at most one servicePrincipalName, `service "/" dNSHostName`,
/// never krbtgt (R47-1); userAccountControl WT or WT|D — the DC account ST
/// alone, without SPN or pwdLastSet (the provisioning exception: ST is
/// never set by the admin plane, A-79 / Q-298 item 2; docs/51 §4.3 step 5);
/// a service object WT without pwdLastSet (its keys come from
/// `create_key`, Q-376 item 6); the admin service object likewise, its one
/// SPN the admin service's name (`names::admin_service_spn_ok` — the only
/// object that may carry it, docs/questions/Q-541); the change-password
/// service object likewise, its one SPN `kadmin/changepw`
/// (`names::change_password_service_spn_ok` — task K9, Q-972).
/// Spec: [MS-SAMR] 3.1.1.6 items 8-12, 20, 23, 24; docs/51 §4.3 step 5,
/// §5.2 row 2, §11; docs/47 §1.3; RFC 4120 §6.2.1; A-79.
fn check_computer(ids: &Ids, obj: &Object, role: Option<ProvisioningRole>) -> Result<(), V> {
    let (account_type, dc, service, spn_rule) = match role {
        None => (
            ADS_UF_WORKSTATION_TRUST_ACCOUNT,
            false,
            false,
            SpnRule::Host,
        ),
        Some(ProvisioningRole::ServiceObject) => {
            (ADS_UF_WORKSTATION_TRUST_ACCOUNT, false, true, SpnRule::Host)
        }
        // The admin service object (docs/52 R2b follow-up; Q-541): a service
        // object whose one SPN is the admin service's name.
        Some(ProvisioningRole::AdminServiceObject) => (
            ADS_UF_WORKSTATION_TRUST_ACCOUNT,
            false,
            true,
            SpnRule::AdminService,
        ),
        // The change-password service object (task K9; docs/53 §5.2): a
        // service object whose one SPN is `kadmin/changepw` (RFC 3244 §2).
        Some(ProvisioningRole::ChangePasswordServiceObject) => (
            ADS_UF_WORKSTATION_TRUST_ACCOUNT,
            false,
            true,
            SpnRule::ChangePasswordService,
        ),
        Some(ProvisioningRole::DcAccount) => {
            (ADS_UF_SERVER_TRUST_ACCOUNT, true, false, SpnRule::None)
        }
        Some(_) => return Err(V::Exception),
    };
    let name = text(obj, ids.cn)?;
    let sam = text(obj, ids.sam_account_name)?;
    // A computer's name ends with "$", so it can never be "krbtgt".
    if !names::computer_name_ok(name) || names::computer_sam(name) != sam {
        return Err(V::Name);
    }
    if !uac_ok(uac_of(ids, obj)?, account_type, !dc) {
        return Err(V::AccountControl);
    }
    let host = text(obj, ids.dns_host_name)?;
    if !names::dns_host_name_ok(host) {
        return Err(V::Value);
    }
    match (spn_rule, record::text(obj, ids.service_principal_name)) {
        (SpnRule::Host | SpnRule::None, Ok(None)) => {}
        (SpnRule::Host, Ok(Some(spn))) if names::spn_ok(spn, host) => {}
        (SpnRule::AdminService, Ok(Some(spn))) if names::admin_service_spn_ok(spn, host) => {}
        (SpnRule::ChangePasswordService, Ok(Some(spn)))
            if names::change_password_service_spn_ok(spn) => {}
        _ => return Err(V::Value),
    }
    check_account_values(ids, obj, !dc && !service)
}

/// The servicePrincipalName rule of a computer, by the claim it makes.
/// Spec: docs/51 §4.3 step 5, §5.2 row 2; docs/47 §1.3; A-73; docs/53 §5.2;
/// docs/questions/Q-541, Q-972.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpnRule {
    /// No SPN (the DC account, docs/51 §4.3 step 5).
    None,
    /// At most one SPN, `service "/" dNSHostName`, not reserved
    /// (`names::spn_ok`).
    Host,
    /// Exactly the admin service's name on the object's host
    /// (`names::admin_service_spn_ok`).
    AdminService,
    /// Exactly `kadmin/changepw` (`names::change_password_service_spn_ok`).
    ChangePasswordService,
}

/// A group: cn = sAMAccountName (Q-355 item 1), the group name rules
/// (items 8-10, 13; ≤ 64 as the cn; no trailing "$"), never "krbtgt";
/// groupType one of the six phase-1 values (docs/46 §8.2; [MS-SAMR] 3.1.1.6
/// item 29 via docs/46); never an exception. Its `member` values are links,
/// checked against the store (module crate::invariants::graph).
/// Spec: [MS-SAMR] 3.1.1.6 items 8-10, 13, 29; docs/46 §8.2; docs/51 §5.2
/// row 3, §11; docs/questions/Q-355 items 1-2.
fn check_group(ids: &Ids, obj: &Object, role: Option<ProvisioningRole>) -> Result<(), V> {
    if role.is_some() {
        return Err(V::Exception);
    }
    let sam = text(obj, ids.sam_account_name)?;
    if text(obj, ids.cn)? != sam || !names::group_sam_ok(sam) {
        return Err(V::Name);
    }
    if sam.eq_ignore_ascii_case(KRBTGT_NAME) {
        return Err(V::ReservedName);
    }
    let group_type = record::flags(obj, ids.group_type)
        .map_err(|_| V::Value)?
        .ok_or(V::Value)?;
    if !ALLOWED_VALUES
        .iter()
        .any(|v| u32::from_be_bytes(v.to_be_bytes()) == group_type)
    {
        return Err(V::Value);
    }
    check_description(ids, obj)
}

/// The rule of one change (attribute `id` replaced by `values`) of the
/// object `current` (most specific class `class`), beside the store-wide
/// rules of a `member` change:
///
/// - userAccountControl (accounts only, one value): only ACCOUNTDISABLE may
///   differ from the current value — the account type never changes (item
///   21 read strictly; ST never set, A-79) and no other bit appears; the
///   bits already stored are not judged again (a change is checked on what
///   it changes, as A-95 leaves a store already over a bound unrepaired);
/// - accountExpires (accounts only, one value): ≥ 1 (R47-5b);
/// - pwdLastSet (accounts only, one value): ≥ 1 (A-79);
/// - member (groups only): any value set — its new links are checked
///   against the store;
/// - whenChanged: one value;
/// - anything else: no write path changes it.
///
/// Spec: [MS-SAMR] 3.1.1.6 items 20-22; docs/51 §5.2 rows 5-8, §11; docs/47
/// §4.2; docs/46 §5.4; A-79.
pub(crate) fn check_change(
    ids: &Ids,
    current: &Object,
    class: ClassId,
    id: AttrId,
    values: &[Vec<u8>],
) -> Result<(), V> {
    if !modifiable(ids, id) {
        return Err(V::NotModifiable);
    }
    let account = class == ids.user.id || class == ids.computer.id;
    let one = || match values {
        [only] => Ok(only.as_slice()),
        _ => Err(V::Value),
    };
    let int64 = |bytes: &[u8]| {
        <[u8; 8]>::try_from(bytes)
            .map(i64::from_be_bytes)
            .map_err(|_| V::Value)
    };
    if id == ids.user_account_control {
        if !account {
            return Err(V::NotModifiable);
        }
        let new = <[u8; 4]>::try_from(one()?)
            .map(u32::from_be_bytes)
            .map_err(|_| V::AccountControl)?;
        let old = uac_of(ids, current)?;
        if (new ^ old) & !ADS_UF_ACCOUNT_DISABLE != 0 {
            return Err(V::AccountControl);
        }
        Ok(())
    } else if id == ids.account_expires || id == ids.pwd_last_set {
        if !account {
            return Err(V::NotModifiable);
        }
        let value = int64(one()?)?;
        let ok = if id == ids.account_expires {
            account_expires_ok(value)
        } else {
            pwd_last_set_ok(value)
        };
        if ok {
            Ok(())
        } else {
            Err(V::Value)
        }
    } else if id == ids.member {
        if class == ids.group.id {
            Ok(())
        } else {
            Err(V::NotModifiable)
        }
    } else {
        // whenChanged.
        one().map(|_| ())
    }
}

#[cfg(test)]
mod reserved_claim_tests {
    use super::{
        claim_of_reserved_purpose, claims_a_reserved_purpose, KeyPurpose, ProvisioningRole,
    };

    /// The two exhaustive matches agree: a claim that exists to carry a
    /// reserved name is exactly a claim some reserved purpose maps to, and
    /// the online path (`None`) carries none. Source: docs/52 R2b;
    /// docs/questions/Q-541, Q-972.
    #[test]
    fn every_reserved_claim_has_its_purpose() {
        let purposes = [
            KeyPurpose::PrincipalLongterm,
            KeyPurpose::Krbtgt,
            KeyPurpose::Service,
            KeyPurpose::AdminService,
            KeyPurpose::ChangePasswordService,
        ];
        let roles = [
            None,
            Some(ProvisioningRole::NamingContextRoot),
            Some(ProvisioningRole::Krbtgt),
            Some(ProvisioningRole::DcAccount),
            Some(ProvisioningRole::ServiceObject),
            Some(ProvisioningRole::AdminServiceObject),
            Some(ProvisioningRole::ChangePasswordServiceObject),
        ];
        for role in roles {
            let mapped = role.is_some()
                && purposes
                    .iter()
                    .any(|purpose| claim_of_reserved_purpose(*purpose) == role);
            assert_eq!(mapped, claims_a_reserved_purpose(role), "{role:?}");
        }
    }
}
