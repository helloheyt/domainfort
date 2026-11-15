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
//! The name rules are the online path's own functions (crate::names, A-79)
//! for the admin plane's value rules, and crate principal-names for the
//! namespace (below).
//!
//! # The one principal namespace (task PN5; docs/59 §4-§5, A-173)
//!
//! Every security principal (user, computer, group) holds the keys its
//! stored names produce in the one namespace — `principal_names::
//! keys_of_names` of its sAMAccountName, userPrincipalName,
//! servicePrincipalName and dNSHostName, with the class its provisioning
//! claim gives it ([`principal_class`]). **The checker computes them and the
//! checker writes them** (docs/59 N7): `known()` refuses the namespace
//! attribute (ad-schema `PRINCIPAL_NAME_KEY`) in every caller's input and
//! `modifiable()` never lets a change name it, so no write path can supply
//! or alter a key; crate::invariants appends exactly the derived keys to the
//! object it creates, and the store's unique index on that one attribute
//! then refuses a key another live object holds — uniqueness over the union
//! of every name (N1: `dc$` beside `dc`, a UPN beside another object's
//! sAMAccountName, one SPN in two spellings), in the same commit.
//!
//! No phase-1 change writes a name attribute (`modifiable()`; A-79, docs/51
//! §5.2), so the keys are derived at the create only; a name-changing write
//! of phase 2 (MachineSelfWrite, A-141) must derive them here from the
//! changed record in the same transaction (docs/59 §5.4) —
//! `no_change_names_a_principal_name` pins that none exists yet.
//!
//! The namespace's own syntax (printable, "/" and "@", the final-"$" rule,
//! the UPN suffix, two-part SPNs) is principal-names'; the admin plane's
//! rules stay in crate::names (docs/questions/Q-1018 item 2). A refusal in
//! the sAMAccountName is reported as a name rule (`Name`, or `ReservedName`
//! for a reserved one); in any other name as a value rule (`Value`) — the
//! codes `prepare` gives the same names.
//!
//! **Reserved names, judged on the folded key** (A-163; class C49,
//! docs/questions/Q-1009 items 1-2): a key that spells a reserved name in
//! any case (`principal_names::reserved_name_of`: the TGS's `krbtgt…`, the
//! admin service's `admind/<host>`, the change-password service's
//! `kadmin/changepw`) is carried only by the provisioning claim that owns it
//! ([`claim_of_reserved_name`], an exhaustive match) — `Value` otherwise —
//! and a claim that exists for a reserved name must carry it (`Exception`).
//! Before task PN5 this compared octets (`KeyPurpose::of_service_name` on
//! the stored spelling), so `ADMIND/<host>` and `KADMIN/changepw` were "not
//! reserved". The privileged name is a state rule of the directory, not only
//! a key that keyd refuses to make (docs/52 R2b follow-up;
//! docs/questions/Q-541; task K9, Q-972).
//!
//! A host record (task DN6) is a state rule too ([`check_host_record`]):
//! the internal host-address attribute (ad-schema `HOST_ADDRESS`) only on
//! an online computer or the DC account whose names give one LDH host label
//! `<computerName>.<zone>`, with at most eight registrable addresses — never
//! on a service object, krbtgt, a user, and never without a configured zone.
//! No generic change writes it (it is not [`modifiable`]): only the checked
//! host-record write of crate::invariants.
//!
//! Spec: [MS-SAMR] v20260427 (pinned, sha256 083fe00a…8a4e) 3.1.1.6 items
//! 8-14, 20-24, 3.1.1.8.4 item 2, 3.1.1.8.9; [MS-ADTS] v20261026 (pinned,
//! 55b59eb1…b2b1) 3.1.1.5.1.3, 3.1.1.5.3.1.1.2, 3.1.1.5.3.1.1.4; RFC 4120
//! (pinned, 368d3cd1…f75b) §6.2, §6.2.1, §7.3; docs/51 §4.3 step 5, §5.2
//! rows 1-8, §11 (decided A-79 / docs/questions/Q-298); docs/46 §4.4, §5.4,
//! §8.2; docs/47 §4.2 (R47-5b); docs/59 §4.1-§4.6, §5.1-§5.2 (A-173);
//! docs/questions/Q-355, Q-376 items 5-6, Q-1007, Q-1008 items 2, 6,
//! Q-1009 items 1-2, Q-1010 item 3, Q-1018 item 2, Q-1020 item 7.

use ad_schema::flags::group_type::ALLOWED_VALUES;
use ad_schema::flags::user_account_control::{
    ADS_UF_ACCOUNT_DISABLE, ADS_UF_NORMAL_ACCOUNT, ADS_UF_SERVER_TRUST_ACCOUNT,
    ADS_UF_WORKSTATION_TRUST_ACCOUNT,
};
use dirstore::{AttrId, ClassId, Object};
use principal_names::{
    keys_of_names, reserved_name_of, KeySet, NameContext, NameRefused, PrincipalClass,
    PrincipalNames, ReservedName,
};

use super::{InvariantViolation as V, ProvisioningRole};
use crate::ids::Ids;
use crate::names;
use crate::record;

/// `true` if `id` is an attribute the checker has a rule for. A new object
/// carries only these; anything else has no checked path to the store. The
/// namespace attribute (`ids.principal_name_key`) is not among them: only
/// the checker writes it, from the object's own names (docs/59 N7).
/// Spec: docs/46 §5.1, §5.4 (the phase-1 stored attributes); docs/51 §5.2
/// rows 1-4, §4.3 step 5 (what the two write paths write); docs/59 §4.4
/// N7, §5.1; docs/questions/Q-1008 item 6.
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
        ids.host_address,
    ]
    .contains(&id)
}

/// The attributes a change may name: exactly those an online operation
/// writes — `SetEnabled` (userAccountControl), `SetAccountExpires`
/// (accountExpires), `BeginPasswordSet` (pwdLastSet), `AddMember` /
/// `RemoveMember` (member) — and whenChanged, which every change sets. No
/// write path renames, re-types or re-identifies an object: no name
/// attribute of the namespace and never the namespace attribute itself
/// (docs/59 N7; a phase-2 name change must derive the keys — module
/// documentation).
/// Spec: docs/51 §5.2 rows 5-8; docs/46 §5.4 (whenChanged set by every
/// originating write); [MS-SAMR] 3.1.1.6 item 21; docs/59 §4.4 N7, §5.4.
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
/// claims (`None` on every path but the provisioning session's), in the
/// principal namespace of `names` (required for a security principal —
/// crate::invariants refuses the create before this without one). Returns
/// the keys the object holds in the namespace — `Some` for every security
/// principal, `None` for any other object — for the caller to write
/// (docs/59 N7) or to probe (`prepare`'s conflict check).
/// Spec: as the module; each branch cites its rule.
pub(crate) fn check_new(
    ids: &Ids,
    obj: &Object,
    class: ClassId,
    role: Option<ProvisioningRole>,
    hosts: Option<&HostZone>,
    names: Option<&NameContext>,
) -> Result<Option<KeySet>, V> {
    if obj.attributes.iter().any(|a| !known(ids, a.id)) {
        return Err(V::NotModifiable);
    }
    // A host record (task DN6): only the holder the rule admits (module
    // `host_record`, below), whatever else the class rules say.
    if let Some(values) = obj.attribute(ids.host_address) {
        let values: Vec<&[u8]> = values.values.iter().map(|v| v.value.as_slice()).collect();
        check_host_record(ids, obj, class, role, &values, hosts)?;
    }
    // The namespace (task PN5; module documentation): a security principal's
    // keys — derived now, their refusal (if any) reported after the class
    // rules below, so that a name those rules refuse keeps their code; any
    // other object holds no name of the namespace at all.
    let principal = is_principal_class(ids, class);
    let namespace = if principal {
        match (principal_class(ids, class, role), names) {
            (Some(of), Some(names)) => Some(namespace_keys(ids, obj, of, names)),
            // A claim that does not fit the class: the class rules refuse
            // it (`Exception`); no namespace context: crate::invariants
            // refused the create already. Refused below either way.
            _ => None,
        }
    } else {
        if name_attributes(ids)
            .iter()
            .any(|id| obj.attribute(*id).is_some())
        {
            return Err(V::NotModifiable);
        }
        None
    };
    // A reserved name, in any case, is the one object's alone whose claim
    // owns it (A-163 on the folded key; docs/52 R2b follow-up; Q-541 for the
    // admin service's `admind/<host>`; task K9, Q-972 for the
    // change-password service's `kadmin/changepw`; Q-1009 items 1-2):
    // carried by anything else ⇒ the value is refused (`Value` — the code
    // `prepare` gives the same name); a claim on an object that does not
    // carry its name ⇒ `Exception`.
    if let Some(Ok(keys)) = &namespace {
        check_reserved_names(keys, role)?;
    }
    check_class_rules(ids, obj, class, role)?;
    match namespace {
        Some(keys) => keys.map(Some),
        // A security principal never passes without its keys (fail closed:
        // unreachable — the class rules refuse a claim that does not fit).
        None if principal => Err(V::Exception),
        None => Ok(None),
    }
}

/// The class rules of a new object (the second half of [`check_new`]).
/// Spec: as the module; each branch cites its rule.
fn check_class_rules(
    ids: &Ids,
    obj: &Object,
    class: ClassId,
    role: Option<ProvisioningRole>,
) -> Result<(), V> {
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

/// `true` for the classes of a security principal — the objects of the
/// namespace (docs/59 §4.3: user, computer, group; domainDNS,
/// organizationalUnit and container hold no key).
/// Spec: docs/59 §4.3; [MS-SAMR] 3.1.1.8.4 item 2 (users, computers and
/// groups share one sAMAccountName space).
pub(crate) fn is_principal_class(ids: &Ids, class: ClassId) -> bool {
    class == ids.user.id || class == ids.computer.id || class == ids.group.id
}

/// The name attributes of the namespace: the stored names `keys_of_names`
/// derives keys from (docs/59 §4.1; dNSHostName per Q-1010).
/// Spec: docs/59 §4.1, §5.1; docs/questions/Q-1010 items 1-3.
pub(crate) fn name_attributes(ids: &Ids) -> [AttrId; 4] {
    [
        ids.sam_account_name,
        ids.user_principal_name,
        ids.service_principal_name,
        ids.dns_host_name,
    ]
}

/// The namespace class (crate principal-names) of a new object of most
/// specific class `class` under the claim `role`: a user is the krbtgt
/// account only under the `Krbtgt` claim; a computer is the DC under
/// `DcAccount` and a provisioned service object (the DC's dNSHostName
/// without its key — Q-1010 item 3) under the three service-object claims;
/// a group has no claim. `None` for a claim that does not fit the class
/// (the class rules refuse it: `Exception`) and for a class outside the
/// namespace. Exhaustive over the claims, so a claim added later takes a
/// position here. The claim is the authoritative fact the store keeps too —
/// RID 502, ST and the manifest's service objects (crates/directory-pip
/// `principal.rs` derives the same class from them when it re-derives the
/// keys on lookup — docs/59 §6.1 step 3; Q-1018 item 3).
/// Spec: docs/59 §4.3; docs/questions/Q-1010 item 3, Q-1018 item 3;
/// [MS-SAMR] 2.2.1.14, 3.1.1.6 items 14, 20, 23; docs/51 §4.3 step 5.
fn principal_class(
    ids: &Ids,
    class: ClassId,
    role: Option<ProvisioningRole>,
) -> Option<PrincipalClass> {
    if class == ids.user.id {
        match role {
            None => Some(PrincipalClass::User),
            Some(ProvisioningRole::Krbtgt) => Some(PrincipalClass::TicketGrantingService),
            Some(
                ProvisioningRole::NamingContextRoot
                | ProvisioningRole::DcAccount
                | ProvisioningRole::ServiceObject
                | ProvisioningRole::AdminServiceObject
                | ProvisioningRole::ChangePasswordServiceObject,
            ) => None,
        }
    } else if class == ids.computer.id {
        match role {
            None => Some(PrincipalClass::Computer),
            Some(ProvisioningRole::DcAccount) => Some(PrincipalClass::DomainController),
            Some(
                ProvisioningRole::ServiceObject
                | ProvisioningRole::AdminServiceObject
                | ProvisioningRole::ChangePasswordServiceObject,
            ) => Some(PrincipalClass::ProvisionedService),
            Some(ProvisioningRole::NamingContextRoot | ProvisioningRole::Krbtgt) => None,
        }
    } else if class == ids.group.id {
        role.is_none().then_some(PrincipalClass::Group)
    } else {
        None
    }
}

/// The values of `id` as text (every value; a value that is not UTF-8 ⇒
/// `Value`).
fn texts(obj: &Object, id: AttrId) -> Result<Vec<&str>, V> {
    obj.attribute(id)
        .map(|a| {
            a.values
                .iter()
                .map(|v| core::str::from_utf8(&v.value).map_err(|_| V::Value))
                .collect()
        })
        .unwrap_or_else(|| Ok(Vec::new()))
}

/// The most keys an object of namespace class `class` with `spns`
/// servicePrincipalName values holds, in a realm with `aliases` aliases:
/// user ≤ 2 (sAMAccountName, UPN local part); computer ≤ 3 + SPNs + 1
/// (sAMAccountName, base name, UPN local part; its SPNs; its host name);
/// the krbtgt account ≤ 1 + aliases; a group 1. Exhaustive over the classes.
/// Spec: docs/59 §4.3, §4.6; docs/questions/Q-1008 item 2 (decided A-173:
/// "user ≤ 2 values, computer ≤ 3 + SPNs + 1"), Q-1020 item 7 (the count
/// is the writer's to assert — the store has no per-class bound).
fn key_bound(class: PrincipalClass, spns: usize, aliases: usize) -> usize {
    match class {
        PrincipalClass::User => 2,
        PrincipalClass::Group => 1,
        PrincipalClass::TicketGrantingService => 1 + aliases,
        PrincipalClass::Computer
        | PrincipalClass::DomainController
        | PrincipalClass::ProvisionedService => 3 + spns + 1,
    }
}

/// The keys a security principal `obj` of namespace class `class` holds in
/// the namespace of `names` (module documentation): `keys_of_names` of its
/// stored names — refused, not corrected (docs/59 §4.4). The
/// sAMAccountName is judged alone first, so that its refusal is reported as
/// a name rule (`ReservedName` for a reserved name — the TGS's or a realm
/// alias, RFC 4120 §6.2, §7.3, [MS-SAMR] 3.1.1.6 item 14, docs/59 N5 —
/// otherwise `Name`), and a refusal in any other name as a value rule
/// (`Value`). Then the count of Q-1008 item 2 is asserted (fail closed: by
/// construction of `keys_of_names` it always holds).
/// Spec: docs/59 §4.2-§4.4 (N2-N5), §4.6, §5.1; docs/questions/Q-1008
/// item 2, Q-1018 item 2, Q-1020 item 7; [MS-SAMR] 3.1.1.6 items 10, 11, 14,
/// 3.1.1.8.4 item 2; [MS-ADTS] 2.2.21, 3.1.1.5.3.1.1.4; RFC 4120 §6.2.
pub(crate) fn namespace_keys(
    ids: &Ids,
    obj: &Object,
    class: PrincipalClass,
    names: &NameContext,
) -> Result<KeySet, V> {
    let sam = text(obj, ids.sam_account_name)?;
    let account_name = PrincipalNames {
        class,
        sam_account_name: sam,
        user_principal_name: None,
        service_principal_names: Vec::new(),
        dns_host_name: None,
    };
    keys_of_names(&account_name, names).map_err(|refused| match refused {
        NameRefused::Reserved => V::ReservedName,
        _ => V::Name,
    })?;
    let stored = PrincipalNames {
        class,
        sam_account_name: sam,
        user_principal_name: record::text(obj, ids.user_principal_name).map_err(|_| V::Value)?,
        service_principal_names: texts(obj, ids.service_principal_name)?,
        dns_host_name: record::text(obj, ids.dns_host_name).map_err(|_| V::Value)?,
    };
    let keys = keys_of_names(&stored, names).map_err(|_| V::Value)?;
    let bound = key_bound(
        class,
        stored.service_principal_names.len(),
        names.realm_aliases().count(),
    );
    if keys.is_empty() || keys.len() > bound {
        return Err(V::Value);
    }
    Ok(keys)
}

/// A-163 on the folded key (module documentation): every reserved name the
/// object's keys spell is carried by the claim that owns it (`Value`
/// otherwise), and a claim that exists for a reserved name carries one
/// (`Exception` otherwise).
/// Spec: A-163; docs/52 R2b; docs/59 §5.1; docs/questions/Q-541, Q-972,
/// Q-1009 items 1-2; RFC 4120 §6.2; RFC 3244 §2.
fn check_reserved_names(keys: &KeySet, role: Option<ProvisioningRole>) -> Result<(), V> {
    let formed: Vec<ReservedName> = keys.keys().filter_map(reserved_name_of).collect();
    let carried_by_its_claim = |name: &ReservedName| role == Some(claim_of_reserved_name(*name));
    if !formed.iter().all(carried_by_its_claim) {
        return Err(V::Value);
    }
    if claims_a_reserved_name(role) && !formed.iter().any(carried_by_its_claim) {
        return Err(V::Exception);
    }
    Ok(())
}

/// The provisioning claim that alone may carry a reserved name: the krbtgt
/// account for the TGS's name (RFC 4120 §6.2: "Names of any type with an
/// initial component of 'krbtgt' are reserved for the Kerberos
/// ticket-granting service"; `keys_of_names` already refuses it on any other
/// object), the admin service object for `admind/<host>` (A-73, Q-541), the
/// change-password service object for `kadmin/changepw` (RFC 3244 §2, task
/// K9). Exhaustive over the reserved names, so a reserved name added to
/// principal-names later has no owner until one is written here (it fails
/// to compile — never fails open).
/// Spec: A-163; RFC 4120 §6.2, §7.3; RFC 3244 §2; docs/52 R2b; docs/53
/// §5.2, §10 (K9); docs/questions/Q-541, Q-972, Q-1009 items 1-2, Q-1018
/// item 7.
fn claim_of_reserved_name(name: ReservedName) -> ProvisioningRole {
    match name {
        ReservedName::TicketGrantingService => ProvisioningRole::Krbtgt,
        ReservedName::AdminService => ProvisioningRole::AdminServiceObject,
        ReservedName::ChangePasswordService => ProvisioningRole::ChangePasswordServiceObject,
    }
}

/// `true` if the provisioning claim `role` exists to carry a reserved name
/// (so an object under it that carries none is an `Exception`). Exhaustive
/// over the claims, so a claim added later takes a position here; kept
/// consistent with [`claim_of_reserved_name`] by the unit test
/// `every_reserved_claim_owns_a_reserved_name`.
/// Spec: A-163; docs/52 R2b; docs/questions/Q-541, Q-972.
fn claims_a_reserved_name(role: Option<ProvisioningRole>) -> bool {
    match role {
        Some(
            ProvisioningRole::Krbtgt
            | ProvisioningRole::AdminServiceObject
            | ProvisioningRole::ChangePasswordServiceObject,
        ) => true,
        Some(
            ProvisioningRole::NamingContextRoot
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
/// rules (≤ 20 characters, A-79; no trailing "$", Q-355 item 2);
/// userAccountControl N or N|D — krbtgt N alone (item 22); never a DC or
/// service-object exception (items 23-24: ST and WT are computer bits). The
/// name "krbtgt" — in any case, only for the krbtgt exception, and the
/// exception only with exactly that name (item 14; RFC 4120 §6.2, §7.3) —
/// is the namespace's rule on the folded key (`namespace_keys`:
/// `ReservedName`), not a second comparison here (class C49).
/// Spec: [MS-SAMR] 3.1.1.6 items 8-12, 14, 20, 22-24; docs/51 §4.3 step 5,
/// §5.2 row 1, §11; A-79; docs/questions/Q-1009 item 1.
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
    if !uac_ok(uac_of(ids, obj)?, ADS_UF_NORMAL_ACCOUNT, !krbtgt) {
        return Err(V::AccountControl);
    }
    check_account_values(ids, obj, !krbtgt)
}

/// A computer: sAMAccountName = cn ‖ "$" with cn a valid computer name
/// (items 8-12, A-79); dNSHostName required (printable, lower case — Q-355
/// item 3); at most one servicePrincipalName, `service "/" dNSHostName`
/// (R47-1; a reserved name in any case — `krbtgt/…`, `admind/…`,
/// `kadmin/changepw` — is the namespace's refusal, `namespace_keys` and
/// `check_reserved_names`); userAccountControl WT or WT|D — the DC account ST
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
    // A computer whose base name is "krbtgt" (in any case) is refused by the
    // namespace (its `ComputerBase` key is the TGS's name — RFC 4120 §6.2).
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
/// (items 8-10, 13; ≤ 64 as the cn; no trailing "$"); groupType one of the
/// six phase-1 values (docs/46 §8.2; [MS-SAMR] 3.1.1.6 item 29 via
/// docs/46); never an exception. Never "krbtgt" in any case — the
/// namespace's rule on the folded key (`namespace_keys`: `ReservedName`).
/// Its `member` values are links, checked against the store (module
/// crate::invariants::graph).
/// Spec: [MS-SAMR] 3.1.1.6 items 8-10, 13, 29; docs/46 §8.2; docs/51 §5.2
/// row 3, §11; docs/questions/Q-355 items 1-2, Q-1009 item 1.
fn check_group(ids: &Ids, obj: &Object, role: Option<ProvisioningRole>) -> Result<(), V> {
    if role.is_some() {
        return Err(V::Exception);
    }
    let sam = text(obj, ids.sam_account_name)?;
    if text(obj, ids.cn)? != sam || !names::group_sam_ok(sam) {
        return Err(V::Name);
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

/// The zone a host record lives in and the networks its addresses must lie
/// in (task DN6): the naming context's DNS name (A-53) and the configured
/// registrable networks. The online PEP's checker has it when DNS
/// self-updates are enabled; the provisioning session when it is given one
/// (`Provisioning::with_dns_registration`, task DN10b — the DC's own record)
/// — without it no host address can be written (fail closed).
/// Spec: docs/54 §5.3, §5.5; docs/questions/Q-614 items 3, 8, Q-1003 item 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostZone {
    /// The zone (the NC's DNS name).
    pub(crate) zone: String,
    /// The registrable networks (IPv4, at least one).
    pub(crate) networks: Vec<config::Network>,
}

/// The rule of a host record (task DN6; docs/54 §5.2-§5.5; Q-614 items 2,
/// 3, 8) — the state rule every write that leaves host addresses on an
/// object keeps, whichever path writes it:
///
/// - the holder is a computer, either an online one (no claim) or the DC
///   account (its record comes from provisioning, docs/54 §3.1) — never a
///   service object, krbtgt or the NC root (`Exception`);
/// - the zone is known ([`HostZone`]) — otherwise nothing is written
///   (`Value`);
/// - its names pass the host-name rule: the computerName is one RFC 1035
///   §2.3.1 LDH label and dNSHostName is exactly `<computerName>.<zone>`
///   without case (directory-pip `host_label`; [MS-ADTS] 3.1.1.5.3.1.1.2) —
///   otherwise `Name`;
/// - at most `MAX_HOST_ADDRESSES` values (the image's bound), each four
///   octets (RFC 1035 §3.4.1) holding an address that is registrable:
///   never loopback, unspecified or multicast, inside a registrable network
///   (directory-pip `registrable`) — otherwise `Value`. Distinct by the
///   store's set semantics (one spelling per address).
///
/// An empty value set is no record: nothing to judge.
/// Spec: docs/54 §5.2, §5.3, §5.5; docs/questions/Q-614 items 2, 3, 8;
/// [MS-ADTS] v20261026 3.1.1.5.3.1.1.2; RFC 1035 §2.3.1, §3.4.1.
pub(crate) fn check_host_record(
    ids: &Ids,
    obj: &Object,
    class: ClassId,
    role: Option<ProvisioningRole>,
    values: &[&[u8]],
    hosts: Option<&HostZone>,
) -> Result<(), V> {
    if values.is_empty() {
        return Ok(());
    }
    let hosts = check_host_holder(ids, obj, class, role, hosts)?;
    check_host_values(values, hosts)
}

/// The holder part of [`check_host_record`]: a computer, online or the DC
/// account; the zone known; its names passing the host-name rule. Returns
/// the zone.
/// Spec: as [`check_host_record`].
pub(crate) fn check_host_holder<'h>(
    ids: &Ids,
    obj: &Object,
    class: ClassId,
    role: Option<ProvisioningRole>,
    hosts: Option<&'h HostZone>,
) -> Result<&'h HostZone, V> {
    if class != ids.computer.id {
        return Err(V::NotModifiable);
    }
    match role {
        None | Some(ProvisioningRole::DcAccount) => {}
        Some(_) => return Err(V::Exception),
    }
    let hosts = hosts.ok_or(V::Value)?;
    let sam = text(obj, ids.sam_account_name)?;
    let dns_host_name = text(obj, ids.dns_host_name)?;
    if directory_pip::host_label(sam, dns_host_name, &hosts.zone).is_none() {
        return Err(V::Name);
    }
    Ok(hosts)
}

/// The value part of [`check_host_record`]: at most `MAX_HOST_ADDRESSES`
/// values, each four octets holding a registrable address.
/// Spec: as [`check_host_record`].
pub(crate) fn check_host_values(values: &[&[u8]], hosts: &HostZone) -> Result<(), V> {
    if values.len() > directory_pip::MAX_HOST_ADDRESSES {
        return Err(V::Value);
    }
    let allowed = |value: &&[u8]| {
        directory_pip::host_address_of(value)
            .is_some_and(|address| directory_pip::registrable(address, &hosts.networks))
    };
    if !values.iter().all(allowed) {
        return Err(V::Value);
    }
    Ok(())
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
        claim_of_reserved_name, claims_a_reserved_name, known, modifiable, name_attributes,
        ProvisioningRole, ReservedName,
    };
    use crate::ids::Ids;

    /// The two exhaustive matches agree: a claim that exists to carry a
    /// reserved name is exactly a claim some reserved name maps to, and the
    /// online path (`None`) carries none. Source: A-163; docs/52 R2b;
    /// docs/questions/Q-541, Q-972, Q-1009 items 1-2.
    #[test]
    fn every_reserved_claim_owns_a_reserved_name() {
        let reserved = [
            ReservedName::TicketGrantingService,
            ReservedName::AdminService,
            ReservedName::ChangePasswordService,
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
            let owns = reserved
                .iter()
                .any(|name| Some(claim_of_reserved_name(*name)) == role);
            assert_eq!(owns, claims_a_reserved_name(role), "{role:?}");
        }
    }

    /// docs/59 §4.4 N7, §5.1, §5.4; Q-1008 item 6: the namespace attribute
    /// has no caller path — no new object may carry it (`known`) and no
    /// change may name it (`modifiable`) — and no phase-1 change names a
    /// principal name (A-79; docs/51 §5.2), so the keys the checker derives
    /// at the create stay the object's keys. A phase-2 name change must
    /// derive them in the checker (module documentation).
    #[test]
    fn no_change_names_a_principal_name() {
        let ids = Ids::resolve(&ad_schema::phase1().unwrap()).unwrap();
        assert!(!known(&ids, ids.principal_name_key));
        assert!(!modifiable(&ids, ids.principal_name_key));
        for id in name_attributes(&ids) {
            assert!(known(&ids, id), "{id:?}");
            assert!(!modifiable(&ids, id), "{id:?}");
        }
        assert!(!modifiable(&ids, ids.cn));
    }
}
