//! Typed values: each value is accepted in exactly one canonical spelling.
//!
//! Nothing is ever expanded (docs/50 §7.1: "no override from the
//! environment"): no value type admits a space inside a scalar, `{`, `}` or
//! `%`, and only a sAMAccountName may contain `$` ([MS-SAMR] 3.1.1.6 does
//! not forbid it), which is then a literal character of the name.

use crate::error::ErrorKind;
use crate::limits::{
    MAX_ACCOUNT_NAME_OCTETS, MAX_DNS_NAME_OCTETS, MAX_FIRST_ADMINS, MAX_NC_LABELS, MIN_FIRST_ADMINS,
};
use dtyp::{Guid, Sid, SECURITY_NT_AUTHORITY};
use keyd_types::PrincipalBinding;
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_HST, KRB_NT_SRV_INST};
use krb_proto::{KerberosString, PrincipalName, Realm};

/// The one manifest format version this crate reads and writes.
/// Project choice: an exact version, no negotiation (as the IPC envelope,
/// docs/50 §3.3, D57).
pub(crate) const MANIFEST_VERSION: &str = "1";

/// `manifest_version`: exactly [`MANIFEST_VERSION`].
/// Spec: docs/50 §3.3 (D57: exact version, no fallback) — applied here.
pub(crate) fn version(text: &str) -> Result<(), ErrorKind> {
    if text == MANIFEST_VERSION {
        Ok(())
    } else {
        Err(ErrorKind::UnsupportedVersion)
    }
}

// ---- realm, naming context, host name --------------------------------------

/// The realm: 1 ..= 255 octets of `A-Z 0-9 . -`, upper case only, and a
/// valid KerberosString.
///
/// The realm "MUST be the domain's DNS name in upper case" (docs/47 §3.3
/// item 3, citing RFC 4120 §6.1 "it is recommended by convention that the
/// characters be converted to uppercase"); docs/51 §4.3 step 1 checks it at
/// provisioning, and dird refuses a realm with a lower-case letter
/// (crates/directory-pip `DirectoryContext::new`). Its agreement with the
/// naming context is checked by the manifest.
/// Spec: RFC 4120 §5.2.1 (krb-proto's KerberosString rule), §6.1; docs/47
/// §3.3 item 3; docs/51 §4.3 step 1.
pub(crate) fn realm(text: &str) -> Result<Realm, ErrorKind> {
    let valid = !text.is_empty()
        && text.len() <= MAX_DNS_NAME_OCTETS
        && text
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'));
    if !valid {
        return Err(ErrorKind::InvalidRealm);
    }
    Realm::new(text).map_err(|_| ErrorKind::InvalidRealm)
}

/// The attribute of every naming-context component, lower case.
/// Spec: the naming-context form dird uses (crates/directory-pip
/// `NC_RDN_ATTRIBUTE`, naming.rs) and crates/config accepts; A-53.
const NC_COMPONENT_PREFIX: &str = "dc=";

/// The separator of naming-context components: a comma, no space (A-53).
const NC_COMPONENT_SEPARATOR: char = ',';

/// The naming context — the DN of the domain root — as its labels n1 … nk,
/// leaf first: `dc=<label>,…,dc=<label>`, 1 ..= [`MAX_NC_LABELS`]
/// components, each label one or more of `A-Z a-z 0-9 -`, and the DNS name
/// n1.….nk at most [`MAX_DNS_NAME_OCTETS`] octets.
///
/// The same spelling crates/config accepts for dird's `naming_context`, so
/// the value `provision domain` writes into both files is the same text.
/// Spec: docs/50 §7.1 ("naming context (A-53)"); PENDING-OWNER A-53, A-55;
/// docs/51 §4.3 steps 1, 8.
pub(crate) fn naming_context(text: &str) -> Result<Vec<String>, ErrorKind> {
    let mut labels: Vec<String> = Vec::new();
    for component in text.split(NC_COMPONENT_SEPARATOR) {
        if labels.len() == MAX_NC_LABELS {
            return Err(ErrorKind::InvalidNamingContext);
        }
        let label = component
            .strip_prefix(NC_COMPONENT_PREFIX)
            .ok_or(ErrorKind::InvalidNamingContext)?;
        let valid = !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !valid {
            return Err(ErrorKind::InvalidNamingContext);
        }
        labels.push(label.to_owned());
    }
    if dns_name(&labels).len() > MAX_DNS_NAME_OCTETS {
        return Err(ErrorKind::InvalidNamingContext);
    }
    Ok(labels)
}

/// The DNS name the naming context corresponds to, n1.n2.….nk.
/// Spec: crates/directory-pip `NamingContext::dns_name` (the DNS name dird
/// compares with the realm); A-53, A-55.
pub(crate) fn dns_name(labels: &[String]) -> String {
    labels.join(".")
}

/// The naming context as written: `dc=n1,…,dc=nk`. Spec: A-53.
pub(crate) fn naming_context_text(labels: &[String]) -> String {
    labels
        .iter()
        .map(|label| format!("{NC_COMPONENT_PREFIX}{label}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// `true` if `realm` is the naming context's DNS name in upper case, octet
/// for octet — the check dird makes at start.
/// Spec: docs/47 §3.3 item 3; crates/directory-pip `NamingContext::
/// names_realm` / `DirectoryContext::new`; A-55.
pub(crate) fn names_realm(labels: &[String], realm: &Realm) -> bool {
    dns_name(labels).to_ascii_uppercase().as_bytes() == realm.as_bytes()
}

/// The DC's host name: labels of one or more `a-z 0-9 -` separated by
/// single dots, at most [`MAX_DNS_NAME_OCTETS`] octets — lower case only,
/// because it is the host component of the service bindings.
/// Spec: RFC 4120 §6.2.1 ("Where the name of the host is not case sensitive
/// (for example, with Internet domain names) the name of the host MUST be
/// lowercase"); docs/47 §1.3 (the SPN host component is stored lower case);
/// docs/51 §4.3 step 5 (the service objects' SPNs).
pub(crate) fn host_name(text: &str) -> Result<KerberosString, ErrorKind> {
    let valid = !text.is_empty()
        && text.len() <= MAX_DNS_NAME_OCTETS
        && text.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    if !valid {
        return Err(ErrorKind::InvalidHostName);
    }
    KerberosString::new(text).map_err(|_| ErrorKind::InvalidHostName)
}

// ---- domain SID -------------------------------------------------------------

/// SECURITY_NT_NON_UNIQUE, the first SubAuthority of a domain SID.
/// Spec: [MS-DTYP] 2.4.2.4 ("21: SECURITY_NT_NON_UNIQUE, indicates a domain
/// id will follow").
const SECURITY_NT_NON_UNIQUE: u32 = 21;

/// SubAuthority values of a domain SID: 21 and three 32-bit numbers.
/// Spec: [MS-DTYP] 2.4.2.4 ("1-2-3: The next three SubAuthority arrays
/// contain 32-bit random numbers to uniquely identify the domain").
const DOMAIN_SID_SUB_AUTHORITIES: usize = 4;

/// The domain SID `S-1-5-21-<n>-<n>-<n>`: the string form of [MS-DTYP]
/// 2.4.2.1 (dtyp's parser), in its canonical spelling (dtyp's printer
/// reproduces it exactly), with identifier authority SECURITY_NT_AUTHORITY
/// (5), first SubAuthority SECURITY_NT_NON_UNIQUE (21) and exactly three
/// more SubAuthority values.
/// Spec: [MS-DTYP] 2.4.2.1, 2.4.2.4; docs/51 §4.1, §4.3 step 2 (R51-3).
pub(crate) fn domain_sid(text: &str) -> Result<Sid, ErrorKind> {
    let sid = Sid::parse_sid_string(text).map_err(|_| ErrorKind::InvalidDomainSid)?;
    let sub = sid.sub_authority();
    let shaped = sid.identifier_authority() == SECURITY_NT_AUTHORITY
        && sub.len() == DOMAIN_SID_SUB_AUTHORITIES
        && sub.first() == Some(&SECURITY_NT_NON_UNIQUE);
    if !shaped || sid.to_sid_string() != text {
        return Err(ErrorKind::InvalidDomainSid);
    }
    Ok(sid)
}

// ---- GUID -------------------------------------------------------------------
//
// The text form is dtyp's one mapping ([`Guid::parse_text`] /
// [`Guid::to_text`]): the lower-case `8-4-4-4-12` form of [MS-DTYP] 2.5.1.1,
// fields from 2.3.4.1 / 2.3.4.2, group order from the [MS-DRSR] 5.16.3.16
// example — the A-31 route this crate had re-derived (Q-345 item 5), moved
// to dtyp so the workspace has one copy (A-86 follow-up, task F7). The
// manifest adds only its own rule: the NULL GUID is no object's GUID.

/// Length of the GUID text. Spec: [MS-DTYP] 2.5.1.1 (dtyp `GUID_TEXT_LEN`).
const GUID_TEXT_LEN: usize = dtyp::GUID_TEXT_LEN;

/// A GUID in the lower-case `8-4-4-4-12` form (dtyp's mapping); the NULL
/// GUID is refused.
/// Spec: [MS-DTYP] 2.3.4.1, 2.3.4.2, 2.5.1.1; [MS-DRSR] 5.16.3.16; docs/51
/// §4.1 ([MS-ADTS] 3.1.1.5.2.4 as quoted there: an objectGUID "MUST NOT be
/// the NULL GUID"); PENDING-OWNER A-31.
pub(crate) fn guid(text: &str) -> Result<Guid, ErrorKind> {
    let guid = Guid::parse_text(text).map_err(|_| ErrorKind::InvalidGuid)?;
    if guid.to_packet() == [0u8; dtyp::GUID_PACKET_LEN] {
        return Err(ErrorKind::NullGuid);
    }
    Ok(guid)
}

/// The text of a GUID: the inverse of [`guid`] (dtyp's mapping).
/// Spec: [MS-DTYP] 2.5.1.1; [MS-DRSR] 5.16.3.16.
pub(crate) fn guid_text(guid: &Guid) -> String {
    guid.to_text()
}

// ---- sAMAccountName ---------------------------------------------------------

/// The characters a sAMAccountName must not contain besides 0x00-0x1F.
/// Spec: [MS-SAMR] 3.1.1.6 item 10 (the table: `" / \ [ ] : | < > + = ; ?
/// , *`).
const ACCOUNT_NAME_FORBIDDEN: &[u8] = b"\"/\\[]:|<>+=;?,*";

/// The sAMAccountName of the krbtgt account.
/// Spec: [MS-SAMR] 3.1.1.6 item 14; RFC 4120 §6.2 ("Names of any type with
/// an initial component of 'krbtgt' are reserved for the Kerberos
/// ticket-granting service").
pub(crate) const KRBTGT_ACCOUNT_NAME: &str = "krbtgt";

/// A first administrator's sAMAccountName:
///
/// * 1 ..= 20 octets ([MS-SAMR] 3.1.1.6 item 12, objectClass user);
/// * printable ASCII without the space (P-6 ASCII only; the space is also
///   refused because list items of the manifest never contain one — a
///   project restriction, docs/questions/Q-345 item 6), so it has at least
///   one non-blank character (item 8) and no 0x00-0x1F (item 10);
/// * none of the characters of item 10's table;
/// * not ending with "." (item 9);
/// * not `krbtgt` in any ASCII case (item 14; RFC 4120 §6.2; dird's
///   uniqueness index folds A-Z, docs/47 §1.1).
///
/// Spec: [MS-SAMR] 3.1.1.6 items 8, 9, 10, 12, 14; docs/51 §11; RFC 4120
/// §5.2.1, §6.2; PENDING-OWNER P-6.
pub(crate) fn account_name(text: &str) -> Result<KerberosString, ErrorKind> {
    let octets = text.as_bytes();
    let valid = !octets.is_empty()
        && octets.len() <= MAX_ACCOUNT_NAME_OCTETS
        && octets
            .iter()
            .all(|&c| (0x21..=0x7E).contains(&c) && !ACCOUNT_NAME_FORBIDDEN.contains(&c))
        && octets.last() != Some(&b'.');
    if !valid {
        return Err(ErrorKind::InvalidAccountName);
    }
    if text.eq_ignore_ascii_case(KRBTGT_ACCOUNT_NAME) {
        return Err(ErrorKind::ReservedAccountName);
    }
    KerberosString::new(text).map_err(|_| ErrorKind::InvalidAccountName)
}

// ---- lists and object entries -----------------------------------------------

/// The list separator: exactly a comma and one space (as crates/config).
/// Spec: docs/50 §7.1; docs/questions/Q-230 item 14.
pub(crate) const LIST_SEPARATOR: &str = ", ";

/// The items of `first_admins`: [`MIN_FIRST_ADMINS`] ..= [`MAX_FIRST_ADMINS`]
/// non-empty parts separated by exactly `", "`.
/// Spec: docs/50 §7.1; docs/questions/Q-295 (P-22: at least two).
pub(crate) fn first_admin_items(text: &str) -> Result<Vec<&str>, ErrorKind> {
    let mut items: Vec<&str> = Vec::new();
    for part in text.split(LIST_SEPARATOR) {
        if items.len() == MAX_FIRST_ADMINS {
            return Err(ErrorKind::TooManyFirstAdmins);
        }
        // No item contains a space or a comma, so an empty part or a part
        // holding either means the separator was not exactly ", ".
        if part.is_empty() || part.contains([' ', ',']) {
            return Err(ErrorKind::InvalidList);
        }
        items.push(part);
    }
    if items.len() < MIN_FIRST_ADMINS {
        return Err(ErrorKind::TooFewFirstAdmins);
    }
    Ok(items)
}

/// The separator between an object's GUID and its binding, and between a
/// binding's name type and its components.
pub(crate) const ENTRY_SEPARATOR: char = ':';

/// The separator between the components of a binding's name, as an SPN is
/// written ([MS-KILE] 3.1.5.11 as cited in docs/47 §1.1; docs/47 §9.1: "the
/// one SPN split on /").
pub(crate) const COMPONENT_SEPARATOR: &str = "/";

/// An object entry `<guid>:<rest>`: the GUID and the rest (the binding).
/// Spec: docs/51 §4.3 step 8 ("the GUIDs and the bindings").
pub(crate) fn object_entry(text: &str) -> Result<(Guid, &str), ErrorKind> {
    let (guid_part, rest) = text
        .split_at_checked(GUID_TEXT_LEN)
        .ok_or(ErrorKind::InvalidObjectEntry)?;
    let binding = rest
        .strip_prefix(ENTRY_SEPARATOR)
        .ok_or(ErrorKind::InvalidObjectEntry)?;
    Ok((guid(guid_part)?, binding))
}

// ---- bindings ---------------------------------------------------------------

/// The written names of the three name types a manifest binding uses.
/// Spec: RFC 4120 §6.2 (the name-type table: NT-PRINCIPAL 1, NT-SRV-INST 2,
/// NT-SRV-HST 3).
const NAME_TYPE_LABELS: [(i32, &str); 3] = [
    (KRB_NT_PRINCIPAL, "NT-PRINCIPAL"),
    (KRB_NT_SRV_INST, "NT-SRV-INST"),
    (KRB_NT_SRV_HST, "NT-SRV-HST"),
];

/// The written name of `name_type`, if it is one of the three a manifest
/// uses. Spec: RFC 4120 §6.2.
pub(crate) fn name_type_label(name_type: i32) -> Option<&'static str> {
    NAME_TYPE_LABELS
        .iter()
        .find(|(value, _)| *value == name_type)
        .map(|&(_, label)| label)
}

/// A binding as written in the manifest: `<NAME-TYPE>:<c1>[/<c2>…]`; the
/// realm is the manifest's realm and is not repeated. A name type outside
/// the three of [`NAME_TYPE_LABELS`] (never built by this crate) is written
/// as its decimal value.
/// Spec: RFC 4120 §6.2 (name types), §5.2.2 (PrincipalName); docs/47 §9.1.
pub fn binding_text(binding: &PrincipalBinding) -> String {
    let name_type = match name_type_label(binding.name.name_type) {
        Some(label) => label.to_owned(),
        None => binding.name.name_type.to_string(),
    };
    let components: Vec<&str> = binding
        .name
        .name_string
        .iter()
        .map(KerberosString::as_str)
        .collect();
    format!(
        "{name_type}{ENTRY_SEPARATOR}{}",
        components.join(COMPONENT_SEPARATOR)
    )
}

/// The binding (`realm`, `name_type`, `components`).
/// Spec: docs/10 §1 (`PrincipalBinding { realm, name }`); RFC 4120 §5.2.2.
pub(crate) fn binding(
    realm: &Realm,
    name_type: i32,
    components: &[&str],
) -> Result<PrincipalBinding, ErrorKind> {
    let name_string = components
        .iter()
        .map(|component| KerberosString::new(component))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ErrorKind::BindingMismatch)?;
    Ok(PrincipalBinding::new(
        realm.clone(),
        PrincipalName {
            name_type,
            name_string,
        },
    ))
}
