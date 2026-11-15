//! The write side: the keys an object's stored names produce.
//!
//! `keys_of_names` maps an object's stored names — its sAMAccountName,
//! userPrincipalName, servicePrincipalName values and dNSHostName, with its
//! class and provisioning claim — to the set of keys it holds in the one
//! namespace, each with the kinds it carries (docs/59 §4.1, §4.3). The
//! write checker stores exactly these keys (docs/59 §4.4 N7, task PN5), and
//! the lookup re-derives them from the stored names to check the key it
//! probed (docs/59 §6.1 step 3, task PN4) — one derivation for both.
//!
//! # The derivation (docs/59 §4.3)
//!
//! | class | keys |
//! |---|---|
//! | [`PrincipalClass::User`] | `SamAccountName`; `UpnLocal` if it has a UPN |
//! | [`PrincipalClass::Computer`] | `SamAccountName` (`x$`), `ComputerBase` (`x`), `UpnLocal`?, every `ServicePrincipalName`, `HostName`? |
//! | [`PrincipalClass::DomainController`] | as a computer |
//! | [`PrincipalClass::ProvisionedService`] | as a computer **without** `HostName` (Q-1010 item 3) |
//! | [`PrincipalClass::TicketGrantingService`] | `SamAccountName` (`krbtgt`) and every `RealmAlias` |
//! | [`PrincipalClass::Group`] | `SamAccountName` |
//!
//! # The namespace's rules (refusal, not correction)
//!
//! `keys_of_names` refuses every name that would break the key model's
//! syntactic separation (docs/59 §4.4 "what the separation gives"):
//!
//! - every name non-empty printable ASCII, at most `MAX_KEY_OCTETS` octets
//!   (Q-080; Q-1008 item 2);
//! - sAMAccountName without "/" ([MS-SAMR] 3.1.1.6 item 10) and without "@"
//!   (N2, project rule); a computer's ends with a single "$" (item 11), no
//!   other's ends with "$" (N2; Q-355 item 2); the krbtgt account's is
//!   exactly "krbtgt" ([MS-SAMR] 3.1.1.6 item 14);
//! - userPrincipalName: exactly one "@", the local part non-empty, without
//!   "/" and not ending with "$", the suffix a realm alias (N3; Q-1007
//!   items 2-3);
//! - servicePrincipalName: exactly two parts in phase 1 (three only for the
//!   DC account, task PN16), no empty part, no "@", no ":instancename" in
//!   the host part ([MS-ADTS] 2.2.21, 3.1.1.5.3.1.1.4; N4);
//! - dNSHostName without "/" and without "@" (it shares the client names'
//!   syntax and stays out of the SPN and UPN forms — docs/59 §4.4);
//! - no object but the krbtgt account holds a key whose initial component
//!   is "krbtgt" (RFC 4120 §6.2) or a key equal to a realm alias (N5);
//! - each kind only on the classes of the table above.
//!
//! The admin plane's value rules stay in crates/directory-admin `names.rs`
//! (lengths of docs/51 §11, [MS-SAMR] 3.1.1.6 items 8-10 beyond "/", the
//! host part of an SPN equal to the object's dNSHostName, a lower-case host
//! — RFC 4120 §6.2.1), as do the dNSHostName format of N6 (task PN6;
//! Q-1010 item 1) and which claim may carry a reserved name (A-163) —
//! docs/questions/Q-1018 item 2.
//!
//! Spec: docs/59 §4.1-§4.4; docs/questions/Q-1007 items 1-5, 7-9, Q-1008
//! item 2, Q-1009 items 1-2, Q-1010 items 1-3; [MS-SAMR] 3.1.1.6 items
//! 10, 11, 14, 3.1.1.8.4 item 2; [MS-ADTS] 2.2.21, 3.1.1.5.3.1.1.2,
//! 3.1.1.5.3.1.1.4; RFC 4120 §6.2, §7.3.

use crate::context::NameContext;
use crate::error::NameRefused;
use crate::key::{KindSet, NameKind, PrincipalKey, COMPONENT_SEPARATOR, UPN_SEPARATOR};
use crate::reserved::{is_tgs_name, TGS_NAME};
use std::collections::BTreeMap;

/// The most servicePrincipalName values one object may hold: phase 1 keeps
/// servicePrincipalName single-valued (R47-13); a multi-valued attribute
/// gets the bound 32 with task PN16 (Q-1008 item 2, decided A-173).
/// Spec: docs/47 R47-13; docs/59 §4.6; Q-1008 item 2.
pub const MAX_SERVICE_PRINCIPAL_NAMES: usize = 1;

/// The most keys one object holds: sAMAccountName, computer base,
/// userPrincipalName local part and host name, plus its SPNs (the krbtgt
/// account holds two: its sAMAccountName and the one realm alias).
/// Spec: Q-1008 item 2 ("user ≤ 2 values, computer ≤ 3 + SPNs + 1").
pub const MAX_KEYS_PER_OBJECT: usize = 4 + MAX_SERVICE_PRINCIPAL_NAMES;

/// The number of parts of a phase-1 servicePrincipalName ("a syntactically
/// correct two-part SPN"; three parts only on a DC's object, task PN16).
/// Spec: [MS-ADTS] 2.2.21, 3.1.1.5.3.1.1.4; docs/59 §4.4 N4.
const STORED_SPN_PARTS: usize = 2;

/// The final character of a computer's sAMAccountName. Spec: [MS-SAMR]
/// 3.1.1.6 item 11 ("MUST end with a single '$' (dollar sign) character").
const COMPUTER_SUFFIX: char = '$';

/// The separator of an SPN host part's ":port" / ":instancename" component.
/// Spec: [MS-ADTS] 2.2.21 (`hostname [":"port | ":"instancename]`).
const PORT_SEPARATOR: char = ':';

/// The class of an object, with the provisioning claim that changes its
/// keys (docs/59 §4.3). Which class an object has is decided by the caller
/// from authoritative data: its objectClass, its objectSid's RID, its
/// userAccountControl and the provisioning configuration (crates/
/// directory-pip `principal.rs`; crates/directory-admin's claims).
/// Spec: docs/59 §4.3; A-163; Q-1010 item 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrincipalClass {
    /// A user account (not the krbtgt account). Spec: docs/59 §4.3.
    User,
    /// A computer account with no provisioning claim. Spec: docs/59 §4.3.
    Computer,
    /// The DC's computer account (the `DcAccount` claim; ST).
    /// Spec: docs/59 §4.3; [MS-ADTS] 2.2.16; A-172.
    DomainController,
    /// A provisioned service object (the `ServiceObject`,
    /// `AdminServiceObject` and `ChangePasswordServiceObject` claims): a
    /// computer that carries the DC's dNSHostName without its key.
    /// Spec: docs/59 §4.3, §4.4 N6; Q-1010 item 3 (decided A-173).
    ProvisionedService,
    /// The krbtgt account (the `Krbtgt` claim; RID 502).
    /// Spec: docs/59 §4.3; [MS-SAMR] 2.2.1.14, 3.1.1.6 item 14.
    TicketGrantingService,
    /// A group: in the namespace by its sAMAccountName only, accepted by no
    /// lookup. Spec: docs/59 §4.1, §4.3; Q-1007 item 7.
    Group,
}

impl PrincipalClass {
    /// `true` for the classes that are computer objects.
    const fn is_computer(self) -> bool {
        matches!(
            self,
            PrincipalClass::Computer
                | PrincipalClass::DomainController
                | PrincipalClass::ProvisionedService
        )
    }

    /// `true` for the classes that may carry a userPrincipalName.
    /// Spec: docs/59 §4.1 (`UpnLocal`: "user, computer (if present)"), §4.3.
    const fn carries_upn(self) -> bool {
        matches!(self, PrincipalClass::User) || self.is_computer()
    }
}

/// An object's stored names (module documentation). The caller reads them
/// from the object; nothing here is trusted until `keys_of_names` accepts
/// it. Spec: docs/59 §4.2 (`PrincipalNames`), §4.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalNames<'a> {
    /// The object's class and claim.
    pub class: PrincipalClass,
    /// sAMAccountName (a must of every security principal).
    pub sam_account_name: &'a str,
    /// userPrincipalName, if present.
    pub user_principal_name: Option<&'a str>,
    /// The servicePrincipalName values (at most
    /// [`MAX_SERVICE_PRINCIPAL_NAMES`]).
    pub service_principal_names: Vec<&'a str>,
    /// dNSHostName, if present.
    pub dns_host_name: Option<&'a str>,
}

/// The keys one object holds, each with the kinds it carries (Q-1007 item
/// 4: one key may carry several kinds; dirstore refuses two equal values in
/// one attribute, so a key is stored once). Ordered by key octets.
/// Spec: docs/59 §4.1, §4.2 (`KeySet`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeySet {
    keys: BTreeMap<PrincipalKey, KindSet>,
}

impl KeySet {
    /// Add `key` with `kind` (merging the kinds of an equal key).
    fn add(&mut self, key: PrincipalKey, kind: NameKind) {
        let kinds = self.keys.entry(key).or_insert(KindSet::EMPTY);
        *kinds = kinds.with(kind);
    }

    /// The number of distinct keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// `true` if the object holds no key.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// `true` if `key` is one of the keys.
    #[must_use]
    pub fn contains(&self, key: &PrincipalKey) -> bool {
        self.keys.contains_key(key)
    }

    /// The kinds `key` carries (empty if it is not one of the keys).
    /// Spec: docs/59 §6.1 step 3 ("the kinds of the key = `matched`").
    #[must_use]
    pub fn kinds_of(&self, key: &PrincipalKey) -> KindSet {
        self.keys.get(key).copied().unwrap_or(KindSet::EMPTY)
    }

    /// The keys, ordered by their octets.
    pub fn keys(&self) -> impl Iterator<Item = &PrincipalKey> {
        self.keys.keys()
    }

    /// Every key with its kinds, ordered by the key's octets.
    pub fn iter(&self) -> impl Iterator<Item = (&PrincipalKey, KindSet)> {
        self.keys.iter().map(|(key, kinds)| (key, *kinds))
    }
}

/// The keys of an object's stored names (module documentation), or the
/// first rule a name breaks.
/// Spec: docs/59 §4.2, §4.3, §4.4 N2-N5; Q-1007; Q-1009 item 1; Q-1010
/// item 3; [MS-SAMR] 3.1.1.6 items 10, 11, 14; [MS-ADTS] 2.2.21,
/// 3.1.1.5.3.1.1.4; RFC 4120 §6.2.
pub fn keys_of_names(names: &PrincipalNames<'_>, ctx: &NameContext) -> Result<KeySet, NameRefused> {
    let class = names.class;
    let mut keys = KeySet::default();

    // sAMAccountName (N2). Spec: [MS-SAMR] 3.1.1.6 items 10, 11, 14.
    let sam = names.sam_account_name;
    if class == PrincipalClass::TicketGrantingService && sam != TGS_NAME {
        return Err(NameRefused::Reserved);
    }
    keys.add(
        PrincipalKey::of_components(&[sam])?,
        NameKind::SamAccountName,
    );
    match (class.is_computer(), sam.strip_suffix(COMPUTER_SUFFIX)) {
        (true, Some(base)) if !base.ends_with(COMPUTER_SUFFIX) => {
            keys.add(
                PrincipalKey::of_components(&[base])?,
                NameKind::ComputerBase,
            );
        }
        (false, None) => {}
        _ => return Err(NameRefused::ComputerSuffix),
    }

    // userPrincipalName (N3). Spec: docs/59 §4.4 N3; Q-1007 items 2-3.
    if let Some(upn) = names.user_principal_name {
        if !class.carries_upn() {
            return Err(NameRefused::NotForClass);
        }
        keys.add(upn_local_key(upn, ctx)?, NameKind::UpnLocal);
    }

    // servicePrincipalName (N4). Spec: [MS-ADTS] 2.2.21, 3.1.1.5.3.1.1.4.
    if !names.service_principal_names.is_empty() && !class.is_computer() {
        return Err(NameRefused::NotForClass);
    }
    if names.service_principal_names.len() > MAX_SERVICE_PRINCIPAL_NAMES {
        return Err(NameRefused::TooManyServicePrincipalNames);
    }
    for spn in &names.service_principal_names {
        keys.add(spn_key(spn)?, NameKind::ServicePrincipalName);
    }

    // dNSHostName. Spec: docs/59 §4.3, §4.4; Q-1010 items 1-3.
    if let Some(host) = names.dns_host_name {
        if !class.is_computer() {
            return Err(NameRefused::NotForClass);
        }
        let key = PrincipalKey::of_components(&[host])?;
        // The provisioned service objects carry the DC's host name without
        // claiming its key (Q-1010 item 3, decided A-173).
        if class != PrincipalClass::ProvisionedService {
            keys.add(key, NameKind::HostName);
        }
    }

    if class == PrincipalClass::TicketGrantingService {
        // The realm aliases are keys of the krbtgt account (N5).
        // Spec: docs/59 §4.3, §4.4 N5; Q-1007 item 9.
        for alias in ctx.realm_aliases() {
            keys.add(alias.clone(), NameKind::RealmAlias);
        }
    } else {
        // No other object holds a TGS name or a realm alias.
        // Spec: RFC 4120 §6.2; docs/59 §4.4 N4, N5; Q-1009 item 1.
        let reserved = keys
            .keys()
            .any(|key| is_tgs_name(key.first_component()) || ctx.is_alias_key(key));
        if reserved {
            return Err(NameRefused::Reserved);
        }
    }
    Ok(keys)
}

/// The key of a userPrincipalName: `fold(local)` for `local "@" suffix`
/// with exactly one "@", `local` not ending with "$", and `suffix` a realm
/// alias (compared folded). Spec: docs/59 §4.4 N3; Q-1007 items 2-3;
/// [MS-DRSR] 4.1.4.2.22 ("The user name is the component before the '@'").
fn upn_local_key(upn: &str, ctx: &NameContext) -> Result<PrincipalKey, NameRefused> {
    let (local, suffix) = upn.split_once(UPN_SEPARATOR).ok_or(NameRefused::UpnForm)?;
    if suffix.contains(UPN_SEPARATOR) || local.ends_with(COMPUTER_SUFFIX) {
        return Err(NameRefused::UpnForm);
    }
    let key = PrincipalKey::of_components(&[local])?;
    if !ctx.is_realm_alias(suffix) {
        return Err(NameRefused::UpnSuffix);
    }
    Ok(key)
}

/// The key of a stored servicePrincipalName: two parts in phase 1, no
/// ":instancename" in the host part. Spec: [MS-ADTS] 2.2.21,
/// 3.1.1.5.3.1.1.4; docs/59 §4.4 N4.
fn spn_key(spn: &str) -> Result<PrincipalKey, NameRefused> {
    let parts: Vec<&str> = spn
        .splitn(STORED_SPN_PARTS + 1, COMPONENT_SEPARATOR)
        .collect();
    let [_, host] = parts.as_slice() else {
        return Err(NameRefused::SpnForm);
    };
    if !host_part_ok(host) {
        return Err(NameRefused::SpnForm);
    }
    PrincipalKey::of_components(&parts)
}

/// `true` if an SPN's host part carries no ":instancename": no ":" at all,
/// or a non-empty host name followed by ":" and a port "entirely composed of
/// numeric digits". Spec: [MS-ADTS] 2.2.21 ("A port component is
/// distinguished from an instancename component by being entirely composed
/// of numeric digits"), 3.1.1.5.3.1.1.4 ("The SPN (2) MUST NOT contain an
/// ":instancename" component").
fn host_part_ok(host: &str) -> bool {
    match host.split_once(PORT_SEPARATOR) {
        None => true,
        Some((name, port)) => {
            !name.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [MS-ADTS] 2.2.21 (port "entirely composed of numeric digits"),
    /// 3.1.1.5.3.1.1.4 (no ":instancename").
    #[test]
    fn port_and_instancename() {
        assert!(host_part_ok("ws01.example.test"));
        assert!(host_part_ok("ws01.example.test:8080"));
        assert!(!host_part_ok("ws01.example.test:inst"));
        assert!(!host_part_ok("ws01.example.test:80a"));
        assert!(!host_part_ok("ws01.example.test:"));
        assert!(!host_part_ok(":80"));
        assert!(!host_part_ok("ws01:80:81"));
    }
}
