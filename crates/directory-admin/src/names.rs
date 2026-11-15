//! The value rules of the request's name fields, checked before anything is
//! read from the directory (they reveal nothing about it).
//!
//! Names are printable ASCII only (P-6, P-9; Q-080), so a character is an
//! octet here and "characters" counts octets.
//!
//! # The admin plane's rules, not the namespace's (task PN5)
//!
//! These are the admin-plane value rules of docs/questions/Q-1018 item 2
//! (decided A-175): the lengths of docs/51 §11 and docs/46 §5.4, [MS-SAMR]
//! 3.1.1.6 items 8-13, the SPN's host part equal to the object's own
//! dNSHostName in lower case (RFC 4120 §6.2.1). The namespace's syntax ("/"
//! and "@", the final-"$" rule both ways, the UPN suffix, two-part SPNs
//! without ":instancename") and **every reserved name** — the TGS's
//! `krbtgt` (RFC 4120 §6.2), the admin service's `admind/<host>` (A-73),
//! the change-password service's `kadmin/changepw` (RFC 3244 §2), in any
//! case — are judged once, by crate principal-names on the object's folded
//! keys, in the one checker (crate::invariants, module `object`), which
//! the online create also runs at `prepare` (class C49, docs/questions/
//! Q-1009 items 1-2: no octet comparison decides a reservation here any
//! more). What stays here is exact by design: the two provisioned objects
//! that own a reserved name must spell it exactly as keyd derives their
//! key set's purpose from it ([`admin_service_spn_ok`],
//! `change_password_service_spn_ok`).
//!
//! Spec: [MS-SAMR] v20260427 3.1.1.6 items 8-13 (sAMAccountName); docs/51
//! §11 (the table, decided A-79 / Q-298 item 1: ≤ 20 for user and computer
//! including the "$", ≤ 256 for a group); docs/46 §5.4 (cn / ou 1..64
//! characters, userPrincipalName and servicePrincipalName 1..1024,
//! dNSHostName 0..2048, description 0..1024); RFC 4120 §6.2.1 (the host
//! component of a server name "MUST be lowercase"); docs/47 §1.3 (R47-1,
//! the SPN write rule); docs/59 §4.4, §5.1; docs/questions/Q-1009, Q-1018
//! item 2.

use keyd_types::KeyPurpose;
use krb_proto::constants::KRB_NT_SRV_HST;
use krb_proto::{KerberosString, PrincipalName};

/// The most characters of a user's or a computer's sAMAccountName ("$"
/// included for a computer). Spec: [MS-SAMR] 3.1.1.6 item 12 ("MUST contain
/// less than or equal to 20 characters if the object's objectClass is
/// user"); A-79 (Q-298 item 1: computer too, its class chain contains user).
pub const MAX_ACCOUNT_SAM_CHARS: usize = 20;

/// The most characters of a group's sAMAccountName. Spec: [MS-SAMR] 3.1.1.6
/// item 13 ("less than or equal to 256 characters if the object's
/// objectClass is group").
pub const MAX_GROUP_SAM_CHARS: usize = 256;

/// The most characters of a cn / ou value (docs/46 §5.4: 1..64). A group's
/// cn is its sAMAccountName, so a group name is bounded by this too
/// (docs/questions/Q-355 item 1).
pub const MAX_RDN_VALUE_CHARS: usize = 64;

/// The most characters of userPrincipalName and servicePrincipalName.
/// Spec: docs/46 §5.4 (1..1024).
pub const MAX_PRINCIPAL_NAME_CHARS: usize = 1024;

/// The most characters of dNSHostName. Spec: docs/46 §5.4 (0..2048).
pub const MAX_DNS_HOST_NAME_CHARS: usize = 2048;

/// The most UTF-16 units of description. Spec: docs/46 §5.4 (0..1024
/// characters, counted in UTF-16 units — Q-080).
pub const MAX_DESCRIPTION_UNITS: usize = 1024;

/// The characters a sAMAccountName must not contain besides 0x00-0x1F.
/// Spec: [MS-SAMR] 3.1.1.6 item 10 (the table: 0x22 ", 0x2F /, 0x5C \,
/// 0x5B [, 0x5D ], 0x3A :, 0x7C |, 0x3C <, 0x3E >, 0x2B +, 0x3D =, 0x3B ;,
/// 0x3F ?, 0x2C ",", 0x2A *).
const SAM_FORBIDDEN: [u8; 15] = [
    b'"', b'/', b'\\', b'[', b']', b':', b'|', b'<', b'>', b'+', b'=', b';', b'?', b',', b'*',
];

/// The trailing character of a computer's sAMAccountName. Spec: [MS-SAMR]
/// 3.1.1.6 item 11 ("MUST end with a single '$'").
pub(crate) const COMPUTER_SUFFIX: char = '$';

/// The SPN component separator. Spec: docs/47 §1.3 (R47-1); [MS-KILE]
/// 3.1.5.11 as cited there.
const SPN_SEPARATOR: char = '/';

/// `true` if every octet is printable ASCII, 0x20..=0x7E (P-6; this also
/// excludes [MS-SAMR] 3.1.1.6 item 10's 0x00-0x1F).
fn printable_ascii(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// The userPrincipalName separator, which no sAMAccountName holds: docs/59
/// N2's project rule (stricter than [MS-SAMR] 3.1.1.6 item 10) — a name in
/// "@" form is never itself a key of the namespace (docs/59 §4.2). Judged
/// again by the namespace's own syntax (`principal_names::keys_of_names`);
/// a value refused by both is fine (docs/questions/Q-1018 item 2), and this
/// one refuses it before anything is read — for `provision domain`'s input
/// check too. Spec: docs/59 §4.2, §4.4 N2.
const UPN_SEPARATOR: u8 = b'@';

/// A sAMAccountName of at most `max_chars` characters: non-empty printable
/// ASCII (P-6), at least one non-blank character (item 8), not ending with
/// "." (item 9), none of the item-10 characters, no "@" (docs/59 N2).
/// Spec: [MS-SAMR] 3.1.1.6 items 8, 9, 10, 12, 13; docs/59 §4.4 N2.
pub(crate) fn sam_ok(sam: &str, max_chars: usize) -> bool {
    !sam.is_empty()
        && sam.len() <= max_chars
        && printable_ascii(sam)
        && sam.bytes().any(|b| b != b' ')
        && !sam.ends_with('.')
        && !sam.bytes().any(|b| b == UPN_SEPARATOR)
        && !sam.bytes().any(|b| SAM_FORBIDDEN.contains(&b))
}

/// A user's sAMAccountName (also its cn). A trailing "$" is refused: it is
/// the computer-account form (item 11), and a user holding a computer-shaped
/// name invites confusion between the two (docs/questions/Q-355 item 2).
/// Spec: [MS-SAMR] 3.1.1.6 items 8-12; A-79.
pub fn user_sam_ok(sam: &str) -> bool {
    sam_ok(sam, MAX_ACCOUNT_SAM_CHARS) && !sam.ends_with(COMPUTER_SUFFIX)
}

/// A group's sAMAccountName (also its cn, so also ≤ 64 characters —
/// Q-355 item 1); no trailing "$" (Q-355 item 2).
/// Spec: [MS-SAMR] 3.1.1.6 items 8-10, 13; docs/46 §5.4 (cn).
pub fn group_sam_ok(sam: &str) -> bool {
    sam_ok(sam, MAX_GROUP_SAM_CHARS.min(MAX_RDN_VALUE_CHARS)) && !sam.ends_with(COMPUTER_SUFFIX)
}

/// A computer's name (its cn): `name ‖ "$"` must be a valid sAMAccountName
/// of at most 20 characters ending with a **single** "$", so `name` itself
/// must not end with "$".
/// Spec: [MS-SAMR] 3.1.1.6 items 8-12; docs/51 §5.2 row 2; A-79.
pub fn computer_name_ok(name: &str) -> bool {
    !name.ends_with(COMPUTER_SUFFIX)
        && sam_ok(name, MAX_RDN_VALUE_CHARS)
        && sam_ok(&computer_sam(name), MAX_ACCOUNT_SAM_CHARS)
}

/// The sAMAccountName of a computer named `name`. Spec: docs/51 §5.2 row 2
/// (`sAMAccountName = name ‖ "$"`).
pub fn computer_sam(name: &str) -> String {
    let mut sam = String::with_capacity(name.len() + 1);
    sam.push_str(name);
    sam.push(COMPUTER_SUFFIX);
    sam
}

/// An OU / container name (`ou` / `cn`): 1..64 printable ASCII characters.
/// Spec: docs/46 §5.4; P-6.
pub fn rdn_value_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_RDN_VALUE_CHARS && printable_ascii(name)
}

/// A userPrincipalName: 1..1024 printable ASCII characters. Its form —
/// exactly one "@", a local part without "/" and not ending with "$", the
/// suffix a realm alias — is the namespace's rule N3 (crate principal-names
/// `keys_of_names`, run by the checker; docs/questions/Q-1018 item 2), and
/// its uniqueness is the namespace's over every name (N1).
/// Spec: docs/46 §5.4; P-6; docs/59 §4.4 N1, N3.
pub(crate) fn upn_ok(upn: &str) -> bool {
    !upn.is_empty() && upn.len() <= MAX_PRINCIPAL_NAME_CHARS && printable_ascii(upn)
}

/// A dNSHostName: 1..2048 printable ASCII characters without a space or a
/// "/" (it is the host component of the computer's SPN) and without an
/// upper-case letter (RFC 4120 §6.2.1: the host component "MUST be
/// lowercase"; docs/questions/Q-355 item 3).
/// Spec: docs/46 §5.4; RFC 4120 §6.2.1; docs/47 §1.3; P-6.
pub fn dns_host_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_DNS_HOST_NAME_CHARS
        && printable_ascii(name)
        && !name
            .bytes()
            .any(|b| b == b' ' || b == b'/' || b.is_ascii_uppercase())
}

/// A computer's single servicePrincipalName, by the admin plane's rules:
/// exactly `service "/" host`, a two-component name of type NT-SRV-HST,
/// where `service` is a non-empty printable ASCII component without a
/// space and `host` is the computer's dNSHostName — a host the object does
/// not name cannot be claimed (docs/questions/Q-355 item 3); 1..1024
/// characters.
/// Spec: RFC 4120 §6.2.1 ("a two-component name of type NT-SRV-HST, if the
/// host name is an Internet domain name"; host lowercase); docs/47 §1.3
/// (R47-1); docs/51 §5.2 row 2 (one SPN, host in lower case); docs/46
/// §5.4.
///
/// **Not here — the namespace's, judged on the folded keys by the one
/// checker** (module documentation; task PN5): the reserved names. An SPN
/// whose first component is `krbtgt` in any case (RFC 4120 §6.2: "Names of
/// any type with an initial component of 'krbtgt' are reserved"), or that
/// spells `admind/<host>` or `kadmin/changepw` in any case (A-163: only the
/// provisioning claim that owns the name may carry it), passes this shape
/// rule and is refused by crate::invariants — at `prepare` too, which runs
/// the same rules on the new object (`ValueInvalid`). Before task PN5 this
/// function compared those names octet for octet, so `KRBTGT/…`, `ADMIND/…`
/// and `KADMIN/changepw` passed (class C49; docs/questions/Q-1009 items
/// 1-2).
pub fn spn_ok(spn: &str, dns_host_name: &str) -> bool {
    spn_shape_ok(spn, dns_host_name)
}

/// The admin service object's servicePrincipalName (A-73: `admind/<host>`):
/// the shape of [`spn_ok`], spelled exactly as the name from which keyd
/// derives the admin service's key-set purpose. Only the provisioning
/// claim of the admin service object may carry a name equivalent to it —
/// the reservation, judged on the folded key by crate::invariants (task
/// PN5); this exact spelling is the claimed object's own rule, so that its
/// stored name and its key set's purpose agree. `provision domain` checks
/// its input with it.
/// Spec: A-73; docs/51 §4.3 step 5; docs/52 R2b; docs/questions/Q-541,
/// Q-1009 item 2.
pub fn admin_service_spn_ok(spn: &str, dns_host_name: &str) -> bool {
    spn_shape_ok(spn, dns_host_name) && spn_derives_admin_service(spn)
}

/// `true` if the principal name the SPN forms (its components split on
/// "/", NT-SRV-HST — docs/47 §1.3, §9.1) derives the admin service's key
/// set by the one derivation, `keyd_types::KeyPurpose::of_service_name`
/// (docs/questions/Q-491 item 1) — not a second spelling of the rule. A
/// value that cannot form a name (a component that is not a KerberosString)
/// derives nothing.
/// Spec: docs/52 R2b; docs/questions/Q-491 item 1, Q-541; RFC 4120 §6.2
/// (the name-type a hint only).
pub(crate) fn spn_derives_admin_service(spn: &str) -> bool {
    matches!(purpose_of_spn(spn), Some(purpose) if purpose == KeyPurpose::AdminService)
}

/// The change-password service object's servicePrincipalName (task K9):
/// spelled exactly as the name from which keyd derives the
/// `ChangePasswordService` key-set purpose — `kadmin/changepw` (RFC 3244
/// §2: "the service principal kadmin/changepw@REALM"; keyd-types
/// `is_change_password_service_name`). Its second component is a fixed
/// instance, not a host (RFC 4120 §6.2: NT-SRV-INST, "Service and other
/// unique instance"), so the host rule of [`spn_ok`] does not apply; the
/// value is still printable ASCII within the SPN bound. Only the
/// provisioning claim of the change-password service object may carry a
/// name equivalent to it — the reservation, judged on the folded key by
/// crate::invariants (task PN5); this exact spelling is the claimed object's
/// own rule.
/// Spec: RFC 3244 §2; RFC 4120 §6.2; docs/53 R53-6, §5.2, §10 (K9);
/// docs/52 R2b; docs/questions/Q-964 item 13, Q-972, Q-1009 item 2.
pub(crate) fn change_password_service_spn_ok(spn: &str) -> bool {
    !spn.is_empty()
        && spn.len() <= MAX_PRINCIPAL_NAME_CHARS
        && printable_ascii(spn)
        && matches!(
            purpose_of_spn(spn),
            Some(purpose) if purpose == KeyPurpose::ChangePasswordService
        )
}

/// The key-set purpose keyd derives from the principal name an SPN forms
/// (its components split on "/", the name-type a hint only — RFC 4120 §6.2)
/// by the one derivation, `keyd_types::KeyPurpose::of_service_name`; `None`
/// if the value cannot form a name. Used only for the exact spelling of the
/// two claimed objects' names above — never to decide whether a name is
/// reserved (that is `principal_names::reserved_name_of` on the folded key,
/// in crate::invariants; class C49).
/// Spec: docs/52 R2b (one derivation); docs/questions/Q-491 item 1, Q-541,
/// Q-972, Q-1009 item 2; RFC 4120 §6.2.
fn purpose_of_spn(spn: &str) -> Option<KeyPurpose> {
    let name = principal_name(KRB_NT_SRV_HST, &spn_components(spn))?;
    Some(KeyPurpose::of_service_name(&name))
}

/// The principal name of `components`, if each is a KerberosString.
/// Spec: RFC 4120 §5.2.2 (PrincipalName), §6.2.
fn principal_name(name_type: i32, components: &[&str]) -> Option<PrincipalName> {
    let name_string = components
        .iter()
        .map(|c| KerberosString::new(c).ok())
        .collect::<Option<Vec<_>>>()?;
    Some(PrincipalName {
        name_type,
        name_string,
    })
}

/// The admin plane's SPN shape: `service "/" host`, the rules of
/// [`spn_ok`]'s documentation (the host compared with the object's own
/// dNSHostName, both lower case — RFC 4120 §6.2.1).
/// Spec: as [`spn_ok`].
fn spn_shape_ok(spn: &str, dns_host_name: &str) -> bool {
    if spn.is_empty() || spn.len() > MAX_PRINCIPAL_NAME_CHARS || !printable_ascii(spn) {
        return false;
    }
    match spn.split_once(SPN_SEPARATOR) {
        Some((service, host)) => {
            !service.is_empty()
                && !service.bytes().any(|b| b == b' ')
                && host == dns_host_name
                && dns_host_name_ok(host)
        }
        None => false,
    }
}

/// The components of a stored SPN (for the `Service` key set's binding).
/// Spec: docs/47 §9.1 ("the single SPN split on '/'").
pub(crate) fn spn_components(spn: &str) -> Vec<&str> {
    spn.split(SPN_SEPARATOR).collect()
}

/// A description: 1..1024 UTF-16 units, no control character (an absent
/// description is `None`, so the empty value is refused).
/// Spec: docs/46 §5.4; Q-080 (characters in UTF-16 units).
pub(crate) fn description_ok(text: &str) -> bool {
    !text.is_empty()
        && text.encode_utf16().count() <= MAX_DESCRIPTION_UNITS
        && !text.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [MS-SAMR] 3.1.1.6 items 8-13; A-79 (lengths); P-6.
    #[test]
    fn sam_account_name_rules() {
        assert!(user_sam_ok("alice"));
        assert!(user_sam_ok("a.b-c_d e"));
        assert!(user_sam_ok(&"a".repeat(20)));
        assert!(!user_sam_ok(&"a".repeat(21)));
        assert!(!user_sam_ok(""));
        assert!(!user_sam_ok("   "));
        assert!(!user_sam_ok("alice."));
        assert!(!user_sam_ok("alice$"));
        for c in SAM_FORBIDDEN {
            let name = format!("a{}b", char::from(c));
            assert!(!user_sam_ok(&name), "{name}");
        }
        assert!(!user_sam_ok("a\tb"));
        assert!(!user_sam_ok("caf\u{e9}"));
        // docs/59 N2: no "@" (the UPN form is never a sAMAccountName).
        assert!(!user_sam_ok("a@b"));
        assert!(!group_sam_ok("g@example.test"));
        assert!(!computer_name_ok("ws@1"));
        assert!(group_sam_ok(&"g".repeat(64)));
        assert!(!group_sam_ok(&"g".repeat(65)));
        assert!(computer_name_ok(&"w".repeat(19)));
        assert!(!computer_name_ok(&"w".repeat(20)));
        assert!(!computer_name_ok("ws01$"));
        assert_eq!(computer_sam("ws01"), "ws01$");
    }

    /// RFC 4120 §6.2.1; docs/47 §1.3. The reserved first component
    /// (`krbtgt`, RFC 4120 §6.2) is not this rule's any more: the namespace
    /// refuses it on the folded key (task PN5; crate::invariants tests
    /// `reserved_names_are_judged_on_the_folded_key`).
    #[test]
    fn spn_rules() {
        assert!(spn_ok("host/ws01.example.test", "ws01.example.test"));
        assert!(!spn_ok("host/WS01.example.test", "WS01.example.test"));
        assert!(!spn_ok("host/ws02.example.test", "ws01.example.test"));
        assert!(!spn_ok("host", "ws01.example.test"));
        assert!(!spn_ok("/ws01.example.test", "ws01.example.test"));
        assert!(!spn_ok("host/ws01.example.test/x", "ws01.example.test"));
        assert!(!spn_ok("ho st/ws01.example.test", "ws01.example.test"));
        assert_eq!(
            spn_components("host/ws01.example.test"),
            ["host", "ws01.example.test"]
        );
    }

    /// docs/52 R2b follow-up; Q-491 item 1 (the derivation), Q-541: the
    /// admin service object's own rule is the exact spelling keyd derives
    /// the admin service's purpose from — `admin_service_spn_ok` keeps every
    /// other rule of the shape and refuses a case variant (its stored name
    /// and its key set's purpose must agree). Whether `admind/…` in any case
    /// is reserved is the namespace's question (task PN5; Q-1009 item 2):
    /// `spn_ok` is the shape alone.
    #[test]
    fn the_admin_service_objects_name_is_spelled_exactly() {
        let host = "ws01.example.test";
        assert!(spn_derives_admin_service("admind/ws01.example.test"));
        assert!(admin_service_spn_ok("admind/ws01.example.test", host));
        assert!(!admin_service_spn_ok("admind/ws02.example.test", host));
        assert!(!admin_service_spn_ok(
            "admind/WS01.example.test",
            "WS01.example.test"
        ));
        assert!(!admin_service_spn_ok("ldap/ws01.example.test", host));
        assert!(!admin_service_spn_ok("ADMIND/ws01.example.test", host));
        assert!(!spn_derives_admin_service("ADMIND/ws01.example.test"));
        assert!(spn_ok("ldap/ws01.example.test", host));
    }

    /// Task K9 (docs/53 §5.2, §10; RFC 3244 §2 "the service principal
    /// kadmin/changepw@REALM"; docs/questions/Q-972): the change-password
    /// service object's own rule is the exact name, without the host rule
    /// (its second component is a fixed instance, RFC 4120 §6.2
    /// NT-SRV-INST); a case variant, a third component and other classes are
    /// not the name. The reservation in any case is the namespace's (task
    /// PN5; Q-1009 item 2).
    #[test]
    fn the_change_password_service_objects_name_is_spelled_exactly() {
        assert_eq!(
            purpose_of_spn("kadmin/changepw"),
            Some(KeyPurpose::ChangePasswordService)
        );
        assert!(change_password_service_spn_ok("kadmin/changepw"));
        assert!(!change_password_service_spn_ok("kadmin/changepw/x"));
        assert!(!change_password_service_spn_ok("KADMIN/changepw"));
        assert!(!change_password_service_spn_ok("kadmin/ws01.example.test"));
        assert!(!change_password_service_spn_ok("admind/ws01.example.test"));
        assert!(!change_password_service_spn_ok(""));
        assert_eq!(
            purpose_of_spn("kadmin/ws01.example.test"),
            Some(KeyPurpose::Service)
        );
        assert_eq!(
            purpose_of_spn("admind/ws01.example.test"),
            Some(KeyPurpose::AdminService)
        );
        assert_eq!(
            purpose_of_spn("ldap/ws01.example.test"),
            Some(KeyPurpose::Service)
        );
        assert_eq!(purpose_of_spn("caf\u{e9}/x"), None);
    }
}
