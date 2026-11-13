//! The value rules of the request's name fields, checked before anything is
//! read from the directory (they reveal nothing about it).
//!
//! Names are printable ASCII only (P-6, P-9; Q-080), so a character is an
//! octet here and "characters" counts octets.
//!
//! Spec: [MS-SAMR] v20260427 3.1.1.6 items 8-13 (sAMAccountName); docs/51
//! §11 (the table, decided A-79 / Q-298 item 1: ≤ 20 for user and computer
//! including the "$", ≤ 256 for a group); docs/46 §5.4 (cn / ou 1..64
//! characters, userPrincipalName and servicePrincipalName 1..1024,
//! dNSHostName 0..2048, description 0..1024); RFC 4120 §6.2.1 (the host
//! component of a server name "MUST be lowercase"), §7.3 (krbtgt is the
//! TGS's name); docs/47 §1.3 (R47-1, the SPN write rule).

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

/// The reserved first component of the TGS's name. Spec: RFC 4120 §7.3.
const KRBTGT: &str = "krbtgt";

/// `true` if every octet is printable ASCII, 0x20..=0x7E (P-6; this also
/// excludes [MS-SAMR] 3.1.1.6 item 10's 0x00-0x1F).
fn printable_ascii(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// A sAMAccountName of at most `max_chars` characters: non-empty printable
/// ASCII (P-6), at least one non-blank character (item 8), not ending with
/// "." (item 9), none of the item-10 characters.
/// Spec: [MS-SAMR] 3.1.1.6 items 8, 9, 10, 12, 13.
pub(crate) fn sam_ok(sam: &str, max_chars: usize) -> bool {
    !sam.is_empty()
        && sam.len() <= max_chars
        && printable_ascii(sam)
        && sam.bytes().any(|b| b != b' ')
        && !sam.ends_with('.')
        && !sam.bytes().any(|b| SAM_FORBIDDEN.contains(&b))
}

/// A user's sAMAccountName (also its cn). A trailing "$" is refused: it is
/// the computer-account form (item 11), and a user holding a computer-shaped
/// name invites confusion between the two (docs/questions/Q-355 item 2).
/// Spec: [MS-SAMR] 3.1.1.6 items 8-12; A-79.
pub(crate) fn user_sam_ok(sam: &str) -> bool {
    sam_ok(sam, MAX_ACCOUNT_SAM_CHARS) && !sam.ends_with(COMPUTER_SUFFIX)
}

/// A group's sAMAccountName (also its cn, so also ≤ 64 characters —
/// Q-355 item 1); no trailing "$" (Q-355 item 2).
/// Spec: [MS-SAMR] 3.1.1.6 items 8-10, 13; docs/46 §5.4 (cn).
pub(crate) fn group_sam_ok(sam: &str) -> bool {
    sam_ok(sam, MAX_GROUP_SAM_CHARS.min(MAX_RDN_VALUE_CHARS)) && !sam.ends_with(COMPUTER_SUFFIX)
}

/// A computer's name (its cn): `name ‖ "$"` must be a valid sAMAccountName
/// of at most 20 characters ending with a **single** "$", so `name` itself
/// must not end with "$".
/// Spec: [MS-SAMR] 3.1.1.6 items 8-12; docs/51 §5.2 row 2; A-79.
pub(crate) fn computer_name_ok(name: &str) -> bool {
    !name.ends_with(COMPUTER_SUFFIX)
        && sam_ok(name, MAX_RDN_VALUE_CHARS)
        && sam_ok(&computer_sam(name), MAX_ACCOUNT_SAM_CHARS)
}

/// The sAMAccountName of a computer named `name`. Spec: docs/51 §5.2 row 2
/// (`sAMAccountName = name ‖ "$"`).
pub(crate) fn computer_sam(name: &str) -> String {
    let mut sam = String::with_capacity(name.len() + 1);
    sam.push_str(name);
    sam.push(COMPUTER_SUFFIX);
    sam
}

/// An OU / container name (`ou` / `cn`): 1..64 printable ASCII characters.
/// Spec: docs/46 §5.4; P-6.
pub(crate) fn rdn_value_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_RDN_VALUE_CHARS && printable_ascii(name)
}

/// A userPrincipalName: 1..1024 printable ASCII characters. No further
/// form is checked (no rule for it was found in the opened sections; the
/// unique index rejects a duplicate). Spec: docs/46 §5.4; P-6.
pub(crate) fn upn_ok(upn: &str) -> bool {
    !upn.is_empty() && upn.len() <= MAX_PRINCIPAL_NAME_CHARS && printable_ascii(upn)
}

/// A dNSHostName: 1..2048 printable ASCII characters without a space or a
/// "/" (it is the host component of the computer's SPN) and without an
/// upper-case letter (RFC 4120 §6.2.1: the host component "MUST be
/// lowercase"; docs/questions/Q-355 item 3).
/// Spec: docs/46 §5.4; RFC 4120 §6.2.1; docs/47 §1.3; P-6.
pub(crate) fn dns_host_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_DNS_HOST_NAME_CHARS
        && printable_ascii(name)
        && !name
            .bytes()
            .any(|b| b == b' ' || b == b'/' || b.is_ascii_uppercase())
}

/// A computer's single servicePrincipalName: exactly `service "/" host`,
/// a two-component name of type NT-SRV-HST, where `service` is a non-empty
/// printable ASCII component without a space, not "krbtgt" (the TGS's
/// name), and `host` is the computer's dNSHostName — a host the object does
/// not name cannot be claimed (docs/questions/Q-355 item 3); 1..1024
/// characters.
/// Spec: RFC 4120 §6.2.1 ("a two-component name of type NT-SRV-HST, if the
/// host name is an Internet domain name"; host lowercase), §7.3; docs/47
/// §1.3 (R47-1); docs/51 §5.2 row 2 (one SPN, host in lower case);
/// docs/46 §5.4.
pub(crate) fn spn_ok(spn: &str, dns_host_name: &str) -> bool {
    if spn.is_empty() || spn.len() > MAX_PRINCIPAL_NAME_CHARS || !printable_ascii(spn) {
        return false;
    }
    match spn.split_once(SPN_SEPARATOR) {
        Some((service, host)) => {
            !service.is_empty()
                && !service.bytes().any(|b| b == b' ')
                && service != KRBTGT
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
        assert!(group_sam_ok(&"g".repeat(64)));
        assert!(!group_sam_ok(&"g".repeat(65)));
        assert!(computer_name_ok(&"w".repeat(19)));
        assert!(!computer_name_ok(&"w".repeat(20)));
        assert!(!computer_name_ok("ws01$"));
        assert_eq!(computer_sam("ws01"), "ws01$");
    }

    /// RFC 4120 §6.2.1, §7.3; docs/47 §1.3.
    #[test]
    fn spn_rules() {
        assert!(spn_ok("host/ws01.example.test", "ws01.example.test"));
        assert!(!spn_ok("host/WS01.example.test", "WS01.example.test"));
        assert!(!spn_ok("host/ws02.example.test", "ws01.example.test"));
        assert!(!spn_ok("krbtgt/ws01.example.test", "ws01.example.test"));
        assert!(!spn_ok("host", "ws01.example.test"));
        assert!(!spn_ok("/ws01.example.test", "ws01.example.test"));
        assert!(!spn_ok("host/ws01.example.test/x", "ws01.example.test"));
        assert_eq!(
            spn_components("host/ws01.example.test"),
            ["host", "ws01.example.test"]
        );
    }
}
