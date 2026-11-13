//! The account salt (docs/47 §3, R47-4): ONE public function, shared by the
//! password path (the management plane passes it to keyd `set_secret`) and
//! by the account source (PA-ETYPE-INFO2), so the two can never diverge
//! (D64: one canonical identity in one place).
//!
//! The rule is [MS-KILE] v20260928 3.1.1.2: "KILE concatenates the following
//! information to use as the key salt for principals:
//! - User accounts: < DNS of the realm, converted to uppercase> | <user
//!   name>
//! - Computer accounts: < DNS name of the realm, converted to uppercase > |
//!   "host" | < computer name, converted to lower case with trailing "$"
//!   stripped off > | "." | < DNS name of the realm, converted to lower case
//!   >"
//!
//! Interpretation (docs/47 §3.3, decided A-37 on Q-110): "<user name>" and
//! "<computer name>" are the sAMAccountName as stored (case kept for a user);
//! the realm is the configured Kerberos realm, which must be the DNS name of
//! the domain in upper case (a setup constraint checked when the view is
//! built); the same salt serves every configured enctype and both key sets
//! (PrincipalLongterm and Service) of one account. Names are ASCII only
//! (P-6, P-9), so "converted to upper / lower case" is the ASCII A-Z / a-z
//! mapping.
//!
//! Spec: [MS-KILE] 3.1.1.2, 4.4 (the printed salt
//! "DOMAIN.COMhostclient.domain.com"); RFC 4120 §3.1.3, §4, §6.1; docs/47
//! §3.3 (R47-4); Q-110 (A-37); P-6.

use krb_proto::{KerberosString, Realm};

/// Which salt rule of [MS-KILE] 3.1.1.2 applies. Chosen from the account's
/// most specific class: `user` → User, `computer` → Computer (docs/47 §3.3:
/// "kind = User (class user, UAC N)"; "kind = Computer (class computer, UAC
/// WT/ST)").
///
/// Spec: [MS-KILE] 3.1.1.2 ("User accounts", "Computer accounts"); docs/47
/// §3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountKind {
    /// A user account.
    User,
    /// A computer account.
    Computer,
}

/// The salt could not be formed. Carries no name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SaltError {
    /// The realm or the name is empty or not printable ASCII (P-6).
    NotPrintableAscii,
    /// A computer name is empty once its trailing "$" is stripped.
    EmptyComputerName,
    /// The result is not a valid KerberosString (RFC 4120 5.2.1).
    NotKerberosString,
}

impl core::fmt::Display for SaltError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            SaltError::NotPrintableAscii => "realm or account name is not printable ASCII",
            SaltError::EmptyComputerName => "computer name is empty",
            SaltError::NotKerberosString => "salt is not a valid KerberosString",
        })
    }
}

impl std::error::Error for SaltError {}

/// The literal "host" of the computer rule. Spec: [MS-KILE] 3.1.1.2.
const HOST: &str = "host";

/// The literal "." of the computer rule. Spec: [MS-KILE] 3.1.1.2.
const DOT: &str = ".";

/// The trailing character stripped from a computer name. Spec: [MS-KILE]
/// 3.1.1.2 ("with trailing "$" stripped off").
const COMPUTER_SUFFIX: char = '$';

/// `true` if `s` is non-empty printable ASCII (0x20..=0x7E). Spec: P-6
/// (ASCII-only names); docs/46 §8.2 (AsciiPrintable on sAMAccountName).
fn printable_ascii(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// The key salt of the account named `sam_account_name` in `realm`, by the
/// [MS-KILE] 3.1.1.2 rule for `kind` (module docs):
///
/// - User: `upper(realm) ‖ sAMAccountName`;
/// - Computer: `upper(realm) ‖ "host" ‖ lower(sAMAccountName without its
///   trailing "$") ‖ "." ‖ lower(realm)`.
///
/// Used both to derive the keys (keyd `set_secret`, docs/47 §9) and to
/// advertise them (PA-ETYPE-INFO2, RFC 4120 §3.1.3, 5.2.7.5).
///
/// Spec: [MS-KILE] 3.1.1.2; docs/47 §3.3 (R47-4); Q-110 (A-37).
pub fn account_salt(
    realm: &Realm,
    kind: AccountKind,
    sam_account_name: &str,
) -> Result<KerberosString, SaltError> {
    let realm = realm.as_str();
    if !printable_ascii(realm) || !printable_ascii(sam_account_name) {
        return Err(SaltError::NotPrintableAscii);
    }
    // "< DNS of the realm, converted to uppercase>".
    let mut salt = realm.to_ascii_uppercase();
    match kind {
        AccountKind::User => salt.push_str(sam_account_name),
        AccountKind::Computer => {
            let name = sam_account_name
                .strip_suffix(COMPUTER_SUFFIX)
                .unwrap_or(sam_account_name);
            if name.is_empty() {
                return Err(SaltError::EmptyComputerName);
            }
            salt.push_str(HOST);
            salt.push_str(&name.to_ascii_lowercase());
            salt.push_str(DOT);
            salt.push_str(&realm.to_ascii_lowercase());
        }
    }
    KerberosString::new(&salt).map_err(|_| SaltError::NotKerberosString)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm(r: &str) -> Realm {
        Realm::new(r).unwrap()
    }

    /// [MS-KILE] 4.4: the printed salt "DOMAIN.COMhostclient.domain.com"
    /// (UTF8Salt), worked from the 3.1.1.2 computer rule with realm
    /// DOMAIN.COM and computer name "client": "DOMAIN.COM" | "host" |
    /// "client" | "." | "domain.com". The sAMAccountName forms "CLIENT$" and
    /// "client$" both reduce to "client".
    #[test]
    fn kile_4_4_printed_salt() {
        for name in ["CLIENT$", "client$", "Client$"] {
            assert_eq!(
                account_salt(&realm("DOMAIN.COM"), AccountKind::Computer, name)
                    .unwrap()
                    .as_str(),
                "DOMAIN.COMhostclient.domain.com",
                "{name}"
            );
        }
    }

    /// [MS-KILE] 3.1.1.2 user rule: realm | user name, case kept (Q-110).
    #[test]
    fn user_rule() {
        assert_eq!(
            account_salt(&realm("EXAMPLE.TEST"), AccountKind::User, "Alice")
                .unwrap()
                .as_str(),
            "EXAMPLE.TESTAlice"
        );
    }

    /// Only one trailing "$" is stripped ([MS-KILE] 3.1.1.2); an empty or
    /// non-printable name is refused (P-6, fail closed).
    #[test]
    fn edge_cases() {
        let r = realm("EXAMPLE.TEST");
        assert_eq!(
            account_salt(&r, AccountKind::Computer, "a$$")
                .unwrap()
                .as_str(),
            "EXAMPLE.TESThosta$.example.test"
        );
        assert_eq!(
            account_salt(&r, AccountKind::Computer, "$"),
            Err(SaltError::EmptyComputerName)
        );
        assert_eq!(
            account_salt(&r, AccountKind::User, ""),
            Err(SaltError::NotPrintableAscii)
        );
        assert_eq!(
            account_salt(&r, AccountKind::User, "a\tb"),
            Err(SaltError::NotPrintableAscii)
        );
        assert_eq!(
            account_salt(&r, AccountKind::User, "\u{e9}"),
            Err(SaltError::NotPrintableAscii)
        );
    }
}
