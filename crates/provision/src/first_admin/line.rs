//! What a password entered through `provision first-admin-secret` is, as
//! octets: **one line of text** — the same shape for both sources (a
//! terminal line, a password file's single line) — and then the
//! management plane's password rules.
//!
//! 1. **The line** (this tool's input rule, a project choice — Q-411
//!    item 3): at most [`MAX_PASSWORD_OCTETS`] octets; not empty; valid
//!    UTF-8 (keyd takes passwords as text, docs/50 §3.4); no C0 control
//!    character (0x00-0x1F) and no DEL (0x7F). A control character in a
//!    line cannot be typed back reliably at a login prompt, a line ending
//!    other than the one terminator means the input is not one line, and
//!    on the terminal the interrupt and suspend keys arrive as control
//!    characters while their signals are off (module `terminal`) — so a
//!    control character is always refused, never kept in a password.
//! 2. **The rules** ([`check_password`]): exactly keyd's — crate
//!    admin-password-policy's `check_password`, the one rule set keyd's
//!    install path enforces (docs/56 §7 P-24 on top of [MS-SAMR] 3.1.1.7.2;
//!    docs/questions/Q-605 item 3, Q-910) — with the minimum from admind's
//!    own configuration (`min_password_length`, floor 8, P-24), the
//!    administrator's sAMAccountName, the realm as the organisation's name,
//!    and the 1024-octet bound of keyd's secret field
//!    (`ipc_keyd::MAX_SECRET`). A password this pre-check passes is one
//!    keyd's check passes too, when keyd's `min_password_chars` is no higher
//!    than admind's minimum. Which rule failed is not said (docs/37 §2;
//!    Q-401 item 8).
//!
//! Spec: docs/51 §4.4 (R51-5: "≤ 256 characters ([MS-SAMR] 3.1.1.7.2 item
//! 2) and 1024 bytes = `ipc_keyd::MAX_SECRET`; does not contain the
//! sAMAccountName (item 3.2.2)"), §11; [MS-SAMR] 3.1.1.7.2; docs/50 §3.4;
//! docs/56 §7 (P-24); A-79; A-94; docs/questions/Q-401, Q-411, Q-605,
//! Q-910.

use core::fmt;

use admin_password_policy::PasswordRefused;
use zeroize::Zeroizing;

/// The most octets a password may have — keyd's secret field.
/// Spec: docs/51 §4.4 (R51-5: "1024 bytes = `ipc_keyd::MAX_SECRET`").
pub const MAX_PASSWORD_OCTETS: usize = 1024;

const _: () = assert!(MAX_PASSWORD_OCTETS as u64 == ipc_keyd::channel::MAX_SECRET as u64);

/// The line terminator. Spec: Q-411 item 3 (one line, LF-terminated).
pub(crate) const LF: u8 = b'\n';

/// Why a line is not a password. Fixed texts; never an octet of the line.
/// Spec: module documentation; AGENTS.md §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineError {
    /// Nothing before the terminator.
    Empty,
    /// More than [`MAX_PASSWORD_OCTETS`] octets.
    TooLong,
    /// A C0 control character or DEL.
    ControlCharacter,
    /// Not valid UTF-8.
    NotUtf8,
}

impl fmt::Display for LineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LineError::Empty => "the password is empty",
            LineError::TooLong => "the password is longer than 1024 octets",
            LineError::ControlCharacter => {
                "the password contains a control character (an interrupt or suspend key cancels the entry)"
            }
            LineError::NotUtf8 => "the password is not valid UTF-8 text",
        })
    }
}

impl std::error::Error for LineError {}

/// A password as this tool holds it: zeroized on drop, never printed (its
/// `Debug` shows nothing), never cloned.
/// Spec: docs/51 §4.4 ("the buffers are `Zeroizing`"); AGENTS.md §6.
pub struct EnteredPassword(Zeroizing<String>);

impl EnteredPassword {
    /// The text, for the rules.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The text, by value, for keyd's `set_secret` (which takes it in a
    /// zeroizing string, crates/ipc-keyd `Password`).
    #[must_use]
    pub fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl fmt::Debug for EnteredPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Not even the length (as crates/ipc-keyd `Password`).
        f.write_str("EnteredPassword(<redacted>)")
    }
}

/// The text of one line (without its terminator), by the input rule of the
/// module documentation. The result is the only copy made; `octets` stays
/// with the caller (a zeroizing buffer).
///
/// # Errors
/// [`LineError`].
///
/// Spec: module documentation item 1; docs/50 §3.4.
pub fn password_text(octets: &[u8]) -> Result<EnteredPassword, LineError> {
    if octets.is_empty() {
        return Err(LineError::Empty);
    }
    if octets.len() > MAX_PASSWORD_OCTETS {
        return Err(LineError::TooLong);
    }
    if octets.iter().any(|&b| b < 0x20 || b == 0x7F) {
        return Err(LineError::ControlCharacter);
    }
    let text = core::str::from_utf8(octets).map_err(|_| LineError::NotUtf8)?;
    Ok(EnteredPassword(Zeroizing::new(text.to_owned())))
}

/// The password rules for a first administrator: at most
/// [`MAX_PASSWORD_OCTETS`] octets, then crate admin-password-policy's
/// `check_password` — the very rule set keyd's install path enforces
/// (docs/questions/Q-605 item 3) — with `min_chars`, the administrator's
/// sAMAccountName as the account's name and `realm` as the organisation's
/// name (as keyd passes them: the binding's one name component, keyd's
/// realm).
///
/// # Errors
/// [`PasswordRefused`] — deliberately without saying which rule.
///
/// Spec: [MS-SAMR] 3.1.1.7.2 items 2, 3.2.1-3.2.4; docs/51 §4.4, §11;
/// docs/56 §7 (P-24); A-79; A-94 (Q-401); docs/questions/Q-605, Q-910.
pub fn check_password(
    password: &str,
    min_chars: u32,
    sam_account_name: &str,
    realm: &str,
) -> Result<(), PasswordRefused> {
    if password.len() > MAX_PASSWORD_OCTETS {
        return Err(PasswordRefused);
    }
    admin_password_policy::check_password(
        password,
        &admin_password_policy::PolicyInputs {
            min_chars,
            account_name: &[sam_account_name],
            organisation_name: realm,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Q-411 item 3 (one line of text): accepted text, refused shapes.
    /// Test data constructed by hand.
    #[test]
    fn the_line_rule() {
        assert_eq!(
            password_text(b"Juniper-Kettle-Ample-71").unwrap().expose(),
            "Juniper-Kettle-Ample-71"
        );
        assert_eq!(password_text(b"").unwrap_err(), LineError::Empty);
        assert_eq!(
            password_text(&[b'a'; 1025]).unwrap_err(),
            LineError::TooLong
        );
        assert!(password_text(&[b'a'; 1024]).is_ok());
        for control in [0x00u8, 0x03, 0x09, 0x0A, 0x0D, 0x1A, 0x1C, 0x1F, 0x7F] {
            let line = [b'a', b'b', control, b'c'];
            assert_eq!(
                password_text(&line).unwrap_err(),
                LineError::ControlCharacter,
                "{control:#x}"
            );
        }
        assert_eq!(
            password_text(&[b'a', 0xFF, b'b']).unwrap_err(),
            LineError::NotUtf8
        );
        assert_eq!(password_text("é-ü-ß".as_bytes()).unwrap().expose(), "é-ü-ß");
    }

    /// The password never shows in `Debug`.
    #[test]
    fn the_password_is_redacted() {
        let p = password_text(b"Juniper-Kettle-Ample-71").unwrap();
        let shown = format!("{p:?}");
        assert!(!shown.contains("Juniper"));
    }

    /// [MS-SAMR] 3.1.1.7.2 items 2, 3.2.1, 3.2.2 and docs/56 §7 P-24,
    /// through the shared crate (each rule once; the shared crate's own
    /// tests cover the readings). Test data constructed by hand; realm
    /// `EXAMPLE.ORG` and account `alice` are made-up names.
    #[test]
    fn keyds_rules_apply() {
        let realm = "EXAMPLE.ORG";
        assert_eq!(
            check_password("Juniper-Kettle-71", 12, "alice", realm),
            Ok(())
        );
        // The owner's floor: exactly 8 passes with a minimum of 8.
        assert_eq!(check_password("Tq7#Lm2!", 8, "alice", realm), Ok(()));
        assert!(check_password("Tq7#Lm2", 8, "alice", realm).is_err());
        assert!(check_password("Juniper-Kettle-71", 18, "alice", realm).is_err());
        assert!(check_password(&"a".repeat(257), 12, "alice", realm).is_err());
        assert!(check_password(&"é".repeat(513), 12, "alice", realm).is_err());
        // The account's name, the organisation's name, a weak word.
        assert!(check_password("Tq7#ALICE!w", 8, "alice", realm).is_err());
        assert!(check_password("Tq7#Example!", 8, "alice", realm).is_err());
        assert!(check_password("Tq7#Admin!w", 8, "alice", realm).is_err());
        // Classes, sequences, repeats (the owner's examples).
        assert!(check_password("juniper-kettle-71", 8, "alice", realm).is_err());
        assert!(check_password("Tq7#Abc!w", 8, "alice", realm).is_err());
        assert!(check_password("Tq7#123!w", 8, "alice", realm).is_err());
        assert!(check_password("Tq7#111!w", 8, "alice", realm).is_err());
    }
}
