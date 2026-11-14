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
//! 2. **The rules** ([`check_password`]): exactly admind's — crate
//!    admin-password-policy ([MS-SAMR] 3.1.1.7.2 items 2, 3.2.1, 3.2.2 as
//!    A-79 / Q-401 read them) — with the minimum from admind's own
//!    configuration (`min_password_length`, floor 12, A-79 / P-24) and the
//!    1024-octet bound of keyd's secret field (`ipc_keyd::MAX_SECRET`).
//!    Which rule failed is not said (docs/37 §2; Q-401 item 8).
//!
//! Spec: docs/51 §4.4 (R51-5: "≤ 256 characters ([MS-SAMR] 3.1.1.7.2 item
//! 2) and 1024 bytes = `ipc_keyd::MAX_SECRET`; does not contain the
//! sAMAccountName (item 3.2.2)"), §11; [MS-SAMR] 3.1.1.7.2; docs/50 §3.4;
//! A-79; A-94; P-24; docs/questions/Q-401, Q-411.

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

/// admind's password rules for a first administrator: at most
/// [`MAX_PASSWORD_OCTETS`] octets, then crate admin-password-policy's
/// `check_length` (≤ 256 UTF-16 code units, ≥ `min_chars` code points) and
/// `check_account_name` (the sAMAccountName, more than two characters, not
/// a case-insensitive substring) — the very functions admind's
/// `SetPassword` applies.
///
/// # Errors
/// [`PasswordRefused`] — deliberately without saying which rule.
///
/// Spec: [MS-SAMR] 3.1.1.7.2 items 2, 3.2.1, 3.2.2; docs/51 §4.4, §11;
/// A-79; A-94 (Q-401); P-24.
pub fn check_password(
    password: &str,
    min_chars: u32,
    sam_account_name: &str,
) -> Result<(), PasswordRefused> {
    if password.len() > MAX_PASSWORD_OCTETS {
        return Err(PasswordRefused);
    }
    admin_password_policy::check_length(password, min_chars)?;
    admin_password_policy::check_account_name(password, sam_account_name)
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

    /// [MS-SAMR] 3.1.1.7.2 items 2, 3.2.1, 3.2.2 with A-79's minimum,
    /// through the shared crate (each rule once; the shared crate's own
    /// tests cover the readings).
    #[test]
    fn admind_rules_apply() {
        assert_eq!(check_password("Juniper-Kettle-71", 12, "alice"), Ok(()));
        assert!(check_password("short-pw-12", 12, "alice").is_err());
        assert!(check_password("Juniper-Kettle-71", 18, "alice").is_err());
        assert!(check_password(&"a".repeat(257), 12, "alice").is_err());
        assert!(check_password("xx-ALICE-padding", 12, "alice").is_err());
        assert!(check_password(&"é".repeat(513), 12, "alice").is_err());
    }
}
