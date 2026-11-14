//! Password entry at the terminal (docs/51 §4.4 source (a): "a TTY without
//! echo, entered twice, and compared").
//!
//! [`Terminal`] is the seam: the production implementation is the process's
//! standard input when it is a terminal (module `terminal`, rustix
//! termios), the tests inject a scripted one. [`enter_twice`] is the logic
//! both share: two hidden entries of one line each, compared octet for
//! octet; a mismatch, a cancelled entry or a line that breaks the line rule
//! (module `line`) ends the entry with nothing kept. There is no second
//! attempt within a run: the operator runs the command again (nothing was
//! sent — every password is entered before keyd is contacted).
//!
//! Spec: docs/51 §4.4 (source (a)); docs/21 D95; docs/questions/Q-411.

use core::fmt;

use zeroize::Zeroizing;

use super::line::{password_text, EnteredPassword, LineError, MAX_PASSWORD_OCTETS};

/// The second prompt (fixed text).
pub const PROMPT_AGAIN: &str = "provision: the same password again: ";

/// The first prompt for the first administrator `sam` (an identifier from
/// the manifest — printable ASCII without a space, crates/provision-manifest).
#[must_use]
pub fn first_prompt(sam: &str) -> String {
    format!("provision: new password for first administrator {sam}: ")
}

/// Why an entry ended without a password. Fixed texts; never an octet of
/// what was typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryError {
    /// The two entries differ.
    Mismatch,
    /// The input ended before a line was complete (end of input).
    EndOfInput,
    /// More than [`MAX_PASSWORD_OCTETS`] octets before the line ended.
    TooLong,
    /// More than one line arrived in one read.
    NotOneLine,
    /// The line broke the line rule.
    Line(LineError),
    /// The terminal could not be read, or its mode changed.
    Terminal,
    /// The terminal's mode could not be put back as it was: reset it.
    NotRestored,
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EntryError::Mismatch => f.write_str("the two entries differ"),
            EntryError::EndOfInput => f.write_str("the input ended before the line did"),
            EntryError::TooLong => f.write_str("the entry is longer than 1024 octets"),
            EntryError::NotOneLine => f.write_str("more than one line arrived at once"),
            EntryError::Line(e) => write!(f, "{e}"),
            EntryError::Terminal => {
                f.write_str("the terminal could not be read or its echo could not be turned off")
            }
            EntryError::NotRestored => f.write_str(
                "the terminal's mode could not be restored after the entry; reset the terminal",
            ),
        }
    }
}

impl std::error::Error for EntryError {}

/// A terminal to enter passwords at.
/// Spec: docs/51 §4.4 (source (a)).
pub trait Terminal {
    /// Whether there is a terminal to enter at (in production: standard
    /// input refers to a terminal).
    fn is_terminal(&self) -> bool;

    /// Show `prompt` (fixed text, never a secret), then read one line with
    /// echo off into `line` (emptied first), without its terminator. At most
    /// [`MAX_PASSWORD_OCTETS`] + 1 octets are kept: an overlong line is
    /// reported as [`EntryError::TooLong`]. Whatever happens, the terminal is
    /// left in the mode it had (module `terminal`).
    ///
    /// # Errors
    /// [`EntryError`].
    fn read_hidden(
        &mut self,
        prompt: &str,
        line: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), EntryError>;
}

/// Enter the password of first administrator `sam` twice; return it if both
/// entries are the same line and the line is a password by the line rule.
///
/// # Errors
/// [`EntryError`].
///
/// Spec: docs/51 §4.4 ("entered twice and compared").
pub fn enter_twice<T: Terminal + ?Sized>(
    terminal: &mut T,
    sam: &str,
) -> Result<EnteredPassword, EntryError> {
    let mut first = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_OCTETS + 1));
    terminal.read_hidden(&first_prompt(sam), &mut first)?;
    let mut second = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_OCTETS + 1));
    terminal.read_hidden(PROMPT_AGAIN, &mut second)?;
    if first.as_slice() != second.as_slice() {
        return Err(EntryError::Mismatch);
    }
    password_text(&first).map_err(EntryError::Line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A scripted terminal: each `read_hidden` answers the next item.
    struct Scripted {
        answers: VecDeque<Result<Vec<u8>, EntryError>>,
        prompts: Vec<String>,
    }

    impl Scripted {
        fn new(answers: Vec<Result<&[u8], EntryError>>) -> Scripted {
            Scripted {
                answers: answers.into_iter().map(|a| a.map(<[u8]>::to_vec)).collect(),
                prompts: Vec::new(),
            }
        }
    }

    impl Terminal for Scripted {
        fn is_terminal(&self) -> bool {
            true
        }

        fn read_hidden(
            &mut self,
            prompt: &str,
            line: &mut Zeroizing<Vec<u8>>,
        ) -> Result<(), EntryError> {
            self.prompts.push(prompt.to_owned());
            line.clear();
            let answer = self.answers.pop_front().ok_or(EntryError::EndOfInput)??;
            line.extend_from_slice(&answer);
            Ok(())
        }
    }

    /// docs/51 §4.4: the same line twice is the password; both prompts
    /// shown, the first naming the administrator.
    #[test]
    fn two_equal_entries_give_the_password() {
        let mut t = Scripted::new(vec![Ok(b"Juniper-Kettle-71"), Ok(b"Juniper-Kettle-71")]);
        let p = enter_twice(&mut t, "alice").unwrap();
        assert_eq!(p.expose(), "Juniper-Kettle-71");
        assert_eq!(
            t.prompts,
            [
                "provision: new password for first administrator alice: ",
                PROMPT_AGAIN
            ]
        );
    }

    /// docs/51 §4.4 ("compared"): different entries — even by one octet or
    /// by case — are refused; no third prompt.
    #[test]
    fn different_entries_are_refused() {
        for (a, b) in [
            (&b"Juniper-Kettle-71"[..], &b"Juniper-Kettle-72"[..]),
            (b"Juniper-Kettle-71", b"juniper-kettle-71"),
            (b"Juniper-Kettle-71", b"Juniper-Kettle-71 "),
            (b"Juniper-Kettle-71", b""),
        ] {
            let mut t = Scripted::new(vec![Ok(a), Ok(b)]);
            assert_eq!(
                enter_twice(&mut t, "alice").unwrap_err(),
                EntryError::Mismatch
            );
            assert_eq!(t.prompts.len(), 2);
        }
    }

    /// A failure of the first entry stops before the second prompt; a
    /// failure of the second is reported as such.
    #[test]
    fn a_failed_entry_stops() {
        let mut t = Scripted::new(vec![Err(EntryError::EndOfInput)]);
        assert_eq!(
            enter_twice(&mut t, "alice").unwrap_err(),
            EntryError::EndOfInput
        );
        assert_eq!(t.prompts.len(), 1);
        let mut t = Scripted::new(vec![Ok(b"Juniper-Kettle-71"), Err(EntryError::TooLong)]);
        assert_eq!(
            enter_twice(&mut t, "alice").unwrap_err(),
            EntryError::TooLong
        );
    }

    /// Q-411 item 3: two equal entries that break the line rule are
    /// refused (empty; an interrupt key arriving as a control character).
    #[test]
    fn equal_entries_still_obey_the_line_rule() {
        let mut t = Scripted::new(vec![Ok(b""), Ok(b"")]);
        assert_eq!(
            enter_twice(&mut t, "alice").unwrap_err(),
            EntryError::Line(LineError::Empty)
        );
        let mut t = Scripted::new(vec![Ok(b"abc\x03"), Ok(b"abc\x03")]);
        assert_eq!(
            enter_twice(&mut t, "alice").unwrap_err(),
            EntryError::Line(LineError::ControlCharacter)
        );
    }
}
