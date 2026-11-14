//! A first administrator's password file (`--password-file
//! <sAMAccountName>=<path>`, docs/51 §4.4 source (b); R51-5; D95: never
//! argv or env).
//!
//! # The file rule
//!
//! Checked on the file **as the running uid (root), before the privilege
//! drop** ([`open_password_file`]) — no octet of the content is read yet:
//!
//! 1. the path is inspected first without following a link
//!    (`symlink_metadata`): a symbolic link is refused, anything but a
//!    regular file is refused (so a FIFO or a device is never opened);
//! 2. it is opened with O_NOFOLLOW (a link put there since step 1 fails the
//!    open) and the **opened** file is checked again (`fstat`): a regular
//!    file, owned by the running uid, permission bits exactly 0400 or 0600
//!    (no other bit — not group, not other, not set-id), at most
//!    [`MAX_PASSWORD_FILE_OCTETS`] octets, not empty.
//!
//! The content is read **after** the drop, from the descriptor opened as
//! root ([`OpenedPasswordFile::read`]), once the process is not dumpable
//! and its memory locked (module `privilege`): no password is in memory
//! before that (docs/51 §4.4; Q-411 item 2). It is read into a zeroizing
//! buffer of [`MAX_PASSWORD_FILE_OCTETS`] + 1 octets (never more is read)
//! and must be **exactly one line** ([`parse_password_file`]): the
//! password, optionally followed by one LF, and no other line ending (an LF
//! elsewhere or any CR is "not one line"); then the line rule of module
//! `line` (no control character, UTF-8, not empty).
//!
//! Errors are fixed texts; a path is the operator's own argument; no octet
//! of the content ever appears in one.
//!
//! Spec: docs/51 §4.4 ("a regular file (not a symlink), owned by the
//! running uid, mode 0400/0600, ≤ 1024 bytes, one line"; "the buffers are
//! `Zeroizing`"); A-86 follow-up (O_NOFOLLOW in every reader); docs/21 D95;
//! rustix docs.rs `fs::openat`, `fs::OFlags::NOFOLLOW` (through
//! crate::fs, P-2); std `fs::symlink_metadata`, `fs::Metadata`,
//! `os::unix::fs::MetadataExt` (`uid`, `mode`, `len`), `io::Read::read`
//! (`Ok(0)`: end of file); docs/questions/Q-411.

use core::fmt;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use zeroize::Zeroizing;

use super::line::{password_text, EnteredPassword, LineError, LF, MAX_PASSWORD_OCTETS};

/// The largest password file accepted, in octets.
/// Spec: docs/51 §4.4 ("≤ 1024 bytes"); `ipc_keyd::MAX_SECRET`.
pub const MAX_PASSWORD_FILE_OCTETS: usize = 1024;

const _: () = assert!(MAX_PASSWORD_FILE_OCTETS == MAX_PASSWORD_OCTETS);

/// The permission bits a password file may have: owner read, or owner read
/// and write. Spec: docs/51 §4.4 ("mode 0400/0600").
pub const ACCEPTED_MODES: [u32; 2] = [0o400, 0o600];

/// Every permission bit, set-id and sticky included (compared exactly).
const PERMISSION_BITS: u32 = 0o7777;

/// Why a password file was refused. Fixed texts.
/// Spec: module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileRefusal {
    /// The file could not be inspected, opened or read.
    Unreadable,
    /// The path is a symbolic link.
    Symlink,
    /// The path is not a regular file.
    NotRegular,
    /// The file is not owned by the running uid.
    WrongOwner,
    /// The permission bits are not exactly 0400 or 0600.
    WrongMode,
    /// The file is empty (or holds only a line terminator).
    Empty,
    /// The file is larger than [`MAX_PASSWORD_FILE_OCTETS`].
    TooLarge,
    /// The content is not exactly one line.
    NotOneLine,
    /// The line holds a control character.
    ControlCharacter,
    /// The line is not UTF-8.
    NotUtf8,
}

impl fmt::Display for FileRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FileRefusal::Unreadable => "the password file cannot be inspected, opened or read",
            FileRefusal::Symlink => "the password file is a symbolic link",
            FileRefusal::NotRegular => "the password file is not a regular file",
            FileRefusal::WrongOwner => {
                "the password file is not owned by the account running provision (root)"
            }
            FileRefusal::WrongMode => "the password file's mode is not exactly 0400 or 0600",
            FileRefusal::Empty => "the password file is empty",
            FileRefusal::TooLarge => "the password file is larger than 1024 octets",
            FileRefusal::NotOneLine => {
                "the password file is not exactly one line (one LF at most, at the end; no CR)"
            }
            FileRefusal::ControlCharacter => {
                "the password file's line contains a control character"
            }
            FileRefusal::NotUtf8 => "the password file's line is not valid UTF-8 text",
        })
    }
}

impl std::error::Error for FileRefusal {}

/// The facts of the file rule, as read from a file's metadata.
/// Spec: module documentation, step 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordFileFacts {
    /// A regular file.
    pub regular_file: bool,
    /// The owner uid.
    pub owner_uid: u32,
    /// The mode bits.
    pub mode: u32,
    /// The size in octets.
    pub size: u64,
}

impl PasswordFileFacts {
    /// The facts of `metadata`.
    #[must_use]
    pub fn of(metadata: &std::fs::Metadata) -> PasswordFileFacts {
        PasswordFileFacts {
            regular_file: metadata.is_file(),
            owner_uid: metadata.uid(),
            mode: metadata.mode(),
            size: metadata.len(),
        }
    }
}

/// The file rule on metadata: regular, owned by `running_uid`, permission
/// bits exactly 0400 or 0600, 1 ..= [`MAX_PASSWORD_FILE_OCTETS`] octets —
/// checked in that order.
///
/// # Errors
/// [`FileRefusal`].
///
/// Spec: docs/51 §4.4.
pub fn check_facts(facts: &PasswordFileFacts, running_uid: u32) -> Result<(), FileRefusal> {
    if !facts.regular_file {
        return Err(FileRefusal::NotRegular);
    }
    if facts.owner_uid != running_uid {
        return Err(FileRefusal::WrongOwner);
    }
    if !ACCEPTED_MODES.contains(&(facts.mode & PERMISSION_BITS)) {
        return Err(FileRefusal::WrongMode);
    }
    if facts.size == 0 {
        return Err(FileRefusal::Empty);
    }
    let bound = u64::try_from(MAX_PASSWORD_FILE_OCTETS).unwrap_or(u64::MAX);
    if facts.size > bound {
        return Err(FileRefusal::TooLarge);
    }
    Ok(())
}

/// A password file that passed the file rule, opened (as root, before the
/// drop) and not read yet.
#[derive(Debug)]
pub struct OpenedPasswordFile {
    file: File,
}

/// Inspect, open and check the password file at `path` as `running_uid`
/// (module documentation, steps 1-2). Nothing of the content is read.
///
/// # Errors
/// [`FileRefusal`].
///
/// Spec: docs/51 §4.4; A-86 (O_NOFOLLOW).
pub fn open_password_file(
    path: &Path,
    running_uid: u32,
) -> Result<OpenedPasswordFile, FileRefusal> {
    let link = std::fs::symlink_metadata(path).map_err(|_| FileRefusal::Unreadable)?;
    if link.file_type().is_symlink() {
        return Err(FileRefusal::Symlink);
    }
    check_facts(&PasswordFileFacts::of(&link), running_uid)?;
    let file = crate::fs::open_no_follow(path).map_err(|_| FileRefusal::Unreadable)?;
    let opened = file.metadata().map_err(|_| FileRefusal::Unreadable)?;
    check_facts(&PasswordFileFacts::of(&opened), running_uid)?;
    Ok(OpenedPasswordFile { file })
}

impl OpenedPasswordFile {
    /// Read the content (at most [`MAX_PASSWORD_FILE_OCTETS`] + 1 octets,
    /// into a zeroizing buffer) and take its one line.
    ///
    /// # Errors
    /// [`FileRefusal`].
    ///
    /// Spec: module documentation; std `io::Read::read` (`Ok(0)`: end of
    /// file; `ErrorKind::Interrupted` retried).
    pub fn read(mut self) -> Result<EnteredPassword, FileRefusal> {
        let mut buffer = Zeroizing::new([0u8; MAX_PASSWORD_FILE_OCTETS + 1]);
        let mut filled = 0;
        while filled < buffer.len() {
            match self.file.read(&mut buffer[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err(FileRefusal::Unreadable),
            }
        }
        parse_password_file(&buffer[..filled])
    }
}

/// The password of a password file's content: exactly one line — the
/// password, optionally followed by one LF — by the line rule of module
/// `line`. At most [`MAX_PASSWORD_FILE_OCTETS`] octets of content.
///
/// # Errors
/// [`FileRefusal`]: `TooLarge`, `Empty`, `NotOneLine` (an LF that is not
/// the last octet, or any CR), `ControlCharacter`, `NotUtf8`.
///
/// Spec: docs/51 §4.4 ("one line"); Q-411 item 3.
pub fn parse_password_file(content: &[u8]) -> Result<EnteredPassword, FileRefusal> {
    if content.len() > MAX_PASSWORD_FILE_OCTETS {
        return Err(FileRefusal::TooLarge);
    }
    let line = content.strip_suffix(&[LF]).unwrap_or(content);
    if line.iter().any(|&b| b == LF || b == b'\r') {
        return Err(FileRefusal::NotOneLine);
    }
    password_text(line).map_err(|e| match e {
        LineError::Empty => FileRefusal::Empty,
        LineError::TooLong => FileRefusal::TooLarge,
        LineError::ControlCharacter => FileRefusal::ControlCharacter,
        LineError::NotUtf8 => FileRefusal::NotUtf8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(mode: u32, size: u64) -> PasswordFileFacts {
        PasswordFileFacts {
            regular_file: true,
            owner_uid: 0,
            mode: 0o100_000 | mode,
            size,
        }
    }

    /// docs/51 §4.4: owner, mode 0400/0600 exactly, size bounds.
    #[test]
    fn the_metadata_rule() {
        assert_eq!(check_facts(&facts(0o600, 20), 0), Ok(()));
        assert_eq!(check_facts(&facts(0o400, 20), 0), Ok(()));
        for mode in [
            0o644, 0o640, 0o604, 0o700, 0o660, 0o4600, 0o1600, 0o000, 0o200,
        ] {
            assert_eq!(
                check_facts(&facts(mode, 20), 0),
                Err(FileRefusal::WrongMode),
                "{mode:o}"
            );
        }
        assert_eq!(
            check_facts(&facts(0o600, 20), 1000),
            Err(FileRefusal::WrongOwner)
        );
        assert_eq!(check_facts(&facts(0o600, 0), 0), Err(FileRefusal::Empty));
        assert_eq!(check_facts(&facts(0o600, 1024), 0), Ok(()));
        assert_eq!(
            check_facts(&facts(0o600, 1025), 0),
            Err(FileRefusal::TooLarge)
        );
        let mut dir = facts(0o600, 20);
        dir.regular_file = false;
        assert_eq!(check_facts(&dir, 0), Err(FileRefusal::NotRegular));
    }

    /// docs/51 §4.4 ("one line"); Q-411 item 3. Test data constructed by
    /// hand.
    #[test]
    fn the_content_rule() {
        let pw = "Juniper-Kettle-Ample-71";
        assert_eq!(parse_password_file(pw.as_bytes()).unwrap().expose(), pw);
        assert_eq!(
            parse_password_file(format!("{pw}\n").as_bytes())
                .unwrap()
                .expose(),
            pw
        );
        for (content, refusal) in [
            (format!("{pw}\n\n"), FileRefusal::NotOneLine),
            (format!("{pw}\nsecond-line\n"), FileRefusal::NotOneLine),
            (format!("{pw}\r\n"), FileRefusal::NotOneLine),
            (format!("{pw}\r"), FileRefusal::NotOneLine),
            ("\n".to_owned(), FileRefusal::Empty),
            (String::new(), FileRefusal::Empty),
            (format!("{pw}\t"), FileRefusal::ControlCharacter),
            ("a".repeat(1025), FileRefusal::TooLarge),
        ] {
            assert_eq!(
                parse_password_file(content.as_bytes()).unwrap_err(),
                refusal,
                "{refusal:?}"
            );
        }
        assert_eq!(
            parse_password_file(&[b'a', 0xC3]).unwrap_err(),
            FileRefusal::NotUtf8
        );
        // 1023 octets + LF fits; 1024 octets without LF fits.
        assert!(parse_password_file(format!("{}\n", "a".repeat(1023)).as_bytes()).is_ok());
        assert!(parse_password_file("a".repeat(1024).as_bytes()).is_ok());
    }
}
