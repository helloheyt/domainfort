//! Reading the attestation key keyadm's ceremony hands keyd (task PN9).
//!
//! The attestation key is the key with which keyd verifies dird's name
//! resolutions (docs/59 §7.2, §7.4). `provision domain` draws it and writes
//! dird's protected key file and keyadm's input file from that one draw
//! (task PN12: `--attestation-key-path`, `--keyadm-attestation-key-path` —
//! keyadm's uid, mode 0400); keyadm reads the input file here and sends the
//! key to keyd in the ceremony, before the seal
//! ([`crate::ceremony::run_with_attestation_key`]). keyd never returns it
//! (docs/10 I1; D28 / D29); keyadm never prints it, and never deletes the
//! file — it could not (the file's directory is root's, the provisioning
//! installer's rule), and in development mode the next ceremony needs it
//! (docs/51 §4.5; docs/questions/Q-1057).
//!
//! # The file rule
//!
//! keyadm runs under its own account, never as root (crate identity), so the
//! file is the **running account's**: it is reached through
//! crates/protected-file's walk from `/` (every directory owned by root or by
//! that account and not writable by group or others; no symbolic link at any
//! component — A-86, docs/52 R11, Q-468), and the file itself must be
//!
//! 1. a regular file (a link or anything else is refused before any open),
//! 2. owned by the running account (its effective uid),
//! 3. with permission bits exactly 0400 or 0600 — no access for group or
//!    others, no set-id or sticky bit —
//!
//! checked on the name and again on the opened descriptor; then
//! 4. exactly [`ATTESTATION_KEY_OCTETS`] octets (raw key octets, no
//!    encoding — like dird's integrity key file, docs/50 §7.4), read into a
//!    zeroizing buffer of one octet more (never more is read), and
//! 5. not all zero (a never-filled buffer is not a key — A-173: the key is
//!    drawn at random; [`AttestationKeyOctets::from_slice`]).
//!
//! The owner and mode follow the precedent of `provision`'s password files
//! (docs/51 §4.4: "a regular file (not a symlink), owned by the running uid,
//! mode 0400/0600"); the raw 32 octets follow dird's integrity key file
//! (crates/directory-daemon `read_integrity_key`). `provision domain` writes
//! it so (task PN12; docs/questions/Q-1039 item 1, A-183).
//!
//! Errors are fixed texts: no octet of the file, no length read, no path
//! (the path is the operator's own argument).
//!
//! Spec: docs/59 §7.4, §10 (PN9, PN12); docs/questions/Q-1011 item 2
//! (A-173: "drawn by `provision` … delivered to keyd in ceremony mode only,
//! never exported"), Q-1033 (A-177); docs/51 §4.4 (the password-file rule),
//! §6; docs/50 §7.4, §8.2; A-86; docs/52 §3.13 (C13), §7 R11; Q-468 (A-102);
//! crates/protected-file `open`, `FileFacts`, `OpenError`, `PathBreak`; std
//! `io::Read::read` (`Ok(0)`: end of file); AGENTS.md §6.

use core::fmt;
use ipc_keyd::{AttestationKeyOctets, ATTESTATION_KEY_OCTETS};
use protected_file::{FileFacts, OpenError, PathBreak};
use std::io::{ErrorKind, Read};
use std::path::Path;
use zeroize::Zeroizing;

/// The permission bits the attestation key file may have: owner read, or
/// owner read and write. Spec: docs/51 §4.4 (the precedent: "mode
/// 0400/0600").
pub const ACCEPTED_MODES: [u32; 2] = [0o400, 0o600];

/// Every permission bit, set-id and sticky included (compared exactly).
const PERMISSION_BITS: u32 = 0o7777;

/// Why the attestation key file was refused. Fixed texts; no octet of the
/// file and no length ever appears in one.
/// Spec: module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFileError {
    /// The running account cannot be read (any platform but Linux).
    Identity,
    /// The file could not be inspected, opened or read.
    Unreadable,
    /// The path is a symbolic link, or not a regular file.
    NotRegular,
    /// The file is not owned by the account running keyadm.
    WrongOwner,
    /// The permission bits are not exactly 0400 or 0600.
    WrongMode,
    /// The file does not hold exactly 32 octets.
    WrongLength,
    /// The file holds 32 zero octets: a key that was never drawn.
    AllZero,
    /// The path does not end in a file name, or a directory on it is a
    /// symbolic link or not a directory, is owned by neither root nor the
    /// running account, or is writable by group or others.
    Path(PathBreak),
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let KeyFileError::Path(path) = self {
            return write!(f, "the attestation key file's path {path}");
        }
        f.write_str(match self {
            KeyFileError::Identity => {
                "the running account cannot be read (keyadm runs on Linux only)"
            }
            KeyFileError::Unreadable => {
                "the attestation key file cannot be inspected, opened or read"
            }
            KeyFileError::NotRegular => {
                "the attestation key file is a symbolic link or not a regular file"
            }
            KeyFileError::WrongOwner => {
                "the attestation key file is not owned by the account running keyadm"
            }
            KeyFileError::WrongMode => {
                "the attestation key file's mode is not exactly 0400 or 0600"
            }
            KeyFileError::WrongLength => "the attestation key file does not hold exactly 32 octets",
            KeyFileError::AllZero => "the attestation key file holds no key (all octets are zero)",
            // Handled above.
            KeyFileError::Path(_) => "the attestation key file's path is refused",
        })
    }
}

impl std::error::Error for KeyFileError {}

/// The file rule on one set of facts (the name's, then the opened
/// descriptor's): a regular file, owned by `owner`, mode exactly 0400 or
/// 0600 — in that order.
///
/// # Errors
/// [`KeyFileError::NotRegular`], [`KeyFileError::WrongOwner`],
/// [`KeyFileError::WrongMode`].
///
/// Spec: module documentation, rules 1-3.
pub fn check_facts(facts: &FileFacts, owner: u32) -> Result<(), KeyFileError> {
    if facts.symbolic_link || !facts.regular_file {
        return Err(KeyFileError::NotRegular);
    }
    if facts.owner_uid != owner {
        return Err(KeyFileError::WrongOwner);
    }
    if !ACCEPTED_MODES.contains(&(facts.mode & PERMISSION_BITS)) {
        return Err(KeyFileError::WrongMode);
    }
    Ok(())
}

/// Read the attestation key file at `path`, owned by the account running
/// keyadm (its effective uid, through `daemon_sandbox::read_state` — the
/// project's one reader of the process identity, as crate identity uses).
///
/// # Errors
/// [`KeyFileError`].
///
/// Spec: module documentation.
pub fn read_attestation_key(path: &Path) -> Result<AttestationKeyOctets, KeyFileError> {
    let state = daemon_sandbox::read_state().map_err(|_| KeyFileError::Identity)?;
    read_attestation_key_owned_by(path, state.effective_uid)
}

/// Read the attestation key file at `path`, which must be owned by `owner`
/// (the running account in the binary — [`read_attestation_key`]; the test
/// account in tests). The key's octets live only in the zeroizing reading
/// buffer (wiped when this returns) and in the returned value (wiped when
/// it drops).
///
/// # Errors
/// [`KeyFileError`].
///
/// Spec: module documentation, rules 1-5.
pub fn read_attestation_key_owned_by(
    path: &Path,
    owner: u32,
) -> Result<AttestationKeyOctets, KeyFileError> {
    let file =
        protected_file::open(path, owner, |facts| check_facts(facts, owner)).map_err(|error| {
            match error {
                OpenError::Io(_) => KeyFileError::Unreadable,
                OpenError::Path(path) => KeyFileError::Path(path),
                OpenError::Refused(refusal) => refusal,
            }
        })?;
    // One octet more than a key: a longer file is refused without reading
    // it whole (AGENTS.md §6: bounded).
    let mut buffer = Zeroizing::new([0u8; ATTESTATION_KEY_OCTETS + 1]);
    let mut filled = 0usize;
    let mut reader = file.take(u64::try_from(ATTESTATION_KEY_OCTETS + 1).unwrap_or(u64::MAX));
    loop {
        let slot = buffer.get_mut(filled..).ok_or(KeyFileError::WrongLength)?;
        if slot.is_empty() {
            break;
        }
        match reader.read(slot) {
            Ok(0) => break,
            Ok(read) => filled = filled.saturating_add(read),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(KeyFileError::Unreadable),
        }
    }
    if filled != ATTESTATION_KEY_OCTETS {
        return Err(KeyFileError::WrongLength);
    }
    let octets = buffer
        .get(..ATTESTATION_KEY_OCTETS)
        .ok_or(KeyFileError::WrongLength)?;
    AttestationKeyOctets::from_slice(octets).ok_or(KeyFileError::AllZero)
}

#[cfg(test)]
mod tests {
    //! The file rule on hand-made facts (the walk and the read are tested on
    //! real files in tests/attestation_key_file.rs). Source: docs/51 §4.4
    //! (the rule's precedent); module documentation.

    use super::*;

    fn facts(mode: u32, owner: u32) -> FileFacts {
        FileFacts {
            regular_file: true,
            symbolic_link: false,
            owner_uid: owner,
            mode: 0o100_000 | mode,
            size: 32,
        }
    }

    /// Rules 1-3: a regular file of the running account, 0400 or 0600; no
    /// other bit, no other owner, no link.
    #[test]
    fn the_file_rule_is_exact() {
        assert_eq!(check_facts(&facts(0o400, 4103), 4103), Ok(()));
        assert_eq!(check_facts(&facts(0o600, 4103), 4103), Ok(()));
        for mode in [
            0o440, 0o640, 0o604, 0o644, 0o700, 0o4400, 0o1600, 0o000, 0o200,
        ] {
            assert_eq!(
                check_facts(&facts(mode, 4103), 4103),
                Err(KeyFileError::WrongMode),
                "{mode:o}"
            );
        }
        assert_eq!(
            check_facts(&facts(0o400, 0), 4103),
            Err(KeyFileError::WrongOwner)
        );
        let link = FileFacts {
            regular_file: false,
            symbolic_link: true,
            ..facts(0o400, 4103)
        };
        assert_eq!(check_facts(&link, 4103), Err(KeyFileError::NotRegular));
        let directory = FileFacts {
            regular_file: false,
            ..facts(0o400, 4103)
        };
        assert_eq!(check_facts(&directory, 4103), Err(KeyFileError::NotRegular));
    }

    /// AGENTS.md §6 (no secret in an error): every refusal is a fixed text.
    #[test]
    fn refusals_are_fixed_texts() {
        for error in [
            KeyFileError::Identity,
            KeyFileError::Unreadable,
            KeyFileError::NotRegular,
            KeyFileError::WrongOwner,
            KeyFileError::WrongMode,
            KeyFileError::WrongLength,
            KeyFileError::AllZero,
            KeyFileError::Path(PathBreak::NoFileName),
        ] {
            assert!(
                error.to_string().contains("attestation key file")
                    || error == KeyFileError::Identity
            );
        }
    }
}
