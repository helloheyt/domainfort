//! keyadm's attestation key file (task PN9) on real files: the
//! crates/protected-file walk, the owner and mode rule, exactly 32 octets,
//! never all zero — and nothing of the key in a `Debug` or an error.
//!
//! The test runs as an ordinary account, so the owner is injected
//! (`read_attestation_key_owned_by`, the test account standing in for the
//! account running keyadm — which is what the binary passes: its effective
//! uid). The files live inside the workspace (crates/test-scratch), where
//! the walk from `/` accepts the test account's directories (Q-480).
//!
//! Source: docs/59 §7.4, §10 (PN9); docs/questions/Q-1011 item 2 (A-173),
//! Q-1033; docs/51 §4.4 (the precedent: "a regular file (not a symlink),
//! owned by the running uid, mode 0400/0600"); docs/50 §7.4 (a raw 32-octet
//! key file); A-86; docs/52 R11; Q-468 (A-102). Every key here is made up;
//! no vector comes from any other implementation.

use keyadm::attestation_key::{read_attestation_key_owned_by, KeyFileError};
use protected_file::PathBreak;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use test_scratch::ScratchDir;

/// A made-up key: 32 distinct octets.
fn key_octets() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, octet) in key.iter_mut().enumerate() {
        *octet = 0xA0 ^ u8::try_from(i).unwrap();
    }
    key
}

/// Write `content` at `path` with `mode`.
fn write(path: &Path, content: &[u8], mode: u32) {
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The module rules 1-5: a 32-octet file of the running account, 0400 or
/// 0600, is read exactly; the octets are the file's.
#[test]
fn a_well_formed_key_file_is_read() {
    let scratch = ScratchDir::new("keyadm-attestation-ok").unwrap();
    for mode in [0o400, 0o600] {
        let path = scratch.join(format!("attestation-{mode:o}.key"));
        write(&path, &key_octets(), mode);
        let owner = std::fs::metadata(&path).unwrap().uid();
        let key = read_attestation_key_owned_by(&path, owner).unwrap();
        assert_eq!(key.expose(), &key_octets(), "{mode:o}");
        // docs/CLEAN-ROOM.md: the carrier prints nothing of the key.
        let text = format!("{key:?}");
        assert_eq!(text, "AttestationKeyOctets(<redacted>)");
    }
}

/// Rule 3 (exactly 0400 or 0600), rule 4 (exactly 32 octets — 0, 31 and 33
/// refused, a longer file never read whole), rule 5 (not all zero); a
/// missing file is unreadable.
#[test]
fn a_key_file_breaking_the_rule_is_refused() {
    let scratch = ScratchDir::new("keyadm-attestation-bad").unwrap();
    let path = scratch.join("attestation.key");
    write(&path, &key_octets(), 0o400);
    let owner = std::fs::metadata(&path).unwrap().uid();
    for mode in [0o440, 0o640, 0o604, 0o644, 0o700, 0o200] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            read_attestation_key_owned_by(&path, owner).err(),
            Some(KeyFileError::WrongMode),
            "{mode:o}"
        );
    }
    for content in [
        &[][..],
        &key_octets()[..31],
        &[0x5A; 33][..],
        &[0x5A; 4096][..],
    ] {
        write(&path, content, 0o600);
        assert_eq!(
            read_attestation_key_owned_by(&path, owner).err(),
            Some(KeyFileError::WrongLength),
            "{} octets",
            content.len()
        );
    }
    write(&path, &[0u8; 32], 0o600);
    assert_eq!(
        read_attestation_key_owned_by(&path, owner).err(),
        Some(KeyFileError::AllZero)
    );
    assert_eq!(
        read_attestation_key_owned_by(&scratch.join("absent"), owner).err(),
        Some(KeyFileError::Unreadable)
    );
}

/// A-86 / docs/52 R11 / Q-468: a symbolic link to a valid key file is
/// refused (not a regular file), and so is a key file whose directory is
/// writable by group or others, or reached through a link in a directory
/// component.
#[test]
fn links_and_writable_directories_are_refused() {
    let scratch = ScratchDir::new("keyadm-attestation-walk").unwrap();
    let real = scratch.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = real.join("attestation.key");
    write(&path, &key_octets(), 0o400);
    let owner = std::fs::metadata(&path).unwrap().uid();
    assert!(read_attestation_key_owned_by(&path, owner).is_ok());

    let link = real.join("link.key");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert_eq!(
        read_attestation_key_owned_by(&link, owner).err(),
        Some(KeyFileError::NotRegular)
    );
    std::os::unix::fs::symlink(&real, scratch.join("via")).unwrap();
    assert_eq!(
        read_attestation_key_owned_by(&scratch.join("via/attestation.key"), owner).err(),
        Some(KeyFileError::Path(PathBreak::NotADirectory))
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o757)).unwrap();
    assert_eq!(
        read_attestation_key_owned_by(&path, owner).err(),
        Some(KeyFileError::Path(
            PathBreak::DirectoryWritableByGroupOrOthers
        ))
    );
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(read_attestation_key_owned_by(&path, owner).is_ok());
}

/// docs/CLEAN-ROOM.md / docs/50 §8.2: no refusal carries an octet of the file —
/// the error of a wrong-length file holding a recognisable pattern is a
/// fixed text with none of it.
#[test]
fn no_refusal_shows_the_file() {
    let scratch = ScratchDir::new("keyadm-attestation-text").unwrap();
    let path = scratch.join("attestation.key");
    write(&path, &[0x7B; 31], 0o600);
    let owner = std::fs::metadata(&path).unwrap().uid();
    let error = read_attestation_key_owned_by(&path, owner).err().unwrap();
    for text in [error.to_string(), format!("{error:?}")] {
        assert!(!text.contains("123") && !text.contains("7b") && !text.contains("7B"));
        assert!(!text.contains("31"), "{text}");
    }
}
