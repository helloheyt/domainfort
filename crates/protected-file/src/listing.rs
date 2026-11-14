//! The entries of the directory a file path lies in, read through the
//! walked, checked directory's own descriptor (task R11b; docs/questions
//! Q-481 item b; Q-530): auditd finds its log segments by listing the
//! directory of `audit_log_path`, and that listing must be of the directory
//! the walk checked — not of whatever a link in a directory component
//! would lead a path-based listing to.
//!
//! Spec: docs/52 §3.13 (C13), §7 R11; Q-468 options 1, 2(b), 3 (A-102);
//! rustix docs.rs `fs::Dir::read_from` ("Borrow `fd` and construct a `Dir`
//! that reads entries from the given directory file descriptor"),
//! `fs::Dir::read` ("`readdir(self)`, where `None` means the end of the
//! directory"), `fs::DirEntry::file_name` ("Returns the file name of this
//! directory entry"), `fs::statat` with `AtFlags::SYMLINK_NOFOLLOW`.

use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{AtFlags, Dir};

use crate::{absolute, system, walk, FileFacts, OpenError};

/// The names `.` and `..`, which every directory lists and which name no
/// entry of its own. Spec: Q-482 item 5 (`.` and `..` are walked as names;
/// here they are not entries).
const SELF_AND_PARENT: [&[u8]; 2] = [b".", b".."];

/// Walk the path from `/` under the directory rule (with `file_owner_uid`
/// as the owner of the files in the directory), then call `visit` with the
/// name and the facts of every entry of the directory the file path `path`
/// lies in — `.` and `..` apart — in the order the directory gives them.
/// The facts are taken without following a link (a link's facts are a
/// link's, never a regular file's), relative to the walked directory. The
/// file `path` names need not exist; nothing is opened but directories.
///
/// # Errors
/// [`OpenError::Path`] when the path does not end in a file name or a
/// directory breaks the directory rule; [`OpenError::Io`] when a directory
/// cannot be read or an entry inspected (one removed while listing
/// included); [`OpenError::Refused`] with `visit`'s first error, which ends
/// the listing.
///
/// Spec: this module's documentation.
pub fn for_each_entry_beside<E>(
    path: &Path,
    file_owner_uid: u32,
    mut visit: impl FnMut(&[u8], &FileFacts) -> Result<(), E>,
) -> Result<(), OpenError<E>> {
    let absolute = absolute(path).map_err(|error| OpenError::Io(error.kind()))?;
    let (directory, _name) = walk(absolute.as_os_str().as_bytes(), file_owner_uid)?;
    let mut entries = Dir::read_from(&directory).map_err(system)?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(system)?;
        let name = entry.file_name().to_bytes();
        if SELF_AND_PARENT.contains(&name) {
            continue;
        }
        let seen =
            rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(system)?;
        visit(name, &FileFacts::of(&seen)).map_err(OpenError::Refused)?;
    }
    Ok(())
}
