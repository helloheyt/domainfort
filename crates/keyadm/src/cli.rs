//! The command line: `keyadm <configuration file> ceremony <manifest file>`.
//!
//! The configuration file comes first, as every daemon of this project takes
//! its configuration path as its argument (crates/keyd-daemon
//! `keyd-daemon <configuration file>`); then the command and its operand
//! (docs/51 §6: `ceremony <manifest>`). Exactly three arguments; the command
//! is matched exactly; there are no options. No secret is ever an argument
//! (docs/51 §3, citing D95: "no secrets in argv/env") — keyadm has none.
//!
//! This task builds `ceremony` only. `destroy-sweep`, `rotate-key`,
//! `rotate-krbtgt` and `retire-kvno` (docs/51 §6) come with tasks A9 / A10
//! and have no code path yet: any other command is a usage error.
//!
//! Spec: docs/51 §3 (D95), §6, §12 (A5, A9, A10); docs/50 §7.1.

use std::ffi::OsString;
use std::path::PathBuf;

/// The usage line.
pub const USAGE: &str = "usage: keyadm <configuration file> ceremony <manifest file>";

/// The command name of the ceremony. Spec: docs/51 §6.
pub const CEREMONY: &str = "ceremony";

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `ceremony`: create the manifest's krbtgt and service key sets.
    /// Spec: docs/51 §4.3 step 11, §6.
    Ceremony {
        /// keyadm's configuration file.
        config: PathBuf,
        /// The provisioning manifest.
        manifest: PathBuf,
    },
}

/// The command line was not `<configuration file> ceremony <manifest file>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageError;

/// Parse the arguments after the program name.
///
/// # Errors
/// [`UsageError`] unless there are exactly three arguments with `ceremony`
/// in the middle.
///
/// Spec: docs/51 §6.
pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<Command, UsageError> {
    let mut args = args.into_iter();
    match (args.next(), args.next(), args.next(), args.next()) {
        (Some(config), Some(command), Some(manifest), None) if command == CEREMONY => {
            Ok(Command::Ceremony {
                config: PathBuf::from(config),
                manifest: PathBuf::from(manifest),
            })
        }
        _ => Err(UsageError),
    }
}
