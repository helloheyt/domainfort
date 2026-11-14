//! The command line:
//!
//! ```text
//! keyadm <configuration file> ceremony <manifest file>
//! keyadm <configuration file> rotate-krbtgt <decision id>
//! keyadm <configuration file> rotate-key <decision id>
//! keyadm <configuration file> retire-kvno <decision id>
//! keyadm <configuration file> destroy-sweep
//! ```
//!
//! The configuration file comes first, as every daemon of this project takes
//! its configuration path as its argument (crates/keyd-daemon
//! `keyd-daemon <configuration file>`); then the command and its operand
//! (docs/51 §6: `ceremony <manifest>`, `rotate-key`, `rotate-krbtgt`,
//! `retire-kvno`, `destroy-sweep`). The three commands that run a key
//! operation name dird's **decision** by its id — the request id the
//! `Approve` reply shows, under which dird registered the decision in keyd
//! (A-102, docs/52 §4.2). The operation itself (which key set, which kvno,
//! which approvers) is the one keyd holds under that id, never anything on
//! the command line. The
//! command is matched exactly; there are no options. No secret is ever an
//! argument (docs/51 §3, citing D95: "no secrets in argv/env") — keyadm has
//! none.
//!
//! A decision id is written in decimal: digits only, no sign, no leading
//! zero (one spelling per value), at most a `u64`.
//!
//! Spec: docs/51 §3 (D95), §6, §12 (A5, A10); docs/50 §7.1; docs/52 §4.2.

use std::ffi::OsString;
use std::path::PathBuf;

/// The usage lines.
pub const USAGE: &str = "usage: keyadm <configuration file> ceremony <manifest file>\n       keyadm <configuration file> rotate-krbtgt|rotate-key|retire-kvno <decision id>\n       keyadm <configuration file> destroy-sweep";

/// The command name of the ceremony. Spec: docs/51 §6.
pub const CEREMONY: &str = "ceremony";
/// `rotate-krbtgt`. Spec: docs/51 §6.
pub const ROTATE_KRBTGT: &str = "rotate-krbtgt";
/// `rotate-key`. Spec: docs/51 §6.
pub const ROTATE_KEY: &str = "rotate-key";
/// `retire-kvno`. Spec: docs/51 §6.
pub const RETIRE_KVNO: &str = "retire-kvno";
/// `destroy-sweep`. Spec: docs/51 §6.
pub const DESTROY_SWEEP: &str = "destroy-sweep";

/// The key operation a decision command runs.
/// Spec: docs/51 §6 (the table: "approved request (dual)"); docs/52 §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approved {
    /// `rotate-krbtgt`: `rotate_krbtgt(decision)`.
    RotateKrbtgt,
    /// `rotate-key`: `rotate_key(decision)`.
    RotateKey,
    /// `retire-kvno`: `retire_kvno(decision)`.
    RetireKvno,
}

impl Approved {
    /// The command's name. Spec: docs/51 §6.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Approved::RotateKrbtgt => ROTATE_KRBTGT,
            Approved::RotateKey => ROTATE_KEY,
            Approved::RetireKvno => RETIRE_KVNO,
        }
    }
}

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
    /// `rotate-krbtgt` / `rotate-key` / `retire-kvno <decision id>`: run
    /// dird's decision. Spec: docs/51 §6; docs/52 §4.2.
    Execute {
        /// keyadm's configuration file.
        config: PathBuf,
        /// Which operation the operator means to run.
        command: Approved,
        /// dird's decision id (the approved request's id).
        id: u64,
    },
    /// `destroy-sweep`: run the destroy decisions dird registered.
    /// Spec: docs/51 §6, §9; docs/52 §4.3.
    DestroySweep {
        /// keyadm's configuration file.
        config: PathBuf,
    },
}

/// The command line was not one of the forms of [`USAGE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageError;

/// A decision id: decimal digits, no sign, no leading zero, within `u64`.
/// Spec: module documentation (one spelling per value, docs/50 §7.1's rule
/// for integers).
fn request_id(text: &OsString) -> Result<u64, UsageError> {
    let text = text.to_str().ok_or(UsageError)?;
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(UsageError);
    }
    text.parse::<u64>().map_err(|_| UsageError)
}

/// Parse the arguments after the program name.
///
/// # Errors
/// [`UsageError`] unless the arguments are exactly one of the forms of
/// [`USAGE`].
///
/// Spec: docs/51 §6.
pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<Command, UsageError> {
    let args: Vec<OsString> = args.into_iter().take(4).collect();
    match args.as_slice() {
        [config, command, manifest] if command == CEREMONY => Ok(Command::Ceremony {
            config: PathBuf::from(config),
            manifest: PathBuf::from(manifest),
        }),
        [config, command, id] => {
            let command = if command == ROTATE_KRBTGT {
                Approved::RotateKrbtgt
            } else if command == ROTATE_KEY {
                Approved::RotateKey
            } else if command == RETIRE_KVNO {
                Approved::RetireKvno
            } else {
                return Err(UsageError);
            };
            Ok(Command::Execute {
                config: PathBuf::from(config),
                command,
                id: request_id(id)?,
            })
        }
        [config, command] if command == DESTROY_SWEEP => Ok(Command::DestroySweep {
            config: PathBuf::from(config),
        }),
        _ => Err(UsageError),
    }
}
