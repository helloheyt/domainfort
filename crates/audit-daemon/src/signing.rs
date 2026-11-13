//! The chain-head signing hook, in its only phase-1 mode: **unsigned**.
//!
//! docs/37 §2 wants each DC to sign its segment with a key held in an HSM
//! (D157). Who holds that key, what is signed and how often is undecided
//! (docs/questions/Q-251 → owner item P-20); the decision in force is
//! "unsigned chain + an external checkpoint". So this module wires
//! crates/audit-log's [`HeadSigner`] trait with a signer that signs nothing,
//! behind a mode whose name says so, and the daemon prints that mode at start.
//! No key is invented, read or generated here.
//!
//! The writer calls the hook with the persisted head after start-up and after
//! every rotation (the cadence Q-251 recommends: "a signature at every
//! rotation"); in this mode each call returns [`NoSignature`] and nothing is
//! stored. When P-20 is decided, a real signer takes this place.
//!
//! Spec: docs/37 §2, §7, D157; docs/questions/Q-218 item 2 (A-57),
//! Q-251 (P-20); crates/audit-log `HeadSigner`, `LogWriter::sign_head`.

use audit_log::{ChainHead, HeadSigner};
use core::convert::Infallible;

/// How chain heads are signed. Phase 1 has exactly one mode.
///
/// Spec: docs/questions/Q-251 (P-20 undecided: "unsigned chain + an
/// external checkpoint").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningMode {
    /// Heads are not signed. A change to the last record, or a cut at a
    /// record boundary, is detectable only against a head held elsewhere
    /// (docs/questions/Q-250 item 10).
    Unsigned,
}

impl SigningMode {
    /// The fixed start-up line that names the mode (stderr).
    ///
    /// Spec: task P6b ("a clearly named 'unsigned' mode logged at startup");
    /// docs/50 §8.2 (fixed texts).
    #[must_use]
    pub const fn startup_notice(self) -> &'static str {
        match self {
            SigningMode::Unsigned => {
                "audit-daemon: chain-head signing: UNSIGNED mode (owner item P-20 undecided); \
                 keep an off-box checkpoint of the chain head"
            }
        }
    }
}

/// The result of signing in [`SigningMode::Unsigned`]: no signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoSignature;

/// The [`HeadSigner`] of [`SigningMode::Unsigned`]: signs nothing.
///
/// Spec: docs/questions/Q-251 (P-20); crates/audit-log `HeadSigner`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnsignedHeads;

impl HeadSigner for UnsignedHeads {
    type Signature = NoSignature;
    type Error = Infallible;

    fn sign_head(&mut self, _head: &ChainHead) -> Result<NoSignature, Infallible> {
        Ok(NoSignature)
    }
}
