//! The hook for signing the chain head. No signing scheme is defined here.
//!
//! docs/37 §2 requires that "each DC signs its segment (signing key in an
//! HSM)" (D157). Phase 1 has no HSM (docs/questions/Q-212), and who holds the
//! signing key — keyd, a tier-0 tool, an HSM partition — is a design decision
//! that has not been taken (docs/questions/Q-251). So this crate fixes only
//! **what** is signed — a persisted [`ChainHead`] (sequence number and
//! hash) — and leaves the algorithm, the key, the signature's encoding and
//! where signatures are kept to the implementor chosen by that decision.
//!
//! Signing a head vouches for every record up to it: the chain links each
//! record to its predecessor, so a valid signature over `(seq, hash)` lets a
//! verifier pass it as the `checkpoint` of [`crate::verify_segment`] /
//! [`crate::verify_log`] and detect a cut tail or an altered last record
//! (which the chain alone cannot show).
//!
//! Spec: docs/37 §2, §7 ("the signing key in an HSM"), D157;
//! docs/questions/Q-218 item 2 ("unsigned hash-chain in phase 1 + anchoring
//! the chain head (after Q-212)"), Q-251.

use crate::format::ChainHead;

/// Signs a persisted chain head. Implemented by whatever holds the signing
/// key, once its custody is decided (docs/questions/Q-251).
///
/// [`crate::LogWriter::sign_head`] calls this only with the head of the
/// synced chain, never with records that are not yet on stable storage.
///
/// Spec: docs/37 §2, D157; docs/questions/Q-251.
pub trait HeadSigner {
    /// The signature (its encoding is the implementor's).
    type Signature;
    /// Why signing failed.
    type Error;

    /// Sign `head`.
    ///
    /// # Errors
    /// The implementor's (for example, the key holder is unavailable).
    fn sign_head(&mut self, head: &ChainHead) -> Result<Self::Signature, Self::Error>;
}
