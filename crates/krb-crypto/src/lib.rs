#![forbid(unsafe_code)]
//! `krb-crypto`: the Kerberos 5 encryption and checksum profile for the AES
//! encryption types only.
//!
//! # Scope
//!
//! | etype | name                         | cksumtype | definition |
//! |-------|------------------------------|-----------|------------|
//! | 17    | aes128-cts-hmac-sha1-96      | 15        | RFC 3962   |
//! | 18    | aes256-cts-hmac-sha1-96      | 16        | RFC 3962   |
//! | 19    | aes128-cts-hmac-sha256-128   | 19        | RFC 8009   |
//! | 20    | aes256-cts-hmac-sha384-192   | 20        | RFC 8009   |
//!
//! Every other encryption or checksum type number — DES, 3DES, RC4 and the
//! rest — is an error; none of them has a code path (docs/CLEAN-ROOM.md; docs/38
//! §2). The RFC 3961 operations provided are: string-to-key, random-to-key,
//! key derivation for a caller-supplied key usage (Kc / Ke / Ki), encrypt and
//! decrypt with integrity, get_mic / verify_mic, and the pseudo-random
//! function; plus PRF+ and KRB-FX-CF2 (RFC 6113 §5.1), which combine two
//! protocol keys through that pseudo-random function.
//!
//! The raw CBC-CTS functions (E and D without integrity) are crate-private:
//! no unauthenticated encryption or decryption is reachable from outside
//! (minimal surface, docs/25 D104).
//!
//! # Properties
//!
//! - Pure library: no I/O, no global state, and **no randomness** — the
//!   confounder is an explicit caller-supplied parameter, so the owning
//!   component (`keyd`) supplies it from an approved source and tests are
//!   deterministic. Only `keyd` links this crate (compute-don't-give; docs/09,
//!   docs/10).
//! - No cryptographic primitive is implemented here (docs/CLEAN-ROOM.md). AES, SHA-1,
//!   SHA-2, HMAC and PBKDF2 come from approved RustCrypto crates. This crate
//!   composes only the Kerberos-specified constructions: n-fold, DR/DK, the
//!   KDF-HMAC-SHA2 framing, CBC with ciphertext stealing, and the
//!   encrypt-with-integrity layouts.
//! - Integrity and checksum comparisons use the `hmac` crate's verification
//!   facility (constant-time), never a hand-rolled loop, and always require
//!   the exact truncated length h.
//! - Key material is zeroized on drop and never printed: key types have a
//!   redacted `Debug`, no `Display`, and no `PartialEq`. Errors carry no data.
//! - Fail closed: malformed input, a bad length, or an integrity failure is a
//!   distinct [`Error`]; no operation panics on any input.
//! - Only the initial cipher state (all bits zero) is used; cipher-state
//!   chaining between messages is not offered.
//!
//! # Provenance
//!
//! Written only from the allowed specifications, opened in-session
//! (docs/CLEAN-ROOM.md): RFC 3961 (framework, n-fold, simplified profile, DK/DR),
//! RFC 3962 (AES with HMAC-SHA1, PBKDF2 string-to-key, ciphertext stealing),
//! RFC 8009 (AES with HMAC-SHA2, KDF-HMAC-SHA2), RFC 2040 §8 (the
//! ciphertext-stealing steps RFC 3962 §5 references, with the errata of
//! RFC 3962 Appendix A), and RFC 6113 §5.1 / Appendix A (PRF+, KRB-FX-CF2 and
//! the AES pseudo-random interpretation). No other implementation was
//! consulted or recalled.
//!
//! Spec: RFC 3961 §3, §4, §5.1-5.4; RFC 3962 §3-7, App. A; RFC 8009 §2-7;
//! RFC 2040 §8; RFC 6113 §5.1, App. A.

mod cts;
mod error;
mod key;
mod mac;
mod nfold;
mod profile;
mod sha2_profile;
mod simplified;
mod types;

pub use error::{Error, Result};
pub use key::{ProtocolKey, SpecificKey};
pub use nfold::{n_fold, N_FOLD_MAX_OCTETS};
pub use profile::{
    decrypt, derive_key, encrypt, get_mic, iteration_count, krb_fx_cf2, pseudo_random,
    random_to_key, string_to_key, verify_mic,
};
pub use types::{ChecksumType, EncType, KeyUsage, SpecificKeyKind, CONFOUNDER_LENGTH};
