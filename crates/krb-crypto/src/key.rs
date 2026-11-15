//! Key types: the protocol key (base key) and the specific keys derived from
//! it.
//!
//! Security (docs/CLEAN-ROOM.md):
//! - Key octets live in a fixed-size buffer (no reallocation can leave stray
//!   copies) and are zeroized when the value is dropped.
//! - `Debug` prints only the encryption type / key kind and the length — never
//!   key octets. There is no `Display`, no `Clone`, and no `PartialEq` (a
//!   non-constant-time comparison of key material would be a timing leak).
//! - Access to the octets is a single, explicitly named method, so every
//!   place that touches raw key material is easy to audit.

use crate::types::{EncType, SpecificKeyKind};
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Largest key this crate holds: a 256-bit AES key.
/// Spec: RFC 3962 §6 (128- or 256-bit string); RFC 8009 §2, §5 (Ke is at most
/// 256 bits; Kc/Ki at most 192 bits).
pub(crate) const MAX_KEY_LENGTH: usize = 32;

/// Fixed-capacity secret octet buffer, zeroized on drop.
struct SecretOctets {
    buf: [u8; MAX_KEY_LENGTH],
    len: usize,
}

impl SecretOctets {
    /// Copy `octets` into a new buffer. An input longer than
    /// `MAX_KEY_LENGTH` is rejected with `None` (never truncated, never a
    /// panic).
    fn new(octets: &[u8]) -> Option<Self> {
        if octets.len() > MAX_KEY_LENGTH {
            return None;
        }
        let mut buf = [0u8; MAX_KEY_LENGTH];
        buf[..octets.len()].copy_from_slice(octets);
        Some(SecretOctets {
            buf,
            len: octets.len(),
        })
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl Drop for SecretOctets {
    fn drop(&mut self) {
        self.buf.zeroize();
        self.len = 0;
    }
}

impl ZeroizeOnDrop for SecretOctets {}

/// A protocol key ("base key") of one of the AES encryption types.
///
/// The AES key space is dense, so any octet string of the right length is a
/// valid key, used directly as the AES key and as the key-derivation input.
/// Spec: RFC 3961 §3 ("protocol key format"); RFC 3962 §3; RFC 8009 §2.
pub struct ProtocolKey {
    enc_type: EncType,
    octets: SecretOctets,
}

impl ProtocolKey {
    /// Build a protocol key from octets whose length is already checked
    /// against `enc_type.key_length()`.
    pub(crate) fn from_checked(enc_type: EncType, octets: &[u8]) -> Option<Self> {
        if octets.len() != enc_type.key_length() {
            return None;
        }
        Some(ProtocolKey {
            enc_type,
            octets: SecretOctets::new(octets)?,
        })
    }

    /// The encryption type this key belongs to.
    pub fn enc_type(&self) -> EncType {
        self.enc_type
    }

    /// The raw key octets (the protocol key format of RFC 3962 §3 /
    /// RFC 8009 §2).
    ///
    /// SECURITY: this exposes long-term secret material. It exists so the
    /// owning component (`keyd`) can persist a key it generated; it must never
    /// be logged, returned over an interface, or compared with `==`
    /// (compute-don't-give, docs/10).
    pub fn octets(&self) -> &[u8] {
        self.octets.as_slice()
    }
}

impl fmt::Debug for ProtocolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolKey")
            .field("enc_type", &self.enc_type)
            .field("octets", &"<redacted>")
            .finish()
    }
}

impl ZeroizeOnDrop for ProtocolKey {}

/// One of the specific keys (Kc, Ke or Ki) derived from a protocol key for a
/// given key usage.
///
/// Spec: RFC 3961 §2 ("specific key"), §5.3; RFC 8009 §5.
pub struct SpecificKey {
    kind: SpecificKeyKind,
    octets: SecretOctets,
}

impl SpecificKey {
    pub(crate) fn from_octets(kind: SpecificKeyKind, octets: &[u8]) -> Option<Self> {
        Some(SpecificKey {
            kind,
            octets: SecretOctets::new(octets)?,
        })
    }

    /// Which specific key this is.
    pub fn kind(&self) -> SpecificKeyKind {
        self.kind
    }

    /// The raw derived key octets.
    ///
    /// SECURITY: secret material — never log it, never return it over an
    /// interface, never compare it with `==` (docs/10).
    pub fn octets(&self) -> &[u8] {
        self.octets.as_slice()
    }
}

impl fmt::Debug for SpecificKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpecificKey")
            .field("kind", &self.kind)
            .field("octets", &"<redacted>")
            .finish()
    }
}

impl ZeroizeOnDrop for SpecificKey {}
