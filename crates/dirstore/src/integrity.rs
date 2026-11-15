//! At-rest integrity: an HMAC-SHA-256 tag on every stored record.
//!
//! Construction (this crate's own, built on the approved primitive — no
//! primitive is implemented here, docs/CLEAN-ROOM.md):
//!
//! ```text
//! tag   = HMAC-SHA-256(K, MAC_CONTEXT || kind || u32be(len(key)) || key || body)
//! value = body || tag                      (what is stored under `key`)
//! ```
//!
//! - `kind` binds the tag to the table, so a record cannot be moved between
//!   tables; `key` (length-prefixed, so the key/body split is unambiguous)
//!   binds it to its key, so a record cannot be moved to another object or
//!   name. Spec: docs/32 §3 ("direct change of the KV beneath our interface is
//!   detected"), D135.
//! - Reading verifies the tag **before** anything else, with the `hmac`
//!   crate's constant-time `verify_slice` — never a hand-rolled compare. Only a
//!   verified body is handed to the bounded decoder. Spec: docs/32 §3, §8.
//! - `K` is injected by the caller (keyd will supply it, docs/32 §3: "the key
//!   for integrity verification is managed in keyd/HSM"), held in a zeroizing
//!   container and never printed.
//!
//! Known limit (docs/questions/Q-060): a per-record tag cannot detect the
//! replay of an older, validly tagged version of the same record, nor the
//! removal of a whole set of related records. The same holds for the
//! reverse-link and unique-index tables (docs/46 §8.4-§8.5): a *stale* entry
//! put back is caught by the cross-check against the object it names, but a
//! *removed* entry is noticed only where it is relied on (delete / modify of
//! the value it indexes) — not by a delete of the target, nor by a create
//! that would duplicate a value whose entry vanished. A named counter
//! (docs/51 §8.3) has the same limit: an altered, truncated or moved counter
//! record is [`Error::Tamper`], but an older, validly tagged version of it put
//! back would re-issue values (P-7; Q-330 item 3). For a RID the unique index
//! of objectSid (docs/46 §8.5) still refuses a value held by a live object.

use crate::error::{Error, RecordKind, Result};
use crate::MAX_RECORD_BODY_LEN;
use core::fmt;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Length of the integrity key, in bytes (the SHA-256 output size; HMAC
/// accepts any length, this crate fixes one). Spec: D135.
pub const INTEGRITY_KEY_LEN: usize = 32;

/// Length of the stored tag, in bytes: the full, untruncated HMAC-SHA-256
/// output. Spec: D135.
pub const MAC_LEN: usize = 32;

/// Domain-separation label at the start of every tagged message, so this key
/// can never produce a tag that is valid for another use. Spec: D135; project
/// construction.
const MAC_CONTEXT: &[u8] = b"dirstore.record.v1";

/// The key for the at-rest integrity tag, injected by the caller.
///
/// Held in a [`Zeroizing`] buffer (wiped on drop); `Debug` prints no key
/// bytes; there is no accessor and no `Clone`. Spec: docs/32 §3 (key managed
/// by keyd/HSM), D135; docs/CLEAN-ROOM.md (secrets never in logs).
pub struct IntegrityKey {
    key: Zeroizing<[u8; INTEGRITY_KEY_LEN]>,
}

impl IntegrityKey {
    /// Take a copy of the key. The caller keeps responsibility for wiping its
    /// own copy. Spec: D135.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; INTEGRITY_KEY_LEN]) -> IntegrityKey {
        IntegrityKey {
            key: Zeroizing::new(*bytes),
        }
    }
}

impl fmt::Debug for IntegrityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IntegrityKey(<redacted>)")
    }
}

/// The table-binding byte of the tagged message. Spec: D135 (project
/// construction).
fn kind_tag(kind: RecordKind) -> u8 {
    match kind {
        RecordKind::Meta => 0x01,
        RecordKind::Object => 0x02,
        RecordKind::NameIndex => 0x03,
        RecordKind::ChildCount => 0x04,
        // Spec: docs/46 §8.4 ("tagged with HMAC like name_index, with its
        // own kind"), §8.5.
        RecordKind::BackLink => 0x05,
        RecordKind::UniqueIndex => 0x06,
        // A counter shares the meta table with the store record but has its
        // own kind, so neither can stand in for the other. Spec: docs/51
        // §8.2-§8.3 (A-75: a MAC-tagged record in the meta table); D135.
        RecordKind::Counter => 0x07,
    }
}

/// An HMAC-SHA-256 instance that has absorbed everything but the tag.
fn keyed(
    key: &IntegrityKey,
    kind: RecordKind,
    record_key: &[u8],
    body: &[u8],
) -> Result<Hmac<Sha256>> {
    // HMAC accepts keys of any length; the error arm is mapped, not unwrapped
    // (no panic path).
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key.key[..])
        .map_err(|_| Error::IntegrityKeyUnusable)?;
    // Record keys are bounded far below 4 GiB (16-byte GUIDs, 17 bytes plus
    // an RDN key of at most MAX_RDN_KEY_LEN, 36-byte reverse-link keys, or 4
    // bytes plus a comparison key of at most MAX_VALUE_LEN); refuse rather
    // than wrap.
    let key_len = u32::try_from(record_key.len()).map_err(|_| Error::Tamper(kind))?;
    mac.update(MAC_CONTEXT);
    mac.update(&[kind_tag(kind)]);
    mac.update(&key_len.to_be_bytes());
    mac.update(record_key);
    mac.update(body);
    Ok(mac)
}

/// Append the tag to `body`, giving the value to store under `record_key`.
/// Spec: docs/32 §3, §7 (the tag is written in the same transaction), D135.
pub(crate) fn seal(
    key: &IntegrityKey,
    kind: RecordKind,
    record_key: &[u8],
    mut body: Vec<u8>,
) -> Result<Vec<u8>> {
    let tag = keyed(key, kind, record_key, &body)?.finalize().into_bytes();
    body.extend_from_slice(&tag);
    Ok(body)
}

/// Verify the tag of a stored value and return its body.
///
/// The length is checked first (a value that cannot hold a tag, or is larger
/// than anything this crate writes, is tampered with — and the bound keeps
/// the MAC work bounded); then the tag is verified in constant time. Any
/// failure is [`Error::Tamper`]; the body is returned only after success.
/// Spec: docs/32 §3 (tamper is detected and not taken as ground truth), §8;
/// D135.
pub(crate) fn open<'a>(
    key: &IntegrityKey,
    kind: RecordKind,
    record_key: &[u8],
    stored: &'a [u8],
) -> Result<&'a [u8]> {
    if stored.len() <= MAC_LEN || stored.len() > MAX_RECORD_BODY_LEN + MAC_LEN {
        return Err(Error::Tamper(kind));
    }
    let (body, tag) = stored
        .split_at_checked(stored.len() - MAC_LEN)
        .ok_or(Error::Tamper(kind))?;
    keyed(key, kind, record_key, body)?
        .verify_slice(tag)
        .map_err(|_| Error::Tamper(kind))?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Source: D135 construction above (no external vector exists for it).
    #[test]
    fn seal_then_open_round_trips_and_binds_kind_and_key() {
        let key = IntegrityKey::from_bytes(&[7u8; INTEGRITY_KEY_LEN]);
        let sealed = seal(&key, RecordKind::Object, b"k1", b"body".to_vec()).unwrap();
        assert_eq!(sealed.len(), 4 + MAC_LEN);
        assert_eq!(
            open(&key, RecordKind::Object, b"k1", &sealed).unwrap(),
            b"body"
        );
        assert!(matches!(
            open(&key, RecordKind::Object, b"k2", &sealed),
            Err(Error::Tamper(RecordKind::Object))
        ));
        assert!(matches!(
            open(&key, RecordKind::NameIndex, b"k1", &sealed),
            Err(Error::Tamper(RecordKind::NameIndex))
        ));
        let other = IntegrityKey::from_bytes(&[8u8; INTEGRITY_KEY_LEN]);
        assert!(matches!(
            open(&other, RecordKind::Object, b"k1", &sealed),
            Err(Error::Tamper(RecordKind::Object))
        ));
        assert!(matches!(
            open(&key, RecordKind::Object, b"k1", &sealed[..MAC_LEN]),
            Err(Error::Tamper(RecordKind::Object))
        ));
    }

    #[test]
    fn debug_does_not_print_key_bytes() {
        let key = IntegrityKey::from_bytes(&[0xAB; INTEGRITY_KEY_LEN]);
        let shown = format!("{key:?}");
        assert!(!shown.contains("171") && !shown.to_lowercase().contains("ab,"));
        assert_eq!(shown, "IntegrityKey(<redacted>)");
    }
}
