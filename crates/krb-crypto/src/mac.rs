//! HMAC over the hash functions the AES encryption types use, through the
//! approved `hmac`, `sha1` and `sha2` crates (docs/CLEAN-ROOM.md: no primitive is
//! implemented here).
//!
//! Spec: RFC 3962 §6 (H = SHA-1); RFC 8009 §5 (HMAC-SHA-256 for
//! aes128-cts-hmac-sha256-128, HMAC-SHA-384 for aes256-cts-hmac-sha384-192);
//! HMAC itself per RFC 2104 as cited by RFC 3961 §5.2 and RFC 8009 §1.

use crate::error::{Error, Result};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use zeroize::Zeroizing;

/// The hash function H inside the HMAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashAlg {
    /// SHA-1. Spec: RFC 3962 §6.
    Sha1,
    /// SHA-256. Spec: RFC 8009 §3, §5.
    Sha256,
    /// SHA-384. Spec: RFC 8009 §3, §5.
    Sha384,
}

fn keyed<M: Mac + KeyInit>(key: &[u8], parts: &[&[u8]]) -> Result<M> {
    // HMAC accepts keys of any length; the error arm is unreachable in
    // practice but is mapped rather than unwrapped (no panic path).
    let mut m = <M as KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    for part in parts {
        m.update(part);
    }
    Ok(m)
}

/// HMAC(key, part_1 | part_2 | ...), full output. The output may be key
/// material (KDF-HMAC-SHA2's K1), so it is returned in a zeroizing buffer.
pub(crate) fn hmac(alg: HashAlg, key: &[u8], parts: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>> {
    let out = match alg {
        HashAlg::Sha1 => keyed::<Hmac<Sha1>>(key, parts)?
            .finalize()
            .into_bytes()
            .to_vec(),
        HashAlg::Sha256 => keyed::<Hmac<Sha256>>(key, parts)?
            .finalize()
            .into_bytes()
            .to_vec(),
        HashAlg::Sha384 => keyed::<Hmac<Sha384>>(key, parts)?
            .finalize()
            .into_bytes()
            .to_vec(),
    };
    Ok(Zeroizing::new(out))
}

/// Check `tag` against the leading `tag.len()` octets of
/// HMAC(key, part_1 | part_2 | ...), i.e. HMAC(...)[1..h] in RFC notation.
///
/// The comparison is the approved library facility (`Mac::
/// verify_truncated_left` over the `hmac` crate's constant-time output
/// type), never a hand-rolled loop. Callers MUST first check that
/// `tag.len()` is exactly the h of the encryption/checksum type: the library
/// accepts any non-empty truncation, and a shorter tag would weaken the
/// check.
///
/// Returns `Ok(true)` on match, `Ok(false)` on mismatch.
pub(crate) fn verify_truncated(
    alg: HashAlg,
    key: &[u8],
    parts: &[&[u8]],
    tag: &[u8],
) -> Result<bool> {
    let ok = match alg {
        HashAlg::Sha1 => keyed::<Hmac<Sha1>>(key, parts)?
            .verify_truncated_left(tag)
            .is_ok(),
        HashAlg::Sha256 => keyed::<Hmac<Sha256>>(key, parts)?
            .verify_truncated_left(tag)
            .is_ok(),
        HashAlg::Sha384 => keyed::<Hmac<Sha384>>(key, parts)?
            .verify_truncated_left(tag)
            .is_ok(),
    };
    Ok(ok)
}
