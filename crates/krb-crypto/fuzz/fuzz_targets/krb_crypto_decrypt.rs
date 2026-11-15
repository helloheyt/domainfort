#![no_main]
//! Fuzz target for `krb_crypto::decrypt`.
//!
//! docs/CLEAN-ROOM.md requires a fuzz target for code that consumes untrusted input
//! before it merges to `main`. The input is split as:
//!
//! ```text
//! [0]        selects the encryption type (17, 18, 19, 20 by value mod 4)
//! [1..5]     key usage, big-endian u32 (zero is rejected by KeyUsage::new)
//! [5..5+K]   the protocol key (K = 16 or 32 octets)
//! [5+K..]    the ciphertext
//! ```
//!
//! `decrypt` must never panic, hang, or over-allocate on any of it: a short
//! ciphertext is `CiphertextTooShort`, anything else that is not a genuine
//! encryption is `IntegrityCheckFailed` (RFC 3961 §3, §5.3; RFC 8009 §5).
//! Random input essentially never forges the HMAC; if an `Ok` ever occurs,
//! its length is checked (confounder and HMAC stripped, no padding added).
//!
//! Spec: RFC 3961 §3 (decrypt), §5.3; RFC 3962 §6; RFC 8009 §5.

use krb_crypto::{decrypt, random_to_key, EncType, KeyUsage, CONFOUNDER_LENGTH};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let enc_type = match selector % 4 {
        0 => EncType::Aes128CtsHmacSha196,
        1 => EncType::Aes256CtsHmacSha196,
        2 => EncType::Aes128CtsHmacSha256128,
        _ => EncType::Aes256CtsHmacSha384192,
    };
    if rest.len() < 4 + enc_type.key_length() {
        return;
    }
    let (usage_octets, rest) = rest.split_at(4);
    let (key_octets, ciphertext) = rest.split_at(enc_type.key_length());

    let usage_number = u32::from_be_bytes([
        usage_octets[0],
        usage_octets[1],
        usage_octets[2],
        usage_octets[3],
    ]);
    let Ok(usage) = KeyUsage::new(usage_number) else {
        return;
    };
    let key = random_to_key(enc_type, key_octets).expect("key length was selected to match");

    if let Ok(plaintext) = decrypt(&key, usage, ciphertext) {
        // A successful decrypt returns exactly the ciphertext minus the
        // confounder and the truncated HMAC (CTS adds no padding).
        assert_eq!(
            plaintext.len() + CONFOUNDER_LENGTH + enc_type.hmac_length(),
            ciphertext.len()
        );
    }
});
