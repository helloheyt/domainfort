#![no_main]
//! Fuzz target for `krb_crypto::verify_mic`.
//!
//! docs/CLEAN-ROOM.md requires a fuzz target for code that consumes untrusted input
//! before it merges to `main`. The input is split as:
//!
//! ```text
//! [0]          selects the checksum type (15, 16, 19, 20 by value mod 4)
//! [1]          MIC length to take (any value; mismatches must be rejected)
//! [2..6]       key usage, big-endian u32 (zero is rejected by KeyUsage::new)
//! [6..6+K]     the protocol key of the associated encryption type
//! [6+K..6+K+L] the MIC token (L from byte [1], clamped to what is present)
//! [rest]       the message
//! ```
//!
//! `verify_mic` must never panic: a MIC of the wrong length is
//! `InvalidChecksumLength`, a mismatch is `ChecksumVerificationFailed`
//! (RFC 3961 §4, §5.4; RFC 3962 §6, §7; RFC 8009 §6). A MIC freshly computed
//! by `get_mic` over the same input must always verify.

use krb_crypto::{get_mic, random_to_key, verify_mic, ChecksumType, KeyUsage};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 6 {
        return;
    }
    let cksumtype = match data[0] % 4 {
        0 => ChecksumType::HmacSha196Aes128,
        1 => ChecksumType::HmacSha196Aes256,
        2 => ChecksumType::HmacSha256128Aes128,
        _ => ChecksumType::HmacSha384192Aes256,
    };
    let enc_type = cksumtype.enc_type();
    let mic_len_wanted = usize::from(data[1]);
    let usage_number = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
    let rest = &data[6..];
    if rest.len() < enc_type.key_length() {
        return;
    }
    let (key_octets, rest) = rest.split_at(enc_type.key_length());
    let mic_len = mic_len_wanted.min(rest.len());
    let (mic, message) = rest.split_at(mic_len);

    let Ok(usage) = KeyUsage::new(usage_number) else {
        return;
    };
    let key = random_to_key(enc_type, key_octets).expect("key length was selected to match");

    // Arbitrary MIC: must return an error or Ok, never panic.
    let _ = verify_mic(&key, cksumtype, usage, message, mic);

    // A genuine MIC must verify.
    let genuine = get_mic(&key, cksumtype, usage, message).expect("associated checksum type");
    assert!(verify_mic(&key, cksumtype, usage, message, &genuine).is_ok());
});
