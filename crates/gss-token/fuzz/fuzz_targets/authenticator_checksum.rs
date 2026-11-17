#![no_main]
//! Fuzz target for the RFC 4121 §4.1.1 authenticator checksum parser.
//!
//! docs/CLEAN-ROOM.md / docs/60 §10 LG1. Arbitrary bytes are parsed as the
//! `checksum` octets of a `cksum` of type 0x8003 (and of another type): the
//! parser must never panic or hang. An accepted checksum had the right type,
//! at least 24 octets, DELEG clear, INTEG and MUTUAL set, and a non-zero Bnd
//! taken from octets 4..19. The same property runs deterministically in
//! `tests/robustness.rs`.
//!
//! Spec: RFC 4121 §4.1.1, §4.1.1.1, §4.1.1.2; docs/60 §3.4 step 4.

use gss_token::{AuthenticatorChecksum, ChecksumField, GSS_CHECKSUM_TYPE};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for cksumtype in [GSS_CHECKSUM_TYPE, 0] {
        let field = ChecksumField {
            cksumtype,
            checksum: data,
        };
        if let Ok(accepted) = AuthenticatorChecksum::from_authenticator(Some(field), Some(1)) {
            assert_eq!(cksumtype, GSS_CHECKSUM_TYPE, "only type 0x8003");
            assert!(data.len() >= 24, "at least 24 octets");
            let flags = accepted.flags();
            assert!(!flags.deleg() && flags.integ() && flags.mutual());
            assert_ne!(accepted.bnd().octets(), &[0u8; 16], "Bnd carries a binding");
            assert_eq!(
                &accepted.bnd().octets()[..],
                &data[4..20],
                "Bnd is octets 4..19"
            );
        }
    }
});
