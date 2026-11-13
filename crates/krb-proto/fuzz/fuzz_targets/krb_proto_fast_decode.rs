#![no_main]
//! Fuzz target for the RFC 6113 FAST decoders.
//!
//! AGENTS.md §6 / docs/32 §8 require a fuzz target for every parser before it
//! merges to `main`. Arbitrary bytes are fed to the `decode` of every FAST
//! type that is decoded on its own: the PA-FX-FAST padata values
//! (PA-FX-FAST-REQUEST, PA-FX-FAST-REPLY), the decrypted inner messages
//! (KrbFastReq, KrbFastResponse) and their components. None may panic, hang,
//! or over-allocate — each fails closed with a `krb_proto::Error`. When a
//! decoder accepts the input, decoding is lossless, so re-encoding must
//! reproduce the exact bytes (RFC 4120 5.1.1 / X.690 clause 10).
//!
//! Spec: RFC 6113 5.4, Appendix B; X.690 clauses 8, 10.

use libfuzzer_sys::fuzz_target;

/// Decode with `$ty::decode`; if accepted, `encode` must reproduce `$data`.
macro_rules! check {
    ($ty:ty, $data:expr) => {
        if let Ok(value) = <$ty>::decode($data) {
            let reencoded = value
                .encode()
                .expect("re-encoding an accepted value must succeed");
            assert_eq!(
                AsRef::<[u8]>::as_ref(&reencoded),
                $data,
                "decode then encode must reproduce the accepted input"
            );
        }
    };
}

fuzz_target!(|data: &[u8]| {
    // PA-FX-FAST padata values (RFC 6113 5.4.2, 5.4.3).
    check!(krb_proto::PaFxFastRequest, data);
    check!(krb_proto::PaFxFastReply, data);
    // Decrypted inner messages (keyd decodes these after decryption).
    check!(krb_proto::KrbFastReq, data);
    check!(krb_proto::KrbFastResponse, data);
    // Components decoded on their own.
    check!(krb_proto::KrbFastArmoredReq, data);
    check!(krb_proto::KrbFastArmoredRep, data);
    check!(krb_proto::KrbFastArmor, data);
    check!(krb_proto::KrbFastFinished, data);
});
