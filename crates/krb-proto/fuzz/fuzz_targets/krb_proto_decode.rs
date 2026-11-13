#![no_main]
//! Fuzz target for the typed Kerberos message decoders.
//!
//! AGENTS.md §6 / docs/32 §8 require a fuzz target for every parser before it
//! merges to `main`. Arbitrary bytes are fed to the `decode` of every top-level
//! message and every structure that is decoded on its own (decrypted parts,
//! padata values, e-data): none may panic, hang, or over-allocate — each fails
//! closed with a `krb_proto::Error`. When a decoder *does* accept the input,
//! decoding is lossless, so re-encoding must reproduce the exact bytes
//! (RFC 4120 5.1.1 / X.690 clause 10: DER is a single canonical encoding).
//!
//! Spec: RFC 4120 §5, Appendix A; X.690 clauses 8, 10, 11.

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
    // Top-level messages (RFC 4120 5.10 PDUs in scope).
    check!(krb_proto::KdcRequest, data);
    check!(krb_proto::AsReq, data);
    check!(krb_proto::TgsReq, data);
    check!(krb_proto::AsRep, data);
    check!(krb_proto::TgsRep, data);
    check!(krb_proto::ApReq, data);
    check!(krb_proto::ApRep, data);
    check!(krb_proto::KrbError, data);
    check!(krb_proto::Ticket, data);
    // Decrypted parts (keyd decodes these after decryption).
    check!(krb_proto::EncTicketPart, data);
    check!(krb_proto::EncAsRepPart, data);
    check!(krb_proto::EncTgsRepPart, data);
    check!(krb_proto::Authenticator, data);
    check!(krb_proto::EncApRepPart, data);
    // Typed-hole contents decoded on their own.
    check!(krb_proto::PaEncTsEnc, data);
    check!(krb_proto::EtypeInfo2, data);
    check!(krb_proto::MethodData, data);
    check!(krb_proto::AuthorizationData, data);
    check!(krb_proto::KdcReqBody, data);
    check!(krb_proto::EncryptedData, data);
    check!(krb_proto::EncryptionKey, data);
});
