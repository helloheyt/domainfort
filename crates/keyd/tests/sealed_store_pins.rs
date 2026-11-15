//! Pins between the sealed key store's crypto-free format (keyd-types
//! `sealed_store`, task KL1) and what keyd links (D182: keyd-types does not
//! link the crypto profile), and the public face of the custody backends
//! (task KL2).
//!
//! Source: RFC 3962 §6, §7 and RFC 8009 §2, §5, §7 (the key sizes the
//! format's body lengths follow, as krb-crypto implements them);
//! docs/research/r4-c-key-lifecycle.md §3.2, §3.3, §3.7 steps 1-3, §9.1
//! (C38); docs/50 R50-18. Test-only; no vector from any other
//! implementation.

use keyd::custody_backend::{AnchorReading, INSECURE_DEVELOPMENT_NOTICE, STORE_KEY_OCTETS};
use keyd::{
    probe, CustodyError, CustodyProfile, EncTypeId, InsecureDevelopmentCustody, ProbeError,
};
use keyd_types::sealed_store::{record_key_octets, MAX_KEY_OCTETS};
use keyd_types::StoreId;
use krb_crypto::EncType;

/// The format's key length of each encryption type is the crypto profile's
/// own (RFC 3962 §6, RFC 8009 §5) — the format's body holds exactly the
/// octets `ProtocolKey::octets` gives and `random_to_key` takes back.
#[test]
fn record_key_lengths_equal_the_crypto_profile() {
    for id in EncTypeId::ALL {
        let profile = EncType::from_number(id.number()).expect("one of the four AES types");
        assert_eq!(record_key_octets(id), profile.key_length(), "{id:?}");
        assert!(profile.key_length() <= MAX_KEY_OCTETS);
        let key = krb_crypto::random_to_key(profile, &vec![0x42; profile.key_length()])
            .expect("random-to-key is the identity (RFC 3962 §6, RFC 8009 §5)");
        assert_eq!(key.octets().len(), record_key_octets(id));
    }
    // The store wrapping key is a 256-bit key (r4-a R4A-5).
    assert_eq!(STORE_KEY_OCTETS, 32);
}

/// r4-c §3.7 steps 1-3 through the public API: the development backend runs
/// only under its own profile, announces itself, binds once, and reads
/// Bound — never NeverInitialized — after a re-probe (C38).
#[test]
fn the_development_backend_through_the_public_api() {
    assert_eq!(
        probe(
            InsecureDevelopmentCustody::new_insecure_development(),
            CustodyProfile::Tpm
        )
        .map(|_| ())
        .unwrap_err(),
        ProbeError::ProfileMismatch
    );
    let mut probed = probe(
        InsecureDevelopmentCustody::new_insecure_development(),
        CustodyProfile::InsecureDevelopment,
    )
    .unwrap();
    assert_eq!(probed.notice(), Some(INSECURE_DEVELOPMENT_NOTICE));
    assert_eq!(probed.state(), AnchorReading::NeverInitialized);
    let store = StoreId::from_bytes([7; 16]);
    let evidence = probed.bind_new_store(store).unwrap();
    assert_eq!(evidence.store_id(), store);
    assert!(probed.unseal_store_key().is_ok());
    assert_eq!(probed.advance_anchor(0), Ok(1));
    let mut again = probe(probed.into_backend(), CustodyProfile::InsecureDevelopment).unwrap();
    assert_eq!(
        again.state(),
        AnchorReading::Bound {
            store_id: store,
            generation: 1
        }
    );
    assert_eq!(again.bind_new_store(store), Err(CustodyError::Refused));
}
