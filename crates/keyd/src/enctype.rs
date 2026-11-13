//! The bridge between the crypto-free encryption-type identifier of keyd's
//! interface ([`EncTypeId`], keyd-types) and the crypto profile's own type
//! (`krb_crypto::EncType`), which only keyd links (D182; decision A-63).
//!
//! Both are closed tables of the same four AES types; the conversion is a
//! total match in each direction, so no identifier can name a type the
//! profile does not implement, and the tests below pin the two tables to
//! each other number for number — and keyd-types' string-to-key iteration
//! rule (used by `KeydConfig::validate`) to the profile's
//! `iteration_count`.
//!
//! Spec: RFC 3962 §4, §7; RFC 8009 §4, §7; RFC 3961 §8; docs/10 §12 I5;
//! D182; A-63.

use keyd_types::EncTypeId;
use krb_crypto::EncType;

/// The profile's type for a configured identifier. Spec: RFC 3962 §7; RFC
/// 8009 §7; A-63.
pub(crate) const fn to_crypto(id: EncTypeId) -> EncType {
    match id {
        EncTypeId::Aes128CtsHmacSha196 => EncType::Aes128CtsHmacSha196,
        EncTypeId::Aes256CtsHmacSha196 => EncType::Aes256CtsHmacSha196,
        EncTypeId::Aes128CtsHmacSha256128 => EncType::Aes128CtsHmacSha256128,
        EncTypeId::Aes256CtsHmacSha384192 => EncType::Aes256CtsHmacSha384192,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyd_types::{ConfigError, KeydConfig};
    use krb_proto::Realm;

    /// The identity map from the profile's side, for the pin below.
    fn to_id(enctype: EncType) -> EncTypeId {
        match enctype {
            EncType::Aes128CtsHmacSha196 => EncTypeId::Aes128CtsHmacSha196,
            EncType::Aes256CtsHmacSha196 => EncTypeId::Aes256CtsHmacSha196,
            EncType::Aes128CtsHmacSha256128 => EncTypeId::Aes128CtsHmacSha256128,
            EncType::Aes256CtsHmacSha384192 => EncTypeId::Aes256CtsHmacSha384192,
        }
    }

    /// A-63: the identifier table and krb-crypto's table accept exactly the
    /// same etype numbers (RFC 3962 §7, RFC 8009 §7), and the conversion
    /// keeps the number. Swept over a range around the assigned numbers and
    /// the i32 extremes (RFC 3961 §8: signed 32-bit values).
    #[test]
    fn identifier_table_equals_the_crypto_profile_table() {
        let numbers = (-1_024..=1_024).chain([i32::MIN, i32::MAX]);
        for n in numbers {
            let id = EncTypeId::from_number(n);
            let crypto = EncType::from_number(n).ok();
            assert_eq!(id.is_some(), crypto.is_some(), "{n}");
            if let (Some(id), Some(crypto)) = (id, crypto) {
                assert_eq!(to_crypto(id), crypto, "{n}");
                assert_eq!(to_id(crypto), id, "{n}");
                assert_eq!(to_crypto(id).number(), id.number(), "{n}");
            }
        }
        for id in EncTypeId::ALL {
            assert_eq!(to_id(to_crypto(id)), id);
        }
    }

    /// A-63: `KeydConfig::validate` (keyd-types) refuses string-to-key
    /// parameters exactly when krb-crypto's `iteration_count` (RFC 3962 §4,
    /// RFC 8009 §4) exceeds the configured cap — for every enctype, without
    /// parameters (the enctype default) and with parameters (big-endian;
    /// 00 00 00 00 = 2^32). The cap is set to the profile's count (accepted)
    /// and one below it (refused).
    #[test]
    fn validate_iteration_cap_matches_the_crypto_profile() {
        let params: [Option<[u8; 4]>; 6] = [
            None,
            Some([0, 0, 0x10, 0]),
            Some([0, 0, 0x80, 0]),
            Some([0, 0, 0xC3, 0x50]),
            Some([0, 0, 0, 1]),
            Some([0, 0, 0, 0]),
        ];
        for id in EncTypeId::ALL {
            for p in params {
                let count = krb_crypto::iteration_count(to_crypto(id), p.as_ref().map(|o| &o[..]))
                    .expect("four octets or none");
                let mut config = KeydConfig::new(Realm::new("EXAMPLE.ORG").unwrap());
                config.enctypes = vec![id];
                config.s2k_params = p;
                match u32::try_from(count) {
                    Ok(cap) => {
                        config.max_s2k_iterations = cap;
                        assert_eq!(config.validate(), Ok(()), "{id:?} {p:?}");
                        config.max_s2k_iterations = cap - 1;
                        assert_eq!(
                            config.validate(),
                            Err(ConfigError::S2kParams),
                            "{id:?} {p:?}"
                        );
                    }
                    // 2^32 iterations: above every expressible cap.
                    Err(_) => {
                        config.max_s2k_iterations = u32::MAX;
                        assert_eq!(
                            config.validate(),
                            Err(ConfigError::S2kParams),
                            "{id:?} {p:?}"
                        );
                    }
                }
            }
        }
    }
}
