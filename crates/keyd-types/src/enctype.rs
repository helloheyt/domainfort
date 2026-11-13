//! The encryption-type identifiers keyd configures — a name for an
//! encryption type, without its cryptographic profile.
//!
//! keyd's configuration ([`crate::KeydConfig::enctypes`],
//! [`crate::ConfigDescription::enctypes`]) and its ticket templates
//! (`session_enctype` of [`crate::AsTicketTemplate`] and
//! [`crate::TgsTicketTemplate`]) name encryption types by their assigned
//! numbers. The profile that implements them is the `krb-crypto` crate,
//! which only keyd links (D182); this identifier lets the KDC, the LDAP
//! engine, the directory PIP and the ipc-keyd client carry those values
//! without linking it (decision A-63). keyd converts an identifier to the
//! profile's own type internally, and a keyd test pins the two closed
//! tables to each other, number for number.
//!
//! Only the four AES encryption types exist: no DES, 3DES or RC4 type is
//! expressible (AGENTS.md §6; docs/10 §1, §12 I5).
//!
//! Spec: RFC 3961 §8 ("Encryption and checksum-type numbers are signed
//! 32-bit values"; 17 and 18 assigned to [KRB5-AES]); RFC 3962 §4, §7 (17,
//! 18); RFC 8009 §4, §7 (19, 20); D182; A-63.

/// A Kerberos encryption type keyd may configure, by its assigned number.
///
/// Not a cryptographic object: it carries no key, no profile and no
/// algorithm — only which of the four AES types is meant.
///
/// Spec: RFC 3962 §7 (17, 18); RFC 8009 §7 (19, 20); RFC 3961 §8 (numbers
/// are signed 32-bit values); D182; A-63.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncTypeId {
    /// `aes128-cts-hmac-sha1-96`, etype 17. Spec: RFC 3962 §7.
    Aes128CtsHmacSha196,
    /// `aes256-cts-hmac-sha1-96`, etype 18. Spec: RFC 3962 §7.
    Aes256CtsHmacSha196,
    /// `aes128-cts-hmac-sha256-128`, etype 19. Spec: RFC 8009 §7.
    Aes128CtsHmacSha256128,
    /// `aes256-cts-hmac-sha384-192`, etype 20. Spec: RFC 8009 §7.
    Aes256CtsHmacSha384192,
}

impl EncTypeId {
    /// Every identifier, in etype-number order (for exhaustive checks).
    /// Spec: RFC 3962 §7; RFC 8009 §7.
    pub const ALL: [EncTypeId; 4] = [
        EncTypeId::Aes128CtsHmacSha196,
        EncTypeId::Aes256CtsHmacSha196,
        EncTypeId::Aes128CtsHmacSha256128,
        EncTypeId::Aes256CtsHmacSha384192,
    ];

    /// The identifier of an etype number, or `None` for every number other
    /// than 17, 18, 19, 20 — fail closed: no other type is expressible.
    /// Spec: RFC 3962 §7; RFC 8009 §7; RFC 3961 §8.
    pub const fn from_number(etype: i32) -> Option<Self> {
        match etype {
            17 => Some(EncTypeId::Aes128CtsHmacSha196),
            18 => Some(EncTypeId::Aes256CtsHmacSha196),
            19 => Some(EncTypeId::Aes128CtsHmacSha256128),
            20 => Some(EncTypeId::Aes256CtsHmacSha384192),
            _ => None,
        }
    }

    /// The assigned etype number. Spec: RFC 3962 §7; RFC 8009 §7.
    pub const fn number(self) -> i32 {
        match self {
            EncTypeId::Aes128CtsHmacSha196 => 17,
            EncTypeId::Aes256CtsHmacSha196 => 18,
            EncTypeId::Aes128CtsHmacSha256128 => 19,
            EncTypeId::Aes256CtsHmacSha384192 => 20,
        }
    }

    /// The string-to-key iteration count used when no parameters are given:
    /// 4,096 ("00 00 10 00") for etypes 17 / 18, decimal 32768 for etypes 19
    /// / 20.
    /// Spec: RFC 3962 §4 ("If the string-to-key parameters are not supplied,
    /// the value used is 00 00 10 00 (decimal 4,096 ...)"); RFC 8009 §4 ("the
    /// default is decimal 32768 if the parameter is not specified").
    const fn default_s2k_iterations(self) -> u64 {
        match self {
            EncTypeId::Aes128CtsHmacSha196 | EncTypeId::Aes256CtsHmacSha196 => 4_096,
            EncTypeId::Aes128CtsHmacSha256128 | EncTypeId::Aes256CtsHmacSha384192 => 32_768,
        }
    }
}

/// The PBKDF2 iteration count a string-to-key parameter block names for
/// `enctype`: the four octets as an unsigned big-endian number, where
/// 00 00 00 00 means 2^32; without parameters, the enctype's default. A
/// `u64`, so that 2^32 is representable.
///
/// Used only by [`crate::KeydConfig::validate`] to hold the configured
/// parameters to the configured iteration cap without linking the crypto
/// profile (A-63); keyd's tests pin it to the profile's own count for every
/// enctype.
///
/// Spec: RFC 3962 §4 ("The parameter string is four octets indicating an
/// unsigned number in big-endian order. ... If the value is 00 00 00 00, the
/// number of iterations to be performed is 4,294,967,296 (2**32)"); RFC 8009
/// §4 ("4 octets indicating an unsigned number in big-endian order,
/// consistent with [RFC3962], except that the default is decimal 32768");
/// A-63.
pub(crate) const fn s2k_iteration_count(enctype: EncTypeId, s2k_params: Option<[u8; 4]>) -> u64 {
    match s2k_params {
        None => enctype.default_s2k_iterations(),
        Some(octets) => match u32::from_be_bytes(octets) {
            0 => 1u64 << 32,
            n => n as u64,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3962 §7 / RFC 8009 §7: exactly 17..=20 map, and back.
    #[test]
    fn numbers_round_trip_and_nothing_else_maps() {
        for id in EncTypeId::ALL {
            assert_eq!(EncTypeId::from_number(id.number()), Some(id));
        }
        let numbers: Vec<i32> = EncTypeId::ALL.iter().map(|e| e.number()).collect();
        assert_eq!(numbers, [17, 18, 19, 20]);
        // RFC 3961 §8: zero is invalid, negatives are local, 1-16 and 23/24
        // are DES / 3DES / RC4 / others — none is expressible.
        for n in [i32::MIN, -1, 0, 1, 3, 16, 21, 23, 24, 65, i32::MAX] {
            assert_eq!(EncTypeId::from_number(n), None, "{n}");
        }
    }

    /// RFC 3962 §4 / RFC 8009 §4: big-endian count, 00 00 00 00 = 2^32,
    /// defaults 4096 / 32768. Values hand-derived from the RFC text.
    #[test]
    fn s2k_iteration_count_follows_rfc3962_and_rfc8009() {
        assert_eq!(
            s2k_iteration_count(EncTypeId::Aes128CtsHmacSha196, None),
            4_096
        );
        assert_eq!(
            s2k_iteration_count(EncTypeId::Aes256CtsHmacSha196, None),
            4_096
        );
        assert_eq!(
            s2k_iteration_count(EncTypeId::Aes128CtsHmacSha256128, None),
            32_768
        );
        assert_eq!(
            s2k_iteration_count(EncTypeId::Aes256CtsHmacSha384192, None),
            32_768
        );
        for id in EncTypeId::ALL {
            assert_eq!(s2k_iteration_count(id, Some([0, 0, 0x10, 0])), 4_096);
            assert_eq!(s2k_iteration_count(id, Some([0, 0, 0, 1])), 1);
            assert_eq!(s2k_iteration_count(id, Some([0, 0, 0xC3, 0x50])), 50_000);
            assert_eq!(s2k_iteration_count(id, Some([0, 0, 0, 0])), 1 << 32);
            assert_eq!(
                s2k_iteration_count(id, Some([0xFF, 0xFF, 0xFF, 0xFF])),
                u64::from(u32::MAX)
            );
        }
    }
}
