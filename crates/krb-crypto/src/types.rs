//! Encryption types, checksum types and key usage numbers.
//!
//! Only the four AES encryption types and their four associated checksum
//! types exist here. Any other number maps to an error: DES, 3DES, RC4 and the
//! rest have no code path at all (docs/CLEAN-ROOM.md; docs/38 §2 "hard floor").
//!
//! Spec: RFC 3962 §6, §7; RFC 8009 §5, §6, §7; RFC 3961 §2, §8.

use crate::error::{Error, Result};

/// A Kerberos encryption type ("etype") implemented by this crate.
///
/// Spec: RFC 3962 §7 (17, 18); RFC 8009 §7 (19, 20). Type numbers are signed
/// 32-bit values (RFC 3961 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncType {
    /// `aes128-cts-hmac-sha1-96`, etype 17. Spec: RFC 3962 §7.
    Aes128CtsHmacSha196,
    /// `aes256-cts-hmac-sha1-96`, etype 18. Spec: RFC 3962 §7.
    Aes256CtsHmacSha196,
    /// `aes128-cts-hmac-sha256-128`, etype 19. Spec: RFC 8009 §7.
    Aes128CtsHmacSha256128,
    /// `aes256-cts-hmac-sha384-192`, etype 20. Spec: RFC 8009 §7.
    Aes256CtsHmacSha384192,
}

impl EncType {
    /// Map an etype number to an implemented encryption type.
    ///
    /// Every number other than 17, 18, 19, 20 is
    /// [`Error::UnsupportedEncType`] — fail closed.
    /// Spec: RFC 3962 §7; RFC 8009 §7.
    pub fn from_number(etype: i32) -> Result<Self> {
        match etype {
            17 => Ok(EncType::Aes128CtsHmacSha196),
            18 => Ok(EncType::Aes256CtsHmacSha196),
            19 => Ok(EncType::Aes128CtsHmacSha256128),
            20 => Ok(EncType::Aes256CtsHmacSha384192),
            _ => Err(Error::UnsupportedEncType),
        }
    }

    /// The assigned etype number. Spec: RFC 3962 §7; RFC 8009 §7.
    pub fn number(self) -> i32 {
        match self {
            EncType::Aes128CtsHmacSha196 => 17,
            EncType::Aes256CtsHmacSha196 => 18,
            EncType::Aes128CtsHmacSha256128 => 19,
            EncType::Aes256CtsHmacSha384192 => 20,
        }
    }

    /// The protocol key length in octets (128- or 256-bit AES key); this is
    /// also the key-generation seed length K.
    /// Spec: RFC 3962 §6 ("key-generation seed length: key size"), §7;
    /// RFC 8009 §2, §5.
    pub fn key_length(self) -> usize {
        match self {
            EncType::Aes128CtsHmacSha196 | EncType::Aes128CtsHmacSha256128 => 16,
            EncType::Aes256CtsHmacSha196 | EncType::Aes256CtsHmacSha384192 => 32,
        }
    }

    /// The associated (required) checksum type.
    /// Spec: RFC 3961 §3 ("required checksum mechanism"); RFC 3962 §7
    /// ("These checksum types will be used with the corresponding encryption
    /// types"); RFC 8009 §6.
    pub fn checksum_type(self) -> ChecksumType {
        match self {
            EncType::Aes128CtsHmacSha196 => ChecksumType::HmacSha196Aes128,
            EncType::Aes256CtsHmacSha196 => ChecksumType::HmacSha196Aes256,
            EncType::Aes128CtsHmacSha256128 => ChecksumType::HmacSha256128Aes128,
            EncType::Aes256CtsHmacSha384192 => ChecksumType::HmacSha384192Aes256,
        }
    }

    /// Length in octets of the truncated HMAC appended to each ciphertext.
    /// Spec: RFC 3962 §6 (h = 12 octets); RFC 8009 §5 (128 or 192 bits).
    pub fn hmac_length(self) -> usize {
        match self {
            EncType::Aes128CtsHmacSha196 | EncType::Aes256CtsHmacSha196 => 12,
            EncType::Aes128CtsHmacSha256128 => 16,
            EncType::Aes256CtsHmacSha384192 => 24,
        }
    }

    /// Minimum valid ciphertext length: the 16-octet confounder block plus
    /// the truncated HMAC. Spec: RFC 3961 §5.3; RFC 8009 §5.
    pub fn min_ciphertext_length(self) -> usize {
        CONFOUNDER_LENGTH + self.hmac_length()
    }
}

/// Length of the confounder in octets: the AES cipher block size c.
/// Spec: RFC 3961 §5.3 ("conf = Random string of length c"); RFC 3962 §6
/// (cipher block size 16 octets); RFC 8009 §5 (128-bit confounder N).
pub const CONFOUNDER_LENGTH: usize = 16;

/// A Kerberos checksum type implemented by this crate.
///
/// Spec: RFC 3962 §7 (15, 16); RFC 8009 §7 (19, 20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChecksumType {
    /// `hmac-sha1-96-aes128`, sumtype 15. Spec: RFC 3962 §7.
    HmacSha196Aes128,
    /// `hmac-sha1-96-aes256`, sumtype 16. Spec: RFC 3962 §7.
    HmacSha196Aes256,
    /// `hmac-sha256-128-aes128`, sumtype 19. Spec: RFC 8009 §7.
    HmacSha256128Aes128,
    /// `hmac-sha384-192-aes256`, sumtype 20. Spec: RFC 8009 §7.
    HmacSha384192Aes256,
}

impl ChecksumType {
    /// Map a checksum type number to an implemented checksum type.
    ///
    /// Every number other than 15, 16, 19, 20 is
    /// [`Error::UnsupportedChecksumType`] — fail closed.
    /// Spec: RFC 3962 §7; RFC 8009 §7.
    pub fn from_number(sumtype: i32) -> Result<Self> {
        match sumtype {
            15 => Ok(ChecksumType::HmacSha196Aes128),
            16 => Ok(ChecksumType::HmacSha196Aes256),
            19 => Ok(ChecksumType::HmacSha256128Aes128),
            20 => Ok(ChecksumType::HmacSha384192Aes256),
            _ => Err(Error::UnsupportedChecksumType),
        }
    }

    /// The assigned checksum type number. Spec: RFC 3962 §7; RFC 8009 §7.
    pub fn number(self) -> i32 {
        match self {
            ChecksumType::HmacSha196Aes128 => 15,
            ChecksumType::HmacSha196Aes256 => 16,
            ChecksumType::HmacSha256128Aes128 => 19,
            ChecksumType::HmacSha384192Aes256 => 20,
        }
    }

    /// The associated encryption type (the only key type this checksum may
    /// be computed with). Spec: RFC 3961 §4; RFC 3962 §7; RFC 8009 §6.
    pub fn enc_type(self) -> EncType {
        match self {
            ChecksumType::HmacSha196Aes128 => EncType::Aes128CtsHmacSha196,
            ChecksumType::HmacSha196Aes256 => EncType::Aes256CtsHmacSha196,
            ChecksumType::HmacSha256128Aes128 => EncType::Aes128CtsHmacSha256128,
            ChecksumType::HmacSha384192Aes256 => EncType::Aes256CtsHmacSha384192,
        }
    }

    /// The checksum (MIC) length h in octets.
    ///
    /// Spec: RFC 3962 §6 ("HMAC output size, h: 12 octets (96 bits)") and §7
    /// (length 96); RFC 8009 §6 and §7 (16 and 24 octets). Note: the RFC 3961
    /// §8 table lists size 20 for sumtypes 15/16 but defers their definition
    /// to [KRB5-AES] (RFC 3962), which specifies 96 bits; the defining
    /// document governs (docs/questions/Q-012, resolved).
    pub fn mic_length(self) -> usize {
        self.enc_type().hmac_length()
    }
}

/// A key usage number: an unsigned 32-bit integer, never zero.
///
/// Spec: RFC 3961 §2 ("Key usages are unsigned 32-bit integers; zero is not
/// permitted"). The enumeration of usages is outside RFC 3961 (RFC 4120 §7.5.1
/// assigns them); this crate accepts any non-zero value from the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyUsage(u32);

impl KeyUsage {
    /// Validate a key usage number. Zero is [`Error::InvalidKeyUsage`].
    /// Spec: RFC 3961 §2.
    pub fn new(usage: u32) -> Result<Self> {
        if usage == 0 {
            return Err(Error::InvalidKeyUsage);
        }
        Ok(KeyUsage(usage))
    }

    /// The usage number.
    pub fn get(self) -> u32 {
        self.0
    }

    /// The well-known constant for deriving one specific key: the usage
    /// number as four octets in big-endian order followed by one octet
    /// (0x99 for Kc, 0xAA for Ke, 0x55 for Ki).
    /// Spec: RFC 3961 §5.3 (key-derivation function); RFC 8009 §5.
    pub(crate) fn derivation_constant(self, kind: SpecificKeyKind) -> [u8; 5] {
        let u = self.0.to_be_bytes();
        [u[0], u[1], u[2], u[3], kind.constant_octet()]
    }
}

/// Which of the three specific keys derived from a base key.
///
/// Spec: RFC 3961 §5.3 ("Three protocol-format keys: { Kc, Ke, Ki }");
/// RFC 8009 §5 ("specific key structure: three derived keys").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpecificKeyKind {
    /// Kc, the checksum key. Constant octet 0x99. Spec: RFC 3961 §5.3;
    /// RFC 8009 §5.
    Kc,
    /// Ke, the encryption key. Constant octet 0xAA. Spec: RFC 3961 §5.3;
    /// RFC 8009 §5.
    Ke,
    /// Ki, the integrity key. Constant octet 0x55. Spec: RFC 3961 §5.3;
    /// RFC 8009 §5.
    Ki,
}

impl SpecificKeyKind {
    /// The octet appended to the big-endian usage number.
    /// Spec: RFC 3961 §5.3; RFC 8009 §5.
    fn constant_octet(self) -> u8 {
        match self {
            SpecificKeyKind::Kc => 0x99,
            SpecificKeyKind::Ke => 0xAA,
            SpecificKeyKind::Ki => 0x55,
        }
    }
}
