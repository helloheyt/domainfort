//! Error type for the Kerberos AES encryption and checksum profile.
//!
//! Hand-rolled (docs/CLEAN-ROOM.md: prefer a hand-rolled enum over a crate for a
//! leaf). Every variant names one specific rule that failed. Fail closed:
//! malformed input, a bad length, or an integrity failure is a distinct `Err`,
//! never a panic and never a silent repair (docs/CLEAN-ROOM.md).
//!
//! Security: no variant carries any data at all — in particular no key
//! octets, no plaintext, no MAC value and no attacker-supplied bytes. Only the
//! fact of which rule failed is reported (docs/CLEAN-ROOM.md "secrets never in
//! errors").

use core::fmt;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A failure of one of the profile operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The encryption type number is not one of the four AES types this crate
    /// implements (17, 18, 19, 20). Every other number — including DES, 3DES
    /// and RC4 — has no code path (docs/CLEAN-ROOM.md).
    /// Spec: RFC 3962 §7; RFC 8009 §7; RFC 3961 §8 (numbers are signed 32-bit).
    UnsupportedEncType,

    /// The checksum type number is not one of 15, 16, 19, 20.
    /// Spec: RFC 3962 §7; RFC 8009 §7.
    UnsupportedChecksumType,

    /// A key usage number of zero was supplied.
    /// Spec: RFC 3961 §2 ("Key usages are unsigned 32-bit integers; zero is
    /// not permitted").
    InvalidKeyUsage,

    /// Key material had the wrong length for the encryption type: the
    /// random-to-key input is exactly the key-generation seed length K (the
    /// key size), and the CTS key is an AES-128 or AES-256 key.
    /// Spec: RFC 3961 §3 (random-to-key takes bitstring\[K\]); RFC 3962 §6;
    /// RFC 8009 §5 ("key-generation seed length: key size").
    InvalidKeyLength,

    /// The string-to-key parameter block was not exactly four octets.
    /// Spec: RFC 3962 §4 ("The parameter string is four octets"); RFC 8009 §4.
    InvalidS2kParams,

    /// The iteration count named by the string-to-key parameters exceeds the
    /// caller's limit. Spec: RFC 3962 §4 and §8 (implementations may limit the
    /// iteration count against a spoofed parameter; bounds are site policy).
    IterationCountAboveLimit,

    /// A ciphertext was shorter than the confounder plus the truncated HMAC,
    /// so it cannot be a valid output of the encryption function.
    /// Spec: RFC 3961 §5.3 (ciphertext = C1 | H1[1..h], C1 covers the
    /// c-octet confounder); RFC 8009 §5 (ciphertext = C | H[1..h], C covers
    /// the 16-octet confounder N).
    CiphertextTooShort,

    /// The HMAC carried in a ciphertext did not match: the ciphertext was
    /// altered, or the wrong key or key usage was used. The decrypted data is
    /// discarded. Spec: RFC 3961 §3 (decrypt: "otherwise, an error indication
    /// must be returned, and the data discarded"), §5.3; RFC 8009 §5.
    IntegrityCheckFailed,

    /// A checksum (MIC token) did not have the exact length h of its
    /// checksum type. Spec: RFC 3962 §6/§7 (96 bits); RFC 8009 §6/§7
    /// (128 or 192 bits).
    InvalidChecksumLength,

    /// verify_mic found that the message integrity was compromised (the MIC
    /// did not match). Spec: RFC 3961 §4 (verify_mic); §5.4; RFC 8009 §6.
    ChecksumVerificationFailed,

    /// The checksum type is not the one associated with the key's encryption
    /// type. Spec: RFC 3961 §4 ("associated encryption algorithm(s)");
    /// RFC 3962 §7; RFC 8009 §6.
    ChecksumTypeNotForKey,

    /// KRB-FX-CF2 was called with pepper1 equal to pepper2. Spec: RFC 6113
    /// §5.1 ("The pepper1 and pepper2 MUST be distinct so that if the two keys
    /// being combined are the same, the resulting key is not a trivial key").
    PeppersNotDistinct,

    /// An input to a building-block function (n-fold, CBC-CTS) had a length
    /// outside the range that function accepts.
    /// Spec: RFC 3961 §5.1 (n-fold); RFC 3962 §5 (CTS on at least one block);
    /// resource bounds per docs/CLEAN-ROOM.md
    InvalidInputLength,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::UnsupportedEncType => "encryption type is not implemented",
            Error::UnsupportedChecksumType => "checksum type is not implemented",
            Error::InvalidKeyUsage => "key usage zero is not permitted",
            Error::InvalidKeyLength => "key material has the wrong length",
            Error::InvalidS2kParams => "string-to-key parameters are not four octets",
            Error::IterationCountAboveLimit => "iteration count exceeds the configured limit",
            Error::CiphertextTooShort => "ciphertext is too short to be valid",
            Error::IntegrityCheckFailed => "ciphertext integrity check failed",
            Error::InvalidChecksumLength => "checksum has the wrong length",
            Error::ChecksumVerificationFailed => "checksum verification failed",
            Error::ChecksumTypeNotForKey => "checksum type does not match the key",
            Error::PeppersNotDistinct => "KRB-FX-CF2 peppers must be distinct",
            Error::InvalidInputLength => "input length outside the accepted range",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}
