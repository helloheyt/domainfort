//! Why a certificate was refused.
//!
//! Hand-rolled, no dependency beyond parse-asn1's own error (AGENTS.md §7).
//! No variant carries input octets — only which field and which rule —
//! so an error can be logged without echoing anything from the file
//! (AGENTS.md §6; docs/50 §8.2).

use core::fmt;

/// The certificate field being read when a rule failed. Names follow
/// RFC 5280 §4.1 (AGENTS.md §4.4).
/// Spec: RFC 5280 4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Field {
    /// `Certificate`. Spec: RFC 5280 4.1.
    Certificate,
    /// `tbsCertificate`. Spec: RFC 5280 4.1.1.1, 4.1.2.
    TbsCertificate,
    /// `version`. Spec: RFC 5280 4.1.2.1.
    Version,
    /// `serialNumber`. Spec: RFC 5280 4.1.2.2.
    SerialNumber,
    /// `signature` (inside tbsCertificate). Spec: RFC 5280 4.1.2.3.
    Signature,
    /// `issuer`. Spec: RFC 5280 4.1.2.4.
    Issuer,
    /// `validity`. Spec: RFC 5280 4.1.2.5.
    Validity,
    /// `notBefore`. Spec: RFC 5280 4.1.2.5.
    NotBefore,
    /// `notAfter`. Spec: RFC 5280 4.1.2.5.
    NotAfter,
    /// `subject`. Spec: RFC 5280 4.1.2.6.
    Subject,
    /// `subjectPublicKeyInfo`. Spec: RFC 5280 4.1.2.7.
    SubjectPublicKeyInfo,
    /// `subjectPublicKey` (inside subjectPublicKeyInfo). Spec: RFC 5280 4.1.
    SubjectPublicKey,
    /// `issuerUniqueID`. Spec: RFC 5280 4.1.2.8.
    IssuerUniqueId,
    /// `subjectUniqueID`. Spec: RFC 5280 4.1.2.8.
    SubjectUniqueId,
    /// `extensions`. Spec: RFC 5280 4.1.2.9.
    Extensions,
    /// One `Extension`. Spec: RFC 5280 4.1, 4.2.
    Extension,
    /// `signatureAlgorithm` (outer). Spec: RFC 5280 4.1.1.2.
    SignatureAlgorithm,
    /// `signatureValue`. Spec: RFC 5280 4.1.1.3.
    SignatureValue,
}

/// A refused certificate.
/// Spec: RFC 5280 4.1, 4.2; X.690 clauses 8, 10, 11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input is longer than [`crate::MAX_CERTIFICATE_OCTETS`]
    /// (resource bound, AGENTS.md §6).
    TooLarge,
    /// A DER rule was broken while reading the field (non-minimal or
    /// indefinite length, truncation, a non-minimal INTEGER, …).
    /// Spec: X.690 8.1, 10, 11.
    Der(Field, parse_asn1::Error),
    /// The field is missing or carries another tag than RFC 5280 §4.1
    /// gives it.
    UnexpectedElement(Field),
    /// Octets follow the last component of the field.
    TrailingData(Field),
    /// The version is not v3 (absent, v1 or v2). Spec: RFC 5280 4.1.2.1.
    VersionNotV3,
    /// The serialNumber has more than [`crate::MAX_SERIAL_NUMBER_OCTETS`]
    /// contents octets. Spec: RFC 5280 4.1.2.2.
    SerialNumberTooLong,
    /// The issuer is an empty name. Spec: RFC 5280 4.1.2.4 ("MUST contain a
    /// non-empty distinguished name").
    EmptyIssuer,
    /// A Name is not an RDNSequence of non-empty SETs of
    /// AttributeTypeAndValue in DER order. Spec: RFC 5280 4.1.2.4;
    /// X.690 11.6.
    MalformedName(Field),
    /// More components than the resource bound allows (names, extensions).
    TooManyComponents(Field),
    /// A Time is not `YYMMDDHHMMSSZ` (UTCTime) or `YYYYMMDDHHMMSSZ`
    /// (GeneralizedTime, from 2050 on), or names no calendar instant.
    /// Spec: RFC 5280 4.1.2.5, 4.1.2.5.1, 4.1.2.5.2; X.690 11.7, 11.8.
    InvalidTime(Field),
    /// A BIT STRING that carries whole octets in this profile has unused
    /// bits. Spec: RFC 5280 4.1, 4.1.1.3, 4.1.2.7 (project profile).
    PartialOctet(Field),
    /// An Extension encodes `critical` as FALSE, its DEFAULT value.
    /// Spec: RFC 5280 4.1; X.690 11.5.
    DefaultEncoded,
    /// Two extensions carry the same extnID. Spec: RFC 5280 4.2 ("MUST NOT
    /// include more than one instance of a particular extension").
    DuplicateExtension,
    /// The extensions field is present with no extension.
    /// Spec: RFC 5280 4.1 (`SEQUENCE SIZE (1..MAX) OF Extension`).
    EmptyExtensions,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooLarge => f.write_str("certificate too large"),
            Error::Der(field, error) => write!(f, "{field:?}: not DER ({error})"),
            Error::UnexpectedElement(field) => write!(f, "{field:?}: missing or wrong tag"),
            Error::TrailingData(field) => write!(f, "{field:?}: unexpected trailing octets"),
            Error::VersionNotV3 => f.write_str("version is not v3"),
            Error::SerialNumberTooLong => f.write_str("serialNumber longer than 20 octets"),
            Error::EmptyIssuer => f.write_str("issuer is an empty name"),
            Error::MalformedName(field) => write!(f, "{field:?}: malformed name"),
            Error::TooManyComponents(field) => write!(f, "{field:?}: too many components"),
            Error::InvalidTime(field) => write!(f, "{field:?}: invalid time"),
            Error::PartialOctet(field) => write!(f, "{field:?}: BIT STRING with unused bits"),
            Error::DefaultEncoded => f.write_str("extension critical encoded as its default"),
            Error::DuplicateExtension => f.write_str("extension present more than once"),
            Error::EmptyExtensions => f.write_str("extensions present but empty"),
        }
    }
}

impl std::error::Error for Error {}
