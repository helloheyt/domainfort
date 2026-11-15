//! Error type for the strict DER codec.
//!
//! Hand-rolled, zero-dependency (docs/CLEAN-ROOM.md). Every variant corresponds to a
//! specific rule the decoder enforces or a canonicality rule the encoder
//! refuses to break. Fail closed: any malformed or non-canonical input is a
//! distinct `Err`, never a panic and never a silent repair (docs/CLEAN-ROOM.md;
//! docs/32 §8).
//!
//! Security: no variant carries attacker-supplied contents — only structural
//! facts (which rule failed). Nothing that could be secret material is ever
//! placed in an error (docs/CLEAN-ROOM.md "secrets never in errors").

use core::fmt;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A decode or encode failure.
///
/// Spec references below cite ITU-T X.690 (02/2021) clauses (the encoding
/// rules) and ITU-T X.680 (02/2021) where the type is defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Input ended before a complete tag/length/contents could be read.
    /// Spec: X.690 8.1 (every encoding is identifier + length + contents).
    Truncated,

    /// A tag number encoded in the high-tag-number form used continuation
    /// octets with a leading zero, or encoded a number < 31 (which must use
    /// the single-octet form). Spec: X.690 8.1.2.4.2 c), 8.1.2.2.
    NonMinimalTagNumber,

    /// A tag number did not fit in the supported range.
    /// Spec: X.690 8.1.2.4.
    TagNumberOverflow,

    /// The indefinite length form was used. DER forbids it.
    /// Spec: X.690 8.1.3.6; 10.1 (DER: definite form only).
    IndefiniteLength,

    /// The reserved length octet 0xFF was used. Spec: X.690 8.1.3.5 c).
    ReservedLengthOctet,

    /// A definite length was not encoded in the minimum number of octets
    /// (long form where short form fits, or leading zero octets).
    /// Spec: X.690 10.1.
    NonMinimalLength,

    /// A declared length did not fit in a machine word. Spec: X.690 8.1.3.5.
    LengthOverflow,

    /// A declared length ran past the end of the available input.
    /// Spec: X.690 8.1.3.3 (length counts the contents octets present).
    LengthExceedsInput,

    /// Bytes remained after a complete top-level value, or after the single
    /// inner value of an explicit tag. Spec: X.690 8.14.3 (explicit tag
    /// contents are exactly the complete base encoding); strict framing.
    TrailingData,

    /// Nesting of constructed values exceeded [`crate::MAX_DEPTH`].
    /// Resource bound, not an encoding rule (docs/CLEAN-ROOM.md; docs/32 §8).
    DepthExceeded,

    /// A tag outside the implemented Kerberos subset was encountered.
    /// Fail closed (docs/CLEAN-ROOM.md). Spec: subset per docs/45 §3 / RFC 4120 §5.
    UnsupportedTag,

    /// Primitive/constructed bit did not match the type: a primitive type was
    /// constructed (or vice versa), or an explicit context/application tag was
    /// primitive (Kerberos uses EXPLICIT TAGS). Spec: X.690 8.2.1/8.3.1/8.6.1
    /// & 10.2 (primitive in DER); 8.9.1/8.11.1 (constructed); 8.14.3; RFC 4120
    /// §5 module header "DEFINITIONS EXPLICIT TAGS".
    PrimitiveConstructedMismatch,

    /// An INTEGER/ENUMERATED had zero contents octets. Spec: X.690 8.3.1.
    EmptyInteger,

    /// An INTEGER/ENUMERATED was not in the minimal two's-complement form.
    /// Spec: X.690 8.3.2.
    NonMinimalInteger,

    /// An INTEGER/ENUMERATED did not fit the requested Rust integer type.
    /// Conversion helper only.
    IntegerOutOfRange,

    /// A BOOLEAN was not a single octet, or (DER) TRUE was not 0xFF.
    /// Spec: X.690 8.2.1; 11.1.
    InvalidBoolean,

    /// A BIT STRING had no initial (unused-bits) octet. Spec: X.690 8.6.2.
    BitStringEmpty,

    /// A BIT STRING initial octet declared more than 7 unused bits.
    /// Spec: X.690 8.6.2.2.
    BitStringUnusedBits,

    /// A BIT STRING had unused bits that were not zero. Spec: X.690 11.2.1.
    BitStringNonZeroUnused,

    /// An OBJECT IDENTIFIER had zero contents octets. Spec: X.690 8.19.
    EmptyOid,

    /// An OBJECT IDENTIFIER ended in the middle of a subidentifier (the final
    /// octet still had the continuation bit set). Spec: X.690 8.19.2.
    OidTruncatedSubidentifier,

    /// An OBJECT IDENTIFIER subidentifier was not minimally encoded (a leading
    /// 0x80 continuation octet). Spec: X.690 8.19.2.
    NonMinimalSubidentifier,

    /// An OBJECT IDENTIFIER subidentifier did not fit in the supported range,
    /// or the value had fewer than two arcs. Spec: X.690 8.19.3/8.19.4.
    InvalidOid,

    /// A GeneralizedTime did not meet the DER restrictions (terminating "Z",
    /// seconds present, no trailing fractional zeros, "." as the point).
    /// Spec: X.690 11.7; X.680 46.3; RFC 4120 5.2.3.
    InvalidGeneralizedTime,

    /// A SET OF was not in the canonical ascending order. Spec: X.690 11.6.
    SetOfNotCanonical,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::Truncated => "input ended before a complete encoding",
            Error::NonMinimalTagNumber => "tag number not minimally encoded",
            Error::TagNumberOverflow => "tag number out of supported range",
            Error::IndefiniteLength => "indefinite length form is forbidden in DER",
            Error::ReservedLengthOctet => "reserved length octet 0xFF",
            Error::NonMinimalLength => "length not encoded in the minimum octets",
            Error::LengthOverflow => "declared length does not fit a machine word",
            Error::LengthExceedsInput => "declared length exceeds available input",
            Error::TrailingData => "unexpected trailing data after a complete value",
            Error::DepthExceeded => "nesting depth limit exceeded",
            Error::UnsupportedTag => "tag outside the implemented subset",
            Error::PrimitiveConstructedMismatch => "primitive/constructed bit wrong for this type",
            Error::EmptyInteger => "INTEGER has no contents octets",
            Error::NonMinimalInteger => "INTEGER not in minimal two's-complement form",
            Error::IntegerOutOfRange => "INTEGER does not fit the target type",
            Error::InvalidBoolean => "BOOLEAN not a single octet or not canonical",
            Error::BitStringEmpty => "BIT STRING missing its initial octet",
            Error::BitStringUnusedBits => "BIT STRING declares more than 7 unused bits",
            Error::BitStringNonZeroUnused => "BIT STRING unused bits are not zero",
            Error::EmptyOid => "OBJECT IDENTIFIER has no contents octets",
            Error::OidTruncatedSubidentifier => "OBJECT IDENTIFIER ends mid-subidentifier",
            Error::NonMinimalSubidentifier => "OBJECT IDENTIFIER subidentifier not minimal",
            Error::InvalidOid => "OBJECT IDENTIFIER value is not well formed",
            Error::InvalidGeneralizedTime => "GeneralizedTime not in DER form",
            Error::SetOfNotCanonical => "SET OF not in canonical order",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}
