//! Error type for the LDAP-BER codec.
//!
//! Hand-rolled, zero-dependency (docs/CLEAN-ROOM.md). Every variant names one rule the
//! decoder enforces (or one representability rule the encoder enforces). Fail
//! closed: malformed input is always a distinct `Err`, never a panic and never a
//! silent repair (docs/CLEAN-ROOM.md; docs/49 §2.3).
//!
//! Disposition (docs/49 §2.3, §9): [`Error::MessageTooLarge`] means "drop the
//! connection without a response" ([MS-ADTS] 3.1.1.3.4.6). Every other decode
//! error means the PDU is malformed: Notice of Disconnection with
//! `protocolError` and immediate termination (RFC 4511 §4.1.1).
//!
//! Security: no variant carries attacker-supplied bytes — only which rule
//! failed. Nothing secret can reach an error (docs/CLEAN-ROOM.md).

use core::fmt;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Which resource bound (docs/49 §2.4, R49-3) was exceeded.
///
/// Each bound is a named constant in [`crate::limits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Limit {
    /// Nesting of constructed elements. [`crate::MAX_TLV_DEPTH`].
    TlvDepth,
    /// Nesting of Filter choices. [`crate::MAX_FILTER_DEPTH`].
    FilterDepth,
    /// Number of Filter elements in one search filter. [`crate::MAX_FILTER_NODES`].
    FilterNodes,
    /// Number of `any` components in one SubstringFilter. [`crate::MAX_SUBSTRING_ANY`].
    SubstringAny,
    /// Number of selectors in an AttributeSelection. [`crate::MAX_ATTRIBUTE_SELECTORS`].
    AttributeSelectors,
    /// Number of controls on one message. [`crate::MAX_CONTROLS`].
    Controls,
    /// Number of PartialAttributes in one SearchResultEntry. [`crate::MAX_PARTIAL_ATTRIBUTES`].
    PartialAttributes,
    /// Number of values of one PartialAttribute. [`crate::MAX_ATTRIBUTE_VALUES`].
    AttributeValues,
    /// Octets of an LDAPDN (or diagnosticMessage). [`crate::MAX_LDAPDN_OCTETS`].
    LdapDnOctets,
    /// Octets of a short identifier string. [`crate::MAX_IDENTIFIER_OCTETS`].
    IdentifierOctets,
    /// Octets of an AttributeValue / AssertionValue. [`crate::MAX_VALUE_OCTETS`].
    ValueOctets,
}

/// A decode or encode failure.
///
/// Spec references cite RFC 4511 (the protocol and its §5.1 BER profile),
/// ITU-T X.690 (02/2021) (the encoding rules), and the project decision A-45
/// (docs/questions/Q-160) for the profile choices the specs leave open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    // ---- framing and TLV structure ------------------------------------------
    /// Input ended before a complete identifier/length/contents was read.
    /// Spec: X.690 8.1.1.1 (every encoding has all its components).
    Truncated,

    /// The declared length runs past the end of the enclosing input.
    /// Spec: X.690 8.1.3.3 (the length counts the contents octets present).
    LengthExceedsInput,

    /// The indefinite length form (`0x80`) was used.
    /// Spec: RFC 4511 §5.1 ("Only the definite form of length encoding is
    /// used"); X.690 8.1.3.6.
    IndefiniteLength,

    /// The reserved initial length octet `0xFF` was used. Spec: X.690 8.1.3.5 c).
    ReservedLengthOctet,

    /// A long-form length used more than [`crate::MAX_LENGTH_OCTETS`] subsequent
    /// octets. Spec: A-45 (non-minimal long form accepted up to 4 octets);
    /// X.690 8.1.3.5 NOTE 2.
    TooManyLengthOctets,

    /// A length was not in the minimum number of octets. Raised only by the
    /// [`crate::Profile::Canonical`] profile. Spec: X.690 10.1; docs/49 §11.
    NonMinimalLength,

    /// An identifier used the high-tag-number form (tag number >= 31). LDAP
    /// defines no such tag (RFC 4511 App. B), so the form is refused outright.
    /// Spec: X.690 8.1.2.4; docs/49 §2.3 E6.
    HighTagNumber,

    /// The identifier `[UNIVERSAL 0]` appeared: the end-of-contents marker,
    /// which exists only with the indefinite form, and is reserved for the
    /// encoding rules. Spec: X.690 8.1.5; X.680 Table 1; RFC 4511 §5.1.
    EndOfContents,

    /// Constructed nesting or a counted element exceeded a bound.
    /// Spec: docs/49 §2.4 (R49-3); docs/CLEAN-ROOM.md
    LimitExceeded(Limit),

    /// The message is larger than the bound for the session's authentication
    /// state: drop the connection. Spec: [MS-ADTS] 3.1.1.3.4.6
    /// (MaxReceiveBuffer / MaxPreAuthReceiveBuffer, "it will drop the
    /// connection"); docs/49 §2.4, §9.
    MessageTooLarge,

    /// Octets remained after a complete value where nothing may follow (after
    /// the LDAPMessage, or inside the explicit `not [2]` wrapper).
    /// Spec: RFC 4511 §5.2 (PDUs follow one another directly); X.690 8.14.3.
    TrailingData,

    // ---- component structure ------------------------------------------------
    /// A required component was absent. Spec: X.690 8.9.2.
    MissingComponent,

    /// An element carried an identifier that is not valid at its position —
    /// including a tag the module defines, appearing out of place.
    /// Spec: X.690 8.9.2 (components appear in definition order); docs/49 §2.3
    /// E12 ("a known tag in an unexpected place is malformed").
    UnexpectedTag,

    /// A primitive type was encoded constructed, or vice versa.
    /// Spec: X.690 8.1.2.5, 8.2.1, 8.3.1, 8.8.1, 8.9.1, 8.10.1, 8.12.1,
    /// 8.14.4 a).
    PrimitiveConstructedMismatch,

    /// An OCTET STRING (or a type derived from it, directly or by implicit
    /// tagging) was encoded constructed.
    /// Spec: RFC 4511 §5.1 ("OCTET STRING values are encoded in the primitive
    /// form only"); X.690 8.7.1, 8.14.4 a).
    ConstructedOctetString,

    /// A trailing SEQUENCE component with an unrecognised tag appeared where
    /// the [`crate::Profile::Canonical`] profile allows none. (The
    /// [`crate::Profile::Wire`] profile skips such components.)
    /// Spec: RFC 4511 §4; docs/49 §11.
    UnrecognizedComponent,

    /// A form the canonical encoder never produces appeared under the
    /// [`crate::Profile::Canonical`] profile (an unrecognised CHOICE alternative
    /// or an unsupported operation with contents, or a simple-bind password
    /// other than the placeholder). Spec: docs/49 §11 (R49-16).
    NonCanonical,

    // ---- primitive values ---------------------------------------------------
    /// A BOOLEAN was not one octet, or its octet was neither `0x00` nor `0xFF`.
    /// Spec: X.690 8.2.1; RFC 4511 §5.1 (TRUE is `FF`); A-45 (Q-160 item 3).
    InvalidBoolean,

    /// A BOOLEAN DEFAULT FALSE component was present with the value FALSE.
    /// Spec: RFC 4511 §5.1 ("If a value of a type is its default value, it is
    /// absent"); A-45 (Q-160 item 4).
    ExplicitDefault,

    /// An INTEGER/ENUMERATED had no contents octets. Spec: X.690 8.3.1, 8.4.
    EmptyInteger,

    /// An INTEGER/ENUMERATED was not in its minimal form.
    /// Spec: X.690 8.3.2 (a BER rule, not only DER), 8.4.
    NonMinimalInteger,

    /// An INTEGER/ENUMERATED value is outside the range its type allows.
    /// Spec: RFC 4511 §4.5.1 (`sizeLimit`/`timeLimit` 0..maxInt), §4.11
    /// (MessageID), App. B.
    IntegerOutOfRange,

    /// A MessageID was outside `0 .. maxInt`. Spec: RFC 4511 §4.1.1.
    MessageIdOutOfRange,

    /// A request carried MessageID zero, or a response other than an
    /// unsolicited notification did. Spec: RFC 4511 §4.1.1.1 ("The zero value
    /// is reserved for the unsolicited notification message"), §4.4.
    ZeroMessageId,

    /// A BindRequest `version` was outside `1 .. 127`. Spec: RFC 4511 §4.2;
    /// docs/49 §2.3 E9.
    VersionOutOfRange,

    /// A NULL (UnbindRequest) had contents octets. Spec: X.690 8.8.2;
    /// RFC 4511 §4.3.
    InvalidNull,

    /// An LDAPString (or LDAPDN, AttributeDescription, LDAPOID, MatchingRuleId)
    /// was not well-formed UTF-8. Spec: RFC 4511 §4.1.2; RFC 4512 §1.4 (UTF8
    /// production); RFC 4511 §6 ("UTF-8 encoding exceptions").
    InvalidUtf8,

    // ---- operation-level structure ------------------------------------------
    /// The protocolOp tag is not recognised as a request (request direction)
    /// or as a response this codec models (response direction).
    /// Spec: RFC 4511 §4.1.1 ("the tag of the protocolOp is not recognized as
    /// a request"); docs/49 §2.3 E13, R49-17.
    UnrecognizedProtocolOp,

    /// An `and` / `or` filter had no elements.
    /// Spec: RFC 4511 §4.5.1 (`SET SIZE (1..MAX)`), §4.5.1.7 ("At least one
    /// filter element MUST be present"); docs/49 §2.3 E16.
    EmptySet,

    /// A SubstringFilter had no substrings.
    /// Spec: RFC 4511 §4.5.1 (`SEQUENCE SIZE (1..MAX)`); docs/49 §2.3 E15.
    EmptySubstrings,

    /// A SubstringFilter had more than one `initial`/`final`, an `initial` that
    /// was not first, or a `final` that was not last.
    /// Spec: RFC 4511 §4.5.1.7.2; docs/49 §2.3 E15.
    SubstringOrder,

    /// A MatchingRuleAssertion had neither `matchingRule` nor `type`.
    /// Spec: RFC 4511 §4.5.1.7.7 ("If the matchingRule field is absent, the
    /// type field MUST be present").
    MissingMatchingRuleAndType,

    /// A resultCode value is not one RFC 4511 defines (response direction).
    /// Spec: RFC 4511 §4.1.9.
    UnrecognizedResultCode,

    // ---- encoder-only -------------------------------------------------------
    /// The value is not representable canonically: an `Unrecognized` variant
    /// carrying a value or tag that the module defines (it would decode as the
    /// defined alternative), or a tag number above 30 (X.690 8.1.2.2).
    InvalidValue,
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Limit::TlvDepth => "element nesting depth",
            Limit::FilterDepth => "filter nesting depth",
            Limit::FilterNodes => "filter element count",
            Limit::SubstringAny => "substring 'any' count",
            Limit::AttributeSelectors => "attribute selector count",
            Limit::Controls => "control count",
            Limit::PartialAttributes => "partial attribute count",
            Limit::AttributeValues => "attribute value count",
            Limit::LdapDnOctets => "distinguished name size",
            Limit::IdentifierOctets => "identifier string size",
            Limit::ValueOctets => "value size",
        };
        f.write_str(name)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::Truncated => "input ends inside an element",
            Error::LengthExceedsInput => "declared length is longer than the enclosing input",
            Error::IndefiniteLength => "indefinite length form is not allowed in LDAP",
            Error::ReservedLengthOctet => "reserved initial length octet",
            Error::TooManyLengthOctets => "long-form length uses more than four octets",
            Error::NonMinimalLength => "length is not in its shortest form",
            Error::HighTagNumber => "high tag number form is not used by LDAP",
            Error::EndOfContents => "end-of-contents identifier outside the indefinite form",
            Error::LimitExceeded(limit) => return write!(f, "bound exceeded: {limit}"),
            Error::MessageTooLarge => "message exceeds the size bound for this session",
            Error::TrailingData => "octets follow a complete value",
            Error::MissingComponent => "a required component is absent",
            Error::UnexpectedTag => "identifier not valid at this position",
            Error::PrimitiveConstructedMismatch => "primitive/constructed form wrong for this type",
            Error::ConstructedOctetString => "octet string in constructed form",
            Error::UnrecognizedComponent => "unrecognised trailing component in canonical input",
            Error::NonCanonical => "form never produced by the canonical encoder",
            Error::InvalidBoolean => "boolean is not a single 00 or FF octet",
            Error::ExplicitDefault => "component encodes its default value",
            Error::EmptyInteger => "integer has no contents octets",
            Error::NonMinimalInteger => "integer is not in its shortest form",
            Error::IntegerOutOfRange => "integer outside the range of its type",
            Error::MessageIdOutOfRange => "message identifier outside 0..maxInt",
            Error::ZeroMessageId => "message identifier zero is reserved",
            Error::VersionOutOfRange => "bind version outside 1..127",
            Error::InvalidNull => "null has contents octets",
            Error::InvalidUtf8 => "string is not well-formed UTF-8",
            Error::UnrecognizedProtocolOp => "protocol operation not recognised here",
            Error::EmptySet => "and/or filter has no elements",
            Error::EmptySubstrings => "substring filter has no substrings",
            Error::SubstringOrder => "substring initial/final misplaced or repeated",
            Error::MissingMatchingRuleAndType => "extensible match lacks both rule and type",
            Error::UnrecognizedResultCode => "result code not defined by the protocol",
            Error::InvalidValue => "value has no canonical encoding",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}
