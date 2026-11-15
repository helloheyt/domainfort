//! Error type for the typed Kerberos message layer.
//!
//! Hand-rolled, no extra dependency (docs/CLEAN-ROOM.md; house style of
//! `parse-asn1`). Every variant names one specific rule that the input broke —
//! a DER rule (delegated to `parse-asn1`), an RFC 4120 §5 constraint, or one of
//! this crate's documented resource bounds. Fail closed: malformed input is a
//! distinct `Err`, never a panic and never a silent repair (docs/CLEAN-ROOM.md).
//!
//! Security: no variant carries any input content — only the structural fact
//! of which rule failed — so key material, cipher text, or names can never leak
//! through an error, its `Debug`, or its `Display` (docs/CLEAN-ROOM.md "secrets never
//! in errors").

use core::fmt;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A decode or encode failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The DER layer (`parse-asn1`) rejected the input.
    /// Spec: RFC 4120 5.1.1 — Kerberos messages obey DER; the option to accept
    /// BER ("MAY accept such encodings") is deliberately not taken (fail closed).
    Der(parse_asn1::Error),

    /// The input is longer than [`crate::limits::MAX_MESSAGE_LEN`].
    /// Resource bound (docs/CLEAN-ROOM.md), not an RFC 4120 rule.
    MessageTooLarge,

    /// An `[APPLICATION n]` value was required but a value of another class was
    /// found. Spec: RFC 4120 5.10 (application tag numbers), Appendix A.
    ExpectedApplicationTag,

    /// An `[APPLICATION n]` value carried a tag number other than the one the
    /// type requires — including unrecognized message types and tag numbers
    /// greater than 30. Spec: RFC 4120 5.1.4, 5.1.5 (return an error), 5.10;
    /// 5.4.2 compatibility note (the relaxed EncASRepPart/EncTGSRepPart tag
    /// check is not taken).
    UnexpectedApplicationTag,

    /// A SEQUENCE or SEQUENCE OF was required but another type was found.
    /// Spec: X.690 8.9, 8.10; RFC 4120 Appendix A.
    ExpectedSequence,

    /// A component of a SEQUENCE was not an explicit context tag `[n]`. Every
    /// component of every SEQUENCE type in scope is context-tagged.
    /// Spec: RFC 4120 §5 module header "DEFINITIONS EXPLICIT TAGS", Appendix A.
    ExpectedContextTag,

    /// A SEQUENCE component carried a context tag number that the type does not
    /// define. The Appendix A module has no extension marker, and RFC 4120 1.5
    /// / 1.5.1 state that extension is by typed holes, not by adding fields.
    /// The RFC 6113 Appendix B (FAST) types do end in an extension marker;
    /// an undefined component is rejected there too until it is defined (fail
    /// closed; see docs/questions/Q-032).
    /// Spec: RFC 4120 1.5, 1.5.1, 5.1.4, 5.1.5 (fail closed: return an error);
    /// RFC 6113 Appendix B.
    UnknownField,

    /// A CHOICE value was not one of the alternatives its type defines: it was
    /// not a context tag, or its context tag number selects no alternative.
    /// PA-FX-FAST-REQUEST and PA-FX-FAST-REPLY define only `armored-data [0]`;
    /// their extension marker leaves room for future alternatives, none of
    /// which is accepted until it is defined (fail closed; see
    /// docs/questions/Q-032).
    /// Spec: RFC 6113 5.4.2, 5.4.3, Appendix B; X.690 8.13 (a choice value is
    /// encoded as the chosen alternative, carrying that alternative's tag).
    UnknownChoiceAlternative,

    /// SEQUENCE components were not in the order of their definition
    /// (ascending context tag numbers in every RFC 4120 type).
    /// Spec: X.690 8.9.2, 8.9.3.
    FieldOutOfOrder,

    /// The same SEQUENCE component appeared more than once.
    /// Spec: X.690 8.9.2 (one data value per component).
    DuplicateField,

    /// A component that is not OPTIONAL was absent.
    /// Spec: X.690 8.9.2; RFC 4120 Appendix A (fields without OPTIONAL).
    MissingField,

    /// An INTEGER was required (Int32, UInt32, Microseconds, pvno, msg-type).
    /// Spec: RFC 4120 5.2.4, Appendix A.
    ExpectedInteger,

    /// An OCTET STRING was required. Spec: RFC 4120 Appendix A.
    ExpectedOctetString,

    /// A GeneralString (KerberosString) was required.
    /// Spec: RFC 4120 5.2.1, Appendix A.
    ExpectedGeneralString,

    /// A GeneralizedTime (KerberosTime) was required.
    /// Spec: RFC 4120 5.2.3, Appendix A.
    ExpectedGeneralizedTime,

    /// A BIT STRING (KerberosFlags) was required.
    /// Spec: RFC 4120 5.2.8, Appendix A.
    ExpectedBitString,

    /// An Int32 was outside -2147483648..2147483647.
    /// Spec: RFC 4120 5.2.4 (`Int32 ::= INTEGER (-2147483648..2147483647)`).
    Int32OutOfRange,

    /// A UInt32 was outside 0..4294967295 (negative values are rejected; the
    /// seq-number "MAY accept the equivalent negative number" option of
    /// RFC 4120 5.5.1 is not taken — fail closed).
    /// Spec: RFC 4120 5.2.4 (`UInt32 ::= INTEGER (0..4294967295)`).
    UInt32OutOfRange,

    /// A Microseconds value was outside 0..999999.
    /// Spec: RFC 4120 5.2.4 (`Microseconds ::= INTEGER (0..999999)`).
    MicrosecondsOutOfRange,

    /// pvno / tkt-vno / authenticator-vno was not 5.
    /// Spec: RFC 4120 5.2.4 ("always the constant integer 5"), 7.5.6.
    InvalidPvno,

    /// msg-type was outside the values the ASN.1 module permits for the type.
    /// Spec: RFC 4120 Appendix A (e.g. `INTEGER (10 -- AS -- | 12 -- TGS --)`).
    InvalidMsgType,

    /// msg-type was a permitted value but did not match the enclosing
    /// application tag (e.g. msg-type 12 inside an `[APPLICATION 10]` AS-REQ).
    /// Spec: RFC 4120 5.4.1 ("For the KDC-REQ message, this type will be
    /// KRB_AS_REQ or KRB_TGS_REQ"), 5.4.2, 5.2.4; fail closed.
    MsgTypeMismatch,

    /// A KerberosString contained an octet outside the IA5String repertoire
    /// (any octet >= 0x80). The option to accept non-IA5 GeneralString values
    /// ("MAY choose to accept") is not taken — fail closed.
    /// Spec: RFC 4120 5.2.1 (`KerberosString ::= GeneralString (IA5String)`);
    /// X.680 Table 8 (IA5String: register entries 1, 6 + SPACE + DELETE).
    /// See docs/questions/Q-031 (interop impact).
    NonIa5Character,

    /// A KerberosString contained a US-ASCII control character (0x00-0x1F or
    /// 0x7F, which includes NUL and the ISO 2022 ESC that would start a
    /// character-set designation). RFC 4120 says control characters "should
    /// not be used" in KerberosString and "SHOULD NOT be used in principal
    /// names or realm names", and that realms "shall not contain" NUL; this
    /// crate rejects them everywhere (fail closed). See docs/questions/Q-031.
    /// Spec: RFC 4120 5.2.1, 5.2.2.
    ControlCharacter,

    /// A KerberosTime carried fractional seconds.
    /// Spec: RFC 4120 5.2.3 ("shall not include any fractional portions of the
    /// seconds").
    FractionalKerberosTime,

    /// A KerberosTime was not a valid calendar date and UTC time of day
    /// (month 01-12, day within the month, hour 00-23, minute 00-59,
    /// second 00-59). Spec: X.680 46.2, 46.3; X.690 11.7.5 (hour 24 is not
    /// valid); RFC 4120 5.2.3. See docs/questions/Q-030 (leap seconds).
    InvalidKerberosTime,

    /// A KerberosFlags value was not exactly 32 bits. Fewer than 32 bits: the
    /// lenient "MAY choose to accept fewer than 32 bits" option is not taken.
    /// More than 32 bits: no use defines more than 32 flags and the minimum
    /// number of bits "shall be sent" — fail closed.
    /// Spec: RFC 4120 5.2.8 (`BIT STRING (SIZE (32..MAX))`).
    KerberosFlagsLength,

    /// A SEQUENCE OF whose ASN.1 type requires at least one element was empty.
    /// Spec: RFC 4120 5.2.7.5 (`ETYPE-INFO2 ::= SEQUENCE SIZE (1..MAX) OF ...`).
    EmptySequenceOf,

    /// A SEQUENCE OF had more elements than this crate's documented bound for
    /// that field (see [`crate::limits`]). Resource bound (docs/CLEAN-ROOM.md).
    TooManyElements,

    /// A ChangePasswdData `newpasswd` was longer than
    /// [`crate::limits::MAX_NEWPASSWD_LEN`] octets. A distinct variant so
    /// keyd can answer it with the PasswordRefused verdict (SOFTERROR), as
    /// docs/53 §5.7 asks for a password that is "too long".
    /// Spec: docs/53 §5.4 item 4, §5.9 (project bound; RFC 3244 §2 states
    /// none).
    NewPasswdTooLong,

    /// Change-password result data was not exactly the two octets of a result
    /// code: shorter is truncated; longer would carry a result string, which
    /// this project never sends and does not accept.
    /// Spec: RFC 3244 §2 ("result code (16 bits)"; the result string "may be
    /// omitted"); docs/questions/Q-604 item 5 (always omitted).
    ResultDataLength,

    /// A change-password result code outside the values RFC 3244 §2 defines
    /// (0-7). 0xFFFF ("some other reason") is outside the closed set: this
    /// project never sends it.
    /// Spec: RFC 3244 §2 ("The result code must have one of the following
    /// values"); docs/questions/Q-604 item 4.
    UnknownResultCode,

    /// Result code 0 (KRB5_KPASSWD_SUCCESS) where only a failure code is
    /// allowed.
    /// Spec: RFC 3244 §2 (SUCCESS "is not allowed in a KRB-ERROR message").
    SuccessNotAllowed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::Der(inner) => return write!(f, "DER layer rejected the input: {inner}"),
            Error::MessageTooLarge => "message exceeds the size bound",
            Error::ExpectedApplicationTag => "expected an APPLICATION-class tag",
            Error::UnexpectedApplicationTag => "APPLICATION tag number not valid here",
            Error::ExpectedSequence => "expected a SEQUENCE",
            Error::ExpectedContextTag => "SEQUENCE component is not context-tagged",
            Error::UnknownField => "context tag number not defined for this type",
            Error::UnknownChoiceAlternative => "value is not a defined CHOICE alternative",
            Error::FieldOutOfOrder => "SEQUENCE components out of definition order",
            Error::DuplicateField => "SEQUENCE component repeated",
            Error::MissingField => "required SEQUENCE component absent",
            Error::ExpectedInteger => "expected an INTEGER",
            Error::ExpectedOctetString => "expected an OCTET STRING",
            Error::ExpectedGeneralString => "expected a GeneralString",
            Error::ExpectedGeneralizedTime => "expected a GeneralizedTime",
            Error::ExpectedBitString => "expected a BIT STRING",
            Error::Int32OutOfRange => "Int32 value out of range",
            Error::UInt32OutOfRange => "UInt32 value out of range",
            Error::MicrosecondsOutOfRange => "Microseconds value out of range",
            Error::InvalidPvno => "protocol version number is not 5",
            Error::InvalidMsgType => "msg-type value not permitted for this type",
            Error::MsgTypeMismatch => "msg-type does not match the application tag",
            Error::NonIa5Character => "KerberosString octet outside IA5String",
            Error::ControlCharacter => "KerberosString contains a control character",
            Error::FractionalKerberosTime => "KerberosTime has fractional seconds",
            Error::InvalidKerberosTime => "KerberosTime is not a valid UTC date-time",
            Error::KerberosFlagsLength => "KerberosFlags is not exactly 32 bits",
            Error::EmptySequenceOf => "SEQUENCE OF must not be empty here",
            Error::TooManyElements => "SEQUENCE OF exceeds its element bound",
            Error::NewPasswdTooLong => "newpasswd exceeds its length bound",
            Error::ResultDataLength => "result data is not exactly a 16-bit result code",
            Error::UnknownResultCode => "result code value not defined",
            Error::SuccessNotAllowed => "result code 0 where a failure code is required",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Der(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<parse_asn1::Error> for Error {
    fn from(inner: parse_asn1::Error) -> Self {
        Error::Der(inner)
    }
}
