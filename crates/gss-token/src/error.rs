//! Errors of the token codecs.
//!
//! Hand-rolled, no dependency (docs/CLEAN-ROOM.md). Every variant names the one rule
//! of RFC 2743 §3.1, RFC 4121 or the docs/60 profile (Q-1093, A-193) that the
//! input broke. No variant carries an input octet — not of a token, a Kerberos
//! message, a `Bnd` value or a plaintext — so nothing of a token can leak
//! through an error, its `Debug` or its `Display` (docs/CLEAN-ROOM.md; docs/60 §7:
//! no token, Bnd or EKM is logged). keyd maps every variant to its uniform
//! `Denied` with an audit reason (docs/60 §3.4, §7).

use core::fmt;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A refused token, field or construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    // -----------------------------------------------------------------------
    // RFC 2743 §3.1 framing — context-establishment tokens
    // -----------------------------------------------------------------------
    /// The token is longer than [`crate::limits::MAX_CONTEXT_TOKEN_LEN`]
    /// (checked before any other octet), or a token to encode would be.
    /// Spec: docs/60 R60-11; docs/CLEAN-ROOM.md.
    ContextTokenTooLong,

    /// The input ended inside a fixed element: the tag, the length octets, the
    /// OID tag, or the two-octet TOK_ID.
    /// Spec: RFC 2743 §3.1 elements 1–5; RFC 4121 §4.1.
    Truncated,

    /// The first octet is not 0x60, the tag for [APPLICATION 0] SEQUENCE.
    /// Spec: RFC 2743 §3.1 element 1.
    BadTokenTag,

    /// A length whose first octet is 0x80: the long form with no subsequent
    /// octet ("two or more octets" are required when the high bit is set).
    /// Spec: RFC 2743 §3.1 element 2b.
    MalformedLength,

    /// A length not in the minimum number of octets: the long form for a value
    /// below 128, or a leading zero octet.
    /// Spec: RFC 2743 §3.1 elements 2a, 2b ("The minimum number of octets
    /// shall be used to encode the length").
    NonMinimalLength,

    /// A declared length (the token length or the OID length) runs past the
    /// octets present.
    /// Spec: RFC 2743 §3.1 elements 2, 4.
    LengthExceedsInput,

    /// Octets follow the token: the token length covers fewer octets than
    /// were given. Spec: RFC 2743 §3.1 element 2 (the length of all the
    /// subsequent data); docs/60 §3.4 step 2 ("no trailing octets").
    TrailingOctets,

    /// The element after the token length is not 0x06, the tag for OBJECT
    /// IDENTIFIER. Spec: RFC 2743 §3.1 element 3.
    BadOidTag,

    /// The mechanism OID is the truncated Kerberos OID 1.2.840.48018.1.2.2 of
    /// [MS-KILE] 3.1.1.7 — recognised only to be refused in phase 1.
    /// Spec: [MS-KILE] 3.1.1.7; docs/60 §3.4 step 2, §10.1; Q-1093 item 11.
    TruncatedKerberosOid,

    /// The mechanism OID is not the Kerberos V5 OID 1.2.840.113554.1.2.2.
    /// Spec: [MS-KILE] 1.9.1; RFC 4752 §3 (the GSSAPI SASL mechanism is tied
    /// to the Kerberos V5 mechanism); docs/60 §10.1.
    UnsupportedMechanism,

    /// The TOK_ID is not the one the caller expects (KRB_AP_REQ 01 00 in an
    /// initial context token). An unknown TOK_ID is refused rather than
    /// answered with a KRB_ERROR token — a recorded deviation from RFC 4121
    /// §4.1. Spec: RFC 4121 §4.1; docs/60 §3.4 step 2, R60-8; Q-1093 item 9.
    UnexpectedTokId,

    /// No Kerberos message follows the TOK_ID ("followed by a Kerberos
    /// message"), or an empty message was given to encode.
    /// Spec: RFC 4121 §4.1.
    MissingKerberosMessage,

    // -----------------------------------------------------------------------
    // RFC 4121 §4.1.1 — the authenticator checksum
    // -----------------------------------------------------------------------
    /// The Authenticator has no `cksum`: "The authenticator in the
    /// KRB_AP_REQ message MUST include ... the checksum field".
    /// Spec: RFC 4121 §4.1.1; RFC 4120 §5.5.1.
    MissingChecksum,

    /// The Authenticator has no `seq-number`: it "MUST include the optional
    /// sequence number". Spec: RFC 4121 §4.1.1; RFC 4120 §5.5.1; Q-1093 item 5.
    MissingSequenceNumber,

    /// The `cksumtype` is not 0x8003 ("The checksum type MUST be 0x8003").
    /// Spec: RFC 4121 §4.1.1.
    WrongChecksumType,

    /// The checksum field is shorter than 24 octets.
    /// Spec: RFC 4121 §4.1.1.
    ChecksumTooShort,

    /// The checksum field is longer than
    /// [`crate::limits::MAX_CONTEXT_TOKEN_LEN`] — longer than the token that
    /// carries it could be. Spec: docs/60 R60-11; docs/CLEAN-ROOM.md.
    ChecksumTooLong,

    /// The `Lgth` field is not 16. Spec: RFC 4121 §4.1.1.
    LgthNot16,

    /// GSS_C_DELEG_FLAG is set: delegation is refused (there is no KRB_CRED
    /// path). Spec: RFC 4121 §4.1.1, §4.1.1.1; docs/60 §3.4 step 4, §10.1;
    /// Q-1093 item 3.
    DelegationRefused,

    /// GSS_C_INTEG_FLAG is not set. Spec: RFC 4121 §4.1.1.1; RFC 4752 §3.1
    /// (the client MUST request integrity); docs/60 §3.4 step 4; Q-1093
    /// item 2.
    IntegFlagMissing,

    /// GSS_C_MUTUAL_FLAG is not set. Spec: RFC 4121 §4.1.1.1; docs/60 §3.2,
    /// §3.4 step 4; Q-1093 item 1.
    MutualFlagMissing,

    /// `Bnd` is 16 zero-valued octets — GSS_C_NO_BINDINGS — and channel
    /// binding is mandatory in this profile.
    /// Spec: RFC 4121 §4.1.1.2 (3); docs/60 R60-1, §3.4 step 4, §10.1.
    NoChannelBindings,

    // -----------------------------------------------------------------------
    // RFC 4121 §4.2.6.2 — Wrap tokens
    // -----------------------------------------------------------------------
    /// The first octet of a per-message token is 0x60: the generic GSS-API
    /// framing of the older token format, which this profile never accepts.
    /// Spec: RFC 4121 §4.4, §6; docs/60 §3.4.
    FramedToken,

    /// The TOK_ID of a per-message token is not 05 04 (Wrap).
    /// Spec: RFC 4121 §4.2.6.2.
    NotWrapToken,

    /// The Filler octet is not 0xFF. Spec: RFC 4121 §4.2.6.2.
    BadFiller,

    /// The Sealed flag is set: the profile offers no security layer, so no
    /// Wrap token with confidentiality is accepted, and none is ever built.
    /// Spec: RFC 4121 §4.2.2; RFC 4752 §3.1 (the selection is wrapped with
    /// conf_flag FALSE); docs/60 §3.4, §10.1; Q-1093 item 6.
    Sealed,

    /// The SentByAcceptor flag does not match the sender the caller expects
    /// (the direction indicator). Spec: RFC 4121 §4.2.2; docs/60 §9 K12.
    DirectionMismatch,

    /// The AcceptorSubkey flag does not match whether the acceptor asserted a
    /// subkey. Spec: RFC 4121 §2, §4.2.2; docs/60 §3.4; Q-1093 item 4.
    AcceptorSubkeyMismatch,

    /// EC is not the checksum length the caller expects (in a Wrap token
    /// without confidentiality EC is "the number of octets in the trailing
    /// checksum"). Spec: RFC 4121 §4.2.3, §4.2.4; docs/60 §3.4.
    EcMismatch,

    /// The Wrap token is longer than [`crate::limits::MAX_WRAP_TOKEN_LEN`],
    /// or a token to build would be. Spec: docs/60 R60-11; docs/CLEAN-ROOM.md.
    WrapTokenTooLong,

    /// The octets after the header are fewer than EC: there is no room for
    /// the checksum. Spec: RFC 4121 §4.2.4, §4.2.6.2.
    WrapBodyTooShort,

    /// The checksum given to finish a Wrap token is not the announced
    /// length. Spec: RFC 4121 §4.2.3, §4.2.4.
    ChecksumLengthMismatch,

    /// The caller's verification of the Wrap token's checksum failed; the
    /// plaintext is not released. Spec: RFC 4121 §4.2.4; RFC 4752 §3
    /// (an unsuccessful GSS_Unwrap fails the authentication).
    ChecksumMismatch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Error::ContextTokenTooLong => "context-establishment token over the size bound",
            Error::Truncated => "token ends inside a fixed element",
            Error::BadTokenTag => "token tag is not 0x60",
            Error::MalformedLength => "length octet 0x80 has no subsequent octets",
            Error::NonMinimalLength => "length not in the minimum number of octets",
            Error::LengthExceedsInput => "declared length exceeds the octets present",
            Error::TrailingOctets => "octets follow the token",
            Error::BadOidTag => "mechanism tag is not 0x06",
            Error::TruncatedKerberosOid => "truncated Kerberos OID is refused",
            Error::UnsupportedMechanism => "mechanism is not Kerberos V5",
            Error::UnexpectedTokId => "TOK_ID is not the expected one",
            Error::MissingKerberosMessage => "no Kerberos message after the TOK_ID",
            Error::MissingChecksum => "authenticator has no checksum",
            Error::MissingSequenceNumber => "authenticator has no sequence number",
            Error::WrongChecksumType => "checksum type is not 0x8003",
            Error::ChecksumTooShort => "checksum field shorter than 24 octets",
            Error::ChecksumTooLong => "checksum field over the size bound",
            Error::LgthNot16 => "Lgth field is not 16",
            Error::DelegationRefused => "delegation flag is refused",
            Error::IntegFlagMissing => "integrity flag not set",
            Error::MutualFlagMissing => "mutual flag not set",
            Error::NoChannelBindings => "Bnd carries no channel bindings",
            Error::FramedToken => "per-message token in the framed format",
            Error::NotWrapToken => "TOK_ID is not 05 04",
            Error::BadFiller => "Filler is not 0xFF",
            Error::Sealed => "Sealed flag is refused",
            Error::DirectionMismatch => "SentByAcceptor flag does not match the sender",
            Error::AcceptorSubkeyMismatch => "AcceptorSubkey flag does not match",
            Error::EcMismatch => "EC is not the expected checksum length",
            Error::WrapTokenTooLong => "Wrap token over the size bound",
            Error::WrapBodyTooShort => "Wrap token body shorter than EC",
            Error::ChecksumLengthMismatch => "checksum is not the announced length",
            Error::ChecksumMismatch => "Wrap token checksum not verified",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for Error {}
