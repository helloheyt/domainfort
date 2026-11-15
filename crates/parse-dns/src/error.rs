//! Error type of the DNS codec.
//!
//! Hand-rolled, zero-dependency (docs/CLEAN-ROOM.md). Every variant names one rule
//! the decoder (or, for [`Error::InvalidValue`], the encoder) enforces. Fail
//! closed: malformed input is always a distinct `Err`, never a panic and never
//! a silent repair (docs/CLEAN-ROOM.md; docs/54 §6.1).
//!
//! What the server answers for each error is the caller's policy (docs/54
//! §6.6, task DN2): e.g. [`Error::MessageTooLarge`] on UDP is silence,
//! [`Error::UnexpectedDirection`] is silence, [`Error::UnsupportedOpcode`] is
//! NOTIMP from the header alone ([`crate::decode_header`]), and the others are
//! FORMERR on TCP (when the header decoded) and silence on UDP.
//!
//! Security: no variant carries attacker-supplied octets — only which rule
//! failed.

use core::fmt;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A message section, named as in RFC 1035 §4.1 (for UPDATE, RFC 2136 §2 calls
/// them Zone, Prerequisite, Update and Additional Data, in the same order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// Question section (UPDATE: Zone section). Spec: RFC 1035 §4.1.2; RFC
    /// 2136 §2.3.
    Question,
    /// Answer section (UPDATE: Prerequisite section). Spec: RFC 1035 §4.1.3;
    /// RFC 2136 §2.4.
    Answer,
    /// Authority section (UPDATE: Update section). Spec: RFC 1035 §4.1.3; RFC
    /// 2136 §2.5.
    Authority,
    /// Additional section (UPDATE: Additional Data section). Spec: RFC 1035
    /// §4.1.3; RFC 2136 §2.6.
    Additional,
}

/// A decode or encode failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    // ---- message framing ----------------------------------------------------
    /// The input ended inside a field (including a header shorter than 12
    /// octets, and a field running past the end of the message).
    /// Spec: RFC 1035 §4.1 (every section has its stated format).
    Truncated,

    /// The message is longer than the transport allows: 512 octets on UDP,
    /// 65535 on TCP (and for forwarded messages).
    /// Spec: RFC 1035 §2.3.4, §4.2.1, §4.2.2; docs/54 §6.2.
    MessageTooLarge,

    /// Octets remained after the last record the header counts.
    /// Spec: docs/54 §6.2 ("after the last record — exactly the end of the
    /// message"); docs/50 §3.3 (no trailing octet).
    TrailingData,

    /// QR does not match the profile: a response where a request was expected
    /// (dnsd stays silent — docs/54 §6.6), or a request where the profile
    /// decodes the server's responses. Spec: RFC 1035 §4.1.1 (QR).
    UnexpectedDirection,

    /// The opcode is not one the profile decodes (IQUERY, STATUS and the
    /// reserved values; QUERY in the forwarded profile). The header alone is
    /// enough to answer NOTIMP. Spec: RFC 1035 §4.1.1 (OPCODE); RFC 2136 §3;
    /// RFC 1034 §3.7.2; docs/54 §3.2.
    UnsupportedOpcode,

    /// A section count is outside the profile's bound (docs/54 §6.2), or more
    /// than the one question the model holds.
    /// Spec: docs/54 §6.2; RFC 2136 §2.3 (exactly one zone).
    SectionCount(Section),

    /// The section counts cannot fit in the octets that follow the header,
    /// even with every name at its shortest. Checked before anything is
    /// allocated. Spec: RFC 1035 §4.1.1 (the counts number the entries
    /// present); docs/CLEAN-ROOM.md (no allocation from attacker-supplied counts).
    CountExceedsMessage,

    // ---- names --------------------------------------------------------------
    /// A length octet began with the bits `01` or `10`. This is also how a
    /// label longer than 63 octets shows on the wire.
    /// Spec: RFC 1035 §4.1.4 ("The 10 and 01 combinations are reserved for
    /// future use"), §3.1; docs/54 §6.2.
    ReservedLabelType,

    /// A name is longer than 255 octets after compression pointers are
    /// followed. Spec: RFC 1035 §2.3.4, §3.1; RFC 1034 §3.1; docs/54 §6.2.
    NameTooLong,

    /// A compression pointer's OFFSET is not strictly less than the pointer's
    /// own position (a forward or self pointer).
    /// Spec: RFC 1035 §4.1.4 ("a pointer to a prior occurance of the same
    /// name"); docs/54 §6.3.
    PointerNotBackward,

    /// A compression pointer points backwards, but not at the start of a
    /// label, a pointer or a terminating zero octet of a name already decoded
    /// from this message (e.g. into the header, into the middle of a label or
    /// an integer field, or into the name being decoded itself).
    /// Spec: RFC 1035 §4.1.4 (the target is "a prior occurance of the same
    /// name"); docs/questions/Q-640 (one hop per name by construction).
    PointerTarget,

    /// A compression pointer appeared where compression is not allowed: the
    /// SRV Target, the TSIG Algorithm Name, or anywhere in the canonical
    /// profile that verifies the server's own replies.
    /// Spec: RFC 2782 ("name compression is not to be used for this field");
    /// RFC 8945 §4.2 ("this name MUST NOT be compressed"); docs/54 §6.3.
    CompressionNotAllowed,

    /// A label was empty where a label must have content (only the
    /// terminating root label is empty). Raised by the name constructors.
    /// Spec: RFC 1034 §3.1 (the null label is reserved for the root).
    EmptyLabel,

    /// A label longer than 63 octets was given to a name constructor.
    /// Spec: RFC 1035 §2.3.4, §3.1.
    LabelTooLong,

    // ---- resource records ---------------------------------------------------
    /// RDLENGTH differs from the length of the RDATA decoded for a type the
    /// codec models (too short to hold it, or octets left over).
    /// Spec: RFC 1035 §3.2.1, §4.1.3, §4.1.4 (compressed length counts);
    /// docs/54 §6.2 ("equal exactly to the length of the decoded RDATA").
    RdataLength,

    /// A TSIG RR was not the last record of the additional section, or there
    /// was more than one. Spec: RFC 8945 §5.1, §5.2 ("If multiple TSIG
    /// records are detected or a TSIG record is present in any other position
    /// … FORMERR"); docs/54 §6.2.
    MisplacedTsig,

    /// A TSIG RR that cannot be interpreted: CLASS not ANY, TTL not 0, or a
    /// non-zero Error in a request. Spec: RFC 8945 §4.2 ("CLASS: This MUST be
    /// ANY", "TTL: This MUST be 0", Error "In requests, this MUST be zero"),
    /// §5.2 ("cannot be interpreted … FORMERR").
    MalformedTsig,

    /// A TSIG MAC Size above 64. Spec: docs/54 §6.2; RFC 8945 §5.2.2.1.
    TsigMacTooLong,

    /// A forwarded UPDATE carries no TSIG: dird never decodes an unsigned
    /// UPDATE (dnsd refuses those itself). Spec: docs/54 §4.5 step 1, §6.2
    /// ("ADCOUNT = 1 (the TSIG)").
    MissingTsig,

    /// The Additional Data section of an UPDATE request holds a record other
    /// than the TSIG. Spec: docs/questions/Q-615 item 8 (FORMERR); docs/54
    /// §5.5 ("Additional — only the TSIG"); RFC 2136 §2.6.
    UnexpectedRecord,

    // ---- encoder only -------------------------------------------------------
    /// The value has no encoding the decoder would read back as the same
    /// value: a record whose RDATA was skipped on decode (the octets were
    /// never retained), typed RDATA under a class other than IN or NONE,
    /// empty RDATA under a class other than ANY or NONE, a TSIG-typed record
    /// outside the TSIG slot, or flag bits set in an UPDATE header (RFC 2136
    /// §2.2: UPDATE uses only QR). Spec: docs/54 §6.3 (the server never emits
    /// what it cannot parse back).
    InvalidValue,
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Section::Question => "question/zone",
            Section::Answer => "answer/prerequisite",
            Section::Authority => "authority/update",
            Section::Additional => "additional",
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Error::Truncated => "message ends inside a field",
            Error::MessageTooLarge => "message is larger than its transport allows",
            Error::TrailingData => "octets follow the last counted record",
            Error::UnexpectedDirection => "query/response bit does not match the profile",
            Error::UnsupportedOpcode => "opcode not handled by this profile",
            Error::SectionCount(section) => {
                return write!(f, "{section} section count outside the profile bound")
            }
            Error::CountExceedsMessage => "section counts cannot fit in the message",
            Error::ReservedLabelType => "length octet uses a reserved label type",
            Error::NameTooLong => "domain name longer than 255 octets",
            Error::PointerNotBackward => "compression pointer does not point backwards",
            Error::PointerTarget => "compression pointer target is not a decoded name position",
            Error::CompressionNotAllowed => "compression pointer where compression is not allowed",
            Error::EmptyLabel => "empty label inside a domain name",
            Error::LabelTooLong => "label longer than 63 octets",
            Error::RdataLength => "RDLENGTH does not match the record data",
            Error::MisplacedTsig => "TSIG record is not the single last additional record",
            Error::MalformedTsig => "TSIG record fields cannot be interpreted",
            Error::TsigMacTooLong => "TSIG MAC longer than the bound",
            Error::MissingTsig => "forwarded update carries no TSIG",
            Error::UnexpectedRecord => "update additional section holds a non-TSIG record",
            Error::InvalidValue => "value has no canonical encoding",
        };
        f.write_str(text)
    }
}

impl std::error::Error for Error {}
