//! Distinguished names: a strict, bounded RFC 4514 parser, the canonical
//! RFC 4514 §2 string encoder, the RDN comparison key, and the one alternative
//! form docs/49 admits, `<GUID=hex>` (docs/49 R49-11, build task L5).
//!
//! # Accepted input ([`parse_ldap_dn`])
//!
//! An LDAPDN is "`Constrained to <distinguishedName> [RFC4514]`" (RFC 4511
//! §4.1.3). Two forms are accepted:
//!
//! * an RFC 4514 §3 `distinguishedName`, possibly empty (zero RDNs — the
//!   rootDSE base), into a typed [`Dn`];
//! * the [MS-ADTS] 3.1.1.3.1.2.4 alternative form `<GUID=object_guid>`, with
//!   `object_guid` "the hexadecimal representation of the binary form of a
//!   GUID ([MS-DTYP] section 2.3.4)", into the 16 octets of that binary form
//!   ([`LdapDn::ObjectGuid`]).
//!
//! Every other `<…>` form — `<SID=…>`, `<WKGUID=…>`, the TTL-DN, the
//! "extended DN" `<GUID=…>;…`, and the dashed GUID string (defined only by
//! RFC 4122, which is not an allowed source) — is refused (docs/49 §7, §14).
//!
//! # Refusals and the result code the engine maps them to
//!
//! The whole input is checked against the grammar first; only a syntactically
//! valid DN can earn a phase-1 refusal, and then the leftmost one is reported.
//! The mapping to an LDAP resultCode is the engine's (docs/49 §9); the
//! recommendation per group, recorded in docs/questions/Q-195:
//!
//! | group | [`DnError`] variants | recommended resultCode |
//! |---|---|---|
//! | bounds, grammar (RFC 4514 §3), `<GUID=…>` syntax, other `<…>` forms | `TooLong`, `TooManyRdns`, `AttributeTypeTooLong`, `EmptyRdn`, `InvalidAttributeType`, `MissingEquals`, `UnescapedCharacter`, `InvalidEscape`, `InvalidHexString`, `InvalidObjectGuid`, `UnsupportedExtendedForm` | `invalidDNSyntax` (docs/49 §9) |
//! | multi-valued RDN | `MultiValuedRdn` | `invalidDNSyntax` ([MS-ADTS] 3.1.1.3.1.2.3; docs/49 §7) |
//! | a well-formed DN that cannot name a phase-1 object | `ValueNotPrintableAscii`, `EmptyValue`, `ValueTooLong`, `HexStringValue` | `noSuchObject` in a search, `namingViolation` in an add (docs/49 §7, ASCII rule) |
//!
//! # Values
//!
//! A value is unescaped per RFC 4514 §3, then must be **printable ASCII**,
//! octets `0x20..=0x7E` (Q-080 interim, PENDING-OWNER P-9; the same rule
//! dirstore computes the RDN key with). The value is kept exactly as
//! unescaped: the A–Z fold is applied only by [`Rdn::comparison_key`], never
//! to the value itself.
//!
//! # Canonical output
//!
//! [`Dn::encode`] is the RFC 4514 §2 algorithm. `directory_pip::DirectoryView::dn_of`
//! does not emit a string: it emits `pdp::Dn`, the RDN components
//! `<lDAPDisplayName>=<stored value>` **unescaped**, leaf first. Joined with
//! `,`, those components equal [`Dn::encode`] of
//! [`Dn::from_directory_rdns`] exactly when no value holds a character
//! RFC 4514 §2.4 requires escaping. The PDP always receives the `dn_of`
//! components (R49-11) — never a DN parsed from a client.
//!
//! # Provenance
//!
//! Written only from sources opened in this session (docs/CLEAN-ROOM.md): RFC 4511
//! §4.1.3; RFC 4514 (§1, §2.1–§2.4, §3, §4, §5, App. A, App. B); RFC 4512
//! §1.4, §2.5; RFC 4517
//! §3.3.9; [MS-ADTS] v20261026 3.1.1.1.4, 3.1.1.3.1.2.1–3.1.1.3.1.2.5,
//! 3.1.1.3.4.1.5, 3.1.1.5.1.2; [MS-DTYP] v20241119 2.3.4, 2.3.4.1, 2.3.4.2;
//! docs/49 R49-11, §7, §9; docs/46 §8.3; Q-080; Q-090 (A-30). No other
//! implementation was consulted or recalled.

use core::fmt;

use crate::limits::{MAX_DN_RDNS, MAX_IDENTIFIER_OCTETS, MAX_LDAPDN_OCTETS, MAX_RDN_VALUE_OCTETS};

/// Octets in the binary form of a GUID. Spec: [MS-DTYP] 2.3.4 ("a 16-byte
/// structure").
pub const OBJECT_GUID_OCTETS: usize = 16;

/// The literal that opens the GUID alternative form, exactly as printed.
/// Spec: [MS-ADTS] 3.1.1.3.1.2.4 (`<GUID=object_guid>`). Only "TTL" is given a
/// case-insensitive rule there, so the literal is matched as printed (Q-195 item 1).
const GUID_FORM_PREFIX: &str = "<GUID=";

/// The literal that closes the GUID alternative form. Spec: [MS-ADTS]
/// 3.1.1.3.1.2.4.
const GUID_FORM_SUFFIX: u8 = b'>';

// Character productions used by the grammar. Spec: RFC 4512 §1.4.
const SPACE: u8 = 0x20;
const DQUOTE: u8 = 0x22;
const SHARP: u8 = 0x23;
const PLUS: u8 = 0x2B;
const COMMA: u8 = 0x2C;
const HYPHEN: u8 = 0x2D;
const DOT: u8 = 0x2E;
const SEMI: u8 = 0x3B;
const LANGLE: u8 = 0x3C;
const EQUALS: u8 = 0x3D;
const RANGLE: u8 = 0x3E;
const ESC: u8 = 0x5C;
const NULL: u8 = 0x00;

/// An LDAPDN as the engine receives it: a parsed RFC 4514 name, or the GUID
/// of the object it designates.
///
/// Spec: RFC 4511 §4.1.3 (LDAPDN); RFC 4514 §3; [MS-ADTS] 3.1.1.3.1.2.4;
/// docs/49 R49-11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapDn {
    /// An RFC 4514 `distinguishedName` (empty for the zero-RDN name).
    Distinguished(Dn),
    /// `<GUID=object_guid>`: the 16 octets of the GUID's binary form, in the
    /// order the hexadecimal digits give them. That order is the [MS-DTYP]
    /// 2.3.4.2 packet representation (Data1, Data2, Data3 little-endian, then
    /// Data4), so the engine converts with `dtyp::Guid::from_packet`.
    ///
    /// Spec: [MS-ADTS] 3.1.1.3.1.2.4 ("the hexadecimal representation of the
    /// binary form of a GUID ([MS-DTYP] section 2.3.4)"); [MS-DTYP] 2.3.4.2;
    /// the order is confirmed by the [MS-ADTS] 3.1.1.3.4.1.5 example, which
    /// prints one GUID in both the hexadecimal and the dashed form.
    ObjectGuid([u8; OBJECT_GUID_OCTETS]),
}

/// A distinguished name: its RDNs in string order — the leaf first, the
/// naming-context root last (RFC 4514 §2.1 writes the RDNSequence "starting
/// with the last element"), the same order as `pdp::Dn`.
///
/// Every value of this type encodes ([`Dn::encode`]) to at most
/// [`MAX_LDAPDN_OCTETS`] octets and parses back to itself.
///
/// Spec: RFC 4514 §2, §3; [MS-ADTS] 3.1.1.1.4 (DN = RDN "," parent DN).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dn {
    rdns: Vec<Rdn>,
}

/// A single-valued relative distinguished name: one attributeType and one
/// value. A multi-valued RDN is not representable: Active Directory restricts
/// `RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue`
/// to "MAX equals 1".
///
/// Invariant: the value is non-empty printable ASCII of at most
/// [`MAX_RDN_VALUE_OCTETS`] octets.
///
/// Spec: RFC 4514 §2.2, §3; [MS-ADTS] 3.1.1.3.1.2.3; docs/46 §8.3 item 3;
/// Q-080.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rdn {
    attribute_type: AttributeType,
    value: String,
}

/// An `attributeType`: a `descr` or a `numericoid`, kept as spelled.
///
/// Equality is exact. Descriptors are case-insensitive and a numericoid can
/// name the same attribute as a descriptor (RFC 4512 §1.4; [MS-ADTS]
/// 3.1.1.1.4 "2.5.4.3=Peter Houston"); recognising an attribute type belongs
/// to the engine (ad-schema), not to this parser.
///
/// Spec: RFC 4514 §3 (`attributeType = descr / numericoid`); RFC 4512 §1.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeType(String);

/// Why a DN was refused. No variant carries input bytes (docs/CLEAN-ROOM.md).
///
/// See the module documentation for the resultCode each group maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnError {
    // ---- bounds -------------------------------------------------------------
    /// The input, or the encoding of a constructed [`Dn`], is longer than
    /// [`MAX_LDAPDN_OCTETS`]. Spec: docs/49 §2.4.
    TooLong,
    /// More than [`MAX_DN_RDNS`] RDNs. Spec: docs/49 §2.4.
    TooManyRdns,
    /// An attributeType longer than [`MAX_IDENTIFIER_OCTETS`].
    /// Spec: docs/questions/Q-185 item 10 (identifier bound).
    AttributeTypeTooLong,

    // ---- grammar ------------------------------------------------------------
    /// An RDN, or an attributeTypeAndValue after `+`, is empty (a leading,
    /// doubled or trailing `,`, or a trailing `+`). Spec: RFC 4514 §3
    /// (`relativeDistinguishedName = attributeTypeAndValue *( PLUS
    /// attributeTypeAndValue )`).
    EmptyRdn,
    /// The attributeType is neither a `descr` nor a `numericoid` (this
    /// includes attribute options, which RFC 4514 §3 does not allow, and a
    /// space anywhere around it). Spec: RFC 4514 §3; RFC 4512 §1.4.
    InvalidAttributeType,
    /// An attributeType is not followed by `=`. Spec: RFC 4514 §3
    /// (`attributeTypeAndValue = attributeType EQUALS attributeValue`).
    MissingEquals,
    /// A character appears unescaped where the `string` production forbids
    /// it: NUL, `"`, `;`, `<`, `>` anywhere, a leading or a trailing space.
    /// Spec: RFC 4514 §3 (LUTF1, SUTF1, TUTF1).
    UnescapedCharacter,
    /// `\` is not followed by `\`, a `special`, or a `hexpair`.
    /// Spec: RFC 4514 §3 (`pair = ESC ( ESC / special / hexpair )`).
    InvalidEscape,
    /// A value beginning with `#` is not `#` followed by one or more hexpairs.
    /// Spec: RFC 4514 §3 (`hexstring = SHARP 1*hexpair`).
    InvalidHexString,
    /// `<GUID=` is not followed by exactly 32 hexadecimal digits and `>`.
    /// Spec: [MS-ADTS] 3.1.1.3.1.2.4; [MS-DTYP] 2.3.4.
    InvalidObjectGuid,
    /// An alternative form other than `<GUID=hex>` (`<SID=…>`, `<WKGUID=…>`,
    /// TTL-DN, the extended DN `<GUID=…>;…`). Spec: [MS-ADTS] 3.1.1.3.1.2.4;
    /// docs/49 §7, §14.
    UnsupportedExtendedForm,

    // ---- phase-1 refusals of a well-formed DN -------------------------------
    /// A multi-valued RDN. Spec: [MS-ADTS] 3.1.1.3.1.2.3 ("considered an
    /// attempt to create a syntactically invalid DN"); docs/49 §7.
    MultiValuedRdn,
    /// A value in the `hexstring` form (the BER encoding of the value). Phase 1
    /// has no handler for BER-encoded values. Spec: RFC 4514 §2.4, §3; Q-195 item 12.
    HexStringValue,
    /// An empty value: no phase-1 object has one (the RDN attribute has
    /// exactly one value, and dirstore refuses an empty RDN key).
    /// Spec: [MS-ADTS] 3.1.1.1.4; docs/46 §8.3 item 3; Q-195 item 13.
    EmptyValue,
    /// After unescaping, the value holds an octet outside printable ASCII
    /// `0x20..=0x7E`. Spec: Q-080 item 1 (interim, P-9); [MS-ADTS] 3.1.1.5.1.2
    /// (no 0x00, no 0x0A); docs/49 §7.
    ValueNotPrintableAscii,
    /// After unescaping, the value is longer than [`MAX_RDN_VALUE_OCTETS`].
    /// Spec: [MS-ADTS] 3.1.1.5.1.2; Q-090 (A-30).
    ValueTooLong,
}

impl fmt::Display for DnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            DnError::TooLong => "distinguished name too long",
            DnError::TooManyRdns => "too many relative distinguished names",
            DnError::AttributeTypeTooLong => "attribute type too long",
            DnError::EmptyRdn => "empty relative distinguished name",
            DnError::InvalidAttributeType => "attribute type is neither a descriptor nor an OID",
            DnError::MissingEquals => "attribute type not followed by '='",
            DnError::UnescapedCharacter => "character must be escaped here",
            DnError::InvalidEscape => "invalid escape sequence",
            DnError::InvalidHexString => "invalid hex string value",
            DnError::InvalidObjectGuid => "GUID form is not 32 hexadecimal digits",
            DnError::UnsupportedExtendedForm => "alternative DN form not supported",
            DnError::MultiValuedRdn => "multi-valued relative distinguished name",
            DnError::HexStringValue => "hex string values are not supported",
            DnError::EmptyValue => "empty attribute value",
            DnError::ValueNotPrintableAscii => "attribute value is not printable ASCII",
            DnError::ValueTooLong => "attribute value too long",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for DnError {}

// ---- public API -------------------------------------------------------------

/// Parse an LDAPDN: an RFC 4514 `distinguishedName`, or `<GUID=hex>`.
///
/// The input bound is checked before anything is read. Input that begins with
/// `<` is an alternative form: an RFC 4514 name never begins with `<`
/// (attributeType begins with ALPHA or DIGIT, and `<` appears only escaped —
/// RFC 4514 §3, App. A).
///
/// Spec: RFC 4511 §4.1.3; RFC 4514 §3; [MS-ADTS] 3.1.1.3.1.2.4; docs/49
/// R49-11, §7.
pub fn parse_ldap_dn(input: &str) -> Result<LdapDn, DnError> {
    if input.len() > MAX_LDAPDN_OCTETS {
        return Err(DnError::TooLong);
    }
    if input.as_bytes().first() == Some(&LANGLE) {
        return parse_object_guid_form(input).map(LdapDn::ObjectGuid);
    }
    Dn::parse(input).map(LdapDn::Distinguished)
}

impl Dn {
    /// Parse an RFC 4514 `distinguishedName` (no alternative form).
    ///
    /// Spec: RFC 4514 §3; docs/49 §2.4 (bounds); [MS-ADTS] 3.1.1.3.1.2.3
    /// (single-valued RDNs); Q-080 (printable ASCII values).
    pub fn parse(input: &str) -> Result<Dn, DnError> {
        // Spec: docs/49 §2.4 — bound before reading.
        if input.len() > MAX_LDAPDN_OCTETS {
            return Err(DnError::TooLong);
        }
        distinguished_name(input.as_bytes())
    }

    /// Build a DN from RDNs in string order (leaf first).
    ///
    /// Refuses more than [`MAX_DN_RDNS`] RDNs and a DN whose encoding is
    /// longer than [`MAX_LDAPDN_OCTETS`], so that every [`Dn`] round-trips
    /// through [`Dn::encode`] and [`Dn::parse`].
    ///
    /// Spec: docs/49 §2.4; RFC 4514 §2.1.
    pub fn new(rdns: Vec<Rdn>) -> Result<Dn, DnError> {
        if rdns.len() > MAX_DN_RDNS {
            return Err(DnError::TooManyRdns);
        }
        let dn = Dn { rdns };
        if dn.encode().len() > MAX_LDAPDN_OCTETS {
            return Err(DnError::TooLong);
        }
        Ok(dn)
    }

    /// Build a DN from the directory's canonical RDN components — the
    /// `att=value` strings, unescaped and leaf first, that
    /// `directory_pip::DirectoryView::dn_of` puts in a `pdp::Dn`.
    ///
    /// Each component is split at its first `=`: an attributeType never holds
    /// `=` (`descr` and `numericoid`, RFC 4512 §1.4), while a value may. This
    /// is the path from a GUID to the RFC 4514 string of a response
    /// (`dn_of` → this → [`Dn::encode`]).
    ///
    /// Spec: [MS-ADTS] 3.1.1.1.4 (RDN = "att=val"); docs/47 §8.2; docs/49 §7.
    pub fn from_directory_rdns<S: AsRef<str>>(rdns: &[S]) -> Result<Dn, DnError> {
        if rdns.len() > MAX_DN_RDNS {
            return Err(DnError::TooManyRdns);
        }
        let mut out = Vec::with_capacity(rdns.len());
        for component in rdns {
            let (att, value) = component
                .as_ref()
                .split_once(char::from(EQUALS))
                .ok_or(DnError::MissingEquals)?;
            out.push(Rdn::new(AttributeType::new(att)?, value)?);
        }
        Dn::new(out)
    }

    /// The RDNs, leaf first.
    pub fn rdns(&self) -> &[Rdn] {
        &self.rdns
    }

    /// `true` for the zero-RDN name (the empty string).
    /// Spec: RFC 4514 §2.1, §3.
    pub fn is_empty(&self) -> bool {
        self.rdns.is_empty()
    }

    /// The RFC 4514 §2 string: the RDNs leaf first, separated by `,`; each
    /// `attributeType=value`, the value escaped where §2.4 requires it, by a
    /// backslash before the character (every character that must be escaped
    /// is one of those §2.4 allows to be escaped this way; NUL, the one that
    /// is not, never occurs in a printable-ASCII value). Nothing else is
    /// escaped, and the attributeType is written as held.
    ///
    /// A `numericoid` type is written with its value in string form, not as
    /// the `#`-hexstring §2.4 recommends: §2 admits other algorithms whose
    /// output conforms to §3, and this one does.
    ///
    /// Spec: RFC 4514 §2.1, §2.3, §2.4, §3.
    pub fn encode(&self) -> String {
        let mut out = String::new();
        for (i, rdn) in self.rdns.iter().enumerate() {
            // Spec: RFC 4514 §2.1 — adjoining RDNs separated by ','.
            if i > 0 {
                out.push(char::from(COMMA));
            }
            // Spec: RFC 4514 §2.3 — type, '=', value.
            out.push_str(rdn.attribute_type.as_str());
            out.push(char::from(EQUALS));
            escape_value(&rdn.value, &mut out);
        }
        out
    }
}

impl Rdn {
    /// Build a single-valued RDN. The value is taken as already unescaped and
    /// must be non-empty printable ASCII of at most [`MAX_RDN_VALUE_OCTETS`]
    /// octets.
    ///
    /// Spec: [MS-ADTS] 3.1.1.1.4, 3.1.1.5.1.2; Q-080; Q-090.
    pub fn new(attribute_type: AttributeType, value: &str) -> Result<Rdn, DnError> {
        check_value(value.as_bytes())?;
        Ok(Rdn {
            attribute_type,
            value: value.to_owned(),
        })
    }

    /// The attributeType, as spelled.
    pub fn attribute_type(&self) -> &AttributeType {
        &self.attribute_type
    }

    /// The value, unescaped and exactly as given (never case-folded).
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The comparison key of this RDN: the value with `A`–`Z` folded to
    /// `a`–`z` and every other octet kept. The attributeType takes no part:
    /// sibling RDNs are distinct by their value parts.
    ///
    /// Byte for byte the RDN key dirstore computes from the same value (its
    /// lookup rule: printable ASCII, non-empty, A–Z folded — which every
    /// [`Rdn`] value already satisfies).
    ///
    /// Spec: Q-080 item 2 (interim, P-9); docs/46 §8.3 item 3; [MS-ADTS]
    /// 3.1.1.1.4 ("the value parts of the RDNs of all children of an object
    /// be distinct"), 3.1.1.3.1.2.1.
    pub fn comparison_key(&self) -> Vec<u8> {
        self.value.bytes().map(|b| b.to_ascii_lowercase()).collect()
    }
}

impl AttributeType {
    /// Validate an attributeType: a `descr` (`ALPHA *( ALPHA / DIGIT /
    /// HYPHEN )`) or a `numericoid` (`number 1*( DOT number )`, `number =
    /// DIGIT / ( LDIGIT 1*DIGIT )`), at most [`MAX_IDENTIFIER_OCTETS`] octets.
    ///
    /// Spec: RFC 4514 §3; RFC 4512 §1.4.
    pub fn new(spelling: &str) -> Result<AttributeType, DnError> {
        if spelling.len() > MAX_IDENTIFIER_OCTETS {
            return Err(DnError::AttributeTypeTooLong);
        }
        let valid = match spelling.as_bytes().first() {
            Some(b) if b.is_ascii_alphabetic() => is_descr(spelling),
            Some(b) if b.is_ascii_digit() => is_numericoid(spelling),
            _ => false,
        };
        if valid {
            Ok(AttributeType(spelling.to_owned()))
        } else {
            Err(DnError::InvalidAttributeType)
        }
    }

    /// The attributeType as spelled.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `true` for the `numericoid` form. Spec: RFC 4512 §1.4.
    pub fn is_numericoid(&self) -> bool {
        self.0.as_bytes().first().is_some_and(u8::is_ascii_digit)
    }
}

// ---- the <GUID=hex> form ----------------------------------------------------

/// Parse `<GUID=` 32 hexadecimal digits `>` into the 16 octets they represent,
/// in order. Hexadecimal digits are accepted in either case (RFC 4512 §1.4
/// `HEX`; Q-195 item 1). Anything after `>` is the "extended DN" or another combined
/// form, which "is not accepted as a means of specifying DNs in requests".
///
/// Spec: [MS-ADTS] 3.1.1.3.1.2.4, 3.1.1.3.4.1.5; [MS-DTYP] 2.3.4, 2.3.4.2;
/// docs/49 §7.
fn parse_object_guid_form(input: &str) -> Result<[u8; OBJECT_GUID_OCTETS], DnError> {
    let Some(rest) = input.strip_prefix(GUID_FORM_PREFIX) else {
        return Err(DnError::UnsupportedExtendedForm);
    };
    let mut octets = [0u8; OBJECT_GUID_OCTETS];
    let mut digits = rest.bytes();
    for octet in octets.iter_mut() {
        let high = digits
            .next()
            .and_then(hex_value)
            .ok_or(DnError::InvalidObjectGuid)?;
        let low = digits
            .next()
            .and_then(hex_value)
            .ok_or(DnError::InvalidObjectGuid)?;
        *octet = (high << 4) | low;
    }
    if digits.next() != Some(GUID_FORM_SUFFIX) {
        return Err(DnError::InvalidObjectGuid);
    }
    if digits.next().is_some() {
        return Err(DnError::UnsupportedExtendedForm);
    }
    Ok(octets)
}

// ---- the RFC 4514 §3 grammar ------------------------------------------------

/// A read position over the input octets. Never indexes: every read is a
/// checked `get`.
struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }
}

/// A parsed attributeValue before the phase-1 checks.
enum AttributeValue {
    /// The `string` form, unescaped.
    String(Vec<u8>),
    /// The `hexstring` form (its octets are not kept: phase 1 refuses it).
    HexString,
}

/// Record the leftmost phase-1 refusal; grammar checking continues so that a
/// syntax error anywhere in the input takes precedence. Spec: Q-195 item 7.
fn note(refusal: &mut Option<DnError>, error: DnError) {
    if refusal.is_none() {
        *refusal = Some(error);
    }
}

/// `distinguishedName = [ relativeDistinguishedName *( COMMA
/// relativeDistinguishedName ) ]`. Spec: RFC 4514 §3; docs/49 §2.4.
fn distinguished_name(input: &[u8]) -> Result<Dn, DnError> {
    let mut cursor = Cursor { input, pos: 0 };
    // Spec: RFC 4514 §3 — zero RDNs is the empty string (§2.1).
    if cursor.peek().is_none() {
        return Ok(Dn::default());
    }
    let mut rdns = Vec::new();
    let mut refusal = None;
    let mut count = 0usize;
    loop {
        if count == MAX_DN_RDNS {
            return Err(DnError::TooManyRdns);
        }
        count += 1;
        if let Some(rdn) = relative_distinguished_name(&mut cursor, &mut refusal)? {
            rdns.push(rdn);
        }
        match cursor.peek() {
            None => break,
            Some(COMMA) => cursor.bump(),
            // A value ends only at ',', '+' (consumed by the RDN) or the end,
            // so nothing else can follow an RDN. Fail closed regardless.
            Some(_) => return Err(DnError::UnescapedCharacter),
        }
    }
    if let Some(error) = refusal {
        return Err(error);
    }
    Ok(Dn { rdns })
}

/// `relativeDistinguishedName = attributeTypeAndValue *( PLUS
/// attributeTypeAndValue )`: every AVA is parsed; a second one makes the RDN
/// multi-valued, which phase 1 refuses.
///
/// Spec: RFC 4514 §3; [MS-ADTS] 3.1.1.3.1.2.3 ("MAX equals 1").
fn relative_distinguished_name(
    cursor: &mut Cursor<'_>,
    refusal: &mut Option<DnError>,
) -> Result<Option<Rdn>, DnError> {
    let first = attribute_type_and_value(cursor, refusal)?;
    while cursor.peek() == Some(PLUS) {
        cursor.bump();
        note(refusal, DnError::MultiValuedRdn);
        attribute_type_and_value(cursor, refusal)?;
    }
    Ok(first)
}

/// `attributeTypeAndValue = attributeType EQUALS attributeValue`, then the
/// phase-1 value checks. Returns `None` when the AVA earned a refusal.
///
/// Spec: RFC 4514 §3; Q-080; Q-090; Q-195.
fn attribute_type_and_value(
    cursor: &mut Cursor<'_>,
    refusal: &mut Option<DnError>,
) -> Result<Option<Rdn>, DnError> {
    let attribute_type = attribute_type(cursor)?;
    match attribute_value(cursor)? {
        AttributeValue::HexString => {
            note(refusal, DnError::HexStringValue);
            Ok(None)
        }
        AttributeValue::String(octets) => {
            if let Err(error) = check_value(&octets) {
                note(refusal, error);
                return Ok(None);
            }
            // Printable ASCII is UTF-8; the conversion cannot fail.
            let value = String::from_utf8(octets).map_err(|_| DnError::ValueNotPrintableAscii)?;
            Ok(Some(Rdn {
                attribute_type,
                value,
            }))
        }
    }
}

/// `attributeType = descr / numericoid`, followed by `EQUALS` (consumed).
///
/// The candidate is the run of octets that can appear in either production
/// (ALPHA, DIGIT, HYPHEN, DOT); it is then validated as one of them.
///
/// Spec: RFC 4514 §3; RFC 4512 §1.4.
fn attribute_type(cursor: &mut Cursor<'_>) -> Result<AttributeType, DnError> {
    let start = cursor.pos;
    while let Some(b) = cursor.peek() {
        if b.is_ascii_alphanumeric() || b == HYPHEN || b == DOT {
            cursor.bump();
        } else {
            break;
        }
    }
    let token = cursor.input.get(start..cursor.pos).unwrap_or_default();
    match cursor.peek() {
        Some(EQUALS) if !token.is_empty() => {
            cursor.bump();
            // ALPHA / DIGIT / HYPHEN / DOT octets: always UTF-8.
            let spelling =
                core::str::from_utf8(token).map_err(|_| DnError::InvalidAttributeType)?;
            AttributeType::new(spelling)
        }
        None | Some(COMMA) | Some(PLUS) => Err(if token.is_empty() {
            DnError::EmptyRdn
        } else {
            DnError::MissingEquals
        }),
        _ => Err(DnError::InvalidAttributeType),
    }
}

/// `attributeValue = string / hexstring`. A value ends at an unescaped `,` or
/// `+`, or at the end of the input. A leading unescaped `#` starts the
/// `hexstring` form (LUTF1 excludes SHARP, so a `string` cannot begin with it).
///
/// Spec: RFC 4514 §3.
fn attribute_value(cursor: &mut Cursor<'_>) -> Result<AttributeValue, DnError> {
    if cursor.peek() == Some(SHARP) {
        cursor.bump();
        return hex_string(cursor);
    }
    string(cursor).map(AttributeValue::String)
}

/// `hexstring = SHARP 1*hexpair` (the SHARP already consumed), up to the end
/// of the value. Spec: RFC 4514 §3.
fn hex_string(cursor: &mut Cursor<'_>) -> Result<AttributeValue, DnError> {
    let mut pairs = 0usize;
    loop {
        match cursor.peek() {
            None | Some(COMMA) | Some(PLUS) => break,
            Some(high) => {
                hex_value(high).ok_or(DnError::InvalidHexString)?;
                cursor.bump();
                cursor
                    .peek()
                    .and_then(hex_value)
                    .ok_or(DnError::InvalidHexString)?;
                cursor.bump();
                pairs = pairs.saturating_add(1);
            }
        }
    }
    if pairs == 0 {
        return Err(DnError::InvalidHexString);
    }
    Ok(AttributeValue::HexString)
}

/// `string = [ ( leadchar / pair ) [ *( stringchar / pair ) ( trailchar /
/// pair ) ] ]`, unescaped as RFC 4514 §3 directs ("replacing (left to right,
/// non-recursively) each <pair>").
///
/// Unescaped octets: NUL, DQUOTE, SEMI, LANGLE and RANGLE are in none of
/// LUTF1 / SUTF1 / TUTF1; SPACE is not in LUTF1 or TUTF1 (no leading or
/// trailing space); SHARP is not in LUTF1 (handled by the caller); COMMA and
/// PLUS end the value; ESC starts a pair. Every other octet — including the
/// octets of UTFMB characters and the controls %x01-1F / %x7F — is allowed by
/// the grammar and left to the printable-ASCII check.
///
/// Spec: RFC 4514 §3; RFC 4512 §1.4.
fn string(cursor: &mut Cursor<'_>) -> Result<Vec<u8>, DnError> {
    let mut value = Vec::new();
    let mut last_unescaped_space = false;
    loop {
        match cursor.peek() {
            None | Some(COMMA) | Some(PLUS) => break,
            Some(ESC) => {
                cursor.bump();
                value.push(pair(cursor)?);
                last_unescaped_space = false;
            }
            Some(b) => {
                if matches!(b, NULL | DQUOTE | SEMI | LANGLE | RANGLE)
                    || (b == SPACE && value.is_empty())
                {
                    return Err(DnError::UnescapedCharacter);
                }
                cursor.bump();
                value.push(b);
                last_unescaped_space = b == SPACE;
            }
        }
    }
    // Spec: RFC 4514 §3 — trailchar (TUTF1) excludes SPACE.
    if last_unescaped_space {
        return Err(DnError::UnescapedCharacter);
    }
    Ok(value)
}

/// The rest of `pair = ESC ( ESC / special / hexpair )` (ESC consumed), as
/// the octet it stands for: `<ESC><ESC>` → ESC, `<ESC><special>` → special,
/// `<ESC><hexpair>` → the octet the hexpair indicates.
///
/// Spec: RFC 4514 §3 (`special = escaped / SPACE / SHARP / EQUALS`,
/// `escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE`).
fn pair(cursor: &mut Cursor<'_>) -> Result<u8, DnError> {
    let first = cursor.peek().ok_or(DnError::InvalidEscape)?;
    if first == ESC || is_special(first) {
        cursor.bump();
        return Ok(first);
    }
    let high = hex_value(first).ok_or(DnError::InvalidEscape)?;
    cursor.bump();
    let low = cursor
        .peek()
        .and_then(hex_value)
        .ok_or(DnError::InvalidEscape)?;
    cursor.bump();
    Ok((high << 4) | low)
}

/// `special = escaped / SPACE / SHARP / EQUALS`. Spec: RFC 4514 §3.
fn is_special(b: u8) -> bool {
    matches!(
        b,
        DQUOTE | PLUS | COMMA | SEMI | LANGLE | RANGLE | SPACE | SHARP | EQUALS
    )
}

/// The value of one `HEX` digit (`DIGIT / %x41-46 / %x61-66`).
/// Spec: RFC 4512 §1.4.
fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// `descr = keystring`, `keystring = leadkeychar *keychar`, `leadkeychar =
/// ALPHA`, `keychar = ALPHA / DIGIT / HYPHEN`. Spec: RFC 4512 §1.4.
fn is_descr(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == HYPHEN)
}

/// `numericoid = number 1*( DOT number )`, `number = DIGIT / ( LDIGIT
/// 1*DIGIT )` — at least two arcs, no empty arc, no leading zero.
/// Spec: RFC 4512 §1.4.
fn is_numericoid(s: &str) -> bool {
    let mut arcs = 0usize;
    for arc in s.split(char::from(DOT)) {
        let well_formed = match arc.as_bytes() {
            [] => false,
            [single] => single.is_ascii_digit(),
            [lead, rest @ ..] => {
                (b'1'..=b'9').contains(lead) && rest.iter().all(u8::is_ascii_digit)
            }
        };
        if !well_formed {
            return false;
        }
        arcs = arcs.saturating_add(1);
    }
    arcs >= 2
}

// ---- values ------------------------------------------------------------------

/// The phase-1 checks of an unescaped value, in this order: non-empty,
/// printable ASCII, length.
///
/// Spec: [MS-ADTS] 3.1.1.1.4 (exactly one value), 3.1.1.5.1.2 (no 0x00 /
/// 0x0A; under 255 characters — Q-090); Q-080 item 1 (printable ASCII,
/// `0x20..=0x7E`); docs/49 §7.
fn check_value(value: &[u8]) -> Result<(), DnError> {
    if value.is_empty() {
        return Err(DnError::EmptyValue);
    }
    if !value.iter().all(|b| (0x20..=0x7E).contains(b)) {
        return Err(DnError::ValueNotPrintableAscii);
    }
    if value.len() > MAX_RDN_VALUE_OCTETS {
        return Err(DnError::ValueTooLong);
    }
    Ok(())
}

/// Append `value` escaped as RFC 4514 §2.4 requires: a leading space or `#`,
/// a trailing space, and `"`, `+`, `,`, `;`, `<`, `>`, `\` anywhere, each
/// prefixed by a backslash (all are in the §2.4 list that "can be prefixed by
/// a backslash"). The value is printable ASCII (an [`Rdn`] invariant), so no
/// NUL needs the hexpair form.
///
/// Spec: RFC 4514 §2.4.
fn escape_value(value: &str, out: &mut String) {
    let bytes = value.as_bytes();
    let last = bytes.len().saturating_sub(1);
    for (i, &b) in bytes.iter().enumerate() {
        let must_escape = matches!(b, DQUOTE | PLUS | COMMA | SEMI | LANGLE | RANGLE | ESC)
            || (i == 0 && (b == SPACE || b == SHARP))
            || (i == last && b == SPACE);
        if must_escape {
            out.push(char::from(ESC));
        }
        out.push(char::from(b));
    }
}
