//! Strict, bounded decoder from LDAP-BER octets to typed messages.
//!
//! The grammar is the ASN.1 module of RFC 4511 App. B (`IMPLICIT TAGS`,
//! `EXTENSIBILITY IMPLIED`), restricted to the phase-1 operations (docs/49
//! R49-7). The encoding rules are X.690 clause 8 with the RFC 4511 §5.1
//! restrictions and the A-45 profile choices (see [`crate::ber`]).
//!
//! Under implicit tagging an element's form is that of its base type
//! (X.690 8.14.4 a)): `[APPLICATION 10] LDAPDN`, `simple [0] OCTET STRING` and
//! `present [7] AttributeDescription` are primitive; `[APPLICATION 0] SEQUENCE`
//! is constructed. The one exception is `not [2] Filter`, an implicitly tagged
//! CHOICE, which "In BER ... is treated as if the tag were explicit"
//! (RFC 4511 §4.5.1.7).
//!
//! Trailing SEQUENCE components with unrecognised tags are validated and
//! skipped under [`Profile::Wire`] (RFC 4511 §4: "clients and servers MUST
//! (unless otherwise specified) ignore trailing SEQUENCE components whose tags
//! they do not recognize"; docs/49 §2.3 E12) and refused under
//! [`Profile::Canonical`]. A tag the SEQUENCE does define, appearing out of
//! place, is always malformed (E12). The rule applies to SEQUENCE types only —
//! not to SEQUENCE OF / SET OF, whose elements all have one type.
//!
//! Nothing here indexes into input, unwraps, or panics; every length is bounded
//! by the octets present and every count by a named limit (AGENTS.md §6).

use crate::ber::{
    application, context, integer_value, is_constructed, tag_of, validate_element, Profile, Reader,
    Tlv, BOOLEAN, CLASS_APPLICATION, CLASS_CONTEXT, CLASS_MASK, ENUMERATED, INTEGER, NUMBER_MASK,
    OCTET_STRING, SEQUENCE, SET,
};
use crate::error::{Error, Limit, Result};
use crate::limits::{
    AuthState, MAX_ATTRIBUTE_SELECTORS, MAX_ATTRIBUTE_VALUES, MAX_CONTROLS, MAX_FILTER_DEPTH,
    MAX_FILTER_NODES, MAX_IDENTIFIER_OCTETS, MAX_INT, MAX_LDAPDN_OCTETS, MAX_PARTIAL_ATTRIBUTES,
    MAX_SUBSTRING_ANY, MAX_VALUE_OCTETS,
};
use crate::message::{
    AttributeValueAssertion, AuthenticationChoice, BindRequest, BindResponse, Control,
    DerefAliases, ExtendedRequest, ExtendedResponse, Filter, LdapMessage, LdapResult,
    MatchingRuleAssertion, MessageId, PartialAttribute, ProtocolOp, ResultCode, SaslCredentials,
    Scope, SearchRequest, SearchResultEntry, Substring, SubstringFilter, UnsupportedOp,
    SIMPLE_PASSWORD_PLACEHOLDER,
};

/// Which way the message travels.
///
/// Spec: RFC 4511 §4.1.1 — a server receiving a protocolOp that "is not
/// recognized as a request" treats the PDU as malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client to server: only request operations are accepted.
    Request,
    /// Server to client: only the responses this codec models are accepted
    /// (used to check the engine's own output and in tests).
    Response,
}

/// How [`decode_message`] decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeOptions {
    pub direction: Direction,
    pub profile: Profile,
    /// The largest message accepted; larger input is
    /// [`Error::MessageTooLarge`]. Normally [`AuthState::max_message_octets`].
    pub max_message_octets: usize,
}

impl DecodeOptions {
    /// Client requests as received on the wire, bounded for `auth`.
    /// Spec: docs/49 §2.4, §11 (the front).
    pub const fn request(auth: AuthState) -> DecodeOptions {
        DecodeOptions {
            direction: Direction::Request,
            profile: Profile::Wire,
            max_message_octets: auth.max_message_octets(),
        }
    }

    /// Client requests in the canonical form the front re-encodes, bounded for
    /// `auth`. Spec: docs/49 §11 (the engine decodes "in canonical mode only").
    pub const fn canonical_request(auth: AuthState) -> DecodeOptions {
        DecodeOptions {
            direction: Direction::Request,
            profile: Profile::Canonical,
            max_message_octets: auth.max_message_octets(),
        }
    }
}

/// Decode exactly one complete LDAPMessage.
///
/// `input` must hold one message and nothing else (use
/// [`crate::frame_length`] to cut it from a stream).
///
/// Spec: RFC 4511 §4.1.1 (LDAPMessage), §5.1 (encoding), §5.2 (one PDU after
/// another); [MS-ADTS] 3.1.1.3.4.6 (size bound); docs/49 §2.3–§2.4.
pub fn decode_message(input: &[u8], options: &DecodeOptions) -> Result<LdapMessage> {
    // Bound first, before reading anything. Spec: docs/49 §2.4.
    if input.len() > options.max_message_octets {
        return Err(Error::MessageTooLarge);
    }
    let profile = options.profile;
    let mut outer = Reader::new(input, profile);
    let envelope = outer.read_tlv()?;
    // "LDAPMessage ::= SEQUENCE". Spec: RFC 4511 §4.1.1.
    expect_identifier(envelope.identifier, SEQUENCE, false)?;
    if !outer.is_empty() {
        return Err(Error::TrailingData);
    }

    let mut r = Reader::new(envelope.contents, profile);
    // "messageID MessageID". Spec: RFC 4511 §4.1.1.
    let id = next(&mut r)?;
    expect_identifier(id.identifier, INTEGER, false)?;
    let message_id = message_id_value(id.contents)?;
    // "The messageID of a request MUST have a non-zero value". Spec: RFC 4511
    // §4.1.1.1.
    if options.direction == Direction::Request && message_id.get() == 0 {
        return Err(Error::ZeroMessageId);
    }

    let protocol_op = protocol_op(&mut r, options.direction)?;
    // In a response, zero is only for the unsolicited notification, which is
    // an ExtendedResponse. Spec: RFC 4511 §4.1.1.1, §4.4.
    if options.direction == Direction::Response
        && message_id.get() == 0
        && !matches!(protocol_op, ProtocolOp::ExtendedResponse(_))
    {
        return Err(Error::ZeroMessageId);
    }

    // "controls [0] Controls OPTIONAL". Spec: RFC 4511 §4.1.1, §4.1.11.
    let controls = if peek_is(&r, CONTROLS) {
        Some(controls(next(&mut r)?, profile)?)
    } else {
        None
    };
    finish_sequence(&mut r, LDAP_MESSAGE_TAGS, LEVEL_MESSAGE)?;

    Ok(LdapMessage {
        message_id,
        protocol_op,
        controls,
    })
}

// ---- nesting levels (for the element-depth bound on skipped components) ----
//
// A level is the number of constructed elements enclosing a reader's contents.

/// Contents of the LDAPMessage SEQUENCE.
const LEVEL_MESSAGE: usize = 1;
/// Contents of a protocolOp (and of `controls [0]`).
const LEVEL_OP: usize = 2;
/// Contents of a component of a protocolOp (SaslCredentials, PartialAttribute)
/// or of one Control.
const LEVEL_COMPONENT: usize = 3;
/// A top-level Filter element sits inside the SearchRequest contents, so a
/// filter at depth `d` has its contents at level `FILTER_BASE_LEVEL + d`.
const FILTER_BASE_LEVEL: usize = 2;

// ---- tags each SEQUENCE defines (form bit cleared), for the E12 rule ----

/// `controls [0]` (constructed).
const CONTROLS: u8 = context(0, true);

/// Tags defined in LDAPMessage: messageID, every protocolOp alternative of
/// RFC 4511 App. B (APPLICATION 0–16, 19, 23–25), and `controls [0]`.
const LDAP_MESSAGE_TAGS: &[u8] = &[
    INTEGER,
    application(0, false),
    application(1, false),
    application(2, false),
    application(3, false),
    application(4, false),
    application(5, false),
    application(6, false),
    application(7, false),
    application(8, false),
    application(9, false),
    application(10, false),
    application(11, false),
    application(12, false),
    application(13, false),
    application(14, false),
    application(15, false),
    application(16, false),
    application(19, false),
    application(23, false),
    application(24, false),
    application(25, false),
    context(0, false),
];

/// BindRequest: version, name, and the defined AuthenticationChoice tags.
const BIND_REQUEST_TAGS: &[u8] = &[INTEGER, OCTET_STRING, context(0, false), context(3, false)];

/// SaslCredentials: mechanism and credentials (both OCTET STRING).
const SASL_CREDENTIALS_TAGS: &[u8] = &[OCTET_STRING];

/// SearchRequest: LDAPDN, the two ENUMERATEDs, the two INTEGERs, BOOLEAN, the
/// ten defined Filter alternatives `[0]`–`[9]`, and AttributeSelection.
const SEARCH_REQUEST_TAGS: &[u8] = &[
    OCTET_STRING,
    ENUMERATED,
    INTEGER,
    tag_of(BOOLEAN),
    context(0, false),
    context(1, false),
    context(2, false),
    context(3, false),
    context(4, false),
    context(5, false),
    context(6, false),
    context(7, false),
    context(8, false),
    context(9, false),
    tag_of(SEQUENCE),
];

/// AttributeValueAssertion: attributeDesc and assertionValue.
const AVA_TAGS: &[u8] = &[OCTET_STRING];

/// SubstringFilter: type and the substrings SEQUENCE OF.
const SUBSTRING_FILTER_TAGS: &[u8] = &[OCTET_STRING, tag_of(SEQUENCE)];

/// MatchingRuleAssertion: `[1]`–`[4]`.
const MATCHING_RULE_ASSERTION_TAGS: &[u8] = &[
    context(1, false),
    context(2, false),
    context(3, false),
    context(4, false),
];

/// Control: controlType, criticality, controlValue.
const CONTROL_TAGS: &[u8] = &[OCTET_STRING, BOOLEAN];

/// ExtendedRequest: `requestName [0]`, `requestValue [1]`.
const EXTENDED_REQUEST_TAGS: &[u8] = &[context(0, false), context(1, false)];

/// LDAPResult: resultCode, matchedDN, diagnosticMessage, `referral [3]`.
const LDAP_RESULT_TAGS: &[u8] = &[ENUMERATED, OCTET_STRING, context(3, false)];

/// BindResponse: the LDAPResult components and `serverSaslCreds [7]`.
const BIND_RESPONSE_TAGS: &[u8] = &[
    ENUMERATED,
    OCTET_STRING,
    context(3, false),
    context(7, false),
];

/// ExtendedResponse: the LDAPResult components, `responseName [10]`,
/// `responseValue [11]`.
const EXTENDED_RESPONSE_TAGS: &[u8] = &[
    ENUMERATED,
    OCTET_STRING,
    context(3, false),
    context(10, false),
    context(11, false),
];

/// SearchResultEntry: objectName and PartialAttributeList.
const SEARCH_RESULT_ENTRY_TAGS: &[u8] = &[OCTET_STRING, tag_of(SEQUENCE)];

/// PartialAttribute: type and the vals SET OF.
const PARTIAL_ATTRIBUTE_TAGS: &[u8] = &[OCTET_STRING, tag_of(SET)];

// ---- generic component helpers ----

/// Read the next element, which must be present. Spec: X.690 8.9.2.
fn next<'a>(r: &mut Reader<'a>) -> Result<Tlv<'a>> {
    if r.is_empty() {
        Err(Error::MissingComponent)
    } else {
        r.read_tlv()
    }
}

/// Whether the next element carries `identifier`'s tag (either form), so an
/// OPTIONAL / DEFAULT component is present. The reader then checks the form.
/// Spec: X.690 8.9.3.
fn peek_is(r: &Reader<'_>, identifier: u8) -> bool {
    r.peek_identifier().map(tag_of) == Some(tag_of(identifier))
}

/// Compare an identifier with the expected one, reporting a form-only
/// difference precisely.
///
/// Spec: X.690 8.1.2.5; RFC 4511 §5.1 (OCTET STRING primitive only) and
/// X.690 8.14.4 a) (implicit tags keep the base form).
fn expect_identifier(found: u8, expected: u8, octet_string_based: bool) -> Result<()> {
    if found == expected {
        return Ok(());
    }
    if tag_of(found) == tag_of(expected) {
        if octet_string_based && is_constructed(found) {
            return Err(Error::ConstructedOctetString);
        }
        return Err(Error::PrimitiveConstructedMismatch);
    }
    Err(Error::UnexpectedTag)
}

/// Read an OCTET STRING (or an implicitly tagged one), bounded only by its
/// enclosing element. Spec: X.690 8.7.2; RFC 4511 §5.1.
fn octet_string<'a>(r: &mut Reader<'a>, identifier: u8) -> Result<&'a [u8]> {
    let tlv = next(r)?;
    expect_identifier(tlv.identifier, identifier, true)?;
    Ok(tlv.contents)
}

/// Read an OCTET STRING no longer than `max` octets.
/// Spec: X.690 8.7.2; RFC 4511 §5.1; docs/49 §2.4.
fn bounded_octet_string<'a>(
    r: &mut Reader<'a>,
    identifier: u8,
    max: usize,
    limit: Limit,
) -> Result<&'a [u8]> {
    let contents = octet_string(r, identifier)?;
    if contents.len() > max {
        return Err(Error::LimitExceeded(limit));
    }
    Ok(contents)
}

/// Read an LDAPString-based value (LDAPString, LDAPDN, AttributeDescription,
/// LDAPOID, MatchingRuleId) no longer than `max` octets.
///
/// Spec: RFC 4511 §4.1.2 (UTF-8), §4.1.3, §4.1.4, §4.1.8; RFC 4512 §1.4
/// (the UTF8 production: no overlong forms, no surrogates, nothing above
/// U+10FFFF — exactly what `core::str::from_utf8` accepts); docs/49 §2.3 E17.
/// The ABNF of AttributeDescription / numericoid is the engine's concern: an
/// unrecognised description is Undefined in a filter and ignored in a
/// selection (RFC 4511 §4.5.1.7, §4.5.1.8), never a codec error.
fn ldap_string(r: &mut Reader<'_>, identifier: u8, max: usize, limit: Limit) -> Result<String> {
    let contents = bounded_octet_string(r, identifier, max, limit)?;
    let text = core::str::from_utf8(contents).map_err(|_| Error::InvalidUtf8)?;
    Ok(text.to_owned())
}

/// Read a BOOLEAN. Spec: X.690 8.2; RFC 4511 §5.1; A-45.
fn boolean(r: &mut Reader<'_>, identifier: u8) -> Result<bool> {
    let tlv = next(r)?;
    expect_identifier(tlv.identifier, identifier, false)?;
    crate::ber::boolean_value(tlv.contents)
}

/// Read a `BOOLEAN DEFAULT FALSE` component: absent is FALSE; present must be
/// TRUE. Spec: RFC 4511 §5.1 ("If a value of a type is its default value, it
/// is absent"); X.690 8.9.3; A-45 (Q-160 item 4).
fn default_false_boolean(r: &mut Reader<'_>, identifier: u8) -> Result<bool> {
    if !peek_is(r, identifier) {
        return Ok(false);
    }
    if boolean(r, identifier)? {
        Ok(true)
    } else {
        Err(Error::ExplicitDefault)
    }
}

/// Read an ENUMERATED value. Spec: X.690 8.4.
fn enumerated(r: &mut Reader<'_>) -> Result<i64> {
    let tlv = next(r)?;
    expect_identifier(tlv.identifier, ENUMERATED, false)?;
    integer_value(tlv.contents)
}

/// Read an `INTEGER (0 .. maxInt)`. Spec: RFC 4511 §4.5.1 (`sizeLimit`,
/// `timeLimit`); X.690 8.3.
fn zero_to_max_int(r: &mut Reader<'_>) -> Result<u32> {
    let tlv = next(r)?;
    expect_identifier(tlv.identifier, INTEGER, false)?;
    let value = integer_value(tlv.contents)?;
    match u32::try_from(value) {
        Ok(v) if v <= MAX_INT => Ok(v),
        _ => Err(Error::IntegerOutOfRange),
    }
}

/// Decode MessageID contents. Spec: RFC 4511 §4.1.1 (`INTEGER (0 .. maxInt)`).
fn message_id_value(contents: &[u8]) -> Result<MessageId> {
    let value = integer_value(contents).map_err(|e| match e {
        Error::IntegerOutOfRange => Error::MessageIdOutOfRange,
        other => other,
    })?;
    let value = u32::try_from(value).map_err(|_| Error::MessageIdOutOfRange)?;
    MessageId::new(value)
}

/// After the last component this codec models, handle what remains of a
/// SEQUENCE: unrecognised trailing components are validated and skipped
/// (wire) or refused (canonical); a defined tag here is out of place.
///
/// Spec: RFC 4511 §4; docs/49 §2.3 E12; A-45 (Q-160 item 2); docs/49 §11.
fn finish_sequence(r: &mut Reader<'_>, defined: &[u8], level: usize) -> Result<()> {
    while !r.is_empty() {
        let tlv = r.read_tlv()?;
        if defined.contains(&tag_of(tlv.identifier)) {
            return Err(Error::UnexpectedTag);
        }
        if r.profile() == Profile::Canonical {
            return Err(Error::UnrecognizedComponent);
        }
        validate_element(&tlv, r.profile(), level + 1)?;
    }
    Ok(())
}

/// Accept an unrecognised CHOICE alternative: validated then dropped (wire),
/// or only as an empty primitive element (canonical).
///
/// Spec: RFC 4511 §4 (CHOICE types are extensible), §4.2, §4.5.1.7;
/// docs/49 §2.3 E13, §11.
fn unrecognized_alternative(tlv: &Tlv<'_>, profile: Profile, level: usize) -> Result<()> {
    match profile {
        Profile::Wire => validate_element(tlv, profile, level),
        Profile::Canonical => {
            if !is_constructed(tlv.identifier) && tlv.contents.is_empty() {
                Ok(())
            } else {
                Err(Error::NonCanonical)
            }
        }
    }
}

/// Check the primitive/constructed form of an element. Spec: X.690 8.1.2.5.
fn expect_form(identifier: u8, constructed: bool) -> Result<()> {
    if is_constructed(identifier) == constructed {
        Ok(())
    } else {
        Err(Error::PrimitiveConstructedMismatch)
    }
}

// ---- protocolOp ----

/// Decode the protocolOp CHOICE. Spec: RFC 4511 §4.1.1, App. B; docs/49
/// §2.3 E13, §5.1 (phase-1 operations; the rest by tag only — A-48).
fn protocol_op(r: &mut Reader<'_>, direction: Direction) -> Result<ProtocolOp> {
    let tlv = next(r)?;
    let profile = r.profile();
    let id = tlv.identifier;
    if id & CLASS_MASK != CLASS_APPLICATION {
        return Err(Error::UnrecognizedProtocolOp);
    }
    let number = id & NUMBER_MASK;
    match (direction, number) {
        (Direction::Request, 0) => {
            expect_form(id, true)?;
            Ok(ProtocolOp::BindRequest(bind_request(
                tlv.contents,
                profile,
            )?))
        }
        (Direction::Request, 2) => {
            // "UnbindRequest ::= [APPLICATION 2] NULL" — primitive, no
            // contents. Spec: RFC 4511 §4.3; X.690 8.8; docs/49 §2.3 E10.
            expect_form(id, false)?;
            if !tlv.contents.is_empty() {
                return Err(Error::InvalidNull);
            }
            Ok(ProtocolOp::UnbindRequest)
        }
        (Direction::Request, 3) => {
            expect_form(id, true)?;
            Ok(ProtocolOp::SearchRequest(search_request(
                tlv.contents,
                profile,
            )?))
        }
        (Direction::Request, 16) => {
            // "AbandonRequest ::= [APPLICATION 16] MessageID" — primitive.
            // Spec: RFC 4511 §4.11.
            expect_form(id, false)?;
            Ok(ProtocolOp::AbandonRequest(message_id_value(tlv.contents)?))
        }
        (Direction::Request, 23) => {
            expect_form(id, true)?;
            Ok(ProtocolOp::ExtendedRequest(extended_request(
                tlv.contents,
                profile,
            )?))
        }
        (Direction::Request, 6 | 8 | 10 | 12 | 14) => unsupported(&tlv, number, profile),
        (Direction::Response, 1) => {
            expect_form(id, true)?;
            Ok(ProtocolOp::BindResponse(bind_response(
                tlv.contents,
                profile,
            )?))
        }
        (Direction::Response, 4) => {
            expect_form(id, true)?;
            Ok(ProtocolOp::SearchResultEntry(search_result_entry(
                tlv.contents,
                profile,
            )?))
        }
        (Direction::Response, 5) => {
            // "SearchResultDone ::= [APPLICATION 5] LDAPResult".
            // Spec: RFC 4511 §4.5.2.
            expect_form(id, true)?;
            let mut inner = Reader::new(tlv.contents, profile);
            let result = ldap_result_components(&mut inner)?;
            finish_sequence(&mut inner, LDAP_RESULT_TAGS, LEVEL_OP)?;
            Ok(ProtocolOp::SearchResultDone(result))
        }
        (Direction::Response, 24) => {
            expect_form(id, true)?;
            Ok(ProtocolOp::ExtendedResponse(extended_response(
                tlv.contents,
                profile,
            )?))
        }
        (Direction::Response, 7 | 9 | 11 | 13 | 15) => unsupported_response(&tlv, number, profile),
        _ => Err(Error::UnrecognizedProtocolOp),
    }
}

/// The `[APPLICATION n] LDAPResult` response of an operation phase 1 does
/// not perform (ModifyResponse 7, AddResponse 9, DelResponse 11,
/// ModifyDNResponse 13, CompareResponse 15), decoded exactly like
/// SearchResultDone apart from the tag.
///
/// Spec: RFC 4511 §4.6-§4.10, App. B; X.690 8.14.4 a) (constructed, the base
/// being a SEQUENCE); A-48; docs/questions/Q-190 item 1 (A-54).
fn unsupported_response(tlv: &Tlv<'_>, number: u8, profile: Profile) -> Result<ProtocolOp> {
    let op = match number {
        7 => UnsupportedOp::ModifyRequest,
        9 => UnsupportedOp::AddRequest,
        11 => UnsupportedOp::DelRequest,
        13 => UnsupportedOp::ModifyDnRequest,
        15 => UnsupportedOp::CompareRequest,
        _ => return Err(Error::UnrecognizedProtocolOp),
    };
    expect_form(tlv.identifier, true)?;
    let mut inner = Reader::new(tlv.contents, profile);
    let result = ldap_result_components(&mut inner)?;
    finish_sequence(&mut inner, LDAP_RESULT_TAGS, LEVEL_OP)?;
    Ok(ProtocolOp::UnsupportedResponse { op, result })
}

/// Recognise an out-of-scope request by its tag and form only; the body is
/// already bounded by its length and is not decoded. The canonical form is an
/// empty body.
///
/// Spec: RFC 4511 App. B (`DelRequest` is an implicitly tagged LDAPDN, hence
/// primitive — RFC 4511 §5.1, X.690 8.14.4 a); the others are SEQUENCEs,
/// hence constructed — X.690 8.9.1); A-48; docs/49 §11.
fn unsupported(tlv: &Tlv<'_>, number: u8, profile: Profile) -> Result<ProtocolOp> {
    let op_tag = match number {
        6 => UnsupportedOp::ModifyRequest,
        8 => UnsupportedOp::AddRequest,
        10 => UnsupportedOp::DelRequest,
        12 => UnsupportedOp::ModifyDnRequest,
        14 => UnsupportedOp::CompareRequest,
        _ => return Err(Error::UnrecognizedProtocolOp),
    };
    if op_tag == UnsupportedOp::DelRequest {
        if is_constructed(tlv.identifier) {
            return Err(Error::ConstructedOctetString);
        }
    } else {
        expect_form(tlv.identifier, true)?;
    }
    if profile == Profile::Canonical && !tlv.contents.is_empty() {
        return Err(Error::NonCanonical);
    }
    Ok(ProtocolOp::Unsupported { op_tag })
}

// ---- Bind ----

/// Spec: RFC 4511 §4.2 (BindRequest); docs/49 §2.3 E9, §3.1.
fn bind_request(contents: &[u8], profile: Profile) -> Result<BindRequest> {
    let mut r = Reader::new(contents, profile);
    // "version INTEGER (1 .. 127)".
    let tlv = next(&mut r)?;
    expect_identifier(tlv.identifier, INTEGER, false)?;
    let version = integer_value(tlv.contents).map_err(|e| match e {
        Error::IntegerOutOfRange => Error::VersionOutOfRange,
        other => other,
    })?;
    let version = match u8::try_from(version) {
        Ok(v) if (1..=127).contains(&v) => v,
        _ => return Err(Error::VersionOutOfRange),
    };
    // "name LDAPDN".
    let name = ldap_string(&mut r, OCTET_STRING, MAX_LDAPDN_OCTETS, Limit::LdapDnOctets)?;
    let authentication = authentication_choice(next(&mut r)?, profile)?;
    finish_sequence(&mut r, BIND_REQUEST_TAGS, LEVEL_OP)?;
    Ok(BindRequest {
        version,
        name,
        authentication,
    })
}

/// Spec: RFC 4511 §4.2 (AuthenticationChoice, extensible); docs/49 §2.3
/// ("simple decoded to its shape only"), E13.
fn authentication_choice(tlv: Tlv<'_>, profile: Profile) -> Result<AuthenticationChoice> {
    let id = tlv.identifier;
    if id & CLASS_MASK != CLASS_CONTEXT {
        return Err(Error::UnexpectedTag);
    }
    match id & NUMBER_MASK {
        0 => {
            // "simple [0] OCTET STRING" — primitive (RFC 4511 §5.1).
            if is_constructed(id) {
                return Err(Error::ConstructedOctetString);
            }
            let password_empty = tlv.contents.is_empty();
            if profile == Profile::Canonical
                && !password_empty
                && tlv.contents != [SIMPLE_PASSWORD_PLACEHOLDER]
            {
                return Err(Error::NonCanonical);
            }
            // The password octets are dropped here and never copied.
            Ok(AuthenticationChoice::Simple { password_empty })
        }
        3 => {
            // "sasl [3] SaslCredentials" — a SEQUENCE, constructed.
            expect_form(id, true)?;
            Ok(AuthenticationChoice::Sasl(sasl_credentials(
                tlv.contents,
                profile,
            )?))
        }
        tag_number => {
            unrecognized_alternative(&tlv, profile, LEVEL_COMPONENT)?;
            Ok(AuthenticationChoice::Unrecognized { tag_number })
        }
    }
}

/// Spec: RFC 4511 §4.2 (SaslCredentials).
fn sasl_credentials(contents: &[u8], profile: Profile) -> Result<SaslCredentials> {
    let mut r = Reader::new(contents, profile);
    let mechanism = ldap_string(
        &mut r,
        OCTET_STRING,
        MAX_IDENTIFIER_OCTETS,
        Limit::IdentifierOctets,
    )?;
    // "credentials OCTET STRING OPTIONAL" — bounded by the message bound
    // (docs/49 §2.4: "SASL credentials within MAX_PREAUTH_PDU").
    let credentials = if peek_is(&r, OCTET_STRING) {
        Some(octet_string(&mut r, OCTET_STRING)?.to_vec())
    } else {
        None
    };
    finish_sequence(&mut r, SASL_CREDENTIALS_TAGS, LEVEL_COMPONENT)?;
    Ok(SaslCredentials {
        mechanism,
        credentials,
    })
}

/// Spec: RFC 4511 §4.2.2 (BindResponse).
fn bind_response(contents: &[u8], profile: Profile) -> Result<BindResponse> {
    let mut r = Reader::new(contents, profile);
    let result = ldap_result_components(&mut r)?;
    let server_sasl_creds = if peek_is(&r, context(7, false)) {
        Some(octet_string(&mut r, context(7, false))?.to_vec())
    } else {
        None
    };
    finish_sequence(&mut r, BIND_RESPONSE_TAGS, LEVEL_OP)?;
    Ok(BindResponse {
        result,
        server_sasl_creds,
    })
}

/// The components of LDAPResult, without `referral` (no code path, R49-17:
/// a `[3]` is then out of place). Spec: RFC 4511 §4.1.9.
fn ldap_result_components(r: &mut Reader<'_>) -> Result<LdapResult> {
    let code = enumerated(r)?;
    let result_code = ResultCode::from_code(code).ok_or(Error::UnrecognizedResultCode)?;
    let matched_dn = ldap_string(r, OCTET_STRING, MAX_LDAPDN_OCTETS, Limit::LdapDnOctets)?;
    let diagnostic_message = ldap_string(r, OCTET_STRING, MAX_LDAPDN_OCTETS, Limit::LdapDnOctets)?;
    Ok(LdapResult {
        result_code,
        matched_dn,
        diagnostic_message,
    })
}

// ---- Search ----

/// Spec: RFC 4511 §4.5.1 (SearchRequest); docs/49 §2.3 E14.
fn search_request(contents: &[u8], profile: Profile) -> Result<SearchRequest> {
    let mut r = Reader::new(contents, profile);
    let base_object = ldap_string(&mut r, OCTET_STRING, MAX_LDAPDN_OCTETS, Limit::LdapDnOctets)?;
    // "scope ENUMERATED { baseObject (0), singleLevel (1), wholeSubtree (2),
    // ... }" — an unknown value is kept for the engine (E14).
    let scope = match enumerated(&mut r)? {
        0 => Scope::BaseObject,
        1 => Scope::SingleLevel,
        2 => Scope::WholeSubtree,
        other => Scope::Unrecognized(i32::try_from(other).map_err(|_| Error::IntegerOutOfRange)?),
    };
    // "derefAliases ENUMERATED { neverDerefAliases (0) ... derefAlways (3) }",
    // extensible by implication (RFC 4511 §4).
    let deref_aliases = match enumerated(&mut r)? {
        0 => DerefAliases::NeverDerefAliases,
        1 => DerefAliases::DerefInSearching,
        2 => DerefAliases::DerefFindingBaseObj,
        3 => DerefAliases::DerefAlways,
        other => {
            DerefAliases::Unrecognized(i32::try_from(other).map_err(|_| Error::IntegerOutOfRange)?)
        }
    };
    let size_limit = zero_to_max_int(&mut r)?;
    let time_limit = zero_to_max_int(&mut r)?;
    // "typesOnly BOOLEAN" — no DEFAULT, so FALSE is encoded.
    let types_only = boolean(&mut r, BOOLEAN)?;
    let mut nodes = 0;
    let filter = filter(next(&mut r)?, profile, 1, &mut nodes)?;
    let attributes = attribute_selection(next(&mut r)?, profile)?;
    finish_sequence(&mut r, SEARCH_REQUEST_TAGS, LEVEL_OP)?;
    Ok(SearchRequest {
        base_object,
        scope,
        deref_aliases,
        size_limit,
        time_limit,
        types_only,
        filter,
        attributes,
    })
}

/// "AttributeSelection ::= SEQUENCE OF selector LDAPString".
/// Spec: RFC 4511 §4.5.1, §4.5.1.8; docs/49 §2.4 (64 selectors).
fn attribute_selection(tlv: Tlv<'_>, profile: Profile) -> Result<Vec<String>> {
    expect_identifier(tlv.identifier, SEQUENCE, false)?;
    let mut r = Reader::new(tlv.contents, profile);
    let mut selectors = Vec::new();
    while !r.is_empty() {
        if selectors.len() >= MAX_ATTRIBUTE_SELECTORS {
            return Err(Error::LimitExceeded(Limit::AttributeSelectors));
        }
        selectors.push(ldap_string(
            &mut r,
            OCTET_STRING,
            MAX_IDENTIFIER_OCTETS,
            Limit::IdentifierOctets,
        )?);
    }
    Ok(selectors)
}

/// Decode one Filter element at nesting `depth` (the top-level filter is
/// depth 1), counting every element against the node budget.
///
/// Spec: RFC 4511 §4.5.1 (Filter), §4.5.1.7 (`not` explicit in BER; unknown
/// alternatives are Undefined), §4.5.1.7.2, §4.5.1.7.7; docs/49 §2.3
/// E13/E15/E16, §2.4 (depth 32, 256 elements).
fn filter(tlv: Tlv<'_>, profile: Profile, depth: usize, nodes: &mut usize) -> Result<Filter> {
    if depth > MAX_FILTER_DEPTH {
        return Err(Error::LimitExceeded(Limit::FilterDepth));
    }
    *nodes += 1;
    if *nodes > MAX_FILTER_NODES {
        return Err(Error::LimitExceeded(Limit::FilterNodes));
    }
    let id = tlv.identifier;
    if id & CLASS_MASK != CLASS_CONTEXT {
        return Err(Error::UnexpectedTag);
    }
    let level = FILTER_BASE_LEVEL + depth;
    match id & NUMBER_MASK {
        number @ (0 | 1) => {
            // "and [0] SET SIZE (1..MAX) OF filter Filter" / "or [1] ...":
            // implicitly tagged SET OF, constructed (X.690 8.12.1).
            expect_form(id, true)?;
            let mut r = Reader::new(tlv.contents, profile);
            let mut items = Vec::new();
            while !r.is_empty() {
                let child = r.read_tlv()?;
                items.push(filter(child, profile, depth + 1, nodes)?);
            }
            if items.is_empty() {
                return Err(Error::EmptySet);
            }
            Ok(if number == 0 {
                Filter::And(items)
            } else {
                Filter::Or(items)
            })
        }
        2 => {
            // "not [2] Filter" — explicit: exactly one complete Filter.
            // Spec: RFC 4511 §4.5.1.7; X.690 8.14.3.
            expect_form(id, true)?;
            let mut r = Reader::new(tlv.contents, profile);
            let inner = filter(next(&mut r)?, profile, depth + 1, nodes)?;
            if !r.is_empty() {
                return Err(Error::TrailingData);
            }
            Ok(Filter::Not(Box::new(inner)))
        }
        number @ (3 | 5 | 6 | 8) => {
            expect_form(id, true)?;
            let ava = attribute_value_assertion(tlv.contents, profile, level)?;
            Ok(match number {
                3 => Filter::EqualityMatch(ava),
                5 => Filter::GreaterOrEqual(ava),
                6 => Filter::LessOrEqual(ava),
                _ => Filter::ApproxMatch(ava),
            })
        }
        4 => {
            expect_form(id, true)?;
            Ok(Filter::Substrings(substring_filter(
                tlv.contents,
                profile,
                level,
            )?))
        }
        7 => {
            // "present [7] AttributeDescription" — primitive (RFC 4511 §5.1).
            if is_constructed(id) {
                return Err(Error::ConstructedOctetString);
            }
            if tlv.contents.len() > MAX_IDENTIFIER_OCTETS {
                return Err(Error::LimitExceeded(Limit::IdentifierOctets));
            }
            let text = core::str::from_utf8(tlv.contents).map_err(|_| Error::InvalidUtf8)?;
            Ok(Filter::Present(text.to_owned()))
        }
        9 => {
            expect_form(id, true)?;
            Ok(Filter::ExtensibleMatch(matching_rule_assertion(
                tlv.contents,
                profile,
                level,
            )?))
        }
        tag_number => {
            unrecognized_alternative(&tlv, profile, level)?;
            Ok(Filter::Unrecognized { tag_number })
        }
    }
}

/// Spec: RFC 4511 §4.1.6 (AttributeValueAssertion); docs/49 §2.4.
fn attribute_value_assertion(
    contents: &[u8],
    profile: Profile,
    level: usize,
) -> Result<AttributeValueAssertion> {
    let mut r = Reader::new(contents, profile);
    let attribute_desc = ldap_string(
        &mut r,
        OCTET_STRING,
        MAX_IDENTIFIER_OCTETS,
        Limit::IdentifierOctets,
    )?;
    let assertion_value =
        bounded_octet_string(&mut r, OCTET_STRING, MAX_VALUE_OCTETS, Limit::ValueOctets)?.to_vec();
    finish_sequence(&mut r, AVA_TAGS, level)?;
    Ok(AttributeValueAssertion {
        attribute_desc,
        assertion_value,
    })
}

/// Check that `next` may follow `previous` in a SubstringFilter, with
/// `any_so_far` `any` components already present.
///
/// Spec: RFC 4511 §4.5.1.7.2 ("at most one 'initial' and at most one 'final'
/// ... If 'initial' is present, it SHALL be the first element ... If 'final'
/// is present, it SHALL be the last element"); docs/49 §2.3 E15, §2.4.
pub(crate) fn check_next_substring(
    previous: Option<&Substring>,
    next: &Substring,
    any_so_far: usize,
) -> Result<()> {
    if matches!(previous, Some(Substring::Final(_))) {
        return Err(Error::SubstringOrder);
    }
    match next {
        Substring::Initial(_) if previous.is_some() => Err(Error::SubstringOrder),
        Substring::Any(_) if any_so_far >= MAX_SUBSTRING_ANY => {
            Err(Error::LimitExceeded(Limit::SubstringAny))
        }
        _ => Ok(()),
    }
}

/// Spec: RFC 4511 §4.5.1 (SubstringFilter), §4.5.1.7.2.
fn substring_filter(contents: &[u8], profile: Profile, level: usize) -> Result<SubstringFilter> {
    let mut r = Reader::new(contents, profile);
    let r#type = ldap_string(
        &mut r,
        OCTET_STRING,
        MAX_IDENTIFIER_OCTETS,
        Limit::IdentifierOctets,
    )?;
    let list = next(&mut r)?;
    expect_identifier(list.identifier, SEQUENCE, false)?;
    let mut items = Reader::new(list.contents, profile);
    let mut substrings: Vec<Substring> = Vec::new();
    let mut any_count = 0;
    while !items.is_empty() {
        let element = items.read_tlv()?;
        let id = element.identifier;
        if id & CLASS_MASK != CLASS_CONTEXT {
            return Err(Error::UnexpectedTag);
        }
        let number = id & NUMBER_MASK;
        if number > 2 {
            // Not one of initial/any/final. Unknown alternatives of this inner
            // CHOICE are refused (not covered by E13; fail closed — Q-185).
            return Err(Error::UnexpectedTag);
        }
        // "[0..2] AssertionValue" — implicitly tagged OCTET STRING, primitive.
        if is_constructed(id) {
            return Err(Error::ConstructedOctetString);
        }
        if element.contents.len() > MAX_VALUE_OCTETS {
            return Err(Error::LimitExceeded(Limit::ValueOctets));
        }
        let value = element.contents.to_vec();
        let substring = match number {
            0 => Substring::Initial(value),
            1 => Substring::Any(value),
            _ => Substring::Final(value),
        };
        check_next_substring(substrings.last(), &substring, any_count)?;
        if matches!(substring, Substring::Any(_)) {
            any_count += 1;
        }
        substrings.push(substring);
    }
    if substrings.is_empty() {
        return Err(Error::EmptySubstrings);
    }
    finish_sequence(&mut r, SUBSTRING_FILTER_TAGS, level)?;
    Ok(SubstringFilter { r#type, substrings })
}

/// Spec: RFC 4511 §4.5.1 (MatchingRuleAssertion), §4.5.1.7.7, §5.1.
fn matching_rule_assertion(
    contents: &[u8],
    profile: Profile,
    level: usize,
) -> Result<MatchingRuleAssertion> {
    let mut r = Reader::new(contents, profile);
    let matching_rule = if peek_is(&r, context(1, false)) {
        Some(ldap_string(
            &mut r,
            context(1, false),
            MAX_IDENTIFIER_OCTETS,
            Limit::IdentifierOctets,
        )?)
    } else {
        None
    };
    let r#type = if peek_is(&r, context(2, false)) {
        Some(ldap_string(
            &mut r,
            context(2, false),
            MAX_IDENTIFIER_OCTETS,
            Limit::IdentifierOctets,
        )?)
    } else {
        None
    };
    let match_value = bounded_octet_string(
        &mut r,
        context(3, false),
        MAX_VALUE_OCTETS,
        Limit::ValueOctets,
    )?
    .to_vec();
    let dn_attributes = default_false_boolean(&mut r, context(4, false))?;
    // "If the matchingRule field is absent, the type field MUST be present".
    if matching_rule.is_none() && r#type.is_none() {
        return Err(Error::MissingMatchingRuleAndType);
    }
    finish_sequence(&mut r, MATCHING_RULE_ASSERTION_TAGS, level)?;
    Ok(MatchingRuleAssertion {
        matching_rule,
        r#type,
        match_value,
        dn_attributes,
    })
}

/// Spec: RFC 4511 §4.5.2 (SearchResultEntry, PartialAttributeList), §4.1.7;
/// docs/49 §2.4.
fn search_result_entry(contents: &[u8], profile: Profile) -> Result<SearchResultEntry> {
    let mut r = Reader::new(contents, profile);
    let object_name = ldap_string(&mut r, OCTET_STRING, MAX_LDAPDN_OCTETS, Limit::LdapDnOctets)?;
    let list = next(&mut r)?;
    expect_identifier(list.identifier, SEQUENCE, false)?;
    let mut items = Reader::new(list.contents, profile);
    let mut attributes = Vec::new();
    while !items.is_empty() {
        if attributes.len() >= MAX_PARTIAL_ATTRIBUTES {
            return Err(Error::LimitExceeded(Limit::PartialAttributes));
        }
        let element = items.read_tlv()?;
        expect_identifier(element.identifier, SEQUENCE, false)?;
        attributes.push(partial_attribute(element.contents, profile)?);
    }
    finish_sequence(&mut r, SEARCH_RESULT_ENTRY_TAGS, LEVEL_OP)?;
    Ok(SearchResultEntry {
        object_name,
        attributes,
    })
}

/// Spec: RFC 4511 §4.1.7 (PartialAttribute: `vals SET OF value
/// AttributeValue`, possibly empty); docs/49 §2.4.
fn partial_attribute(contents: &[u8], profile: Profile) -> Result<PartialAttribute> {
    let mut r = Reader::new(contents, profile);
    let r#type = ldap_string(
        &mut r,
        OCTET_STRING,
        MAX_IDENTIFIER_OCTETS,
        Limit::IdentifierOctets,
    )?;
    let set = next(&mut r)?;
    expect_identifier(set.identifier, SET, false)?;
    let mut values = Reader::new(set.contents, profile);
    let mut vals = Vec::new();
    while !values.is_empty() {
        if vals.len() >= MAX_ATTRIBUTE_VALUES {
            return Err(Error::LimitExceeded(Limit::AttributeValues));
        }
        vals.push(
            bounded_octet_string(
                &mut values,
                OCTET_STRING,
                MAX_VALUE_OCTETS,
                Limit::ValueOctets,
            )?
            .to_vec(),
        );
    }
    // Inside SearchResultEntry and its PartialAttributeList.
    finish_sequence(&mut r, PARTIAL_ATTRIBUTE_TAGS, LEVEL_COMPONENT + 1)?;
    Ok(PartialAttribute { r#type, vals })
}

// ---- Extended ----

/// Spec: RFC 4511 §4.12 (ExtendedRequest), §4.14.1 (StartTLS). Any
/// `requestName` is accepted here; the engine compares it octet for octet and
/// refuses all but StartTLS (docs/49 §5.1).
fn extended_request(contents: &[u8], profile: Profile) -> Result<ExtendedRequest> {
    let mut r = Reader::new(contents, profile);
    let request_name = ldap_string(
        &mut r,
        context(0, false),
        MAX_IDENTIFIER_OCTETS,
        Limit::IdentifierOctets,
    )?;
    let request_value = if peek_is(&r, context(1, false)) {
        Some(octet_string(&mut r, context(1, false))?.to_vec())
    } else {
        None
    };
    finish_sequence(&mut r, EXTENDED_REQUEST_TAGS, LEVEL_OP)?;
    Ok(ExtendedRequest {
        request_name,
        request_value,
    })
}

/// Spec: RFC 4511 §4.12 (ExtendedResponse).
fn extended_response(contents: &[u8], profile: Profile) -> Result<ExtendedResponse> {
    let mut r = Reader::new(contents, profile);
    let result = ldap_result_components(&mut r)?;
    let response_name = if peek_is(&r, context(10, false)) {
        Some(ldap_string(
            &mut r,
            context(10, false),
            MAX_IDENTIFIER_OCTETS,
            Limit::IdentifierOctets,
        )?)
    } else {
        None
    };
    let response_value = if peek_is(&r, context(11, false)) {
        Some(octet_string(&mut r, context(11, false))?.to_vec())
    } else {
        None
    };
    finish_sequence(&mut r, EXTENDED_RESPONSE_TAGS, LEVEL_OP)?;
    Ok(ExtendedResponse {
        result,
        response_name,
        response_value,
    })
}

// ---- Controls ----

/// "controls [0] Controls" with "Controls ::= SEQUENCE OF control Control".
/// Spec: RFC 4511 §4.1.1, §4.1.11; docs/49 §2.4 (8 controls), R49-8.
fn controls(tlv: Tlv<'_>, profile: Profile) -> Result<Vec<Control>> {
    expect_identifier(tlv.identifier, CONTROLS, false)?;
    let mut r = Reader::new(tlv.contents, profile);
    let mut out = Vec::new();
    while !r.is_empty() {
        if out.len() >= MAX_CONTROLS {
            return Err(Error::LimitExceeded(Limit::Controls));
        }
        let element = r.read_tlv()?;
        expect_identifier(element.identifier, SEQUENCE, false)?;
        out.push(control(element.contents, profile)?);
    }
    Ok(out)
}

/// Spec: RFC 4511 §4.1.11 (Control), §5.1 (`criticality` FALSE is absent).
fn control(contents: &[u8], profile: Profile) -> Result<Control> {
    let mut r = Reader::new(contents, profile);
    let control_type = ldap_string(
        &mut r,
        OCTET_STRING,
        MAX_IDENTIFIER_OCTETS,
        Limit::IdentifierOctets,
    )?;
    let criticality = default_false_boolean(&mut r, BOOLEAN)?;
    // "controlValue OCTET STRING OPTIONAL" — arbitrary contents, bounded by
    // the message bound ("Implementations MUST be prepared to handle
    // arbitrary contents of the controlValue octet string").
    let control_value = if peek_is(&r, OCTET_STRING) {
        Some(octet_string(&mut r, OCTET_STRING)?.to_vec())
    } else {
        None
    };
    finish_sequence(&mut r, CONTROL_TAGS, LEVEL_COMPONENT)?;
    Ok(Control {
        control_type,
        criticality,
        control_value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Source: [MS-ADTS] v20261026 6.3.3 "Network payload", verbatim: the
    /// `and` filter of an LDAP ping, every length in the four-octet long form
    /// (the A-45 reason), followed by the AttributeSelection `"netlogon"`.
    const MS_ADTS_6_3_3_PAYLOAD: &[u8] = &[
        0xA0, 0x84, 0x00, 0x00, 0x00, 0xA8, 0xA3, 0x84, 0x00, 0x00, 0x00, 0x25, 0x04, 0x09, 0x44,
        0x6E, 0x73, 0x44, 0x6F, 0x6D, 0x61, 0x69, 0x6E, 0x04, 0x18, 0x61, 0x62, 0x63, 0x64, 0x65,
        0x2E, 0x63, 0x6F, 0x72, 0x70, 0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74,
        0x2E, 0x63, 0x6F, 0x6D, 0xA3, 0x84, 0x00, 0x00, 0x00, 0x14, 0x04, 0x04, 0x48, 0x6F, 0x73,
        0x74, 0x04, 0x0C, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x2D, 0x64, 0x65, 0x76,
        0xA3, 0x84, 0x00, 0x00, 0x00, 0x15, 0x04, 0x04, 0x55, 0x73, 0x65, 0x72, 0x04, 0x0D, 0x61,
        0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x2D, 0x64, 0x65, 0x76, 0x24, 0xA3, 0x84, 0x00,
        0x00, 0x00, 0x0B, 0x04, 0x03, 0x41, 0x41, 0x43, 0x04, 0x04, 0x80, 0x00, 0x00, 0x00, 0xA3,
        0x84, 0x00, 0x00, 0x00, 0x1E, 0x04, 0x0A, 0x44, 0x6F, 0x6D, 0x61, 0x69, 0x6E, 0x47, 0x75,
        0x69, 0x64, 0x04, 0x10, 0x3B, 0xB0, 0x21, 0xCA, 0xD3, 0x6D, 0xD1, 0x11, 0x8A, 0x7D, 0xB8,
        0xDF, 0xB1, 0x56, 0x87, 0x1F, 0xA3, 0x84, 0x00, 0x00, 0x00, 0x0D, 0x04, 0x05, 0x4E, 0x74,
        0x56, 0x65, 0x72, 0x04, 0x04, 0x06, 0x00, 0x00, 0x00, 0x30, 0x84, 0x00, 0x00, 0x00, 0x0A,
        0x04, 0x08, 0x6E, 0x65, 0x74, 0x6C, 0x6F, 0x67, 0x6F, 0x6E,
    ];

    /// The filter and AttributeSelection of the [MS-ADTS] 6.3.3 payload decode
    /// with the wire profile; the canonical profile refuses the long lengths.
    #[test]
    fn ms_adts_6_3_3_filter_and_selection() {
        let mut r = Reader::new(MS_ADTS_6_3_3_PAYLOAD, Profile::Wire);
        let mut nodes = 0;
        let parsed = filter(r.read_tlv().unwrap(), Profile::Wire, 1, &mut nodes).unwrap();
        let Filter::And(items) = parsed else {
            panic!("expected an and filter");
        };
        let names: Vec<&str> = items
            .iter()
            .map(|f| match f {
                Filter::EqualityMatch(ava) => ava.attribute_desc.as_str(),
                _ => panic!("expected equalityMatch"),
            })
            .collect();
        assert_eq!(
            names,
            ["DnsDomain", "Host", "User", "AAC", "DomainGuid", "NtVer"]
        );
        assert_eq!(nodes, 7);
        let selection = attribute_selection(r.read_tlv().unwrap(), Profile::Wire).unwrap();
        assert_eq!(selection, ["netlogon"]);
        assert!(r.is_empty());

        let mut canonical = Reader::new(MS_ADTS_6_3_3_PAYLOAD, Profile::Canonical);
        assert_eq!(canonical.read_tlv().unwrap_err(), Error::NonMinimalLength);
    }
}
