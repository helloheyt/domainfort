//! Typed LDAP messages for the phase-1 operations (docs/49 R49-7).
//!
//! Type and field names follow the ASN.1 module of RFC 4511 App. B, in Rust
//! conventions (`baseObject` → `base_object`; the field `type` keeps its name
//! as the raw identifier `r#type`). Only the operations phase 1 handles are
//! modelled; the other request operations are recognised by tag alone
//! ([`ProtocolOp::Unsupported`], A-48), and referrals, IntermediateResponse and
//! SearchResultReference have no code path (R49-17).

use core::fmt;

use crate::error::{Error, Result};
use crate::limits::MAX_INT;

/// `requestName` / `responseName` of StartTLS. Spec: RFC 4511 §4.14.1, §4.14.2.
pub const START_TLS_OID: &str = "1.3.6.1.4.1.1466.20037";

/// `responseName` of the Notice of Disconnection. Spec: RFC 4511 §4.4.1.
pub const NOTICE_OF_DISCONNECTION_OID: &str = "1.3.6.1.4.1.1466.20036";

/// The octet a non-empty simple-bind password is re-encoded as.
///
/// The password octets are never retained (docs/49 §2.3: only the "shape" of
/// `simple` is decoded); the canonical encoding keeps the one fact the engine
/// uses — empty or not — by writing this single placeholder octet, and the
/// canonical profile accepts nothing else. Listed in Q-185.
pub const SIMPLE_PASSWORD_PLACEHOLDER: u8 = 0x00;

/// `MessageID ::= INTEGER (0 .. maxInt)`.
///
/// Spec: RFC 4511 §4.1.1, §4.1.1.1 (zero is reserved for the unsolicited
/// notification).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(u32);

impl MessageId {
    /// The MessageID of an unsolicited notification. Spec: RFC 4511 §4.4.
    pub const UNSOLICITED: MessageId = MessageId(0);

    /// A MessageID, if `value` is within `0 .. maxInt`.
    /// Spec: RFC 4511 §4.1.1.
    pub const fn new(value: u32) -> Result<MessageId> {
        if value > MAX_INT {
            Err(Error::MessageIdOutOfRange)
        } else {
            Ok(MessageId(value))
        }
    }

    /// The numeric value.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// `LDAPMessage`. Spec: RFC 4511 §4.1.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapMessage {
    pub message_id: MessageId,
    pub protocol_op: ProtocolOp,
    /// `controls [0] Controls OPTIONAL` — `None` when absent; `Some(vec![])`
    /// when present but empty (a distinct ASN.1 value, preserved).
    pub controls: Option<Vec<Control>>,
}

impl LdapMessage {
    /// The Notice of Disconnection: MessageID zero, an ExtendedResponse with
    /// `responseName` 1.3.6.1.4.1.1466.20036, no `responseValue`, and
    /// `resultCode` giving the reason.
    /// Spec: RFC 4511 §4.4, §4.4.1; docs/49 §9 (empty matchedDN and
    /// diagnosticMessage).
    pub fn notice_of_disconnection(result_code: ResultCode) -> LdapMessage {
        LdapMessage {
            message_id: MessageId::UNSOLICITED,
            protocol_op: ProtocolOp::ExtendedResponse(ExtendedResponse {
                result: LdapResult::new(result_code),
                response_name: Some(NOTICE_OF_DISCONNECTION_OID.to_owned()),
                response_value: None,
            }),
            controls: None,
        }
    }
}

/// The `protocolOp` CHOICE, restricted to phase 1. Spec: RFC 4511 §4.1.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolOp {
    /// `[APPLICATION 0]`. Spec: RFC 4511 §4.2.
    BindRequest(BindRequest),
    /// `[APPLICATION 1]`. Spec: RFC 4511 §4.2.2.
    BindResponse(BindResponse),
    /// `[APPLICATION 2] NULL`. Spec: RFC 4511 §4.3.
    UnbindRequest,
    /// `[APPLICATION 3]`. Spec: RFC 4511 §4.5.1.
    SearchRequest(SearchRequest),
    /// `[APPLICATION 4]`. Spec: RFC 4511 §4.5.2.
    SearchResultEntry(SearchResultEntry),
    /// `[APPLICATION 5] LDAPResult`. Spec: RFC 4511 §4.5.2.
    SearchResultDone(LdapResult),
    /// `[APPLICATION 16] MessageID` — the MessageID of the operation to
    /// abandon. Spec: RFC 4511 §4.11.
    AbandonRequest(MessageId),
    /// `[APPLICATION 23]`. Spec: RFC 4511 §4.12.
    ExtendedRequest(ExtendedRequest),
    /// `[APPLICATION 24]`. Spec: RFC 4511 §4.12.
    ExtendedResponse(ExtendedResponse),
    /// A request operation outside phase 1, recognised by its tag only; its
    /// body is bounded but never decoded, so the engine answers
    /// `unwillingToPerform`. The canonical encoding is the tag with an empty
    /// body. Spec: docs/49 §5.1; A-48.
    Unsupported { op_tag: UnsupportedOp },
}

/// The request operations phase 1 recognises but does not perform.
/// Spec: RFC 4511 §4.6–§4.10 (their tags); A-48.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedOp {
    /// `ModifyRequest ::= [APPLICATION 6] SEQUENCE`. Spec: RFC 4511 §4.6.
    ModifyRequest,
    /// `AddRequest ::= [APPLICATION 8] SEQUENCE`. Spec: RFC 4511 §4.7.
    AddRequest,
    /// `DelRequest ::= [APPLICATION 10] LDAPDN`. Spec: RFC 4511 §4.8.
    DelRequest,
    /// `ModifyDNRequest ::= [APPLICATION 12] SEQUENCE`. Spec: RFC 4511 §4.9.
    ModifyDnRequest,
    /// `CompareRequest ::= [APPLICATION 14] SEQUENCE`. Spec: RFC 4511 §4.10.
    CompareRequest,
}

impl UnsupportedOp {
    /// The APPLICATION tag number of the request. Spec: RFC 4511 App. B.
    pub const fn tag_number(self) -> u8 {
        match self {
            UnsupportedOp::ModifyRequest => 6,
            UnsupportedOp::AddRequest => 8,
            UnsupportedOp::DelRequest => 10,
            UnsupportedOp::ModifyDnRequest => 12,
            UnsupportedOp::CompareRequest => 14,
        }
    }

    /// The APPLICATION tag number of the matching response (ModifyResponse 7,
    /// AddResponse 9, DelResponse 11, ModifyDNResponse 13, CompareResponse 15).
    /// Spec: RFC 4511 App. B.
    pub const fn response_tag_number(self) -> u8 {
        self.tag_number() + 1
    }
}

/// `BindRequest`. Spec: RFC 4511 §4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRequest {
    /// `version INTEGER (1 .. 127)`; a value other than 3 is the engine's to
    /// answer with `protocolError` (§4.2, docs/49 E9).
    pub version: u8,
    /// `name LDAPDN`.
    pub name: String,
    pub authentication: AuthenticationChoice,
}

/// `AuthenticationChoice`. Spec: RFC 4511 §4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationChoice {
    /// `simple [0] OCTET STRING`, decoded to its shape only: the password
    /// octets are never retained (docs/49 §2.3). Name/password simple bind has
    /// no code path (AGENTS.md §6; R49-4) — the codec parses it only so the
    /// engine can refuse it.
    Simple { password_empty: bool },
    /// `sasl [3] SaslCredentials`.
    Sasl(SaslCredentials),
    /// Any other context-specific alternative of the extensible CHOICE
    /// (including the reserved `[1]`/`[2]`). Its contents are validated and
    /// dropped; the engine answers `authMethodNotSupported`.
    /// Spec: RFC 4511 §4.2 ("Servers that do not support a choice supplied by
    /// a client return ... authMethodNotSupported"); docs/49 §2.3 E13.
    Unrecognized { tag_number: u8 },
}

/// `SaslCredentials`. Spec: RFC 4511 §4.2.
#[derive(Clone, PartialEq, Eq)]
pub struct SaslCredentials {
    /// `mechanism LDAPString`.
    pub mechanism: String,
    /// `credentials OCTET STRING OPTIONAL`.
    pub credentials: Option<Vec<u8>>,
}

impl fmt::Debug for SaslCredentials {
    /// Shows only the size of `credentials`: SASL tokens never reach debug
    /// output (AGENTS.md §6; docs/49 §10).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SaslCredentials")
            .field("mechanism", &self.mechanism)
            .field(
                "credentials",
                &self.credentials.as_ref().map(|c| Redacted(c.len())),
            )
            .finish()
    }
}

/// Debug stand-in for octets that must not be printed.
struct Redacted(usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} octets>", self.0)
    }
}

/// `BindResponse`. Spec: RFC 4511 §4.2.2.
#[derive(Clone, PartialEq, Eq)]
pub struct BindResponse {
    /// `COMPONENTS OF LDAPResult`.
    pub result: LdapResult,
    /// `serverSaslCreds [7] OCTET STRING OPTIONAL`.
    pub server_sasl_creds: Option<Vec<u8>>,
}

impl fmt::Debug for BindResponse {
    /// Shows only the size of `serverSaslCreds` (AGENTS.md §6; docs/49 §10).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindResponse")
            .field("result", &self.result)
            .field(
                "server_sasl_creds",
                &self.server_sasl_creds.as_ref().map(|c| Redacted(c.len())),
            )
            .finish()
    }
}

/// `LDAPResult`, without `referral` (no code path, R49-17).
/// Spec: RFC 4511 §4.1.9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapResult {
    pub result_code: ResultCode,
    /// `matchedDN LDAPDN`.
    pub matched_dn: String,
    /// `diagnosticMessage LDAPString`.
    pub diagnostic_message: String,
}

impl LdapResult {
    /// A result with empty `matchedDN` and `diagnosticMessage`, as the engine
    /// always sends. Spec: RFC 4511 §4.1.9 ("If the server chooses not to
    /// return a textual diagnostic, the diagnosticMessage field MUST be
    /// empty"); docs/49 R49-13.
    pub fn new(result_code: ResultCode) -> LdapResult {
        LdapResult {
            result_code,
            matched_dn: String::new(),
            diagnostic_message: String::new(),
        }
    }
}

/// The `resultCode` ENUMERATED. Spec: RFC 4511 §4.1.9 (values), App. A.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResultCode {
    Success,
    OperationsError,
    ProtocolError,
    TimeLimitExceeded,
    SizeLimitExceeded,
    CompareFalse,
    CompareTrue,
    AuthMethodNotSupported,
    StrongerAuthRequired,
    Referral,
    AdminLimitExceeded,
    UnavailableCriticalExtension,
    ConfidentialityRequired,
    SaslBindInProgress,
    NoSuchAttribute,
    UndefinedAttributeType,
    InappropriateMatching,
    ConstraintViolation,
    AttributeOrValueExists,
    InvalidAttributeSyntax,
    NoSuchObject,
    AliasProblem,
    InvalidDnSyntax,
    AliasDereferencingProblem,
    InappropriateAuthentication,
    InvalidCredentials,
    InsufficientAccessRights,
    Busy,
    Unavailable,
    UnwillingToPerform,
    LoopDetect,
    NamingViolation,
    ObjectClassViolation,
    NotAllowedOnNonLeaf,
    NotAllowedOnRdn,
    EntryAlreadyExists,
    ObjectClassModsProhibited,
    AffectsMultipleDsas,
    Other,
}

impl ResultCode {
    /// The enumerated value. Spec: RFC 4511 §4.1.9.
    pub const fn code(self) -> u8 {
        match self {
            ResultCode::Success => 0,
            ResultCode::OperationsError => 1,
            ResultCode::ProtocolError => 2,
            ResultCode::TimeLimitExceeded => 3,
            ResultCode::SizeLimitExceeded => 4,
            ResultCode::CompareFalse => 5,
            ResultCode::CompareTrue => 6,
            ResultCode::AuthMethodNotSupported => 7,
            ResultCode::StrongerAuthRequired => 8,
            ResultCode::Referral => 10,
            ResultCode::AdminLimitExceeded => 11,
            ResultCode::UnavailableCriticalExtension => 12,
            ResultCode::ConfidentialityRequired => 13,
            ResultCode::SaslBindInProgress => 14,
            ResultCode::NoSuchAttribute => 16,
            ResultCode::UndefinedAttributeType => 17,
            ResultCode::InappropriateMatching => 18,
            ResultCode::ConstraintViolation => 19,
            ResultCode::AttributeOrValueExists => 20,
            ResultCode::InvalidAttributeSyntax => 21,
            ResultCode::NoSuchObject => 32,
            ResultCode::AliasProblem => 33,
            ResultCode::InvalidDnSyntax => 34,
            ResultCode::AliasDereferencingProblem => 36,
            ResultCode::InappropriateAuthentication => 48,
            ResultCode::InvalidCredentials => 49,
            ResultCode::InsufficientAccessRights => 50,
            ResultCode::Busy => 51,
            ResultCode::Unavailable => 52,
            ResultCode::UnwillingToPerform => 53,
            ResultCode::LoopDetect => 54,
            ResultCode::NamingViolation => 64,
            ResultCode::ObjectClassViolation => 65,
            ResultCode::NotAllowedOnNonLeaf => 66,
            ResultCode::NotAllowedOnRdn => 67,
            ResultCode::EntryAlreadyExists => 68,
            ResultCode::ObjectClassModsProhibited => 69,
            ResultCode::AffectsMultipleDsas => 71,
            ResultCode::Other => 80,
        }
    }

    /// The result code with this enumerated value, if RFC 4511 defines one.
    /// Spec: RFC 4511 §4.1.9.
    pub fn from_code(code: i64) -> Option<ResultCode> {
        ALL_RESULT_CODES
            .iter()
            .copied()
            .find(|rc| i64::from(rc.code()) == code)
    }
}

/// Every [`ResultCode`], in the order of RFC 4511 §4.1.9.
const ALL_RESULT_CODES: [ResultCode; 39] = [
    ResultCode::Success,
    ResultCode::OperationsError,
    ResultCode::ProtocolError,
    ResultCode::TimeLimitExceeded,
    ResultCode::SizeLimitExceeded,
    ResultCode::CompareFalse,
    ResultCode::CompareTrue,
    ResultCode::AuthMethodNotSupported,
    ResultCode::StrongerAuthRequired,
    ResultCode::Referral,
    ResultCode::AdminLimitExceeded,
    ResultCode::UnavailableCriticalExtension,
    ResultCode::ConfidentialityRequired,
    ResultCode::SaslBindInProgress,
    ResultCode::NoSuchAttribute,
    ResultCode::UndefinedAttributeType,
    ResultCode::InappropriateMatching,
    ResultCode::ConstraintViolation,
    ResultCode::AttributeOrValueExists,
    ResultCode::InvalidAttributeSyntax,
    ResultCode::NoSuchObject,
    ResultCode::AliasProblem,
    ResultCode::InvalidDnSyntax,
    ResultCode::AliasDereferencingProblem,
    ResultCode::InappropriateAuthentication,
    ResultCode::InvalidCredentials,
    ResultCode::InsufficientAccessRights,
    ResultCode::Busy,
    ResultCode::Unavailable,
    ResultCode::UnwillingToPerform,
    ResultCode::LoopDetect,
    ResultCode::NamingViolation,
    ResultCode::ObjectClassViolation,
    ResultCode::NotAllowedOnNonLeaf,
    ResultCode::NotAllowedOnRdn,
    ResultCode::EntryAlreadyExists,
    ResultCode::ObjectClassModsProhibited,
    ResultCode::AffectsMultipleDsas,
    ResultCode::Other,
];

/// `SearchRequest`. Spec: RFC 4511 §4.5.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    /// `baseObject LDAPDN`.
    pub base_object: String,
    pub scope: Scope,
    pub deref_aliases: DerefAliases,
    /// `sizeLimit INTEGER (0 .. maxInt)`; zero means no client limit.
    pub size_limit: u32,
    /// `timeLimit INTEGER (0 .. maxInt)`; zero means no client limit.
    pub time_limit: u32,
    /// `typesOnly BOOLEAN`.
    pub types_only: bool,
    pub filter: Filter,
    /// `attributes AttributeSelection` — each an LDAPString selector.
    pub attributes: Vec<String>,
}

/// `scope ENUMERATED { ..., ... }`. Spec: RFC 4511 §4.5.1, §4.5.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    BaseObject,
    SingleLevel,
    WholeSubtree,
    /// A value outside the root of the extensible enumeration; the engine
    /// answers `protocolError` (docs/49 §2.3 E14).
    Unrecognized(i32),
}

/// `derefAliases ENUMERATED`. Spec: RFC 4511 §4.5.1, §4.5.1.3. Aliases do not
/// exist in phase 1, so the engine ignores this field (R49-17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerefAliases {
    NeverDerefAliases,
    DerefInSearching,
    DerefFindingBaseObj,
    DerefAlways,
    /// A value outside the defined ones; enumerations are extensible by
    /// implication (RFC 4511 §4 "EXTENSIBILITY IMPLIED"). Listed in Q-185.
    Unrecognized(i32),
}

/// `Filter`. Spec: RFC 4511 §4.5.1, §4.5.1.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// `and [0] SET SIZE (1..MAX) OF filter Filter`. SET OF order is kept as
    /// received (X.690 8.12.3 — order is not significant).
    And(Vec<Filter>),
    /// `or [1] SET SIZE (1..MAX) OF filter Filter`.
    Or(Vec<Filter>),
    /// `not [2] Filter` — explicit in BER (RFC 4511 §4.5.1.7).
    Not(Box<Filter>),
    /// `equalityMatch [3] AttributeValueAssertion`.
    EqualityMatch(AttributeValueAssertion),
    /// `substrings [4] SubstringFilter`.
    Substrings(SubstringFilter),
    /// `greaterOrEqual [5] AttributeValueAssertion`.
    GreaterOrEqual(AttributeValueAssertion),
    /// `lessOrEqual [6] AttributeValueAssertion`.
    LessOrEqual(AttributeValueAssertion),
    /// `present [7] AttributeDescription`.
    Present(String),
    /// `approxMatch [8] AttributeValueAssertion`.
    ApproxMatch(AttributeValueAssertion),
    /// `extensibleMatch [9] MatchingRuleAssertion`.
    ExtensibleMatch(MatchingRuleAssertion),
    /// A context-specific alternative of the extensible CHOICE that RFC 4511
    /// does not define; its contents are validated and dropped, and the item
    /// evaluates to Undefined. Spec: RFC 4511 §4.5.1.7 ("The type of filtering
    /// requested is not implemented"); docs/49 §2.3 E13.
    Unrecognized { tag_number: u8 },
}

/// `AttributeValueAssertion`. Spec: RFC 4511 §4.1.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeValueAssertion {
    /// `attributeDesc AttributeDescription`.
    pub attribute_desc: String,
    /// `assertionValue AssertionValue` (OCTET STRING — not UTF-8 checked).
    pub assertion_value: Vec<u8>,
}

/// `SubstringFilter`. Spec: RFC 4511 §4.5.1, §4.5.1.7.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstringFilter {
    /// `type AttributeDescription`.
    pub r#type: String,
    /// `substrings SEQUENCE SIZE (1..MAX) OF substring CHOICE`.
    pub substrings: Vec<Substring>,
}

/// One `substring` CHOICE alternative. Spec: RFC 4511 §4.5.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Substring {
    /// `initial [0] AssertionValue` — at most once, first.
    Initial(Vec<u8>),
    /// `any [1] AssertionValue`.
    Any(Vec<u8>),
    /// `final [2] AssertionValue` — at most once, last.
    Final(Vec<u8>),
}

/// `MatchingRuleAssertion`. Spec: RFC 4511 §4.5.1, §4.5.1.7.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchingRuleAssertion {
    /// `matchingRule [1] MatchingRuleId OPTIONAL`.
    pub matching_rule: Option<String>,
    /// `type [2] AttributeDescription OPTIONAL`.
    pub r#type: Option<String>,
    /// `matchValue [3] AssertionValue`.
    pub match_value: Vec<u8>,
    /// `dnAttributes [4] BOOLEAN DEFAULT FALSE`.
    pub dn_attributes: bool,
}

/// `SearchResultEntry`. Spec: RFC 4511 §4.5.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResultEntry {
    /// `objectName LDAPDN`.
    pub object_name: String,
    /// `attributes PartialAttributeList`.
    pub attributes: Vec<PartialAttribute>,
}

/// `PartialAttribute`. Spec: RFC 4511 §4.1.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialAttribute {
    /// `type AttributeDescription`.
    pub r#type: String,
    /// `vals SET OF value AttributeValue` — may be empty; order as given.
    pub vals: Vec<Vec<u8>>,
}

/// `ExtendedRequest`. Spec: RFC 4511 §4.12.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedRequest {
    /// `requestName [0] LDAPOID` — compared octet for octet by the engine
    /// (docs/49 §2.3 "LDAPOID").
    pub request_name: String,
    /// `requestValue [1] OCTET STRING OPTIONAL`.
    pub request_value: Option<Vec<u8>>,
}

impl ExtendedRequest {
    /// Whether this is the StartTLS request name. Spec: RFC 4511 §4.14.1.
    pub fn is_start_tls(&self) -> bool {
        self.request_name == START_TLS_OID
    }
}

/// `ExtendedResponse`. Spec: RFC 4511 §4.12.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedResponse {
    /// `COMPONENTS OF LDAPResult`.
    pub result: LdapResult,
    /// `responseName [10] LDAPOID OPTIONAL`.
    pub response_name: Option<String>,
    /// `responseValue [11] OCTET STRING OPTIONAL`.
    pub response_value: Option<Vec<u8>>,
}

/// `Control`. Spec: RFC 4511 §4.1.11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    /// `controlType LDAPOID`.
    pub control_type: String,
    /// `criticality BOOLEAN DEFAULT FALSE`.
    pub criticality: bool,
    /// `controlValue OCTET STRING OPTIONAL`.
    pub control_value: Option<Vec<u8>>,
}
