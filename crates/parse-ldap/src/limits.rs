//! Resource bounds of the codec, each a named constant with its justification.
//!
//! docs/CLEAN-ROOM.md (and docs/32 §8, per docs/49 §2.4) require bounds but do not
//! fix the numbers, so
//! each value below is a project choice (docs/49 §2.4, R49-3), anchored where
//! possible to the LDAP policy names of [MS-ADTS] 3.1.1.3.4.6 but stricter than
//! their defaults. Every string and value is also bounded by the enclosing
//! element, which is bounded by the message bound — so nothing is ever
//! allocated from an attacker-supplied length beyond the input actually present.

/// `maxInt` of the LDAP module: the upper bound of MessageID, `sizeLimit` and
/// `timeLimit`. Spec: RFC 4511 §4.1.1 ("maxInt INTEGER ::= 2147483647").
pub const MAX_INT: u32 = 2_147_483_647;

/// Largest LDAPMessage accepted on an unauthenticated session: 64 KiB.
///
/// Spec: docs/49 §2.4 (`MAX_PREAUTH_PDU`). Anchor: [MS-ADTS] 3.1.1.3.4.6
/// MaxPreAuthReceiveBuffer, default 262,144 — "If the server receives a request
/// that is larger than this, it will drop the connection". Stricter: an
/// anonymous or binding client needs only a bind (SASL token) or rootDSE search.
pub const MAX_PREAUTH_MESSAGE_OCTETS: usize = 64 * 1024;

/// Largest LDAPMessage accepted on an authenticated session: 1 MiB.
///
/// Spec: docs/49 §2.4 (`MAX_AUTH_PDU`). Anchor: [MS-ADTS] 3.1.1.3.4.6
/// MaxReceiveBuffer, default 10,485,760. Stricter: phase 1 has no writes
/// (R49-12), so no request needs to carry large values.
pub const MAX_AUTH_MESSAGE_OCTETS: usize = 1024 * 1024;

/// Most subsequent octets in a long-form length: 4.
///
/// Spec: A-45 (docs/questions/Q-160 item 1) — X.690 8.1.3.5 NOTE 2 makes extra
/// length octets a sender's option, and the [MS-ADTS] 6.3.3 example uses
/// `84 00 00 00 A8`. Four octets cover every message the bounds above admit.
pub const MAX_LENGTH_OCTETS: usize = 4;

/// Deepest nesting of constructed elements (including inside skipped
/// unrecognised components): 64.
///
/// Spec: docs/49 §2.4 — the same value as `parse_asn1::MAX_DEPTH`. The fixed
/// grammar nests at most ~8 levels outside a filter, and the filter depth bound
/// below keeps the whole message far under this.
pub const MAX_TLV_DEPTH: usize = 64;

/// Deepest nesting of Filter choices: 32 (the top-level filter is depth 1).
///
/// Spec: docs/49 §2.4, which anchors it to the filter-depth limit of
/// [MS-ADTS] 3.1.1.3.1.3.1 (stricter) and to docs/07 §1's cap on filter depth
/// and width.
pub const MAX_FILTER_DEPTH: usize = 32;

/// Most Filter elements in one search filter: 256.
///
/// Spec: docs/49 §2.4 (there anchored to docs/07 §1).
pub const MAX_FILTER_NODES: usize = 256;

/// Most `any` components in one SubstringFilter: 16.
///
/// Spec: docs/49 §2.4 (there anchored to docs/07 §1).
pub const MAX_SUBSTRING_ANY: usize = 16;

/// Most selectors in one AttributeSelection: 64.
///
/// Spec: docs/49 §2.4.
pub const MAX_ATTRIBUTE_SELECTORS: usize = 64;

/// Most controls on one message: 8.
///
/// Spec: docs/49 §2.4. Phase 1 supports no control at all (R49-8); the engine
/// only needs to see each one to refuse a critical one.
pub const MAX_CONTROLS: usize = 8;

/// Most octets in an LDAPDN (also applied to `diagnosticMessage`): 2048.
///
/// Spec: docs/49 §2.4 (there anchored to the [MS-ADTS] 3.1.1.5.1.2 RDN length
/// limit and `directory_pip::MAX_DN_DEPTH`, 64).
pub const MAX_LDAPDN_OCTETS: usize = 2048;

/// Most RDNs in one distinguished name: 64.
///
/// Spec: docs/49 §2.4, which anchors the LDAPDN bound to
/// `directory_pip::MAX_DN_DEPTH` (64): a DN with more RDNs than the directory
/// produces or resolves can never name an object.
pub const MAX_DN_RDNS: usize = 64;

/// Most octets in one RDN attribute value, counted unescaped: 252.
///
/// Spec: [MS-ADTS] 3.1.1.5.1.2 ("The RDN size MUST be less than 255
/// characters"), read strictly as the whole "att=val" string ([MS-ADTS]
/// 3.1.1.1.4; docs/46 §8.3 item 3; Q-090 / A-30), the value counted unescaped
/// (Q-090 item 3). The shortest attributeType is one character (RFC 4512
/// §1.4: `keystring`, `number`), so `1 + 1 + value < 255` bounds the value at
/// 252: a longer one cannot name any object. Phase-1 values are printable
/// ASCII (Q-080), so octets are characters. dirstore applies the exact rule,
/// with the label length of the class's RDN attribute, on create.
pub const MAX_RDN_VALUE_OCTETS: usize = 252;

/// Most octets in a short identifier string: AttributeDescription, attribute
/// selector, LDAPOID (`controlType`, `requestName`, `responseName`),
/// MatchingRuleId and SASL `mechanism`: 256.
///
/// Project choice (not in docs/49 §2.4; listed in Q-185): more than ten times
/// the 22-octet OIDs of RFC 4511 §4.4.1 / §4.14.1.
pub const MAX_IDENTIFIER_OCTETS: usize = 256;

/// Most PartialAttributes in one SearchResultEntry: 256.
///
/// Spec: docs/49 §2.4 — `dirstore::MAX_ATTRIBUTES_PER_OBJECT` (256).
pub const MAX_PARTIAL_ATTRIBUTES: usize = 256;

/// Most values of one PartialAttribute: 4096.
///
/// Spec: docs/49 §2.4 — `dirstore::MAX_VALUES_PER_ATTRIBUTE` (4096).
pub const MAX_ATTRIBUTE_VALUES: usize = 4096;

/// Most octets in one AttributeValue or AssertionValue: 65,536.
///
/// Spec: docs/49 §2.4 — `dirstore::MAX_VALUE_LEN` (64 KiB). An assertion value
/// longer than any storable value can never match.
pub const MAX_VALUE_OCTETS: usize = 64 * 1024;

/// The authentication state of the session, which selects the message bound.
///
/// Spec: docs/49 §2.4 (the framer compares against the bound "of the current
/// authentication state, before any allocation"); [MS-ADTS] 3.1.1.3.4.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// Anonymous, or a bind not yet complete.
    Unauthenticated,
    /// A bind has succeeded.
    Authenticated,
}

impl AuthState {
    /// The largest LDAPMessage accepted in this state.
    pub const fn max_message_octets(self) -> usize {
        match self {
            AuthState::Unauthenticated => MAX_PREAUTH_MESSAGE_OCTETS,
            AuthState::Authenticated => MAX_AUTH_MESSAGE_OCTETS,
        }
    }
}
