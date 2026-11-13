#![forbid(unsafe_code)]
//! `parse-ldap`: the strict LDAP-BER message codec (docs/49 R49-1..R49-3,
//! build task L1).
//!
//! # Scope
//!
//! * [`frame_length`] cuts one LDAPMessage from a TCP byte stream, bounded by
//!   the session's [`AuthState`] before any allocation (RFC 4511 §5.2;
//!   docs/49 §2.4).
//! * [`decode_message`] decodes one LDAPMessage into typed values for the
//!   phase-1 operations (R49-7): BindRequest/BindResponse, UnbindRequest,
//!   SearchRequest (with its Filter tree), SearchResultEntry,
//!   SearchResultDone, AbandonRequest, ExtendedRequest/ExtendedResponse, and
//!   the Controls field (bounded, so the engine can refuse critical controls —
//!   R49-8). Modify, Add, Delete, ModifyDN and Compare are recognised by tag
//!   only ([`ProtocolOp::Unsupported`], A-48).
//! * [`encode_message`] produces the canonical form: the re-encoding the front
//!   hands to the engine (R49-16) and the encoding of every response.
//!
//! Distinguished-name syntax (RFC 4514) is not parsed here: an LDAPDN is a
//! UTF-8 LDAPString to this crate (docs/49 R49-11, task L5).
//!
//! # Strictness (the LDAP-BER profile, docs/49 §2.3 and A-45)
//!
//! The RFC 4511 §5.1 BER subset: definite lengths only; OCTET STRINGs (and
//! everything implicitly tagged on them) primitive only; BOOLEAN exactly
//! `00`/`FF`; DEFAULT values absent; minimal INTEGERs (X.690 8.3.2); LDAPStrings
//! well-formed UTF-8 (RFC 4511 §4.1.2); no tag >= 31 and no end-of-contents;
//! MessageID within `0 .. maxInt` and non-zero in a request; the Filter
//! constraints of §4.5.1 / §4.5.1.7.2 / §4.5.1.7.7. Under [`Profile::Wire`] a
//! long-form length may use up to four octets even if not minimal (A-45;
//! X.690 8.1.3.5 NOTE 2; [MS-ADTS] 6.3.3) and unrecognised trailing SEQUENCE
//! components are validated and skipped (RFC 4511 §4); [`Profile::Canonical`]
//! accepts only what [`encode_message`] produces. Every rejection is a typed
//! [`Error`]; nothing panics, and nothing is allocated from an
//! attacker-supplied length beyond the octets present (AGENTS.md §6). All
//! bounds are named constants in [`limits`].
//!
//! # Provenance
//!
//! Written only from the allowed specifications, opened in-session (AGENTS.md
//! §1-3): RFC 4511 (§4, §4.1–§4.5.2, §4.6–§4.14, §5, §6, App. B); RFC 4512
//! §1.4, §2.5; ITU-T X.690 (02/2021) clauses 7.3, 8.1–8.4, 8.7–8.14, 10.1–10.3,
//! 11.1; ITU-T X.680 (02/2021) Table 1; [MS-ADTS] v20261026 3.1.1.3.4.6 and
//! 6.3.3; and the project's
//! decided design docs/49 with decision A-45 (docs/questions/Q-160). No other
//! implementation was consulted or recalled.
//!
//! Spec: RFC 4511; X.690 (02/2021) clauses 8, 10; docs/49 §2, §11.

mod ber;
mod decode;
mod encode;
mod error;
mod frame;
pub mod limits;
mod message;

pub use ber::Profile;
pub use decode::{decode_message, DecodeOptions, Direction};
pub use encode::encode_message;
pub use error::{Error, Limit, Result};
pub use frame::{frame_length, Frame};
pub use limits::{
    AuthState, MAX_ATTRIBUTE_SELECTORS, MAX_ATTRIBUTE_VALUES, MAX_AUTH_MESSAGE_OCTETS,
    MAX_CONTROLS, MAX_FILTER_DEPTH, MAX_FILTER_NODES, MAX_IDENTIFIER_OCTETS, MAX_INT,
    MAX_LDAPDN_OCTETS, MAX_LENGTH_OCTETS, MAX_PARTIAL_ATTRIBUTES, MAX_PREAUTH_MESSAGE_OCTETS,
    MAX_SUBSTRING_ANY, MAX_TLV_DEPTH, MAX_VALUE_OCTETS,
};
pub use message::{
    AttributeValueAssertion, AuthenticationChoice, BindRequest, BindResponse, Control,
    DerefAliases, ExtendedRequest, ExtendedResponse, Filter, LdapMessage, LdapResult,
    MatchingRuleAssertion, MessageId, PartialAttribute, ProtocolOp, ResultCode, SaslCredentials,
    Scope, SearchRequest, SearchResultEntry, Substring, SubstringFilter, UnsupportedOp,
    NOTICE_OF_DISCONNECTION_OID, SIMPLE_PASSWORD_PLACEHOLDER, START_TLS_OID,
};
