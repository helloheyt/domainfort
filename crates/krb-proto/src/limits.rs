//! Documented resource bounds (docs/CLEAN-ROOM.md: "no unbounded allocation from
//! attacker-supplied lengths"; docs/45 §5).
//!
//! These are **not** RFC 4120 rules — RFC 4120 §5 places no size limit on these
//! SEQUENCE OF fields. They are this crate's fail-closed resource bounds,
//! applied identically on decode and on encode (so anything this crate encodes
//! it will also decode). A value over a bound is rejected with
//! [`crate::Error::TooManyElements`] or [`crate::Error::MessageTooLarge`].
//!
//! `parse-asn1` already bounds nesting depth (`parse_asn1::MAX_DEPTH`) and never
//! reads past the input; the total input size bound below caps the size of the
//! intermediate value tree that `parse-asn1` builds before these per-field
//! element counts are checked.

/// Maximum length, in octets, of one encoded message or structure passed to a
/// `decode` function or produced by an `encode` function.
pub const MAX_MESSAGE_LEN: usize = 256 * 1024;

/// Maximum number of PA-DATA elements in KDC-REQ `padata`, KDC-REP `padata`
/// and METHOD-DATA, and in the FAST typed holes KrbFastReq `padata` and
/// KrbFastResponse `padata`. Spec context: RFC 4120 5.2.7, 5.4.1, 5.4.2,
/// 5.9.1.
///
/// The FAST fields share this bound because they carry the same items: the
/// client "MUST place any padata that is otherwise in the outer KDC request
/// body" into KrbFastReq `padata` (RFC 6113 5.4.2), and the KDC "MUST include
/// any padata that are otherwise in the outer KDC-REP or KDC-ERROR structure"
/// in KrbFastResponse `padata` (5.4.3, 5.4.4), whose outer padata then
/// "typically includes only the PA-FX-FAST-REPLY padata" (5.4.3).
pub const MAX_PADATA: usize = 32;

/// Maximum number of components in PrincipalName `name-string`.
/// Spec context: RFC 4120 5.2.2 ("Most PrincipalNames will have only a few
/// components (typically one or two)").
pub const MAX_NAME_COMPONENTS: usize = 16;

/// Maximum number of entries in KDC-REQ-BODY `etype`.
/// Spec context: RFC 4120 5.4.1.
pub const MAX_ETYPES: usize = 32;

/// Maximum number of HostAddress elements in a HostAddresses value.
/// Spec context: RFC 4120 5.2.5.
pub const MAX_HOST_ADDRESSES: usize = 32;

/// Maximum number of authorization elements in one AuthorizationData value.
/// Spec context: RFC 4120 5.2.6.
pub const MAX_AUTHORIZATION_ELEMENTS: usize = 32;

/// Maximum number of LastReq entries. RFC 4120 5.4.2 defines lr-type
/// magnitudes 0..=7 with a sign, i.e. at most 15 distinct kinds.
pub const MAX_LAST_REQ: usize = 16;

/// Maximum number of tickets in KDC-REQ-BODY `additional-tickets`.
/// Spec context: RFC 4120 5.4.1 (one per option that requires a ticket).
pub const MAX_ADDITIONAL_TICKETS: usize = 8;

/// Maximum number of entries in an ETYPE-INFO2 value.
/// Spec context: RFC 4120 5.2.7.5.
pub const MAX_ETYPE_INFO2_ENTRIES: usize = 32;

/// Maximum length, in octets, of ChangePasswdData `newpasswd` (decode and
/// encode; over it ⇒ [`crate::Error::NewPasswdTooLong`]).
///
/// Not an RFC 3244 rule — RFC 3244 §2 bounds no field. It is the project's one
/// bound on a password on every path: docs/53 §5.4 item 4 and §5.9
/// ("newpasswd ≤ 1024 octets (`ipc_keyd::MAX_SECRET`)"), equal to docs/50 §3.4
/// `password: secret bytes<1024>` (`ipc_keyd::channel::MAX_SECRET`). keyd maps
/// the error to the PasswordRefused verdict (SOFTERROR, docs/53 §5.7 "too
/// long"), not to MALFORMED (docs/questions/Q-620).
pub const MAX_NEWPASSWD_LEN: usize = 1024;
