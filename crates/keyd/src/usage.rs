//! Key usage numbers, exactly as assigned by RFC 4120 §7.5.1 (only those the
//! phase-1 operations use), plus one keyd-internal usage from the range RFC
//! 4120 reserves for that purpose.
//!
//! Spec: RFC 4120 §4 (key usages are unsigned 32-bit, non-zero; 512-1023
//! "reserved for uses internal to a Kerberos implementation"), §7.5.1.

/// Key usage 1 — AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the client
/// key. Spec: RFC 4120 7.5.1, 5.2.7.2.
pub(crate) const AS_REQ_PA_ENC_TIMESTAMP: u32 = 1;

/// Key usage 2 — AS-REP Ticket and TGS-REP Ticket, encrypted with the service key.
/// Spec: RFC 4120 7.5.1, 5.3.
pub(crate) const TICKET_ENC_PART: u32 = 2;

/// Key usage 3 — AS-REP encrypted part, encrypted with the client key.
/// Spec: RFC 4120 7.5.1, 5.4.2.
pub(crate) const AS_REP_ENC_PART: u32 = 3;

/// Key usage 6 — TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator cksum, keyed with the
/// TGS session key. Spec: RFC 4120 7.5.1, 5.5.1.
pub(crate) const TGS_REQ_AUTHENTICATOR_CKSUM: u32 = 6;

/// Key usage 7 — TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator, encrypted with the TGS
/// session key. Spec: RFC 4120 7.5.1, 5.5.1.
pub(crate) const TGS_REQ_AUTHENTICATOR: u32 = 7;

/// Key usage 8 — TGS-REP encrypted part, encrypted with the TGS session key.
/// Spec: RFC 4120 7.5.1, 5.4.2.
pub(crate) const TGS_REP_ENC_PART_SESSION_KEY: u32 = 8;

/// Key usage 9 — TGS-REP encrypted part, encrypted with the TGS authenticator subkey.
/// Spec: RFC 4120 7.5.1, 5.4.2.
pub(crate) const TGS_REP_ENC_PART_SUBKEY: u32 = 9;

/// keyd-internal: the one-shot MIC that `verify_secret` uses to compare a
/// candidate key with the stored key in constant time (krb-crypto
/// `verify_mic`). Chosen from the 512-1023 range RFC 4120 §4 / §7.5.1
/// reserves "for uses internal to a Kerberos implementation"; never sent on
/// the wire. Spec: RFC 4120 §4, §7.5.1; docs/10 §6, §12 I6.
pub(crate) const KEYD_INTERNAL_SECRET_COMPARE: u32 = 512;
