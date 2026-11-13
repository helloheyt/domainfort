//! Key usage numbers, exactly as assigned by RFC 4120 §7.5.1 (only those the
//! phase-1 operations use) and by RFC 6113 §6.2 (FAST), plus one
//! keyd-internal usage from the range RFC 4120 reserves for that purpose.
//!
//! Spec: RFC 4120 §4 (key usages are unsigned 32-bit, non-zero; 512-1023
//! "reserved for uses internal to a Kerberos implementation"), §7.5.1;
//! RFC 6113 §5.4.2, §5.4.3, §5.4.6, §6.2.

/// Key usage 1 — AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the client
/// key. Spec: RFC 4120 7.5.1, 5.2.7.2.
pub(crate) const AS_REQ_PA_ENC_TIMESTAMP: u32 = 1;

/// Key usage 2 — AS-REP Ticket and TGS-REP Ticket, encrypted with the service key.
/// Spec: RFC 4120 7.5.1, 5.3.
pub(crate) const TICKET_ENC_PART: u32 = 2;

/// Key usage 3 — AS-REP encrypted part, encrypted with the client key ("or
/// another key selected via pre-authentication mechanisms", RFC 4120 5.4.2).
/// Under FAST the same usage seals EncASRepPart in the strengthened reply
/// key (docs/questions/Q-121 option (a), decided A-32). Spec: RFC 4120
/// 7.5.1, 5.4.2; RFC 6113 5.4.3.
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

/// Key usage 11 — AP-REQ Authenticator, encrypted with the application session
/// key: "a key usage value of 11 in normal application exchanges, or 7 when
/// used as the PA-TGS-REQ PA-DATA field". keyd uses it for the authenticator
/// of the FX_FAST_ARMOR_AP_REQUEST armor AP-REQ, which is not a PA-TGS-REQ
/// (docs/questions/Q-120 item 1, decided A-32). Spec: RFC 4120 7.5.1, 5.5.1;
/// RFC 6113 5.4.1.1.
pub(crate) const AP_REQ_AUTHENTICATOR: u32 = 11;

/// Key usage 50 — KEY_USAGE_FAST_REQ_CHKSUM: the req-checksum of a
/// KrbFastArmoredReq, keyed with the armor key. Spec: RFC 6113 5.4.2, 6.2.
pub(crate) const KEY_USAGE_FAST_REQ_CHKSUM: u32 = 50;

/// Key usage 51 — KEY_USAGE_FAST_ENC: enc-fast-req (KrbFastReq), encrypted
/// with the armor key. Spec: RFC 6113 5.4.2, 6.2.
pub(crate) const KEY_USAGE_FAST_ENC: u32 = 51;

/// Key usage 52 — KEY_USAGE_FAST_REP: enc-fast-rep (KrbFastResponse),
/// encrypted with the armor key of the request. Spec: RFC 6113 5.4.3, 6.2.
pub(crate) const KEY_USAGE_FAST_REP: u32 = 52;

/// Key usage 53 — KEY_USAGE_FAST_FINISHED: the ticket-checksum of
/// KrbFastFinished, keyed with the armor key. Used by the armored
/// `issue_as_rep` (docs/48 §4.4; and `issue_tgs_rep`, task T3). Spec: RFC
/// 6113 5.4.3, 6.2.
pub(crate) const KEY_USAGE_FAST_FINISHED: u32 = 53;

/// Key usage 54 — KEY_USAGE_ENC_CHALLENGE_CLIENT: the client's
/// EncryptedChallenge, encrypted with the client challenge key. Used by the
/// armored `verify_preauth` (docs/48 §4.5). Spec: RFC 6113 5.4.6, 6.2.
pub(crate) const KEY_USAGE_ENC_CHALLENGE_CLIENT: u32 = 54;

/// Key usage 55 — KEY_USAGE_ENC_CHALLENGE_KDC: the KDC's EncryptedChallenge,
/// encrypted with the KDC challenge key. Used by the armored `issue_as_rep`
/// (docs/48 §4.3, §10.2). Spec: RFC 6113 5.4.6, 6.2.
pub(crate) const KEY_USAGE_ENC_CHALLENGE_KDC: u32 = 55;

/// keyd-internal: the one-shot MIC that `verify_secret` uses to compare a
/// candidate key with the stored key in constant time (krb-crypto
/// `verify_mic`). Chosen from the 512-1023 range RFC 4120 §4 / §7.5.1
/// reserves "for uses internal to a Kerberos implementation"; never sent on
/// the wire. Spec: RFC 4120 §4, §7.5.1; docs/10 §6, §12 I6.
pub(crate) const KEYD_INTERNAL_SECRET_COMPARE: u32 = 512;

#[cfg(test)]
mod tests {
    use super::*;

    /// The FAST usages are those of the RFC 6113 §6.2 table, in its order,
    /// and none collides with an RFC 4120 §7.5.1 usage keyd uses: key
    /// separation between the armor-key operations (docs/48 §2.2).
    #[test]
    fn fast_usages_follow_rfc6113_6_2() {
        let fast = [
            KEY_USAGE_FAST_REQ_CHKSUM,
            KEY_USAGE_FAST_ENC,
            KEY_USAGE_FAST_REP,
            KEY_USAGE_FAST_FINISHED,
            KEY_USAGE_ENC_CHALLENGE_CLIENT,
            KEY_USAGE_ENC_CHALLENGE_KDC,
        ];
        assert_eq!(fast, [50, 51, 52, 53, 54, 55]);
        let rfc4120 = [
            AS_REQ_PA_ENC_TIMESTAMP,
            TICKET_ENC_PART,
            AS_REP_ENC_PART,
            TGS_REQ_AUTHENTICATOR_CKSUM,
            TGS_REQ_AUTHENTICATOR,
            TGS_REP_ENC_PART_SESSION_KEY,
            TGS_REP_ENC_PART_SUBKEY,
            AP_REQ_AUTHENTICATOR,
        ];
        for usage in fast {
            assert!(!rfc4120.contains(&usage));
        }
    }
}
