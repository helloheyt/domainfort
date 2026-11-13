//! FAST (RFC 6113) in the KDC: framing and policy only.
//!
//! Every FAST key computation is keyd's (docs/48 §2, R48-1, A-33): opening
//! the armor, decrypting the KrbFastReq, the encrypted challenge, the
//! strengthened reply key, KrbFastFinished and the sealed KrbFastResponse of
//! a reply or an error. This module holds what the KDC itself decides about
//! FAST, none of it secret:
//! - how many PA-FX-FAST a request carries and what it decodes to
//!   (docs/48 §4.1 A1-A3);
//! - the refusal codes of keyd's armor refusals (A-26, Q-125);
//! - the FastOptions check (A-25, docs/48 §8);
//! - the PA-FX-COOKIE (docs/48 §6.4, Q-126) and the inner padata scan
//!   (docs/48 §4.1 A7);
//! - the PA-FX-FAST padata of a reply and the METHOD-DATA of an armored
//!   error (RFC 6113 5.4.3, 5.4.4).
//!
//! Spec: RFC 6113 2.4, 5.2, 5.4.1, 5.4.2, 5.4.3, 5.4.4, 5.4.5, 7.3; docs/48
//! §4.1, §5, §6, §8; docs/questions/Q-125, Q-126 (A-32); A-25, A-26.

use crate::audit::AuditReason;
use crate::kdc::{custody_unavailable, Refusal};
use keyd::{AuthnError, MAX_FX_COOKIE_LENGTH};
use krb_proto::constants::{
    KDC_ERR_PREAUTH_EXPIRED, KDC_ERR_PREAUTH_FAILED, KRB_AP_ERR_REPEAT, KRB_AP_ERR_SKEW,
    KRB_AP_ERR_TKT_EXPIRED, KRB_AP_ERR_TKT_NYV, KRB_ERR_GENERIC, PA_ENCRYPTED_CHALLENGE,
    PA_FX_COOKIE, PA_FX_FAST,
};
use krb_proto::{
    EncryptedData, FastOptions, KrbFastArmoredRep, KrbFastArmoredReq, MethodData, PaData,
    PaFxFastReply, PaFxFastRequest,
};

/// The PA-FX-COOKIE value the KDC sends: a fixed, content-free, versioned
/// token. "The content of the cookie field is a local matter of the KDC"
/// (RFC 6113 5.2); this value is this project's own choice, taken from no
/// other source. Nothing in it is ever parsed, so a client cannot
/// "manipulate" it into anything (5.2: "the KDC MUST construct the cookie
/// token in such a manner that a malicious client cannot subvert the
/// authentication process"); phase 1 has no multi-round-trip mechanism, so
/// there is no state for it to carry.
///
/// Documented deviation: 5.2 says "the KDC is expected to generate a new
/// cookie for each message" — "expected", not MUST (docs/questions/Q-126).
///
/// Spec: RFC 6113 5.2; docs/48 §6.4 (R48-7); docs/questions/Q-126 (a),
/// decided A-32.
pub(crate) const FX_COOKIE: &[u8] = b"kdc-phase1-fx-cookie/v1";

// keyd seals at most MAX_FX_COOKIE_LENGTH octets of cookie into an armored
// error (docs/48 §2.3 allowlist), and at least one.
const _: () = assert!(!FX_COOKIE.is_empty() && FX_COOKIE.len() <= MAX_FX_COOKIE_LENGTH);

/// FastOptions bits 0 to 15: the critical options. Bit 0 is the most
/// significant bit of the 32 (X.680 22.4 numbering, as krb-proto stores
/// KerberosFlags).
/// Spec: RFC 6113 7.3 ("Bits 0-15 are critical"), 5.4.2; A-25
/// (docs/questions/Q-033).
const CRITICAL_FAST_OPTIONS: u32 = 0xFFFF_0000;

/// The PA-FX-COOKIE padata the KDC sends.
/// Spec: RFC 6113 5.2; docs/48 §6.4.
pub(crate) fn cookie_padata() -> PaData {
    PaData {
        padata_type: PA_FX_COOKIE,
        padata_value: FX_COOKIE.to_vec(),
    }
}

/// `true` if `options` sets a critical FastOptions bit. Phase 1 supports no
/// critical option — hide-client-names (bit 1) included, which would need
/// the anonymous principal of RFC 6112 (not pinned) — so every one of bits
/// 0-15 is refused with KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS. Bits 16 and
/// up are non-critical and ignored.
/// Spec: RFC 6113 5.4.2 ("If the KDC does not support a critical option, it
/// MUST fail the request with KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS";
/// "KDCs conforming to this specification ignore unknown non-critical
/// options"), 7.3; A-25; docs/48 §8 (R48-9).
pub(crate) fn has_critical_fast_option(options: FastOptions) -> bool {
    options.0.bits() & CRITICAL_FAST_OPTIONS != 0
}

/// The one PA-FX-FAST of a request, if any (docs/48 §4.1 A1): none →
/// `Ok(None)`; more than one → KRB_ERR_GENERIC, unarmored (ambiguous, as a
/// doubled PA-TGS-REQ; docs/questions/Q-125 item 3).
/// Spec: RFC 6113 5.4.2; docs/48 §4.1 A1; Q-125 (A-32).
pub(crate) fn fx_fast_padata(padata: &[PaData]) -> Result<Option<&PaData>, Refusal> {
    let mut found = padata.iter().filter(|p| p.padata_type == PA_FX_FAST);
    match (found.next(), found.next()) {
        (None, _) => Ok(None),
        (Some(_), Some(_)) => Err(Refusal::new(
            KRB_ERR_GENERIC,
            AuditReason::FastPadataAmbiguous,
        )),
        (Some(pa), None) => Ok(Some(pa)),
    }
}

/// Decode the KrbFastArmoredReq of a PA-FX-FAST (krb-proto, strict, A-24).
/// Undecodable → KDC_ERR_PREAUTH_FAILED, unarmored (docs/questions/Q-125
/// item 2: FAST is a pre-authentication mechanism and there is no armor key
/// yet).
/// Spec: RFC 6113 5.4.2; docs/48 §4.1 A2; A-24; Q-125 (A-32).
pub(crate) fn armored_request(pa: &PaData) -> Result<KrbFastArmoredReq, Refusal> {
    match PaFxFastRequest::decode(&pa.padata_value) {
        Ok(PaFxFastRequest::ArmoredData(armored)) => Ok(armored),
        Err(_) => Err(Refusal::new(
            KDC_ERR_PREAUTH_FAILED,
            AuditReason::FastMalformed,
        )),
    }
}

/// keyd's `open_fast_armor` refusals, sent unarmored (no armor token exists
/// after a failure): `Denied` → KDC_ERR_PREAUTH_FAILED (as for an unknown
/// armor type, RFC 6113 5.4.1); the classes keyd reports only after its
/// cryptographic chain completed (A-26) → the RFC 4120 3.2.3 AP-REQ codes, so
/// that the client refreshes its armor TGT (RFC 6113 5.4.4: "the client
/// SHOULD process the KDC errors as the result of the KDC's inability to
/// accept the AP_REQ armor and potentially retry another request with a
/// different armor"). `Unavailable` — keyd did not serve the call (its
/// startup hold-down, or keyd unreachable) — is KDC_ERR_SVC_UNAVAILABLE,
/// never PREAUTH_FAILED (docs/50 §3.7, R50-8; A-56).
/// Spec: RFC 6113 5.4.1, 5.4.4; RFC 4120 3.2.3, 7.5.9; docs/48 §6.2, §6.3;
/// docs/questions/Q-125 items 4, 5 (A-32); A-26; docs/questions/Q-217
/// (A-56).
pub(crate) fn armor_refusal(error: AuthnError) -> Refusal {
    match error {
        AuthnError::Unavailable => custody_unavailable(),
        AuthnError::Denied => Refusal::new(KDC_ERR_PREAUTH_FAILED, AuditReason::ArmorDenied),
        AuthnError::Skew => Refusal::new(KRB_AP_ERR_SKEW, AuditReason::ArmorSkew),
        AuthnError::TicketNotYetValid => {
            Refusal::new(KRB_AP_ERR_TKT_NYV, AuditReason::ArmorNotYetValid)
        }
        AuthnError::TicketExpired => {
            Refusal::new(KRB_AP_ERR_TKT_EXPIRED, AuditReason::ArmorExpired)
        }
        AuthnError::Replay => Refusal::new(KRB_AP_ERR_REPEAT, AuditReason::ArmorReplay),
    }
}

/// Process the PA-FX-COOKIE of a request first (RFC 6113 2.4): none → go
/// on; exactly one whose value is [`FX_COOKIE`] octet for octet → go on;
/// anything else (another value — the comparison stops at the first octet
/// that differs, so a long value costs nothing — or more than one) →
/// KDC_ERR_PREAUTH_EXPIRED, which tells the client to "abort the existing
/// conversation, and restart a new one" (5.2). The cookie is not secret: a
/// plain comparison is enough.
/// Spec: RFC 6113 2.4, 5.2; docs/48 §6.4; docs/questions/Q-126 (a) (A-32).
pub(crate) fn check_cookie(padata: &[PaData]) -> Result<(), Refusal> {
    let mut cookies = padata.iter().filter(|p| p.padata_type == PA_FX_COOKIE);
    match (cookies.next(), cookies.next()) {
        (None, _) => Ok(()),
        (Some(cookie), None) if cookie.padata_value == FX_COOKIE => Ok(()),
        _ => Err(Refusal::new(
            KDC_ERR_PREAUTH_EXPIRED,
            AuditReason::CookieMismatch,
        )),
    }
}

/// The padata of an armored AS request's KrbFastReq (docs/48 §4.1 A7):
/// 1. the PA-FX-COOKIE first ([`check_cookie`]);
/// 2. at most one PA-ENCRYPTED-CHALLENGE — the only FAST factor of phase 1
///    (docs/48 §4.5) — returned if present; two → KDC_ERR_PREAUTH_FAILED
///    (ambiguous);
/// 3. everything else is ignored: unknown types ("MUST ignore padata of an
///    unknown type") and PA-ENC-TIMESTAMP inside FAST, which is not bound to
///    the conversation ("MAY ignore padata that are inappropriate"; docs/48
///    §4.5), so such a request gets an armored PREAUTH_REQUIRED.
///
/// The caller seals any refusal (the armor is open).
/// Spec: RFC 6113 2.4, 5.4.6, 8; docs/48 §4.1 A7, §4.5.
pub(crate) fn inner_challenge(padata: &[PaData]) -> Result<Option<&PaData>, Refusal> {
    check_cookie(padata)?;
    let mut challenges = padata
        .iter()
        .filter(|p| p.padata_type == PA_ENCRYPTED_CHALLENGE);
    match (challenges.next(), challenges.next()) {
        (Some(_), Some(_)) => Err(Refusal::new(
            KDC_ERR_PREAUTH_FAILED,
            AuditReason::PreauthAmbiguous,
        )),
        (first, _) => Ok(first),
    }
}

/// The PA-FX-FAST padata of a KDC reply or armored error:
/// PA-FX-FAST-REPLY `armored-data [0]` KrbFastArmoredRep { enc-fast-rep }.
/// `None` only if encoding fails.
/// Spec: RFC 6113 5.4.3 ("The KDC that supports the PA-FX-FAST padata MUST
/// include a PA-FX-FAST padata element in the KDC reply"), 5.4.4.
pub(crate) fn fx_fast_reply(enc_fast_rep: EncryptedData) -> Option<PaData> {
    let value = PaFxFastReply::ArmoredData(KrbFastArmoredRep { enc_fast_rep })
        .encode()
        .ok()?;
    Some(PaData {
        padata_type: PA_FX_FAST,
        padata_value: value,
    })
}

/// The e-data of an armored KRB-ERROR: METHOD-DATA carrying ONLY the
/// PA-FX-FAST — every other padata travels inside the sealed
/// KrbFastResponse (docs/48 §6.1; minimalism, docs/25 §5).
/// Spec: RFC 6113 5.4.4 ("the e-data field of the KRB-ERROR message
/// contains the ASN.1 DER encoding of the type METHOD-DATA and a PA-FX-FAST
/// is included in the METHOD-DATA"), 5.4.5.
pub(crate) fn armored_error_e_data(enc_fast_rep: EncryptedData) -> Option<Vec<u8>> {
    MethodData(vec![fx_fast_reply(enc_fast_rep)?]).encode().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb_proto::KerberosFlags;

    fn bit(n: u32) -> FastOptions {
        FastOptions(KerberosFlags::from_bits(0x8000_0000 >> n))
    }

    fn pa(padata_type: i32, value: &[u8]) -> PaData {
        PaData {
            padata_type,
            padata_value: value.to_vec(),
        }
    }

    /// A-25 / RFC 6113 7.3: bits 0-15 critical (hide-client-names = bit 1
    /// included); bits 16-31 ignored.
    #[test]
    fn critical_bits_are_0_to_15() {
        for n in 0..16 {
            assert!(has_critical_fast_option(bit(n)), "bit {n}");
        }
        for n in 16..32 {
            assert!(!has_critical_fast_option(bit(n)), "bit {n}");
        }
        assert!(has_critical_fast_option(FastOptions::HIDE_CLIENT_NAMES));
        assert!(!has_critical_fast_option(FastOptions::empty()));
    }

    /// RFC 6113 2.4 / 5.2, Q-126 (a): absent or exactly ours → accepted;
    /// another value, a prefix, or two → KDC_ERR_PREAUTH_EXPIRED.
    #[test]
    fn cookie_must_match_exactly() {
        assert!(check_cookie(&[]).is_ok());
        assert!(check_cookie(&[cookie_padata()]).is_ok());
        for bad in [
            vec![pa(PA_FX_COOKIE, b"other")],
            vec![pa(PA_FX_COOKIE, &FX_COOKIE[..FX_COOKIE.len() - 1])],
            vec![pa(PA_FX_COOKIE, b"")],
            vec![cookie_padata(), cookie_padata()],
        ] {
            assert_eq!(
                check_cookie(&bad).map_err(|r| r.code),
                Err(KDC_ERR_PREAUTH_EXPIRED)
            );
        }
    }

    /// docs/48 §4.1 A7: one challenge returned; two refused; PA-ENC-TIMESTAMP
    /// and unknown types ignored.
    #[test]
    fn inner_padata_scan() {
        let challenge = pa(PA_ENCRYPTED_CHALLENGE, b"c");
        let timestamp = pa(krb_proto::constants::PA_ENC_TIMESTAMP, b"t");
        let unknown = pa(4242, b"u");
        assert_eq!(
            inner_challenge(&[timestamp.clone(), unknown.clone()]).unwrap(),
            None
        );
        assert_eq!(
            inner_challenge(&[unknown, challenge.clone(), timestamp]).unwrap(),
            Some(&challenge)
        );
        assert_eq!(
            inner_challenge(&[challenge.clone(), challenge]).map_err(|r| r.code),
            Err(KDC_ERR_PREAUTH_FAILED)
        );
    }

    /// Q-125 item 3: two PA-FX-FAST are ambiguous.
    #[test]
    fn doubled_fx_fast_is_generic() {
        let fast = pa(PA_FX_FAST, b"x");
        assert_eq!(fx_fast_padata(&[]).unwrap(), None);
        assert_eq!(
            fx_fast_padata(core::slice::from_ref(&fast)).unwrap(),
            Some(&fast)
        );
        assert_eq!(
            fx_fast_padata(&[fast.clone(), fast]).map_err(|r| r.code),
            Err(KRB_ERR_GENERIC)
        );
    }
}
