//! The end of an authentication step's cryptographic chain, as a type
//! (docs/52 §3.6 option (a), task R7; decision A-26).
//!
//! # The class (C6)
//!
//! The kind of an error — or the order of the checks — reveals what the
//! authority would hide. A-26 lets keyd report a non-secret class
//! (`AuthnError::{Skew, TicketNotYetValid, TicketExpired, Replay}`) only once
//! the step's whole cryptographic chain has passed: the facts behind a class
//! (a ticket's times, an authenticator's time, a replay) are learned only
//! from decrypted, integrity-checked structures, so only a holder of the key
//! that protects them may learn them; before that every failure is the
//! uniform `Denied` (docs/10 §9, §12 I6). Until R7 that order was a
//! convention in each operation: `Deny::classified` could be called anywhere,
//! and each time finding was pre-built as a classified refusal long before
//! the chain ended.
//!
//! # The root-level change
//!
//! * A classified refusal is built only by [`ChainVerified`]
//!   ([`ChainVerified::refuse`], [`ChainVerified::report`]); `Deny` has no
//!   other constructor that sets a class (crate::error — its `class` field is
//!   private there). Without a `ChainVerified` every refusal is the uniform
//!   `Denied` **by type**.
//! * A `ChainVerified` is minted only from the **evidence** of the chain's
//!   cryptographic steps, taken by value: [`Decrypted`] (a decryption whose
//!   integrity check passed, RFC 3961 §3) and [`MicVerified`] (a verified
//!   checksum, RFC 3961 §4) — values made only by [`open`] and
//!   [`verify_mic`] here, each by one real verification. Each operation's
//!   constructor names the steps of its chain: the pre-authentication
//!   timestamp ([`ChainVerified::preauthentication`]); an AP-REQ's ticket and
//!   authenticator ([`ApReqOpened`]) plus the TGS request checksum and, under
//!   FAST, the armor's req-checksum and KrbFastReq ([`ArmorOpened`],
//!   [`ChainVerified::tgs_request`], [`ChainVerified::fast_armor`]); or the
//!   service AP-REQ's operation binding ([`BindingEvidence`],
//!   [`ChainVerified::service_ticket`]).
//! * The time findings recorded while opening an AP-REQ are a
//!   [`TimeFindings`] — no `Deny` inside — read only by
//!   [`ChainVerified::report`].
//!
//! So a class cannot be returned before the chain's cryptographic steps
//! were performed: the code that would do it does not compile. The order of
//! the non-cryptographic checks between those steps (subkey shape, names,
//! transited) is still the operation's own: each refuses with the uniform
//! `Denied` either way.
//!
//! Spec: docs/52 §3.6 (a), §7 R7; docs/10 §9 (A-26), §12 I6;
//! docs/questions/Q-071 (A-26); RFC 4120 3.2.3 (the reporting order: skew,
//! then the ticket's age; the replay cache), 5.2.7.2; RFC 3961 §3 (decrypt
//! "an error indication must be returned"), §4 (verify_mic); RFC 6113 5.4.2,
//! 5.4.6.

use crate::audit::AuditReason;
use crate::error::{AuthnError, Deny, Internal};
use crate::keyd::key_usage;
use keyd_types::OperationDigest;
use krb_crypto::{ChecksumType, ProtocolKey};
use zeroize::Zeroizing;

/// Evidence of one decryption under `key` whose integrity check passed
/// (RFC 3961 §3). Made only by [`open`]; not `Clone`.
#[derive(Debug)]
pub(crate) struct Decrypted(());

/// Evidence of one verified checksum (RFC 3961 §4 `verify_mic`). Made only
/// by [`verify_mic`]; not `Clone`.
#[derive(Debug)]
pub(crate) struct MicVerified(());

/// Decrypt and integrity-check `ciphertext` under `key` with `usage` — as
/// `keyd::open` (any failure `Denied`, reason `IntegrityFailure`) — and
/// return the plaintext with the evidence of the step.
/// Spec: RFC 3961 §3 (decrypt); RFC 4120 3.2.3 (KRB_AP_ERR_BAD_INTEGRITY).
pub(crate) fn open(
    key: &ProtocolKey,
    usage: u32,
    ciphertext: &[u8],
) -> Internal<(Zeroizing<Vec<u8>>, Decrypted)> {
    let plaintext = crate::keyd::open(key, usage, ciphertext)?;
    Ok((plaintext, Decrypted(())))
}

/// Verify `checksum` (of type `cksumtype`) over `message` under `key` with
/// `usage`; a mismatch is `Denied` with `mismatch` as its reason. Returns
/// the evidence of the step.
/// Spec: RFC 3961 §4 (verify_mic); RFC 4120 §4.
pub(crate) fn verify_mic(
    key: &ProtocolKey,
    cksumtype: ChecksumType,
    usage: u32,
    message: &[u8],
    checksum: &[u8],
    mismatch: AuditReason,
) -> Internal<MicVerified> {
    krb_crypto::verify_mic(key, cksumtype, key_usage(usage)?, message, checksum)
        .map_err(|_| Deny::denied(mismatch))?;
    Ok(MicVerified(()))
}

/// Evidence that an AP-REQ was opened: its ticket decrypted under the
/// server key and its authenticator under the ticket session key (RFC 4120
/// 3.2.3). Built from the two decryptions' evidence.
#[derive(Debug)]
pub(crate) struct ApReqOpened {
    _ticket: Decrypted,
    _authenticator: Decrypted,
}

impl ApReqOpened {
    /// Spec: RFC 4120 3.2.3 (the ticket, then the authenticator).
    pub(crate) fn new(ticket: Decrypted, authenticator: Decrypted) -> ApReqOpened {
        ApReqOpened {
            _ticket: ticket,
            _authenticator: authenticator,
        }
    }
}

/// Evidence that a FAST armored request was opened under its armor key:
/// the req-checksum verified and enc-fast-req decrypted (RFC 6113 5.4.2).
#[derive(Debug)]
pub(crate) struct ArmorOpened {
    _req_checksum: MicVerified,
    _fast_req: Decrypted,
}

impl ArmorOpened {
    /// Spec: RFC 6113 5.4.2 (req-checksum, usage 50; enc-fast-req, usage 51).
    pub(crate) fn new(req_checksum: MicVerified, fast_req: Decrypted) -> ArmorOpened {
        ArmorOpened {
            _req_checksum: req_checksum,
            _fast_req: fast_req,
        }
    }
}

/// What a service AP-REQ's application binding verified (R2, docs/52 §5):
/// nothing for an unbound verification (the LDAP front: no `cksum`), or the
/// operation digest whose MIC verified (dird's admin channel).
#[derive(Debug)]
pub(crate) enum BindingEvidence {
    /// No application data to bind (the `cksum` was absent, as required).
    Unbound,
    /// The `cksum` verified over this operation digest (key usage 10).
    OperationDigest(OperationDigest, MicVerified),
}

impl BindingEvidence {
    /// The operation digest the `cksum` verified over, if any.
    pub(crate) fn digest(&self) -> Option<OperationDigest> {
        match self {
            BindingEvidence::Unbound => None,
            BindingEvidence::OperationDigest(digest, _) => Some(*digest),
        }
    }
}

/// The non-secret classes a completed chain may report (A-26) — a closed
/// set: no other class is expressible after the chain.
/// Spec: docs/10 §9; RFC 4120 3.2.3 (KRB_AP_ERR_SKEW, KRB_AP_ERR_TKT_NYV,
/// KRB_AP_ERR_TKT_EXPIRED, KRB_AP_ERR_REPEAT); docs/questions/Q-071.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainClass {
    /// The (authenticator's or timestamp's) client time is outside the skew.
    Skew,
    /// The ticket's start is later than now beyond the skew.
    TicketNotYetValid,
    /// The ticket's end is earlier than now beyond the skew.
    TicketExpired,
    /// The authenticator is in the replay cache.
    Replay,
}

impl ChainClass {
    /// The audit reason and the public class.
    /// Spec: docs/10 §9; docs/questions/Q-071 (A-26).
    pub(crate) const fn parts(self) -> (AuditReason, AuthnError) {
        match self {
            ChainClass::Skew => (AuditReason::ClockSkew, AuthnError::Skew),
            ChainClass::TicketNotYetValid => (
                AuditReason::TicketNotYetValid,
                AuthnError::TicketNotYetValid,
            ),
            ChainClass::TicketExpired => (AuditReason::TicketExpired, AuthnError::TicketExpired),
            ChainClass::Replay => (AuditReason::Replay, AuthnError::Replay),
        }
    }
}

/// A ticket's age finding (RFC 4120 3.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TicketTime {
    /// The start is later than now beyond the skew.
    NotYetValid,
    /// The end is earlier than now beyond the skew.
    Expired,
}

/// The time findings of an opened ticket and authenticator, recorded during
/// the cryptographic chain and readable only by [`ChainVerified::report`]
/// once it completed (A-26). Holds no refusal: nothing here can be returned
/// as an error by itself.
/// Spec: RFC 4120 3.2.3; docs/questions/Q-071 (A-26).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimeFindings {
    skew: bool,
    ticket_time: Option<TicketTime>,
}

impl TimeFindings {
    /// The findings: whether the authenticator's time is outside the skew,
    /// and the ticket's age.
    pub(crate) fn recorded(skew: bool, ticket_time: Option<TicketTime>) -> TimeFindings {
        TimeFindings { skew, ticket_time }
    }
}

/// Proof that an authentication step's cryptographic chain completed — the
/// only maker of a classified refusal (module documentation). Minted only
/// from the evidence of the chain's steps; not `Clone`.
///
/// Spec: docs/52 §3.6 (a), §7 R7; docs/10 §9 (A-26), §12 I6.
#[derive(Debug)]
pub(crate) struct ChainVerified(());

impl ChainVerified {
    /// `verify_preauth`: the PA-ENC-TS-ENC decrypted under the client key
    /// (usage 1) — or, armored, under the challenge key (usage 54) — and
    /// decoded. Spec: RFC 4120 5.2.7.2; RFC 6113 5.4.6; A-26.
    pub(crate) fn preauthentication(_timestamp: Decrypted) -> ChainVerified {
        ChainVerified(())
    }

    /// `open_and_verify_tgt`: the TGT and the authenticator opened, the
    /// authenticator's checksum over the KDC-REQ-BODY verified (usage 6),
    /// and — under FAST — the implicit armor's req-checksum and KrbFastReq.
    /// Spec: RFC 4120 3.3.2, 5.5.1; RFC 6113 5.4.2; docs/48 §6.3; A-26.
    pub(crate) fn tgs_request(
        _ap_req: ApReqOpened,
        _req_body: MicVerified,
        _armor: Option<ArmorOpened>,
    ) -> ChainVerified {
        ChainVerified(())
    }

    /// `open_fast_armor`: the armor TGT and its authenticator opened, the
    /// req-checksum verified and enc-fast-req decrypted.
    /// Spec: RFC 6113 5.4.1.1, 5.4.2; docs/48 §6.3; A-26.
    pub(crate) fn fast_armor(_ap_req: ApReqOpened, _armor: ArmorOpened) -> ChainVerified {
        ChainVerified(())
    }

    /// `open_and_verify_service_ticket`: the service ticket and its
    /// authenticator opened, and the application binding as required (R2:
    /// the operation digest's MIC, usage 10, before the replay cache).
    /// Spec: RFC 4120 3.2.3, 5.5.1, 7.5.1 item 10; docs/52 §5; A-26.
    pub(crate) fn service_ticket(_ap_req: ApReqOpened, _binding: BindingEvidence) -> ChainVerified {
        ChainVerified(())
    }

    /// The refusal of `class`, reported as itself (A-26).
    /// Spec: docs/10 §9; docs/questions/Q-071 (A-26).
    pub(crate) fn refuse(&self, class: ChainClass) -> Deny {
        Deny::after_chain(self, class)
    }

    /// The recorded findings, in RFC 4120 3.2.3 order: the authenticator's
    /// skew, then the ticket's age (not yet valid, else expired).
    /// Spec: RFC 4120 3.2.3; docs/questions/Q-071 (A-26).
    pub(crate) fn report(&self, findings: TimeFindings) -> Internal<()> {
        if findings.skew {
            return Err(self.refuse(ChainClass::Skew));
        }
        match findings.ticket_time {
            Some(TicketTime::NotYetValid) => Err(self.refuse(ChainClass::TicketNotYetValid)),
            Some(TicketTime::Expired) => Err(self.refuse(ChainClass::TicketExpired)),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb_crypto::{EncType, KeyUsage};

    fn key(byte: u8) -> ProtocolKey {
        krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &[byte; 32]).unwrap()
    }

    fn verified() -> ChainVerified {
        let k = key(0x21);
        let cipher =
            krb_crypto::encrypt(&k, KeyUsage::new(1).unwrap(), &[0x55; 16], b"ts").unwrap();
        let (_, evidence) = open(&k, 1, &cipher).unwrap();
        ChainVerified::preauthentication(evidence)
    }

    /// A-26: a completed chain reports the findings in RFC 4120 3.2.3 order
    /// — skew first, then the ticket's age — each as its own class with its
    /// own audit reason; no finding ⇒ no refusal. Source: RFC 4120 3.2.3;
    /// docs/questions/Q-071.
    #[test]
    fn findings_are_reported_in_the_rfc_order() {
        let chain = verified();
        let class = |findings| chain.report(findings).map_err(AuthnError::from);
        assert_eq!(class(TimeFindings::recorded(false, None)), Ok(()));
        assert_eq!(
            class(TimeFindings::recorded(true, Some(TicketTime::Expired))),
            Err(AuthnError::Skew)
        );
        assert_eq!(
            class(TimeFindings::recorded(false, Some(TicketTime::NotYetValid))),
            Err(AuthnError::TicketNotYetValid)
        );
        assert_eq!(
            class(TimeFindings::recorded(false, Some(TicketTime::Expired))),
            Err(AuthnError::TicketExpired)
        );
        let deny = chain.refuse(ChainClass::Replay);
        assert_eq!(deny.reason, AuditReason::Replay);
        assert_eq!(AuthnError::from(deny), AuthnError::Replay);
    }

    /// R7: the evidence comes only from a real verification — a ciphertext
    /// that does not decrypt under the key, or a checksum that does not
    /// verify, yields the uniform `Denied` and no evidence. Source: RFC 3961
    /// §3, §4.
    #[test]
    fn evidence_only_from_a_passing_verification() {
        let k = key(0x21);
        let other = key(0x22);
        let usage = KeyUsage::new(6).unwrap();
        let cipher = krb_crypto::encrypt(&k, usage, &[0x55; 16], b"body").unwrap();
        assert!(open(&k, 6, &cipher).is_ok());
        let refused = open(&other, 6, &cipher).map(|_| ()).unwrap_err();
        assert_eq!(refused.reason, AuditReason::IntegrityFailure);
        assert_eq!(AuthnError::from(refused), AuthnError::Denied);
        let cksumtype = k.enc_type().checksum_type();
        let mic = krb_crypto::get_mic(&k, cksumtype, usage, b"body").unwrap();
        assert!(verify_mic(
            &k,
            cksumtype,
            6,
            b"body",
            &mic,
            AuditReason::ChecksumMismatch
        )
        .is_ok());
        let refused = verify_mic(
            &other,
            cksumtype,
            6,
            b"body",
            &mic,
            AuditReason::ChecksumMismatch,
        )
        .unwrap_err();
        assert_eq!(refused.reason, AuditReason::ChecksumMismatch);
        assert_eq!(AuthnError::from(refused), AuthnError::Denied);
    }
}
