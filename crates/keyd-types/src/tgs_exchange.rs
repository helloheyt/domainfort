//! The argument and result types of keyd's TGS exchange
//! (`open_and_verify_tgt`, `issue_tgs_rep`; role `Kdc`), with and without
//! the implicit FAST armor. The operations themselves — opening the TGT and
//! the authenticator, the req-checksum, the reply sealed under the session
//! key or subkey — are keyd's; these types carry no key (moved unchanged
//! from keyd: D182; decision A-63).
//!
//! Spec: RFC 4120 3.3.2, 3.3.3, 5.3, 5.4.2; RFC 6113 5.4.2, 5.4.3; docs/10
//! §5, §8; docs/48 §2.3, §5.

use crate::enctype::EncTypeId;
use crate::tokens::CtxId;
use krb_proto::{
    EncryptedData, KerberosTime, KrbFastArmoredReq, KrbFastReq, PrincipalName, Realm, Ticket,
    TicketFlags,
};

/// The FAST part of an armored TGS-REQ, handed to `open_and_verify_tgt`
/// (implicit armor, docs/48 §5).
///
/// `ap_req_octets` are the raw DER of the PA-TGS-REQ padata-value — "the
/// type AP-REQ in the PA-TGS-REQ padata" over which the req-checksum is
/// computed (RFC 6113 5.4.2). keyd decodes them itself and requires them to
/// be exactly the AP-REQ it opens, so the octets the checksum covers and the
/// AP-REQ keyd authenticates are one and the same (docs/48 §5.2 step 4).
///
/// Spec: docs/48 §2.3 (`fast: Option<FastArmoredFields>`; the raw AP-REQ),
/// §5; RFC 6113 5.4.2; RFC 4120 5.2.7.1 ("padata-value will contain an
/// encoded AP-REQ").
#[derive(Debug, Clone, Copy)]
pub struct TgsFastRequest<'a> {
    /// The raw DER of the PA-TGS-REQ padata-value (the AP-REQ).
    pub ap_req_octets: &'a [u8],
    /// The KrbFastArmoredReq of the request's PA-FX-FAST padata. Its `armor`
    /// field must be absent: implicit armor is the only TGS armor (RFC 6113
    /// 5.4.1.1, 5.4.2; docs/questions/Q-124 item 2).
    pub armored_req: &'a KrbFastArmoredReq,
}

/// Non-secret facts of a verified TGT, plus the one-time context id that
/// binds `issue_tgs_rep` to this verification.
///
/// docs/10 §5 lists `client: PrincipalId` and `pac`; a phase-1 TGT carries
/// no PAC, so the client is identified by the ticket's crealm / cname.
///
/// Spec: docs/10 §5 (`struct TgtContext`), §8, D36; RFC 4120 5.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TgtContext {
    /// The one-time context token.
    pub ctx_id: CtxId,
    /// Client realm from the TGT.
    pub crealm: Realm,
    /// Client name from the TGT.
    pub cname: PrincipalName,
    /// Time of initial authentication.
    pub authtime: KerberosTime,
    /// TGT starttime.
    pub starttime: Option<KerberosTime>,
    /// TGT endtime.
    pub endtime: KerberosTime,
    /// TGT renew-till.
    pub renew_till: Option<KerberosTime>,
    /// TGT flags.
    pub flags: TicketFlags,
    /// The decrypted KrbFastReq of an armored request (fast-options, padata,
    /// the inner req-body the KDC must process instead of the outer one);
    /// `None` without FAST. It holds no key.
    /// Spec: docs/48 §2.3 (`TgtContext { …, fast_req: Option<KrbFastReq> }`),
    /// §5.2; RFC 6113 5.4.2 ("This req-body field is preferred over the
    /// outer field").
    pub fast_req: Option<KrbFastReq>,
}

/// The KDC's request for a service ticket. keyd copies the client name,
/// realm, authtime and transited field from the verified TGT (RFC 4120
/// 3.3.3: by default these fields of the new ticket come from the TGT) and
/// fills in the session key itself. The service's key set is reached only
/// through dird's attested name resolution of `sname`, which `issue_tgs_rep`
/// takes beside the template (task PN11; docs/59 §7.2).
///
/// Spec: docs/10 §5 (`tgs_template: TicketTemplate`); RFC 4120 3.3.3, 5.3;
/// docs/59 §7.2 step 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TgsTicketTemplate {
    /// Service name; must equal the sname of the authenticated KDC-REQ-BODY,
    /// must be a name of the principal namespace (never a TGS name, in any
    /// case — crate principal-names), and together with this realm must be
    /// one of the two (realm, name) pairs of the service's attested name
    /// resolution — as sent or canonical, exactly (docs/59 §7.2 step 5).
    pub sname: PrincipalName,
    /// Requested starttime; within the clock skew of now (no postdating).
    pub starttime: Option<KerberosTime>,
    /// Expiration time; not after the TGT's endtime (RFC 4120 3.3.3).
    pub endtime: KerberosTime,
    /// Renew-till; exactly when RENEWABLE; not after the TGT's renew-till.
    pub renew_till: Option<KerberosTime>,
    /// Requested flags (allowed mask; RFC 4120 2.1 / 5.4.1 TGT rules).
    pub flags: TicketFlags,
    /// Session-key encryption type; must be configured (I5). A crypto-free
    /// identifier (D182; A-63).
    pub session_enctype: EncTypeId,
    /// Must equal the nonce of the authenticated KDC-REQ-BODY (RFC 4120
    /// 5.4.2 nonce echoed in EncTGSRepPart).
    pub nonce: u32,
}

/// The sealed TGS-REP parts: the service ticket (sealed under the service
/// key), the enc-part (sealed under the TGT session key or the authenticator
/// subkey — under FAST, under the reply key strengthened from the subkey)
/// and, when armored, the enc-fast-rep. The KDC assembles the TGS-REP (and,
/// when armored, its PA-FX-FAST padata around `fast_rep`).
///
/// Spec: docs/10 §5 (`struct TgsRep`); docs/48 §2.3 (`TgsRep { …, fast_rep:
/// Option<Sealed> } // Some ⇔ ctx armored`), §5.2; RFC 4120 5.4.2; RFC 6113
/// 5.4.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TgsRepParts {
    /// `ticket [5] Ticket`.
    pub ticket: Ticket,
    /// `enc-part [6] EncryptedData` (EncTGSRepPart, key usage 8 or 9, no
    /// kvno).
    pub enc_part: EncryptedData,
    /// `enc-fast-rep` of the KrbFastArmoredRep (the KrbFastResponse sealed
    /// in the armor key, key usage 52): `Some` exactly when the context was
    /// armored. Spec: RFC 6113 5.4.3; docs/48 §2.3.
    pub fast_rep: Option<EncryptedData>,
}
