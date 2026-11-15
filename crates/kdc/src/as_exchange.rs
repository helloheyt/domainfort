//! The Authentication Service exchange: receipt of KRB_AS_REQ and generation
//! of KRB_AS_REP (phase 1: the AS issues TGTs, docs/30 §2, and — armored
//! only, to users only — tickets for the change-password service
//! `kadmin/changepw`, docs/53 §5.2) — FAST-armored (RFC 6113), with one
//! narrow unarmored exception, the bootstrap of a computer account (docs/48
//! §4, §7).
//!
//! # The request shape (steps R1-R8, on the outer body of an unarmored
//! request, on the INNER body of an armored one)
//!
//! R1. KDC options asking for an unimplemented operation, or request content
//!     phase 1 cannot honour (addresses, additional tickets,
//!     enc-authorization-data) → KDC_ERR_BADOPTION (decision 9);
//! R2. cname absent → KDC_ERR_C_PRINCIPAL_UNKNOWN; sname absent →
//!     KDC_ERR_S_PRINCIPAL_UNKNOWN (5.4.1);
//! R3. another realm → KDC_ERR_C_PRINCIPAL_UNKNOWN (single realm, decision
//!     4: such a client is not in this KDC's database, 3.1.3);
//! R4. sname: a TGS name of another realm → KDC_ERR_S_PRINCIPAL_UNKNOWN (no
//!     inter-realm key); `kadmin/changepw` → accepted on the armored path
//!     only (below); any other non-TGS service → KDC_ERR_POLICY (the phase-1
//!     AS issues TGTs, docs/30 §2);
//! R5. starttime beyond the skew → KDC_ERR_CANNOT_POSTDATE (3.1.3);
//! R6. the client account: source failure → KRB_ERR_GENERIC (fail closed,
//!     decision 3), source unreachable → KDC_ERR_SVC_UNAVAILABLE (7.5.9;
//!     docs/50 §3.7, A-56); unknown → KDC_ERR_C_PRINCIPAL_UNKNOWN (3.1.3;
//!     user enumeration is a documented residual, decision 5);
//! R7. disabled / locked / expired → KDC_ERR_CLIENT_REVOKED, checked BEFORE
//!     pre-authentication so that a locked or disabled account is never a
//!     password-guessing oracle and keyd is never asked for it;
//! R8. no acceptable AES enctype → KDC_ERR_ETYPE_NOSUPP (decision 6).
//!
//! # Unarmored (no PA-FX-FAST): the layer-1 gate and the bootstrap
//!
//! U1. R1-R8 on the request body. Here R4 can yield one server only, this
//!     realm's TGS ([`LocalTgt`]): `kadmin/changepw` → the U2 refusal at
//!     once, for every client, before the account is looked up and before
//!     keyd — the unarmored path has no value that names that service, so an
//!     unarmored AS for it cannot be expressed, not merely is refused (A-142:
//!     a passive observer of such an AS could guess the old password offline
//!     and read the new one; docs/53 §5.2: "an unarmored AS to
//!     `kadmin/changepw` is refused for every principal");
//! U2. the mandatory-FAST gate (docs/48 §7.2 layer 1, before keyd): unless
//!     the client is a computer account allowed to bootstrap
//!     ([`crate::ClientAccount`] `kind` / `armor_policy`, P-10 interim) — it
//!     asks for this realm's TGT by U1's type — → KDC_ERR_PREAUTH_REQUIRED
//!     advertising ONLY PA-FX-FAST and PA-FX-COOKIE — no padata is looked at
//!     and keyd is not asked, so a passive observer never gets a
//!     PA-ENC-TIMESTAMP of such a principal to attack offline (RFC 6113 5.4);
//! U3. the PA-FX-COOKIE, if any, first (RFC 6113 2.4) → else
//!     KDC_ERR_PREAUTH_EXPIRED;
//! U4. PA-ENC-TIMESTAMP is mandatory (docs/02 §3, docs/30 §2.1): none →
//!     KDC_ERR_PREAUTH_REQUIRED with METHOD-DATA (PA-FX-FAST, PA-ENC-TIMESTAMP,
//!     PA-ETYPE-INFO2 for the acceptable enctypes, PA-FX-COOKIE); more than
//!     one, an undecodable one, or one in a non-negotiated enctype →
//!     KDC_ERR_PREAUTH_FAILED; keyd `verify_preauth` (no armor) refuses →
//!     KDC_ERR_PREAUTH_FAILED — also when keyd reports the timestamp, which
//!     decrypted, as out of skew (`AuthnError::Skew`, A-26): RFC 4120 names no
//!     distinct code for that (see [`preauth_refusal`]);
//! U5. the PDP (`KdcAs`, `armored = false`) denies → KDC_ERR_POLICY;
//! U6. times planned within policy (decision 10) → KDC_ERR_NEVER_VALID if too
//!     short; keyd `issue_as_rep` (no armor) seals the TGT and the reply;
//! U7. the AS-REP: crealm / cname as requested (no canonicalisation), no
//!     padata (PA-ETYPE-INFO2 "MAY also be sent in an AS-REP"; the client
//!     already used the right key, so it is omitted — minimalism, docs/25 §5).
//!
//! # Armored (one PA-FX-FAST): docs/48 §4.1 A1-A14
//!
//! A1. two PA-FX-FAST → KRB_ERR_GENERIC; one → the outer body and every other
//!     outer padata are ignored (RFC 6113 5.4.5) — the outer body only feeds
//!     keyd's req-checksum;
//! A2. the PA-FX-FAST does not decode → KDC_ERR_PREAUTH_FAILED;
//! A3. no armor ("MUST be present in AS-REQ", 5.4.2), or an armor type other
//!     than FX_FAST_ARMOR_AP_REQUEST ("it MUST respond with
//!     KDC_ERR_PREAUTH_FAILED", 5.4.1) → KDC_ERR_PREAUTH_FAILED;
//! A4. keyd `open_fast_armor` refuses → KDC_ERR_PREAUTH_FAILED, or the A-26
//!     class code ([`crate::fast`]); every refusal up to here is UNARMORED
//!     (no armor key exists, docs/48 §6.2); from here on every refusal is
//!     ARMORED — sealed by keyd in the armor key (docs/48 §6.1, R48-6) — and
//!     the request is the INNER one;
//! A5. the armor ticket's client is re-evaluated (D126, D53): unknown, not a
//!     computer account, disabled / locked / expired, or the armor TGT
//!     predates its revocation instant → KDC_ERR_POLICY (Q-125 item 6);
//! A6. a critical FastOptions bit (0-15; hide-client-names included) →
//!     KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS (A-25, docs/48 §8);
//! A7. the inner padata: PA-FX-COOKIE first (→ KDC_ERR_PREAUTH_EXPIRED); two
//!     PA-ENCRYPTED-CHALLENGE → KDC_ERR_PREAUTH_FAILED; everything else —
//!     PA-ENC-TIMESTAMP included — ignored (docs/48 §4.5);
//! A8. R1-R8 on the inner body; R4 yields this realm's TGS or
//!     `kadmin/changepw` — the latter holding this exchange's armor
//!     ([`ArmoredServer::ChangePassword`]);
//! A8a. `kadmin/changepw` only (docs/53 §5.2): the client must be a user
//!     account (R53-1: a computer, and so every service object, R47-13 →
//!     KDC_ERR_POLICY); the service object (unknown →
//!     KDC_ERR_S_PRINCIPAL_UNKNOWN; key set not ChangePasswordService →
//!     KRB_ERR_GENERIC; disabled / locked / expired →
//!     KDC_ERR_SERVICE_REVOKED); a session-key type both the client offers
//!     and the service accepts (RFC 4120 3.1.3; none → KDC_ERR_ETYPE_NOSUPP)
//!     — all before pre-authentication and keyd;
//! A9. no PA-ENCRYPTED-CHALLENGE → KDC_ERR_PREAUTH_REQUIRED whose sealed
//!     KrbFastResponse advertises PA-ENCRYPTED-CHALLENGE (empty) and carries
//!     PA-ETYPE-INFO2 with the ONE entry keyd will use as the long-term key
//!     (docs/questions/Q-123) and the PA-FX-COOKIE;
//! A10. keyd `verify_preauth` under the armor refuses → KDC_ERR_PREAUTH_FAILED
//!     with that PA-ETYPE-INFO2 (RFC 6113 5.4.6), or — the challenge
//!     decrypted but out of skew — KRB_AP_ERR_SKEW (5.4.6 "KRB_APP_ERR_SKEW",
//!     which RFC 4120 7.5.9 calls KRB_AP_ERR_SKEW; R48-6, Q-125 item 8);
//! A11. the PDP (`KdcAs`, `armored = true`, strength `KerberosFast`; the
//!     resource the TGT, or `KerbResKind::ChangePassword`) denies →
//!     KDC_ERR_POLICY;
//! A12-A13. times and flags as U6 — for `kadmin/changepw` the ticket profile
//!     instead (docs/53 §5.2): endtime capped at the start plus
//!     [`CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS`], never renewable,
//!     forwardable or proxiable, starting now; keyd sets INITIAL and
//!     PRE-AUTHENT itself — keyd `issue_as_rep` under the armor (the
//!     strengthened reply key, KrbFastFinished, the sealed `fast_rep`), for
//!     `kadmin/changepw` with that service's key set as the server key and
//!     the requested sname (no canonicalisation, [MS-KILE] 3.3.5.1.2);
//! A14. the AS-REP: padata = [PA-FX-FAST(enc-fast-rep)] only, crealm / cname
//!     of the inner request (5.4.3, 5.4.5).
//!
//! Every keyd call above (`open_fast_armor`, `verify_preauth`,
//! `issue_as_rep`) that keyd does not serve — the `Unavailable` variant: its
//! startup hold-down (RFC 4120 3.2.3), or keyd unreachable at an IPC client
//! — is KDC_ERR_SVC_UNAVAILABLE (7.5.9, code 29), never PREAUTH_FAILED;
//! nothing is sent over UDP (docs/50 §3.7, R50-8; A-56).
//!
//! Spec: RFC 4120 2.1, 3.1.2, 3.1.3, 3.2.3, 5.2.7.2-5.2.7.5, 5.4.1, 5.4.2,
//! 6.2, 7.3, 7.5.9; RFC 6113 2.4, 5.2, 5.4, 5.4.1, 5.4.1.1, 5.4.2, 5.4.3,
//! 5.4.4, 5.4.5, 5.4.6, 7.3; RFC 3244 §2; [MS-KILE] 3.3.5.1.2; docs/30 §2;
//! docs/10 §4, §5a; docs/48 §3.1, §4, §6, §7, §8; docs/50 §3.7 (R50-8);
//! docs/53 R53-1, R53-6, §5.2 (task K5); Q-123, Q-125, Q-126 (A-32); Q-127
//! interim (P-10); Q-217 (A-56); A-117, A-139, A-142; main-session decisions
//! 3-10.

use crate::accounts::{AccountKind, AccountSource, ClientAccount, NamedPrincipal, ServiceAccount};
use crate::audit::{AuditReason, AuditSink};
use crate::etype::negotiate;
use crate::fast::{
    armor_refusal, armored_request, check_cookie, cookie_padata, fx_fast_padata, fx_fast_reply,
    has_critical_fast_option, inner_challenge,
};
use crate::gate::{enforce, PolicyInputs, Question, RateLimiter};
use crate::kdc::{
    account_source_refusal, custody_unavailable, internal, issue_refusal, local_tgs_name,
    time_refusal, Kdc, Refusal, Scope,
};
use crate::krb_error::{advertise, etype_info2, fast_required_e_data, preauth_required_e_data};
use crate::lifetime::{check_starttime, plan, LifetimeRequest, Limits};
use crate::names::{classify_server, same_realm, ServerNameKind};
use crate::options::{asks_unsupported_operation, delegation_flags, FlagRequests};
use crate::time::seconds;
use crate::transport::Peer;
use core::time::Duration;
use keyd_types::{
    ArmorId, AsRepParts, AsTicketTemplate, AuthnError, AuthnProof, EncTypeId, KeyCustody,
    KeyPurpose, CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS,
};
use krb_proto::constants::{
    FX_FAST_ARMOR_AP_REQUEST, KDC_ERR_BADOPTION, KDC_ERR_CLIENT_REVOKED,
    KDC_ERR_C_PRINCIPAL_UNKNOWN, KDC_ERR_ETYPE_NOSUPP, KDC_ERR_POLICY, KDC_ERR_PREAUTH_FAILED,
    KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_SERVICE_REVOKED, KDC_ERR_S_PRINCIPAL_UNKNOWN,
    KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS, KRB_AP_ERR_SKEW, PA_ENCRYPTED_CHALLENGE,
    PA_ENC_TIMESTAMP,
};
use krb_proto::{
    AsRep, EncryptedData, EtypeInfo2Entry, KdcRep, KdcReq, KdcReqBody, KerberosTime, PaData,
    PrincipalName, Realm, TicketFlags,
};
use pdp::{Action, KerbResKind, Resource};

/// `true` if the request carries content phase 1 cannot honour: addresses
/// (keyd issues addressless tickets and refuses to drop a restriction,
/// docs/10 §5), additional tickets (only for ENC-TKT-IN-SKEY / S4U, refused),
/// or enc-authorization-data (TGS-only per 5.4.1, and keyd carries no
/// authorization data in phase 1). Empty SEQUENCE OF values count as absent
/// (5.1.3).
/// Spec: RFC 4120 5.1.3, 5.4.1, 3.3.3; docs/10 §5.
pub(crate) fn has_unsupported_content(body: &KdcReqBody) -> bool {
    body.addresses.as_ref().is_some_and(|a| !a.0.is_empty())
        || body
            .additional_tickets
            .as_ref()
            .is_some_and(|t| !t.is_empty())
        || body.enc_authorization_data.is_some()
}

/// keyd's unarmored `verify_preauth` refusals. Every one is
/// KDC_ERR_PREAUTH_FAILED: RFC 4120 3.1.3 — "if the pre-authentication check
/// fails, an error message with the code KDC_ERR_PREAUTH_FAILED is
/// returned". 5.2.7.2 defines PA-ENC-TIMESTAMP without naming any error
/// code, and 3.1.5 (client clock offset) concerns a successful AS-REP, so
/// RFC 4120 prescribes no code for an out-of-skew timestamp distinct from
/// PREAUTH_FAILED (KRB_AP_ERR_SKEW is prescribed only for the AP-REQ
/// authenticator, 3.2.3). The skew class (A-26) is kept apart in audit only
/// (`PreauthSkew`). The KRB-ERROR's stime is the KDC's `now` (5.9.1). keyd's
/// per-principal failure throttle (A-34) refuses as the uniform `Denied`, so
/// a throttled attempt is the same KDC_ERR_PREAUTH_FAILED as a wrong
/// password — nothing tells the client the account exists or is under
/// attack; keyd's own audit records `Throttled` (the KDC audit cannot tell it
/// apart: docs/questions/Q-128). The one exception is `Unavailable` — keyd
/// did not look at the timestamp at all (its startup hold-down, or keyd
/// unreachable): KDC_ERR_SVC_UNAVAILABLE, so that a user is not told the
/// password is wrong (docs/50 §3.7, R50-8; A-56).
/// Spec: RFC 4120 3.1.3, 5.2.7.2, 3.1.5, 3.2.3, 7.5.9; docs/questions/Q-071
/// (A-26); A-34; docs/questions/Q-217 (A-56).
fn preauth_refusal(error: AuthnError) -> Refusal {
    let reason = match error {
        AuthnError::Unavailable => return custody_unavailable(),
        AuthnError::Skew => AuditReason::PreauthSkew,
        AuthnError::Denied
        | AuthnError::TicketExpired
        | AuthnError::TicketNotYetValid
        | AuthnError::Replay => AuditReason::PreauthDenied,
    };
    Refusal::new(KDC_ERR_PREAUTH_FAILED, reason)
}

/// keyd's armored `verify_preauth` (encrypted challenge) refusals, sealed by
/// the caller:
/// - the challenge decrypted under the challenge key but is outside the
///   clock skew (`Skew`, reported only after the chain completed, A-26) →
///   KRB_AP_ERR_SKEW — unlike PA-ENC-TIMESTAMP, RFC 6113 5.4.6 names a clock
///   code for the encrypted challenge ("returning KRB_APP_ERR_SKEW"; RFC 4120
///   7.5.9 calls code 37 KRB_AP_ERR_SKEW, Q-125 item 8); the KRB-ERROR's
///   stime, integrity-protected inside PA-FX-ERROR, is the KDC time the
///   client may base its next challenge on (5.4.6); the cookie lets it retry;
/// - anything else (a wrong key, keyd's throttle, a second attempt on the
///   armor) → KDC_ERR_PREAUTH_FAILED "including PA-ETYPE-INFO2 in the
///   KRBFastResponse" (5.4.6), and the cookie (5.2: "KDCs SHOULD include a
///   cookie in errors containing additional information allowing a client to
///   retry");
/// - `Unavailable` (keyd did not serve the call) → KDC_ERR_SVC_UNAVAILABLE,
///   sent unarmored over TCP (keyd cannot seal it) and not at all over UDP
///   (docs/50 §3.7, R50-8; A-56).
///
/// Spec: RFC 6113 5.2, 5.4.6; RFC 4120 7.5.9; docs/48 §4.1 A10, §6.3 (R48-6);
/// docs/questions/Q-125 item 8 (A-32); A-26, A-34; docs/questions/Q-217
/// (A-56).
fn challenge_refusal(error: AuthnError, etype_info: PaData) -> Refusal {
    match error {
        AuthnError::Unavailable => custody_unavailable(),
        AuthnError::Skew => Refusal::new(KRB_AP_ERR_SKEW, AuditReason::PreauthSkew)
            .with_fast_padata(vec![cookie_padata()]),
        AuthnError::Denied
        | AuthnError::TicketExpired
        | AuthnError::TicketNotYetValid
        | AuthnError::Replay => Refusal::new(KDC_ERR_PREAUTH_FAILED, AuditReason::PreauthDenied)
            .with_fast_padata(vec![etype_info, cookie_padata()]),
    }
}

/// The refusal of an AS request that must be FAST-armored, before keyd and
/// before any padata is looked at: KDC_ERR_PREAUTH_REQUIRED whose METHOD-DATA
/// advertises ONLY PA-FX-FAST (empty) and PA-FX-COOKIE (U1, U2).
/// Spec: docs/48 §7.2 layer 1; RFC 6113 5.2, 5.4.2 ("KDCs MUST send the
/// advertisement of PA-FX-FAST with an empty pa-value"); RFC 4120 3.1.3
/// (KDC_ERR_PREAUTH_REQUIRED with METHOD-DATA); A-142.
fn fast_required() -> Refusal {
    match fast_required_e_data() {
        Some(e_data) => Refusal {
            code: KDC_ERR_PREAUTH_REQUIRED,
            reason: AuditReason::FastRequired,
            e_data: Some(e_data),
            fast_padata: Vec::new(),
        },
        None => internal(AuditReason::InternalFailure),
    }
}

/// The one server an unarmored AS request can name (R4 on the unarmored
/// path, U1): this realm's TGS. It carries nothing — and there is no other
/// value, so the unarmored path cannot express a ticket for any other
/// server, the change-password service included.
/// Spec: docs/48 §7.3 (the bootstrap: "only TGT"); docs/53 §5.2; A-142.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalTgt;

/// R4 on the unarmored path (U1): this realm's TGS is the only server;
/// `kadmin/changepw` is refused with the U2 shape at once — for every
/// client, before the account lookup (so it is no account oracle either);
/// the other refusals are R4's.
/// Spec: RFC 4120 3.1.3, 7.3; docs/30 §2; docs/48 §7.2 layer 1, §7.3;
/// docs/53 §5.2; A-142; main-session decision 4.
fn unarmored_server(kind: ServerNameKind) -> Result<LocalTgt, Refusal> {
    match kind {
        ServerNameKind::LocalTgs => Ok(LocalTgt),
        ServerNameKind::ForeignTgs => Err(Refusal::new(
            KDC_ERR_S_PRINCIPAL_UNKNOWN,
            AuditReason::CrossRealm,
        )),
        ServerNameKind::Service => Err(Refusal::new(KDC_ERR_POLICY, AuditReason::AsServerNotTgs)),
        ServerNameKind::ChangePassword => Err(fast_required()),
    }
}

/// The servers an armored AS request can name (R4 on the armored path, A8).
/// Spec: docs/30 §2; docs/53 §5.2; A-117.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArmoredServer {
    /// This realm's TGS.
    Tgt,
    /// The change-password service (`kadmin/changepw`), holding the armor of
    /// this exchange: the variant is built only by [`armored_server`], from
    /// the `ArmorId` keyd's `open_fast_armor` returned — the issuance of its
    /// ticket ([`ChangePasswordTarget`]) takes that armor, not an `Option`
    /// of one, and keyd binds a proof to its armor (None↔None,
    /// Some(a)↔Some(a), docs/48 §2.3).
    /// Spec: docs/53 §5.2; A-117, A-142.
    ChangePassword {
        /// The armor of this exchange.
        armor: ArmorId,
    },
}

/// R4 on the armored path (A8): this realm's TGS, or `kadmin/changepw` with
/// `armor`; the other refusals are R4's.
/// Spec: RFC 4120 3.1.3, 7.3; docs/30 §2; docs/53 §5.2; main-session
/// decision 4.
fn armored_server(kind: ServerNameKind, armor: ArmorId) -> Result<ArmoredServer, Refusal> {
    match kind {
        ServerNameKind::LocalTgs => Ok(ArmoredServer::Tgt),
        ServerNameKind::ChangePassword => Ok(ArmoredServer::ChangePassword { armor }),
        ServerNameKind::ForeignTgs => Err(Refusal::new(
            KDC_ERR_S_PRINCIPAL_UNKNOWN,
            AuditReason::CrossRealm,
        )),
        ServerNameKind::Service => Err(Refusal::new(KDC_ERR_POLICY, AuditReason::AsServerNotTgs)),
    }
}

/// What A8a established for an armored AS request for `kadmin/changepw`:
/// the armor (from [`ArmoredServer::ChangePassword`]), the service object
/// whose key set seals the ticket, and the session-key type.
/// Spec: docs/53 §5.2; RFC 4120 3.1.3.
struct ChangePasswordTarget {
    /// The armor of this exchange (never absent: no `Option`).
    armor: ArmorId,
    /// The change-password service's account (key purpose
    /// ChangePasswordService, usable now).
    service: ServiceAccount,
    /// The session-key type: the first of the client's list that keyd
    /// configures and the service accepts.
    session_enctype: EncTypeId,
}

/// What R1-R8 established about a request body; `S` is what R4 may yield
/// on the path that checked it ([`LocalTgt`] unarmored, [`ArmoredServer`]
/// armored).
/// Spec: RFC 4120 3.1.3; docs/48 §4.1 A8.
struct CheckedRequest<S> {
    /// The client account (key purpose and state checked).
    account: ClientAccount,
    /// The acceptable enctypes, in the client's preference order (non-empty).
    acceptable: Vec<i32>,
    /// The requested server (R4).
    server: S,
}

impl<S> CheckedRequest<S> {
    /// The client's ETYPE-INFO2 entries for the acceptable enctypes, in the
    /// client's order. Spec: RFC 4120 3.1.3, 5.2.7.5.
    fn hints(&self) -> Vec<EtypeInfo2Entry> {
        self.acceptable
            .iter()
            .filter_map(|etype| self.account.etype_info.iter().find(|e| e.etype == *etype))
            .cloned()
            .collect()
    }

    /// PA-ETYPE-INFO2 with ONE entry: the first acceptable enctype — the
    /// long-term key keyd selects for the encrypted challenge (the first of
    /// the inner etype list ∩ configured ∩ the client's keys), so the client
    /// is told exactly the key keyd will use.
    /// Spec: RFC 6113 2.1 ("KDC implementations MAY choose to offer only one
    /// key in the PA-ETYPE-INFO2 element"), 5.4.6; docs/48 §4.5 step 3;
    /// docs/questions/Q-123 (a) (A-32).
    fn challenge_etype_info(&self) -> Result<PaData, Refusal> {
        let first = self
            .hints()
            .into_iter()
            .next()
            .ok_or_else(|| internal(AuditReason::AccountRecordInvalid))?;
        etype_info2(vec![first]).ok_or_else(|| internal(AuditReason::InternalFailure))
    }
}

impl<K: KeyCustody, U: AuditSink, R: RateLimiter> Kdc<K, U, R> {
    /// Receipt of KRB_AS_REQ and generation of KRB_AS_REP (module docs).
    /// `scope` turns to the inner request once the FAST armor is open;
    /// `accounts` is this request's account source (docs/47 R47-14).
    /// Spec: RFC 4120 3.1.2, 3.1.3; RFC 6113 5.4.2, 5.4.5; docs/30 §2;
    /// docs/48 §4.1.
    pub(crate) fn receive_as_req(
        &mut self,
        req: &KdcReq,
        scope: &mut Scope,
        peer: Peer,
        now: &KerberosTime,
        policy: &PolicyInputs<'_>,
        accounts: &dyn AccountSource,
    ) -> Result<Vec<u8>, Refusal> {
        let padata = req.padata.as_deref().unwrap_or(&[]);
        // A1 (docs/48 §4.1).
        match fx_fast_padata(padata)? {
            None => self.unarmored_as(req, peer, now, policy, accounts),
            Some(fast) => self.armored_as(req, fast, scope, peer, now, policy, accounts),
        }
    }

    /// Steps R1-R8 (module docs) on `body` — the outer body of an unarmored
    /// request, the inner body of an armored one ("The KDC-REQ-BODY in the
    /// FAST structure is used in preference", RFC 6113 5.4.2). R4 is the
    /// path's `server_of` ([`unarmored_server`] / [`armored_server`]).
    /// Spec: RFC 4120 3.1.3, 5.4.1; docs/48 §4.1 A8; docs/53 §5.2; decisions
    /// 3-9.
    fn check_as_request<S>(
        &self,
        body: &KdcReqBody,
        now: &KerberosTime,
        accounts: &dyn AccountSource,
        server_of: impl FnOnce(ServerNameKind) -> Result<S, Refusal>,
    ) -> Result<CheckedRequest<S>, Refusal> {
        let keyd_config = self.custody.config();
        let configured: Vec<i32> = keyd_config.enctypes.iter().map(|e| e.number()).collect();
        let skew = keyd_config.clock_skew_secs;

        // R1. Options and content (decision 9).
        if asks_unsupported_operation(body.kdc_options) {
            return Err(Refusal::new(
                KDC_ERR_BADOPTION,
                AuditReason::UnsupportedOption,
            ));
        }
        if has_unsupported_content(body) {
            return Err(Refusal::new(
                KDC_ERR_BADOPTION,
                AuditReason::UnsupportedContent,
            ));
        }

        // R2-R4. Names and realm (5.4.1; decision 4; docs/30 §2).
        let cname = body.cname.as_ref().ok_or(Refusal::new(
            KDC_ERR_C_PRINCIPAL_UNKNOWN,
            AuditReason::MissingName,
        ))?;
        let sname = body.sname.as_ref().ok_or(Refusal::new(
            KDC_ERR_S_PRINCIPAL_UNKNOWN,
            AuditReason::MissingName,
        ))?;
        if !same_realm(&body.realm, &self.config.realm) {
            return Err(Refusal::new(
                KDC_ERR_C_PRINCIPAL_UNKNOWN,
                AuditReason::CrossRealm,
            ));
        }
        let server = server_of(classify_server(sname, &self.config.realm))?;

        // R5. Starttime (3.1.3).
        check_starttime(body.from.as_ref(), now, skew).map_err(time_refusal)?;

        // R6-R7. The client account and its state (3.1.3; decisions 3, 5, 8).
        let account = match accounts.client(&body.realm, cname) {
            Err(error) => return Err(account_source_refusal(error)),
            Ok(None) => {
                return Err(Refusal::new(
                    KDC_ERR_C_PRINCIPAL_UNKNOWN,
                    AuditReason::ClientUnknown,
                ))
            }
            Ok(Some(account)) => account,
        };
        if account.key.purpose != KeyPurpose::PrincipalLongterm {
            return Err(internal(AuditReason::AccountRecordInvalid));
        }
        if !account.state.usable_at(now) {
            return Err(Refusal::new(
                KDC_ERR_CLIENT_REVOKED,
                AuditReason::ClientRevoked,
            ));
        }

        // R8. Encryption types (3.1.3; decision 6).
        let account_etypes: Vec<i32> = account.etype_info.iter().map(|e| e.etype).collect();
        let acceptable = negotiate(&body.etype, &configured, &account_etypes);
        if acceptable.is_empty() {
            return Err(Refusal::new(
                KDC_ERR_ETYPE_NOSUPP,
                AuditReason::NoCommonEncType,
            ));
        }
        Ok(CheckedRequest {
            account,
            acceptable,
            server,
        })
    }

    /// The unarmored AS request: steps U1-U7 (module docs).
    /// Spec: RFC 4120 3.1.3, 5.2.7.2; docs/48 §7.2 (layer 1), §7.3.
    fn unarmored_as(
        &mut self,
        req: &KdcReq,
        peer: Peer,
        now: &KerberosTime,
        policy: &PolicyInputs<'_>,
        accounts: &dyn AccountSource,
    ) -> Result<Vec<u8>, Refusal> {
        let body = &req.req_body;

        // U1. R1-R8; R4 yields this realm's TGS or nothing — the unarmored
        // path has no value for any other server (A-142; docs/53 §5.2).
        let checked: CheckedRequest<LocalTgt> =
            self.check_as_request(body, now, accounts, unarmored_server)?;

        // U2. The mandatory-FAST gate, before keyd and before any padata is
        // looked at (docs/48 §7.2 layer 1). The bootstrap is for a computer
        // account and for this realm's TGT only (docs/48 §7.3) — the TGT by
        // the type of `checked.server`, so the exception cannot outgrow its
        // definition.
        let LocalTgt = checked.server;
        if !checked.account.may_bootstrap() {
            return Err(fast_required());
        }

        // U3. The cookie first (RFC 6113 2.4).
        let padata = req.padata.as_deref().unwrap_or(&[]);
        check_cookie(padata)?;

        // U4. PA-ENC-TIMESTAMP (3.1.3, 5.2.7.2; decision 5).
        let mut timestamps = padata.iter().filter(|p| p.padata_type == PA_ENC_TIMESTAMP);
        let timestamp = match (timestamps.next(), timestamps.next()) {
            (None, _) => {
                let e_data = preauth_required_e_data(checked.hints())
                    .ok_or_else(|| internal(AuditReason::InternalFailure))?;
                return Err(Refusal {
                    code: KDC_ERR_PREAUTH_REQUIRED,
                    reason: AuditReason::PreauthRequired,
                    e_data: Some(e_data),
                    fast_padata: Vec::new(),
                });
            }
            (Some(_), Some(_)) => {
                return Err(Refusal::new(
                    KDC_ERR_PREAUTH_FAILED,
                    AuditReason::PreauthAmbiguous,
                ))
            }
            (Some(timestamp), None) => timestamp,
        };
        let offered = EncryptedData::decode(&timestamp.padata_value)
            .map_err(|_| Refusal::new(KDC_ERR_PREAUTH_FAILED, AuditReason::PreauthUnacceptable))?;
        if !checked.acceptable.contains(&offered.etype) {
            return Err(Refusal::new(
                KDC_ERR_PREAUTH_FAILED,
                AuditReason::PreauthUnacceptable,
            ));
        }
        let proof = self
            .custody
            .verify_preauth(&checked.account.key, timestamp, None, now)
            .map_err(preauth_refusal)?;

        // U5-U6. The PDP (armored = false), times, keyd issues.
        let parts = self.issue_tgt(body, &checked, &proof, None, peer, now, policy)?;

        // U7. The AS-REP (5.4.2).
        let cname = body
            .cname
            .clone()
            .ok_or_else(|| internal(AuditReason::InternalFailure))?;
        encode_as_rep(None, &body.realm, cname, parts)
    }

    /// The armored AS request: steps A2-A14 (module docs; docs/48 §4.1).
    /// Spec: RFC 6113 5.4.1, 5.4.1.1, 5.4.2, 5.4.3, 5.4.5, 5.4.6; docs/48
    /// §3.1, §4, §6, §8.
    #[allow(clippy::too_many_arguments)]
    fn armored_as(
        &mut self,
        req: &KdcReq,
        fast: &PaData,
        scope: &mut Scope,
        peer: Peer,
        now: &KerberosTime,
        policy: &PolicyInputs<'_>,
        accounts: &dyn AccountSource,
    ) -> Result<Vec<u8>, Refusal> {
        // A2-A3. The armored request and its armor (unarmored refusals).
        let armored_req = armored_request(fast)?;
        let armor = armored_req.armor.as_ref().ok_or(Refusal::new(
            KDC_ERR_PREAUTH_FAILED,
            AuditReason::FastArmorMissing,
        ))?;
        if armor.armor_type != FX_FAST_ARMOR_AP_REQUEST {
            return Err(Refusal::new(
                KDC_ERR_PREAUTH_FAILED,
                AuditReason::FastArmorTypeUnsupported,
            ));
        }

        // A4. keyd opens the armor; the req-checksum covers the outer body's
        // octets (RFC 6113 5.4.2). krb-proto decodes strict DER only and
        // losslessly, so encoding the decoded body reproduces the received
        // octets exactly (tests/body_reencode.rs).
        let outer_body = req
            .req_body
            .encode()
            .map_err(|_| internal(AuditReason::InternalFailure))?;
        let krbtgt = self.config.krbtgt;
        let opened = self
            .custody
            .open_fast_armor(&krbtgt, &armored_req, &outer_body, now)
            .map_err(armor_refusal)?;
        let armor_id = opened.armor_id;
        let fast_req = opened.fast_req;
        // From here on: the inner request, armored refusals (docs/48 §6.1).
        scope.armor_as(
            &fast_req.req_body,
            &self.local,
            NamedPrincipal {
                realm: opened.armor_crealm.clone(),
                name: opened.armor_cname.clone(),
            },
            armor_id,
        );

        // A5. The armor principal, re-evaluated now (D126, D53).
        self.check_armor_principal(
            &opened.armor_crealm,
            &opened.armor_cname,
            &opened.armor_authtime,
            now,
            accounts,
        )?;

        // A6. FastOptions (A-25; docs/48 §8).
        if has_critical_fast_option(fast_req.fast_options) {
            return Err(Refusal::new(
                KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
                AuditReason::UnknownCriticalFastOption,
            ));
        }

        // A7. The inner padata.
        let challenge = inner_challenge(&fast_req.padata)?;

        // A8. R1-R8 on the inner body; R4 yields this realm's TGS, or
        // `kadmin/changepw` holding this exchange's armor (docs/53 §5.2).
        let body = &fast_req.req_body;
        let checked: CheckedRequest<ArmoredServer> =
            self.check_as_request(body, now, accounts, |kind| armored_server(kind, armor_id))?;

        // A8a. The change-password service: a user client, its service
        // object, its session-key type — before pre-authentication and keyd
        // (docs/53 R53-1, §5.2).
        let change_password = match checked.server {
            ArmoredServer::Tgt => None,
            ArmoredServer::ChangePassword { armor } => {
                Some(self.change_password_target(body, &checked.account, armor, now, accounts)?)
            }
        };
        let etype_info = checked.challenge_etype_info()?;

        // A9. PREAUTH_REQUIRED, armored (RFC 6113 2.2, 5.2, 5.4.4, 5.4.6).
        let Some(challenge) = challenge else {
            let fallback =
                fast_required_e_data().ok_or_else(|| internal(AuditReason::InternalFailure))?;
            return Err(Refusal {
                code: KDC_ERR_PREAUTH_REQUIRED,
                reason: AuditReason::PreauthRequired,
                e_data: Some(fallback),
                fast_padata: vec![
                    advertise(PA_ENCRYPTED_CHALLENGE),
                    etype_info,
                    cookie_padata(),
                ],
            });
        };

        // A10. keyd verifies the encrypted challenge under the armor.
        let proof = self
            .custody
            .verify_preauth(&checked.account.key, challenge, Some(armor_id), now)
            .map_err(|error| challenge_refusal(error, etype_info))?;

        // A11-A13. The PDP (armored = true), times, keyd issues under the
        // armor — a TGT, or the change-password service's ticket under its
        // profile (docs/53 §5.2).
        let parts = match change_password {
            None => self.issue_tgt(body, &checked, &proof, Some(armor_id), peer, now, policy)?,
            Some(target) => self
                .issue_change_password_ticket(body, &checked, &proof, target, peer, now, policy)?,
        };

        // A14. The AS-REP: PA-FX-FAST only; the inner request's names.
        let fast_rep = parts
            .fast_rep
            .clone()
            .ok_or_else(|| internal(AuditReason::InternalFailure))?;
        let padata =
            fx_fast_reply(fast_rep).ok_or_else(|| internal(AuditReason::InternalFailure))?;
        let cname = body
            .cname
            .clone()
            .ok_or_else(|| internal(AuditReason::InternalFailure))?;
        encode_as_rep(Some(vec![padata]), &body.realm, cname, parts)
    }

    /// A5: the armor ticket's client must be an account of this KDC that is a
    /// computer account (D126), usable now, and whose revocation instant does
    /// not post-date the armor TGT's authtime (D53; the RFC 4120 3.3.3.1
    /// hot-list the KDC also applies at TGS) — so a machine that was removed
    /// stops armoring at once, not when its TGT expires. Every failure is
    /// KDC_ERR_POLICY (sealed by the caller); an account-source failure is
    /// KRB_ERR_GENERIC (fail closed), an unreachable account source
    /// KDC_ERR_SVC_UNAVAILABLE (docs/50 §3.7).
    /// Spec: docs/48 §3.1 (option (b)), §4.1 A5; RFC 6113 5.4.1.1; RFC 4120
    /// 3.3.3.1; docs/questions/Q-125 item 6 (A-32); D126, D53.
    fn check_armor_principal(
        &self,
        crealm: &Realm,
        cname: &PrincipalName,
        authtime: &KerberosTime,
        now: &KerberosTime,
        accounts: &dyn AccountSource,
    ) -> Result<(), Refusal> {
        let account = match accounts.client(crealm, cname) {
            Err(error) => return Err(account_source_refusal(error)),
            Ok(None) => {
                return Err(Refusal::new(
                    KDC_ERR_POLICY,
                    AuditReason::ArmorPrincipalUnknown,
                ))
            }
            Ok(Some(account)) => account,
        };
        if !account.may_armor() {
            return Err(Refusal::new(KDC_ERR_POLICY, AuditReason::ArmorNotComputer));
        }
        if !account.state.usable_at(now) || account.state.revokes(authtime) {
            return Err(Refusal::new(
                KDC_ERR_POLICY,
                AuditReason::ArmorPrincipalRevoked,
            ));
        }
        Ok(())
    }

    /// The common tail of both paths: the PDP (`armored` exactly when `armor`
    /// is set — keyd verified the armor, the armor principal passed and the
    /// encrypted challenge verified under it, docs/48 §4.2), the ticket
    /// times and flags, and keyd's `issue_as_rep` (armored when `armor` is
    /// set). The session-key type is the first acceptable one (3.1.3); the
    /// reply is sealed under the key that pre-authenticated (strengthened
    /// when armored, RFC 6113 5.4.3, 5.4.6). The TGS is named in its RFC 4120
    /// 7.3 form (NT-SRV-INST); the name-type is not significant (6.2).
    /// Spec: RFC 4120 3.1.3, 6.2, 7.3; docs/10 §4; docs/48 §4.1 A11-A13,
    /// §4.2; decisions 7, 9, 10.
    #[allow(clippy::too_many_arguments)]
    fn issue_tgt<S>(
        &mut self,
        body: &KdcReqBody,
        checked: &CheckedRequest<S>,
        proof: &AuthnProof,
        armor: Option<ArmorId>,
        peer: Peer,
        now: &KerberosTime,
        policy: &PolicyInputs<'_>,
    ) -> Result<AsRepParts, Refusal> {
        let account = &checked.account;
        let keyd_config = self.custody.config();
        let skew = keyd_config.clock_skew_secs;
        let ticket_policy = keyd_config.ticket_policy;

        // The PDP (docs/30 §2.4; decision 7; docs/48 §4.2).
        enforce(
            Question {
                action: Action::KdcAs,
                client: account,
                resource: Resource::Kerberos {
                    kind: KerbResKind::Tgt,
                },
                ticket_age: Duration::ZERO,
                src_net: peer.src_net,
                now,
                armored: armor.is_some(),
            },
            policy,
            &mut self.rate,
        )
        .map_err(|reason| Refusal::new(KDC_ERR_POLICY, reason))?;

        // Flags and times (decisions 9, 10).
        let requests = FlagRequests::of(body.kdc_options);
        let caps: Vec<i64> = account.state.expires.iter().map(seconds).collect();
        let planned = plan(
            now,
            &LifetimeRequest {
                from: body.from.as_ref(),
                till: &body.till,
                rtime: body.rtime.as_ref(),
                flags: requests,
            },
            &Limits {
                policy: ticket_policy,
                skew_secs: skew,
                end_caps: caps.clone(),
                renew_caps: caps,
                renewable_permitted: ticket_policy.allowed_flags.contains(TicketFlags::RENEWABLE),
            },
        )
        .map_err(time_refusal)?;
        let mut flags = delegation_flags(requests, ticket_policy.allowed_flags, None);
        if planned.renew_till.is_some() {
            flags.insert(TicketFlags::RENEWABLE);
        }

        // keyd issues (docs/10 §4; docs/48 §4.1 A13).
        let session_etype = checked
            .acceptable
            .first()
            .copied()
            .ok_or_else(|| internal(AuditReason::InternalFailure))?;
        let session_enctype = self
            .custody
            .config()
            .enctypes
            .iter()
            .copied()
            .find(|e| e.number() == session_etype)
            .ok_or_else(|| internal(AuditReason::InternalFailure))?;
        let cname = body
            .cname
            .clone()
            .ok_or_else(|| internal(AuditReason::InternalFailure))?;
        let template = AsTicketTemplate {
            client: account.key.principal,
            crealm: body.realm.clone(),
            cname,
            sname: local_tgs_name(&self.config.realm)?,
            starttime: None,
            endtime: planned.endtime,
            renew_till: planned.renew_till,
            flags,
            session_enctype,
            nonce: body.nonce,
        };
        let krbtgt = self.config.krbtgt;
        self.custody
            .issue_as_rep(&account.key, &krbtgt, proof, armor, &template, now)
            .map_err(issue_refusal)
    }

    /// A8a (module docs): what an armored AS for `kadmin/changepw` needs
    /// before pre-authentication — the client is a user account (docs/53
    /// R53-1: users only; a computer account, and so every service object,
    /// R47-13, is refused); the service object exists, its key set is the
    /// change-password service's (the one derivation,
    /// `KeyPurpose::of_service_name`, R2b) and it is usable; and a
    /// session-key type both the client offers and the service accepts.
    /// Every refusal here is armored (sealed by the caller).
    /// Spec: docs/53 R53-1, §5.2; RFC 4120 3.1.3 ("looks up the client and
    /// server principals"; "information from the Kerberos database
    /// indicating acceptable encryption methods for the application
    /// server"); decisions 3, 6, 8.
    fn change_password_target(
        &self,
        body: &KdcReqBody,
        account: &ClientAccount,
        armor: ArmorId,
        now: &KerberosTime,
        accounts: &dyn AccountSource,
    ) -> Result<ChangePasswordTarget, Refusal> {
        if account.kind != AccountKind::User {
            return Err(Refusal::new(
                KDC_ERR_POLICY,
                AuditReason::ChangePasswordNotUser,
            ));
        }
        let sname = body.sname.as_ref().ok_or(Refusal::new(
            KDC_ERR_S_PRINCIPAL_UNKNOWN,
            AuditReason::MissingName,
        ))?;
        let service = match accounts.service(&body.realm, sname) {
            Err(error) => return Err(account_source_refusal(error)),
            Ok(None) => {
                return Err(Refusal::new(
                    KDC_ERR_S_PRINCIPAL_UNKNOWN,
                    AuditReason::ServiceUnknown,
                ))
            }
            Ok(Some(service)) => service,
        };
        if service.key.purpose != KeyPurpose::ChangePasswordService
            || service.key.purpose != KeyPurpose::of_service_name(sname)
        {
            return Err(internal(AuditReason::AccountRecordInvalid));
        }
        if !service.state.usable_at(now) {
            return Err(Refusal::new(
                KDC_ERR_SERVICE_REVOKED,
                AuditReason::ServiceRevoked,
            ));
        }
        let configured = &self.custody.config().enctypes;
        let numbers: Vec<i32> = configured.iter().map(|e| e.number()).collect();
        let session_enctype = negotiate(&body.etype, &numbers, &service.enctypes)
            .first()
            .and_then(|etype| configured.iter().copied().find(|e| e.number() == *etype))
            .ok_or(Refusal::new(
                KDC_ERR_ETYPE_NOSUPP,
                AuditReason::NoCommonEncType,
            ))?;
        Ok(ChangePasswordTarget {
            armor,
            service,
            session_enctype,
        })
    }

    /// A11-A13 for `kadmin/changepw` (module docs): the PDP with `armored =
    /// true` — true by construction, the target holds this exchange's armor
    /// — on `KerbResKind::ChangePassword`; the ticket profile (docs/53 §5.2):
    /// it starts now, ends no later than the start plus
    /// [`CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS`] (and the accounts'
    /// expiry), is never renewable, forwardable or proxiable whatever the
    /// options ask — keyd adds INITIAL and PRE-AUTHENT itself (RFC 4120 2.1);
    /// then keyd's `issue_as_rep` under the armor with the service's key set
    /// as the server key and the requested sname, which the KDC never
    /// canonicalises ([MS-KILE] 3.3.5.1.2).
    /// Spec: docs/53 R53-6, §5.2; RFC 4120 2.1, 3.1.3 ("The flags field of
    /// the new ticket will have the following options set if they have been
    /// requested and if the policy of the local realm allows"; the server
    /// principal's maximum life); docs/48 §4.2; A-117.
    #[allow(clippy::too_many_arguments)]
    fn issue_change_password_ticket<S>(
        &mut self,
        body: &KdcReqBody,
        checked: &CheckedRequest<S>,
        proof: &AuthnProof,
        target: ChangePasswordTarget,
        peer: Peer,
        now: &KerberosTime,
        policy: &PolicyInputs<'_>,
    ) -> Result<AsRepParts, Refusal> {
        let account = &checked.account;
        let keyd_config = self.custody.config();
        let skew = keyd_config.clock_skew_secs;
        let ticket_policy = keyd_config.ticket_policy;

        // The PDP (docs/53 §5.2: `KdcAs` on this service, armored).
        enforce(
            Question {
                action: Action::KdcAs,
                client: account,
                resource: Resource::Kerberos {
                    kind: KerbResKind::ChangePassword,
                },
                ticket_age: Duration::ZERO,
                src_net: peer.src_net,
                now,
                armored: true,
            },
            policy,
            &mut self.rate,
        )
        .map_err(|reason| Refusal::new(KDC_ERR_POLICY, reason))?;

        // The profile: one more endtime cap, no renewal (docs/53 §5.2). The
        // cap is keyd-types' one definition, the value keyd enforces in
        // `issue_as_rep` (docs/questions/Q-915 item 2).
        let mut end_caps = vec![seconds(now) + i64::from(CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS)];
        end_caps.extend(
            account
                .state
                .expires
                .iter()
                .chain(target.service.state.expires.iter())
                .map(seconds),
        );
        let planned = plan(
            now,
            &LifetimeRequest {
                from: body.from.as_ref(),
                till: &body.till,
                rtime: body.rtime.as_ref(),
                flags: FlagRequests::of(body.kdc_options),
            },
            &Limits {
                policy: ticket_policy,
                skew_secs: skew,
                end_caps,
                renew_caps: Vec::new(),
                renewable_permitted: false,
            },
        )
        .map_err(time_refusal)?;

        // keyd issues under the armor (docs/53 §5.2; docs/48 §4.1 A13).
        let cname = body
            .cname
            .clone()
            .ok_or_else(|| internal(AuditReason::InternalFailure))?;
        let sname = body
            .sname
            .clone()
            .ok_or_else(|| internal(AuditReason::InternalFailure))?;
        let template = AsTicketTemplate {
            client: account.key.principal,
            crealm: body.realm.clone(),
            cname,
            sname,
            starttime: None,
            endtime: planned.endtime,
            renew_till: None,
            flags: TicketFlags::empty(),
            session_enctype: target.session_enctype,
            nonce: body.nonce,
        };
        self.custody
            .issue_as_rep(
                &account.key,
                &target.service.key,
                proof,
                Some(target.armor),
                &template,
                now,
            )
            .map_err(issue_refusal)
    }
}

/// Encode the AS-REP (RFC 4120 5.4.2): crealm / cname of the (inner) request
/// as requested, `padata` — `None` unarmored, `[PA-FX-FAST]` armored
/// (RFC 6113 5.4.3, 5.4.5).
/// Spec: RFC 4120 5.4.2; RFC 6113 5.4.3, 5.4.5.
fn encode_as_rep(
    padata: Option<Vec<PaData>>,
    crealm: &Realm,
    cname: PrincipalName,
    parts: AsRepParts,
) -> Result<Vec<u8>, Refusal> {
    AsRep(KdcRep {
        padata,
        crealm: crealm.clone(),
        cname,
        ticket: parts.ticket,
        enc_part: parts.enc_part,
    })
    .encode()
    .map_err(|_| internal(AuditReason::InternalFailure))
}
