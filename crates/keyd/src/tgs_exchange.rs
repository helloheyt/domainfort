//! The TGS exchange inside keyd: `open_and_verify_tgt` and `issue_tgs_rep`.
//! Role `Kdc` only.
//!
//! State machine: `open_and_verify_tgt ──(ctx_id)──► issue_tgs_rep`. The TGT
//! session key, the authenticator subkey and the new service session key
//! never leave keyd; the KDC receives only non-secret ticket facts and the
//! sealed reply parts (docs/10 §5, D33).
//!
//! Phase-1 scope: the presented ticket must be a TGT of this realm sealed
//! under the krbtgt key; the issued ticket is a service ticket of this realm.
//! RENEW / VALIDATE / PROXY / FORWARDED / ENC-TKT-IN-SKEY (user-to-user),
//! cross-realm referrals, S4U and PAC are not implemented. Authorization
//! data that keyd would have to carry or enforce (request
//! enc-authorization-data, authenticator authorization-data, a TGT with
//! authorization-data or addresses) is refused rather than silently dropped
//! — dropping a restriction would widen the ticket (RFC 4120 5.3).
//!
//! The TGT-opening steps (local TGT, binding, decryption, validity findings,
//! authenticator) and the end of the chain (findings, replay cache) are
//! shared helpers — `OpenedApReq`, `open_local_tgt`, `complete_chain` — that
//! the FAST armor (`open_fast_armor`, docs/48 §3.2) reuses with its own
//! authenticator key usage. The decryption, validity and authenticator steps
//! alone (`open_ap_req`) also open a service AP-REQ under a service key
//! (`open_and_verify_service_ticket`, crate::service_ticket; docs/49 §3.3).
//!
//! **TGS under FAST** (docs/48 §5, task T3): implicit armor only. With a
//! [`TgsFastRequest`], `open_and_verify_tgt` derives the armor key from the
//! PA-TGS-REQ authenticator's subkey (mandatory) and the TGT session key —
//! "the same armor key that would be computed if the TGS-REQ authenticator
//! was used in an FX_FAST_ARMOR_AP_REQUEST armor" (RFC 6113 5.4.2) —
//! verifies the req-checksum over the PA-TGS-REQ AP-REQ, decrypts the
//! KrbFastReq and keeps the armor key and the INNER request's nonce and sname
//! in the context. `issue_tgs_rep` on such a context strengthens the reply
//! key (mandatory in a TGS reply), seals EncTGSRepPart under it and returns
//! the sealed KrbFastResponse (`fast_rep`); `seal_fast_error(Tgs(ctx))`
//! (crate::fast_armor) seals an armored error instead. An explicit armor
//! field in a TGS request is refused (RFC 6113 5.4.1.1 "only valid for AS
//! requests"; docs/questions/Q-124). The armor key, the strengthen key and the
//! reply key never leave keyd (docs/48 §2.2, A-33).
//!
//! Spec: RFC 4120 3.2.3, 3.3.2, 3.3.3, 5.2.7.1, 5.4.1, 5.4.2, 5.5.1, 7.3,
//! 7.5.1; RFC 6113 5.1, 5.4.1.1, 5.4.2, 5.4.3, 6.2, 8; docs/10 §5, §8, D33;
//! docs/30 §3, §7; docs/48 §3.2, §5; docs/questions/Q-121, Q-122, Q-124
//! (A-32), Q-150.

use crate::as_exchange::token_deny;
use crate::audit::{AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::entropy::EntropySource;
use crate::error::{AuthnError, Deny, Internal, IssueError};
use crate::fast_armor::{
    open_armored_request, seal_fast_reply, seal_strengthened, ticket_armor_key, ArmoredConversation,
};
use crate::keyd::{authorize, draw, key_usage, new_random_key, open, seal, AuditFields, Keyd};
use crate::model::KeyHandle;
use crate::replay::{ReplayKey, ReplayRefusal};
use crate::store::{KeyStore, KvnoKeys};
use crate::template::{
    check_binding, check_times, is_tgs_name, tgs_name, tgs_ticket_flags, TemplateTimes,
};
use crate::time::{kerberos_time_seconds, within_skew};
use crate::tokens::{CtxId, TOKEN_ID_LENGTH};
use crate::usage::{
    TGS_REP_ENC_PART_SESSION_KEY, TGS_REP_ENC_PART_SUBKEY, TGS_REQ_AUTHENTICATOR,
    TGS_REQ_AUTHENTICATOR_CKSUM, TICKET_ENC_PART,
};
use krb_crypto::{ChecksumType, EncType, ProtocolKey};
use krb_proto::{
    ApOptions, ApReq, Authenticator, EncKdcRepPart, EncTgsRepPart, EncTicketPart, EncryptedData,
    EncryptionKey, KdcReqBody, KerberosTime, KeyValue, KrbFastArmoredReq, KrbFastReq, LastReq,
    PrincipalName, Realm, Ticket, TicketFlags, TransitedEncoding,
};
use zeroize::Zeroizing;

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

/// What keyd keeps about a live TGS context (never leaves keyd). The reply
/// key and the armor key are zeroized when the entry is consumed or expires.
/// Under FAST, `req_nonce` / `req_sname` are the INNER request's (docs/48
/// §3.4).
pub(crate) struct ContextEntry {
    crealm: Realm,
    cname: PrincipalName,
    authtime: KerberosTime,
    endtime: KerberosTime,
    renew_till: Option<KerberosTime>,
    flags: TicketFlags,
    transited: TransitedEncoding,
    reply_key: ProtocolKey,
    reply_usage: u32,
    req_nonce: u32,
    req_sname: Option<PrincipalName>,
    /// The implicit armor key of an armored request; `None` without FAST.
    /// Spec: RFC 6113 5.4.2; docs/48 §5.2 step 6.
    armor_key: Option<ProtocolKey>,
}

impl ContextEntry {
    /// The conversation `seal_fast_error(Tgs)` answers, or `None` for a
    /// context opened without FAST (it has no armor key). The KRB-ERROR's
    /// realm is the inner request's — which `open_and_verify_tgt` verified is
    /// `realm`, this realm — its sname the inner sname (or this realm's TGS
    /// name when it had none, the KDC's KRB-ERROR rule), and its crealm /
    /// cname, when present, the TGT's client, as the KDC names it in a TGS
    /// error.
    /// Spec: docs/48 §2.3, §5, §6.1; RFC 4120 5.9.1; RFC 6113 5.4.3 (nonce),
    /// 5.4.4; docs/questions/Q-150.
    pub(crate) fn into_fast_conversation(self, realm: &Realm) -> Option<ArmoredConversation> {
        let armor_key = self.armor_key?;
        Some(ArmoredConversation {
            armor_key,
            nonce: self.req_nonce,
            realm: realm.clone(),
            sname: self.req_sname.unwrap_or_else(|| tgs_name(realm)),
            crealm: self.crealm,
            cname: Some(self.cname),
        })
    }
}

/// The KDC's request for a service ticket. keyd copies the client name,
/// realm, authtime and transited field from the verified TGT (RFC 4120
/// 3.3.3: by default these fields of the new ticket come from the TGT) and
/// fills in the session key itself.
///
/// Spec: docs/10 §5 (`tgs_template: TicketTemplate`); RFC 4120 3.3.3, 5.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TgsTicketTemplate {
    /// Service name; must equal the sname of the authenticated KDC-REQ-BODY
    /// and must not be a TGS name.
    pub sname: PrincipalName,
    /// Requested starttime; within the clock skew of now (no postdating).
    pub starttime: Option<KerberosTime>,
    /// Expiration time; not after the TGT's endtime (RFC 4120 3.3.3).
    pub endtime: KerberosTime,
    /// Renew-till; exactly when RENEWABLE; not after the TGT's renew-till.
    pub renew_till: Option<KerberosTime>,
    /// Requested flags (allowed mask; RFC 4120 2.1 / 5.4.1 TGT rules).
    pub flags: TicketFlags,
    /// Session-key encryption type; must be configured (I5).
    pub session_enctype: EncType,
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

/// A configured encryption type from a wire number, else `deny`.
fn configured_enctype(number: i32, supported: &[EncType], deny: Deny) -> Internal<EncType> {
    EncType::from_number(number)
        .ok()
        .filter(|e| supported.contains(e))
        .ok_or(deny)
}

/// The time findings of an opened TGT and authenticator, recorded during the
/// cryptographic chain and reported only once it completed (A-26).
/// Spec: RFC 4120 3.2.3; docs/questions/Q-071 (A-26).
pub(crate) struct TimeFindings {
    /// The authenticator's ctime is outside the clock skew.
    skew: Option<Deny>,
    /// The ticket is not yet valid, or has expired.
    ticket_time: Option<Deny>,
}

/// What opening an AP-REQ — its ticket and its authenticator — yields;
/// shared by `open_and_verify_tgt` (PA-TGS-REQ), `open_fast_armor` (the
/// armor AP-REQ) and `open_and_verify_service_ticket` (a service AP-REQ).
/// The session key and the decrypted structures never leave keyd; the
/// ticket session key and an authenticator subkey are zeroized when dropped
/// (krb-crypto `ProtocolKey`, krb-proto `KeyValue`).
/// Spec: RFC 4120 3.2.3; docs/48 §3.2; docs/49 §3.3.
pub(crate) struct OpenedApReq {
    /// The decrypted EncTicketPart.
    pub(crate) ticket_part: EncTicketPart,
    /// The ticket session key.
    pub(crate) session: ProtocolKey,
    /// The decrypted Authenticator.
    pub(crate) authenticator: Authenticator,
    /// The authenticator's ctime in seconds (keyd's time scale).
    pub(crate) ctime: i64,
    /// Findings to report after the caller completes its chain.
    pub(crate) findings: TimeFindings,
}

/// Step 2 of opening an AP-REQ: USE-SESSION-KEY (user-to-user) has no code
/// path. Spec: RFC 4120 5.5.1, 3.7; docs/48 §3.2 (same for the armor).
pub(crate) fn check_ap_options(ap_req: &ApReq) -> Internal<()> {
    if ap_req.ap_options.contains(ApOptions::USE_SESSION_KEY) {
        return Err(Deny::denied(AuditReason::UnsupportedApOption));
    }
    Ok(())
}

/// An authenticator subkey as a protocol key: a configured enctype (I5) and a
/// valid key of it. Spec: RFC 4120 5.5.1 (subkey); RFC 3961 §3
/// (random-to-key); docs/10 §12 I5.
pub(crate) fn subkey_protocol_key(
    subkey: &EncryptionKey,
    supported: &[EncType],
) -> Internal<ProtocolKey> {
    let enctype = configured_enctype(
        subkey.keytype,
        supported,
        Deny::denied(AuditReason::UnsupportedEncType),
    )?;
    krb_crypto::random_to_key(enctype, subkey.keyvalue.as_bytes())
        .map_err(|_| Deny::denied(AuditReason::MalformedInput))
}

/// The replay-cache key of an authenticator presented with `ticket`: server
/// name, client name, time and microseconds. Spec: RFC 4120 3.2.3.
pub(crate) fn replay_key_for(
    ticket: &Ticket,
    authenticator: &Authenticator,
    ctime: i64,
) -> ReplayKey {
    ReplayKey {
        server_realm: ticket.realm.clone(),
        server: ticket.sname.clone(),
        client_realm: authenticator.crealm.clone(),
        client: authenticator.cname.clone(),
        ctime,
        cusec: authenticator.cusec.get(),
    }
}

/// Decrypt a ticket enc-part under the server's key versions: the version
/// named by the ticket's kvno, or — with no kvno — current then previous.
/// Spec: RFC 4120 3.2.3 ("decrypted using the version of the server's key
/// specified by the ticket"); docs/10 §1 ("decrypt may try a set of kvnos");
/// [MS-KILE] 3.4.5 (retry with older versions of the server key).
fn open_ticket<'a>(
    versions: [Option<&'a KvnoKeys>; 2],
    enc_part: &EncryptedData,
    enctype: EncType,
) -> Internal<(Zeroizing<Vec<u8>>, &'a KvnoKeys)> {
    let mut reason = AuditReason::KvnoMismatch;
    for version in versions.into_iter().flatten() {
        if enc_part.kvno.is_some_and(|k| k != version.kvno().get()) {
            continue;
        }
        let Some(key) = version.key_for(enctype) else {
            continue;
        };
        match open(key, TICKET_ENC_PART, &enc_part.cipher) {
            Ok(plaintext) => return Ok((plaintext, version)),
            Err(deny) => reason = deny.reason,
        }
    }
    Err(Deny::denied(reason))
}

/// Step 3 of `open_and_verify_tgt`, FAST part — the shape of the FAST part,
/// before any key is used (uniform `Denied`, A-26):
/// - no explicit armor: "This armor type is only valid for AS requests;
///   implicit armor ... is the only supported way to establish an armor key
///   for the TGS" (RFC 6113 5.4.1.1; 5.4.2 "the client SHOULD NOT include
///   the armor field"; refused per docs/questions/Q-124 item 2);
/// - `ap_req_octets` decode as an AP-REQ equal to `ap_req`, the one keyd
///   opens — so the req-checksum covers exactly the authenticated AP-REQ.
///
/// Spec: RFC 6113 5.4.1.1, 5.4.2; RFC 4120 5.2.7.1; docs/48 §5.2, §5.3;
/// docs/questions/Q-124 (A-32).
fn check_fast_shape(fast: &TgsFastRequest<'_>, ap_req: &ApReq) -> Internal<()> {
    if fast.armored_req.armor.is_some() {
        return Err(Deny::denied(AuditReason::TgsExplicitArmor));
    }
    let decoded =
        ApReq::decode(fast.ap_req_octets).map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
    if decoded != *ap_req {
        return Err(Deny::denied(AuditReason::FastApReqMismatch));
    }
    Ok(())
}

/// Step 10 of `open_and_verify_tgt` (FAST only) — the implicit armor and the
/// inner request:
/// 1. armor key = KRB-FX-CF2(subkey, TGT session key, "subkeyarmor",
///    "ticketarmor"), of the subkey's enctype (RFC 6113 5.4.2: "the same
///    armor key that would be computed if the TGS-REQ authenticator was used
///    in an FX_FAST_ARMOR_AP_REQUEST armor"; 5.4.1.1; 5.1);
/// 2. the req-checksum (armor key, its required checksum type, usage 50)
///    verifies over the AP-REQ octets — "for a TGS-REQ, it is performed over
///    the type AP-REQ in the PA-TGS-REQ padata" (RFC 6113 5.4.2);
/// 3. enc-fast-req decrypts under the armor key (usage 51) and decodes as
///    KrbFastReq; the inner req-body is for this realm and carries no
///    enc-authorization-data (as the outer body, step 3; docs/48 §5.2
///    step 5).
///
/// Every failure is the uniform `Denied` (A-26: the chain is not complete).
///
/// Spec: RFC 6113 5.1, 5.4.1.1, 5.4.2, 6.2, 8 (the armor key "tied to the
/// authentication of the client to the KDC" through the sub-session key);
/// RFC 4120 5.4.1; docs/48 §5.1, §5.2.
fn open_implicit_armor(
    fast: &TgsFastRequest<'_>,
    subkey: &ProtocolKey,
    session: &ProtocolKey,
    realm: &Realm,
) -> Internal<(ProtocolKey, KrbFastReq)> {
    let armor_key = ticket_armor_key(subkey, session)?;
    let fast_req = open_armored_request(&armor_key, fast.armored_req, fast.ap_req_octets)?;
    let inner = &fast_req.req_body;
    if inner.realm != *realm {
        return Err(Deny::denied(AuditReason::WrongRealm));
    }
    if inner.enc_authorization_data.is_some() {
        return Err(Deny::denied(AuditReason::UnsupportedContent));
    }
    Ok((armor_key, fast_req))
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// `open_and_verify_tgt`: open the TGT and the PA-TGS-REQ authenticator
    /// inside keyd — and, for an armored request, its implicit FAST armor and
    /// KrbFastReq — and return a one-time [`TgtContext`].
    ///
    /// `ap_req` is the AP-REQ from the PA-TGS-REQ padata; `req_body` is the
    /// raw DER of the request's (outer) KDC-REQ-BODY, over which the
    /// authenticator checksum is verified; `fast` is the FAST part of an
    /// armored request (`None` without PA-FX-FAST).
    ///
    /// Checks failing as the uniform `AuthnError::Denied` (reason to audit
    /// only):
    /// 1. authorize (Kdc; krbtgt handle Krbtgt);
    /// 2. no USE-SESSION-KEY ap-option (user-to-user not implemented);
    /// 3. `req_body` decodes as KDC-REQ-BODY for this realm, without
    ///    enc-authorization-data; FAST only: no explicit armor field (Q-124),
    ///    and the AP-REQ octets decode to exactly `ap_req`
    ///    ([`TgsFastRequest`]);
    /// 4. the ticket is this realm's TGT (realm, sname krbtgt/realm), and the
    ///    krbtgt key set is bound to krbtgt/realm (Q-040, A-19);
    /// 5. decrypt the ticket under krbtgt (kvno-selected, else current then
    ///    previous), usage 2; decode EncTicketPart;
    /// 6. client realm is this realm; no INVALID flag; no authorization-data
    ///    or addresses in the TGT; the ticket times are RECORDED, not yet
    ///    reported;
    /// 7. decrypt the authenticator with the ticket session key, usage 7;
    ///    decode it; crealm / cname match the ticket; no authorization-data;
    ///    the ctime skew is RECORDED, not yet reported;
    /// 8. the checksum is present, of the session key's checksum type, and
    ///    verifies over `req_body` with usage 6 — binding the authenticator
    ///    to this request (no cut-and-paste). Under FAST too it covers the
    ///    OUTER body (A-17 unchanged, docs/questions/Q-124 item 1); the inner
    ///    body is bound by the armor key instead (RFC 6113 8);
    /// 9. a subkey is a configured enctype and a valid key; without FAST it
    ///    is optional, with FAST it is mandatory (RFC 6113 5.4.2: "a subkey
    ///    MUST be included in the PA-TGS-REQ authenticator");
    /// 10. FAST only: the implicit armor key, the req-checksum over the
    ///     AP-REQ octets (usage 50) and the KrbFastReq (usage 51), whose inner
    ///     body is for this realm without enc-authorization-data
    ///     ([`open_implicit_armor`]).
    ///
    /// Only now — the TGT decrypted, the authenticator decrypted, the
    /// req-body checksum verified and, under FAST, the req-checksum verified
    /// and the KrbFastReq decrypted and decoded — are the recorded findings
    /// reported, as non-secret classes (A-26, docs/48 §6.3), in RFC 4120
    /// 3.2.3 order: ctime skew → `Skew`; starttime in the future (beyond
    /// skew) → `TicketNotYetValid`; endtime past (beyond skew) →
    /// `TicketExpired`. A request refused for these never enters the replay
    /// cache. Then:
    /// 11. the replay cache accepts (server, client, ctime, cusec), else
    ///     `Replay` (a full cache stays `Denied`, fail closed);
    /// 12. store the reply key (subkey with usage 9, else session key with
    ///     usage 8) in a new context bound to this caller — under FAST also
    ///     the armor key, and the INNER request's nonce and sname (docs/48
    ///     §3.4); `TgtContext::fast_req` returns the KrbFastReq.
    ///
    /// Any cryptographic failure is `Denied` even when the ticket is also
    /// expired or the authenticator also skewed: classes are reachable only
    /// by a holder of the TGT session key (and, under FAST, the armor key),
    /// so they are no decryption or MAC oracle (A-26).
    ///
    /// Spec: RFC 4120 3.2.3, 3.3.2, 5.2.7.1 ("checksum ... computed over the
    /// KDC-REQ-BODY encoding"), 5.4.1 (req-body), 5.5.1 (cksum usage 6,
    /// authenticator usage 7), 7.3, 7.5.1; RFC 6113 5.1, 5.4.1.1, 5.4.2, 6.2,
    /// 8; docs/10 §5, D33; docs/48 §2.3, §5, §6.3; A-26
    /// (docs/questions/Q-071); docs/questions/Q-124 (A-32).
    pub fn open_and_verify_tgt(
        &mut self,
        caller: &CallerId,
        krbtgt: &KeyHandle,
        ap_req: &ApReq,
        req_body: &[u8],
        fast: Option<TgsFastRequest<'_>>,
        now: &KerberosTime,
    ) -> Result<TgtContext, AuthnError> {
        let mut fields = AuditFields::for_handle(krbtgt);
        let result = self.open_and_verify_tgt_inner(
            caller,
            krbtgt,
            ap_req,
            req_body,
            fast,
            now,
            &mut fields,
        );
        self.emit(caller, Operation::OpenAndVerifyTgt, now, &fields, &result);
        result.map_err(AuthnError::from)
    }

    #[allow(clippy::too_many_arguments)]
    fn open_and_verify_tgt_inner(
        &mut self,
        caller: &CallerId,
        krbtgt: &KeyHandle,
        ap_req: &ApReq,
        req_body: &[u8],
        fast: Option<TgsFastRequest<'_>>,
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<TgtContext> {
        authorize(
            caller,
            Operation::OpenAndVerifyTgt,
            &[(HandleSlot::Primary, krbtgt)],
        )?;
        let now_s = kerberos_time_seconds(now);

        // 2. AP options.
        check_ap_options(ap_req)?;

        // 3. The request body (structure only; its checksum is step 8).
        let body =
            KdcReqBody::decode(req_body).map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        if body.realm != self.config.realm {
            return Err(Deny::denied(AuditReason::WrongRealm));
        }
        if body.enc_authorization_data.is_some() {
            return Err(Deny::denied(AuditReason::UnsupportedContent));
        }

        // 3 (FAST part). Its shape, before any key is used.
        if let Some(fast) = &fast {
            check_fast_shape(fast, ap_req)?;
        }

        // 4-7. The TGT and the authenticator, usage 7 (shared with
        // open_fast_armor).
        let OpenedApReq {
            ticket_part,
            session,
            authenticator,
            ctime,
            findings,
        } = self.open_local_tgt(krbtgt, ap_req, TGS_REQ_AUTHENTICATOR, now_s, fields)?;

        // 8. The checksum over the raw KDC-REQ-BODY.
        let cksum = authenticator
            .cksum
            .as_ref()
            .ok_or(Deny::denied(AuditReason::ChecksumMissing))?;
        let cksumtype = ChecksumType::from_number(cksum.cksumtype)
            .ok()
            .filter(|t| *t == session.enc_type().checksum_type())
            .ok_or(Deny::denied(AuditReason::ChecksumUnsupported))?;
        krb_crypto::verify_mic(
            &session,
            cksumtype,
            key_usage(TGS_REQ_AUTHENTICATOR_CKSUM)?,
            req_body,
            &cksum.checksum,
        )
        .map_err(|_| Deny::denied(AuditReason::ChecksumMismatch))?;

        // 9. The subkey: a configured enctype and a valid key (I5); optional
        // without FAST, mandatory with it. Spec: RFC 4120 5.5.1; RFC 6113
        // 5.4.2.
        let subkey = authenticator
            .subkey
            .as_ref()
            .map(|subkey| subkey_protocol_key(subkey, &self.config.enctypes))
            .transpose()?;

        // 10. FAST: the implicit armor key, the req-checksum over the AP-REQ
        // octets, the KrbFastReq and its inner body.
        let armored = match (&fast, &subkey) {
            (None, _) => None,
            (Some(_), None) => return Err(Deny::denied(AuditReason::ArmorSubkeyMissing)),
            (Some(fast), Some(subkey)) => Some(open_implicit_armor(
                fast,
                subkey,
                &session,
                &self.config.realm,
            )?),
        };

        // 12 (prepared before the findings and the replay insert, so that
        // every check that can fail precedes them). The reply key: subkey
        // (usage 9) or session key (usage 8) — under FAST always the subkey,
        // the padata reply key that issue_tgs_rep strengthens (RFC 6113
        // 5.4.3; docs/questions/Q-121). Spec: RFC 4120 3.3.3, 5.4.2.
        let (reply_key, reply_usage) = match subkey {
            Some(subkey) => {
                drop(session);
                (subkey, TGS_REP_ENC_PART_SUBKEY)
            }
            None => (session, TGS_REP_ENC_PART_SESSION_KEY),
        };

        // The cryptographic chain is complete: the TGT decrypted, the
        // authenticator decrypted and its req-body checksum verified, and —
        // under FAST — the req-checksum verified and the KrbFastReq decrypted
        // and decoded. Only now are the recorded findings reported, then the
        // replay cache (step 11) consulted (A-26; docs/48 §6.3).
        self.complete_chain(
            findings,
            replay_key_for(&ap_req.ticket, &authenticator, ctime),
            now_s,
        )?;

        // 12. The one-time context. Under FAST the nonce and sname are the
        // inner request's (docs/48 §3.4; RFC 6113 5.4.2 "This req-body field
        // is preferred over the outer field").
        let (armor_key, fast_req) = match armored {
            Some((armor_key, fast_req)) => (Some(armor_key), Some(fast_req)),
            None => (None, None),
        };
        let (req_nonce, req_sname) = match &fast_req {
            Some(fast_req) => (fast_req.req_body.nonce, fast_req.req_body.sname.clone()),
            None => (body.nonce, body.sname),
        };
        let mut id = [0u8; TOKEN_ID_LENGTH];
        draw(&mut self.entropy, &mut id)?;
        let context = TgtContext {
            ctx_id: CtxId::from_bytes(id),
            crealm: ticket_part.crealm.clone(),
            cname: ticket_part.cname.clone(),
            authtime: ticket_part.authtime,
            starttime: ticket_part.starttime,
            endtime: ticket_part.endtime,
            renew_till: ticket_part.renew_till,
            flags: ticket_part.flags,
            fast_req,
        };
        let entry = ContextEntry {
            crealm: ticket_part.crealm.clone(),
            cname: ticket_part.cname.clone(),
            authtime: ticket_part.authtime,
            endtime: ticket_part.endtime,
            renew_till: ticket_part.renew_till,
            flags: ticket_part.flags,
            transited: ticket_part.transited.clone(),
            reply_key,
            reply_usage,
            req_nonce,
            req_sname,
            armor_key,
        };
        let expires_at = now_s + i64::from(self.config.token_lifetime_secs);
        if !self.contexts.insert(id, *caller, expires_at, entry, now_s) {
            return Err(Deny::unavailable(AuditReason::TokenTableFull));
        }
        Ok(context)
    }

    /// Steps 4-7 of opening an AP-REQ whose ticket must be this realm's TGT,
    /// shared by `open_and_verify_tgt` (PA-TGS-REQ, `authenticator_usage`
    /// 7) and `open_fast_armor` (armor AP-REQ, usage 11):
    /// 4. the ticket is this realm's TGT (realm, sname krbtgt/realm), and the
    ///    krbtgt key set is bound to krbtgt/realm (Q-040, A-19) — RFC 6113
    ///    5.4.1.1 "The server name field of the armor ticket MUST identify
    ///    the TGS of the target realm";
    /// 5. decrypt the ticket under krbtgt (kvno-selected, else current then
    ///    previous), usage 2; decode EncTicketPart; the kvno goes to audit;
    /// 6. client realm is this realm; no INVALID flag; no authorization-data
    ///    or addresses; the ticket times are RECORDED, not yet reported;
    /// 7. decrypt the authenticator with the ticket session key under
    ///    `authenticator_usage`; decode it; crealm / cname match the ticket;
    ///    no authorization-data; the ctime skew is RECORDED.
    ///
    /// Every failure here is the uniform `Denied`; the findings are reported
    /// by [`Self::complete_chain`] once the caller's chain completed (A-26).
    /// Steps 5-7 are [`Self::open_ap_req`], shared with
    /// `open_and_verify_service_ticket`.
    ///
    /// Spec: RFC 4120 3.2.3, 3.3.2, 5.5.1, 7.3, 7.5.1; RFC 6113 5.4.1.1;
    /// docs/48 §3.2; A-26 (docs/questions/Q-071).
    pub(crate) fn open_local_tgt(
        &self,
        krbtgt: &KeyHandle,
        ap_req: &ApReq,
        authenticator_usage: u32,
        now_s: i64,
        fields: &mut AuditFields,
    ) -> Internal<OpenedApReq> {
        let realm = &self.config.realm;

        // 4. A TGT of this realm.
        let tgt = &ap_req.ticket;
        if tgt.realm != *realm || tgt.sname != tgs_name(realm) {
            return Err(Deny::denied(AuditReason::NotLocalTgt));
        }
        let set = self
            .store
            .get(krbtgt)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
        // Name binding (Q-040, A-19): the krbtgt key must be bound to this
        // realm's TGS name (RFC 4120 7.3).
        check_binding(set.binding(), realm, &tgs_name(realm))?;

        // 5-7. Decrypt under krbtgt, then the ticket and the authenticator.
        self.open_ap_req(
            [Some(set.current()), set.previous()],
            ap_req,
            authenticator_usage,
            now_s,
            fields,
        )
    }

    /// Steps 5-7 of opening an AP-REQ under the server key `versions` (the
    /// caller has already checked whose ticket it is and resolved the key
    /// set — `open_local_tgt`: a TGT under krbtgt; `open_and_verify_service_
    /// ticket`: a service ticket under the service key bound to its sname):
    /// 5. the ticket enctype is configured; decrypt the ticket enc-part with
    ///    usage 2 under the version its kvno names (no kvno: current, then
    ///    previous); decode EncTicketPart; the kvno goes to audit;
    /// 6. client realm is this realm; no INVALID flag; no authorization-data
    ///    or addresses; the ticket times are RECORDED, not yet reported;
    /// 7. decrypt the authenticator with the ticket session key under
    ///    `authenticator_usage`; decode it; crealm / cname match the ticket;
    ///    no authorization-data; the ctime skew is RECORDED.
    ///
    /// Every failure here is the uniform `Denied`; the findings are reported
    /// by [`Self::complete_chain`] once the caller's chain completed (A-26).
    ///
    /// Spec: RFC 4120 2.2 ("Application servers MUST reject tickets that have
    /// this flag set"), 3.2.3, 5.3, 5.5.1, 7.5.1; A-26
    /// (docs/questions/Q-071).
    pub(crate) fn open_ap_req(
        &self,
        versions: [Option<&KvnoKeys>; 2],
        ap_req: &ApReq,
        authenticator_usage: u32,
        now_s: i64,
        fields: &mut AuditFields,
    ) -> Internal<OpenedApReq> {
        let skew = self.config.clock_skew_secs;
        let realm = &self.config.realm;
        let ticket = &ap_req.ticket;

        // 5. Decrypt under the server key.
        let ticket_enctype = configured_enctype(
            ticket.enc_part.etype,
            &self.config.enctypes,
            Deny::denied(AuditReason::UnsupportedEncType),
        )?;
        let (ticket_plain, version) = open_ticket(versions, &ticket.enc_part, ticket_enctype)?;
        fields.kvno = Some(version.kvno());
        let ticket_part = EncTicketPart::decode(&ticket_plain)
            .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        drop(ticket_plain);

        // 6. Ticket validity. The time findings are recorded and reported only
        // after the whole cryptographic chain has passed (A-26).
        if ticket_part.crealm != *realm {
            return Err(Deny::denied(AuditReason::WrongRealm));
        }
        if ticket_part.flags.contains(TicketFlags::INVALID) {
            return Err(Deny::denied(AuditReason::TicketInvalidFlag));
        }
        let start = kerberos_time_seconds(
            ticket_part
                .starttime
                .as_ref()
                .unwrap_or(&ticket_part.authtime),
        );
        let ticket_time_finding = if start > now_s + i64::from(skew) {
            Some(Deny::classified(
                AuditReason::TicketNotYetValid,
                AuthnError::TicketNotYetValid,
            ))
        } else if now_s > kerberos_time_seconds(&ticket_part.endtime) + i64::from(skew) {
            Some(Deny::classified(
                AuditReason::TicketExpired,
                AuthnError::TicketExpired,
            ))
        } else {
            None
        };
        if ticket_part.authorization_data.is_some() || ticket_part.caddr.is_some() {
            return Err(Deny::denied(AuditReason::UnsupportedContent));
        }
        let session_enctype = configured_enctype(
            ticket_part.key.keytype,
            &self.config.enctypes,
            Deny::denied(AuditReason::UnsupportedEncType),
        )?;
        let session =
            krb_crypto::random_to_key(session_enctype, ticket_part.key.keyvalue.as_bytes())
                .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;

        // 7. The authenticator.
        if ap_req.authenticator.etype != session_enctype.number() {
            return Err(Deny::denied(AuditReason::UnsupportedEncType));
        }
        let authenticator_plain: Zeroizing<Vec<u8>> =
            open(&session, authenticator_usage, &ap_req.authenticator.cipher)?;
        let authenticator = Authenticator::decode(&authenticator_plain)
            .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        drop(authenticator_plain);
        if authenticator.crealm != ticket_part.crealm || authenticator.cname != ticket_part.cname {
            return Err(Deny::denied(AuditReason::NameMismatch));
        }
        let ctime = kerberos_time_seconds(&authenticator.ctime);
        // Recorded; reported only after the caller's chain completed (A-26).
        let skew_finding = (!within_skew(ctime, now_s, skew))
            .then_some(Deny::classified(AuditReason::ClockSkew, AuthnError::Skew));
        if authenticator.authorization_data.is_some() {
            return Err(Deny::denied(AuditReason::UnsupportedContent));
        }
        Ok(OpenedApReq {
            ticket_part,
            session,
            authenticator,
            ctime,
            findings: TimeFindings {
                skew: skew_finding,
                ticket_time: ticket_time_finding,
            },
        })
    }

    /// The end of an AP-REQ chain, shared by `open_and_verify_tgt`,
    /// `open_fast_armor` and `open_and_verify_service_ticket` (one replay
    /// cache for every server name keyd verifies for — RFC 4120 3.2.3 "they
    /// MUST share this replay cache"). Call ONLY once every cryptographic
    /// check of the
    /// caller's chain has passed: the recorded findings are reported as
    /// non-secret classes in RFC 4120 3.2.3 order (skew, then the ticket's
    /// age) — before the replay cache, so a refused request never enters it —
    /// then the replay cache must accept `replay_key` (a replay is the
    /// `Replay` class; a full cache stays the uniform `Denied`, fail closed).
    ///
    /// Spec: RFC 4120 3.2.3; docs/10 D33; A-26 (docs/questions/Q-071).
    pub(crate) fn complete_chain(
        &mut self,
        findings: TimeFindings,
        replay_key: ReplayKey,
        now_s: i64,
    ) -> Internal<()> {
        if let Some(finding) = findings.skew.or(findings.ticket_time) {
            return Err(finding);
        }
        // 10. Replay cache (D33).
        self.replay
            .check_and_insert(replay_key, self.config.clock_skew_secs, now_s)
            .map_err(|refusal| match refusal {
                ReplayRefusal::Replay => Deny::classified(AuditReason::Replay, AuthnError::Replay),
                ReplayRefusal::Full => Deny::denied(AuditReason::ReplayCacheFull),
            })
    }

    /// `issue_tgs_rep`: consume `ctx` and issue a service ticket — armored
    /// when the context was opened with FAST.
    ///
    /// 1. authorize (Kdc; service handle Service);
    /// 2. the context: live and issued to this caller (`Denied` otherwise;
    ///    destroyed either way). A context opened without FAST is consumed
    ///    now, whatever follows (unchanged). An ARMORED context is consumed
    ///    only by a successful issuance: a refusal at step 3 leaves it live so
    ///    that the KDC can seal the armored error with
    ///    `seal_fast_error(Tgs(ctx))` — the rule A-42 set for the AS armor
    ///    (docs/questions/Q-145 item 3), applied to the TGS conversation
    ///    (docs/questions/Q-150);
    /// 3. armored: template.sname and template.nonce are the INNER request's
    ///    stored ones (`Denied`, docs/48 §3.4, §9.2 item 7); then, for every
    ///    context, validate the template (`BadTemplate`): sname equals the
    ///    authenticated request's sname and is not a TGS name; nonce equals
    ///    the request nonce; enctype configured; flags (mask, RFC 4120 2.1 /
    ///    5.4.1 TGT rules); times within policy, endtime and renew-till not
    ///    beyond the TGT's (RFC 4120 3.3.3); the service key set's name
    ///    binding must identify template.sname in this realm (`Denied`, Q-040
    ///    A-19);
    /// 4. draw a fresh session key;
    /// 5. EncTicketPart — client name, realm, authtime, transited carried
    ///    over from the TGT — sealed under the CURRENT service key, usage 2;
    /// 6. EncTGSRepPart, without kvno, sealed under the context's reply key,
    ///    usage 8 (session key) or 9 (subkey) — or, armored, under the reply
    ///    key strengthened from the subkey with a fresh strengthen key, usage
    ///    9 ("it MUST be set in a TGS reply", RFC 6113 5.4.3; usage per
    ///    docs/questions/Q-121 (a)), with the KrbFastResponse { padata: [],
    ///    strengthen-key, KrbFastFinished (ticket-checksum over the ticket DER
    ///    under the armor key, usage 53 — Q-122 (a)), the stored inner nonce }
    ///    sealed in the armor key, usage 52, as `fast_rep`.
    ///
    /// The session key, the strengthen key, the reply key and the armor key
    /// never leave keyd (docs/48 §2.2, §9.1 I1).
    ///
    /// Spec: docs/10 §5 (issue_tgs_rep), §8; docs/48 §2.3, §3.4, §5.2; RFC
    /// 4120 3.3.3, 5.3, 5.4.2, 7.5.1 (usages 2, 8, 9); RFC 6113 5.4.3, 6.2;
    /// docs/questions/Q-121, Q-122 (A-32), Q-150.
    pub fn issue_tgs_rep(
        &mut self,
        caller: &CallerId,
        service: &KeyHandle,
        ctx: &CtxId,
        template: &TgsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<TgsRepParts, IssueError> {
        let mut fields = AuditFields::for_handle(service);
        let result = self.issue_tgs_rep_inner(caller, service, ctx, template, now, &mut fields);
        self.emit(caller, Operation::IssueTgsRep, now, &fields, &result);
        result.map_err(IssueError::from)
    }

    fn issue_tgs_rep_inner(
        &mut self,
        caller: &CallerId,
        service: &KeyHandle,
        ctx: &CtxId,
        template: &TgsTicketTemplate,
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<TgsRepParts> {
        authorize(
            caller,
            Operation::IssueTgsRep,
            &[(HandleSlot::Primary, service)],
        )?;
        let now_s = kerberos_time_seconds(now);

        // 2. The context (I4): an unarmored one is consumed now; an armored
        // one only after every check of step 3 passed (docs/questions/Q-150).
        let armored = self
            .contexts
            .peek_mut(ctx.as_bytes(), caller, now_s)
            .map_err(token_deny)?
            .armor_key
            .is_some();
        let consumed = if armored {
            None
        } else {
            Some(
                self.contexts
                    .take(ctx.as_bytes(), caller, now_s)
                    .map_err(token_deny)?,
            )
        };

        // 3. The checks that may refuse, on the consumed (unarmored) or the
        // still-live (armored) entry.
        let (flags, version, service_key) = {
            let entry: &ContextEntry = match &consumed {
                Some(entry) => entry,
                None => self
                    .contexts
                    .peek_mut(ctx.as_bytes(), caller, now_s)
                    .map_err(token_deny)?,
            };

            // Armored: the template answers the inner request (docs/48 §3.4;
            // RFC 6113 5.4.2 inner req-body preferred, 5.4.3 nonce).
            if entry.armor_key.is_some()
                && (entry.req_sname.as_ref() != Some(&template.sname)
                    || template.nonce != entry.req_nonce)
            {
                return Err(Deny::denied(AuditReason::FastBindingMismatch));
            }

            // The template.
            if is_tgs_name(&template.sname) || entry.req_sname.as_ref() != Some(&template.sname) {
                return Err(Deny::bad_template(AuditReason::TemplateNames));
            }
            if template.nonce != entry.req_nonce {
                return Err(Deny::bad_template(AuditReason::TemplateNonce));
            }
            if !self.config.supports(template.session_enctype) {
                return Err(Deny::bad_template(AuditReason::TemplateEncType));
            }
            let policy = &self.config.ticket_policy;
            let flags = tgs_ticket_flags(policy, template.flags, entry.flags)?;
            let renewable = template.flags.contains(TicketFlags::RENEWABLE);
            check_times(
                policy,
                self.config.clock_skew_secs,
                now_s,
                &entry.authtime,
                &TemplateTimes {
                    starttime: template.starttime.as_ref(),
                    endtime: &template.endtime,
                    renew_till: template.renew_till.as_ref(),
                    renewable,
                },
            )?;
            if kerberos_time_seconds(&template.endtime) > kerberos_time_seconds(&entry.endtime) {
                return Err(Deny::bad_template(AuditReason::TemplateTimes));
            }
            if let Some(renew_till) = &template.renew_till {
                let within_tgt = entry.renew_till.as_ref().is_some_and(|tgt| {
                    kerberos_time_seconds(renew_till) <= kerberos_time_seconds(tgt)
                });
                if !within_tgt {
                    return Err(Deny::bad_template(AuditReason::TemplateTimes));
                }
            }

            // The service key (current version).
            let service_set = self
                .store
                .get(service)
                .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
            let version = service_set.current();
            fields.kvno = Some(version.kvno());
            // Name binding (Q-040, A-19): the ticket for sname may only be
            // sealed under the key bound to sname in this realm — otherwise
            // service X could receive tickets naming service S.
            check_binding(service_set.binding(), &self.config.realm, &template.sname)?;
            let service_key = version
                .preferred()
                .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
            (flags, version, service_key)
        };

        // Every check passed: an armored context is consumed now — exactly
        // once (docs/48 §2.3, §9.1 I4); its keys are zeroized with the entry.
        let entry = match consumed {
            Some(entry) => entry,
            None => self
                .contexts
                .take(ctx.as_bytes(), caller, now_s)
                .map_err(token_deny)?,
        };

        // 4. The session key.
        let session = new_random_key(&mut self.entropy, template.session_enctype)?;
        let session_key = EncryptionKey {
            keytype: template.session_enctype.number(),
            keyvalue: KeyValue::from_slice(session.octets()),
        };
        drop(session);

        // 5. EncTicketPart under the service key (usage 2).
        let realm = &self.config.realm;
        let enc_ticket_part = EncTicketPart {
            flags,
            key: session_key.clone(),
            crealm: entry.crealm.clone(),
            cname: entry.cname.clone(),
            transited: entry.transited.clone(),
            authtime: entry.authtime,
            starttime: template.starttime,
            endtime: template.endtime,
            renew_till: template.renew_till,
            caddr: None,
            authorization_data: None,
        };
        // The encoding holds the session key: krb-proto returns it in a
        // Zeroizing buffer (wiped on drop); the annotation pins that.
        let ticket_plain: Zeroizing<Vec<u8>> = enc_ticket_part
            .encode()
            .map_err(|_| Deny::unavailable(AuditReason::InternalFailure))?;
        drop(enc_ticket_part);
        let ticket_cipher = seal(
            &mut self.entropy,
            service_key,
            TICKET_ENC_PART,
            &ticket_plain,
        )?;
        drop(ticket_plain);
        let ticket = Ticket {
            realm: realm.clone(),
            sname: template.sname.clone(),
            enc_part: EncryptedData {
                etype: service_key.enc_type().number(),
                kvno: Some(version.kvno().get()),
                cipher: ticket_cipher,
            },
        };

        // 6. EncTGSRepPart under the reply key (usage 8 or 9) — strengthened
        // when armored — no kvno.
        let rep_part = EncTgsRepPart(EncKdcRepPart {
            key: session_key,
            last_req: LastReq::default(),
            nonce: template.nonce,
            key_expiration: None,
            flags,
            authtime: entry.authtime,
            starttime: template.starttime,
            endtime: template.endtime,
            renew_till: template.renew_till,
            srealm: realm.clone(),
            sname: template.sname.clone(),
            caddr: None,
        });
        let rep_plain: Zeroizing<Vec<u8>> = rep_part
            .encode()
            .map_err(|_| Deny::unavailable(AuditReason::InternalFailure))?;
        drop(rep_part);
        let (rep_cipher, fast_rep) = match &entry.armor_key {
            None => (
                seal(
                    &mut self.entropy,
                    &entry.reply_key,
                    entry.reply_usage,
                    &rep_plain,
                )?,
                None,
            ),
            Some(armor_key) => {
                // RFC 6113 5.4.3: the strengthen key "MUST be set in a TGS
                // reply"; the padata reply key is the subkey (mandatory under
                // FAST), usage 9 (Q-121 (a)). KrbFastFinished names the
                // issued ticket's client — the TGT's (RFC 4120 3.3.3).
                let (strengthen, cipher) = seal_strengthened(
                    &mut self.entropy,
                    &entry.reply_key,
                    entry.reply_usage,
                    &rep_plain,
                )?;
                let fast_rep = seal_fast_reply(
                    &mut self.entropy,
                    armor_key,
                    Vec::new(),
                    strengthen,
                    &ticket,
                    &entry.crealm,
                    &entry.cname,
                    entry.req_nonce,
                    now,
                )?;
                (cipher, Some(fast_rep))
            }
        };
        drop(rep_plain);
        // The reply key, strengthened or not, has the reply key's enctype
        // (RFC 6113 5.4.3 "same etype"; 5.1 "the enctype of k1").
        Ok(TgsRepParts {
            ticket,
            enc_part: EncryptedData {
                etype: entry.reply_key.enc_type().number(),
                kvno: None,
                cipher: rep_cipher,
            },
            fast_rep,
        })
    }
}
