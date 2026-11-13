//! The FAST armor core inside keyd: `open_fast_armor` (an armored AS
//! request's FX_FAST_ARMOR_AP_REQUEST armor and KrbFastReq) and
//! `seal_fast_error` (the armored KRB-ERROR of that conversation). Role `Kdc`
//! only.
//!
//! "Compute, don't give" for FAST (docs/48 §2, decision A-33): every
//! armor-key computation happens here. The armor key is derived, used and
//! stored in keyd, bound to a one-time [`ArmorId`]; it never leaves keyd —
//! not to the KDC, not in an error, not in audit. What leaves: the armor id,
//! the armor ticket's non-secret client facts, the decrypted KrbFastReq (what
//! the client sends the KDC anyway; its secret padata stays ciphertext under
//! other keys), and the sealed enc-fast-rep.
//!
//! State machine (docs/48 §2.3):
//! `open_fast_armor ──(armor_id)──► seal_fast_error(As(armor_id))` — and, in
//! docs/48 task T2, `verify_preauth(armor)` / `issue_as_rep(armor)`. Every
//! armor id is consumed exactly once, or expires and is removed with its key
//! zeroized.
//!
//! **Computer-account-only armor (D126) is not checked here:** keyd holds no
//! account kind. keyd verifies the armor TGT cryptographically and returns
//! its crealm / cname / authtime; the KDC (PEP) maps them to an account and
//! refuses a non-computer, disabled or revoked armor principal (docs/48
//! §3.1, task T5).
//!
//! Not here (docs/48 §12 and later tasks): the TGS (implicit armor) variant
//! and `seal_fast_error(Tgs)` (T3); encrypted challenge and the armored AS
//! reply (T2); anonymous armor; any armor type other than
//! FX_FAST_ARMOR_AP_REQUEST.
//!
//! Spec: RFC 6113 5.1, 5.4, 5.4.1, 5.4.1.1, 5.4.2, 5.4.3, 5.4.4, 6.2;
//! RFC 4120 3.2.3, 5.5.1, 5.9.1, 7.5.1; RFC 3961 §3; docs/48 §2.3, §3, §6,
//! §9; docs/questions/Q-120 (A-32); A-26.

use crate::as_exchange::token_deny;
use crate::audit::{AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::entropy::EntropySource;
use crate::error::{AuthnError, Deny, Error, Internal};
use crate::keyd::{authorize, draw, key_usage, open, seal, AuditFields, Keyd};
use crate::model::KeyHandle;
use crate::store::KeyStore;
use crate::template::tgs_name;
use crate::tgs_exchange::{check_ap_options, replay_key_for, subkey_protocol_key, OpenedTgt};
use crate::time::kerberos_time_seconds;
use crate::tokens::{ArmorId, TOKEN_ID_LENGTH};
use crate::usage::{
    AP_REQ_AUTHENTICATOR, KEY_USAGE_FAST_ENC, KEY_USAGE_FAST_REP, KEY_USAGE_FAST_REQ_CHKSUM,
};
use krb_crypto::{ChecksumType, EncType, ProtocolKey};
use krb_proto::constants::{
    FX_FAST_ARMOR_AP_REQUEST, KDC_ERR_NONE, PA_ENCRYPTED_CHALLENGE, PA_ETYPE_INFO2, PA_FX_COOKIE,
    PA_FX_ERROR,
};
use krb_proto::{
    ApReq, EncryptedData, EtypeInfo2, KdcReqBody, KerberosTime, KrbError, KrbFastArmoredReq,
    KrbFastReq, KrbFastResponse, PaData, PrincipalName, Realm,
};
use zeroize::Zeroizing;

/// KRB-FX-CF2 pepper1 of the ticket-based armor key.
/// Spec: RFC 6113 5.4.1.1 (`"subkeyarmor"`).
const SUBKEY_ARMOR_PEPPER: &[u8] = b"subkeyarmor";

/// KRB-FX-CF2 pepper2 of the ticket-based armor key.
/// Spec: RFC 6113 5.4.1.1 (`"ticketarmor"`).
const TICKET_ARMOR_PEPPER: &[u8] = b"ticketarmor";

/// Upper bound on a PA-FX-COOKIE value keyd seals into an armored error. The
/// cookie's content "is a local matter of the KDC" (RFC 6113 5.2); phase 1's
/// cookie is a short constant token (docs/questions/Q-126, A-32), so this
/// project bound only keeps the sealed reply small. Not taken from any other
/// source.
pub const MAX_FX_COOKIE_LENGTH: usize = 64;

/// The result of `open_fast_armor`: the one-time armor token, the armor
/// ticket's client (non-secret; the KDC re-evaluates it as an account, D126 /
/// D53) and the decrypted inner request. No key of any kind (docs/48 §9.1
/// I1).
///
/// Spec: docs/48 §2.3 (`struct FastArmor`); RFC 6113 5.4.1.1, 5.4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastArmor {
    /// The one-time armor token (docs/48 §2.3, D36).
    pub armor_id: ArmorId,
    /// Client realm of the armor ticket.
    pub armor_crealm: Realm,
    /// Client name of the armor ticket.
    pub armor_cname: PrincipalName,
    /// Authentication time of the armor ticket (for the KDC's
    /// `revoked_before` hot-list check, docs/48 §3.1).
    pub armor_authtime: KerberosTime,
    /// The decrypted KrbFastReq: fast-options, padata, inner req-body.
    pub fast_req: KrbFastReq,
}

/// Which armored conversation `seal_fast_error` answers. Phase 1 has the AS
/// conversation only; the TGS variant (implicit armor, `Tgs(CtxId)`) is
/// docs/48 task T3.
///
/// Spec: docs/48 §2.3 (`enum FastConversation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastConversation {
    /// The AS conversation opened by `open_fast_armor`.
    As(ArmorId),
}

/// What keyd keeps about an opened armor (never leaves keyd). The armor key
/// is zeroized when the entry is consumed or expires (krb-crypto
/// `ProtocolKey` wipes on drop). The inner-request facts are what
/// `seal_fast_error` binds the error to.
///
/// docs/48 §2.3 also lists the inner etype list, `preauth_attempted` and
/// `bound_proof`: they belong to the armored `verify_preauth` /
/// `issue_as_rep` of task T2 and are added there.
///
/// Spec: docs/48 §2.3 (ArmorEntry); RFC 6113 5.4.3 (nonce).
pub(crate) struct ArmorEntry {
    armor_key: ProtocolKey,
    req_nonce: u32,
    req_realm: Realm,
    req_cname: Option<PrincipalName>,
    req_sname: Option<PrincipalName>,
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// `open_fast_armor`: open the armor of an armored AS request and its
    /// KrbFastReq inside keyd, and return a one-time [`FastArmor`].
    ///
    /// `armored_req` is the KrbFastArmoredReq of the request's PA-FX-FAST;
    /// `outer_req_body` is the raw DER of the outer KDC-REQ-BODY, over which
    /// the req-checksum is verified (it is otherwise ignored).
    ///
    /// Checks failing as the uniform `AuthnError::Denied` (reason to audit
    /// only):
    /// 1. authorize (Kdc; krbtgt handle Krbtgt);
    /// 2. the armor is present, of type FX_FAST_ARMOR_AP_REQUEST, and its
    ///    value is a DER AP-REQ without USE-SESSION-KEY (the KDC checks the
    ///    first two before calling — RFC 6113 5.4.1 / 5.4.2 — keyd checks
    ///    again);
    /// 3. `outer_req_body` decodes as a KDC-REQ-BODY (structure only);
    /// 4. the armor ticket is this realm's TGT, bound to krbtgt/realm,
    ///    decrypted under krbtgt; its authenticator decrypts under the ticket
    ///    session key with key usage 11 (Q-120 item 1); names match; no
    ///    authorization-data — the steps shared with `open_and_verify_tgt`;
    /// 5. the authenticator carries no checksum (Q-120 item 3) and does carry
    ///    a subkey of a configured enctype (RFC 6113 5.4.1.1 "MUST be
    ///    present");
    /// 6. armor key = KRB-FX-CF2(subkey, ticket session key, "subkeyarmor",
    ///    "ticketarmor"), of the subkey's enctype (RFC 6113 5.1);
    /// 7. the req-checksum is of the armor key's required checksum type and
    ///    verifies over `outer_req_body` with key usage 50;
    /// 8. enc-fast-req is of the armor key's enctype, decrypts with key usage
    ///    51 and decodes as KrbFastReq.
    ///
    /// Only now — the chain complete — are the recorded findings reported, as
    /// non-secret classes (A-26, docs/48 §6.3): authenticator skew → `Skew`;
    /// armor ticket not yet valid → `TicketNotYetValid`; expired →
    /// `TicketExpired`. Then the replay cache must accept the armor
    /// authenticator (Q-120 item 2), else `Replay` (full: `Denied`). Finally
    /// the armor key and the inner nonce / realm / cname / sname are stored
    /// under a fresh armor id bound to this caller.
    ///
    /// The armor principal is returned, not judged: computer-account-only
    /// armor (D126) is the KDC's check (module docs).
    ///
    /// Spec: RFC 6113 5.1, 5.4.1, 5.4.1.1, 5.4.2; RFC 4120 3.2.3, 5.5.1,
    /// 7.5.1; RFC 3961 §3 (required checksum mechanism); docs/48 §2.3, §3,
    /// §6.3; docs/questions/Q-120 (A-32); A-26.
    pub fn open_fast_armor(
        &mut self,
        caller: &CallerId,
        krbtgt: &KeyHandle,
        armored_req: &KrbFastArmoredReq,
        outer_req_body: &[u8],
        now: &KerberosTime,
    ) -> Result<FastArmor, AuthnError> {
        let mut fields = AuditFields::for_handle(krbtgt);
        let result = self.open_fast_armor_inner(
            caller,
            krbtgt,
            armored_req,
            outer_req_body,
            now,
            &mut fields,
        );
        self.emit(caller, Operation::OpenFastArmor, now, &fields, &result);
        result.map_err(AuthnError::from)
    }

    fn open_fast_armor_inner(
        &mut self,
        caller: &CallerId,
        krbtgt: &KeyHandle,
        armored_req: &KrbFastArmoredReq,
        outer_req_body: &[u8],
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<FastArmor> {
        authorize(
            caller,
            Operation::OpenFastArmor,
            &[(HandleSlot::Primary, krbtgt)],
        )?;
        let now_s = kerberos_time_seconds(now);

        // 2. The armor. Spec: RFC 6113 5.4.1 (armor type), 5.4.1.1
        // ("armor-value contains an ASN.1 DER encoded AP-REQ"), 5.4.2.
        let armor = armored_req
            .armor
            .as_ref()
            .ok_or(Deny::denied(AuditReason::ArmorMissing))?;
        if armor.armor_type != FX_FAST_ARMOR_AP_REQUEST {
            return Err(Deny::denied(AuditReason::ArmorTypeUnsupported));
        }
        let ap_req = ApReq::decode(&armor.armor_value)
            .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        check_ap_options(&ap_req)?;

        // 3. The outer request body: structure only; RFC 6113 5.4.2 has the
        // KDC ignore it apart from the req-checksum (step 7).
        KdcReqBody::decode(outer_req_body)
            .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;

        // 4. The armor TGT and its authenticator, usage 11 (shared steps).
        let OpenedTgt {
            ticket_part,
            session,
            authenticator,
            ctime,
            findings,
        } = self.open_local_tgt(krbtgt, &ap_req, AP_REQ_AUTHENTICATOR, now_s, fields)?;

        // 5. No checksum (Q-120 item 3); the subkey is mandatory (RFC 6113
        // 5.4.1.1) and of a configured enctype (I5).
        if authenticator.cksum.is_some() {
            return Err(Deny::denied(AuditReason::ArmorChecksumPresent));
        }
        let subkey = authenticator
            .subkey
            .as_ref()
            .ok_or(Deny::denied(AuditReason::ArmorSubkeyMissing))?;
        let subkey = subkey_protocol_key(subkey, &self.config.enctypes)?;

        // 6. The armor key; its enctype is the subkey's (k1). Spec: RFC 6113
        // 5.1, 5.4.1.1.
        let armor_key =
            krb_crypto::krb_fx_cf2(&subkey, &session, SUBKEY_ARMOR_PEPPER, TICKET_ARMOR_PEPPER)
                .map_err(|_| Deny::unavailable(AuditReason::InternalFailure))?;
        drop(subkey);
        drop(session);

        // 7. The req-checksum over the outer KDC-REQ-BODY: keyed with the
        // armor key, "the required checksum type for the enctype of the armor
        // key", usage 50. Spec: RFC 6113 5.4.2; RFC 3961 §3.
        let req_checksum = &armored_req.req_checksum;
        let cksumtype = ChecksumType::from_number(req_checksum.cksumtype)
            .ok()
            .filter(|t| *t == armor_key.enc_type().checksum_type())
            .ok_or(Deny::denied(AuditReason::ChecksumUnsupported))?;
        krb_crypto::verify_mic(
            &armor_key,
            cksumtype,
            key_usage(KEY_USAGE_FAST_REQ_CHKSUM)?,
            outer_req_body,
            &req_checksum.checksum,
        )
        .map_err(|_| Deny::denied(AuditReason::FastChecksumMismatch))?;

        // 8. enc-fast-req under the armor key, usage 51. Spec: RFC 6113 5.4.2.
        let enc_fast_req = &armored_req.enc_fast_req;
        if enc_fast_req.etype != armor_key.enc_type().number() {
            return Err(Deny::denied(AuditReason::UnsupportedEncType));
        }
        let fast_req_plain: Zeroizing<Vec<u8>> =
            open(&armor_key, KEY_USAGE_FAST_ENC, &enc_fast_req.cipher)?;
        let fast_req = KrbFastReq::decode(&fast_req_plain)
            .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        drop(fast_req_plain);

        // The chain is complete: armor TGT, authenticator, subkey, armor key,
        // req-checksum, enc-fast-req. Findings, then the replay cache
        // (Q-120 item 2; A-26).
        self.complete_chain(
            findings,
            replay_key_for(&ap_req.ticket, &authenticator, ctime),
            now_s,
        )?;

        // The one-time armor entry.
        let mut id = [0u8; TOKEN_ID_LENGTH];
        draw(&mut self.entropy, &mut id)?;
        let body = &fast_req.req_body;
        let entry = ArmorEntry {
            armor_key,
            req_nonce: body.nonce,
            req_realm: body.realm.clone(),
            req_cname: body.cname.clone(),
            req_sname: body.sname.clone(),
        };
        let expires_at = now_s + i64::from(self.config.token_lifetime_secs);
        if !self.armors.insert(id, *caller, expires_at, entry, now_s) {
            return Err(Deny::unavailable(AuditReason::TokenTableFull));
        }
        Ok(FastArmor {
            armor_id: ArmorId::from_bytes(id),
            armor_crealm: ticket_part.crealm.clone(),
            armor_cname: ticket_part.cname.clone(),
            armor_authtime: ticket_part.authtime,
            fast_req,
        })
    }

    /// `seal_fast_error`: consume the conversation's armor and seal the
    /// enc-fast-rep of an armored KRB-ERROR — a KrbFastResponse carrying the
    /// allowed `padata` plus PA-FX-ERROR (the DER of `error`), no
    /// strengthen-key, no finished, and the nonce of the inner request keyd
    /// stored (not one from the caller), encrypted in the armor key with key
    /// usage 52.
    ///
    /// The KDC frames the result (KRB-ERROR e-data = METHOD-DATA with
    /// PA-FX-FAST, RFC 6113 5.4.4). keyd checks the content so that a
    /// compromised KDC can only ever have an error sealed — never a reply
    /// that reads as success (docs/48 §6.1):
    /// 1. authorize (Kdc; no handle — the armor token is the authority);
    /// 2. consume the armor: live, issued to this caller (`Denied`
    ///    otherwise; destroyed either way);
    /// 3. `error`: no e-data ("MUST be absent in the PA-FX-ERROR"), no
    ///    e-text (docs/48 §2.3), an error code other than KDC_ERR_NONE,
    ///    stime = `now`, realm = the inner request's realm, sname = the inner
    ///    request's sname (or this realm's TGS name when it had none — the
    ///    KDC's KRB-ERROR rule), crealm / cname, when present, those of the
    ///    inner request;
    /// 4. `padata`: only PA-ETYPE-INFO2 (decoding, configured enctypes
    ///    only), PA-FX-COOKIE (1 to [`MAX_FX_COOKIE_LENGTH`] octets) and
    ///    PA-ENCRYPTED-CHALLENGE (empty value: an advertisement), each at
    ///    most once (docs/48 §2.3 allowlist).
    ///
    /// Errors are `Error::Denied` (token, content, padata) or
    /// `Error::Unavailable` (entropy, encoding). On any error the KDC sends
    /// the same code unarmored (docs/questions/Q-125 item 10).
    ///
    /// Spec: RFC 6113 5.4.3 (strengthen-key "MUST be absent in KRB-ERROR";
    /// finished "absent otherwise"; nonce; usage 52), 5.4.4; RFC 4120 5.9.1,
    /// 7.5.9 (KDC_ERR_NONE); docs/48 §2.3, §6.1; docs/questions/Q-125.
    pub fn seal_fast_error(
        &mut self,
        caller: &CallerId,
        conversation: &FastConversation,
        error: &KrbError,
        padata: &[PaData],
        now: &KerberosTime,
    ) -> Result<EncryptedData, Error> {
        let fields = AuditFields::default();
        let result = self.seal_fast_error_inner(caller, conversation, error, padata, now);
        self.emit(caller, Operation::SealFastError, now, &fields, &result);
        result.map_err(Error::from)
    }

    fn seal_fast_error_inner(
        &mut self,
        caller: &CallerId,
        conversation: &FastConversation,
        error: &KrbError,
        padata: &[PaData],
        now: &KerberosTime,
    ) -> Internal<EncryptedData> {
        authorize(caller, Operation::SealFastError, &[])?;
        let now_s = kerberos_time_seconds(now);

        // 2. The armor (I4).
        let entry = match conversation {
            FastConversation::As(armor_id) => self
                .armors
                .take(armor_id.as_bytes(), caller, now_s)
                .map_err(token_deny)?,
        };

        // 3. The error content.
        check_fast_error(error, &entry, &self.config.realm, now)?;

        // 4. The padata, then PA-FX-ERROR.
        let mut response_padata = allowed_fast_error_padata(padata, &self.config.enctypes)?;
        let fx_error = error
            .encode()
            .map_err(|_| Deny::unavailable(AuditReason::InternalFailure))?;
        response_padata.push(PaData {
            padata_type: PA_FX_ERROR,
            padata_value: fx_error,
        });

        // The KrbFastResponse of an error: no strengthen-key, no finished,
        // the stored nonce; sealed under the armor key, usage 52.
        let response = KrbFastResponse {
            padata: response_padata,
            strengthen_key: None,
            finished: None,
            nonce: entry.req_nonce,
        };
        let plain: Zeroizing<Vec<u8>> = response
            .encode()
            .map_err(|_| Deny::unavailable(AuditReason::InternalFailure))?;
        drop(response);
        let cipher = seal(
            &mut self.entropy,
            &entry.armor_key,
            KEY_USAGE_FAST_REP,
            &plain,
        )?;
        Ok(EncryptedData {
            etype: entry.armor_key.enc_type().number(),
            kvno: None,
            cipher,
        })
    }
}

/// The KRB-ERROR checks of `seal_fast_error` step 3: an error, bound to the
/// inner request being answered, with nothing keyd does not seal. Failure is
/// `Denied` (reason `FastErrorContentRefused`).
///
/// Spec: RFC 6113 5.4.4 ("The e-data field MUST be absent in the
/// PA-FX-ERROR"; "All other fields should be the same as the outer
/// KRB-ERROR"); RFC 4120 5.9.1, 7.5.9; docs/48 §2.3, §6.1, §8 (names of the
/// inner request).
fn check_fast_error(
    error: &KrbError,
    entry: &ArmorEntry,
    realm: &Realm,
    now: &KerberosTime,
) -> Internal<()> {
    let expected_sname = match &entry.req_sname {
        Some(sname) => sname.clone(),
        None => tgs_name(realm),
    };
    let acceptable = error.e_data.is_none()
        && error.e_text.is_none()
        && error.error_code > KDC_ERR_NONE
        && error.stime == *now
        && error.realm == entry.req_realm
        && error.sname == expected_sname
        && error
            .crealm
            .as_ref()
            .is_none_or(|crealm| *crealm == entry.req_realm)
        && error
            .cname
            .as_ref()
            .is_none_or(|cname| entry.req_cname.as_ref() == Some(cname));
    if acceptable {
        Ok(())
    } else {
        Err(Deny::denied(AuditReason::FastErrorContentRefused))
    }
}

/// The padata allowlist of `seal_fast_error` step 4. Returns a copy with room
/// for PA-FX-ERROR. Failure is `Denied` (reason `FastErrorPadataRefused`).
///
/// - PA-ETYPE-INFO2: must decode, and every entry must name a configured
///   enctype (no weak type is advertised under integrity protection, I5);
/// - PA-FX-COOKIE: 1 to [`MAX_FX_COOKIE_LENGTH`] octets (Q-126);
/// - PA-ENCRYPTED-CHALLENGE: empty — advertising the mechanism (RFC 6113 2.2;
///   Q-123); the KDC's own challenge belongs to a reply, not an error;
/// - every type at most once; anything else is refused.
///
/// Bounded: at most three entries can pass, so the loop stops at the fourth.
///
/// Spec: docs/48 §2.3 ("allowlist: PA-ETYPE-INFO2, PA-FX-COOKIE,
/// PA-ENCRYPTED-CHALLENGE (empty value)"), §6.1; RFC 6113 5.2, 5.4.4, 5.4.6;
/// RFC 4120 5.2.7.5.
fn allowed_fast_error_padata(padata: &[PaData], supported: &[EncType]) -> Internal<Vec<PaData>> {
    let refused = Deny::denied(AuditReason::FastErrorPadataRefused);
    let mut allowed: Vec<PaData> = Vec::with_capacity(4);
    for pa in padata {
        if allowed
            .iter()
            .any(|seen| seen.padata_type == pa.padata_type)
        {
            return Err(refused);
        }
        let acceptable = match pa.padata_type {
            PA_ETYPE_INFO2 => EtypeInfo2::decode(&pa.padata_value).is_ok_and(|info| {
                info.0.iter().all(|entry| {
                    EncType::from_number(entry.etype).is_ok_and(|e| supported.contains(&e))
                })
            }),
            PA_FX_COOKIE => (1..=MAX_FX_COOKIE_LENGTH).contains(&pa.padata_value.len()),
            PA_ENCRYPTED_CHALLENGE => pa.padata_value.is_empty(),
            _ => false,
        };
        if !acceptable {
            return Err(refused);
        }
        allowed.push(pa.clone());
    }
    Ok(allowed)
}
