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
//! ```text
//! open_fast_armor ─(armor_id)─► verify_preauth(EncryptedChallenge, armor)
//!       │                              └─(proof⊗armor)─► issue_as_rep(proof, armor)   [consumes]
//!       └──────────────────────────────────────────────► seal_fast_error(As(armor))  [consumes]
//! ```
//! Every armor id is consumed exactly once — by the `issue_as_rep` that
//! issues, or by `seal_fast_error` — or expires and is removed with its key
//! zeroized. It allows one pre-authentication attempt (success or failure),
//! and the proof that attempt yields is bound to it both ways. A refused
//! `verify_preauth` or `issue_as_rep` leaves the armor live, so that the KDC
//! can seal the armored refusal (docs/48 §4.1 A10, A13).
//!
//! The armored AS reply (docs/48 §4.3, §4.4) is built here too
//! (`ArmorEntry::seal_as_reply`): a fresh strengthen key, the reply key
//! KRB-FX-CF2(strengthen key, client key, "strengthenkey", "replykey"), the
//! KDC's PA-ENCRYPTED-CHALLENGE, KrbFastFinished with the ticket-checksum,
//! and the KrbFastResponse sealed in the armor key. No FAST key — armor,
//! challenge, strengthen, reply — leaves keyd; the strengthen key leaves only
//! inside the sealed `fast_rep`.
//!
//! **Computer-account-only armor (D126) is not checked here:** keyd holds no
//! account kind. keyd verifies the armor TGT cryptographically and returns
//! its crealm / cname / authtime; the KDC (PEP) maps them to an account and
//! refuses a non-computer, disabled or revoked armor principal (docs/48
//! §3.1, task T5).
//!
//! Not here (docs/48 §12 and later tasks): the TGS (implicit armor) variant
//! and `seal_fast_error(Tgs)` (T3); anonymous armor; any armor type other
//! than FX_FAST_ARMOR_AP_REQUEST; any FAST factor other than encrypted
//! challenge.
//!
//! Spec: RFC 6113 5.1, 5.4, 5.4.1, 5.4.1.1, 5.4.2, 5.4.3, 5.4.4, 5.4.6, 6.2;
//! RFC 4120 3.2.3, 5.2.7.2, 5.4.2, 5.5.1, 5.9.1, 7.5.1; RFC 3961 §3; docs/48
//! §2.3, §3, §4, §6, §9; docs/questions/Q-120..Q-123 (A-32); A-26.

use crate::as_exchange::token_deny;
use crate::audit::{AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::entropy::EntropySource;
use crate::error::{AuthnError, Deny, Error, Internal};
use crate::keyd::{authorize, draw, key_usage, new_random_key, open, seal, AuditFields, Keyd};
use crate::model::KeyHandle;
use crate::store::KeyStore;
use crate::template::tgs_name;
use crate::tgs_exchange::{check_ap_options, replay_key_for, subkey_protocol_key, OpenedTgt};
use crate::time::kerberos_time_seconds;
use crate::tokens::{ArmorId, TOKEN_ID_LENGTH};
use crate::usage::{
    AP_REQ_AUTHENTICATOR, AS_REP_ENC_PART, KEY_USAGE_ENC_CHALLENGE_KDC, KEY_USAGE_FAST_ENC,
    KEY_USAGE_FAST_FINISHED, KEY_USAGE_FAST_REP, KEY_USAGE_FAST_REQ_CHKSUM,
};
use krb_crypto::{ChecksumType, EncType, ProtocolKey};
use krb_proto::constants::{
    FX_FAST_ARMOR_AP_REQUEST, KDC_ERR_NONE, PA_ENCRYPTED_CHALLENGE, PA_ETYPE_INFO2, PA_FX_COOKIE,
    PA_FX_ERROR,
};
use krb_proto::{
    ApReq, Checksum, EncryptedData, EncryptionKey, EtypeInfo2, KdcReqBody, KerberosTime, KeyValue,
    KrbError, KrbFastArmoredReq, KrbFastFinished, KrbFastReq, KrbFastResponse, Microseconds,
    PaData, PaEncTsEnc, PrincipalName, Realm, Ticket,
};
use zeroize::Zeroizing;

/// KRB-FX-CF2 pepper1 of the ticket-based armor key.
/// Spec: RFC 6113 5.4.1.1 (`"subkeyarmor"`).
const SUBKEY_ARMOR_PEPPER: &[u8] = b"subkeyarmor";

/// KRB-FX-CF2 pepper2 of the ticket-based armor key.
/// Spec: RFC 6113 5.4.1.1 (`"ticketarmor"`).
const TICKET_ARMOR_PEPPER: &[u8] = b"ticketarmor";

/// KRB-FX-CF2 pepper1 of the challenge key "used by the client to send a
/// message to the KDC". Spec: RFC 6113 5.4.6 (`"clientchallengearmor"`).
const CLIENT_CHALLENGE_ARMOR_PEPPER: &[u8] = b"clientchallengearmor";

/// KRB-FX-CF2 pepper1 of the challenge key "used by the KDC encrypting to
/// the client". Spec: RFC 6113 5.4.6 (`"kdcchallengearmor"`).
const KDC_CHALLENGE_ARMOR_PEPPER: &[u8] = b"kdcchallengearmor";

/// KRB-FX-CF2 pepper2 of both challenge keys (the long-term key's side).
/// Spec: RFC 6113 5.4.6 (`"challengelongterm"`).
const CHALLENGE_LONG_TERM_PEPPER: &[u8] = b"challengelongterm";

/// KRB-FX-CF2 pepper1 of the strengthened reply key (the strengthen key's
/// side). Spec: RFC 6113 5.4.3 (`"strengthenkey"`).
const STRENGTHEN_KEY_PEPPER: &[u8] = b"strengthenkey";

/// KRB-FX-CF2 pepper2 of the strengthened reply key (the padata reply key's
/// side). Spec: RFC 6113 5.4.3 (`"replykey"`).
const REPLY_KEY_PEPPER: &[u8] = b"replykey";

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
/// `seal_fast_error` and the armored `issue_as_rep` bind their output to, and
/// what the armored `verify_preauth` selects the client key from.
///
/// Spec: docs/48 §2.3 (ArmorEntry: armor key; nonce, crealm / cname and the
/// etype list of the inner req-body; preauth_attempted; bound_proof); RFC
/// 6113 5.4.3 (nonce).
pub(crate) struct ArmorEntry {
    armor_key: ProtocolKey,
    req_nonce: u32,
    req_realm: Realm,
    req_cname: Option<PrincipalName>,
    req_sname: Option<PrincipalName>,
    /// The inner req-body etype list, in the client's order (the long-term
    /// key selection of docs/questions/Q-123).
    req_etypes: Vec<i32>,
    /// The armor's one pre-authentication attempt has been made (docs/48
    /// §2.3: "one attempt per armor, success or failure").
    preauth_attempted: bool,
    /// The proof the armored `verify_preauth` issued (docs/48 §2.3: "the
    /// ArmorEntry remembers the proof").
    bound_proof: Option<[u8; TOKEN_ID_LENGTH]>,
}

/// An encoding or crypto step of keyd's own construction failed (its inputs
/// are keyd's, so this is internal): `Unavailable`, the error discarded.
/// Spec: docs/10 §9 (`Unavailable`).
fn internal<T>(_: T) -> Deny {
    Deny::unavailable(AuditReason::InternalFailure)
}

/// The armored parts of an AS reply, sealed by [`ArmorEntry::seal_as_reply`].
/// Spec: docs/48 §2.3 (`AsRep { enc_part, fast_rep }`); RFC 6113 5.4.3.
pub(crate) struct ArmoredAsReply {
    /// EncASRepPart sealed in the strengthened reply key, key usage 3. The
    /// reply key has the client key's enctype (the strengthen key is drawn in
    /// it, and KRB-FX-CF2 keeps the enctype of k1).
    pub(crate) enc_part_cipher: Vec<u8>,
    /// enc-fast-rep: the KrbFastResponse sealed in the armor key, usage 52.
    pub(crate) fast_rep: EncryptedData,
}

impl ArmorEntry {
    /// Take the armor's one pre-authentication attempt: refused when it was
    /// already taken, marked otherwise — before anything else is checked, so
    /// a failed attempt uses it up too.
    /// Spec: docs/48 §2.3 ("one attempt per armor — success or failure —
    /// limits online guessing to one per armor"), §4.5 step 1, §9.1 I4.
    pub(crate) fn begin_preauth(&mut self) -> Internal<()> {
        if self.preauth_attempted {
            return Err(Deny::denied(AuditReason::ArmorAlreadyAttempted));
        }
        self.preauth_attempted = true;
        Ok(())
    }

    /// The enctype of the challenge keys: the armor key's, because
    /// KRB-FX-CF2 yields "the enctype of k1" and the armor key is k1.
    /// Spec: RFC 6113 5.1, 5.4.6; docs/48 §4.5 step 2.
    pub(crate) fn challenge_enctype(&self) -> EncType {
        self.armor_key.enc_type()
    }

    /// The inner req-body etype list, in the client's order.
    /// Spec: RFC 4120 3.1.3, 5.4.1 (etype); docs/questions/Q-123 (A-32).
    pub(crate) fn requested_etypes(&self) -> &[i32] {
        &self.req_etypes
    }

    /// The client challenge key: KRB-FX-CF2(armor_key, long_term_key,
    /// "clientchallengearmor", "challengelongterm").
    /// Spec: RFC 6113 5.4.6, 5.1.
    pub(crate) fn client_challenge_key(&self, long_term: &ProtocolKey) -> Internal<ProtocolKey> {
        krb_crypto::krb_fx_cf2(
            &self.armor_key,
            long_term,
            CLIENT_CHALLENGE_ARMOR_PEPPER,
            CHALLENGE_LONG_TERM_PEPPER,
        )
        .map_err(|_| Deny::unavailable(AuditReason::InternalFailure))
    }

    /// Remember the proof the armored `verify_preauth` issued.
    /// Spec: docs/48 §2.3 ("the ArmorEntry remembers the proof").
    pub(crate) fn bind_proof(&mut self, proof: [u8; TOKEN_ID_LENGTH]) {
        self.bound_proof = Some(proof);
    }

    /// The armored `issue_as_rep` checks, failing as `Denied`:
    /// - the armor is bound to `proof` (the other direction of the binding
    ///   the proof itself carries) — reason `ArmorProofMismatch`;
    /// - the template's crealm, cname and nonce are those of the inner
    ///   req-body stored when the armor was opened (name-type included) —
    ///   reason `FastBindingMismatch`.
    ///
    /// Spec: docs/48 §2.3, §3.4 ("template.crealm/cname and template.nonce
    /// equal those of the inner req-body"); RFC 6113 5.4.2 ("This req-body
    /// field is preferred over the outer field"), 5.4.3 (the nonce "binds the
    /// KDC response with the client request").
    pub(crate) fn check_issue(
        &self,
        proof: &[u8; TOKEN_ID_LENGTH],
        crealm: &Realm,
        cname: &PrincipalName,
        nonce: u32,
    ) -> Internal<()> {
        if self.bound_proof.as_ref() != Some(proof) {
            return Err(Deny::denied(AuditReason::ArmorProofMismatch));
        }
        if *crealm != self.req_realm
            || self.req_cname.as_ref() != Some(cname)
            || nonce != self.req_nonce
        {
            return Err(Deny::denied(AuditReason::FastBindingMismatch));
        }
        Ok(())
    }

    /// Seal the armored parts of an AS reply (docs/48 §4.3, §4.4):
    /// 1. strengthen key: random, of the client key's enctype ("the same
    ///    etype as that of the reply key before being strengthened");
    /// 2. reply key = KRB-FX-CF2(strengthen key, client key,
    ///    "strengthenkey", "replykey") — the padata reply key is the client
    ///    key, since encrypted challenge "does not provide the Replace Reply
    ///    Key facility";
    /// 3. `rep_plain` (the EncASRepPart encoding) sealed in the reply key with
    ///    key usage 3 (docs/questions/Q-121 (a); RFC 4120 5.4.2: usage 3 with
    ///    "another key selected via pre-authentication mechanisms");
    /// 4. the KDC's PA-ENCRYPTED-CHALLENGE: PA-ENC-TS-ENC { patimestamp =
    ///    `now`, no pausec } in KRB-FX-CF2(armor_key, client key,
    ///    "kdcchallengearmor", "challengelongterm"), usage 55 (Q-123 item 3);
    /// 5. KrbFastFinished: timestamp = `now`, usec = 0 (keyd reads no clock;
    ///    docs/48 §4.4), crealm / cname of the ticket, ticket-checksum =
    ///    get_mic(armor key, its required checksum type, usage 53, the DER of
    ///    `ticket` — the full `[APPLICATION 1]` Ticket as it stands in the
    ///    KDC-REP, docs/questions/Q-122 (a));
    /// 6. KrbFastResponse { padata: [the KDC's PA-ENCRYPTED-CHALLENGE],
    ///    strengthen-key, finished, nonce of the stored inner request }
    ///    sealed in the armor key, usage 52, without kvno.
    ///
    /// Every intermediate key is zeroized on drop; the strengthen key leaves
    /// keyd only inside the sealed KrbFastResponse.
    ///
    /// Spec: RFC 6113 5.1, 5.4.3, 5.4.6, 6.2; RFC 4120 5.2.7.2, 5.4.2, 5.6.1
    /// (timestamp / usec semantics); RFC 3961 §3 (random-to-key, required
    /// checksum mechanism); docs/48 §4.3, §4.4; docs/questions/Q-121..Q-123
    /// (A-32).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal_as_reply<E: EntropySource>(
        &self,
        entropy: &mut E,
        client_key: &ProtocolKey,
        rep_plain: &[u8],
        ticket: &Ticket,
        crealm: &Realm,
        cname: &PrincipalName,
        now: &KerberosTime,
    ) -> Internal<ArmoredAsReply> {
        let armor_enctype = self.armor_key.enc_type();

        // 1-3. The strengthened reply key and the enc-part under it.
        let strengthen = new_random_key(entropy, client_key.enc_type())?;
        let reply_key = krb_crypto::krb_fx_cf2(
            &strengthen,
            client_key,
            STRENGTHEN_KEY_PEPPER,
            REPLY_KEY_PEPPER,
        )
        .map_err(internal)?;
        let enc_part_cipher = seal(entropy, &reply_key, AS_REP_ENC_PART, rep_plain)?;
        drop(reply_key);

        // 4. The KDC's encrypted challenge.
        let kdc_challenge_key = krb_crypto::krb_fx_cf2(
            &self.armor_key,
            client_key,
            KDC_CHALLENGE_ARMOR_PEPPER,
            CHALLENGE_LONG_TERM_PEPPER,
        )
        .map_err(internal)?;
        let timestamp = PaEncTsEnc {
            patimestamp: *now,
            pausec: None,
        }
        .encode()
        .map_err(internal)?;
        let challenge = EncryptedData {
            etype: armor_enctype.number(),
            kvno: None,
            cipher: seal(
                entropy,
                &kdc_challenge_key,
                KEY_USAGE_ENC_CHALLENGE_KDC,
                &timestamp,
            )?,
        };
        drop(kdc_challenge_key);
        let challenge_padata = PaData {
            padata_type: PA_ENCRYPTED_CHALLENGE,
            padata_value: challenge.encode().map_err(internal)?,
        };

        // 5. KrbFastFinished over the issued ticket's DER.
        let ticket_octets = ticket.encode().map_err(internal)?;
        let cksumtype = armor_enctype.checksum_type();
        let ticket_checksum = krb_crypto::get_mic(
            &self.armor_key,
            cksumtype,
            key_usage(KEY_USAGE_FAST_FINISHED)?,
            &ticket_octets,
        )
        .map_err(internal)?;
        let finished = KrbFastFinished {
            timestamp: *now,
            usec: Microseconds::default(),
            crealm: crealm.clone(),
            cname: cname.clone(),
            ticket_checksum: Checksum {
                cksumtype: cksumtype.number(),
                checksum: ticket_checksum,
            },
        };

        // 6. The KrbFastResponse under the armor key (usage 52). The
        // strengthen key's copy lives in a zeroizing KeyValue and the
        // encoding in a Zeroizing buffer.
        let response = KrbFastResponse {
            padata: vec![challenge_padata],
            strengthen_key: Some(EncryptionKey {
                keytype: strengthen.enc_type().number(),
                keyvalue: KeyValue::from_slice(strengthen.octets()),
            }),
            finished: Some(finished),
            nonce: self.req_nonce,
        };
        drop(strengthen);
        let plain: Zeroizing<Vec<u8>> = response.encode().map_err(internal)?;
        drop(response);
        let cipher = seal(entropy, &self.armor_key, KEY_USAGE_FAST_REP, &plain)?;
        Ok(ArmoredAsReply {
            enc_part_cipher,
            fast_rep: EncryptedData {
                etype: armor_enctype.number(),
                kvno: None,
                cipher,
            },
        })
    }
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
    /// the armor key and the inner nonce / realm / cname / sname / etype list
    /// are stored under a fresh armor id bound to this caller, with its one
    /// pre-authentication attempt still open.
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
            req_etypes: body.etype.clone(),
            preauth_attempted: false,
            bound_proof: None,
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
    /// It answers any refusal after the armor was opened — including a
    /// refused armored `verify_preauth` or `issue_as_rep`, which leave the
    /// armor live for this purpose (docs/48 §4.1 A10, A13).
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
