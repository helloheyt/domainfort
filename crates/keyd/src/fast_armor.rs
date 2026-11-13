//! The FAST armor core inside keyd: `open_fast_armor` (an armored AS
//! request's FX_FAST_ARMOR_AP_REQUEST armor and KrbFastReq) and
//! `seal_fast_error` (the armored KRB-ERROR of an AS or a TGS conversation),
//! plus the helpers the armored TGS exchange shares with them (the armor key,
//! opening a KrbFastArmoredReq, the strengthened reply and the sealed
//! KrbFastResponse). Role `Kdc` only.
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
//! The TGS conversation (docs/48 §5, task T3) has no armor token of its own:
//! its implicit armor key lives in the TGS context that the armored
//! `open_and_verify_tgt` opens (crate::tgs_exchange), and that context id is
//! what `seal_fast_error(Tgs)` consumes:
//! ```text
//! open_and_verify_tgt(fast) ─(ctx, armored)─► issue_tgs_rep(ctx) | seal_fast_error(Tgs(ctx))
//! ```
//!
//! The armored AS reply (docs/48 §4.3, §4.4) is built here too
//! (`ArmorEntry::seal_as_reply`): a fresh strengthen key, the reply key
//! KRB-FX-CF2(strengthen key, client key, "strengthenkey", "replykey"), the
//! KDC's PA-ENCRYPTED-CHALLENGE, KrbFastFinished with the ticket-checksum,
//! and the KrbFastResponse sealed in the armor key — the strengthening and
//! the finished response are the helpers [`seal_strengthened`] and
//! [`seal_fast_reply`], which the armored TGS reply uses too. No FAST key —
//! armor, challenge, strengthen, reply — leaves keyd; the strengthen key
//! leaves only inside the sealed `fast_rep`.
//!
//! **Computer-account-only armor (D126) is not checked here:** keyd holds no
//! account kind. keyd verifies the armor TGT cryptographically and returns
//! its crealm / cname / authtime; the KDC (PEP) maps them to an account and
//! refuses a non-computer, disabled or revoked armor principal (docs/48
//! §3.1, task T5).
//!
//! Not here (docs/48 §12): anonymous armor; an explicit armor in a TGS
//! request (refused, Q-124); any armor type other than
//! FX_FAST_ARMOR_AP_REQUEST; any FAST factor other than encrypted challenge.
//!
//! Spec: RFC 6113 5.1, 5.4, 5.4.1, 5.4.1.1, 5.4.2, 5.4.3, 5.4.4, 5.4.6, 6.2;
//! RFC 4120 3.2.3, 5.2.7.2, 5.4.2, 5.5.1, 5.9.1, 7.5.1; RFC 3961 §3; docs/48
//! §2.3, §3, §4, §5, §6, §9; docs/questions/Q-120..Q-124 (A-32), Q-150; A-26.

use crate::as_exchange::token_deny;
use crate::audit::{AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::entropy::EntropySource;
use crate::error::{AuthnError, Deny, Error, Internal};
use crate::keyd::{draw, key_usage, new_random_key, open, seal, AuditFields, Keyd};
use crate::model::KeyHandle;
use crate::store::KeyStore;
use crate::template::tgs_name;
use crate::tgs_exchange::{check_ap_options, replay_key_for, subkey_protocol_key, OpenedApReq};
use crate::time::kerberos_time_seconds;
use crate::tokens::{ArmorId, TOKEN_ID_LENGTH};
use crate::usage::{
    AP_REQ_AUTHENTICATOR, AS_REP_ENC_PART, KEY_USAGE_ENC_CHALLENGE_KDC, KEY_USAGE_FAST_ENC,
    KEY_USAGE_FAST_FINISHED, KEY_USAGE_FAST_REP, KEY_USAGE_FAST_REQ_CHKSUM,
};
use keyd_types::{FastArmor, FastConversation, MAX_FX_COOKIE_LENGTH};
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

// `MAX_FX_COOKIE_LENGTH`, `FastArmor` and `FastConversation` — the public
// bound and the argument / result types of the FAST operations — live in the
// crypto-free keyd-types crate (D182; decision A-63) and are re-exported at
// the crate root.

/// An armored conversation as `seal_fast_error` sees it, built from the
/// consumed token of either conversation: the armor key, the nonce of the
/// inner request, and the names a KRB-ERROR answering that request must
/// carry. Never leaves keyd; the armor key is zeroized when it is dropped.
///
/// Spec: docs/48 §2.3, §6.1; RFC 6113 5.4.3 (nonce "from the client
/// request"), 5.4.4; RFC 4120 5.9.1 (realm / sname: the service; crealm /
/// cname: the client).
pub(crate) struct ArmoredConversation {
    /// The conversation's armor key.
    pub(crate) armor_key: ProtocolKey,
    /// The nonce of the stored inner request.
    pub(crate) nonce: u32,
    /// The KRB-ERROR's realm must be this one.
    pub(crate) realm: Realm,
    /// The KRB-ERROR's sname must be this one.
    pub(crate) sname: PrincipalName,
    /// The KRB-ERROR's crealm, when present, must be this one.
    pub(crate) crealm: Realm,
    /// The KRB-ERROR's cname, when present, must be this one (`None`: no
    /// cname is acceptable).
    pub(crate) cname: Option<PrincipalName>,
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

/// armor_key = KRB-FX-CF2(subkey, ticket_session_key, "subkeyarmor",
/// "ticketarmor"), of the subkey's enctype (k1). This is the
/// FX_FAST_ARMOR_AP_REQUEST armor key of an AS request and also the implicit
/// armor key of a TGS request, which RFC 6113 5.4.2 defines as "the same
/// armor key that would be computed if the TGS-REQ authenticator was used in
/// an FX_FAST_ARMOR_AP_REQUEST armor".
/// Spec: RFC 6113 5.1, 5.4.1.1, 5.4.2.
pub(crate) fn ticket_armor_key(
    subkey: &ProtocolKey,
    ticket_session_key: &ProtocolKey,
) -> Internal<ProtocolKey> {
    krb_crypto::krb_fx_cf2(
        subkey,
        ticket_session_key,
        SUBKEY_ARMOR_PEPPER,
        TICKET_ARMOR_PEPPER,
    )
    .map_err(internal)
}

/// Open a KrbFastArmoredReq under its armor key — shared by
/// `open_fast_armor` (AS) and the armored `open_and_verify_tgt` (TGS):
/// 1. the req-checksum is of "the required checksum type for the enctype of
///    the armor key" and verifies, keyed with the armor key and key usage 50,
///    over `checksummed` — "the type KDC-REQ-BODY for the req-body field" of
///    an AS-REQ, "the type AP-REQ in the PA-TGS-REQ padata" of a TGS-REQ;
/// 2. enc-fast-req is of the armor key's enctype, decrypts with key usage 51
///    and decodes as KrbFastReq (the plaintext buffer is zeroized).
///
/// Every failure is the uniform `Denied` (A-26: it precedes the end of the
/// caller's chain).
///
/// Spec: RFC 6113 5.4.2 (req-checksum, enc-fast-req), 6.2; RFC 3961 §3
/// (required checksum mechanism).
pub(crate) fn open_armored_request(
    armor_key: &ProtocolKey,
    armored_req: &KrbFastArmoredReq,
    checksummed: &[u8],
) -> Internal<KrbFastReq> {
    // 1. The req-checksum (usage 50).
    let req_checksum = &armored_req.req_checksum;
    let cksumtype = ChecksumType::from_number(req_checksum.cksumtype)
        .ok()
        .filter(|t| *t == armor_key.enc_type().checksum_type())
        .ok_or(Deny::denied(AuditReason::ChecksumUnsupported))?;
    krb_crypto::verify_mic(
        armor_key,
        cksumtype,
        key_usage(KEY_USAGE_FAST_REQ_CHKSUM)?,
        checksummed,
        &req_checksum.checksum,
    )
    .map_err(|_| Deny::denied(AuditReason::FastChecksumMismatch))?;

    // 2. enc-fast-req (usage 51).
    let enc_fast_req = &armored_req.enc_fast_req;
    if enc_fast_req.etype != armor_key.enc_type().number() {
        return Err(Deny::denied(AuditReason::UnsupportedEncType));
    }
    let fast_req_plain: Zeroizing<Vec<u8>> =
        open(armor_key, KEY_USAGE_FAST_ENC, &enc_fast_req.cipher)?;
    KrbFastReq::decode(&fast_req_plain).map_err(|_| Deny::denied(AuditReason::MalformedInput))
}

/// The strengthened reply key and the enc-part sealed in it (docs/48 §4.3,
/// §5.2):
/// 1. strengthen key: random, of the padata reply key's enctype — "the same
///    etype as that of the reply key before being strengthened";
/// 2. reply key = KRB-FX-CF2(strengthen key, padata reply key,
///    "strengthenkey", "replykey"), of that enctype too (the enctype of k1);
/// 3. `rep_plain` sealed in the reply key with `usage` — 3 for EncASRepPart,
///    9 for EncTGSRepPart (docs/questions/Q-121 (a)).
///
/// Returns the strengthen key — it leaves keyd only inside the sealed
/// KrbFastResponse ([`seal_fast_reply`]) — and the cipher. The reply key is
/// zeroized on return.
///
/// Spec: RFC 6113 5.1, 5.4.3; RFC 3961 §3 (random-to-key); RFC 4120 5.4.2
/// (usages 3, 9); docs/questions/Q-121 (A-32).
pub(crate) fn seal_strengthened<E: EntropySource>(
    entropy: &mut E,
    padata_reply_key: &ProtocolKey,
    usage: u32,
    rep_plain: &[u8],
) -> Internal<(ProtocolKey, Vec<u8>)> {
    let strengthen = new_random_key(entropy, padata_reply_key.enc_type())?;
    let reply_key = krb_crypto::krb_fx_cf2(
        &strengthen,
        padata_reply_key,
        STRENGTHEN_KEY_PEPPER,
        REPLY_KEY_PEPPER,
    )
    .map_err(internal)?;
    let cipher = seal(entropy, &reply_key, usage, rep_plain)?;
    drop(reply_key);
    Ok((strengthen, cipher))
}

/// KrbFastFinished and the KrbFastResponse of a reply that returns a ticket,
/// sealed in the armor key (docs/48 §4.4, §5.2):
/// - KrbFastFinished: timestamp = `now`, usec = 0 (keyd reads no clock;
///   docs/48 §4.4), crealm / cname of the issued ticket's client ("identify
///   the authenticated client"), ticket-checksum = get_mic(armor key, its
///   required checksum type, usage 53, the DER of `ticket` — the full
///   `[APPLICATION 1]` Ticket as it stands in the KDC-REP,
///   docs/questions/Q-122 (a));
/// - KrbFastResponse { `padata`, strengthen-key, finished, `nonce` } sealed
///   in the armor key, usage 52, without kvno.
///
/// The strengthen key's copy lives in a zeroizing KeyValue and the encoding
/// in a Zeroizing buffer; the strengthen key itself is dropped (zeroized)
/// here.
///
/// Spec: RFC 6113 5.4.3 (strengthen-key, finished "present in an AS-REP or
/// a TGS-REP when a ticket is returned", nonce, KEY_USAGE_FAST_REP /
/// FINISHED), 6.2; RFC 4120 5.6.1 (timestamp / usec semantics); RFC 3961 §3
/// (required checksum mechanism); docs/questions/Q-122 (A-32).
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_fast_reply<E: EntropySource>(
    entropy: &mut E,
    armor_key: &ProtocolKey,
    padata: Vec<PaData>,
    strengthen: ProtocolKey,
    ticket: &Ticket,
    crealm: &Realm,
    cname: &PrincipalName,
    nonce: u32,
    now: &KerberosTime,
) -> Internal<EncryptedData> {
    let armor_enctype = armor_key.enc_type();

    // KrbFastFinished over the issued ticket's DER (usage 53).
    let ticket_octets = ticket.encode().map_err(internal)?;
    let cksumtype = armor_enctype.checksum_type();
    let ticket_checksum = krb_crypto::get_mic(
        armor_key,
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

    // The KrbFastResponse under the armor key (usage 52).
    let response = KrbFastResponse {
        padata,
        strengthen_key: Some(EncryptionKey {
            keytype: strengthen.enc_type().number(),
            keyvalue: KeyValue::from_slice(strengthen.octets()),
        }),
        finished: Some(finished),
        nonce,
    };
    drop(strengthen);
    let plain: Zeroizing<Vec<u8>> = response.encode().map_err(internal)?;
    drop(response);
    let cipher = seal(entropy, armor_key, KEY_USAGE_FAST_REP, &plain)?;
    Ok(EncryptedData {
        etype: armor_enctype.number(),
        kvno: None,
        cipher,
    })
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
    ///    "another key selected via pre-authentication mechanisms") — steps
    ///    1-3 are [`seal_strengthened`];
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
    ///    sealed in the armor key, usage 52, without kvno — steps 5-6 are
    ///    [`seal_fast_reply`].
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
        let (strengthen, enc_part_cipher) =
            seal_strengthened(entropy, client_key, AS_REP_ENC_PART, rep_plain)?;

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

        // 5-6. KrbFastFinished and the KrbFastResponse under the armor key.
        let fast_rep = seal_fast_reply(
            entropy,
            &self.armor_key,
            vec![challenge_padata],
            strengthen,
            ticket,
            crealm,
            cname,
            self.req_nonce,
            now,
        )?;
        Ok(ArmoredAsReply {
            enc_part_cipher,
            fast_rep,
        })
    }

    /// The conversation `seal_fast_error(As)` answers: the armor key, the
    /// stored inner nonce, and the inner request's names — realm, sname (or
    /// this realm's TGS name when it had none, the KDC's KRB-ERROR rule),
    /// crealm = the inner realm, cname = the inner cname.
    /// Spec: docs/48 §2.3, §6.1, §8 (names of the inner request); RFC 4120
    /// 5.4.1 (realm: in the AS exchange also the client's realm), 5.9.1.
    pub(crate) fn into_conversation(self, realm: &Realm) -> ArmoredConversation {
        ArmoredConversation {
            armor_key: self.armor_key,
            nonce: self.req_nonce,
            realm: self.req_realm.clone(),
            sname: self.req_sname.unwrap_or_else(|| tgs_name(realm)),
            crealm: self.req_realm,
            cname: self.req_cname,
        }
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
    /// 1. authorize and admit (Kdc; krbtgt handle Krbtgt);
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
        self.admit(
            caller,
            Operation::OpenFastArmor,
            &[(HandleSlot::Primary, krbtgt)],
            now,
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
        let OpenedApReq {
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
        let subkey = subkey_protocol_key(subkey, &self.enctypes)?;

        // 6. The armor key; its enctype is the subkey's (k1). Spec: RFC 6113
        // 5.1, 5.4.1.1.
        let armor_key = ticket_armor_key(&subkey, &session)?;
        drop(subkey);
        drop(session);

        // 7-8. The req-checksum over the outer KDC-REQ-BODY (usage 50), then
        // enc-fast-req (usage 51). Spec: RFC 6113 5.4.2; RFC 3961 §3.
        let fast_req = open_armored_request(&armor_key, armored_req, outer_req_body)?;

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

    /// `seal_fast_error`: consume the conversation's token and seal the
    /// enc-fast-rep of an armored KRB-ERROR — a KrbFastResponse carrying the
    /// allowed `padata` plus PA-FX-ERROR (the DER of `error`), no
    /// strengthen-key, no finished, and the nonce of the inner request keyd
    /// stored (not one from the caller), encrypted in the armor key with key
    /// usage 52.
    ///
    /// It answers any refusal after the armor was opened — including a
    /// refused armored `verify_preauth` or `issue_as_rep`, which leave the
    /// armor live for this purpose (docs/48 §4.1 A10, A13), and a refused
    /// armored `issue_tgs_rep`, which leaves its context live likewise
    /// (docs/questions/Q-150).
    ///
    /// The KDC frames the result (KRB-ERROR e-data = METHOD-DATA with
    /// PA-FX-FAST, RFC 6113 5.4.4). keyd checks the content so that a
    /// compromised KDC can only ever have an error sealed — never a reply
    /// that reads as success (docs/48 §6.1):
    /// 1. authorize and admit (Kdc; no handle — the conversation token is the
    ///    authority);
    /// 2. consume the token: live, issued to this caller (`Denied`
    ///    otherwise; destroyed either way) — `As`: the armor id; `Tgs`: the
    ///    context id, which must name an ARMORED context (a context opened
    ///    without FAST has no armor key: `Denied`, consumed too);
    /// 3. `error`: no e-data ("MUST be absent in the PA-FX-ERROR"), no
    ///    e-text (docs/48 §2.3), an error code other than KDC_ERR_NONE,
    ///    stime = `now`, realm = the inner request's realm, sname = the inner
    ///    request's sname (or this realm's TGS name when it had none — the
    ///    KDC's KRB-ERROR rule), crealm / cname, when present, the client's —
    ///    `As`: the inner request's; `Tgs`: the TGT's (the KDC's TGS errors
    ///    name the TGT's client once it is known);
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
    /// 7.5.9 (KDC_ERR_NONE); docs/48 §2.3, §5, §6.1; docs/questions/Q-125,
    /// Q-150.
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
        self.admit(caller, Operation::SealFastError, &[], now)?;
        let now_s = kerberos_time_seconds(now);

        // 2. The conversation's token (I4), consumed either way.
        let realm = &self.config.realm;
        let conversation = match conversation {
            FastConversation::As(armor_id) => self
                .armors
                .take(armor_id.as_bytes(), caller, now_s)
                .map_err(token_deny)?
                .into_conversation(realm),
            FastConversation::Tgs(ctx_id) => self
                .contexts
                .take(ctx_id.as_bytes(), caller, now_s)
                .map_err(token_deny)?
                .into_fast_conversation(realm)
                .ok_or(Deny::denied(AuditReason::ArmorConversationMismatch))?,
        };

        // 3. The error content.
        check_fast_error(error, &conversation, now)?;

        // 4. The padata, then PA-FX-ERROR.
        let mut response_padata = allowed_fast_error_padata(padata, &self.enctypes)?;
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
            nonce: conversation.nonce,
        };
        let plain: Zeroizing<Vec<u8>> = response
            .encode()
            .map_err(|_| Deny::unavailable(AuditReason::InternalFailure))?;
        drop(response);
        let armor_key = &conversation.armor_key;
        let cipher = seal(&mut self.entropy, armor_key, KEY_USAGE_FAST_REP, &plain)?;
        Ok(EncryptedData {
            etype: armor_key.enc_type().number(),
            kvno: None,
            cipher,
        })
    }
}

/// The KRB-ERROR checks of `seal_fast_error` step 3: an error, bound to the
/// request being answered, with nothing keyd does not seal. Failure is
/// `Denied` (reason `FastErrorContentRefused`).
///
/// Spec: RFC 6113 5.4.4 ("The e-data field MUST be absent in the
/// PA-FX-ERROR"; "All other fields should be the same as the outer
/// KRB-ERROR"); RFC 4120 5.9.1, 7.5.9; docs/48 §2.3, §6.1, §8 (names of the
/// inner request).
fn check_fast_error(
    error: &KrbError,
    conversation: &ArmoredConversation,
    now: &KerberosTime,
) -> Internal<()> {
    let acceptable = error.e_data.is_none()
        && error.e_text.is_none()
        && error.error_code > KDC_ERR_NONE
        && error.stime == *now
        && error.realm == conversation.realm
        && error.sname == conversation.sname
        && error
            .crealm
            .as_ref()
            .is_none_or(|crealm| *crealm == conversation.crealm)
        && error
            .cname
            .as_ref()
            .is_none_or(|cname| conversation.cname.as_ref() == Some(cname));
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
