//! The AS exchange inside keyd: `verify_preauth` and `issue_as_rep`, without
//! armor (PA-ENC-TIMESTAMP) and with FAST armor (the encrypted challenge FAST
//! factor and the armored reply, docs/48 §4). Role `Kdc` only.
//!
//! State machine: `verify_preauth ──(AuthnProof)──► issue_as_rep`. Issuance
//! without a valid, unexpired, unused proof bound to the same caller and the
//! same client is not expressible (I4). Under FAST the proof is also bound to
//! the armor of its conversation, both ways (docs/48 §2.3): an armored proof
//! issues only with that armor, an unarmored proof only without one.
//!
//! `issue_as_rep` builds the EncTicketPart and EncASRepPart itself from a
//! validated template, draws the session key from the entropy source, seals
//! the ticket under the CURRENT krbtgt key and the reply under the client key
//! that pre-authenticated — or, under FAST, under the reply key strengthened
//! with a fresh strengthen key — and returns only sealed blobs: the session
//! key, the strengthen key and the reply key never leave keyd (docs/10 §4
//! steps 1-7; docs/48 §2.2, §4.3).
//!
//! Phase 1 issues no PAC (MS-PAC / NDR is phase 2, where D124 applies):
//! tickets carry no authorization-data. Tickets are addressless (no caddr;
//! RFC 4120 5.3 recommends allowing addressless tickets). The transited
//! field is empty (local authentication, RFC 4120 3.3.3.2).
//!
//! Spec: RFC 4120 3.1.2, 3.1.3, 5.2.7.2, 5.3, 5.4.2, 7.3, 7.5.1; RFC 6113
//! 5.1, 5.4, 5.4.3, 5.4.6, 6.2, 8; docs/10 §4, §8; docs/30 §2; docs/48 §2.3,
//! §4.

use crate::audit::{AuditKeyRef, AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::entropy::EntropySource;
use crate::error::{AuthnError, Deny, Internal, IssueError};
use crate::keyd::{authorize, draw, new_random_key, open, seal, AuditFields, Keyd};
use crate::model::{KeyHandle, KeyPurpose, Kvno, PrincipalId};
use crate::store::{KeyStore, KvnoKeys};
use crate::template::{as_ticket_flags, check_binding, check_times, tgs_name, TemplateTimes};
use crate::throttle::SecretThrottle;
use crate::time::{kerberos_time_seconds, within_skew};
use crate::tokens::{ArmorId, ExchangeId, TokenRefusal, TOKEN_ID_LENGTH};
use crate::usage::{
    AS_REP_ENC_PART, AS_REQ_PA_ENC_TIMESTAMP, KEY_USAGE_ENC_CHALLENGE_CLIENT, TICKET_ENC_PART,
};
use krb_crypto::{EncType, ProtocolKey};
use krb_proto::constants::{DOMAIN_X500_COMPRESS, PA_ENCRYPTED_CHALLENGE, PA_ENC_TIMESTAMP};
use krb_proto::{
    EncAsRepPart, EncKdcRepPart, EncTicketPart, EncryptedChallenge, EncryptedData, EncryptionKey,
    KerberosTime, KeyValue, LastReq, PaData, PaEncTimestamp, PaEncTsEnc, PrincipalName, Realm,
    Ticket, TicketFlags, TransitedEncoding,
};
use zeroize::Zeroizing;

/// Proof that pre-authentication succeeded, returned by `verify_preauth`
/// and consumed by `issue_as_rep`. It binds the issuance to this exchange,
/// this caller and this client; it is short-lived and single-use. It carries
/// no decrypted plaintext (no decryption oracle, docs/10 §4).
///
/// The expiry is tracked inside keyd (docs/10 `expires: Instant`).
///
/// Spec: docs/10 §4 (`struct AuthnProof`), §8, D36.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnProof {
    /// The one-time exchange token.
    pub exchange_id: ExchangeId,
    /// The pre-authenticated principal.
    pub client: PrincipalId,
    /// The authentication time (the caller's `now` at pre-authentication;
    /// RFC 4120 5.3 authtime of an AS ticket is the KDC's current time).
    pub authtime: KerberosTime,
}

/// What keyd remembers about a live AuthnProof (never leaves keyd).
pub(crate) struct ProofEntry {
    principal: PrincipalId,
    authtime: KerberosTime,
    reply_enctype: EncType,
    reply_kvno: Kvno,
    /// The armor of an armored pre-authentication; `None` without armor.
    /// Spec: docs/48 §2.3 ("the internal AuthnProof remembers the
    /// armor_id").
    armor: Option<[u8; TOKEN_ID_LENGTH]>,
}

/// The client key that passed a pre-authentication check: the enctype and
/// the key version the reply will be sealed for.
/// Spec: RFC 6113 2.1 ("the KDC SHOULD pick the same key as the reply key");
/// RFC 4120 5.4.2 (client kvno in the AS-REP enc-part).
struct PreauthKey {
    enctype: EncType,
    kvno: Kvno,
}

/// The KDC's request for a TGT. keyd fills in the session key, the realm,
/// authtime, transited and the INITIAL / PRE-AUTHENT flags itself.
///
/// Spec: docs/10 §4 (`struct TicketTemplate`); RFC 4120 5.3, 5.4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsTicketTemplate {
    /// The client; must be the principal the proof is bound to.
    pub client: PrincipalId,
    /// Client realm; must be the configured realm (single realm, phase 1).
    pub crealm: Realm,
    /// Client name (RFC 4120 5.3 cname). Must identify the principal name
    /// the client key set is bound to (realm + name-string, RFC 4120 6.2;
    /// docs/questions/Q-040, A-19) — otherwise `Denied`. Canonicalization
    /// (case, aliases, enterprise names) is the KDC's job before the call.
    pub cname: PrincipalName,
    /// Server name; must be this realm's TGS name, NT-SRV-INST ("krbtgt",
    /// realm), because the ticket is sealed under the krbtgt key
    /// (RFC 4120 7.3).
    pub sname: PrincipalName,
    /// Requested starttime; must be within the clock skew of now (no
    /// postdating). `None` = authtime is the start (RFC 4120 5.3).
    pub starttime: Option<KerberosTime>,
    /// Expiration time.
    pub endtime: KerberosTime,
    /// Renew-till; present exactly when RENEWABLE is requested.
    pub renew_till: Option<KerberosTime>,
    /// Requested flags; must lie in the configured allowed mask.
    pub flags: TicketFlags,
    /// Session-key encryption type; must be configured (I5).
    pub session_enctype: EncType,
    /// The AS-REQ nonce, echoed in EncASRepPart (RFC 4120 5.4.2).
    pub nonce: u32,
}

/// The sealed AS-REP parts: the ticket (sealed under krbtgt), the enc-part
/// (sealed under the client key, or under the strengthened reply key when
/// armored) and, when armored, the enc-fast-rep. The KDC assembles the
/// AS-REP (and, when armored, its PA-FX-FAST padata around `fast_rep`).
///
/// Spec: docs/10 §4 (`struct AsRep { ticket: Sealed, enc_part: Sealed }`);
/// docs/48 §2.3 (`fast_rep: Option<Sealed>`), §4.1 A14; RFC 4120 5.4.2; RFC
/// 6113 5.4.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsRepParts {
    /// `ticket [5] Ticket`.
    pub ticket: Ticket,
    /// `enc-part [6] EncryptedData` (EncASRepPart, key usage 3, client
    /// kvno).
    pub enc_part: EncryptedData,
    /// `enc-fast-rep` of the KrbFastArmoredRep (the KrbFastResponse sealed
    /// in the armor key, key usage 52): `Some` exactly when the issuance was
    /// armored. Spec: RFC 6113 5.4.3; docs/48 §2.3.
    pub fast_rep: Option<EncryptedData>,
}

impl ProofEntry {
    /// The principal whose PrincipalLongterm key pre-authenticated. A proof
    /// is discarded when that key set is destroyed (A-35).
    /// Spec: docs/10 §8, §12 I4; docs/questions/Q-115 (A-35).
    pub(crate) fn principal(&self) -> PrincipalId {
        self.principal
    }
}

/// Map a token refusal to its audit reason. Spec: docs/10 §8, D36.
pub(crate) fn token_deny(refusal: TokenRefusal) -> Deny {
    Deny::denied(match refusal {
        TokenRefusal::Unknown => AuditReason::TokenUnknown,
        TokenRefusal::Expired => AuditReason::TokenExpired,
        TokenRefusal::CallerMismatch => AuditReason::TokenCallerMismatch,
    })
}

/// The client long-term key of an encrypted challenge (docs/questions/Q-123
/// option (a), decided A-32): the first enctype of the inner req-body's
/// etype list (the client's order) that is configured (I5) and for which the
/// client's CURRENT key version holds a key. The EncryptedChallenge itself
/// names no long-term key — its etype is the challenge key's — so keyd
/// computes the one key it accepts from what it stored, and tries no other
/// (no per-key trial decryption, I6). The KDC advertises the same single
/// entry in PA-ETYPE-INFO2 (RFC 6113 2.1: "KDC implementations MAY choose to
/// offer only one key").
/// Spec: RFC 4120 3.1.3 ("the KDC SHOULD use the first valid strong etype
/// for which an encryption key is available"); RFC 6113 2.1, 5.4.6;
/// docs/48 §4.5 step 3.
fn challenge_long_term_key<'a>(
    version: &'a KvnoKeys,
    requested: &[i32],
    supported: &[EncType],
) -> Option<(EncType, &'a ProtocolKey)> {
    requested.iter().find_map(|number| {
        let enctype = EncType::from_number(*number)
            .ok()
            .filter(|e| supported.contains(e))?;
        version.key_for(enctype).map(|key| (enctype, key))
    })
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// `verify_preauth`: verify the pre-authentication of `client` and
    /// return a one-time [`AuthnProof`] — PA-ENC-TIMESTAMP when `armor` is
    /// `None`; the encrypted challenge FAST factor (PA-ENCRYPTED-CHALLENGE)
    /// under the FAST armor `armor` otherwise. Any other combination is
    /// refused: a FAST factor "MUST NOT be used outside of FAST" (RFC 6113
    /// 5.4), and inside FAST encrypted challenge is the only factor in phase 1
    /// (docs/48 §4.5 — the KDC ignores a PA-ENC-TIMESTAMP inside FAST and
    /// never passes it here; keyd refuses it if it does).
    ///
    /// Throttle first (decision A-34): right after authorization and BEFORE
    /// any secret work, the per-principal failure throttle must admit the
    /// attempt — the same mechanism and semantics as `verify_secret`
    /// (bounded table, self-expiring window, fail closed when full of live
    /// windows), with its own policy ([`crate::KeydConfig::preauth_throttle`]).
    /// A refused attempt is the uniform `AuthnError::Denied` (it is decided
    /// before the cryptographic chain, A-26); audit records it as
    /// `Throttled`. Only a failure of the cryptographic check itself — the
    /// timestamp does not decrypt under the client key, or the challenge
    /// does not decrypt under the challenge key — counts as a failure, in
    /// the one per-principal count shared by both paths; a success (a proof
    /// issued) clears the principal's count, as in `verify_secret`; every
    /// other refusal leaves the count unchanged.
    ///
    /// **Without armor** — checks failing as the uniform `AuthnError::Denied`:
    /// padata-type is PA-ENC-TIMESTAMP (2); the padata-value decodes as
    /// EncryptedData; its etype is configured (I5) and the client's CURRENT
    /// key version has a key of that type (a kvno, if present, must be the
    /// current one — a superseded password never pre-authenticates);
    /// decryption with key usage 1 succeeds; the plaintext decodes as
    /// PA-ENC-TS-ENC. Then, and only then: patimestamp is within the clock
    /// skew of `now`, else `AuthnError::Skew` (A-26). Only a holder of the
    /// client key reaches the skew check, so a wrong password still cannot be
    /// told apart from an unknown key or kvno — no password oracle.
    ///
    /// **With armor** (docs/48 §4.5) — checks failing as `Denied`:
    /// 1. the armor is live and this caller's (an armor presented by another
    ///    caller is destroyed), and its ONE pre-authentication attempt is
    ///    still open; the attempt is taken now, whatever follows;
    /// 2. padata-type is PA-ENCRYPTED-CHALLENGE (138); the value decodes as
    ///    EncryptedChallenge, of the armor key's enctype (the challenge key's,
    ///    RFC 6113 5.1), without kvno (the challenge key is no long-lasting
    ///    key, RFC 4120 5.2.9; docs/questions/Q-145);
    /// 3. the long-term key (K2) is chosen by keyd alone from the stored
    ///    inner etype list (`challenge_long_term_key`, Q-123);
    /// 4. challenge key = KRB-FX-CF2(armor key, K2, "clientchallengearmor",
    ///    "challengelongterm"); decryption with key usage 54 succeeds and the
    ///    plaintext decodes as PA-ENC-TS-ENC;
    /// 5. only then (A-26): patimestamp outside the clock skew → `Skew`
    ///    (which the KDC answers with KRB_AP_ERR_SKEW, armored — RFC 6113
    ///    5.4.6, docs/48 R48-6, §6.3).
    ///
    /// The proof is bound to (client, armor, enctype, kvno), and the armor to
    /// the proof. Replay of an encrypted challenge ("the ciphertext MUST be
    /// identical", RFC 6113 5.4.6) needs no cache of its own: the challenge
    /// key depends on the armor key, whose armor AP-REQ is in the replay
    /// cache, and each armor allows one attempt (docs/48 §3.3). A refusal
    /// leaves the armor live for the armored error (docs/48 §4.1 A10).
    ///
    /// Spec: RFC 4120 5.2.7.2 ("encrypted using the client's secret key and a
    /// key usage value of 1"), 7.5.1 (usage 1), 3.1.3 (KDC_ERR_PREAUTH_FAILED),
    /// 5.2.9 (kvno); RFC 6113 5.1, 5.4, 5.4.6 (challenge keys, usage 54), 6.2,
    /// 8 (factors bound to the conversation); docs/10 §4, §6 (throttling);
    /// docs/30 §2.3; docs/48 §2.3, §4.5; A-26 (docs/questions/Q-071); A-34
    /// (throttle); docs/questions/Q-123 (A-32).
    pub fn verify_preauth(
        &mut self,
        caller: &CallerId,
        client: &KeyHandle,
        padata: &PaData,
        armor: Option<ArmorId>,
        now: &KerberosTime,
    ) -> Result<AuthnProof, AuthnError> {
        let mut fields = AuditFields::for_handle(client);
        let result = self.verify_preauth_inner(caller, client, padata, armor, now, &mut fields);
        self.emit(caller, Operation::VerifyPreauth, now, &fields, &result);
        result.map_err(AuthnError::from)
    }

    fn verify_preauth_inner(
        &mut self,
        caller: &CallerId,
        client: &KeyHandle,
        padata: &PaData,
        armor: Option<ArmorId>,
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<AuthnProof> {
        authorize(
            caller,
            Operation::VerifyPreauth,
            &[(HandleSlot::Primary, client)],
        )?;
        let now_s = kerberos_time_seconds(now);
        // The failure throttle, before any secret work (A-34). `rate_limited`
        // keeps the audit outcome; the caller sees `Denied` (no class).
        if !self.preauth_throttle.admit(&client.principal, now_s) {
            return Err(Deny::rate_limited(AuditReason::Throttled));
        }
        let verified = match &armor {
            None => self.check_enc_timestamp(client, padata, now_s, fields)?,
            Some(armor_id) => {
                self.check_encrypted_challenge(caller, client, padata, armor_id, now_s, fields)?
            }
        };
        let mut id = [0u8; TOKEN_ID_LENGTH];
        draw(&mut self.entropy, &mut id)?;
        // The armor remembers the proof, the proof remembers the armor
        // (docs/48 §2.3). The armor was found live at `now` above.
        let armor = armor.map(|armor_id| *armor_id.as_bytes());
        if let Some(armor_id) = &armor {
            self.armors
                .peek_mut(armor_id, caller, now_s)
                .map_err(token_deny)?
                .bind_proof(id);
        }
        let entry = ProofEntry {
            principal: client.principal,
            authtime: *now,
            reply_enctype: verified.enctype,
            reply_kvno: verified.kvno,
            armor,
        };
        let expires_at = now_s + i64::from(self.config.token_lifetime_secs);
        if !self.proofs.insert(id, *caller, expires_at, entry, now_s) {
            return Err(Deny::unavailable(AuditReason::TokenTableFull));
        }
        // A success clears the principal's failure count, as in
        // verify_secret (A-34).
        self.preauth_throttle.record(&client.principal, true, now_s);
        Ok(AuthnProof {
            exchange_id: ExchangeId::from_bytes(id),
            client: client.principal,
            authtime: *now,
        })
    }

    /// The unarmored check of `verify_preauth`: PA-ENC-TIMESTAMP under the
    /// client's current key (see [`Self::verify_preauth`]).
    /// Spec: RFC 4120 5.2.7.2, 5.2.9, 7.5.1; A-26; A-34.
    fn check_enc_timestamp(
        &mut self,
        client: &KeyHandle,
        padata: &PaData,
        now_s: i64,
        fields: &mut AuditFields,
    ) -> Internal<PreauthKey> {
        if padata.padata_type != PA_ENC_TIMESTAMP {
            return Err(Deny::denied(AuditReason::UnsupportedPadataType));
        }
        let enc = PaEncTimestamp::decode(&padata.padata_value)
            .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        let enctype = EncType::from_number(enc.etype)
            .ok()
            .filter(|e| self.config.supports(*e))
            .ok_or(Deny::denied(AuditReason::UnsupportedEncType))?;
        let current = self
            .store
            .get(client)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?
            .current();
        fields.kvno = Some(current.kvno());
        if enc.kvno.is_some_and(|k| k != current.kvno().get()) {
            return Err(Deny::denied(AuditReason::KvnoMismatch));
        }
        let key = current
            .key_for(enctype)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
        // The cryptographic check: the only refusal the throttle counts (a
        // wrong key or an undecryptable timestamp — A-34).
        let plaintext = match open(key, AS_REQ_PA_ENC_TIMESTAMP, &enc.cipher) {
            Ok(plaintext) => plaintext,
            Err(deny) => {
                self.preauth_throttle
                    .record(&client.principal, false, now_s);
                return Err(deny);
            }
        };
        let timestamp = PaEncTsEnc::decode(&plaintext)
            .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        // The cryptographic chain is complete (decrypted under the client key,
        // decoded): the skew finding may be reported as a class (A-26).
        if !within_skew(
            kerberos_time_seconds(&timestamp.patimestamp),
            now_s,
            self.config.clock_skew_secs,
        ) {
            return Err(Deny::classified(AuditReason::ClockSkew, AuthnError::Skew));
        }
        Ok(PreauthKey {
            enctype,
            kvno: current.kvno(),
        })
    }

    /// The armored check of `verify_preauth`: the encrypted challenge FAST
    /// factor under `armor_id` (steps 1-5 of [`Self::verify_preauth`]).
    /// Spec: RFC 6113 5.1, 5.4.6, 6.2; RFC 4120 5.2.7.2; docs/48 §2.3, §4.5;
    /// docs/questions/Q-123 (A-32), Q-145; A-26; A-34.
    fn check_encrypted_challenge(
        &mut self,
        caller: &CallerId,
        client: &KeyHandle,
        padata: &PaData,
        armor_id: &ArmorId,
        now_s: i64,
        fields: &mut AuditFields,
    ) -> Internal<PreauthKey> {
        // 1. The armor and its one attempt (I4).
        let armor = self
            .armors
            .peek_mut(armor_id.as_bytes(), caller, now_s)
            .map_err(token_deny)?;
        armor.begin_preauth()?;

        // 2. PA-ENCRYPTED-CHALLENGE, of the challenge key's enctype.
        if padata.padata_type != PA_ENCRYPTED_CHALLENGE {
            return Err(Deny::denied(AuditReason::UnsupportedPadataType));
        }
        let challenge = EncryptedChallenge::decode(&padata.padata_value)
            .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        if challenge.etype != armor.challenge_enctype().number() {
            return Err(Deny::denied(AuditReason::ChallengeEncTypeMismatch));
        }

        // 3. The long-term key K2, chosen by keyd (Q-123), current version.
        let current = self
            .store
            .get(client)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?
            .current();
        fields.kvno = Some(current.kvno());
        // The challenge key is derived per conversation, not a long-lasting
        // key: a kvno "is only present in messages encrypted under long
        // lasting keys" (RFC 4120 5.2.9), so a present one is refused —
        // interim strict reading, docs/questions/Q-145.
        if challenge.kvno.is_some() {
            return Err(Deny::denied(AuditReason::KvnoMismatch));
        }
        let (enctype, long_term) =
            challenge_long_term_key(current, armor.requested_etypes(), &self.config.enctypes)
                .ok_or(Deny::denied(AuditReason::KeyNotFound))?;

        // 4. The challenge key; the cryptographic check (usage 54) — the only
        // refusal the throttle counts, exactly as for PA-ENC-TIMESTAMP (A-34).
        let challenge_key = armor.client_challenge_key(long_term)?;
        let plaintext = match open(
            &challenge_key,
            KEY_USAGE_ENC_CHALLENGE_CLIENT,
            &challenge.cipher,
        ) {
            Ok(plaintext) => plaintext,
            Err(deny) => {
                self.preauth_throttle
                    .record(&client.principal, false, now_s);
                return Err(deny);
            }
        };
        drop(challenge_key);
        let timestamp = PaEncTsEnc::decode(&plaintext)
            .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        drop(plaintext);

        // 5. The chain is complete (decrypted under the challenge key,
        // decoded): only now the skew class (A-26).
        if !within_skew(
            kerberos_time_seconds(&timestamp.patimestamp),
            now_s,
            self.config.clock_skew_secs,
        ) {
            return Err(Deny::classified(AuditReason::ClockSkew, AuthnError::Skew));
        }
        Ok(PreauthKey {
            enctype,
            kvno: current.kvno(),
        })
    }

    /// `issue_as_rep`: consume `proof` and issue a TGT — armored when
    /// `armor` is `Some`.
    ///
    /// 1. authorize (Kdc; client handle PrincipalLongterm, krbtgt handle
    ///    Krbtgt);
    /// 2. consume the proof: live, issued to this caller, bound to this
    ///    client (`Denied` otherwise — the proof is destroyed either way);
    ///    and the proof's armor is `armor` — None↔None, Some(a)↔Some(a)
    ///    (`Denied`, docs/48 §2.3);
    /// 3. validate the template (`BadTemplate`): realm, TGS sname, enctype
    ///    configured, flags in the allowed mask, times within policy;
    ///    armored: the armor is live, this caller's and bound to this proof,
    ///    and the template's crealm / cname / nonce are the stored inner
    ///    request's (`Denied`, docs/48 §3.4); then the name bindings
    ///    (`Denied`): crealm/cname must identify the client key set's bound
    ///    name, and the krbtgt key set must be bound to krbtgt/realm =
    ///    template sname (Q-040, A-19; RFC 4120 6.2, 7.3);
    /// 4. draw a fresh session key;
    /// 5. EncTicketPart sealed under the CURRENT krbtgt key, usage 2;
    /// 6. EncASRepPart, usage 3, with the client kvno, sealed under the
    ///    client key that pre-authenticated (still the current version) —
    ///    or, armored, under the reply key strengthened with a fresh
    ///    strengthen key, with the KrbFastResponse (the KDC's encrypted
    ///    challenge, the strengthen key, KrbFastFinished, the inner nonce)
    ///    sealed in the armor key as `fast_rep` (`ArmorEntry::seal_as_reply`
    ///    in the fast_armor module); the armor is consumed;
    /// 7. return the sealed parts — the session key, the strengthen key and
    ///    the reply key stay inside.
    ///
    /// An armored refusal leaves the armor live (only the proof is consumed),
    /// so that the KDC can seal the armored error with `seal_fast_error`
    /// (docs/48 §4.1 A13); an armor presented by another caller, or expired,
    /// is destroyed.
    ///
    /// Spec: docs/10 §4 (issue_as_rep, steps 1-7), §8; docs/48 §2.3, §3.4,
    /// §4.3, §4.4; RFC 4120 3.1.3, 5.3, 5.4.2 (key usage 3; client kvno
    /// included), 7.5.1 (usages 2, 3); RFC 6113 5.4.2, 5.4.3, 5.4.6.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_as_rep(
        &mut self,
        caller: &CallerId,
        client: &KeyHandle,
        krbtgt: &KeyHandle,
        proof: &AuthnProof,
        armor: Option<ArmorId>,
        template: &AsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<AsRepParts, IssueError> {
        let mut fields = AuditFields::for_handle(client);
        let result = self.issue_as_rep_inner(
            caller,
            client,
            krbtgt,
            proof,
            armor,
            template,
            now,
            &mut fields,
        );
        self.emit(caller, Operation::IssueAsRep, now, &fields, &result);
        result.map_err(IssueError::from)
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_as_rep_inner(
        &mut self,
        caller: &CallerId,
        client: &KeyHandle,
        krbtgt: &KeyHandle,
        proof: &AuthnProof,
        armor: Option<ArmorId>,
        template: &AsTicketTemplate,
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<AsRepParts> {
        authorize(
            caller,
            Operation::IssueAsRep,
            &[(HandleSlot::Primary, client), (HandleSlot::Krbtgt, krbtgt)],
        )?;
        let now_s = kerberos_time_seconds(now);

        // Step 1: the proof (I4).
        let entry = self
            .proofs
            .take(proof.exchange_id.as_bytes(), caller, now_s)
            .map_err(token_deny)?;
        if entry.principal != client.principal
            || proof.client != entry.principal
            || template.client != entry.principal
            || proof.authtime != entry.authtime
        {
            return Err(Deny::denied(AuditReason::TokenPrincipalMismatch));
        }
        // The proof and the armor are one conversation: None↔None,
        // Some(a)↔Some(a). Spec: docs/48 §2.3, §9.2 item 8.
        let armor = armor.map(|armor_id| *armor_id.as_bytes());
        if entry.armor != armor {
            return Err(Deny::denied(AuditReason::ArmorProofMismatch));
        }

        // Step 2: the template.
        let realm = &self.config.realm;
        if template.crealm != *realm || template.sname != tgs_name(realm) {
            return Err(Deny::bad_template(AuditReason::TemplateNames));
        }
        if !self.config.supports(template.session_enctype) {
            return Err(Deny::bad_template(AuditReason::TemplateEncType));
        }
        let policy = &self.config.ticket_policy;
        let flags = as_ticket_flags(policy, template.flags)?;
        check_times(
            policy,
            self.config.clock_skew_secs,
            now_s,
            &entry.authtime,
            &TemplateTimes {
                starttime: template.starttime.as_ref(),
                endtime: &template.endtime,
                renew_till: template.renew_till.as_ref(),
                renewable: template.flags.contains(TicketFlags::RENEWABLE),
            },
        )?;
        // Armored: the armor is live, this caller's and bound to this proof,
        // and the template answers the inner request (crealm, cname, nonce).
        // Not consumed yet — a refusal leaves it for the armored error.
        // Spec: docs/48 §2.3, §3.4, §4.1 A13; RFC 6113 5.4.2, 5.4.3.
        if let Some(armor_id) = &armor {
            self.armors
                .peek_mut(armor_id, caller, now_s)
                .map_err(token_deny)?
                .check_issue(
                    proof.exchange_id.as_bytes(),
                    &template.crealm,
                    &template.cname,
                    template.nonce,
                )?;
        }

        // Keys: the client key that pre-authenticated, the current krbtgt key.
        let client_set = self
            .store
            .get(client)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
        let client_version = client_set.current();
        fields.kvno = Some(client_version.kvno());
        // Name binding (Q-040, A-19): the ticket may only name the principal
        // the client key is bound to.
        check_binding(client_set.binding(), &template.crealm, &template.cname)?;
        if client_version.kvno() != entry.reply_kvno {
            return Err(Deny::denied(AuditReason::KvnoMismatch));
        }
        let client_key = client_version
            .key_for(entry.reply_enctype)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
        let tgs_set = self
            .store
            .get(krbtgt)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
        let tgs_version = tgs_set.current();
        fields.secondary = Some(AuditKeyRef {
            principal: krbtgt.principal,
            purpose: KeyPurpose::Krbtgt,
            kvno: Some(tgs_version.kvno()),
        });
        // Name binding (Q-040, A-19): the krbtgt key must be bound to this
        // realm's TGS name (RFC 4120 7.3), and the ticket's sname must be that
        // bound name.
        check_binding(tgs_set.binding(), realm, &tgs_name(realm))?;
        check_binding(tgs_set.binding(), realm, &template.sname)?;
        let tgs_key = tgs_version
            .preferred()
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?;

        // Step 3: the session key.
        let session = new_random_key(&mut self.entropy, template.session_enctype)?;
        let session_key = EncryptionKey {
            keytype: template.session_enctype.number(),
            keyvalue: KeyValue::from_slice(session.octets()),
        };
        drop(session);

        // Step 5: EncTicketPart under krbtgt (usage 2).
        let enc_ticket_part = EncTicketPart {
            flags,
            key: session_key.clone(),
            crealm: template.crealm.clone(),
            cname: template.cname.clone(),
            transited: TransitedEncoding {
                tr_type: DOMAIN_X500_COMPRESS,
                contents: Vec::new(),
            },
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
        let ticket_cipher = seal(&mut self.entropy, tgs_key, TICKET_ENC_PART, &ticket_plain)?;
        drop(ticket_plain);
        let ticket = Ticket {
            realm: realm.clone(),
            sname: template.sname.clone(),
            enc_part: EncryptedData {
                etype: tgs_key.enc_type().number(),
                kvno: Some(tgs_version.kvno().get()),
                cipher: ticket_cipher,
            },
        };

        // Step 6: EncASRepPart (usage 3) under the client key, or — armored —
        // under the strengthened reply key, with the sealed KrbFastResponse.
        let rep_part = EncAsRepPart(EncKdcRepPart {
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
        let (rep_cipher, fast_rep) = match &armor {
            None => (
                seal(&mut self.entropy, client_key, AS_REP_ENC_PART, &rep_plain)?,
                None,
            ),
            Some(armor_id) => {
                let armored = self
                    .armors
                    .peek_mut(armor_id, caller, now_s)
                    .map_err(token_deny)?
                    .seal_as_reply(
                        &mut self.entropy,
                        client_key,
                        &rep_plain,
                        &ticket,
                        &template.crealm,
                        &template.cname,
                        now,
                    )?;
                // Issued: the armor is consumed — exactly once (docs/48
                // §2.3); its key is zeroized with the entry.
                drop(
                    self.armors
                        .take(armor_id, caller, now_s)
                        .map_err(token_deny)?,
                );
                (armored.enc_part_cipher, Some(armored.fast_rep))
            }
        };
        drop(rep_plain);
        // The reply key, strengthened or not, has the client key's enctype
        // (RFC 6113 5.4.3 "same etype"; 5.1 "the enctype of k1"); the kvno
        // is the client key's (RFC 4120 5.4.2; docs/questions/Q-121 (a)).
        Ok(AsRepParts {
            ticket,
            enc_part: EncryptedData {
                etype: client_key.enc_type().number(),
                kvno: Some(client_version.kvno().get()),
                cipher: rep_cipher,
            },
            fast_rep,
        })
    }
}
