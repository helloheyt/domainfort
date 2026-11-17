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
//! the ticket under the CURRENT key of the server key set and the reply under
//! the client key that pre-authenticated — or, under FAST, under the reply
//! key strengthened with a fresh strengthen key — and returns only sealed
//! blobs: the session key, the strengthen key and the reply key never leave
//! keyd (docs/10 §4 steps 1-7; docs/48 §2.2, §4.3).
//!
//! The server is one of a closed set ([`AsServer`], task K3b): this realm's
//! TGS (a TGT, armored or not) or the change-password service
//! `kadmin/changepw` — only under FAST armor, and only under that service's
//! ticket profile, which keyd enforces whatever the KDC asks (INITIAL and
//! PRE-AUTHENT set by keyd, endtime ≤ authtime + 300 s, no other flag, no
//! starttime, no renew-till). An unarmored change-password issuance has no
//! value inside keyd (`AsIssuance`); the capability table refuses the
//! service's key set in the unarmored server slot before that (docs/53 §5.2;
//! A-142 — the KDC's type is the first layer, this the second).
//!
//! **Keys only through dird's attested name resolution** (task PN11;
//! docs/59 §7.2): the client key set — and, for the change-password
//! service, the server key set — is reached only through the door
//! `store::bound_by` on a resolution keyd verified (dird's tag under the
//! attestation key, keyd's realm, issued within 30 s of keyd's clock),
//! which must name the very (realm, name) the ticket will carry. The krbtgt
//! of a TGT is reached by its exact stored binding to the canonical TGS name
//! (`StoredKeySet::ticket_granting`). The KDC forwards the resolutions; it
//! cannot choose which key set a name maps to (C3).
//!
//! **Each resolved key set is named once** (task PN11b; docs/questions/
//! Q-1067 — the class "one request states one fact twice", AGENTS.md §6.1):
//! `issue_as_rep` takes no client handle and no change-password server
//! handle, and the template no client principal. keyd derives each such
//! key set from the resolution it verified — the door looks it up by the
//! resolution's `(principal, key_purpose)` — and checks the derived
//! handle's purpose against the capability table's slot; the proof of
//! `verify_preauth` (keyd's own record of the key set that
//! pre-authenticated) must be bound to the client key set so derived. The
//! krbtgt keeps its handle (`AsServerKeySet::LocalTgt`): it has no
//! resolution. `verify_preauth` keeps its client handle — it takes no
//! resolution (docs/questions/Q-1080: the alternative of Q-1067 open point
//! 1, and why).
//!
//! Phase 1 issues no PAC (MS-PAC / NDR is phase 2, where D124 applies):
//! tickets carry no authorization-data. Tickets are addressless (no caddr;
//! RFC 4120 5.3 recommends allowing addressless tickets). The transited
//! field is empty (local authentication, RFC 4120 3.3.3.2).
//!
//! Spec: RFC 4120 2.1, 3.1.2, 3.1.3, 3.1.5, 5.2.7.2, 5.3, 5.4.2, 7.3, 7.5.1;
//! RFC 6113 5.1, 5.4, 5.4.3, 5.4.6, 6.2, 8; RFC 3244 §2; [MS-KILE] 3.3.5.1.2;
//! docs/10 §4, §8; docs/30 §2; docs/48 §2.3, §4; docs/53 R53-6, §5.2;
//! docs/59 §7.1, §7.2; docs/questions/Q-915 (A-151), Q-1011 (A-173),
//! Q-1067, Q-1080 (task PN11b).

use crate::audit::{AuditKeyRef, AuditReason, AuditSink};
use crate::authz::{as_server_slot, CallerId, HandleSlot, Operation};
use crate::chain::{self, ChainClass, ChainVerified};
use crate::enctype::to_crypto;
use crate::entropy::EntropySource;
use crate::error::{AuthnError, Deny, Internal, IssueError};
use crate::keyd::{admit_resolved, draw, new_random_key, seal, AuditFields, Keyd};
use crate::model::{KeyHandle, KeyPurpose, Kvno, PrincipalId};
use crate::name_resolution::VerifiedNameResolution;
use crate::store::{bound_by, KeyStore, KeyVersion, UnboundUse};
use crate::template::{
    as_ticket_flags, change_password_ticket, check_times, tgs_name, TemplateTimes,
};
use crate::throttle::SecretThrottle;
use crate::time::{kerberos_time_seconds, within_skew};
use crate::tokens::{ArmorId, ExchangeId, TokenRefusal, TOKEN_ID_LENGTH};
use crate::usage::{
    AS_REP_ENC_PART, AS_REQ_PA_ENC_TIMESTAMP, KEY_USAGE_ENC_CHALLENGE_CLIENT, TICKET_ENC_PART,
};
use keyd_types::{
    is_change_password_service_name, AsRepParts, AsServer, AsServerKeySet, AsTicketTemplate,
    AttestedNameResolution, AuthnProof,
};
use krb_crypto::{EncType, ProtocolKey};
use krb_proto::constants::{DOMAIN_X500_COMPRESS, PA_ENCRYPTED_CHALLENGE, PA_ENC_TIMESTAMP};
use krb_proto::{
    EncAsRepPart, EncKdcRepPart, EncTicketPart, EncryptedChallenge, EncryptedData, EncryptionKey,
    KerberosTime, KeyValue, LastReq, PaData, PaEncTimestamp, PaEncTsEnc, Ticket, TicketFlags,
    TransitedEncoding,
};
use zeroize::Zeroizing;

// The argument and result types of this exchange (`AuthnProof`,
// `AsTicketTemplate`, `AsRepParts`) live in the crypto-free keyd-types crate
// (D182; decision A-63) and are re-exported at the crate root.

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

impl ProofEntry {
    /// The principal whose PrincipalLongterm key pre-authenticated. A proof
    /// is discarded when that key set is destroyed (A-35).
    /// Spec: docs/10 §8, §12 I4; docs/questions/Q-115 (A-35).
    pub(crate) fn principal(&self) -> PrincipalId {
        self.principal
    }
}

/// What one `issue_as_rep` issues: the closed server slot ([`AsServer`])
/// joined with the issuance's armor. Built only by [`AsIssuance::of`] —
/// for a TGT after the capability table admitted the krbtgt handle in the
/// slot of its armoring — and the change-password variant holds its armor,
/// not an `Option` of one: inside keyd an unarmored change-password
/// issuance is not a value (task K3b; the second layer of A-142 — the KDC's
/// `ArmoredServer` is the first).
/// Spec: docs/53 §5.2; docs/questions/Q-915 items 1, 3 (A-151); A-142;
/// docs/52 C24.
enum AsIssuance {
    /// A TGT of this realm, armored or not (docs/48 §7.3: the unarmored
    /// computer bootstrap).
    LocalTgt {
        /// The armor of an armored issuance.
        armor: Option<[u8; TOKEN_ID_LENGTH]>,
    },
    /// A ticket for the change-password service, under its profile.
    ChangePasswordService {
        /// The armor of this issuance (never absent).
        armor: [u8; TOKEN_ID_LENGTH],
    },
}

impl AsIssuance {
    /// The issuance for `server` with `armor` — anything else is `Denied`
    /// (`PurposeMismatch`, decided before the proof is touched): a TGT
    /// whose krbtgt handle the one classification ([`AsServer::of`]) finds
    /// to be this realm's TGS — not merely a server of its slot, so a
    /// change-password key set named as a TGT's krbtgt is refused; the
    /// change-password service only when armored (A-142). The service's own
    /// key set is classified the same way once its resolution is verified
    /// ([`Keyd::issue_as_rep`]).
    /// Spec: docs/53 §5.2; docs/questions/Q-915 items 1, 3; A-142;
    /// docs/questions/Q-1067.
    fn of(server: AsServerKeySet<'_>, armor: Option<ArmorId>) -> Internal<AsIssuance> {
        let armor = armor.map(|armor_id| *armor_id.as_bytes());
        match (server, armor) {
            (AsServerKeySet::LocalTgt(krbtgt), armor)
                if AsServer::of(krbtgt.purpose, armor.is_some()) == Some(AsServer::LocalTgt) =>
            {
                Ok(AsIssuance::LocalTgt { armor })
            }
            (AsServerKeySet::ChangePasswordService(_), Some(armor)) => {
                Ok(AsIssuance::ChangePasswordService { armor })
            }
            _ => Err(Deny::denied(AuditReason::PurposeMismatch)),
        }
    }

    /// The armor of this issuance, if armored.
    fn armor(&self) -> Option<&[u8; TOKEN_ID_LENGTH]> {
        match self {
            AsIssuance::LocalTgt { armor } => armor.as_ref(),
            AsIssuance::ChangePasswordService { armor } => Some(armor),
        }
    }
}

/// The server key set of one `issue_as_rep` as keyd will reach it: this
/// realm's krbtgt by its handle, or the change-password service by the
/// resolution keyd verified (task PN11b — the request named that key set
/// only through its resolution).
/// Spec: docs/59 §7.2; docs/53 §5.2; docs/questions/Q-1067.
enum VerifiedAsServer<'a> {
    /// The krbtgt of a TGT (no resolution — docs/59 §7.2).
    LocalTgt(&'a KeyHandle),
    /// The change-password service, by its verified resolution.
    ChangePasswordService(VerifiedNameResolution),
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
    version: KeyVersion<'a>,
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
        self.admit(
            caller,
            Operation::VerifyPreauth,
            &[(HandleSlot::Primary, client)],
            now,
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
            .filter(|e| self.enctypes.contains(e))
            .ok_or(Deny::denied(AuditReason::UnsupportedEncType))?;
        // A declared unbound use (crate::store `UnboundUse`, R7): the proof
        // is bound to the handle; `issue_as_rep` binds the name.
        let current = self
            .store
            .get(client)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?
            .unbound_current(UnboundUse::Preauthentication);
        fields.kvno = Some(current.kvno());
        if enc.kvno.is_some_and(|k| k != current.kvno().get()) {
            return Err(Deny::denied(AuditReason::KvnoMismatch));
        }
        let key = current
            .key_for(enctype)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
        // The cryptographic check: the only refusal the throttle counts (a
        // wrong key or an undecryptable timestamp — A-34).
        let (plaintext, decrypted) = match chain::open(key, AS_REQ_PA_ENC_TIMESTAMP, &enc.cipher) {
            Ok(opened) => opened,
            Err(deny) => {
                self.preauth_throttle
                    .record(&client.principal, false, now_s);
                return Err(deny);
            }
        };
        let timestamp = PaEncTsEnc::decode(&plaintext)
            .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        // The cryptographic chain is complete (decrypted under the client key,
        // decoded): its proof, the only maker of a class (A-26; crate::chain).
        let verified = ChainVerified::preauthentication(decrypted);
        if !within_skew(
            kerberos_time_seconds(&timestamp.patimestamp),
            now_s,
            self.config.clock_skew_secs,
        ) {
            return Err(verified.refuse(ChainClass::Skew));
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

        // 3. The long-term key K2, chosen by keyd (Q-123), current version —
        // a declared unbound use (crate::store `UnboundUse`, R7): the proof
        // is bound to the handle; `issue_as_rep` binds the name.
        let current = self
            .store
            .get(client)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?
            .unbound_current(UnboundUse::Preauthentication);
        fields.kvno = Some(current.kvno());
        // The challenge key is derived per conversation, not a long-lasting
        // key: a kvno "is only present in messages encrypted under long
        // lasting keys" (RFC 4120 5.2.9), so a present one is refused —
        // interim strict reading, docs/questions/Q-145.
        if challenge.kvno.is_some() {
            return Err(Deny::denied(AuditReason::KvnoMismatch));
        }
        let (enctype, long_term) =
            challenge_long_term_key(current, armor.requested_etypes(), &self.enctypes)
                .ok_or(Deny::denied(AuditReason::KeyNotFound))?;

        // 4. The challenge key; the cryptographic check (usage 54) — the only
        // refusal the throttle counts, exactly as for PA-ENC-TIMESTAMP (A-34).
        let challenge_key = armor.client_challenge_key(long_term)?;
        let (plaintext, decrypted) = match chain::open(
            &challenge_key,
            KEY_USAGE_ENC_CHALLENGE_CLIENT,
            &challenge.cipher,
        ) {
            Ok(opened) => opened,
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
        // decoded): its proof, and only now the skew class (A-26;
        // crate::chain).
        let verified = ChainVerified::preauthentication(decrypted);
        if !within_skew(
            kerberos_time_seconds(&timestamp.patimestamp),
            now_s,
            self.config.clock_skew_secs,
        ) {
            return Err(verified.refuse(ChainClass::Skew));
        }
        Ok(PreauthKey {
            enctype,
            kvno: current.kvno(),
        })
    }

    /// `issue_as_rep`: consume `proof` and issue an AS ticket for `server` —
    /// armored when `armor` is `Some`. `server` is one of a closed set
    /// ([`AsServer`]): this realm's krbtgt key set by its handle (a TGT,
    /// armored or not), or — armored only — the change-password service by
    /// dird's attested resolution of its name (a ticket for
    /// `kadmin/changepw`, under that service's profile). `client` is dird's
    /// attested resolution of the request's client name — the only name of
    /// the client key set in the request (task PN11b).
    ///
    /// 1. authorize and admit (Kdc; for a TGT the krbtgt handle in the
    ///    server slot of its armoring — `as_server_slot`: unarmored Krbtgt
    ///    only, armored Krbtgt or ChangePasswordService); the issuance is
    ///    then one of `AsIssuance` — a TGT's handle must classify as this
    ///    realm's TGS, a change-password one always holds its armor
    ///    (`Denied` / `PurposeMismatch` otherwise, the proof untouched);
    /// 2. consume the proof: live, issued to this caller, its client and
    ///    authtime keyd's own (`Denied` otherwise — the proof is destroyed
    ///    either way); and the proof's armor is the issuance's —
    ///    None↔None, Some(a)↔Some(a) (`Denied`, docs/48 §2.3) — so a
    ///    change-password ticket is issued only on an encrypted challenge
    ///    verified under the same armor;
    /// 3. validate the template (`BadTemplate`): realm; sname — this realm's
    ///    TGS name for a TGT, `kadmin/changepw` (any name-type) for the
    ///    change-password service; enctype configured; for a TGT, flags in
    ///    the allowed mask and times within policy (`check_times`); for the
    ///    change-password service, its profile
    ///    (`template::change_password_ticket`: no flag, no starttime, no
    ///    renew-till, the realm's time rules, endtime ≤ authtime + 300 s);
    ///    armored: the armor is live, this caller's and bound to this proof,
    ///    and the template's crealm / cname / nonce are the stored inner
    ///    request's (`Denied`, docs/48 §3.4); then the keys, each only
    ///    through its proof (`Denied`; tasks PN11, PN11b, docs/59 §7.2):
    ///    dird's client resolution verifies (tag, realm, 30 s — else
    ///    `AttestationKeyMissing` / `NameResolutionInvalid` / `WrongRealm` /
    ///    `NameResolutionStale`); the key set it names is PrincipalLongterm
    ///    (`PurposeMismatch`) and the one the proof is bound to
    ///    (`TokenPrincipalMismatch`); for the change-password service its
    ///    own resolution verifies likewise and names a ChangePasswordService
    ///    key set (`PurposeMismatch`); the door `store::bound_by` looks each
    ///    such set up by its resolution and requires the set's binding and
    ///    the ticket's (crealm, cname) — or the service's sname — to be the
    ///    resolution's (`KeyNotFound` / `NameResolutionMismatch`); for a TGT
    ///    the server key set is the krbtgt bound to this realm's TGS name;
    /// 4. draw a fresh session key;
    /// 5. EncTicketPart sealed under the CURRENT key of the server key set,
    ///    usage 2 (the flags: the TGT's requested ones, or for the
    ///    change-password service exactly INITIAL | PRE-AUTHENT);
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
    /// Spec: docs/10 §2 (b), §4 (issue_as_rep, steps 1-7), §8; docs/48 §2.3,
    /// §3.4, §4.3, §4.4; RFC 4120 2.1, 3.1.3 (the ticket sealed with "the
    /// encryption key extracted from the server principal's record"), 5.3,
    /// 5.4.2 (key usage 3; client kvno included), 7.5.1 (usages 2, 3); RFC
    /// 6113 5.4, 5.4.2, 5.4.3, 5.4.6; RFC 3244 §2; docs/53 R53-6, §5.2;
    /// docs/questions/Q-915 items 1, 3, 4 (A-151); A-142; docs/59 §7.1,
    /// §7.2; docs/questions/Q-1011 items 4, 8 (A-173), Q-1067, Q-1080;
    /// [MS-KILE] 3.3.5.1.2.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_as_rep(
        &mut self,
        caller: &CallerId,
        client: &AttestedNameResolution,
        server: AsServerKeySet<'_>,
        proof: &AuthnProof,
        armor: Option<ArmorId>,
        template: &AsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<AsRepParts, IssueError> {
        // The record names a key set only once keyd knows it: the proof's
        // (keyd's own record), then the verified resolutions'.
        let mut fields = AuditFields::default();
        let result = self.issue_as_rep_inner(
            caller,
            client,
            server,
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
        client: &AttestedNameResolution,
        server: AsServerKeySet<'_>,
        proof: &AuthnProof,
        armor: Option<ArmorId>,
        template: &AsTicketTemplate,
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<AsRepParts> {
        // The role, the hold-down and, for a TGT, the krbtgt handle in the
        // closed server slot of this issuance's armoring (Q-915 items 1, 3;
        // pinned in keyd-types authz.rs). A resolved key set has no handle
        // in the request: its purpose is checked once its resolution is
        // verified (task PN11b).
        let server_slot = as_server_slot(armor.is_some());
        match server {
            AsServerKeySet::LocalTgt(krbtgt) => {
                self.admit(caller, Operation::IssueAsRep, &[(server_slot, krbtgt)], now)?
            }
            AsServerKeySet::ChangePasswordService(_) => {
                self.admit(caller, Operation::IssueAsRep, &[], now)?;
            }
        }
        let issuance = AsIssuance::of(server, armor)?;
        let now_s = kerberos_time_seconds(now);

        // Step 1: the proof (I4) — keyd's own record of the key set that
        // pre-authenticated, (principal, PrincipalLongterm): verify_preauth
        // admits only that purpose.
        let entry = self
            .proofs
            .take(proof.exchange_id.as_bytes(), caller, now_s)
            .map_err(token_deny)?;
        fields.principal = Some(entry.principal);
        fields.purpose = Some(KeyPurpose::PrincipalLongterm);
        if proof.client != entry.principal || proof.authtime != entry.authtime {
            return Err(Deny::denied(AuditReason::TokenPrincipalMismatch));
        }
        // The proof and the armor are one conversation: None↔None,
        // Some(a)↔Some(a). Spec: docs/48 §2.3, §9.2 item 8.
        let armor = issuance.armor().copied();
        if entry.armor != armor {
            return Err(Deny::denied(AuditReason::ArmorProofMismatch));
        }

        // Step 2: the template — the server's name, then its rules.
        let realm = &self.config.realm;
        let sname_fits = match issuance {
            AsIssuance::LocalTgt { .. } => template.sname == tgs_name(realm),
            AsIssuance::ChangePasswordService { .. } => {
                is_change_password_service_name(&template.sname)
            }
        };
        if template.crealm != *realm || !sname_fits {
            return Err(Deny::bad_template(AuditReason::TemplateNames));
        }
        if !self.config.enctypes.contains(&template.session_enctype) {
            return Err(Deny::bad_template(AuditReason::TemplateEncType));
        }
        let policy = &self.config.ticket_policy;
        let times = TemplateTimes {
            starttime: template.starttime.as_ref(),
            endtime: &template.endtime,
            renew_till: template.renew_till.as_ref(),
            renewable: template.flags.contains(TicketFlags::RENEWABLE),
        };
        let flags = match issuance {
            AsIssuance::LocalTgt { .. } => {
                let flags = as_ticket_flags(policy, template.flags)?;
                check_times(
                    policy,
                    self.config.clock_skew_secs,
                    now_s,
                    &entry.authtime,
                    &times,
                )?;
                flags
            }
            // The service's profile, whatever the KDC asked (docs/53 §5.2;
            // Q-915 item 4).
            AsIssuance::ChangePasswordService { .. } => change_password_ticket(
                policy,
                self.config.clock_skew_secs,
                now_s,
                &entry.authtime,
                &times,
                template.flags,
            )?,
        };
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

        // dird's resolutions, verified on keyd's clock before any key is
        // touched (docs/59 §7.2 steps 1-3): the client's always; the
        // change-password service's for that server — a TGT's krbtgt has
        // none (it is bound by its exact stored binding). Each names the
        // key set keyd will reach — the request names it nowhere else (task
        // PN11b) — so its purpose is checked here, against the capability
        // table's slot (docs/10 §2 (b)).
        let client_resolution = self.verify_name_resolution(client, now)?;
        let client_handle = client_resolution.handle();
        // From here the record names the key set the verified resolution
        // names — the issuance's client, as the request's client handle was
        // before task PN11b.
        fields.principal = Some(client_handle.principal);
        fields.purpose = Some(client_handle.purpose);
        admit_resolved(Operation::IssueAsRep, HandleSlot::Primary, &client_handle)?;
        // The proof is bound to the client: the key set that
        // pre-authenticated is the one dird resolved the client's name to
        // (docs/10 §4 step 1) — two statements keyd made or verified
        // itself (docs/questions/Q-1080).
        if client_handle.principal != entry.principal {
            return Err(Deny::denied(AuditReason::TokenPrincipalMismatch));
        }
        let server_set = match server {
            AsServerKeySet::LocalTgt(krbtgt) => VerifiedAsServer::LocalTgt(krbtgt),
            AsServerKeySet::ChangePasswordService(attested) => {
                let resolution = self.verify_name_resolution(attested, now)?;
                let handle = resolution.handle();
                // The same classification as a handle in this slot: the
                // capability table, then the one classification of a server
                // key set — it must be the change-password service's (Q-915
                // items 1, 3).
                admit_resolved(Operation::IssueAsRep, server_slot, &handle)?;
                if AsServer::of(handle.purpose, armor.is_some())
                    != Some(AsServer::ChangePasswordService)
                {
                    return Err(Deny::denied(AuditReason::PurposeMismatch));
                }
                VerifiedAsServer::ChangePasswordService(resolution)
            }
        };

        // Keys: the client key that pre-authenticated, the server's current
        // key — each only through the proof of its door (crate::store, "The
        // doors"; Q-040, A-19; R7). The ticket may only name the client as
        // dird resolved it, under the key set dird resolved it to (docs/59
        // §7.2 steps 4-5).
        let client_version = bound_by(
            &self.store,
            &client_resolution,
            &template.crealm,
            &template.cname,
        )?
        .current();
        fields.kvno = Some(client_version.kvno());
        if client_version.kvno() != entry.reply_kvno {
            return Err(Deny::denied(AuditReason::KvnoMismatch));
        }
        let client_key = client_version
            .key_for(entry.reply_enctype)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
        // The server key: for a TGT the krbtgt bound to this realm's TGS
        // name — which step 2 found the template's sname to be, exactly
        // (RFC 4120 7.3; [MS-KILE] 3.3.5.1.2); for the change-password
        // service the key set its verified resolution names, together with
        // the template's sname, `kadmin/changepw` (RFC 3244 §2; docs/59
        // §7.2). keyd's creation rule binds a Krbtgt key set only to a TGS
        // name and a ChangePasswordService key set only to `kadmin/changepw`
        // (template::check_new_binding).
        let server_keys = match &server_set {
            VerifiedAsServer::LocalTgt(krbtgt) => {
                let set = self
                    .store
                    .get(krbtgt)
                    .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
                fields.secondary = Some(AuditKeyRef {
                    principal: krbtgt.principal,
                    purpose: krbtgt.purpose,
                    kvno: Some(set.current_kvno()),
                });
                set.ticket_granting(realm)?
            }
            VerifiedAsServer::ChangePasswordService(resolution) => {
                let handle = resolution.handle();
                fields.secondary = Some(AuditKeyRef {
                    principal: handle.principal,
                    purpose: handle.purpose,
                    kvno: None,
                });
                let keys = bound_by(&self.store, resolution, realm, &template.sname)?;
                fields.secondary = Some(AuditKeyRef {
                    principal: handle.principal,
                    purpose: handle.purpose,
                    kvno: Some(keys.current().kvno()),
                });
                keys
            }
        };
        let server_version = server_keys.current();
        let server_key = server_version
            .preferred()
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?;

        // Step 3: the session key.
        let session = new_random_key(&mut self.entropy, to_crypto(template.session_enctype))?;
        let session_key = EncryptionKey {
            keytype: template.session_enctype.number(),
            keyvalue: KeyValue::from_slice(session.octets()),
        };
        drop(session);

        // Step 5: EncTicketPart under the server key (usage 2).
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
        let ticket_cipher = seal(
            &mut self.entropy,
            server_key,
            TICKET_ENC_PART,
            &ticket_plain,
        )?;
        drop(ticket_plain);
        let ticket = Ticket {
            realm: realm.clone(),
            sname: template.sname.clone(),
            enc_part: EncryptedData {
                etype: server_key.enc_type().number(),
                kvno: Some(server_version.kvno().get()),
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
