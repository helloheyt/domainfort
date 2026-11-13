//! The AS exchange inside keyd: `verify_preauth` (PA-ENC-TIMESTAMP) and
//! `issue_as_rep`. Role `Kdc` only.
//!
//! State machine: `verify_preauth ──(AuthnProof)──► issue_as_rep`. Issuance
//! without a valid, unexpired, unused proof bound to the same caller and the
//! same client is not expressible (I4).
//!
//! `issue_as_rep` builds the EncTicketPart and EncASRepPart itself from a
//! validated template, draws the session key from the entropy source, seals
//! the ticket under the CURRENT krbtgt key and the reply under the client key
//! that pre-authenticated, and returns only the two sealed blobs — the
//! session key never leaves keyd (docs/10 §4 steps 1-7).
//!
//! Phase 1 issues no PAC (MS-PAC / NDR is phase 2, where D124 applies):
//! tickets carry no authorization-data. Tickets are addressless (no caddr;
//! RFC 4120 5.3 recommends allowing addressless tickets). The transited
//! field is empty (local authentication, RFC 4120 3.3.3.2).
//!
//! Spec: RFC 4120 3.1.2, 3.1.3, 5.2.7.2, 5.3, 5.4.2, 7.3, 7.5.1; docs/10 §4,
//! §8; docs/30 §2.

use crate::audit::{AuditKeyRef, AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::entropy::EntropySource;
use crate::error::{AuthnError, Deny, Internal, IssueError};
use crate::keyd::{authorize, draw, new_random_key, open, seal, AuditFields, Keyd};
use crate::model::{KeyHandle, KeyPurpose, Kvno, PrincipalId};
use crate::store::KeyStore;
use crate::template::{as_ticket_flags, check_binding, check_times, tgs_name, TemplateTimes};
use crate::time::{kerberos_time_seconds, within_skew};
use crate::tokens::{ExchangeId, TokenRefusal, TOKEN_ID_LENGTH};
use crate::usage::{AS_REP_ENC_PART, AS_REQ_PA_ENC_TIMESTAMP, TICKET_ENC_PART};
use krb_crypto::EncType;
use krb_proto::constants::{DOMAIN_X500_COMPRESS, PA_ENC_TIMESTAMP};
use krb_proto::{
    EncAsRepPart, EncKdcRepPart, EncTicketPart, EncryptedData, EncryptionKey, KerberosTime,
    KeyValue, LastReq, PaData, PaEncTimestamp, PaEncTsEnc, PrincipalName, Realm, Ticket,
    TicketFlags, TransitedEncoding,
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

/// The sealed AS-REP parts: the ticket (sealed under krbtgt) and the
/// enc-part (sealed under the client key). The KDC assembles the AS-REP.
///
/// Spec: docs/10 §4 (`struct AsRep { ticket: Sealed, enc_part: Sealed }`);
/// RFC 4120 5.4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsRepParts {
    /// `ticket [5] Ticket`.
    pub ticket: Ticket,
    /// `enc-part [6] EncryptedData` (EncASRepPart, key usage 3).
    pub enc_part: EncryptedData,
}

/// Map a token refusal to its audit reason. Spec: docs/10 §8, D36.
pub(crate) fn token_deny(refusal: TokenRefusal) -> Deny {
    Deny::denied(match refusal {
        TokenRefusal::Unknown => AuditReason::TokenUnknown,
        TokenRefusal::Expired => AuditReason::TokenExpired,
        TokenRefusal::CallerMismatch => AuditReason::TokenCallerMismatch,
    })
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// `verify_preauth`: verify PA-ENC-TIMESTAMP for `client` and return a
    /// one-time [`AuthnProof`].
    ///
    /// Checks, all failing as the uniform `AuthnError::Denied`:
    /// padata-type is PA-ENC-TIMESTAMP (2); the padata-value decodes as
    /// EncryptedData; its etype is configured (I5) and the client's CURRENT
    /// key version has a key of that type (a kvno, if present, must be the
    /// current one — a superseded password never pre-authenticates);
    /// decryption with key usage 1 succeeds; the plaintext decodes as
    /// PA-ENC-TS-ENC; patimestamp is within the clock skew of `now`.
    ///
    /// Spec: RFC 4120 5.2.7.2 ("encrypted using the client's secret key and a
    /// key usage value of 1"), 7.5.1 (usage 1), 3.1.3 (KDC_ERR_PREAUTH_FAILED),
    /// 5.2.9 (kvno); docs/10 §4; docs/30 §2.3.
    pub fn verify_preauth(
        &mut self,
        caller: &CallerId,
        client: &KeyHandle,
        padata: &PaData,
        now: &KerberosTime,
    ) -> Result<AuthnProof, AuthnError> {
        let mut fields = AuditFields::for_handle(client);
        let result = self.verify_preauth_inner(caller, client, padata, now, &mut fields);
        self.emit(caller, Operation::VerifyPreauth, now, &fields, &result);
        result.map_err(AuthnError::from)
    }

    fn verify_preauth_inner(
        &mut self,
        caller: &CallerId,
        client: &KeyHandle,
        padata: &PaData,
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<AuthnProof> {
        authorize(
            caller,
            Operation::VerifyPreauth,
            &[(HandleSlot::Primary, client)],
        )?;
        let now_s = kerberos_time_seconds(now);
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
        let plaintext = open(key, AS_REQ_PA_ENC_TIMESTAMP, &enc.cipher)?;
        let timestamp = PaEncTsEnc::decode(&plaintext)
            .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        if !within_skew(
            kerberos_time_seconds(&timestamp.patimestamp),
            now_s,
            self.config.clock_skew_secs,
        ) {
            return Err(Deny::denied(AuditReason::ClockSkew));
        }
        let reply_kvno = current.kvno();
        let mut id = [0u8; TOKEN_ID_LENGTH];
        draw(&mut self.entropy, &mut id)?;
        let entry = ProofEntry {
            principal: client.principal,
            authtime: *now,
            reply_enctype: enctype,
            reply_kvno,
        };
        let expires_at = now_s + i64::from(self.config.token_lifetime_secs);
        if !self.proofs.insert(id, *caller, expires_at, entry, now_s) {
            return Err(Deny::unavailable(AuditReason::TokenTableFull));
        }
        Ok(AuthnProof {
            exchange_id: ExchangeId::from_bytes(id),
            client: client.principal,
            authtime: *now,
        })
    }

    /// `issue_as_rep`: consume `proof` and issue a TGT.
    ///
    /// 1. authorize (Kdc; client handle PrincipalLongterm, krbtgt handle
    ///    Krbtgt);
    /// 2. consume the proof: live, issued to this caller, bound to this
    ///    client (`Denied` otherwise — the proof is destroyed either way);
    /// 3. validate the template (`BadTemplate`): realm, TGS sname, enctype
    ///    configured, flags in the allowed mask, times within policy; then
    ///    the name bindings (`Denied`): crealm/cname must identify the client
    ///    key set's bound name, and the krbtgt key set must be bound to
    ///    krbtgt/realm = template sname (Q-040, A-19; RFC 4120 6.2, 7.3);
    /// 4. draw a fresh session key;
    /// 5. EncTicketPart sealed under the CURRENT krbtgt key, usage 2;
    /// 6. EncASRepPart sealed under the client key that pre-authenticated
    ///    (still the current version), usage 3, with the client kvno;
    /// 7. return the two sealed parts — the session key stays inside.
    ///
    /// Spec: docs/10 §4 (issue_as_rep, steps 1-7), §8; RFC 4120 3.1.3, 5.3,
    /// 5.4.2 (key usage 3; client kvno included), 7.5.1 (usages 2, 3).
    pub fn issue_as_rep(
        &mut self,
        caller: &CallerId,
        client: &KeyHandle,
        krbtgt: &KeyHandle,
        proof: &AuthnProof,
        template: &AsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<AsRepParts, IssueError> {
        let mut fields = AuditFields::for_handle(client);
        let result =
            self.issue_as_rep_inner(caller, client, krbtgt, proof, template, now, &mut fields);
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

        // Step 6: EncASRepPart under the client key (usage 3).
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
        let rep_cipher = seal(&mut self.entropy, client_key, AS_REP_ENC_PART, &rep_plain)?;
        Ok(AsRepParts {
            ticket,
            enc_part: EncryptedData {
                etype: client_key.enc_type().number(),
                kvno: Some(client_version.kvno().get()),
                cipher: rep_cipher,
            },
        })
    }
}
