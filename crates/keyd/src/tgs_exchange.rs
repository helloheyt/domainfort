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
//! Spec: RFC 4120 3.2.3, 3.3.2, 3.3.3, 5.2.7.1, 5.4.1, 5.4.2, 5.5.1, 7.3,
//! 7.5.1; docs/10 §5, §8, D33; docs/30 §3, §7.

use crate::as_exchange::token_deny;
use crate::audit::{AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::entropy::EntropySource;
use crate::error::{AuthnError, Deny, Internal, IssueError};
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
    EncryptionKey, KdcReqBody, KerberosTime, KeyValue, LastReq, PrincipalName, Realm, Ticket,
    TicketFlags, TransitedEncoding,
};
use zeroize::Zeroizing;

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
}

/// What keyd keeps about a live TGS context (never leaves keyd). The reply
/// key is zeroized when the entry is consumed or expires.
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
/// key) and the enc-part (sealed under the TGT session key or the
/// authenticator subkey).
///
/// Spec: docs/10 §5 (`struct TgsRep`); RFC 4120 5.4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TgsRepParts {
    /// `ticket [5] Ticket`.
    pub ticket: Ticket,
    /// `enc-part [6] EncryptedData` (EncTGSRepPart, key usage 8 or 9, no
    /// kvno).
    pub enc_part: EncryptedData,
}

/// A configured encryption type from a wire number, else `deny`.
fn configured_enctype(number: i32, supported: &[EncType], deny: Deny) -> Internal<EncType> {
    EncType::from_number(number)
        .ok()
        .filter(|e| supported.contains(e))
        .ok_or(deny)
}

/// Decrypt the TGT enc-part under the krbtgt key set: the version named by
/// the ticket's kvno, or — with no kvno — current then previous.
/// Spec: RFC 4120 3.2.3 ("decrypted using the version of the server's key
/// specified by the ticket"); docs/10 §1 ("decrypt may try a set of kvnos").
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

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// `open_and_verify_tgt`: open the TGT and the PA-TGS-REQ authenticator
    /// inside keyd and return a one-time [`TgtContext`].
    ///
    /// `ap_req` is the AP-REQ from the PA-TGS-REQ padata; `req_body` is the
    /// raw DER of the request's KDC-REQ-BODY, over which the authenticator
    /// checksum is verified.
    ///
    /// Checks (each failing as `AuthnError::Denied`, reason to audit only):
    /// 1. authorize (Kdc; krbtgt handle Krbtgt);
    /// 2. no USE-SESSION-KEY ap-option (user-to-user not implemented);
    /// 3. `req_body` decodes as KDC-REQ-BODY for this realm, without
    ///    enc-authorization-data;
    /// 4. the ticket is this realm's TGT (realm, sname krbtgt/realm), and the
    ///    krbtgt key set is bound to krbtgt/realm (Q-040, A-19);
    /// 5. decrypt the ticket under krbtgt (kvno-selected, else current then
    ///    previous), usage 2; decode EncTicketPart;
    /// 6. client realm is this realm; no INVALID flag; starttime not in the
    ///    future and endtime not past (± skew); no authorization-data or
    ///    addresses in the TGT;
    /// 7. decrypt the authenticator with the ticket session key, usage 7;
    ///    decode it; crealm / cname match the ticket; ctime within skew; no
    ///    authorization-data;
    /// 8. the checksum is present, of the session key's checksum type, and
    ///    verifies over `req_body` with usage 6 — binding the authenticator
    ///    to this request (no cut-and-paste);
    /// 9. the replay cache accepts (server, client, ctime, cusec);
    /// 10. store the reply key (subkey with usage 9, else session key with
    ///     usage 8) in a new context bound to this caller.
    ///
    /// Spec: RFC 4120 3.2.3, 3.3.2, 5.2.7.1 ("checksum ... computed over the
    /// KDC-REQ-BODY encoding"), 5.4.1 (req-body), 5.5.1 (cksum usage 6,
    /// authenticator usage 7), 7.3, 7.5.1; docs/10 §5, D33.
    pub fn open_and_verify_tgt(
        &mut self,
        caller: &CallerId,
        krbtgt: &KeyHandle,
        ap_req: &ApReq,
        req_body: &[u8],
        now: &KerberosTime,
    ) -> Result<TgtContext, AuthnError> {
        let mut fields = AuditFields::for_handle(krbtgt);
        let result =
            self.open_and_verify_tgt_inner(caller, krbtgt, ap_req, req_body, now, &mut fields);
        self.emit(caller, Operation::OpenAndVerifyTgt, now, &fields, &result);
        result.map_err(AuthnError::from)
    }

    fn open_and_verify_tgt_inner(
        &mut self,
        caller: &CallerId,
        krbtgt: &KeyHandle,
        ap_req: &ApReq,
        req_body: &[u8],
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<TgtContext> {
        authorize(
            caller,
            Operation::OpenAndVerifyTgt,
            &[(HandleSlot::Primary, krbtgt)],
        )?;
        let now_s = kerberos_time_seconds(now);
        let skew = self.config.clock_skew_secs;
        let realm = &self.config.realm;

        // 2. AP options.
        if ap_req.ap_options.contains(ApOptions::USE_SESSION_KEY) {
            return Err(Deny::denied(AuditReason::UnsupportedApOption));
        }

        // 3. The request body (structure only; its checksum is step 8).
        let body =
            KdcReqBody::decode(req_body).map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        if body.realm != *realm {
            return Err(Deny::denied(AuditReason::WrongRealm));
        }
        if body.enc_authorization_data.is_some() {
            return Err(Deny::denied(AuditReason::UnsupportedContent));
        }

        // 4. A TGT of this realm.
        let tgt = &ap_req.ticket;
        if tgt.realm != *realm || tgt.sname != tgs_name(realm) {
            return Err(Deny::denied(AuditReason::NotLocalTgt));
        }
        let ticket_enctype = configured_enctype(
            tgt.enc_part.etype,
            &self.config.enctypes,
            Deny::denied(AuditReason::UnsupportedEncType),
        )?;

        // 5. Decrypt under krbtgt.
        let set = self
            .store
            .get(krbtgt)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
        // Name binding (Q-040, A-19): the krbtgt key must be bound to this
        // realm's TGS name (RFC 4120 7.3).
        check_binding(set.binding(), realm, &tgs_name(realm))?;
        let (ticket_plain, version) = open_ticket(
            [Some(set.current()), set.previous()],
            &tgt.enc_part,
            ticket_enctype,
        )?;
        fields.kvno = Some(version.kvno());
        let ticket_part = EncTicketPart::decode(&ticket_plain)
            .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        drop(ticket_plain);

        // 6. Ticket validity.
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
        if start > now_s + i64::from(skew) {
            return Err(Deny::denied(AuditReason::TicketNotYetValid));
        }
        if now_s > kerberos_time_seconds(&ticket_part.endtime) + i64::from(skew) {
            return Err(Deny::denied(AuditReason::TicketExpired));
        }
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
        let authenticator_plain: Zeroizing<Vec<u8>> = open(
            &session,
            TGS_REQ_AUTHENTICATOR,
            &ap_req.authenticator.cipher,
        )?;
        let authenticator = Authenticator::decode(&authenticator_plain)
            .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
        drop(authenticator_plain);
        if authenticator.crealm != ticket_part.crealm || authenticator.cname != ticket_part.cname {
            return Err(Deny::denied(AuditReason::NameMismatch));
        }
        let ctime = kerberos_time_seconds(&authenticator.ctime);
        if !within_skew(ctime, now_s, skew) {
            return Err(Deny::denied(AuditReason::ClockSkew));
        }
        if authenticator.authorization_data.is_some() {
            return Err(Deny::denied(AuditReason::UnsupportedContent));
        }

        // 8. The checksum over the raw KDC-REQ-BODY.
        let cksum = authenticator
            .cksum
            .as_ref()
            .ok_or(Deny::denied(AuditReason::ChecksumMissing))?;
        let cksumtype = ChecksumType::from_number(cksum.cksumtype)
            .ok()
            .filter(|t| *t == session_enctype.checksum_type())
            .ok_or(Deny::denied(AuditReason::ChecksumUnsupported))?;
        krb_crypto::verify_mic(
            &session,
            cksumtype,
            key_usage(TGS_REQ_AUTHENTICATOR_CKSUM)?,
            req_body,
            &cksum.checksum,
        )
        .map_err(|_| Deny::denied(AuditReason::ChecksumMismatch))?;

        // 10 (prepared before the replay insert so that every check that can
        // fail precedes it). The reply key: subkey (usage 9) or session key
        // (usage 8). Spec: RFC 4120 3.3.3, 5.4.2.
        let (reply_key, reply_usage) = match &authenticator.subkey {
            Some(subkey) => {
                let enctype = configured_enctype(
                    subkey.keytype,
                    &self.config.enctypes,
                    Deny::denied(AuditReason::UnsupportedEncType),
                )?;
                let key = krb_crypto::random_to_key(enctype, subkey.keyvalue.as_bytes())
                    .map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
                drop(session);
                (key, TGS_REP_ENC_PART_SUBKEY)
            }
            None => (session, TGS_REP_ENC_PART_SESSION_KEY),
        };

        // 9. Replay cache (D33).
        let replay_key = ReplayKey {
            server_realm: tgt.realm.clone(),
            server: tgt.sname.clone(),
            client_realm: authenticator.crealm.clone(),
            client: authenticator.cname.clone(),
            ctime,
            cusec: authenticator.cusec.get(),
        };
        self.replay
            .check_and_insert(replay_key, skew, now_s)
            .map_err(|refusal| {
                Deny::denied(match refusal {
                    ReplayRefusal::Replay => AuditReason::Replay,
                    ReplayRefusal::Full => AuditReason::ReplayCacheFull,
                })
            })?;

        // 10. The one-time context.
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
            req_nonce: body.nonce,
            req_sname: body.sname,
        };
        let expires_at = now_s + i64::from(self.config.token_lifetime_secs);
        if !self.contexts.insert(id, *caller, expires_at, entry, now_s) {
            return Err(Deny::unavailable(AuditReason::TokenTableFull));
        }
        Ok(context)
    }

    /// `issue_tgs_rep`: consume `ctx` and issue a service ticket.
    ///
    /// 1. authorize (Kdc; service handle Service);
    /// 2. consume the context: live, issued to this caller (`Denied`
    ///    otherwise; destroyed either way);
    /// 3. the service key set's name binding must identify template.sname
    ///    in this realm (`Denied`, Q-040 A-19 — checked with the key below);
    ///    validate the template (`BadTemplate`): sname equals the
    ///    authenticated request's sname and is not a TGS name; nonce equals
    ///    the request nonce; enctype configured; flags (mask, RFC 4120 2.1 /
    ///    5.4.1 TGT rules); times within policy, endtime and renew-till not
    ///    beyond the TGT's (RFC 4120 3.3.3);
    /// 4. draw a fresh session key;
    /// 5. EncTicketPart — client name, realm, authtime, transited carried
    ///    over from the TGT — sealed under the CURRENT service key, usage 2;
    /// 6. EncTGSRepPart sealed under the context's reply key, usage 8
    ///    (session key) or 9 (subkey), without kvno.
    ///
    /// Spec: docs/10 §5 (issue_tgs_rep), §8; RFC 4120 3.3.3, 5.3, 5.4.2,
    /// 7.5.1 (usages 2, 8, 9).
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

        // 2. The context (I4).
        let entry = self
            .contexts
            .take(ctx.as_bytes(), caller, now_s)
            .map_err(token_deny)?;

        // 3. The template.
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
            let within_tgt = entry
                .renew_till
                .as_ref()
                .is_some_and(|tgt| kerberos_time_seconds(renew_till) <= kerberos_time_seconds(tgt));
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
        // Name binding (Q-040, A-19): the ticket for sname may only be sealed
        // under the key bound to sname in this realm — otherwise service X
        // could receive tickets naming service S.
        check_binding(service_set.binding(), &self.config.realm, &template.sname)?;
        let service_key = version
            .preferred()
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?;

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

        // 6. EncTGSRepPart under the reply key (usage 8 or 9), no kvno.
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
        let rep_cipher = seal(
            &mut self.entropy,
            &entry.reply_key,
            entry.reply_usage,
            &rep_plain,
        )?;
        Ok(TgsRepParts {
            ticket,
            enc_part: EncryptedData {
                etype: entry.reply_key.enc_type().number(),
                kvno: None,
                cipher: rep_cipher,
            },
        })
    }
}
