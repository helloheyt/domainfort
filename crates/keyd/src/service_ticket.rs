//! Service-ticket verification inside keyd: `open_and_verify_service_ticket`
//! (task L6a). Role `Ldap` only.
//!
//! "Compute, don't give" on the service side (docs/49 §3.3, R49-5; decision
//! A-46, docs/questions/Q-165 option (c)): the LDAP front hands keyd the
//! AP-REQ of a GSSAPI Bind, keyd runs the whole of RFC 4120 3.2.3 under the
//! LDAP service key — which never leaves keyd — and returns only non-secret
//! facts (client realm and name, authtime, endtime, flags, whether a subkey
//! was offered) plus a one-time [`ServiceCtxId`]. The ticket session key and
//! the authenticator subkey stay in keyd, in a bounded, caller-bound,
//! short-lived token table, and are zeroized when the entry is removed
//! (krb-crypto `ProtocolKey` wipes on drop). D29 in its strict form: no
//! session key goes to LDAP.
//!
//! The AP-REQ is opened by the steps keyd already uses for the TGS and the
//! FAST armor (`open_ap_req`, `complete_chain` in crate::tgs_exchange), with
//! key usage 11 ("normal application exchanges", RFC 4120 5.5.1) and the
//! one replay cache keyd keeps for every AP-REQ it verifies — RFC 4120 3.2.3:
//! "If multiple servers ... share a service principal ... they MUST share
//! this replay cache" (docs/49 §3.3).
//!
//! **Not here (task L6b, blocked on P-13 — RFC 4121 / RFC 2743, docs/49
//! §12):** the GSS token framing, the authenticator checksum (an AP-REQ
//! whose authenticator carries one is refused until then), channel binding,
//! the sequence number, and `seal_ap_rep` (RFC 4120 3.2.4: the AP-REP is
//! built in L6b, sealed by keyd with key usage 12). The service context is
//! held now so that L6b can use the session key without it ever leaving
//! keyd; in L6a nothing consumes it and it expires.
//!
//! Spec: RFC 4120 2.2, 3.2.3, 3.3.3.2, 5.3, 5.5.1, 6.2, 7.5.1; [MS-KILE]
//! 3.4.5 (retry with the previous server key); docs/10 §5ב, §8, §9, §12;
//! docs/49 §3.3, §12; docs/questions/Q-165 (A-46), Q-180; A-19
//! (docs/questions/Q-040); A-26 (docs/questions/Q-071).

use crate::audit::{AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::entropy::EntropySource;
use crate::error::{AuthnError, Deny, Internal};
use crate::keyd::{authorize, draw, AuditFields, Keyd};
use crate::model::KeyHandle;
use crate::store::{KeyStore, KvnoKeys, StoredKeySet};
use crate::template::check_binding;
use crate::tgs_exchange::{check_ap_options, replay_key_for, subkey_protocol_key, OpenedApReq};
use crate::time::kerberos_time_seconds;
use crate::tokens::{ServiceCtxId, TOKEN_ID_LENGTH};
use crate::usage::AP_REQ_AUTHENTICATOR;
use krb_crypto::ProtocolKey;
use krb_proto::constants::DOMAIN_X500_COMPRESS;
use krb_proto::{ApReq, KerberosTime, PrincipalName, Realm, TicketFlags, TransitedEncoding};

/// Non-secret facts of a verified service ticket, plus the one-time context
/// id that names the session key keyd keeps for the later GSS steps.
///
/// There is no key field (docs/10 §12 I1): not the service key, not the
/// session key, not the subkey — only whether a subkey was offered.
/// `channel_bound` (docs/49 §3.3) arrives with channel binding in task L6b.
///
/// Spec: docs/49 §3.3 (`struct ServiceContext { ctx_id, client, authtime,
/// endtime, flags, … } // no key field (I1)`); docs/questions/Q-165 item 2
/// (A-46); RFC 4120 5.3 (the EncTicketPart fields), 5.5.1 (subkey).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceContext {
    /// The one-time service-context token.
    pub ctx_id: ServiceCtxId,
    /// Client realm from the ticket (equal to the authenticator's).
    pub crealm: Realm,
    /// Client name from the ticket (equal to the authenticator's).
    pub cname: PrincipalName,
    /// Time of initial authentication — for the PEP's hot-list check
    /// (docs/49 §3.2, R49-15). Spec: RFC 4120 5.3 (authtime: "the necessary
    /// information for implementation of a 'hot list' service").
    pub authtime: KerberosTime,
    /// Ticket expiration time. Spec: RFC 4120 5.3 (endtime).
    pub endtime: KerberosTime,
    /// Ticket flags (never INVALID: such a ticket is refused).
    /// Spec: RFC 4120 2.2, 5.3.
    pub flags: TicketFlags,
    /// `true` if the authenticator offered a subkey ("the client's choice
    /// for an encryption key to be used to protect this specific application
    /// session"); the subkey itself stays in keyd. Spec: RFC 4120 5.5.1.
    pub subkey_present: bool,
}

/// What keyd keeps about a live service context (never leaves keyd). The
/// keys are zeroized when the entry is removed — consumed, expired, or
/// discarded with its destroyed service key set.
/// Spec: docs/10 §8, D36; docs/49 §3.3; RFC 4120 3.2.3 ("If a subkey is
/// present, the server either saves it for later use or uses it ...").
pub(crate) struct ServiceContextEntry {
    /// The service key set the ticket was opened under.
    service: KeyHandle,
    /// The ticket session key. Spec: RFC 4120 5.3 (key).
    #[expect(
        dead_code,
        reason = "held for seal_ap_rep / GSS wrap (task L6b, docs/49 §12); \
                  in L6a the entry only expires"
    )]
    session: ProtocolKey,
    /// The authenticator subkey, when offered. Spec: RFC 4120 5.5.1.
    #[expect(
        dead_code,
        reason = "held for the GSS steps (task L6b, docs/49 §12); in L6a the \
                  entry only expires"
    )]
    subkey: Option<ProtocolKey>,
}

impl ServiceContextEntry {
    /// The service key set the context was opened under (to discard the
    /// context when that key set is destroyed). Spec: docs/questions/Q-115
    /// (A-35).
    pub(crate) fn service(&self) -> KeyHandle {
        self.service
    }
}

/// The service key versions keyd may open a ticket under: only versions
/// keyd drew itself (`create_key` / `rotate_key` — no string-to-key salt),
/// never a password-derived one (`set_secret`), whose key may be known
/// outside keyd. A key set with no such version is refused before any key
/// is used (`Denied`).
///
/// A-46 (docs/questions/Q-165 item 4): the LDAP service key "is created in
/// `create_key` — the key never has to leave keyd because keyd itself
/// verifies". The `Directory` role can still `set_secret` a Service key set
/// (docs/10 §6); this rule keeps such a key from ever authenticating a Bind
/// (docs/questions/Q-180 item 4).
///
/// Spec: docs/questions/Q-165 item 4 (A-46); docs/10 §1 (current + previous
/// kvno), §12 I1.
fn random_versions(set: &StoredKeySet) -> Internal<[Option<&KvnoKeys>; 2]> {
    let versions =
        [Some(set.current()), set.previous()].map(|version| version.filter(|v| v.salt().is_none()));
    if versions.iter().all(Option::is_none) {
        return Err(Deny::denied(AuditReason::ServiceKeyNotRandom));
    }
    Ok(versions)
}

/// The transited field must be the empty DOMAIN-X500-COMPRESS encoding of
/// local authentication. The client is of this realm (checked by
/// `open_ap_req`) and phase 1 has no cross-realm path, so a non-empty field
/// — or an encoding keyd cannot read — is one keyd is "unable" to check, and
/// the authentication is rejected (`Denied`).
///
/// Spec: RFC 4120 3.3.3.2 ("both local and single-hop inter-realm
/// authentication result in a transited field that is empty"), 5.3
/// (transited-policy-checked: "If this flag is reset (0), then the
/// application server must check the transited field itself, and if unable
/// to do so, it must reject the authentication"), 7.5.5.
fn check_transited(transited: &TransitedEncoding) -> Internal<()> {
    if transited.tr_type == DOMAIN_X500_COMPRESS && transited.contents.is_empty() {
        Ok(())
    } else {
        Err(Deny::denied(AuditReason::TransitedNotLocal))
    }
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// `open_and_verify_service_ticket`: verify a service AP-REQ inside
    /// keyd under the service key (RFC 4120 3.2.3) and return a one-time
    /// [`ServiceContext`] — non-secret facts only.
    ///
    /// `ap_req_octets` is the DER of the KRB_AP_REQ as received: keyd
    /// decodes it itself, so the message keyd checks and the message keyd
    /// opens are the same octets (docs/49 §3.3 "like A-43").
    ///
    /// Checks failing as the uniform `AuthnError::Denied` (reason to audit
    /// only):
    /// 1. authorize (Ldap; service handle Service — I2, I3);
    /// 2. the octets decode as a DER AP-REQ: pvno 5, msg-type KRB_AP_REQ
    ///    (RFC 4120 3.2.3 KRB_AP_ERR_MSG_TYPE);
    /// 3. no USE-SESSION-KEY ap-option (user-to-user has no code path; RFC
    ///    4120 3.2.3, 3.7);
    /// 4. the ticket's srealm is this realm (RFC 4120 3.2.3: srealm "is used
    ///    to specify which secret key the server should use"; no
    ///    cross-realm), the service key set exists, and its name binding
    ///    identifies the ticket's (srealm, sname) — A-19: a ticket naming
    ///    another service is never opened under this key, and checked
    ///    before any key is used (the sname is in the clear part, RFC 4120
    ///    5.3);
    /// 5. the key set holds a version keyd drew itself (A-46; password-derived
    ///    versions are not candidates — [`random_versions`]); the ticket
    ///    decrypts under the version its kvno names, or with no kvno under
    ///    current then previous, usage 2 (RFC 4120 3.2.3
    ///    KRB_AP_ERR_BADKEYVER, KRB_AP_ERR_BAD_INTEGRITY; [MS-KILE] 3.4.5);
    ///    EncTicketPart decodes;
    /// 6. client realm is this realm; no INVALID flag (RFC 4120 2.2
    ///    "Application servers MUST reject tickets that have this flag
    ///    set" — the uniform `Denied`, as in the TGS path); no
    ///    authorization-data, no addresses (phase 1 tickets carry neither;
    ///    keyd cannot enforce them); the ticket times are RECORDED;
    /// 7. the authenticator decrypts under the ticket session key with key
    ///    usage 11 (RFC 4120 5.5.1, 7.5.1) and decodes; its crealm / cname
    ///    equal the ticket's (KRB_AP_ERR_BADMATCH); no authorization-data;
    ///    the ctime skew is RECORDED;
    /// 8. the transited field is that of local authentication
    ///    ([`check_transited`]);
    /// 9. the authenticator carries no checksum (task L6a has no
    ///    application data to verify one over; the RFC 4121 checksum is task
    ///    L6b — docs/questions/Q-180 item 3);
    /// 10. a subkey, when present, is a configured enctype and a valid key
    ///     (I5).
    ///
    /// Only now — the ticket and the authenticator decrypted — are the
    /// recorded findings reported, as non-secret classes (A-26), in RFC 4120
    /// 3.2.3 order: ctime skew → `Skew`; starttime (or authtime) later than
    /// now beyond the skew → `TicketNotYetValid`; endtime earlier than now
    /// beyond the skew → `TicketExpired`. A request refused for these never
    /// enters the replay cache. Then:
    /// 11. the shared replay cache accepts (server, client, ctime, cusec),
    ///     else `Replay` (a full cache stays `Denied`, fail closed — RFC 4120
    ///     3.2.3 "MUST reject all requests until the clock skew interval has
    ///     passed");
    /// 12. the session key and the subkey are stored under a fresh
    ///     [`ServiceCtxId`] bound to this caller, for the token lifetime
    ///     (table full: `Denied`).
    ///
    /// Any cryptographic failure is `Denied` even when the ticket is also
    /// expired or the authenticator also skewed: the classes are reachable
    /// only by a holder of the ticket session key, so they are no decryption
    /// or MAC oracle (A-26).
    ///
    /// The address check of RFC 4120 3.2.3 has nothing to compare (tickets
    /// with addresses are refused at step 6); the authorization decision
    /// ("Applications MUST make a separate authorization decision") is the
    /// LDAP PEP's and the PDP's, on the returned facts (docs/49 §3.2).
    ///
    /// Spec: RFC 4120 2.2, 3.2.3, 3.3.3.2, 5.3, 5.5.1, 6.2, 7.5.1; [MS-KILE]
    /// 3.4.5; docs/10 §5ב, §9 (A-26); docs/49 §3.3; docs/questions/Q-165
    /// (A-46), Q-180; A-19 (docs/questions/Q-040).
    pub fn open_and_verify_service_ticket(
        &mut self,
        caller: &CallerId,
        service: &KeyHandle,
        ap_req_octets: &[u8],
        now: &KerberosTime,
    ) -> Result<ServiceContext, AuthnError> {
        let mut fields = AuditFields::for_handle(service);
        let result = self.open_and_verify_service_ticket_inner(
            caller,
            service,
            ap_req_octets,
            now,
            &mut fields,
        );
        self.emit(
            caller,
            Operation::OpenAndVerifyServiceTicket,
            now,
            &fields,
            &result,
        );
        result.map_err(AuthnError::from)
    }

    fn open_and_verify_service_ticket_inner(
        &mut self,
        caller: &CallerId,
        service: &KeyHandle,
        ap_req_octets: &[u8],
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<ServiceContext> {
        // 1. Role Ldap, purpose Service (I2, I3).
        authorize(
            caller,
            Operation::OpenAndVerifyServiceTicket,
            &[(HandleSlot::Primary, service)],
        )?;
        let now_s = kerberos_time_seconds(now);

        // 2. The AP-REQ, decoded by keyd (strict DER; pvno, msg-type).
        // Spec: RFC 4120 3.2.3 (KRB_AP_ERR_MSG_TYPE), 5.5.1.
        let ap_req =
            ApReq::decode(ap_req_octets).map_err(|_| Deny::denied(AuditReason::MalformedInput))?;

        // 3. AP options. Spec: RFC 4120 3.2.3, 3.7, 5.5.1.
        check_ap_options(&ap_req)?;

        // 4. srealm, the key set, and its name binding (A-19), before any
        // key is used.
        let realm = &self.config.realm;
        if ap_req.ticket.realm != *realm {
            return Err(Deny::denied(AuditReason::WrongRealm));
        }
        let set = self
            .store
            .get(service)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?;
        check_binding(set.binding(), &ap_req.ticket.realm, &ap_req.ticket.sname)?;

        // 5-7. Only keyd-drawn versions (A-46); the ticket under usage 2,
        // the authenticator under usage 11 (shared steps).
        let versions = random_versions(set)?;
        let OpenedApReq {
            ticket_part,
            session,
            authenticator,
            ctime,
            findings,
        } = self.open_ap_req(versions, &ap_req, AP_REQ_AUTHENTICATOR, now_s, fields)?;

        // 8. Transited: local authentication only. Spec: RFC 4120 3.3.3.2,
        // 5.3.
        check_transited(&ticket_part.transited)?;

        // 9. No application-data checksum in L6a (Q-180 item 3).
        // Spec: RFC 4120 5.5.1 (cksum).
        if authenticator.cksum.is_some() {
            return Err(Deny::denied(AuditReason::ApChecksumUnsupported));
        }

        // 10. The subkey: a configured enctype and a valid key (I5).
        // Spec: RFC 4120 5.5.1; docs/10 §12 I5.
        let subkey = authenticator
            .subkey
            .as_ref()
            .map(|subkey| subkey_protocol_key(subkey, &self.config.enctypes))
            .transpose()?;

        // The cryptographic chain is complete: the ticket decrypted under the
        // service key and the authenticator under the session key. Only now
        // are the recorded findings reported, then the replay cache (step 11)
        // consulted (A-26). Spec: RFC 4120 3.2.3.
        self.complete_chain(
            findings,
            replay_key_for(&ap_req.ticket, &authenticator, ctime),
            now_s,
        )?;

        // 12. The one-time service context. Spec: docs/10 §8, D36; docs/49
        // §3.3.
        let mut id = [0u8; TOKEN_ID_LENGTH];
        draw(&mut self.entropy, &mut id)?;
        let context = ServiceContext {
            ctx_id: ServiceCtxId::from_bytes(id),
            crealm: ticket_part.crealm.clone(),
            cname: ticket_part.cname.clone(),
            authtime: ticket_part.authtime,
            endtime: ticket_part.endtime,
            flags: ticket_part.flags,
            subkey_present: subkey.is_some(),
        };
        let entry = ServiceContextEntry {
            service: *service,
            session,
            subkey,
        };
        let expires_at = now_s + i64::from(self.config.token_lifetime_secs);
        if !self
            .service_contexts
            .insert(id, *caller, expires_at, entry, now_s)
        {
            return Err(Deny::unavailable(AuditReason::TokenTableFull));
        }
        Ok(context)
    }
}
