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
//! # The application binding (R2; docs/52 §3.2, §5; decision A-102)
//!
//! The caller names the service key set by its principal and an
//! [`AppBinding`]; the key set's purpose is the binding's
//! ([`AppBinding::key_purpose`]), never the caller's choice:
//!
//! | binding | key set | the Authenticator's `cksum` |
//! |---|---|---|
//! | `Unbound` (the LDAP front, L6a) | `(principal, Service)` | must be absent (`ApChecksumUnsupported`) |
//! | `OperationDigest(d)` (dird's admin channel) | `(principal, AdminService)` | must be present (`OperationDigestMissing`), of the session key's required checksum type, and verify as `get_mic(session key, usage 10, d)` (`OperationDigestMismatch`) |
//!
//! What is MIC'd: the 32 octets of the operation digest — the application
//! data the admin channel defines for its AP-REQs (crate ipc-dird-admin
//! `operation_digest`). RFC 4120 5.5.1: the `cksum` is "a checksum of the
//! application data that accompanies the KRB_AP_REQ, computed using a key
//! usage value of 10"; 7.5.1 item 10: "keyed with the application session
//! key" — the ticket session key, not an authenticator subkey; RFC 4120 §4:
//! the RFC 3961 `get_mic` with that key usage; RFC 3961 §3: the checksum
//! mechanism is the session key enctype's "required checksum mechanism"
//! (RFC 3962 §7, RFC 8009 §6 — krb-crypto `EncType::checksum_type`), the
//! same rule keyd applies to the TGS checksum (usage 6). A failure is part
//! of the cryptographic chain: the uniform `Denied` (A-26), before the
//! replay cache, so an AP-REQ attached to another operation leaves no
//! replay entry and no service context.
//!
//! **Not here (task L6b, blocked on P-13 — RFC 4121 / RFC 2743, docs/49
//! §12):** the GSS token framing, the GSS authenticator checksum (an
//! unbound AP-REQ whose authenticator carries one is refused until then),
//! channel binding, the sequence number, and `seal_ap_rep` (RFC 4120 3.2.4:
//! the AP-REP is built in L6b, sealed by keyd with key usage 12). The
//! service context is held now so that L6b can use the session key without
//! it ever leaving keyd; in L6a nothing consumes it and it expires.
//!
//! Spec: RFC 4120 §4, 2.2, 3.2.3, 3.3.3, 3.3.3.2, 5.3, 5.5.1, 6.2, 7.5.1;
//! RFC 3961 §3, §4; RFC 3962 §7; RFC 8009 §6; [MS-KILE] 3.4.5 (retry with
//! the previous server key); docs/10 §5ב, §8, §9, §12; docs/49 §3.3, §12;
//! docs/52 §3.2, §5; docs/questions/Q-165 (A-46), Q-180, Q-463 (A-102);
//! A-19 (docs/questions/Q-040); A-26 (docs/questions/Q-071).

use crate::audit::{AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::entropy::EntropySource;
use crate::error::{AuthnError, Deny, Internal};
use crate::keyd::{draw, key_usage, AuditFields, Keyd};
use crate::model::{KeyHandle, PrincipalId};
use crate::store::{KeyStore, KvnoKeys, StoredKeySet};
use crate::template::check_binding;
use crate::tgs_exchange::{check_ap_options, replay_key_for, subkey_protocol_key, OpenedApReq};
use crate::time::kerberos_time_seconds;
use crate::tokens::{ServiceCtxId, TOKEN_ID_LENGTH};
use crate::usage::{AP_REQ_AUTHENTICATOR, AP_REQ_AUTHENTICATOR_CKSUM};
use keyd_types::{AppBinding, OperationDigest, ServiceContext};
use krb_crypto::{ChecksumType, ProtocolKey};
use krb_proto::constants::DOMAIN_X500_COMPRESS;
use krb_proto::{ApReq, Checksum, KerberosTime, TransitedEncoding};

// `ServiceContext`, the result type of this operation, lives in the
// crypto-free keyd-types crate (D182; decision A-63) and is re-exported at
// the crate root.

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

/// Step 9: the Authenticator's application-data checksum, as `binding`
/// requires (module documentation, "The application binding"). `Ok` carries
/// the operation digest the `cksum` was verified over (`None` for an unbound
/// verification). Every failure is the uniform `Denied` with its own audit
/// reason.
///
/// Spec: RFC 4120 §4 ("the corresponding ... get_mic operations described in
/// [RFC3961], with implicit 'specific key' generation using the 'key usage'
/// values"), 3.3.3 (a checksum that does not match is rejected), 5.5.1
/// (cksum, key usage 10), 7.5.1 item 10 ("keyed with the application session
/// key"); RFC 3961 §3 ("required checksum mechanism"), §4 (verify_mic);
/// RFC 3962 §7; RFC 8009 §6; docs/52 §5 items 2-3; docs/questions/Q-180
/// item 3 (the unbound rule), Q-463 (A-102).
fn verify_app_binding(
    session: &ProtocolKey,
    cksum: Option<&Checksum>,
    binding: &AppBinding,
) -> Internal<Option<OperationDigest>> {
    match (binding, cksum) {
        (AppBinding::Unbound, None) => Ok(None),
        // L6a has no application data to verify a checksum over; ignoring it
        // would waive a binding the client asked for (Q-180 item 3).
        (AppBinding::Unbound, Some(_)) => Err(Deny::denied(AuditReason::ApChecksumUnsupported)),
        (AppBinding::OperationDigest(_), None) => {
            Err(Deny::denied(AuditReason::OperationDigestMissing))
        }
        (AppBinding::OperationDigest(digest), Some(cksum)) => {
            // Exactly the session key's required checksum type: Kerberos
            // has no checksum negotiation (RFC 3961 §3), and krb-crypto
            // implements only the keyed, collision-proof AES types.
            let cksumtype = ChecksumType::from_number(cksum.cksumtype)
                .ok()
                .filter(|t| *t == session.enc_type().checksum_type())
                .ok_or(Deny::denied(AuditReason::OperationDigestMismatch))?;
            krb_crypto::verify_mic(
                session,
                cksumtype,
                key_usage(AP_REQ_AUTHENTICATOR_CKSUM)?,
                digest.as_bytes(),
                &cksum.checksum,
            )
            .map_err(|_| Deny::denied(AuditReason::OperationDigestMismatch))?;
            Ok(Some(*digest))
        }
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
    /// The service key set is `(service, binding.key_purpose())`: the
    /// caller names the principal and the [`AppBinding`]; the purpose
    /// follows from the binding (R2, module documentation) — an admin
    /// service ticket cannot be asked for unbound, nor an operation digest
    /// verified under any other key set.
    ///
    /// Checks failing as the uniform `AuthnError::Denied` (reason to audit
    /// only):
    /// 1. authorize and admit (Ldap; the derived handle Service or
    ///    AdminService — I2, I3);
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
    /// 9. the authenticator's checksum as the binding requires
    ///    ([`verify_app_binding`]): none when `Unbound` (task L6a has no
    ///    application data to verify one over; the RFC 4121 checksum is task
    ///    L6b — docs/questions/Q-180 item 3); for `OperationDigest(d)`
    ///    present, of the session key's required checksum type, and the
    ///    session key's MIC over `d` with key usage 10 (RFC 4120 5.5.1,
    ///    7.5.1 item 10; RFC 3961 §3, §4);
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
    ///     (table full: `Denied`); the answer names the verified operation
    ///     digest ([`ServiceContext::bound_operation`]).
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
    /// Spec: RFC 4120 2.2, 3.2.3, 3.3.3.2, 5.3, 5.5.1, 6.2, 7.5.1; RFC 3961
    /// §3, §4; [MS-KILE] 3.4.5; docs/10 §5ב, §9 (A-26); docs/49 §3.3;
    /// docs/52 §5; docs/questions/Q-165 (A-46), Q-180, Q-463 (A-102); A-19
    /// (docs/questions/Q-040).
    pub fn open_and_verify_service_ticket(
        &mut self,
        caller: &CallerId,
        service: &PrincipalId,
        binding: &AppBinding,
        ap_req_octets: &[u8],
        now: &KerberosTime,
    ) -> Result<ServiceContext, AuthnError> {
        // The key set is named by the binding's purpose (R2): no caller can
        // pair the admin service key with an unbound verification.
        let handle = KeyHandle::new(*service, binding.key_purpose());
        let mut fields = AuditFields::for_handle(&handle);
        let result = self.open_and_verify_service_ticket_inner(
            caller,
            &handle,
            binding,
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
        binding: &AppBinding,
        ap_req_octets: &[u8],
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<ServiceContext> {
        // 1. Role Ldap, purpose Service or AdminService — the binding's
        // (I2, I3).
        self.admit(
            caller,
            Operation::OpenAndVerifyServiceTicket,
            &[(HandleSlot::Primary, service)],
            now,
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

        // 9. The application-data checksum, as the binding requires (R2).
        // Spec: RFC 4120 5.5.1 (cksum), 7.5.1 item 10; RFC 3961 §3, §4.
        let bound_operation = verify_app_binding(&session, authenticator.cksum.as_ref(), binding)?;

        // 10. The subkey: a configured enctype and a valid key (I5).
        // Spec: RFC 4120 5.5.1; docs/10 §12 I5.
        let subkey = authenticator
            .subkey
            .as_ref()
            .map(|subkey| subkey_protocol_key(subkey, &self.enctypes))
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
            bound_operation,
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

#[cfg(test)]
mod tests {
    use super::*;
    use krb_crypto::{EncType, KeyUsage};

    /// The four encryption types keyd's profile has (RFC 3962 §7; RFC 8009
    /// §7), each with a made-up session key of its length.
    fn session_keys() -> Vec<ProtocolKey> {
        [17, 18, 19, 20]
            .into_iter()
            .map(|n| {
                let enctype = EncType::from_number(n).unwrap();
                krb_crypto::random_to_key(enctype, &vec![0x3C; enctype.key_length()]).unwrap()
            })
            .collect()
    }

    fn mic(key: &ProtocolKey, cksumtype: ChecksumType, usage: u32, message: &[u8]) -> Checksum {
        Checksum {
            cksumtype: cksumtype.number(),
            checksum: krb_crypto::get_mic(key, cksumtype, KeyUsage::new(usage).unwrap(), message)
                .unwrap(),
        }
    }

    fn reason(result: Internal<Option<OperationDigest>>) -> Option<AuditReason> {
        result.err().map(|deny| deny.reason)
    }

    /// The operation binding as a round trip over every enctype: the
    /// client's `get_mic` (krb-crypto, checked against the RFC 3962 / RFC
    /// 8009 test vectors in its own tests) with the session key's required
    /// checksum type and key usage 10 verifies; another usage, another
    /// checksum type, another digest, another key, or no `cksum` does not;
    /// an unbound verification refuses any `cksum`. No RFC gives an example
    /// of an AP-REQ authenticator checksum, so this is the round trip the
    /// task asks for. Source: RFC 4120 §4, 5.5.1, 7.5.1 item 10; RFC 3961
    /// §3, §4; RFC 3962 §7; RFC 8009 §6, §7; docs/52 §5 item 2.
    #[test]
    fn operation_binding_round_trips_for_every_enctype() {
        let digest = OperationDigest::new([0x6F; 32]);
        let other = OperationDigest::new([0x70; 32]);
        let bound = AppBinding::OperationDigest(digest);
        let keys = session_keys();
        for (i, key) in keys.iter().enumerate() {
            let own = key.enc_type().checksum_type();
            let good = mic(key, own, 10, digest.as_bytes());
            assert_eq!(
                verify_app_binding(key, Some(&good), &bound),
                Ok(Some(digest)),
                "{:?}",
                key.enc_type()
            );
            for wrong in [
                mic(key, own, 6, digest.as_bytes()),
                mic(key, own, 11, digest.as_bytes()),
                mic(key, own, 10, other.as_bytes()),
                mic(
                    &keys[(i + 1) % keys.len()],
                    keys[(i + 1) % keys.len()].enc_type().checksum_type(),
                    10,
                    digest.as_bytes(),
                ),
                Checksum {
                    cksumtype: own.number(),
                    checksum: good.checksum[..good.checksum.len() - 1].to_vec(),
                },
                Checksum {
                    cksumtype: 0x8003,
                    checksum: good.checksum.clone(),
                },
            ] {
                assert_eq!(
                    reason(verify_app_binding(key, Some(&wrong), &bound)),
                    Some(AuditReason::OperationDigestMismatch)
                );
            }
            assert_eq!(
                reason(verify_app_binding(key, None, &bound)),
                Some(AuditReason::OperationDigestMissing)
            );
            assert_eq!(
                verify_app_binding(key, None, &AppBinding::Unbound),
                Ok(None)
            );
            assert_eq!(
                reason(verify_app_binding(key, Some(&good), &AppBinding::Unbound)),
                Some(AuditReason::ApChecksumUnsupported)
            );
        }
    }
}
