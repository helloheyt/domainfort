//! The Ticket-Granting Service exchange: receipt of KRB_TGS_REQ and
//! generation of KRB_TGS_REP (phase 1: a service ticket of this realm from a
//! TGT of this realm) — always FAST-armored, with the implicit armor of
//! RFC 6113 5.4.2 (docs/48 §5, §7).
//!
//! Steps, each refusing with the code named:
//! 1. no PA-TGS-REQ → KDC_ERR_PADATA_TYPE_NOSUPP (3.3.2: "If no ticket can be
//!    found in the padata field"); more than one → KRB_ERR_GENERIC
//!    (ambiguous); a value that is not an AP-REQ → KRB_AP_ERR_MSG_TYPE
//!    (3.2.3), otherwise undecodable → KRB_ERR_GENERIC;
//! 2. FAST (docs/48 §5, §7.2 layer 1): no PA-FX-FAST → KDC_ERR_POLICY before
//!    keyd is asked (the TGS is always armored; docs/questions/Q-125 item
//!    11); more than one → KRB_ERR_GENERIC; undecodable →
//!    KDC_ERR_PREAUTH_FAILED (Q-125 item 2); an explicit armor field →
//!    KDC_ERR_PREAUTH_FAILED (implicit armor only: "This armor type is only
//!    valid for AS requests", RFC 6113 5.4.1.1; docs/questions/Q-124 item 2);
//! 3. the presented ticket is not this realm's TGT (cleartext realm / sname)
//!    → KRB_AP_ERR_NOT_US (3.2.3, 3.3.2);
//! 4. keyd `open_and_verify_tgt` over the raw outer KDC-REQ-BODY (decision
//!    13) with the FAST part — the PA-TGS-REQ padata-value octets, over which
//!    the req-checksum is computed, and the KrbFastArmoredReq (RFC 6113
//!    5.4.2; docs/questions/Q-150 item 1) — refuses (see [`tgt_refusal`],
//!    A-26): uniformly before its cryptographic chain completed →
//!    KRB_AP_ERR_BAD_INTEGRITY (3.3.2 names it for the decryption step every
//!    forged or altered request fails at); after it completed, the non-secret
//!    class → KRB_AP_ERR_SKEW, KRB_AP_ERR_TKT_NYV, KRB_AP_ERR_TKT_EXPIRED or
//!    KRB_AP_ERR_REPEAT (3.2.3, 3.3.2). Every refusal up to here is
//!    UNARMORED (keyd keeps no token after a failure; Q-125 item 9); from
//!    here on every refusal is ARMORED — sealed by keyd under the implicit
//!    armor key with `seal_fast_error(Tgs)` (docs/48 §6.1) — and the request
//!    is the INNER one (RFC 6113 5.4.2: "A conforming KDC ignores the outer
//!    KDC-REQ-BODY field");
//! 5. a critical FastOptions bit (0-15) → KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS
//!    (A-25, docs/48 §8);
//! 6. on the inner body: operation options / unsupported content →
//!    KDC_ERR_BADOPTION (decision 9); another realm, or a TGS name of another
//!    realm → KDC_ERR_S_PRINCIPAL_UNKNOWN (no inter-realm key; decision 4);
//!    no sname → KDC_ERR_S_PRINCIPAL_UNKNOWN (5.4.1: sname may only be
//!    absent with ENC-TKT-IN-SKEY, refused); this realm's TGS name →
//!    KDC_ERR_POLICY (phase 1 issues no TGT from a TGT; keyd refuses it,
//!    docs/10 §5); the change-password service `kadmin/changepw` →
//!    KDC_ERR_POLICY (its tickets come only from an armored AS, docs/53
//!    §5.2; keyd's `issue_tgs_rep` refuses its key set too); starttime
//!    beyond the skew → KDC_ERR_CANNOT_POSTDATE (3.3.3);
//! 7. re-evaluation at use (D53, decision 8): the client account is read
//!    again — source failure → KRB_ERR_GENERIC (unreachable →
//!    KDC_ERR_SVC_UNAVAILABLE); gone, disabled, locked or
//!    expired → KDC_ERR_CLIENT_REVOKED; TGT authtime before the account's
//!    revocation instant → KDC_ERR_TGT_REVOKED (3.3.3.1 hot-list);
//! 8. the service account: unknown → KDC_ERR_S_PRINCIPAL_UNKNOWN; disabled,
//!    locked or expired → KDC_ERR_SERVICE_REVOKED (decision 8);
//! 9. no acceptable AES enctype for the session key → KDC_ERR_ETYPE_NOSUPP
//!    (3.1.3 via 3.3.2; decision 6);
//! 10. the PDP (`KdcTgs`, resource = the service, `armored = true`) denies →
//!     KDC_ERR_POLICY (docs/30 §3.3; docs/48 §4.2; decision 7);
//! 11. times planned within policy and within the TGT (3.3.3; decision 10)
//!     → KDC_ERR_NEVER_VALID if too short;
//! 12. keyd `issue_tgs_rep` on the armored context seals the service ticket,
//!     the reply under the strengthened reply key, and the KrbFastResponse
//!     (RFC 6113 5.4.3); a refusal leaves the context live for the armored
//!     error (docs/questions/Q-150 item 3);
//! 13. the TGS-REP: padata = [PA-FX-FAST(enc-fast-rep)] (5.4.3); crealm /
//!     cname of the TGT (3.3.3: "the client's name and realm ... of the
//!     newly-issued ticket" come from the TGT).
//!
//! Every keyd call above (`open_and_verify_tgt`, `issue_tgs_rep`) that keyd
//! does not serve — the `Unavailable` variant: its startup hold-down (RFC
//! 4120 3.2.3), or keyd unreachable at an IPC client — and every lookup
//! whose account source cannot be reached is KDC_ERR_SVC_UNAVAILABLE (7.5.9,
//! code 29), never KRB_AP_ERR_BAD_INTEGRITY; nothing is sent over UDP
//! (docs/50 §3.7, R50-8; A-56).
//!
//! Spec: RFC 4120 3.2.3, 3.3.2, 3.3.3, 3.3.3.1, 5.2.7.1, 5.4.1, 5.4.2, 7.5.9;
//! RFC 6113 5.4.1.1, 5.4.2, 5.4.3, 5.4.4, 7.3; docs/30 §3; docs/10 §5, §5a;
//! docs/48 §5, §6, §7.2; docs/25 §4 (D53); docs/50 §3.7 (R50-8); docs/53
//! §5.2 (task K5); docs/questions/Q-124, Q-125 (A-32), Q-150 (A-43), Q-217
//! (A-56); main-session decisions 3-10, 13; A-25, A-26, A-117.

use crate::accounts::AccountSource;
use crate::as_exchange::has_unsupported_content;
use crate::audit::{AuditReason, AuditSink};
use crate::etype::negotiate;
use crate::fast::{armored_request, fx_fast_padata, fx_fast_reply, has_critical_fast_option};
use crate::gate::{enforce, PolicyInputs, Question, RateLimiter};
use crate::kdc::{
    account_source_refusal, custody_unavailable, internal, issue_refusal, time_refusal, Kdc,
    Refusal, Scope,
};
use crate::lifetime::{check_starttime, plan, LifetimeRequest, Limits};
use crate::names::{classify_server, same_realm, service_spn, ServerNameKind};
use crate::options::{asks_unsupported_operation, delegation_flags, FlagRequests};
use crate::time::seconds;
use crate::transport::Peer;
use core::time::Duration;
use keyd_types::{AuthnError, KeyCustody, KeyPurpose, TgsFastRequest, TgsTicketTemplate};
use krb_proto::constants::{
    KDC_ERR_BADOPTION, KDC_ERR_CLIENT_REVOKED, KDC_ERR_ETYPE_NOSUPP, KDC_ERR_PADATA_TYPE_NOSUPP,
    KDC_ERR_POLICY, KDC_ERR_PREAUTH_FAILED, KDC_ERR_SERVICE_REVOKED, KDC_ERR_S_PRINCIPAL_UNKNOWN,
    KDC_ERR_TGT_REVOKED, KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS, KRB_AP_ERR_BAD_INTEGRITY,
    KRB_AP_ERR_MSG_TYPE, KRB_AP_ERR_NOT_US, KRB_AP_ERR_REPEAT, KRB_AP_ERR_SKEW,
    KRB_AP_ERR_TKT_EXPIRED, KRB_AP_ERR_TKT_NYV, KRB_ERR_GENERIC, PA_TGS_REQ,
};
use krb_proto::{ApReq, KdcRep, KdcReq, KerberosTime, TgsRep, TicketFlags};
use pdp::{Action, KerbResKind, Resource, Spn};

/// keyd's `open_and_verify_tgt` refusals (A-26, docs/questions/Q-071), sent
/// unarmored under FAST too (docs/questions/Q-125 item 9: keyd keeps no
/// token after a failure).
///
/// keyd reports a class only after the TGT decrypted, the authenticator
/// decrypted and the req-body checksum verified (and, under FAST, the
/// req-checksum verified and the KrbFastReq decrypted) — facts only a holder
/// of the TGT session key can learn, so no decryption or MAC oracle.
/// Everything decided before that is the uniform `Denied`:
/// - `Denied` → KRB_AP_ERR_BAD_INTEGRITY (3.3.2: "If any of the decryptions
///   indicate failed integrity checks");
/// - `TicketExpired` → KRB_AP_ERR_TKT_EXPIRED (3.2.3);
/// - `TicketNotYetValid` → KRB_AP_ERR_TKT_NYV (3.2.3);
/// - `Skew` → KRB_AP_ERR_SKEW (3.2.3); the KRB-ERROR's stime is the KDC's
///   `now` (5.9.1);
/// - `Replay` → KRB_AP_ERR_REPEAT (3.2.3; 3.3.2: "the KDC SHOULD return
///   KRB_AP_ERR_REPEAT");
/// - `Unavailable` — keyd did not look at the request (its startup
///   hold-down, or keyd unreachable) → KDC_ERR_SVC_UNAVAILABLE (7.5.9), never
///   BAD_INTEGRITY (docs/50 §3.7, R50-8; A-56).
///
/// Spec: RFC 4120 3.2.3, 3.3.2, 5.9.1, 7.5.9; docs/questions/Q-071 (A-26),
/// Q-125 item 9, Q-217 (A-56).
fn tgt_refusal(error: AuthnError) -> Refusal {
    match error {
        AuthnError::Unavailable => custody_unavailable(),
        AuthnError::Denied => Refusal::new(KRB_AP_ERR_BAD_INTEGRITY, AuditReason::TgtDenied),
        AuthnError::TicketExpired => Refusal::new(KRB_AP_ERR_TKT_EXPIRED, AuditReason::TgtExpired),
        AuthnError::TicketNotYetValid => {
            Refusal::new(KRB_AP_ERR_TKT_NYV, AuditReason::TgtNotYetValid)
        }
        AuthnError::Skew => Refusal::new(KRB_AP_ERR_SKEW, AuditReason::AuthenticatorSkew),
        AuthnError::Replay => Refusal::new(KRB_AP_ERR_REPEAT, AuditReason::AuthenticatorReplay),
    }
}

impl<K: KeyCustody, U: AuditSink, R: RateLimiter> Kdc<K, U, R> {
    /// Receipt of KRB_TGS_REQ and generation of KRB_TGS_REP (module docs).
    /// `scope` turns to the inner request once keyd verified the implicit
    /// armor; `accounts` is this request's account source (docs/47 R47-14).
    /// Spec: RFC 4120 3.3.2, 3.3.3; RFC 6113 5.4.2; docs/30 §3; docs/48 §5.
    pub(crate) fn receive_tgs_req(
        &mut self,
        req: &KdcReq,
        scope: &mut Scope,
        peer: Peer,
        now: &KerberosTime,
        policy: &PolicyInputs<'_>,
        accounts: &dyn AccountSource,
    ) -> Result<Vec<u8>, Refusal> {
        let keyd_config = self.custody.config();
        let configured: Vec<i32> = keyd_config.enctypes.iter().map(|e| e.number()).collect();
        let skew = keyd_config.clock_skew_secs;
        let ticket_policy = keyd_config.ticket_policy;
        let realm = self.config.realm.clone();

        // 1. The authentication header (3.3.2, 5.2.7.1, 3.2.3).
        let padata = req.padata.as_deref().unwrap_or(&[]);
        let mut headers = padata.iter().filter(|p| p.padata_type == PA_TGS_REQ);
        let header = match (headers.next(), headers.next()) {
            (None, _) => {
                return Err(Refusal::new(
                    KDC_ERR_PADATA_TYPE_NOSUPP,
                    AuditReason::TgsPadataMissing,
                ))
            }
            (Some(_), Some(_)) => {
                return Err(Refusal::new(
                    KRB_ERR_GENERIC,
                    AuditReason::TgsPadataAmbiguous,
                ))
            }
            (Some(header), None) => header,
        };
        let ap_req = ApReq::decode(&header.padata_value).map_err(|error| {
            let code = match error {
                krb_proto::Error::UnexpectedApplicationTag
                | krb_proto::Error::ExpectedApplicationTag => KRB_AP_ERR_MSG_TYPE,
                _ => KRB_ERR_GENERIC,
            };
            Refusal::new(code, AuditReason::ApReqMalformed)
        })?;

        // 2. FAST is mandatory for the TGS (docs/48 §7.2 layer 1, before
        // keyd), with implicit armor only (RFC 6113 5.4.1.1, 5.4.2; Q-124).
        let fast = fx_fast_padata(padata)?
            .ok_or(Refusal::new(KDC_ERR_POLICY, AuditReason::FastRequired))?;
        let armored_req = armored_request(fast)?;
        if armored_req.armor.is_some() {
            return Err(Refusal::new(
                KDC_ERR_PREAUTH_FAILED,
                AuditReason::TgsExplicitArmor,
            ));
        }

        // 3. The presented ticket must be this realm's TGT (3.3.2, 3.2.3).
        let ticket = &ap_req.ticket;
        if !same_realm(&ticket.realm, &realm)
            || classify_server(&ticket.sname, &realm) != ServerNameKind::LocalTgs
        {
            return Err(Refusal::new(KRB_AP_ERR_NOT_US, AuditReason::NotLocalTgt));
        }

        // 4. keyd verifies the TGT, the authenticator over the raw outer
        // KDC-REQ-BODY (5.2.7.1; decision 13; A-17, Q-124 item 1) and the
        // implicit armor: the req-checksum over the PA-TGS-REQ AP-REQ octets
        // and the KrbFastReq (RFC 6113 5.4.2). krb-proto decodes strict DER
        // only and losslessly, so encoding the decoded body reproduces the
        // received octets exactly (proven by tests/body_reencode.rs).
        let raw_body = req
            .req_body
            .encode()
            .map_err(|_| internal(AuditReason::InternalFailure))?;
        let krbtgt = self.config.krbtgt;
        let tgt = self
            .custody
            .open_and_verify_tgt(
                &krbtgt,
                &ap_req,
                &raw_body,
                Some(TgsFastRequest {
                    ap_req_octets: &header.padata_value,
                    armored_req: &armored_req,
                }),
                now,
            )
            .map_err(tgt_refusal)?;
        scope.set_client(&tgt.crealm, &tgt.cname);
        // keyd returns the KrbFastReq of every armored context; without it
        // the context cannot be answered armored (fail closed, unarmored).
        let fast_req = tgt
            .fast_req
            .clone()
            .ok_or_else(|| internal(AuditReason::FastContextMissing))?;
        // From here on: the inner request, armored refusals (docs/48 §6.1).
        scope.armor_tgs(
            &fast_req.req_body,
            &self.local,
            &tgt.crealm,
            &tgt.cname,
            tgt.ctx_id,
        );
        let body = &fast_req.req_body;

        // 5. FastOptions (A-25; docs/48 §8).
        if has_critical_fast_option(fast_req.fast_options) {
            return Err(Refusal::new(
                KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS,
                AuditReason::UnknownCriticalFastOption,
            ));
        }

        // 6. The inner request: options and content (decision 9), the
        // requested server (decision 4; 5.4.1; docs/10 §5), starttime (3.3.3).
        if asks_unsupported_operation(body.kdc_options) {
            return Err(Refusal::new(
                KDC_ERR_BADOPTION,
                AuditReason::UnsupportedOption,
            ));
        }
        if has_unsupported_content(body) {
            return Err(Refusal::new(
                KDC_ERR_BADOPTION,
                AuditReason::UnsupportedContent,
            ));
        }
        if !same_realm(&body.realm, &realm) {
            return Err(Refusal::new(
                KDC_ERR_S_PRINCIPAL_UNKNOWN,
                AuditReason::CrossRealm,
            ));
        }
        let sname = body.sname.as_ref().ok_or(Refusal::new(
            KDC_ERR_S_PRINCIPAL_UNKNOWN,
            AuditReason::MissingName,
        ))?;
        match classify_server(sname, &realm) {
            ServerNameKind::Service => {}
            ServerNameKind::LocalTgs => {
                return Err(Refusal::new(KDC_ERR_POLICY, AuditReason::TgsForTgs))
            }
            // docs/53 §5.2 ("the TGS refuses the name (KDC_ERR_POLICY, as
            // R4)"): a ticket for the change-password service comes only
            // from an armored AS, with INITIAL (RFC 4120 2.1) — never from a
            // TGT, so a stolen TGT is never a password change. keyd's
            // `issue_tgs_rep` refuses that key set too (second layer).
            ServerNameKind::ChangePassword => {
                return Err(Refusal::new(
                    KDC_ERR_POLICY,
                    AuditReason::TgsForChangePassword,
                ))
            }
            ServerNameKind::ForeignTgs => {
                return Err(Refusal::new(
                    KDC_ERR_S_PRINCIPAL_UNKNOWN,
                    AuditReason::CrossRealm,
                ))
            }
        }
        check_starttime(body.from.as_ref(), now, skew).map_err(time_refusal)?;

        // 7. Re-evaluate the client now (D53; decision 8; 3.3.3.1).
        let client = match accounts.client(&tgt.crealm, &tgt.cname) {
            Err(error) => return Err(account_source_refusal(error)),
            Ok(None) => {
                return Err(Refusal::new(
                    KDC_ERR_CLIENT_REVOKED,
                    AuditReason::ClientRevoked,
                ))
            }
            Ok(Some(client)) => client,
        };
        if !client.state.usable_at(now) {
            return Err(Refusal::new(
                KDC_ERR_CLIENT_REVOKED,
                AuditReason::ClientRevoked,
            ));
        }
        if client.state.revokes(&tgt.authtime) {
            return Err(Refusal::new(KDC_ERR_TGT_REVOKED, AuditReason::TgtRevoked));
        }

        // 8. The service account (decisions 3, 8).
        let service = match accounts.service(&body.realm, sname) {
            Err(error) => return Err(account_source_refusal(error)),
            Ok(None) => {
                return Err(Refusal::new(
                    KDC_ERR_S_PRINCIPAL_UNKNOWN,
                    AuditReason::ServiceUnknown,
                ))
            }
            Ok(Some(service)) => service,
        };
        // A service ticket is sealed under the key set of its service's
        // purpose: Service, or AdminService for the admin service's name —
        // and only for that name (R2, docs/52 §5 item 3; keyd's binding
        // check refuses any other pairing too, A-19).
        if service.key.purpose != KeyPurpose::of_service_name(sname) {
            return Err(internal(AuditReason::AccountRecordInvalid));
        }
        if !service.state.usable_at(now) {
            return Err(Refusal::new(
                KDC_ERR_SERVICE_REVOKED,
                AuditReason::ServiceRevoked,
            ));
        }

        // 9. Session-key encryption type (3.1.3; decision 6).
        let acceptable = negotiate(&body.etype, &configured, &service.enctypes);
        let Some(&session_etype) = acceptable.first() else {
            return Err(Refusal::new(
                KDC_ERR_ETYPE_NOSUPP,
                AuditReason::NoCommonEncType,
            ));
        };

        // 10. The PDP (docs/30 §3.3; decision 7): armored — keyd verified
        // the implicit armor (docs/48 §4.2).
        let spn = service_spn(sname)
            .ok_or_else(|| Refusal::new(KDC_ERR_POLICY, AuditReason::AmbiguousServiceName))?;
        let age = u64::try_from(seconds(now) - seconds(&tgt.authtime)).unwrap_or(0);
        enforce(
            Question {
                action: Action::KdcTgs,
                client: &client,
                resource: Resource::Kerberos {
                    kind: KerbResKind::Service(Spn(spn)),
                },
                ticket_age: Duration::from_secs(age),
                src_net: peer.src_net,
                now,
                armored: true,
            },
            policy,
            &mut self.rate,
        )
        .map_err(|reason| Refusal::new(KDC_ERR_POLICY, reason))?;

        // 11. Flags and times (3.3.3; decisions 9, 10). The endtime is capped
        // by "(b) the endtime from the TGT, and (c) the starttime of the TGT
        // plus ... the maximum life for the local realm", and by both
        // accounts' expiry; renew-till by the TGT's renew-till.
        let requests = FlagRequests::of(body.kdc_options);
        let tgt_start = tgt.starttime.unwrap_or(tgt.authtime);
        let expiries = client
            .state
            .expires
            .iter()
            .chain(service.state.expires.iter())
            .map(seconds);
        let mut end_caps = vec![
            seconds(&tgt.endtime),
            seconds(&tgt_start) + i64::from(ticket_policy.max_lifetime_secs),
        ];
        end_caps.extend(expiries.clone());
        let mut renew_caps: Vec<i64> = tgt.renew_till.iter().map(seconds).collect();
        renew_caps.extend(expiries);
        let renewable_permitted = ticket_policy.allowed_flags.contains(TicketFlags::RENEWABLE)
            && tgt.flags.contains(TicketFlags::RENEWABLE)
            && tgt.renew_till.is_some();
        let planned = plan(
            now,
            &LifetimeRequest {
                from: body.from.as_ref(),
                till: &body.till,
                rtime: body.rtime.as_ref(),
                flags: requests,
            },
            &Limits {
                policy: ticket_policy,
                skew_secs: skew,
                end_caps,
                renew_caps,
                renewable_permitted,
            },
        )
        .map_err(time_refusal)?;
        let mut flags = delegation_flags(requests, ticket_policy.allowed_flags, Some(tgt.flags));
        if planned.renew_till.is_some() {
            flags.insert(TicketFlags::RENEWABLE);
        }

        // 12. keyd issues on the armored context (docs/10 §5, §5a; docs/48
        // §5.2). The service ticket starts now; sname and nonce are the inner
        // request's (keyd checks them against the inner body it kept).
        let session_enctype = self
            .custody
            .config()
            .enctypes
            .iter()
            .copied()
            .find(|e| e.number() == session_etype)
            .ok_or_else(|| internal(AuditReason::InternalFailure))?;
        let template = TgsTicketTemplate {
            sname: sname.clone(),
            starttime: Some(*now),
            endtime: planned.endtime,
            renew_till: planned.renew_till,
            flags,
            session_enctype,
            nonce: body.nonce,
        };
        let parts = self
            .custody
            .issue_tgs_rep(&service.key, &tgt.ctx_id, &template, now)
            .map_err(issue_refusal)?;

        // 13. The TGS-REP (5.4.2): PA-FX-FAST only (RFC 6113 5.4.3).
        let fast_rep = parts
            .fast_rep
            .ok_or_else(|| internal(AuditReason::InternalFailure))?;
        let fx_fast =
            fx_fast_reply(fast_rep).ok_or_else(|| internal(AuditReason::InternalFailure))?;
        TgsRep(KdcRep {
            padata: Some(vec![fx_fast]),
            crealm: tgt.crealm,
            cname: tgt.cname,
            ticket: parts.ticket,
            enc_part: parts.enc_part,
        })
        .encode()
        .map_err(|_| internal(AuditReason::InternalFailure))
    }
}
