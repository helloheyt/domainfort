//! The Authentication Service exchange: receipt of KRB_AS_REQ and generation
//! of KRB_AS_REP (phase 1: the AS issues TGTs, docs/30 §2).
//!
//! Steps, each refusing with the code named:
//! 1. KDC options asking for an unimplemented operation, or request content
//!    phase 1 cannot honour (addresses, additional tickets,
//!    enc-authorization-data) → KDC_ERR_BADOPTION (decision 9);
//! 2. cname absent → KDC_ERR_C_PRINCIPAL_UNKNOWN; sname absent →
//!    KDC_ERR_S_PRINCIPAL_UNKNOWN (5.4.1);
//! 3. another realm → KDC_ERR_C_PRINCIPAL_UNKNOWN (single realm, decision 4:
//!    such a client is not in this KDC's database, 3.1.3);
//! 4. sname: a TGS name of another realm → KDC_ERR_S_PRINCIPAL_UNKNOWN (no
//!    inter-realm key); any non-TGS service → KDC_ERR_POLICY (the phase-1 AS
//!    issues only TGTs, docs/30 §2);
//! 5. starttime beyond the skew → KDC_ERR_CANNOT_POSTDATE (3.1.3);
//! 6. the client account: source failure → KRB_ERR_GENERIC (fail closed,
//!    decision 3); unknown → KDC_ERR_C_PRINCIPAL_UNKNOWN (3.1.3; user
//!    enumeration is a documented residual, decision 5);
//! 7. disabled / locked / expired → KDC_ERR_CLIENT_REVOKED, checked BEFORE
//!    pre-authentication so that a locked or disabled account is never a
//!    password-guessing oracle and keyd is never asked for it;
//! 8. no acceptable AES enctype → KDC_ERR_ETYPE_NOSUPP (decision 6);
//! 9. pre-authentication is mandatory (docs/02 §3, docs/30 §2.1, decision 5):
//!    no PA-ENC-TIMESTAMP → KDC_ERR_PREAUTH_REQUIRED with METHOD-DATA
//!    (PA-ENC-TIMESTAMP, PA-ETYPE-INFO2 for the acceptable enctypes); more
//!    than one, an undecodable one, or one in a non-negotiated enctype →
//!    KDC_ERR_PREAUTH_FAILED; keyd `verify_preauth` refuses →
//!    KDC_ERR_PREAUTH_FAILED — also when keyd reports the timestamp, which
//!    decrypted, as out of skew (`AuthnError::Skew`, A-26): RFC 4120 names no
//!    distinct code for that (see [`preauth_refusal`]);
//! 10. the PDP (`KdcAs`) denies → KDC_ERR_POLICY (decision 7);
//! 11. times planned within policy (decision 10) → KDC_ERR_NEVER_VALID if too
//!     short;
//! 12. keyd `issue_as_rep` seals the TGT and the reply;
//! 13. the AS-REP: crealm / cname as requested (no canonicalisation), no
//!     padata (PA-ETYPE-INFO2 "MAY also be sent in an AS-REP"; the client
//!     already used the right key, so it is omitted — minimalism, docs/25 §5).
//!
//! Spec: RFC 4120 3.1.2, 3.1.3, 5.2.7.2-5.2.7.5, 5.4.1, 5.4.2, 7.3, 7.5.9;
//! docs/30 §2; docs/10 §4; main-session decisions 3-10.

use crate::accounts::AccountSource;
use crate::audit::{AuditReason, AuditSink};
use crate::custody::KeyCustody;
use crate::etype::negotiate;
use crate::gate::{enforce, PolicyInputs, Question, RateLimiter};
use crate::kdc::{internal, issue_refusal, local_tgs_name, time_refusal, Kdc, Refusal};
use crate::krb_error::preauth_required_e_data;
use crate::lifetime::{check_starttime, plan, LifetimeRequest, Limits};
use crate::names::{classify_server, same_realm, ServerNameKind};
use crate::options::{asks_unsupported_operation, delegation_flags, FlagRequests};
use crate::time::seconds;
use crate::transport::Peer;
use core::time::Duration;
use keyd::{AsTicketTemplate, AuthnError, KeyPurpose};
use krb_proto::constants::{
    KDC_ERR_BADOPTION, KDC_ERR_CLIENT_REVOKED, KDC_ERR_C_PRINCIPAL_UNKNOWN, KDC_ERR_ETYPE_NOSUPP,
    KDC_ERR_POLICY, KDC_ERR_PREAUTH_FAILED, KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_S_PRINCIPAL_UNKNOWN,
    PA_ENC_TIMESTAMP,
};
use krb_proto::{
    AsRep, EncryptedData, EtypeInfo2Entry, KdcRep, KdcReq, KdcReqBody, KerberosTime, TicketFlags,
};
use pdp::{Action, KerbResKind, Resource};

/// `true` if the request carries content phase 1 cannot honour: addresses
/// (keyd issues addressless tickets and refuses to drop a restriction,
/// docs/10 §5), additional tickets (only for ENC-TKT-IN-SKEY / S4U, refused),
/// or enc-authorization-data (TGS-only per 5.4.1, and keyd carries no
/// authorization data in phase 1). Empty SEQUENCE OF values count as absent
/// (5.1.3).
/// Spec: RFC 4120 5.1.3, 5.4.1, 3.3.3; docs/10 §5.
pub(crate) fn has_unsupported_content(body: &KdcReqBody) -> bool {
    body.addresses.as_ref().is_some_and(|a| !a.0.is_empty())
        || body
            .additional_tickets
            .as_ref()
            .is_some_and(|t| !t.is_empty())
        || body.enc_authorization_data.is_some()
}

/// keyd's `verify_preauth` refusals. Every one is KDC_ERR_PREAUTH_FAILED:
/// RFC 4120 3.1.3 — "if the pre-authentication check fails, an error message
/// with the code KDC_ERR_PREAUTH_FAILED is returned". 5.2.7.2 defines
/// PA-ENC-TIMESTAMP without naming any error code, and 3.1.5 (client clock
/// offset) concerns a successful AS-REP, so RFC 4120 prescribes no code for
/// an out-of-skew timestamp distinct from PREAUTH_FAILED (KRB_AP_ERR_SKEW is
/// prescribed only for the AP-REQ authenticator, 3.2.3). The skew class
/// (A-26) is kept apart in audit only (`PreauthSkew`). The KRB-ERROR's
/// stime is the KDC's `now` (5.9.1).
/// Spec: RFC 4120 3.1.3, 5.2.7.2, 3.1.5, 3.2.3; docs/questions/Q-071 (A-26).
fn preauth_refusal(error: AuthnError) -> Refusal {
    let reason = match error {
        AuthnError::Skew => AuditReason::PreauthSkew,
        _ => AuditReason::PreauthDenied,
    };
    Refusal::new(KDC_ERR_PREAUTH_FAILED, reason)
}

impl<K: KeyCustody, D: AccountSource, U: AuditSink, R: RateLimiter> Kdc<K, D, U, R> {
    /// Receipt of KRB_AS_REQ and generation of KRB_AS_REP (module docs).
    /// Spec: RFC 4120 3.1.2, 3.1.3; docs/30 §2.
    pub(crate) fn receive_as_req(
        &mut self,
        req: &KdcReq,
        peer: Peer,
        now: &KerberosTime,
        policy: &PolicyInputs<'_>,
    ) -> Result<Vec<u8>, Refusal> {
        let body = &req.req_body;
        let keyd_config = self.custody.config();
        let configured: Vec<i32> = keyd_config.enctypes.iter().map(|e| e.number()).collect();
        let skew = keyd_config.clock_skew_secs;
        let ticket_policy = keyd_config.ticket_policy;

        // 1. Options and content (decision 9).
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

        // 2-4. Names and realm (5.4.1; decision 4; docs/30 §2).
        let cname = body.cname.as_ref().ok_or(Refusal::new(
            KDC_ERR_C_PRINCIPAL_UNKNOWN,
            AuditReason::MissingName,
        ))?;
        let sname = body.sname.as_ref().ok_or(Refusal::new(
            KDC_ERR_S_PRINCIPAL_UNKNOWN,
            AuditReason::MissingName,
        ))?;
        if !same_realm(&body.realm, &self.config.realm) {
            return Err(Refusal::new(
                KDC_ERR_C_PRINCIPAL_UNKNOWN,
                AuditReason::CrossRealm,
            ));
        }
        match classify_server(sname, &self.config.realm) {
            ServerNameKind::LocalTgs => {}
            ServerNameKind::ForeignTgs => {
                return Err(Refusal::new(
                    KDC_ERR_S_PRINCIPAL_UNKNOWN,
                    AuditReason::CrossRealm,
                ))
            }
            ServerNameKind::Service => {
                return Err(Refusal::new(KDC_ERR_POLICY, AuditReason::AsServerNotTgs))
            }
        }

        // 5. Starttime (3.1.3).
        check_starttime(body.from.as_ref(), now, skew).map_err(time_refusal)?;

        // 6-7. The client account and its state (3.1.3; decisions 3, 5, 8).
        let account = match self.accounts.client(&body.realm, cname) {
            Err(_) => return Err(internal(AuditReason::AccountSourceFailure)),
            Ok(None) => {
                return Err(Refusal::new(
                    KDC_ERR_C_PRINCIPAL_UNKNOWN,
                    AuditReason::ClientUnknown,
                ))
            }
            Ok(Some(account)) => account,
        };
        if account.key.purpose != KeyPurpose::PrincipalLongterm {
            return Err(internal(AuditReason::AccountRecordInvalid));
        }
        if !account.state.usable_at(now) {
            return Err(Refusal::new(
                KDC_ERR_CLIENT_REVOKED,
                AuditReason::ClientRevoked,
            ));
        }

        // 8. Encryption types (3.1.3; decision 6).
        let account_etypes: Vec<i32> = account.etype_info.iter().map(|e| e.etype).collect();
        let acceptable = negotiate(&body.etype, &configured, &account_etypes);
        let Some(&session_etype) = acceptable.first() else {
            return Err(Refusal::new(
                KDC_ERR_ETYPE_NOSUPP,
                AuditReason::NoCommonEncType,
            ));
        };

        // 9. Pre-authentication (3.1.3, 5.2.7.2; decision 5).
        let padata = req.padata.as_deref().unwrap_or(&[]);
        let mut timestamps = padata.iter().filter(|p| p.padata_type == PA_ENC_TIMESTAMP);
        let timestamp = match (timestamps.next(), timestamps.next()) {
            (None, _) => {
                let hints: Vec<EtypeInfo2Entry> = acceptable
                    .iter()
                    .filter_map(|etype| account.etype_info.iter().find(|e| e.etype == *etype))
                    .cloned()
                    .collect();
                let e_data = preauth_required_e_data(hints)
                    .ok_or_else(|| internal(AuditReason::InternalFailure))?;
                return Err(Refusal {
                    code: KDC_ERR_PREAUTH_REQUIRED,
                    reason: AuditReason::PreauthRequired,
                    e_data: Some(e_data),
                });
            }
            (Some(_), Some(_)) => {
                return Err(Refusal::new(
                    KDC_ERR_PREAUTH_FAILED,
                    AuditReason::PreauthAmbiguous,
                ))
            }
            (Some(timestamp), None) => timestamp,
        };
        let offered = EncryptedData::decode(&timestamp.padata_value)
            .map_err(|_| Refusal::new(KDC_ERR_PREAUTH_FAILED, AuditReason::PreauthUnacceptable))?;
        if !acceptable.contains(&offered.etype) {
            return Err(Refusal::new(
                KDC_ERR_PREAUTH_FAILED,
                AuditReason::PreauthUnacceptable,
            ));
        }
        let proof = self
            .custody
            .verify_preauth(&account.key, timestamp, now)
            .map_err(preauth_refusal)?;

        // 10. The PDP (docs/30 §2.4; decision 7).
        enforce(
            Question {
                action: Action::KdcAs,
                client: &account,
                resource: Resource::Kerberos {
                    kind: KerbResKind::Tgt,
                },
                ticket_age: Duration::ZERO,
                src_net: peer.src_net,
                now,
            },
            policy,
            &mut self.rate,
        )
        .map_err(|reason| Refusal::new(KDC_ERR_POLICY, reason))?;

        // 11. Flags and times (decisions 9, 10).
        let requests = FlagRequests::of(body.kdc_options);
        let caps: Vec<i64> = account.state.expires.iter().map(seconds).collect();
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
                end_caps: caps.clone(),
                renew_caps: caps,
                renewable_permitted: ticket_policy.allowed_flags.contains(TicketFlags::RENEWABLE),
            },
        )
        .map_err(time_refusal)?;
        let mut flags = delegation_flags(requests, ticket_policy.allowed_flags, None);
        if planned.renew_till.is_some() {
            flags.insert(TicketFlags::RENEWABLE);
        }

        // 12. keyd issues (docs/10 §4). The session-key type is the first
        // acceptable one (3.1.3); the reply is sealed under the key that
        // pre-authenticated. The TGS is named in its RFC 4120 7.3 form
        // (NT-SRV-INST); the name-type is not significant (6.2).
        let session_enctype = self
            .custody
            .config()
            .enctypes
            .iter()
            .copied()
            .find(|e| e.number() == session_etype)
            .ok_or_else(|| internal(AuditReason::InternalFailure))?;
        let template = AsTicketTemplate {
            client: account.key.principal,
            crealm: body.realm.clone(),
            cname: cname.clone(),
            sname: local_tgs_name(&self.config.realm)?,
            starttime: None,
            endtime: planned.endtime,
            renew_till: planned.renew_till,
            flags,
            session_enctype,
            nonce: body.nonce,
        };
        let krbtgt = self.config.krbtgt;
        let parts = self
            .custody
            .issue_as_rep(&account.key, &krbtgt, &proof, &template, now)
            .map_err(issue_refusal)?;

        // 13. The AS-REP (5.4.2).
        AsRep(KdcRep {
            padata: None,
            crealm: body.realm.clone(),
            cname: cname.clone(),
            ticket: parts.ticket,
            enc_part: parts.enc_part,
        })
        .encode()
        .map_err(|_| internal(AuditReason::InternalFailure))
    }
}
