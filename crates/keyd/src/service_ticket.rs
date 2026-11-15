//! Service-ticket verification inside keyd: `open_and_verify_service_ticket`
//! (task L6a — unbound, keeps a service context) and
//! `verify_operation_ticket` (dird's admin channel — bound to one operation,
//! keeps none; docs/questions/Q-523). Role `Ldap` only.
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
//! The caller names the service key set by its principal; each binding has
//! its own operation ([`AppBinding::operation`]), and the key set's purpose
//! is the binding's ([`AppBinding::key_purpose`]), never the caller's
//! choice:
//!
//! | binding | operation | key set | the Authenticator's `cksum` | answer / kept |
//! |---|---|---|---|---|
//! | `Unbound` (the LDAP front, L6a) | `open_and_verify_service_ticket` | `(principal, Service)` | must be absent (`ApChecksumUnsupported`) | [`ServiceContext`] / a service context |
//! | `OperationDigest(d)` (dird's admin channel) | `verify_operation_ticket` | `(principal, AdminService)` | must be present (`OperationDigestMissing`), of the session key's required checksum type, and verify as `get_mic(session key, usage 10, d)` (`OperationDigestMismatch`) | [`OperationTicket`] / nothing |
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
//! it ever leaving keyd; in L6a nothing consumes it and it expires. An
//! operation-bound verification keeps no context at all: dird never uses
//! one (no KRB_AP_REP, no KRB_SAFE / KRB_PRIV on the admin channel), so
//! keeping its session key would be a capability without a consumer
//! (docs/52 §3.4, C4) and a table that fills faster (docs/questions/Q-387
//! item 4, Q-493 item 3, Q-523). Its answer type has no field for a
//! context id, and the one function that creates a context
//! (`keep_service_context`) is reached only from the unbound operation.
//!
//! The split into two operations (Q-523) was written only from RFC 4120 (the
//! pinned copy) §3.2.3, §3.2.4, §5.5.1, §7.5.1, docs/10 §5ב / §8, docs/52 §3.4
//! / §5, docs/questions/Q-387, Q-493, Q-523 and this crate's own code; no other
//! implementation was consulted or recalled (AGENTS.md §1-3).
//!
//! # The third profile: a change-password request (task K3)
//!
//! `open_change_password_request` (crate::change_password) runs **this**
//! core — not a second implementation of RFC 4120 3.2.3 (docs/53 §5.3; class
//! "one security rule implemented twice", docs/52 C14 / C5) — with
//! [`Accompanying::KrbPriv`]: the binding `AppBinding::ChangePassword`, the
//! ChangePasswordService key set, no `cksum` (step 9), and, after the subkey
//! step, step 10a: the subkey and the Authenticator's sequence number are
//! required (RFC 3244 §2) and the accompanying KRB-PRIV is decrypted under
//! the subkey, key usage 13 — part of the cryptographic chain, before the
//! replay cache, so a KRB-PRIV of another request leaves no replay entry.
//! Written from RFC 3244 §2, RFC 4120 §3.5.2, §5.5.1, §5.7.1, §7.5.1 (pinned,
//! SHA-256 verified) and docs/53 §5.3-§5.4.
//!
//! Spec: RFC 4120 §4, 2.2, 3.2.3, 3.3.3, 3.3.3.2, 5.3, 5.5.1, 6.2, 7.5.1;
//! RFC 3961 §3, §4; RFC 3962 §7; RFC 8009 §6; [MS-KILE] 3.4.5 (retry with
//! the previous server key); docs/10 §5ב, §8, §9, §12; docs/49 §3.3, §12;
//! docs/52 §3.2, §3.4, §5; docs/questions/Q-165 (A-46), Q-180, Q-463
//! (A-102), Q-523; A-19 (docs/questions/Q-040); A-26 (docs/questions/Q-071).

use crate::audit::{AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot};
use crate::chain::{self, BindingEvidence, ChainVerified};
use crate::entropy::EntropySource;
use crate::error::{AuthnError, Deny, Internal};
use crate::keyd::{draw, AuditFields, Keyd};
use crate::model::{KeyHandle, PrincipalId};
use crate::store::{BoundKeys, KeyStore, KeyVersion};
use crate::tgs_exchange::{check_ap_options, replay_key_for, subkey_protocol_key, OpenedApReq};
use crate::time::kerberos_time_seconds;
use crate::tokens::{ServiceCtxId, TOKEN_ID_LENGTH};
use crate::usage::{AP_REQ_AUTHENTICATOR, AP_REQ_AUTHENTICATOR_CKSUM, KRB_PRIV_ENC_PART};
use keyd_types::{AppBinding, OperationDigest, OperationTicket, ServiceContext};
use krb_crypto::{ChecksumType, ProtocolKey};
use krb_proto::constants::DOMAIN_X500_COMPRESS;
use krb_proto::{
    ApReq, Checksum, EncKrbPrivPart, KerberosTime, KrbPriv, Microseconds, TransitedEncoding,
};

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
fn random_versions(bound: BoundKeys<'_>) -> Internal<[Option<KeyVersion<'_>>; 2]> {
    let versions = bound
        .versions()
        .map(|version| version.filter(|v| !v.is_password_derived()));
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
/// the evidence: the operation digest the `cksum` was verified over, with the
/// MIC's evidence (crate::chain), or `Unbound`. Every failure is the uniform
/// `Denied` with its own audit reason.
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
) -> Internal<BindingEvidence> {
    match (binding, cksum) {
        // A change-password request carries no `cksum` either: its operation
        // binding is the KRB-PRIV under the subkey (step 10a,
        // [`open_krb_priv`], which replaces this evidence) — task K3, Q-603
        // item 4.
        (AppBinding::Unbound, None) | (AppBinding::ChangePassword, None) => {
            Ok(BindingEvidence::Unbound)
        }
        // L6a has no application data to verify a checksum over; ignoring it
        // would waive a binding the client asked for (Q-180 item 3). Nor does
        // RFC 3244 define any for a change-password request (docs/53 §5.3).
        (AppBinding::Unbound, Some(_)) | (AppBinding::ChangePassword, Some(_)) => {
            Err(Deny::denied(AuditReason::ApChecksumUnsupported))
        }
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
            let verified = chain::verify_mic(
                session,
                cksumtype,
                AP_REQ_AUTHENTICATOR_CKSUM,
                digest.as_bytes(),
                &cksum.checksum,
                AuditReason::OperationDigestMismatch,
            )?;
            Ok(BindingEvidence::OperationDigest(*digest, verified))
        }
    }
}

/// Step 10a of a change-password request (task K3): the subkey and the
/// Authenticator's sequence number are required (RFC 3244 §2: "The
/// authenticator in the AP-REQ must include a subsession key"; "the
/// seq-number in the authenticator will be present"), and the accompanying
/// KRB-PRIV — decoded strictly by keyd — is decrypted under that subkey with
/// key usage 13 and its EncKrbPrivPart decoded. Takes the step-9 evidence
/// (no `cksum`) by value and returns the binding evidence that replaces it.
/// Every failure is the uniform `Denied` (a decryption failure is part of the
/// chain, A-26).
/// Spec: RFC 3244 §2 ("This user-data field in the KRB-PRIV message is
/// encrypted using the subkey from the authenticator in the AP-REQ data");
/// RFC 4120 3.5.2 (version / type, then decryption — KRB_AP_ERR_BAD_INTEGRITY),
/// 5.5.1, 5.7.1, 7.5.1 item 13; docs/53 §5.3, §5.4 item 1; Q-603 item 3.
fn open_krb_priv(
    no_checksum: BindingEvidence,
    subkey: Option<&ProtocolKey>,
    seq_number: Option<u32>,
    krb_priv_octets: &[u8],
) -> Internal<(BindingEvidence, EncKrbPrivPart)> {
    if !matches!(no_checksum, BindingEvidence::Unbound) {
        return Err(Deny::unavailable(AuditReason::InternalFailure));
    }
    let subkey = subkey.ok_or(Deny::denied(AuditReason::SubkeyMissing))?;
    if seq_number.is_none() {
        return Err(Deny::denied(AuditReason::SequenceNumberMissing));
    }
    let krb_priv =
        KrbPriv::decode(krb_priv_octets).map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
    if krb_priv.enc_part.etype != subkey.enc_type().number() {
        return Err(Deny::denied(AuditReason::UnsupportedEncType));
    }
    let (plain, decrypted) = chain::open(subkey, KRB_PRIV_ENC_PART, &krb_priv.enc_part.cipher)?;
    let part =
        EncKrbPrivPart::decode(&plain).map_err(|_| Deny::denied(AuditReason::MalformedInput))?;
    drop(plain);
    Ok((BindingEvidence::KrbPriv(decrypted), part))
}

/// The application data that accompanies an AP-REQ, as each verification
/// receives it — which also fixes the binding ([`Accompanying::binding`]),
/// hence the key set's purpose and the operation (R2).
/// Spec: RFC 4120 5.5.1 ("the application data that accompanies the
/// KRB_AP_REQ"); docs/52 §5 item 3; docs/53 §5.3.
pub(crate) enum Accompanying<'a> {
    /// None (`open_and_verify_service_ticket`).
    Nothing,
    /// The admin channel's operation digest (`verify_operation_ticket`).
    OperationDigest(OperationDigest),
    /// The KRB-PRIV octets of an RFC 3244 request
    /// (`open_change_password_request`, task K3).
    KrbPriv(&'a [u8]),
}

impl Accompanying<'_> {
    /// The binding this application data requires.
    /// Spec: docs/52 §5 item 3; docs/53 §5.3.
    pub(crate) fn binding(&self) -> AppBinding {
        match self {
            Accompanying::Nothing => AppBinding::Unbound,
            Accompanying::OperationDigest(digest) => AppBinding::OperationDigest(*digest),
            Accompanying::KrbPriv(_) => AppBinding::ChangePassword,
        }
    }
}

/// What the shared verification steps 1-11 established about one AP-REQ:
/// the ticket's non-secret facts, the keys a context could keep, and the
/// digest the `cksum` MIC verified over (`None`: unbound). Never leaves
/// keyd; each public operation turns it into its own answer — the unbound
/// one keeps the keys under a context id, the operation-bound one drops them
/// (Q-523), the change-password one keeps them in its request context
/// (task K3).
/// Spec: RFC 4120 3.2.3, 5.3, 5.5.1; docs/10 §5ב; docs/questions/Q-523.
pub(crate) struct VerifiedApReq {
    /// Client realm from the ticket. Spec: RFC 4120 5.3.
    pub(crate) crealm: krb_proto::Realm,
    /// Client name from the ticket. Spec: RFC 4120 5.3.
    pub(crate) cname: krb_proto::PrincipalName,
    /// Spec: RFC 4120 5.3 (authtime).
    pub(crate) authtime: KerberosTime,
    /// Spec: RFC 4120 5.3 (endtime).
    pub(crate) endtime: KerberosTime,
    /// Spec: RFC 4120 5.3 (flags).
    pub(crate) flags: krb_proto::TicketFlags,
    /// The ticket session key. Spec: RFC 4120 5.3 (key).
    pub(crate) session: ProtocolKey,
    /// The authenticator subkey, when offered. Spec: RFC 4120 5.5.1.
    pub(crate) subkey: Option<ProtocolKey>,
    /// The digest the `cksum` MIC verified over (`None`: unbound).
    /// Spec: RFC 4120 5.5.1; docs/52 §5 item 3.
    bound_operation: Option<OperationDigest>,
    /// The Authenticator's ctime and cusec — what a KRB_AP_REP must carry
    /// (RFC 4120 3.2.4: "MUST be the client's timestamp and microsecond
    /// field"). Spec: RFC 4120 5.5.1, 5.5.2.
    pub(crate) ctime: KerberosTime,
    pub(crate) cusec: Microseconds,
    /// The Authenticator's sequence number (RFC 4120 5.5.1: "the initial
    /// sequence number for messages from the client to the server").
    pub(crate) seq_number: Option<u32>,
    /// The decrypted EncKrbPrivPart of a change-password request (task K3);
    /// `None` for the other bindings. Spec: RFC 4120 5.7.1; RFC 3244 §2.
    pub(crate) krb_priv: Option<EncKrbPrivPart>,
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// `open_and_verify_service_ticket`: verify an **unbound** service
    /// AP-REQ (the LDAP front, task L6a) inside keyd under the service key
    /// (RFC 4120 3.2.3) and return a one-time [`ServiceContext`] —
    /// non-secret facts only, and the id of the session key keyd keeps for
    /// the later GSS steps.
    ///
    /// `ap_req_octets` is the DER of the KRB_AP_REQ as received: keyd
    /// decodes it itself, so the message keyd checks and the message keyd
    /// opens are the same octets (docs/49 §3.3 "like A-43").
    ///
    /// The service key set is `(service, Service)`: the binding is
    /// `AppBinding::Unbound` and its purpose is the binding's (R2). An admin
    /// service ticket is verified only by [`Keyd::verify_operation_ticket`]
    /// (Q-523), never here.
    ///
    /// Checks failing as the uniform `AuthnError::Denied` (reason to audit
    /// only):
    /// 1. authorize and admit (Ldap; the derived handle Service — I2, I3);
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
    /// 9. the authenticator carries no checksum ([`verify_app_binding`],
    ///    `Unbound`: task L6a has no application data to verify one over;
    ///    the RFC 4121 checksum is task L6b — docs/questions/Q-180 item 3);
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
    /// 3.4.5; docs/10 §5ב, §9 (A-26); docs/49 §3.3; docs/52 §5;
    /// docs/questions/Q-165 (A-46), Q-180, Q-463 (A-102), Q-523; A-19
    /// (docs/questions/Q-040).
    pub fn open_and_verify_service_ticket(
        &mut self,
        caller: &CallerId,
        service: &PrincipalId,
        ap_req_octets: &[u8],
        now: &KerberosTime,
    ) -> Result<ServiceContext, AuthnError> {
        let accompanying = Accompanying::Nothing;
        let binding = accompanying.binding();
        // The key set is named by the binding's purpose (R2).
        let handle = KeyHandle::new(*service, binding.key_purpose());
        let mut fields = AuditFields::for_handle(&handle);
        let result = self
            .verify_service_ap_req(
                caller,
                &handle,
                &accompanying,
                ap_req_octets,
                now,
                &mut fields,
            )
            .and_then(|verified| self.keep_service_context(caller, &handle, verified, now));
        self.emit(caller, binding.operation(), now, &fields, &result);
        result.map_err(AuthnError::from)
    }

    /// `verify_operation_ticket`: verify a service AP-REQ **bound to one
    /// operation** (dird's admin channel) inside keyd under the admin
    /// service key, and return its non-secret facts as an
    /// [`OperationTicket`] — which has no context id: keyd keeps **no**
    /// session key, subkey or token for it (Q-523; docs/52 §3.4, C4). The
    /// only state it leaves is its replay-cache entry (RFC 4120 3.2.3).
    ///
    /// The service key set is `(service, AdminService)` — the purpose of
    /// `AppBinding::OperationDigest` (R2). The checks are steps 1-11 of
    /// [`Keyd::open_and_verify_service_ticket`], in the same order, except
    /// step 9: the Authenticator's `cksum` must be present
    /// (`OperationDigestMissing`), of the session key's required checksum
    /// type, and the session key's MIC over the 32 octets of `operation`
    /// with key usage 10 (`OperationDigestMismatch`) — RFC 4120 5.5.1,
    /// 7.5.1 item 10; RFC 3961 §3, §4. A failure there is part of the
    /// cryptographic chain: the uniform `Denied` (A-26), before the replay
    /// cache, so an AP-REQ attached to another operation leaves no replay
    /// entry (R2, R7's `ChainVerified` order). Step 12 does not exist: the
    /// keys are dropped (zeroized) when the answer is built. RFC 4120 3.2.3
    /// keeps a subkey "for later use" or for the KRB_AP_REP; the admin
    /// channel has neither (RFC 4120 3.2.4: "the server need not explicitly
    /// reply to the KRB_AP_REQ").
    ///
    /// Spec: RFC 4120 2.2, 3.2.3, 3.2.4, 3.3.3.2, 5.3, 5.5.1, 6.2, 7.5.1;
    /// RFC 3961 §3, §4; RFC 3962 §7; RFC 8009 §6; [MS-KILE] 3.4.5; docs/10
    /// §5ב, §9 (A-26); docs/52 §3.4, §5; docs/questions/Q-387 item 4, Q-463
    /// (A-102), Q-493 item 3, Q-523.
    pub fn verify_operation_ticket(
        &mut self,
        caller: &CallerId,
        service: &PrincipalId,
        operation: &OperationDigest,
        ap_req_octets: &[u8],
        now: &KerberosTime,
    ) -> Result<OperationTicket, AuthnError> {
        let accompanying = Accompanying::OperationDigest(*operation);
        let binding = accompanying.binding();
        // The key set is named by the binding's purpose (R2).
        let handle = KeyHandle::new(*service, binding.key_purpose());
        let mut fields = AuditFields::for_handle(&handle);
        let result = self
            .verify_service_ap_req(
                caller,
                &handle,
                &accompanying,
                ap_req_octets,
                now,
                &mut fields,
            )
            .and_then(|verified| operation_ticket(verified, operation));
        self.emit(caller, binding.operation(), now, &fields, &result);
        result.map_err(AuthnError::from)
    }

    /// Steps 1-11 of every service-ticket verification (see
    /// [`Keyd::open_and_verify_service_ticket`]) — the unbound one, the
    /// operation-bound one and the change-password request (task K3) — under
    /// `service`, the handle of the binding's purpose, with step 9 (and, for
    /// a change-password request, step 10a: [`open_krb_priv`]) as the
    /// accompanying application data requires. The one implementation of
    /// RFC 4120 3.2.3 for a service AP-REQ in keyd (docs/53 §5.3).
    pub(crate) fn verify_service_ap_req(
        &mut self,
        caller: &CallerId,
        service: &KeyHandle,
        accompanying: &Accompanying<'_>,
        ap_req_octets: &[u8],
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<VerifiedApReq> {
        let binding = &accompanying.binding();
        // 1. Role Ldap, purpose the binding's: Service for the unbound
        // operation, AdminService for the operation-bound one (I2, I3).
        self.admit(
            caller,
            binding.operation(),
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
        // The key set is used only through the proof that it is bound to
        // the ticket's (srealm, sname) (A-19; crate::store, R7).
        let bound = self
            .store
            .get(service)
            .ok_or(Deny::denied(AuditReason::KeyNotFound))?
            .bound_to(&ap_req.ticket.realm, &ap_req.ticket.sname)?;

        // 5-7. Only keyd-drawn versions (A-46); the ticket under usage 2,
        // the authenticator under usage 11 (shared steps).
        let versions = random_versions(bound)?;
        let OpenedApReq {
            ticket_part,
            session,
            authenticator,
            ctime,
            findings,
            evidence,
        } = self.open_ap_req(versions, &ap_req, AP_REQ_AUTHENTICATOR, now_s, fields)?;

        // 8. Transited: local authentication only. Spec: RFC 4120 3.3.3.2,
        // 5.3.
        check_transited(&ticket_part.transited)?;

        // 9. The application-data checksum, as the binding requires (R2).
        // Spec: RFC 4120 5.5.1 (cksum), 7.5.1 item 10; RFC 3961 §3, §4.
        let binding_evidence = verify_app_binding(&session, authenticator.cksum.as_ref(), binding)?;
        let bound_operation = binding_evidence.digest();

        // 10. The subkey: a configured enctype and a valid key (I5).
        // Spec: RFC 4120 5.5.1; docs/10 §12 I5.
        let subkey = authenticator
            .subkey
            .as_ref()
            .map(|subkey| subkey_protocol_key(subkey, &self.enctypes))
            .transpose()?;

        // 10a. A change-password request: the subkey and the sequence number
        // required, the KRB-PRIV opened under the subkey (task K3). Spec: RFC
        // 3244 §2; RFC 4120 5.7.1, 7.5.1 item 13; docs/53 §5.3, §5.4 item 1.
        let (binding_evidence, krb_priv) = match accompanying {
            Accompanying::KrbPriv(octets) => {
                let (evidence, part) = open_krb_priv(
                    binding_evidence,
                    subkey.as_ref(),
                    authenticator.seq_number,
                    octets,
                )?;
                (evidence, Some(part))
            }
            Accompanying::Nothing | Accompanying::OperationDigest(_) => (binding_evidence, None),
        };

        // The cryptographic chain is complete: the ticket decrypted under the
        // service key, the authenticator under the session key and — bound —
        // the operation digest's MIC verified. Its proof is made from that
        // evidence; only now are the recorded findings reported, then the
        // replay cache (step 11) consulted (A-26; crate::chain). Spec: RFC
        // 4120 3.2.3.
        let verified = ChainVerified::service_ticket(evidence, binding_evidence);
        self.complete_chain(
            verified,
            findings,
            replay_key_for(&ap_req.ticket, &authenticator, ctime),
            now_s,
        )?;

        Ok(VerifiedApReq {
            crealm: ticket_part.crealm.clone(),
            cname: ticket_part.cname.clone(),
            authtime: ticket_part.authtime,
            endtime: ticket_part.endtime,
            flags: ticket_part.flags,
            session,
            subkey,
            bound_operation,
            ctime: authenticator.ctime,
            cusec: authenticator.cusec,
            seq_number: authenticator.seq_number,
            krb_priv,
        })
    }

    /// Step 12 of the unbound verification — the only place a service
    /// context is created: the session key and the subkey under a fresh
    /// [`ServiceCtxId`] bound to `caller`, for the token lifetime (table
    /// full: `Denied`). The context id exists only in the answer this
    /// returns (Q-523: the operation-bound answer has no field for one).
    /// Spec: docs/10 §8, D36; docs/49 §3.3; RFC 4120 3.2.3 ("If a subkey is
    /// present, the server either saves it for later use ...").
    fn keep_service_context(
        &mut self,
        caller: &CallerId,
        service: &KeyHandle,
        verified: VerifiedApReq,
        now: &KerberosTime,
    ) -> Internal<ServiceContext> {
        let now_s = kerberos_time_seconds(now);
        let mut id = [0u8; TOKEN_ID_LENGTH];
        draw(&mut self.entropy, &mut id)?;
        let VerifiedApReq {
            crealm,
            cname,
            authtime,
            endtime,
            flags,
            session,
            subkey,
            ..
        } = verified;
        let context = ServiceContext {
            ctx_id: ServiceCtxId::from_bytes(id),
            crealm,
            cname,
            authtime,
            endtime,
            flags,
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

/// The answer of an operation-bound verification: the ticket's facts and
/// the digest keyd verified the `cksum` MIC over — the session key and the
/// subkey are dropped here (zeroized: krb-crypto `ProtocolKey` wipes on
/// drop) and no context is created (Q-523). The verified digest must be the
/// one asked for; anything else is refused (fail closed — not reachable,
/// since step 9 verified exactly `operation`).
/// Spec: RFC 4120 3.2.3, 5.5.1; docs/52 §5 items 3-4; docs/questions/Q-523.
fn operation_ticket(
    verified: VerifiedApReq,
    operation: &OperationDigest,
) -> Internal<OperationTicket> {
    let VerifiedApReq {
        crealm,
        cname,
        authtime,
        endtime,
        flags,
        session,
        subkey,
        bound_operation,
        ..
    } = verified;
    // Nothing of the session is kept: no consumer exists for it.
    drop((session, subkey));
    match bound_operation {
        Some(digest) if digest == *operation => Ok(OperationTicket {
            crealm,
            cname,
            authtime,
            endtime,
            flags,
            operation: digest,
        }),
        _ => Err(Deny::denied(AuditReason::OperationDigestMismatch)),
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

    fn reason(result: Internal<BindingEvidence>) -> Option<AuditReason> {
        result.err().map(|deny| deny.reason)
    }

    /// The digest an accepted binding names (`None`: unbound).
    fn accepted(result: Internal<BindingEvidence>) -> Result<Option<OperationDigest>, AuditReason> {
        result.map(|e| e.digest()).map_err(|deny| deny.reason)
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
                accepted(verify_app_binding(key, Some(&good), &bound)),
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
                accepted(verify_app_binding(key, None, &AppBinding::Unbound)),
                Ok(None)
            );
            assert_eq!(
                reason(verify_app_binding(key, Some(&good), &AppBinding::Unbound)),
                Some(AuditReason::ApChecksumUnsupported)
            );
        }
    }
}
