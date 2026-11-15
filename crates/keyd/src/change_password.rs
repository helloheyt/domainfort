//! The RFC 3244 change-password operations inside keyd (task K3; docs/53
//! §5.3-§5.5): `open_change_password_request`, `complete_change_password`,
//! `seal_change_password_error`. Role `Ldap` only (dird).
//!
//! "Compute, don't give" for kpasswd (docs/53 R53-4, D29 strict): keyd
//! verifies the AP-REQ for `kadmin/changepw`, decrypts the KRB-PRIV under the
//! Authenticator's subkey and is the **only** process that ever sees the new
//! password; dird receives a one-time request context id, the ticket's
//! non-secret facts and keyd's verdict.
//!
//! # The state machine (docs/53 §5.5)
//!
//! ```text
//! open_change_password_request ──(ctx)──► complete_change_password(ctx, target)  [consumes; only on a ChangePassword decision]
//!                    │                         └ refused (no decision / another client / install refused): the ctx stays for the error
//!                    └────────────────────────► seal_change_password_error(ctx, code ≠ 0)  [consumes]
//! ```
//!
//! Every context is consumed exactly once — by the completion (after the
//! password is installed) or by the error seal — or expires (its session
//! key, subkey and password zeroized). So an authenticated reply (a KRB-PRIV
//! under the client's subkey) always states what keyd did: class "a reply
//! that claims an outcome other than what was done" (docs/53 §5.5, C3/C10),
//! closed by construction:
//!
//! * only `complete_change_password` makes a success reply, and it releases
//!   it only after the install: the reply is sealed **before** the install
//!   (so nothing can fail once the key state changed — the outcome record is
//!   always true) and dropped unless the install succeeded;
//! * the completion consumes the context after the install, so no error
//!   reply can follow a success; the error seal consumes it, so no
//!   completion can follow an error;
//! * the error seal accepts only a code the context's verdict permits
//!   (`ChangePasswordVerdict::permits_error`).
//!
//! # The completion's target is bound by keyd (docs/53 R53-8)
//!
//! `complete_change_password` redeems a `DecidedOperation::ChangePassword`
//! decision for the target handle whose binding identifies **the request
//! ticket's client** — keyd compares it with the client keyd itself
//! verified; the caller names only the handle. The password comes from the
//! context, never from the caller (no password parameter exists). The
//! install is the one install path of `set_secret`
//! (`Keyd::install_password`), with the decision's binding and salt and the
//! password policy.
//!
//! Written only from RFC 3244 §2 (pinned, SHA-256 `45b9130f…dec378`, read in
//! full), RFC 4120 §2.1, §3.2.3, §3.2.4, §3.2.5, §3.5.1, §3.5.2, §5.5.1,
//! §5.5.2, §5.7.1, §7.1, §7.5.1, §7.5.3 (pinned, `368d3cd1…`), RFC 3961 §3,
//! docs/53 §4-§9, docs/10 §5ב, §6א, §8 and docs/questions/Q-601, Q-603,
//! Q-604, Q-605, Q-620 (A-117, A-121), opened in this session, and this
//! crate's own code. No other implementation was consulted or recalled
//! (AGENTS.md §1-3).
//!
//! Spec: RFC 3244 §2; RFC 4120 2.1, 3.2.3, 3.2.4, 3.5.1, 3.5.2, 5.5.2, 5.7.1,
//! 7.1, 7.5.1; docs/53 R53-5, R53-7, R53-8, R53-9, §5.3-§5.8; docs/10 §8.

use crate::as_exchange::token_deny;
use crate::audit::{AuditReason, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::config::KeydConfig;
use crate::directory::{password_policy, Existence};
use crate::entropy::EntropySource;
use crate::error::{AuthnError, Deny, Error, Internal};
use crate::keyd::{draw, seal, AuditFields, Keyd};
use crate::model::{KeyHandle, PrincipalId};
use crate::service_ticket::{Accompanying, VerifiedApReq};
use crate::store::KeyStore;
use crate::time::{kerberos_time_seconds, within_skew};
use crate::tokens::TOKEN_ID_LENGTH;
use crate::usage::{AP_REP_ENC_PART, KRB_PRIV_ENC_PART};
use keyd_types::{
    ChangePasswordContext, ChangePasswordCtxId, ChangePasswordVerdict, HostAddr, SealedReply,
    ADDRESS_TYPE_DIRECTIONAL, DIRECTIONAL_AP_REQ_RECIPIENT, DIRECTIONAL_AP_REQ_SENDER,
};
use krb_crypto::ProtocolKey;
use krb_proto::{
    ApRep, ChangePasswdData, EncApRepPart, EncKrbPrivPart, EncryptedData, HostAddress,
    KerberosTime, KrbPriv, Microseconds, NonZeroResultCode, PasswordRequest, PrincipalName, Realm,
    ResultCode, TicketFlags, UserData,
};
use zeroize::Zeroizing;

/// How many draws of a reply sequence number keyd makes before it gives up
/// on a non-zero one (fail closed, `Unavailable`). A zero is redrawn: RFC
/// 4120 5.5.1 — implementations "SHOULD NOT transmit an Authenticator with a
/// initial sequence number of zero", and 3.2.4 asks the AP-REP's number to
/// be chosen "as described above for the authenticator". Project choice.
const SEQUENCE_NUMBER_DRAWS: usize = 4;

/// What keyd keeps about an opened change-password request (never leaves
/// keyd). The session key, the subkey and the password are zeroized when
/// the entry is removed — consumed or expired (krb-crypto `ProtocolKey` and
/// `Zeroizing` wipe on drop).
/// Spec: docs/53 §5.4 item 5 (the password "only in `Zeroizing` inside the
/// context"), §5.5; docs/10 §8, I7.
pub(crate) struct ChangePasswordEntry {
    /// The ChangePasswordService key set the request was opened under (for
    /// the error seal's record).
    service: KeyHandle,
    /// The ticket's client — the only principal a completion may install
    /// for (docs/53 R53-8).
    crealm: Realm,
    cname: PrincipalName,
    /// The ticket session key: the AP-REP's key (usage 12, RFC 4120 3.2.5:
    /// "the sub-session key is not used, even if it is present").
    session: ProtocolKey,
    /// The Authenticator's subkey: the reply KRB-PRIV's key (usage 13, RFC
    /// 3244 §2).
    subkey: ProtocolKey,
    /// The Authenticator's ctime / cusec, echoed in the AP-REP (RFC 4120
    /// 3.2.4: MUST).
    ctime: KerberosTime,
    cusec: Microseconds,
    /// The reply KRB-PRIV's `s-address` (docs/53 §5.7; Q-604 item 2).
    reply_s_address: HostAddress,
    /// The verdict, with the new password only when acceptable.
    pending: Pending,
}

/// A request's verdict; only an acceptable one holds the password, so a
/// refused request keeps nothing it cannot use (docs/25 §5 minimalism).
/// Spec: docs/53 §5.4, §5.5.
enum Pending {
    Acceptable(Zeroizing<String>),
    Refused(ChangePasswordVerdict),
}

impl Pending {
    fn verdict(&self) -> ChangePasswordVerdict {
        match self {
            Pending::Acceptable(_) => ChangePasswordVerdict::Acceptable,
            Pending::Refused(verdict) => *verdict,
        }
    }
}

/// The audit reason that names a result code (outcome `Success`: the
/// verdict of an opened request, or the code of a sealed error reply).
/// BAD_VERSION is never sealed (`permits_error`), so it has no reason of its
/// own.
/// Spec: docs/53 §9 ("one record with the code"); RFC 3244 §2.
const fn code_reason(code: NonZeroResultCode) -> AuditReason {
    match code {
        NonZeroResultCode::Malformed => AuditReason::KpasswdMalformed,
        NonZeroResultCode::HardError => AuditReason::KpasswdHardError,
        NonZeroResultCode::AuthError => AuditReason::KpasswdAuthError,
        NonZeroResultCode::SoftError => AuditReason::KpasswdSoftError,
        NonZeroResultCode::AccessDenied => AuditReason::KpasswdAccessDenied,
        NonZeroResultCode::InitialFlagNeeded => AuditReason::KpasswdInitialFlagNeeded,
        NonZeroResultCode::BadVersion => AuditReason::ResultCodeNotPermitted,
    }
}

/// The KRB-PRIV control information of a request (RFC 4120 3.5.2, as RFC
/// 3244 §2 and docs/53 §5.4 items 2-3 read it), checked after the chain;
/// returns the reply's `s-address`. Every failure is the uniform `Denied`.
///
/// * `seq-number` present and equal to the Authenticator's (RFC 3244 §2;
///   RFC 4120 3.5.2 KRB_AP_ERR_BADORDER) — so "neither a time-stamp and usec
///   nor a sequence number" (KRB_AP_ERR_MODIFIED) cannot pass either;
/// * `timestamp`, if present, within the clock skew of keyd's clock (RFC
///   4120 3.5.2 KRB_AP_ERR_SKEW); `usec` accepted in its DER range, not
///   compared (Q-603 item 2); `r-address` ignored (RFC 3244 §2);
/// * `s-address` the directional address 0 (the AP-REQ's sender, RFC 4120
///   7.1) — the reply then carries the directional address 1 — or exactly
///   the peer address the front's kernel reported (an IPv4-mapped one only
///   as type 2, [`HostAddr::is`]) — the reply then carries the connection's
///   local address (Q-604 item 2). Anything else: KRB_AP_ERR_BADADDR.
///
/// Spec: RFC 4120 3.5.2, 5.7.1, 7.1; RFC 3244 §2; docs/53 §5.4 items 2-3,
/// §5.7; docs/questions/Q-603 items 2, 8, Q-604 item 2.
fn check_krb_priv_controls(
    part: &EncKrbPrivPart,
    authenticator_seq: u32,
    peer: &HostAddr,
    local: &HostAddr,
    skew_secs: u32,
    now_s: i64,
) -> Internal<HostAddress> {
    if part.seq_number != Some(authenticator_seq) {
        return Err(Deny::denied(AuditReason::KrbPrivSequenceMismatch));
    }
    if let Some(timestamp) = &part.timestamp {
        if !within_skew(kerberos_time_seconds(timestamp), now_s, skew_secs) {
            return Err(Deny::denied(AuditReason::KrbPrivTimestampSkew));
        }
    }
    let sender = &part.s_address;
    if sender.addr_type == ADDRESS_TYPE_DIRECTIONAL {
        if sender.address.as_slice() == DIRECTIONAL_AP_REQ_SENDER {
            return Ok(HostAddress {
                addr_type: ADDRESS_TYPE_DIRECTIONAL,
                address: DIRECTIONAL_AP_REQ_RECIPIENT.to_vec(),
            });
        }
        return Err(Deny::denied(AuditReason::KrbPrivAddressMismatch));
    }
    if peer.is(sender) {
        Ok(local.host_address())
    } else {
        Err(Deny::denied(AuditReason::KrbPrivAddressMismatch))
    }
}

/// keyd's verdict on the request's ChangePasswdData, in docs/53 §5.4's
/// order: the structure (`NewPasswdTooLong` ⇒ refused password, any other
/// decoding failure ⇒ malformed — Q-620 item 5), the set form (refused
/// without looking the target up — the type gives no access to it), the
/// password's encoding (UTF-8 only — RFC 3961 §3; no conversion of an
/// unknown encoding, Q-603 item 7), the password policy against the ticket
/// client's name ([`password_policy`] — the same function the install path
/// runs, docs/53 §6.2), then the INITIAL flag (RFC 3244 §2; RFC 4120 2.1).
/// Only an acceptable verdict keeps the password (zeroizing).
/// Spec: RFC 3244 §2; RFC 3961 §3; RFC 4120 2.1; [MS-KILE] 3.1.5.12;
/// docs/53 §5.4 items 4-7; docs/questions/Q-603 items 6, 7, Q-620 item 5.
fn judge(
    config: &KeydConfig,
    user_data: &UserData,
    cname: &PrincipalName,
    flags: TicketFlags,
) -> Pending {
    use ChangePasswordVerdict as V;
    let data = match ChangePasswdData::decode(user_data.as_bytes()) {
        Ok(data) => data,
        Err(krb_proto::Error::NewPasswdTooLong) => return Pending::Refused(V::PasswordRefused),
        Err(_) => return Pending::Refused(V::Malformed),
    };
    let newpasswd = match data.request() {
        PasswordRequest::Set => return Pending::Refused(V::SetNotSupported),
        PasswordRequest::Change { newpasswd } => newpasswd,
    };
    let Ok(text) = core::str::from_utf8(newpasswd.as_bytes()) else {
        return Pending::Refused(V::PasswordRefused);
    };
    if password_policy(config, text, cname).is_err() {
        return Pending::Refused(V::PasswordRefused);
    }
    if !flags.contains(TicketFlags::INITIAL) {
        return Pending::Refused(V::InitialFlagNeeded);
    }
    Pending::Acceptable(Zeroizing::new(text.to_owned()))
}

/// A reply sequence number: random, never zero (bounded redraws).
/// Spec: RFC 4120 3.2.4 ("If a sequence number is to be included, it SHOULD
/// be randomly chosen"), 5.5.1; docs/questions/Q-604 items 2, 3.
fn draw_sequence_number<E: EntropySource>(entropy: &mut E) -> Internal<u32> {
    for _ in 0..SEQUENCE_NUMBER_DRAWS {
        let mut octets = [0u8; 4];
        draw(entropy, &mut octets)?;
        let number = u32::from_be_bytes(octets);
        if number != 0 {
            return Ok(number);
        }
    }
    Err(Deny::unavailable(AuditReason::EntropyFailure))
}

/// Seal the reply of `entry` carrying `code`: the AP-REP — EncAPRepPart with
/// the Authenticator's ctime / cusec, no subkey (the client's subkey stays
/// the KRB-PRIV key) and a fresh random sequence number, under the ticket
/// session key with key usage 12 — and the KRB-PRIV — EncKrbPrivPart with the
/// result data (the 2-octet code, no result string), keyd's time, that
/// sequence number and the reply `s-address`, no `r-address`, under the
/// Authenticator's subkey with key usage 13.
/// Spec: RFC 3244 §2 (reply message; "This KRB-PRIV message must be encrypted
/// with the subsession key from the authenticator"; result data); RFC 4120
/// 3.2.4, 3.2.5, 3.5.1 ("MUST choose to use either a timestamp or a sequence
/// number (or both)"), 5.5.2, 5.7.1, 7.5.1 items 12, 13; docs/53 §5.5, §5.7;
/// docs/questions/Q-604 items 2, 3, 5.
fn seal_reply<E: EntropySource>(
    entropy: &mut E,
    entry: &ChangePasswordEntry,
    code: ResultCode,
    now: &KerberosTime,
) -> Internal<SealedReply> {
    let internal = |_| Deny::unavailable(AuditReason::InternalFailure);
    let seq_number = draw_sequence_number(entropy)?;
    let rep_plain = EncApRepPart {
        ctime: entry.ctime,
        cusec: entry.cusec,
        subkey: None,
        seq_number: Some(seq_number),
    }
    .encode()
    .map_err(internal)?;
    let ap_rep = ApRep {
        enc_part: EncryptedData {
            etype: entry.session.enc_type().number(),
            kvno: None,
            cipher: seal(entropy, &entry.session, AP_REP_ENC_PART, &rep_plain)?,
        },
    };
    let priv_plain = EncKrbPrivPart {
        user_data: UserData::from_slice(&code.result_data()),
        timestamp: Some(*now),
        // keyd's clock has second resolution (the daemon's `now`).
        usec: Some(Microseconds::new(0).map_err(internal)?),
        seq_number: Some(seq_number),
        s_address: entry.reply_s_address.clone(),
        r_address: None,
    }
    .encode()
    .map_err(internal)?;
    let krb_priv = KrbPriv {
        enc_part: EncryptedData {
            etype: entry.subkey.enc_type().number(),
            kvno: None,
            cipher: seal(entropy, &entry.subkey, KRB_PRIV_ENC_PART, &priv_plain)?,
        },
    };
    Ok(SealedReply { ap_rep, krb_priv })
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// `open_change_password_request`: verify an RFC 3244 request — its
    /// AP-REQ for `kadmin/changepw` and its KRB-PRIV — inside keyd, judge
    /// it, and keep it under a one-time request context.
    ///
    /// `ap_req_octets` and `krb_priv_octets` are the request's two fields as
    /// received (keyd decodes them itself); `peer` and `local` the
    /// connection's addresses as the front's kernel reported them — `peer`
    /// only for the `s-address` check, `local` only for the reply's
    /// `s-address`; `now` keyd-daemon's own clock (R50-5).
    ///
    /// 1. Steps 1-11 of the **shared** service-ticket verification
    ///    (`verify_service_ap_req`, docs/10 §5ב) with
    ///    `AppBinding::ChangePassword`: Role::Ldap; the ChangePasswordService
    ///    key set of `service` (the binding's purpose); no USE-SESSION-KEY;
    ///    the A-19 binding to `kadmin/changepw`; keyd-drawn key versions
    ///    only; the ticket (usage 2) and the Authenticator (usage 11); no
    ///    authorization-data or addresses; local transited; **no** `cksum`;
    ///    a configured subkey **and** a sequence number required; the
    ///    KRB-PRIV decrypted under the subkey (usage 13) — then the classes
    ///    (Skew, NYV, Expired) and the shared replay cache (RFC 4120 3.2.3).
    /// 2. The KRB-PRIV control information ([`check_krb_priv_controls`]).
    /// 3. The verdict ([`judge`]).
    /// 4. A fresh context id, bound to `caller`, for `token_lifetime_secs`,
    ///    in the bounded table (full ⇒ `Unavailable`).
    ///
    /// Every failure before the chain completed is the uniform `Denied`
    /// (A-26) — an undecodable AP-REQ or KRB-PRIV included (Q-660); the
    /// classes only after it; the startup hold-down is `Unavailable`. A
    /// verdict other than `Acceptable` is not an error: the context exists
    /// so that dird can seal the verdict's error reply. The one record names
    /// the verdict's result code (outcome `Success`).
    ///
    /// Spec: RFC 3244 §2; RFC 4120 2.1, 3.2.3, 3.5.2, 5.5.1, 5.7.1, 7.1,
    /// 7.5.1; docs/53 R53-7, R53-9, §5.3, §5.4, §5.5; docs/10 §5ב, §8, §9
    /// (A-26); docs/questions/Q-601 item 2, Q-603, Q-620 item 5 (A-117).
    #[allow(clippy::too_many_arguments)]
    pub fn open_change_password_request(
        &mut self,
        caller: &CallerId,
        service: &PrincipalId,
        ap_req_octets: &[u8],
        krb_priv_octets: &[u8],
        peer: &HostAddr,
        local: &HostAddr,
        now: &KerberosTime,
    ) -> Result<ChangePasswordContext, AuthnError> {
        let accompanying = Accompanying::KrbPriv(krb_priv_octets);
        let binding = accompanying.binding();
        // The key set is named by the binding's purpose (R2 / docs/53 §4.5).
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
            .and_then(|verified| {
                self.keep_change_password_request(
                    caller,
                    &handle,
                    verified,
                    peer,
                    local,
                    now,
                    &mut fields,
                )
            });
        self.emit(caller, binding.operation(), now, &fields, &result);
        result.map_err(AuthnError::from)
    }

    /// Steps 2-4 of [`Keyd::open_change_password_request`].
    #[allow(clippy::too_many_arguments)]
    fn keep_change_password_request(
        &mut self,
        caller: &CallerId,
        service: &KeyHandle,
        verified: VerifiedApReq,
        peer: &HostAddr,
        local: &HostAddr,
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<ChangePasswordContext> {
        let now_s = kerberos_time_seconds(now);
        let VerifiedApReq {
            crealm,
            cname,
            authtime,
            endtime,
            flags,
            session,
            subkey,
            ctime,
            cusec,
            seq_number,
            krb_priv,
            ..
        } = verified;
        // The core guarantees all three for this binding (step 10a); their
        // absence here is an internal inconsistency (fail closed).
        let (Some(subkey), Some(seq_number), Some(part)) = (subkey, seq_number, krb_priv) else {
            return Err(Deny::unavailable(AuditReason::InternalFailure));
        };
        // 2. The control information.
        let reply_s_address = check_krb_priv_controls(
            &part,
            seq_number,
            peer,
            local,
            self.config.clock_skew_secs,
            now_s,
        )?;
        // 3. The verdict; the decrypted plaintext (the password) goes now.
        let pending = judge(&self.config, &part.user_data, &cname, flags);
        drop(part);
        let verdict = pending.verdict();
        fields.success_reason = verdict.result_code().map(code_reason);
        // 4. The context.
        let mut id = [0u8; TOKEN_ID_LENGTH];
        draw(&mut self.entropy, &mut id)?;
        let expires_at = now_s + i64::from(self.config.token_lifetime_secs);
        let entry = ChangePasswordEntry {
            service: *service,
            crealm: crealm.clone(),
            cname: cname.clone(),
            session,
            subkey,
            ctime,
            cusec,
            reply_s_address,
            pending,
        };
        if !self
            .change_password_contexts
            .insert(id, *caller, expires_at, entry, now_s)
        {
            return Err(Deny::unavailable(AuditReason::TokenTableFull));
        }
        Ok(ChangePasswordContext {
            ctx_id: ChangePasswordCtxId::from_bytes(id),
            crealm,
            cname,
            authtime,
            endtime,
            flags,
            verdict,
        })
    }

    /// `complete_change_password`: install the password of the request
    /// context `ctx` into `target` and return the sealed success reply.
    /// A key-state change; `target` is a user's password key set
    /// (`PrincipalLongterm`).
    ///
    /// 1. The authorization step (`Keyd::admit`): Role::Ldap; the purpose;
    ///    the hold-down; a live `ChangePassword` decision entry for `target`
    ///    (`NoGrant`) — the same check the daemon's classification reads.
    /// 2. The context: live and this caller's (else refused, removed); its
    ///    verdict `Acceptable` (`ChangePasswordNotAcceptable`, the context
    ///    stays). The success reply is sealed now — and released only after
    ///    step 4 (module documentation).
    /// 3. The decision, consumed: its target's binding must identify the
    ///    context's ticket client (`GrantMismatch` — keyd binds the target,
    ///    docs/53 R53-8). The record names the decision.
    /// 4. The install — `Keyd::install_password`, the one install path of
    ///    every password: the password policy, the key set must exist, the
    ///    A-19 binding, keyd's kvno, string-to-key with the decision's salt,
    ///    `BoundKeys::install_password_version`.
    /// 5. The context is consumed; the reply returned.
    ///
    /// A refusal at steps 2-4 leaves the context for the error seal; after
    /// the install nothing can fail.
    ///
    /// Spec: RFC 3244 §2 ("The server then generates the appropriate
    /// keytypes from the password and stores them"); RFC 4120 3.2.4, 5.5.2,
    /// 5.7.1, 6.2; docs/53 R53-5, R53-7, R53-8, §4.4, §5.5, §6; docs/10 §6,
    /// §6א, §10; docs/questions/Q-601 items 2, 5, Q-605 (A-117).
    pub fn complete_change_password(
        &mut self,
        caller: &CallerId,
        ctx: &ChangePasswordCtxId,
        target: &KeyHandle,
        now: &KerberosTime,
    ) -> Result<SealedReply, Error> {
        let mut fields = AuditFields::for_handle(target);
        fields.decision = self
            .decisions
            .secret_decision_for(target, Operation::CompleteChangePassword);
        let result = self.complete_change_password_inner(caller, ctx, target, now, &mut fields);
        self.emit(
            caller,
            Operation::CompleteChangePassword,
            now,
            &fields,
            &result,
        );
        result.map_err(Error::from)
    }

    fn complete_change_password_inner(
        &mut self,
        caller: &CallerId,
        ctx: &ChangePasswordCtxId,
        target: &KeyHandle,
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<SealedReply> {
        // 1.
        self.admit(
            caller,
            Operation::CompleteChangePassword,
            &[(HandleSlot::Primary, target)],
            now,
        )?;
        let now_s = kerberos_time_seconds(now);
        // 2. The context stays in the table until the install succeeded.
        let (crealm, cname, password, reply) = {
            let entry = self
                .change_password_contexts
                .peek_mut(ctx.as_bytes(), caller, now_s)
                .map_err(token_deny)?;
            let Pending::Acceptable(password) = &entry.pending else {
                return Err(Deny::denied(AuditReason::ChangePasswordNotAcceptable));
            };
            let password = Zeroizing::new(password.as_str().to_owned());
            let reply = seal_reply(&mut self.entropy, entry, ResultCode::Success, now)?;
            (entry.crealm.clone(), entry.cname.clone(), password, reply)
        };
        // 3. The decision: the ticket client's own (consumed here).
        let redeemed = self
            .decisions
            .redeem_secret_for_client(target, &crealm, &cname, now_s)?;
        fields.decision = redeemed.decision;
        // 4. The one install path.
        self.install_password(
            target,
            &redeemed.binding,
            &password,
            &redeemed.salt,
            Existence::MustExist,
            &redeemed.account_name,
            fields,
        )?;
        drop(password);
        // 5. Installed: the context is consumed — no error reply can follow.
        // (Single-threaded keyd: the entry peeked above is still there.)
        self.change_password_contexts
            .take(ctx.as_bytes(), caller, now_s)
            .map_err(|_| Deny::unavailable(AuditReason::InternalFailure))?;
        Ok(reply)
    }

    /// `seal_change_password_error`: seal the error reply of the request
    /// context `ctx` with the non-zero result `code` (the type cannot hold
    /// KRB5_KPASSWD_SUCCESS — RFC 3244 §2: "not allowed in a KRB-ERROR
    /// message", and no success can be sealed here), consuming the context.
    ///
    /// 1. The authorization step: Role::Ldap; the hold-down.
    /// 2. The context: live and this caller's (else refused, removed).
    /// 3. `code` permitted by the context's verdict
    ///    (`ChangePasswordVerdict::permits_error`; else
    ///    `ResultCodeNotPermitted`, the context stays).
    /// 4. The reply sealed ([`seal_reply`]: AP-REP + KRB-PRIV with the
    ///    2-octet code, no result string); the context consumed.
    ///
    /// The one record names the code (outcome `Success`) and the
    /// ChangePasswordService key set the request was opened under.
    ///
    /// Spec: RFC 3244 §2; RFC 4120 3.2.4, 5.5.2, 5.7.1; docs/53 R53-7,
    /// R53-11, §5.5, §5.7, §9; docs/questions/Q-604 (A-117).
    pub fn seal_change_password_error(
        &mut self,
        caller: &CallerId,
        ctx: &ChangePasswordCtxId,
        code: NonZeroResultCode,
        now: &KerberosTime,
    ) -> Result<SealedReply, Error> {
        let mut fields = AuditFields::default();
        let result = self.seal_change_password_error_inner(caller, ctx, code, now, &mut fields);
        self.emit(
            caller,
            Operation::SealChangePasswordError,
            now,
            &fields,
            &result,
        );
        result.map_err(Error::from)
    }

    fn seal_change_password_error_inner(
        &mut self,
        caller: &CallerId,
        ctx: &ChangePasswordCtxId,
        code: NonZeroResultCode,
        now: &KerberosTime,
        fields: &mut AuditFields,
    ) -> Internal<SealedReply> {
        // 1.
        self.admit(caller, Operation::SealChangePasswordError, &[], now)?;
        let now_s = kerberos_time_seconds(now);
        // 2-4.
        let reply = {
            let entry = self
                .change_password_contexts
                .peek_mut(ctx.as_bytes(), caller, now_s)
                .map_err(token_deny)?;
            *fields = AuditFields::for_handle(&entry.service);
            if !entry.pending.verdict().permits_error(code) {
                return Err(Deny::denied(AuditReason::ResultCodeNotPermitted));
            }
            seal_reply(&mut self.entropy, entry, ResultCode::Failure(code), now)?
        };
        self.change_password_contexts
            .take(ctx.as_bytes(), caller, now_s)
            .map_err(|_| Deny::unavailable(AuditReason::InternalFailure))?;
        fields.success_reason = Some(code_reason(code));
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb_proto::KerberosString;

    fn part(seq: Option<u32>, timestamp: Option<KerberosTime>, s: HostAddress) -> EncKrbPrivPart {
        EncKrbPrivPart {
            user_data: UserData::from_slice(b"x"),
            timestamp,
            usec: None,
            seq_number: seq,
            s_address: s,
            r_address: None,
        }
    }

    fn now() -> KerberosTime {
        KerberosTime::new(2026, 11, 15, 12, 0, 0).unwrap()
    }

    /// RFC 4120 3.5.2 / 7.1; RFC 3244 §2; Q-603 items 2, 8; Q-604 item 2:
    /// the control information of a request, and the reply `s-address` it
    /// selects. Made-up addresses (RFC 5737 documentation range).
    #[test]
    fn krb_priv_controls_follow_rfc4120_3_5_2() {
        let peer = HostAddr::ipv4([192, 0, 2, 10]);
        let local = HostAddr::ipv4([192, 0, 2, 1]);
        let now_s = kerberos_time_seconds(&now());
        let check = |p: &EncKrbPrivPart| {
            check_krb_priv_controls(p, 77, &peer, &local, 300, now_s).map_err(|d| d.reason)
        };
        let directional = |v: [u8; 4]| HostAddress {
            addr_type: ADDRESS_TYPE_DIRECTIONAL,
            address: v.to_vec(),
        };
        // Directional 0 ⇒ the reply carries directional 1.
        assert_eq!(
            check(&part(Some(77), None, directional([0, 0, 0, 0]))),
            Ok(directional([0, 0, 0, 1]))
        );
        // The peer's own address ⇒ the reply carries the local address.
        assert_eq!(
            check(&part(Some(77), Some(now()), peer.host_address())),
            Ok(local.host_address())
        );
        // Sequence number missing or different (BADORDER).
        for seq in [None, Some(78)] {
            assert_eq!(
                check(&part(seq, None, peer.host_address())),
                Err(AuditReason::KrbPrivSequenceMismatch)
            );
        }
        // A timestamp outside the skew (SKEW).
        let stale = KerberosTime::new(2026, 11, 15, 11, 50, 0).unwrap();
        assert_eq!(
            check(&part(Some(77), Some(stale), peer.host_address())),
            Err(AuditReason::KrbPrivTimestampSkew)
        );
        // Another address, directional 1 (the reflection of keyd's own
        // reply), another type (BADADDR).
        for s in [
            HostAddr::ipv4([192, 0, 2, 11]).host_address(),
            directional([0, 0, 0, 1]),
            HostAddress {
                addr_type: 20,
                address: vec![0; 16],
            },
        ] {
            assert_eq!(
                check(&part(Some(77), None, s)),
                Err(AuditReason::KrbPrivAddressMismatch)
            );
        }
    }

    /// docs/53 §5.4 items 4-7 (Q-620 item 5, Q-603 item 7): the verdict of a
    /// ChangePasswdData — set form, malformed, too long, not UTF-8, policy,
    /// INITIAL — and only an acceptable one keeps the password. The values
    /// are made up for this test.
    #[test]
    fn the_verdict_follows_docs53_order() {
        use ChangePasswordVerdict as V;
        let config = KeydConfig::new(Realm::new("EXAMPLE.ORG").unwrap());
        let cname = PrincipalName {
            name_type: 1,
            name_string: vec![KerberosString::new("carol").unwrap()],
        };
        let initial = TicketFlags::INITIAL.union(TicketFlags::PRE_AUTHENT);
        let change = |password: &[u8]| {
            UserData::from_slice(
                &ChangePasswdData::change(krb_proto::NewPasswd::from_slice(password))
                    .encode()
                    .unwrap(),
            )
        };
        let verdict = |data: &UserData, flags| judge(&config, data, &cname, flags).verdict();
        assert_eq!(
            verdict(&change(b"Mortar-Cypress-19-Wisp"), initial),
            V::Acceptable
        );
        assert!(matches!(
            judge(&config, &change(b"Mortar-Cypress-19-Wisp"), &cname, initial),
            Pending::Acceptable(p) if p.as_str() == "Mortar-Cypress-19-Wisp"
        ));
        assert_eq!(
            verdict(&change(b"Mortar-Cypress-19-Wisp"), TicketFlags::PRE_AUTHENT),
            V::InitialFlagNeeded
        );
        // The policy before the INITIAL flag (docs/53 §5.4 order).
        assert_eq!(
            verdict(&change(b"short"), TicketFlags::PRE_AUTHENT),
            V::PasswordRefused
        );
        // The ticket client's name and keyd's realm reach the policy
        // (docs/56 §7 P-24; each otherwise-valid value breaks one rule).
        for refused in [&b"Tq7#Carol!w"[..], b"Tq7#Example!", b"Tq7#Admin!w"] {
            assert_eq!(verdict(&change(refused), initial), V::PasswordRefused);
        }
        assert_eq!(verdict(&change(&[0xff; 16]), initial), V::PasswordRefused);
        assert_eq!(
            verdict(&UserData::from_slice(&[0x30, 0x00]), initial),
            V::Malformed
        );
        assert_eq!(
            verdict(&UserData::from_slice(b"not der"), initial),
            V::Malformed
        );
        // More than 256 UTF-16 units ([MS-SAMR] 3.1.1.7.2 item 2), within
        // the 1024-octet bound: refused by the policy.
        assert_eq!(verdict(&change(&[b'a'; 257]), initial), V::PasswordRefused);
    }
}
