//! `ChangePassword` (task K6): a user's change of its **own** password
//! through kpasswd (RFC 3244 §2), decided by this PEP for dird's kpasswd
//! service (docs/53 §5.6 step 4).
//!
//! # One password-setting mechanism (docs/53 §4.4, R53-5; class C14)
//!
//! `ChangePassword` adds no write path. It is `BeginPasswordSet` with a
//! different Action and a different source of the Subject:
//!
//! | | `BeginPasswordSet` (admin plane) | `ChangePassword` (kpasswd) |
//! |---|---|---|
//! | Subject | from the admin AP-REQ keyd verified (`VerifiedTicket`) | from the request keyd opened and judged acceptable ([`ChangePasswordTicket`]) — **the same** `AdminSubject::from_verified_ticket` (`usable_at`, `revokes(authtime)`) |
//! | freshness | `ticket_age` ≤ the configured threshold | **the same** threshold (R51-10 — one rule, Q-601 item 8) |
//! | target | the account the request names, through the visibility gate | the requester's own account — users only |
//! | PDP | `DirControlRight(User-Force-Change-Password)` on the target | `DirControlRight(User-Change-Password)` on **the account itself** ([MS-ADTS] 3.1.1.3.1.5.1), through all five layers — the tier invariant without exception (Q-608 item 2) |
//! | key sets | `password_targets` | **the same** `password_targets` (a user: one key set) |
//! | dual control (P-22) | an explicitly Tier0 account needs an approver | an explicitly Tier0 account is **refused**: kpasswd carries one AP-REQ and has no place for an approver (Q-608 item 1 is the owner's and open — the strict default) |
//! | write | `pwdLastSet = now` (`WriteKind::PasswordSet`), applied by **the same** `apply` after auditd acknowledged the decision event | **the same** |
//! | what dird registers in keyd | `SetSecret` (executor: admind's `set_secret`) | `ChangePassword` (executor: keyd's `complete_change_password` — Q-662) |
//!
//! The reply differs only in type ([`crate::Reply::PasswordChange`]), so the
//! decision dird registers cannot be the other one's.
//!
//! # The Subject comes only from keyd (docs/53 §4.3, R53-8)
//!
//! A [`ChangePasswordTicket`] is built only from keyd's
//! `ChangePasswordContext` — the answer of `open_change_password_request`,
//! after keyd verified the AP-REQ for `kadmin/changepw` and decrypted the
//! KRB-PRIV under its subkey — and only when keyd's verdict is
//! `Acceptable`. Nothing the front or the client says about who is asking
//! reaches this module: the ticket's client is the account whose password
//! changes (keyd binds the target to it again at the completion).
//!
//! # The result code (docs/53 §5.7)
//!
//! [`change_password_result`] maps a refusal of this operation to the RFC
//! 3244 code dird seals: before any write — an unusable account, a ticket on
//! the hot-list, `ticket_age` over the threshold ⇒ AUTHERROR (3); the PDP's
//! Deny, a non-user account, a Tier0 account ⇒ ACCESSDENIED (5); anything
//! that failed, and every refusal at the write ⇒ HARDERROR (2). Which rule
//! refused is recorded in the audit event only (A-26).
//!
//! # The operation digest
//!
//! A kpasswd request has no operation digest: the operation is bound to the
//! request by the subkey encryption of its KRB-PRIV, not by an
//! Authenticator `cksum` (docs/53 §5.4 item 1; Q-603 item 4), and dird sees
//! no cleartext operation octets to digest. The events carry
//! [`NO_OPERATION_DIGEST`] (docs/questions/Q-963 item 3).
//!
//! Spec: docs/53 §4.3, §4.4, §5.4, §5.6 steps 4-5, §5.7, §9; [MS-ADTS]
//! v20261026 3.1.1.3.1.5.1, 6.1.1.2.7.52; RFC 4120 §3.2.3 ("does not imply
//! authorization"); docs/questions/Q-601, Q-608, Q-662 (A-117, A-126).
//!
//! Written only from, opened in this session: AGENT-ONBOARDING, AGENTS,
//! docs/53 (whole), PENDING-OWNER (A-117, A-121, A-126, A-142, A-151, A-153,
//! A-156, A-158, A-159), docs/questions Q-600..Q-609, Q-660..Q-664, Q-945,
//! Q-955, docs/research/r3-e (§1-§3), the pinned RFC 3244 §2 (SHA-256
//! `45b9130f…dec378`) and RFC 4120 §3.2.3 (`368d3cd1…f75b`), the pinned
//! [MS-ADTS] v20261026 (`55b59eb1…b2b1`) 3.1.1.3.1.5.1 and 6.1.1.2.7.52, and
//! this repository's own code. No other implementation was consulted or
//! recalled (AGENTS.md §1-3).

use dtyp::Guid;
use ipc_audit::{AdminFailure, AdminRefusal, DecisionResult, DirAdminOperation, DirAdminStage};
use keyd_types::{ChangePasswordContext, ChangePasswordVerdict, OperationDigest};
use krb_proto::{KerberosTime, NonZeroResultCode, PrincipalName, Realm};
use pdp::{Action, ControlRightId, PolicySnapshot, Resource, Tier};

use directory_pip::{AccountKind, DirectoryView};

use crate::admin::{
    subject_of_facts, DirectoryAdmin, OpCx, PasswordWrite, Plan, Prepared, WriteKind, WritePlan,
};
use crate::audit::{sid_value, EventBase, Refusal, Stop};
use crate::checks::Cx;
use crate::random::RandomSource;
use crate::reply::PasswordChangeTarget;
use crate::subject::SubjectError;

/// The control access right User-Change-Password: rightsGuid
/// `ab721a53-1e2f-11d0-9819-00aa0040529b`, its printed groups mapped to the
/// GUID members as the project decided for every schema GUID (A-31: group 1
/// = Data1, group 2 = Data2, group 3 = Data3, groups 4-5 = the eight Data4
/// bytes in order).
/// Spec: [MS-ADTS] v20261026 6.1.1.2.7.52; 3.1.1.3.1.5.1 ("MUST possess the
/// 'User-Change-Password' control access right on itself"); docs/53 §2.2;
/// A-31.
pub const USER_CHANGE_PASSWORD: Guid = Guid {
    data1: 0xab72_1a53,
    data2: 0x1e2f,
    data3: 0x11d0,
    data4: [0x98, 0x19, 0x00, 0xaa, 0x00, 0x40, 0x52, 0x9b],
};

/// The operation digest of every `ChangePassword` event: none (module
/// documentation) — all zero.
/// Spec: docs/questions/Q-888 (the field), Q-963 item 3.
pub const NO_OPERATION_DIGEST: OperationDigest = OperationDigest::new([0; 32]);

/// The facts of a change-password request keyd verified and judged
/// acceptable: the ticket's client realm and name and its authtime (RFC 4120
/// §5.3). Built only from keyd's `ChangePasswordContext` whose verdict is
/// `Acceptable` ([`ChangePasswordTicket::from_context`]) — so a Subject is
/// never built for a request keyd refused, and never from anything the
/// front or the client claims (module documentation).
/// Spec: docs/53 §4.3, §5.5 (`ChangePasswordContext`), §5.6 steps 3-4;
/// docs/questions/Q-601 item 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePasswordTicket {
    crealm: Realm,
    cname: PrincipalName,
    authtime: KerberosTime,
}

impl ChangePasswordTicket {
    /// The ticket facts of `context`, if keyd's verdict is `Acceptable`;
    /// `None` otherwise — dird then seals the verdict's own code (docs/53
    /// §5.6 step 3; docs/questions/Q-663 item 2).
    /// Spec: docs/53 §5.5, §5.6 step 3.
    #[must_use]
    pub fn from_context(context: &ChangePasswordContext) -> Option<ChangePasswordTicket> {
        (context.verdict == ChangePasswordVerdict::Acceptable).then(|| ChangePasswordTicket {
            crealm: context.crealm.clone(),
            cname: context.cname.clone(),
            authtime: context.authtime,
        })
    }

    /// The client realm.
    #[must_use]
    pub fn crealm(&self) -> &Realm {
        &self.crealm
    }

    /// The client name.
    #[must_use]
    pub fn cname(&self) -> &PrincipalName {
        &self.cname
    }

    /// The time of the initial authentication (RFC 4120 §5.3).
    #[must_use]
    pub fn authtime(&self) -> &KerberosTime {
        &self.authtime
    }
}

/// One `ChangePassword` for [`DirectoryAdmin::prepare_change_password`].
/// Spec: docs/53 §5.6 step 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePasswordRequest {
    /// dird's number for the operation: its `Decision` and `Outcome` events
    /// carry it, and — after the commit — the `ChangePassword` decision dird
    /// registers in keyd is numbered by it (Q-340 item 1; docs/52 §4.2).
    pub operation_id: u64,
    /// The ticket keyd verified.
    pub ticket: ChangePasswordTicket,
}

/// The RFC 3244 result code dird seals for `refusal` — a refusal of
/// [`DirectoryAdmin::prepare_change_password`] or of `apply` on its
/// prepared write, or one of dird's own restaged events (module
/// documentation, "The result code").
/// Spec: docs/53 §5.7 (dird's rows); RFC 3244 §2 (codes 2, 3, 5);
/// docs/questions/Q-604 item 4, Q-663 item 2.
#[must_use]
pub fn change_password_result(refusal: &Refusal) -> NonZeroResultCode {
    match refusal.event().stage {
        DirAdminStage::Decision(DecisionResult::Refused(
            AdminRefusal::Unauthenticated | AdminRefusal::TicketAge,
        )) => NonZeroResultCode::AuthError,
        DirAdminStage::Decision(DecisionResult::Refused(_)) => NonZeroResultCode::AccessDenied,
        // A failure before any decision, a refusal or failure at the write,
        // and anything that is not a refusal at all (fail closed).
        DirAdminStage::Decision(DecisionResult::Failed(_) | DecisionResult::Proceed)
        | DirAdminStage::Outcome(_) => NonZeroResultCode::HardError,
    }
}

impl<R: RandomSource> DirectoryAdmin<R> {
    /// Decide a `ChangePassword` against ONE view (taken after the caller
    /// began its `WriteTxn`, as for every write) and the policy of the same
    /// version, at `now` — in docs/53 §5.6 step 4's order:
    ///
    /// 1. the Subject from the ticket keyd verified, through the directory
    ///    exactly as for an administrator (`usable_at`, `revokes(authtime)`)
    ///    — otherwise `Unauthenticated`;
    /// 2. `ticket_age` ≤ the configured threshold — otherwise `TicketAge`;
    /// 3. the requester's own account, a **user** — a computer (or any other
    ///    kind) ⇒ `TargetProtected`;
    /// 4. `DirControlRight(User-Change-Password)` on the account object
    ///    itself, transport `Kpasswd` — Deny ⇒ `PolicyDenied`;
    /// 5. its key set through `password_targets` (never krbtgt, a DC account
    ///    or a service object);
    /// 6. the change-seq counter;
    /// 7. dual control (P-22): an explicitly Tier0 account ⇒
    ///    `ApprovalRequired` (module documentation; Q-608 item 1).
    ///
    /// `Ok` is the [`Prepared`] write — `pwdLastSet = now` — that dird
    /// sends, has acknowledged, and applies with the same
    /// [`DirectoryAdmin::apply`] as every write; `Err` carries the
    /// `Decision` event of the refusal and its client status
    /// ([`change_password_result`] gives the RFC 3244 code).
    ///
    /// Spec: docs/53 §4.4 (R53-5), §5.6 step 4; [MS-ADTS] 3.1.1.3.1.5.1;
    /// docs/51 §5.3, §5.5 (R51-10); docs/questions/Q-601 items 7-8, Q-608
    /// (A-117); P-22.
    pub fn prepare_change_password(
        &self,
        request: &ChangePasswordRequest,
        view: &DirectoryView<'_>,
        policy: &PolicySnapshot,
        now: &KerberosTime,
    ) -> Result<Prepared, Refusal> {
        let mut base = EventBase::bare(
            request.operation_id,
            DirAdminOperation::ChangePassword,
            &NO_OPERATION_DIGEST,
        );
        match self.change_checked(request, view, policy, now, &mut base) {
            Ok((plan, obligations, requester)) => {
                Ok(Prepared::planned(base, now, obligations, requester, plan))
            }
            Err(stop) => Err(base.decision_refusal(now, stop)),
        }
    }

    /// The refusal of a `ChangePassword` that failed before
    /// [`DirectoryAdmin::prepare_change_password`] could run (dird could not
    /// begin its transaction or take its view): its `Decision(Failed)`
    /// event, numbered `operation_id`.
    /// Spec: docs/51 §7.4 steps 2-3 (the admin plane's `ViewUnavailable`);
    /// docs/53 §5.6 step 5 ("a failure in one of them ⇒ 2").
    #[must_use]
    pub fn refuse_failed_change_password(
        &self,
        operation_id: u64,
        failure: AdminFailure,
        now: &KerberosTime,
    ) -> Refusal {
        EventBase::bare(
            operation_id,
            DirAdminOperation::ChangePassword,
            &NO_OPERATION_DIGEST,
        )
        .decision_refusal(now, Stop::Failed(failure))
    }

    /// The checks, in order (see [`DirectoryAdmin::prepare_change_password`]).
    fn change_checked(
        &self,
        request: &ChangePasswordRequest,
        view: &DirectoryView<'_>,
        policy: &PolicySnapshot,
        now: &KerberosTime,
        base: &mut EventBase,
    ) -> Result<(Plan, Vec<pdp::Obligation>, dtyp::Sid), Stop> {
        // The view must be of this PEP's domain (fail closed on a
        // misassembled caller).
        if view.context().realm() != self.config.realm()
            || view.context().naming_context() != self.config.naming_context()
        {
            return Err(Stop::Failed(AdminFailure::InternalFailure));
        }
        let cx = Cx::kpasswd(&self.config, &self.ids, view, policy, now)?;
        // 1. The Subject, from keyd's facts through the directory (docs/53
        //    §5.6 step 4; docs/51 §5.3).
        let ticket = &request.ticket;
        let requester = subject_of_facts(&cx, &ticket.crealm, &ticket.cname, &ticket.authtime)
            .map_err(|e| match e {
                SubjectError::NotUsable => Stop::Refused(AdminRefusal::Unauthenticated),
                SubjectError::Unavailable => Stop::Failed(AdminFailure::StoreFailure),
            })?;
        base.requester = sid_value(requester.sid());
        // docs/53 §9: the target of the event is the requester's own
        // account.
        base.target = Some(requester.guid());
        // 2. Freshness: the admin channel's threshold (R51-10; Q-601 item
        //    8).
        if requester.ticket_age() > self.config.ticket_age_max() {
            return Err(Stop::Refused(AdminRefusal::TicketAge));
        }
        // 3. The account itself — a user only (docs/53 R53-1, §5.6 step 4).
        let own = cx.own_account(requester.guid())?;
        if own.class != self.ids.user.id {
            return Err(Stop::Refused(AdminRefusal::TargetProtected));
        }
        // 4. The PDP: User-Change-Password on the account object itself,
        //    through every layer (docs/53 §5.6 step 4; [MS-ADTS]
        //    3.1.1.3.1.5.1; Q-608 item 2: no exception to the tier rule).
        let ctx = OpCx {
            cx: &cx,
            requester: &requester,
        };
        let action = Action::DirControlRight(ControlRightId(USER_CHANGE_PASSWORD));
        let resource = Resource::DirObject {
            dn: own.dn.clone(),
            attr: None,
        };
        let obligations = self.authorize(&ctx, base, &action, &resource)?;
        // 5. Its key set — the one derivation of every password write
        //    (docs/53 §4.4); a user has exactly one.
        let targets = self.password_targets(&cx, own.guid, &own.obj, own.class)?;
        let (AccountKind::User, [key]) = (targets.kind, targets.keys.as_slice()) else {
            return Err(Stop::Refused(AdminRefusal::TargetProtected));
        };
        let target = PasswordChangeTarget {
            key: key.clone(),
            salt: targets.salt.clone(),
        };
        // 6. The change-seq counter (A-83).
        let change_seq = self.change_seq(&cx)?;
        // 7. Dual control (P-22: "password … of a Tier0 account"): the
        //    classification of BeginPasswordSet; kpasswd has no place for an
        //    approver, so an account that would need one is refused
        //    (Q-608 item 1, owner-open: the strict default).
        if cx.explicit_tier(&own.dn)? == Some(Tier::Tier0) {
            return Err(Stop::Refused(AdminRefusal::ApprovalRequired));
        }
        Ok((
            Plan::Write(WritePlan {
                change_seq,
                seen: vec![(own.guid, own.obj)],
                kind: WriteKind::PasswordSet {
                    target: own.guid,
                    reply: PasswordWrite::Change(target),
                },
            }),
            obligations,
            *requester.sid(),
        ))
    }
}
