//! `ChangePassword` (task K6): a user's change of its own password through
//! kpasswd, decided by the write PEP for dird's kpasswd service.
//!
//! Sources: docs/53 §4.3 (the Subject only from keyd's verified context),
//! §4.4 (R53-5: one password-setting mechanism — the same write plan, the
//! same `password_targets`, the same `apply`), §5.6 step 4 (Subject,
//! `ticket_age`, users only, the PDP on User-Change-Password on the account
//! itself through all five layers), §5.7 (the result codes), §9 (the event:
//! target = the requester's own account); [MS-ADTS] v20261026 3.1.1.3.1.5.1
//! ("MUST possess the 'User-Change-Password' control access right on
//! itself"), 6.1.1.2.7.52 (the rightsGuid); RFC 3244 §2 (result codes 2, 3,
//! 5); RFC 4120 §3.2.3 (authentication "does not imply authorization");
//! docs/questions/Q-601 items 7-8, Q-608 (item 1 owner-open: a Tier0
//! account is refused; item 2: no exception to the tier rule), Q-662 (the
//! decision names its executor — a distinct reply), Q-963. Fixtures:
//! tests/common (this project's own test data; no vector from any other
//! implementation).

mod common;

use common::*;
use directory_admin::{
    change_password_result, ChangePasswordRequest, ChangePasswordTicket, Operation, Refusal, Reply,
    NO_OPERATION_DIGEST, USER_CHANGE_PASSWORD,
};
use dtyp::Guid;
use ipc_audit::{
    AdminFailure, AdminRefusal, DecisionResult, DirAdminEvent, DirAdminOperation, DirAdminStage,
    OutcomeResult, PdpReasonCode,
};
use keyd_types::{
    ChangePasswordContext, ChangePasswordCtxId, ChangePasswordVerdict, KeyHandle, KeyPurpose,
    PrincipalId, TOKEN_ID_LENGTH,
};
use krb_proto::constants::KRB_NT_PRINCIPAL;
use krb_proto::{KerberosString, KerberosTime, NonZeroResultCode, PrincipalName, TicketFlags};
use pdp::Tier;

/// A domain where the root SD grants PRINCIPAL_SELF User-Change-Password
/// (inherited by every account), the policy allows the right to any
/// subject (the ACL decides), and ou=Staff is classified `staff_tier`.
fn self_change_domain(test: &str, staff_tier: Option<Tier>) -> Domain {
    Domain::with_extra(
        test,
        Extra {
            self_ace: true,
            self_rule: true,
            staff_tier,
        },
    )
}

/// keyd's answer to an opened request of `sam`, first authenticated at
/// `authtime`, with `verdict` (crate keyd-types `ChangePasswordContext`; the
/// context id and the times are made up).
fn context(
    sam: &str,
    authtime: KerberosTime,
    verdict: ChangePasswordVerdict,
) -> ChangePasswordContext {
    ChangePasswordContext {
        ctx_id: ChangePasswordCtxId::from_bytes([0xC7; TOKEN_ID_LENGTH]),
        crealm: realm(),
        cname: PrincipalName {
            name_type: KRB_NT_PRINCIPAL,
            name_string: vec![KerberosString::new(sam).unwrap()],
        },
        authtime,
        endtime: kt(2026, 11, 13, 10, 5, 0),
        flags: TicketFlags::INITIAL.union(TicketFlags::PRE_AUTHENT),
        verdict,
    }
}

/// The request of `sam`'s acceptable change, first authenticated at
/// `authtime`.
fn change_at(d: &Domain, sam: &str, authtime: KerberosTime) -> ChangePasswordRequest {
    ChangePasswordRequest {
        operation_id: d.next_id(),
        ticket: ChangePasswordTicket::from_context(&context(
            sam,
            authtime,
            ChangePasswordVerdict::Acceptable,
        ))
        .unwrap(),
    }
}

/// [`change_at`] with the fixtures' authtime (one minute before `now`).
fn change(d: &Domain, sam: &str) -> ChangePasswordRequest {
    change_at(d, sam, authtime())
}

/// `prepare_change_password` at [`now`] over a view taken after the write
/// transaction began, as dird does; on success the write is acknowledged,
/// applied and committed.
fn run(d: &mut Domain, request: &ChangePasswordRequest) -> Result<(DirAdminEvent, Reply), Refusal> {
    let mut txn = d.store.begin_write().unwrap();
    let view = d.ctx.view(&d.store, &d.tiers).unwrap();
    let prepared = d
        .admin
        .prepare_change_password(request, &view, &d.policy, &now());
    drop(view);
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(refusal) => {
            txn.abort().unwrap();
            return Err(refusal);
        }
    };
    let decision = prepared.decision_event().clone();
    let applied = d
        .admin
        .apply(acknowledged(prepared), &mut txn, &now())
        .unwrap();
    txn.commit().unwrap();
    assert_eq!(
        applied.outcome_event().stage,
        DirAdminStage::Outcome(OutcomeResult::Committed { allocated: None })
    );
    Ok((decision, applied.reply().clone()))
}

fn refusal_code(r: &Refusal) -> AdminRefusal {
    match r.event().stage {
        DirAdminStage::Decision(DecisionResult::Refused(code)) => code,
        other => panic!("not a decision refusal: {other:?}"),
    }
}

fn principal(id: u32) -> PrincipalId {
    PrincipalId::from_bytes(guid(id).to_packet())
}

/// [MS-ADTS] 6.1.1.2.7.52: "rightsGuid: ab721a53-1e2f-11d0-9819-00aa0040529b",
/// mapped to the GUID members as A-31 decides (group 1 = Data1, 2 = Data2,
/// 3 = Data3, groups 4-5 = Data4 in order).
#[test]
fn the_right_is_user_change_password() {
    assert_eq!(
        USER_CHANGE_PASSWORD,
        Guid {
            data1: 0xab72_1a53,
            data2: 0x1e2f,
            data3: 0x11d0,
            data4: [0x98, 0x19, 0x00, 0xaa, 0x00, 0x40, 0x52, 0x9b],
        }
    );
    assert_ne!(
        USER_CHANGE_PASSWORD,
        directory_admin::USER_FORCE_CHANGE_PASSWORD
    );
}

/// docs/53 §4.3, §5.6 step 3: a Subject exists only for a request keyd judged
/// acceptable — every other verdict yields no ticket (dird seals the
/// verdict's own code instead, Q-663 item 2).
#[test]
fn only_an_acceptable_context_gives_a_ticket() {
    for verdict in [
        ChangePasswordVerdict::Malformed,
        ChangePasswordVerdict::InitialFlagNeeded,
        ChangePasswordVerdict::SetNotSupported,
        ChangePasswordVerdict::PasswordRefused,
    ] {
        assert!(
            ChangePasswordTicket::from_context(&context("alice", authtime(), verdict)).is_none(),
            "{verdict:?}"
        );
    }
    let ticket = ChangePasswordTicket::from_context(&context(
        "alice",
        authtime(),
        ChangePasswordVerdict::Acceptable,
    ))
    .unwrap();
    assert_eq!(ticket.cname().name_string[0].as_str(), "alice");
    assert_eq!(ticket.crealm(), &realm());
    assert_eq!(ticket.authtime(), &authtime());
}

/// docs/53 §4.4, §5.6 steps 4-5; [MS-ADTS] 3.1.1.3.1.5.1; docs/47 §9.1-§9.2:
/// alice (a user in a Tier2 location) changes her own password: the PDP
/// allows User-Change-Password on her own object (PRINCIPAL_SELF), the write
/// is `pwdLastSet = now` through the same `apply`, and the reply names her
/// one key set — `(objectGUID, PrincipalLongterm)` bound to NT-PRINCIPAL
/// ["alice"] with the user salt — as a `PasswordChange` (never a
/// `PasswordSet`: the decision dird registers names its executor, Q-662).
/// The decision event: operation `ChangePassword`, target and requester her
/// own account, the PDP's Allow, no operation digest (Q-963 item 3).
#[test]
fn a_user_changes_its_own_password() {
    let mut d = self_change_domain("cp-own", Some(Tier::Tier2));
    let request = change(&d, "alice");
    let (event, reply) = run(&mut d, &request).unwrap();
    let Reply::PasswordChange(target) = reply else {
        panic!("{reply:?}");
    };
    assert_eq!(
        target.key.handle,
        KeyHandle::new(principal(ALICE), KeyPurpose::PrincipalLongterm)
    );
    assert_eq!(target.key.binding.realm, realm());
    assert_eq!(target.key.binding.name.name_type, KRB_NT_PRINCIPAL);
    assert_eq!(target.key.binding.name.name_string[0].as_str(), "alice");
    assert_eq!(target.salt.as_str(), "EXAMPLE.TESTalice");
    assert_eq!(event.operation, DirAdminOperation::ChangePassword);
    assert_eq!(
        event.stage,
        DirAdminStage::Decision(DecisionResult::Proceed)
    );
    assert_eq!(event.target, Some(guid(ALICE).to_packet()));
    assert_eq!(
        event.requester,
        ipc_audit::SidValue::new(
            sid_of(ALICE).identifier_authority(),
            sid_of(ALICE).sub_authority().to_vec()
        )
    );
    assert_eq!(event.pdp.unwrap().code, PdpReasonCode::Allowed);
    assert_eq!(&event.operation_digest, NO_OPERATION_DIGEST.as_bytes());
    let obj = d.object(guid(ALICE)).unwrap();
    assert_eq!(
        obj.attribute(d.attr("pwdLastSet")).unwrap().values[0].value,
        int64(NOW_FILETIME)
    );
}

/// docs/53 §5.6 step 4, R53-9; docs/47 §4.5 (R47-7): the change moves
/// `pwdLastSet` to now, so the ticket that made it — first authenticated
/// before now — is on the hot-list: a second change with it is refused
/// (`Unauthenticated` ⇒ AUTHERROR). One INITIAL ticket, at most one change.
#[test]
fn the_ticket_of_a_change_is_revoked_by_it() {
    let mut d = self_change_domain("cp-revoked", Some(Tier::Tier2));
    let first = change(&d, "alice");
    run(&mut d, &first).unwrap();
    let again = change(&d, "alice");
    let r = run(&mut d, &again).unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::Unauthenticated);
    assert_eq!(change_password_result(&r), NonZeroResultCode::AuthError);
}

/// [MS-ADTS] 3.1.1.3.1.5.1 ("on itself"): the right comes from the object's
/// own ACL — without the PRINCIPAL_SELF ACE the change is the PDP's Deny
/// (layer 5, `Acl`); without the coarse rule it is `NoGrant` (layer 3).
/// Both ⇒ ACCESSDENIED (docs/53 §5.7), nothing written.
#[test]
fn the_right_on_itself_is_required() {
    for (extra, reason) in [
        (
            Extra {
                self_ace: false,
                self_rule: true,
                staff_tier: Some(Tier::Tier2),
            },
            PdpReasonCode::Acl,
        ),
        (
            Extra {
                self_ace: true,
                self_rule: false,
                staff_tier: Some(Tier::Tier2),
            },
            PdpReasonCode::NoGrant,
        ),
    ] {
        let mut d = Domain::with_extra("cp-right", extra);
        let before = d.object(guid(ALICE)).unwrap();
        let request = change(&d, "alice");
        let r = run(&mut d, &request).unwrap_err();
        assert_eq!(refusal_code(&r), AdminRefusal::PolicyDenied);
        assert_eq!(r.event().pdp.unwrap().code, reason);
        assert_eq!(change_password_result(&r), NonZeroResultCode::AccessDenied);
        assert_eq!(d.object(guid(ALICE)).unwrap(), before);
    }
}

/// docs/53 R53-1, §5.6 step 4 ("a user account only — computer ⇒ refused"):
/// a computer's change through kpasswd is refused (`TargetProtected` ⇒
/// ACCESSDENIED) before the PDP is asked.
#[test]
fn a_computer_is_refused() {
    let mut d = self_change_domain("cp-computer", Some(Tier::Tier2));
    let before = d.object(guid(WS01)).unwrap();
    let request = change(&d, "ws01$");
    let r = run(&mut d, &request).unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::TargetProtected);
    assert_eq!(change_password_result(&r), NonZeroResultCode::AccessDenied);
    assert_eq!(r.event().pdp, None, "refused before the PDP");
    assert_eq!(d.object(guid(WS01)).unwrap(), before);
}

/// P-22 ("password … of a Tier0 account" needs dual control); Q-608 item 1
/// (owner-open — the strict default): admin1, a Tier0 account, passes the
/// PDP for its own object but is refused (`ApprovalRequired` ⇒
/// ACCESSDENIED): kpasswd carries one AP-REQ and has no place for an
/// approver.
#[test]
fn a_tier0_account_is_refused() {
    let mut d = self_change_domain("cp-tier0", Some(Tier::Tier2));
    let before = d.object(guid(ADMIN1)).unwrap();
    let request = change(&d, "admin1");
    let r = run(&mut d, &request).unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::ApprovalRequired);
    assert_eq!(r.event().pdp.unwrap().code, PdpReasonCode::Allowed);
    assert_eq!(change_password_result(&r), NonZeroResultCode::AccessDenied);
    assert_eq!(d.object(guid(ADMIN1)).unwrap(), before);
}

/// Q-608 item 2 (no exception to the tier rule) and A-36 (an unclassified
/// object is Tier0 for writes): alice in an unclassified location is denied
/// by layer 4 (`TierViolation`) — the recorded consequence: users in
/// unclassified locations cannot use kpasswd until they are classified.
#[test]
fn an_unclassified_user_meets_the_tier_rule() {
    let mut d = self_change_domain("cp-unclassified", None);
    let request = change(&d, "alice");
    let r = run(&mut d, &request).unwrap_err();
    assert_eq!(refusal_code(&r), AdminRefusal::PolicyDenied);
    assert_eq!(r.event().pdp.unwrap().code, PdpReasonCode::TierViolation);
    assert_eq!(change_password_result(&r), NonZeroResultCode::AccessDenied);
}

/// docs/53 §5.6 step 4, §5.7 ("unusable account / hot-listed ticket /
/// `ticket_age` over the threshold ⇒ 3"); docs/51 §5.3, §5.5 (R51-10, the
/// admin channel's threshold — one rule): a disabled account, a name with no
/// account, a ticket first authenticated before the last password set, and
/// a ticket older than the threshold are AUTHERROR.
#[test]
fn unusable_accounts_and_stale_tickets_are_autherror() {
    let mut d = self_change_domain("cp-auth", Some(Tier::Tier2));
    let cases = [
        (change(&d, "disabled"), AdminRefusal::Unauthenticated),
        (change(&d, "nobody"), AdminRefusal::Unauthenticated),
        // Before the provisioning's pwdLastSet (2026-11-01T00:00:00Z).
        (
            change_at(&d, "alice", kt(2026, 10, 31, 23, 59, 59)),
            AdminRefusal::Unauthenticated,
        ),
        // 601 s before `now` (2026-11-13T10:00:00Z): over the 600 s
        // threshold.
        (
            change_at(&d, "alice", kt(2026, 11, 13, 9, 49, 59)),
            AdminRefusal::TicketAge,
        ),
    ];
    for (request, expected) in cases {
        let r = run(&mut d, &request).unwrap_err();
        assert_eq!(refusal_code(&r), expected, "{request:?}");
        assert_eq!(change_password_result(&r), NonZeroResultCode::AuthError);
    }
    // At the threshold it is accepted (600 s before now).
    let request = change_at(&d, "alice", kt(2026, 11, 13, 9, 50, 0));
    assert!(run(&mut d, &request).is_ok());
}

/// docs/53 §5.7 ("audit / write / decision registration failed ⇒ 2"): a
/// failure before any decision is HARDERROR; the admin plane's
/// `BeginPasswordSet` keeps its own reply (`PasswordSet`), so one write path
/// yields two reply types (docs/53 §4.4; Q-662).
#[test]
fn failures_are_harderror_and_the_replies_stay_apart() {
    let d = self_change_domain("cp-fail", Some(Tier::Tier2));
    let failed = d
        .admin
        .refuse_failed_change_password(7, AdminFailure::ViewUnavailable, &now());
    assert_eq!(
        failed.event().stage,
        DirAdminStage::Decision(DecisionResult::Failed(AdminFailure::ViewUnavailable))
    );
    assert_eq!(failed.event().operation, DirAdminOperation::ChangePassword);
    assert_eq!(
        change_password_result(&failed),
        NonZeroResultCode::HardError
    );

    let mut d = self_change_domain("cp-apart", Some(Tier::Tier2));
    let (_, applied) = d
        .run(
            Operation::BeginPasswordSet {
                target: guid(ALICE),
            },
            "admin1",
            &[],
        )
        .applied();
    assert!(matches!(applied.reply(), Reply::PasswordSet(_)));
}
