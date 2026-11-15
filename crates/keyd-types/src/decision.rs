//! The vocabulary of keyd's **decision table** and of its **ceremony
//! state** (docs/52 R1, R3; decision A-102).
//!
//! # Why (docs/52 §3.1, class C1)
//!
//! The component that owns a decision is dird: it verifies the
//! administrators' AP-REQs, builds the Subject and asks the PDP (docs/51
//! §5.3 option D; A-72/A-73). Before A-102 only `set_secret` waited for
//! dird (A-100's grant); keyd ran Role::Admin's rotations, retirement and
//! destruction on keyadm's word, and keyadm took the "approved" operation
//! and the tombstone list from admind unverified (N2) — so a holder of the
//! keyadm and admind uids could destroy a live account's key set and then
//! grant and set its "initial" secret (N1). The root change: **keyd performs
//! no Directory or Admin state change without a one-time, operation-bound
//! decision that dird (Role::Ldap) registered**, and it runs exactly the
//! registered parameters — never the caller's. The decision table
//! generalizes A-100's grant table.
//!
//! # The families
//!
//! | family | decided operation | named by | registered by dird | consumed by |
//! |---|---|---|---|---|
//! | set-secret | [`DecidedOperation::SetSecret`]: the targets (handle, binding, salt) | the handle (admind's `set_secret` names no id) | after `BeginPasswordSet` committed (A-100) | the next `set_secret` of the handle (any presentation) |
//! | set-secret | [`DecidedOperation::ChangePassword`] (task K3): the one target (handle, binding, salt) — a user's own password change through kpasswd | the handle | after `ChangePassword` committed (docs/53 §5.6, the same order as A-100) | the next `complete_change_password` of the handle whose request's ticket client the binding identifies (any presentation) — **never** a `set_secret`, and a `SetSecret` decision is never redeemed by a completion (docs/questions/Q-662) |
//! | key operation | `RotateKrbtgt`, `RotateKey`, `RetireKvno` | the decision id (= dird's request id) | at the `Approve` that completes the quorum | `rotate_krbtgt(id)` / `rotate_key(id)` / `retire_kvno(id)`; the result is kept |
//! | destroy | `DestroyKeySet { principal }` (both purposes) | the decision id (= dird's operation id of the `Delete`) | after a `Delete` of a user / computer committed | `destroy_key_set(id)`; the result is kept |
//!
//! Each family has its own id space, bound and lifetime ceiling, so that a
//! flood in one (e.g. many deletions) cannot starve another (a password
//! set), and so that dird's separate counters (key requests, admin
//! operations) never collide inside keyd.
//!
//! A key-operation or destroy decision, once executed, keeps its **result**
//! until it expires: presenting the id again returns the recorded result
//! (docs/52 §3.10 (a), C10: "outcome unknown" becomes "ask again"), never a
//! second execution.
//!
//! # The approvers
//!
//! dird verified every approver's AP-REQ and PDP decision; keyd records
//! them from the decision and builds the dual-control token of
//! `rotate_krbtgt` **inside keyd** from them — the token is no longer a
//! wire field, so a fabricated token is unrepresentable (docs/52 §4.2). A
//! key operation needs at least [`MIN_KEY_DECISION_APPROVERS`] distinct
//! approvers (the requester and one other, docs/51 §5.6, P-22).
//!
//! # The ceremony state (R3)
//!
//! keyd starts in [`CeremonyState::Provisioning`] only when its key store
//! is empty; there, and only there, Role::Admin's `create_key` and
//! `grant_set_secret` exist (`authz::provisioning_only`). `seal_ceremony`
//! moves it to [`CeremonyState::Operational`] for good (until the next
//! start of a keyd with an empty store — in development mode every start,
//! P-17 / A-77: a documented residual).
//!
//! Spec: docs/52 §3.1, §3.3, §3.4, §3.10, §4, §7 R1, R3; docs/51 §4.3, §5.6,
//! §5.8, §6, §9; docs/10 §2, §6, §6א, §7; docs/questions/Q-460, Q-461,
//! Q-462 item 1 (A-102), Q-421 item 2 (the request lifetime), Q-450, Q-451.

use crate::authz::{purpose_permitted, HandleSlot, Operation};
use crate::grant::{
    AccountKind, SetSecretTarget, MAX_GRANT_TARGETS, MAX_SET_SECRET_GRANTS,
    MAX_SET_SECRET_GRANT_SECS,
};
use crate::model::{KeyHandle, KeyPurpose, Kvno, PrincipalId};

/// The identifier dird gives a decision: its key-request id for a key
/// operation (unique across dird's runs, docs/questions/Q-421 item 3), its
/// admin operation id for a set-secret or destroy decision. Not secret.
/// Spec: docs/52 §4.2 (`DecisionId(u64)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DecisionId(u64);

impl DecisionId {
    /// Wrap an identifier. Spec: docs/52 §4.2.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        DecisionId(id)
    }

    /// The identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// What dird decided: the closed set of state changes keyd performs for
/// Role::Directory and Role::Admin (docs/52 §4.2).
/// Spec: docs/52 §4.2 (`DecidedOperation`), §4.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecidedOperation {
    /// admind's `set_secret` on each target (1 for a user; 1 or 2 for a
    /// computer, the second its `Service` key set), with exactly the target's
    /// binding and salt (A-100's grant, plus the salt — N4).
    SetSecret {
        /// The account kind.
        kind: AccountKind,
        /// The key targets.
        targets: Vec<SetSecretTarget>,
    },
    /// Rotate the krbtgt key set under dual control (docs/10 §7).
    RotateKrbtgt {
        /// The krbtgt handle.
        krbtgt: KeyHandle,
    },
    /// Rotate a key set (a service object's randomized `Service` key set,
    /// docs/51 §6).
    RotateKey {
        /// The key set.
        handle: KeyHandle,
    },
    /// Retire the retained previous kvno of a key set (docs/33 §5).
    RetireKvno {
        /// The key set.
        handle: KeyHandle,
        /// The key version to retire (never 0).
        kvno: Kvno,
    },
    /// Destroy every key set of a deleted account — its `PrincipalLongterm`
    /// and its `Service` key set, whichever exist (docs/51 §6, §9; A-35).
    DestroyKeySet {
        /// The deleted account's principal id (its objectGUID).
        principal: PrincipalId,
    },
    /// A user's own password change through kpasswd (task K3): keyd's
    /// `complete_change_password` installs the password of the request
    /// context — keyd decrypted it from the client's KRB-PRIV — into
    /// `target`, with exactly the target's binding and salt, **only** when
    /// that binding identifies the request ticket's client (keyd binds the
    /// target, docs/53 §5.5). The set-secret family (same table, ceiling and
    /// bound), but a separate variant so that the decision names its
    /// executor: admind's `set_secret` cannot redeem it, and a completion
    /// cannot redeem a `SetSecret` decision (docs/questions/Q-662).
    /// Spec: docs/53 R53-5, R53-8, §4.3, §4.4, §5.5, §5.6 step 5; [MS-ADTS]
    /// 3.1.1.3.1.5.1 (as recorded in docs/53 §2.2); docs/questions/Q-601
    /// items 2, 5 (A-117).
    ChangePassword {
        /// The user's password key set (`PrincipalLongterm`), its binding
        /// and its salt.
        target: SetSecretTarget,
    },
}

/// The families of decisions (module documentation): each has its own id
/// space, bound and lifetime ceiling.
/// Spec: docs/52 §4.2, §4.3; docs/questions/Q-460 (parameters).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionFamily {
    /// `SetSecret`.
    SetSecret,
    /// `RotateKrbtgt`, `RotateKey`, `RetireKvno`.
    KeyOperation,
    /// `DestroyKeySet`.
    Destroy,
}

impl DecisionFamily {
    /// The longest lifetime, in seconds, a decision of this family may be
    /// registered for.
    /// Spec: docs/questions/Q-450 item 3 (30 s), Q-421 item 2 / Q-460 (a
    /// key decision lives no longer than dird's request may: at most
    /// [`MAX_KEY_DECISION_SECS`]); [`MAX_DESTROY_DECISION_SECS`].
    #[must_use]
    pub const fn max_lifetime_secs(self) -> u32 {
        match self {
            DecisionFamily::SetSecret => MAX_SET_SECRET_GRANT_SECS,
            DecisionFamily::KeyOperation => MAX_KEY_DECISION_SECS,
            DecisionFamily::Destroy => MAX_DESTROY_DECISION_SECS,
        }
    }

    /// The fewest distinct approvers a decision of this family names: the
    /// requester and one other for a key operation (dual control); none for
    /// a set-secret or destroy decision (dird's PDP decision on the
    /// `BeginPasswordSet` / `Delete` is the authority; approvers it records
    /// are kept for audit).
    /// Spec: docs/51 §5.6 (R51-11); docs/52 §4.3 ("approvers" column).
    #[must_use]
    pub const fn min_approvers(self) -> usize {
        match self {
            DecisionFamily::KeyOperation => MIN_KEY_DECISION_APPROVERS,
            DecisionFamily::SetSecret | DecisionFamily::Destroy => 0,
        }
    }

    /// How many entries keyd holds at once for this family (key targets for
    /// a set-secret decision). A full family refuses a new decision (fail
    /// closed), never evicting a live one.
    /// Spec: docs/questions/Q-450 item 4; [`MAX_KEY_DECISIONS`],
    /// [`MAX_DESTROY_DECISIONS`]; AGENTS.md §6 (bounded).
    #[must_use]
    pub const fn capacity(self) -> usize {
        match self {
            DecisionFamily::SetSecret => MAX_SET_SECRET_GRANTS,
            DecisionFamily::KeyOperation => MAX_KEY_DECISIONS,
            DecisionFamily::Destroy => MAX_DESTROY_DECISIONS,
        }
    }
}

impl DecidedOperation {
    /// The operation that runs this decision.
    /// Spec: docs/52 §4.2.
    #[must_use]
    pub const fn executed_by(&self) -> Operation {
        match self {
            DecidedOperation::SetSecret { .. } => Operation::SetSecret,
            DecidedOperation::ChangePassword { .. } => Operation::CompleteChangePassword,
            DecidedOperation::RotateKrbtgt { .. } => Operation::RotateKrbtgt,
            DecidedOperation::RotateKey { .. } => Operation::RotateKey,
            DecidedOperation::RetireKvno { .. } => Operation::RetireKvno,
            DecidedOperation::DestroyKeySet { .. } => Operation::DestroyKeySet,
        }
    }

    /// The decision's family.
    /// Spec: module documentation.
    #[must_use]
    pub const fn family(&self) -> DecisionFamily {
        match self {
            DecidedOperation::SetSecret { .. } | DecidedOperation::ChangePassword { .. } => {
                DecisionFamily::SetSecret
            }
            DecidedOperation::RotateKrbtgt { .. }
            | DecidedOperation::RotateKey { .. }
            | DecidedOperation::RetireKvno { .. } => DecisionFamily::KeyOperation,
            DecidedOperation::DestroyKeySet { .. } => DecisionFamily::Destroy,
        }
    }

    /// The first key set the decision acts on (an audit record's
    /// principal / purpose): the first target, the rotated or retired key
    /// set, or the deleted account's `PrincipalLongterm` key set.
    /// Spec: docs/10 §10; docs/52 §4.5.
    #[must_use]
    pub fn primary(&self) -> Option<KeyHandle> {
        match self {
            DecidedOperation::SetSecret { targets, .. } => targets.first().map(|t| t.handle),
            DecidedOperation::ChangePassword { target } => Some(target.handle),
            DecidedOperation::RotateKrbtgt { krbtgt } => Some(*krbtgt),
            DecidedOperation::RotateKey { handle }
            | DecidedOperation::RetireKvno { handle, .. } => Some(*handle),
            DecidedOperation::DestroyKeySet { principal } => {
                Some(KeyHandle::new(*principal, KeyPurpose::PrincipalLongterm))
            }
        }
    }

    /// The second key set the decision acts on: a computer's `Service`
    /// target, or the deleted account's `Service` key set.
    /// Spec: docs/10 §10; docs/questions/Q-452 item 2.
    #[must_use]
    pub fn secondary(&self) -> Option<KeyHandle> {
        match self {
            DecidedOperation::SetSecret { targets, .. } => targets.get(1).map(|t| t.handle),
            DecidedOperation::DestroyKeySet { principal } => {
                Some(KeyHandle::new(*principal, KeyPurpose::Service))
            }
            DecidedOperation::RotateKrbtgt { .. }
            | DecidedOperation::RotateKey { .. }
            | DecidedOperation::RetireKvno { .. }
            | DecidedOperation::ChangePassword { .. } => None,
        }
    }

    /// The kvno the decision names (`RetireKvno`).
    #[must_use]
    pub const fn kvno(&self) -> Option<Kvno> {
        match self {
            DecidedOperation::RetireKvno { kvno, .. } => Some(*kvno),
            _ => None,
        }
    }

    /// Whether every key set the decision names has a purpose the operation
    /// that runs it accepts in that slot (I3): the set-secret targets as the
    /// grant's slots (first `PrincipalLongterm`, second `Service`); krbtgt
    /// for `RotateKrbtgt`; `rotate_key`'s and `retire_kvno`'s own table. A
    /// destroy decision names a principal (both purposes, never krbtgt).
    /// Spec: docs/10 §2 (I3); crate authz `purpose_permitted`.
    #[must_use]
    pub fn purposes_permitted(&self) -> bool {
        match self {
            DecidedOperation::SetSecret { targets, .. } => targets
                .iter()
                .zip([HandleSlot::Primary, HandleSlot::Secondary])
                .all(|(t, slot)| {
                    purpose_permitted(Operation::GrantSetSecret, slot, t.handle.purpose)
                }),
            DecidedOperation::RotateKrbtgt { krbtgt } => {
                purpose_permitted(Operation::RotateKrbtgt, HandleSlot::Primary, krbtgt.purpose)
            }
            DecidedOperation::RotateKey { handle } => {
                purpose_permitted(Operation::RotateKey, HandleSlot::Primary, handle.purpose)
            }
            DecidedOperation::RetireKvno { handle, .. } => {
                purpose_permitted(Operation::RetireKvno, HandleSlot::Primary, handle.purpose)
            }
            DecidedOperation::DestroyKeySet { .. } => true,
            // A user's password key set only (docs/53 R53-1).
            DecidedOperation::ChangePassword { target } => purpose_permitted(
                Operation::CompleteChangePassword,
                HandleSlot::Primary,
                target.handle.purpose,
            ),
        }
    }

    /// Whether the decision's own arguments are well formed: a set-secret
    /// decision has 1 to [`MAX_GRANT_TARGETS`] targets fitting its account
    /// kind (one for a user; one or two of the same principal for a
    /// computer); a kvno to retire is never 0.
    /// Spec: docs/47 §9.1; docs/51 §5.2 row 5, §7.3; docs/questions/Q-420
    /// item 4 (kvno 0), Q-450 item 2.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        match self {
            DecidedOperation::SetSecret { kind, targets } => {
                targets.len() <= MAX_GRANT_TARGETS && set_secret_shape_fits(*kind, targets)
            }
            DecidedOperation::RetireKvno { kvno, .. } => kvno.get() != 0,
            DecidedOperation::RotateKrbtgt { .. }
            | DecidedOperation::RotateKey { .. }
            | DecidedOperation::DestroyKeySet { .. }
            | DecidedOperation::ChangePassword { .. } => true,
        }
    }
}

/// The shape of a set-secret decision's (or grant's) targets for `kind`: one
/// target for a user; one or two for a computer, the second of the same
/// principal (the purposes — first `PrincipalLongterm`, second `Service` —
/// are [`DecidedOperation::purposes_permitted`]'s).
/// Spec: docs/47 §9.1; docs/51 §5.2 row 5, §7.3; docs/questions/Q-450
/// item 2.
#[must_use]
pub fn set_secret_shape_fits(kind: AccountKind, targets: &[SetSecretTarget]) -> bool {
    match (kind, targets) {
        (AccountKind::User, [_]) | (AccountKind::Computer, [_]) => true,
        (AccountKind::Computer, [first, second]) => {
            first.handle.principal == second.handle.principal
        }
        _ => false,
    }
}

/// Most approvers a decision names: the requester and at most two
/// approvals (dird's largest quorum, crates/directory-admin `MAX_QUORUM`,
/// from docs/51 §7.2 `approvals: seq<…, 2>`).
/// Spec: docs/51 §7.2; docs/52 §4.2 ("`Approvers` … ≤ 3").
pub const MAX_DECISION_APPROVERS: usize = 3;

/// The fewest distinct approvers of a key-operation decision: the
/// requester and one other (dual control; there is no single-administrator
/// mode — P-22 item 3).
/// Spec: docs/51 §5.6 (R51-11); docs/10 §7 (`rotate_krbtgt` "dual
/// approval"); docs/43 D175.
pub const MIN_KEY_DECISION_APPROVERS: usize = 2;

/// The longest lifetime of a key-operation decision: one hour — the
/// longest lifetime dird accepts for a pending request
/// (crates/directory-admin `MAX_KEY_REQUEST_LIFETIME`); dird registers its
/// configured request lifetime (default 15 minutes, Q-421 item 2), so a
/// decision lives no longer than the request it came from. Project choice
/// (docs/questions/Q-460 parameters).
pub const MAX_KEY_DECISION_SECS: u32 = 60 * 60;

/// The longest lifetime of a destroy decision: seven days. `destroy-sweep`
/// is run by hand "after deletions" (docs/51 §6, §9), not at the moment of
/// the `Delete`; until it runs, the deleted account's key set is
/// unreachable anyway (no object ⇒ no handle — docs/51 §9, fail closed), so
/// an expired destroy decision costs only hygiene, never safety. Project
/// choice ⚠ (docs/questions/Q-470).
pub const MAX_DESTROY_DECISION_SECS: u32 = 7 * 24 * 60 * 60;

/// How many key-operation decisions keyd holds: 16 — dird holds at most 16
/// pending requests (crates/directory-admin `MAX_PENDING_KEY_REQUESTS`).
/// Project choice (docs/questions/Q-460 parameters).
pub const MAX_KEY_DECISIONS: usize = 16;

/// How many destroy decisions keyd holds: 1024 (each is an id, a principal
/// id, an expiry and a result — under 64 octets). A full family refuses the
/// next destroy decision; dird then records that it was not registered and
/// the key set stays unreachable (fail closed). Project choice ⚠
/// (docs/questions/Q-470).
pub const MAX_DESTROY_DECISIONS: usize = 1024;

/// Most entries of one `list_destroy_decisions` page. Project choice (a
/// bounded reply — docs/50 §3.3).
pub const MAX_DESTROY_DECISION_PAGE: usize = 64;

/// What the daemon needs to record the **intent** of a decision's execution
/// before keyd runs it (A-86 / A-88): the decision id and the parameters
/// keyd will run — taken from keyd's table, never from the request
/// (docs/52 §4.5: the record carries the `DecisionId` and the approvers
/// from the decision).
/// Spec: docs/10 §10; docs/52 §4.5; docs/questions/Q-346 (A-86), Q-365.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionIntent {
    /// The decision.
    pub decision: DecisionId,
    /// The first key set it acts on.
    pub primary: Option<KeyHandle>,
    /// The second key set it acts on.
    pub secondary: Option<KeyHandle>,
    /// The kvno it names (`retire_kvno`).
    pub kvno: Option<Kvno>,
    /// The first two approvers (the dual-control pair), when it names two.
    pub approvers: Option<[PrincipalId; 2]>,
}

/// One pending destroy decision, as `list_destroy_decisions` shows it. Not
/// secret (a tombstone's objectGUID).
/// Spec: docs/52 §4.3, §4.6; docs/51 §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingDestruction {
    /// The decision id `destroy_key_set` takes.
    pub decision: DecisionId,
    /// The deleted account's principal id.
    pub principal: PrincipalId,
}

/// One page of pending destroy decisions, ascending by decision id.
/// Spec: docs/52 §4.6; docs/50 §3.3 (bounded replies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestructionPage {
    /// At most [`MAX_DESTROY_DECISION_PAGE`] entries.
    pub entries: Vec<PendingDestruction>,
    /// Where the next page starts (strictly after this id); `None` when
    /// complete.
    pub next: Option<DecisionId>,
}

/// keyd's ceremony state (R3; module documentation).
/// Spec: docs/52 §4.4, §7 R3; docs/questions/Q-462 item 1 (A-102).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CeremonyState {
    /// The key store was empty at start: the ceremony may draw keys
    /// (`create_key`) and grant the first administrators' initial secrets.
    Provisioning,
    /// The ceremony was sealed (or the store held keys at start): only
    /// decisions dird registered change state.
    Operational,
}

// The bounds agree with the values they come from (docs/52 §4.2; Q-460).
const _: () = {
    assert!(MAX_DECISION_APPROVERS >= MIN_KEY_DECISION_APPROVERS);
    assert!(MIN_KEY_DECISION_APPROVERS == 2);
    assert!(MAX_SET_SECRET_GRANT_SECS <= MAX_KEY_DECISION_SECS);
    assert!(MAX_KEY_DECISION_SECS <= MAX_DESTROY_DECISION_SECS);
    assert!(MAX_DESTROY_DECISION_PAGE <= MAX_DESTROY_DECISIONS);
    assert!(MAX_KEY_DECISIONS > 0 && MAX_DESTROY_DECISIONS > 0);
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PrincipalBinding;
    use krb_proto::{KerberosString, PrincipalName, Realm};

    fn target(byte: u8, purpose: KeyPurpose) -> SetSecretTarget {
        SetSecretTarget {
            handle: KeyHandle::new(PrincipalId::from_bytes([byte; 16]), purpose),
            binding: PrincipalBinding::new(
                Realm::new("EXAMPLE.ORG").unwrap(),
                PrincipalName {
                    name_type: 1,
                    name_string: vec![KerberosString::new("x").unwrap()],
                },
            ),
            salt: String::from("EXAMPLE.ORGx"),
        }
    }

    /// docs/47 §9.1; Q-450 item 2: the shapes keyd accepts.
    #[test]
    fn the_set_secret_shape_follows_the_account_kind() {
        let pl = target(1, KeyPurpose::PrincipalLongterm);
        let svc = target(1, KeyPurpose::Service);
        let other_svc = target(2, KeyPurpose::Service);
        assert!(set_secret_shape_fits(
            AccountKind::User,
            std::slice::from_ref(&pl)
        ));
        assert!(!set_secret_shape_fits(
            AccountKind::User,
            &[pl.clone(), svc.clone()]
        ));
        assert!(!set_secret_shape_fits(AccountKind::User, &[]));
        assert!(set_secret_shape_fits(
            AccountKind::Computer,
            &[pl.clone(), svc.clone()]
        ));
        assert!(!set_secret_shape_fits(
            AccountKind::Computer,
            &[pl.clone(), other_svc]
        ));
        assert!(!set_secret_shape_fits(AccountKind::Computer, &[]));
    }

    /// docs/10 §2 (I3), docs/52 §4.2: the decided handles' purposes are the
    /// executing operation's; a kvno 0 is never retired (Q-420 item 4).
    #[test]
    fn purposes_and_forms_follow_the_executing_operation() {
        let p = PrincipalId::from_bytes([7; 16]);
        let krbtgt = KeyHandle::new(p, KeyPurpose::Krbtgt);
        let service = KeyHandle::new(p, KeyPurpose::Service);
        assert!(DecidedOperation::RotateKrbtgt { krbtgt }.purposes_permitted());
        assert!(!DecidedOperation::RotateKrbtgt { krbtgt: service }.purposes_permitted());
        assert!(!DecidedOperation::RotateKey { handle: krbtgt }.purposes_permitted());
        assert!(DecidedOperation::RotateKey { handle: service }.purposes_permitted());
        assert!(!DecidedOperation::RetireKvno {
            handle: krbtgt,
            kvno: Kvno::new(0)
        }
        .is_well_formed());
        let wrong_first = DecidedOperation::SetSecret {
            kind: AccountKind::User,
            targets: vec![target(1, KeyPurpose::Service)],
        };
        assert!(!wrong_first.purposes_permitted());
        // Task K3 (Q-662): a user's own change is the set-secret family,
        // run by the completion, on a PrincipalLongterm target only.
        let change = DecidedOperation::ChangePassword {
            target: target(1, KeyPurpose::PrincipalLongterm),
        };
        assert_eq!(change.family(), DecisionFamily::SetSecret);
        assert_eq!(change.executed_by(), Operation::CompleteChangePassword);
        assert!(change.purposes_permitted() && change.is_well_formed());
        assert_eq!(
            change.primary(),
            Some(KeyHandle::new(
                PrincipalId::from_bytes([1; 16]),
                KeyPurpose::PrincipalLongterm
            ))
        );
        assert_eq!(change.secondary(), None);
        for purpose in [
            KeyPurpose::Service,
            KeyPurpose::Krbtgt,
            KeyPurpose::AdminService,
            KeyPurpose::ChangePasswordService,
        ] {
            assert!(!DecidedOperation::ChangePassword {
                target: target(1, purpose)
            }
            .purposes_permitted());
        }
        let destroy = DecidedOperation::DestroyKeySet { principal: p };
        assert_eq!(destroy.family(), DecisionFamily::Destroy);
        assert_eq!(
            destroy.primary(),
            Some(KeyHandle::new(p, KeyPurpose::PrincipalLongterm))
        );
        assert_eq!(destroy.secondary(), Some(service));
        assert_eq!(destroy.executed_by(), Operation::DestroyKeySet);
    }
}
