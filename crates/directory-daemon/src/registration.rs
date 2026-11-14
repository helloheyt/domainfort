//! The decisions dird registers in keyd — each built only from its evidence
//! (docs/52 §3.11 R6, §4.3; decision A-102).
//!
//! # The class (docs/52 §3.11 C11, §3.1 C1)
//!
//! A registration loosens keyd (keyd will then run, for keyadm or admind, a
//! change it would otherwise refuse). The rule was that dird registers only
//! what its PDP decided **and** auditd durably recorded (A-85; Q-453 item 1)
//! — a comment in the code path, with `TicketVerifier::register_decision`
//! taking free parameters.
//!
//! # The root-level change
//!
//! [`TicketVerifier::register_decision`](crate::TicketVerifier::register_decision)
//! takes a [`DecisionRegistration`], and a `DecisionRegistration` has no
//! public constructor: it is made inside this crate, only from
//!
//! * an `ipc_audit::AckedIntent<directory_admin::QuorumStep>` — the `Approve`
//!   that completed a key request's quorum, whose `Decision` event auditd
//!   acknowledged ([`DecisionRegistration::of_quorum`]);
//! * a `directory_admin::Applied` of a `BeginPasswordSet` — made only by
//!   `DirectoryAdmin::apply`, which takes the write's `AckedIntent`
//!   ([`DecisionRegistration::of_password_set`]);
//! * a `directory_admin::TombstonedPrincipal` — a tombstone of the `user`
//!   class in dird's store, which exists only because a `Delete` committed
//!   after its decision event was acknowledged; durable, so it also serves
//!   the re-registration of destroy decisions keyd lost (A-105,
//!   [`DecisionRegistration::of_tombstone`], crate::reconcile).
//!
//! So dird cannot register a decision whose deciding event auditd has not
//! acknowledged, and cannot register the destruction of a live account.
//!
//! # The id of a destroy decision
//!
//! [`destroy_decision_id`]: the objectGUID's two 8-octet halves XORed —
//! the same id for the same tombstone at the `Delete` and at every
//! re-registration, so keyd accepts a re-registration of a decision it holds
//! unchanged (A-105; keyd keeps an executed decision's result until it
//! expires, docs/52 §3.10 (a)) and dird can tell "keyd ran it" from "keyd
//! lost it" (crate::reconcile; docs/questions/Q-501). Before task R6 it was
//! the `Delete`'s operation id, which a re-registration cannot know.
//!
//! Spec: docs/52 §3.1, §3.10, §3.11 R6 (a), §4.2, §4.3; docs/51 §5.6, §5.7
//! item 2, §5.8 option (b), §6, §9; A-85; A-102; A-105; docs/questions/
//! Q-453 item 1, Q-460, Q-470, Q-500, Q-501.

use crate::admin_service::{secret_decision_of, SET_SECRET_GRANT_LIFETIME_SECS};
use directory_admin::{Applied, QuorumStep, TombstonedPrincipal};
use dtyp::Guid;
use ipc_audit::AckedIntent;
use keyd_types::{DecidedOperation, DecisionId, PrincipalId, MAX_DESTROY_DECISION_SECS};

/// The id of the destroy decision of the tombstone `guid`: the XOR of its objectGUID's
/// two 8-octet halves (packet form, big-endian) — stable across dird's runs
/// (module documentation). Two tombstones share an id only if their GUIDs'
/// halves XOR alike; the second registration is then refused by keyd
/// (`DecisionConflict`) and its key sets stay unreachable (docs/51 §9).
/// Project choice (docs/questions/Q-501).
/// Spec: docs/52 §4.2 (`DecisionId(u64)`, dird's to assign), §4.3; A-105.
#[must_use]
pub fn destroy_decision_id(guid: Guid) -> DecisionId {
    let packet = guid.to_packet();
    let (high, low) = packet.split_at(packet.len() / 2);
    // A GUID packet is 16 octets: both halves are 8 (the defaults are never
    // taken).
    let high = <[u8; 8]>::try_from(high).unwrap_or_default();
    let low = <[u8; 8]>::try_from(low).unwrap_or_default();
    DecisionId::new(u64::from_be_bytes(high) ^ u64::from_be_bytes(low))
}

/// A decision dird registers in keyd (`register_decision`, Role::Ldap):
/// built only from its evidence (module documentation). Not `Clone`.
/// Spec: docs/52 §4.2 (`register_decision(id, op, approvers,
/// lifetime_secs)`), §4.3, §3.11 R6 (a).
#[derive(Debug, PartialEq, Eq)]
pub struct DecisionRegistration {
    id: DecisionId,
    operation: DecidedOperation,
    approvers: Vec<PrincipalId>,
    lifetime_secs: u32,
}

impl DecisionRegistration {
    /// The key-operation decision of the `Approve` that completed its
    /// request's quorum, whose `Decision` event auditd acknowledged; the
    /// step back, for its registration's `Outcome` event and its reply.
    /// Spec: docs/52 §4.3 (the key-operation rows); docs/51 §5.6, §5.7 item
    /// 2; A-85; docs/questions/Q-453 item 1.
    pub(crate) fn of_quorum(acked: AckedIntent<QuorumStep>) -> (DecisionRegistration, QuorumStep) {
        let step = acked.into_inner();
        let decision = step.decision();
        let registration = DecisionRegistration {
            id: decision.id,
            operation: decision.operation.clone(),
            approvers: decision.approvers.clone(),
            lifetime_secs: decision.lifetime_secs,
        };
        (registration, step)
    }

    /// The set-secret decision of a committed `BeginPasswordSet` (decision
    /// `id`, its operation id): exactly the key targets and salt its reply
    /// hands admind, live [`SET_SECRET_GRANT_LIFETIME_SECS`]; `None` for any
    /// other write.
    /// Spec: docs/51 §5.8 option (b); docs/52 §4.2 (+ salt, N4), §4.3;
    /// docs/questions/Q-450 item 2, Q-453 item 1.
    pub(crate) fn of_password_set(
        id: DecisionId,
        applied: &Applied,
    ) -> Option<DecisionRegistration> {
        secret_decision_of(applied.reply()).map(|operation| DecisionRegistration {
            id,
            operation,
            approvers: Vec::new(),
            lifetime_secs: SET_SECRET_GRANT_LIFETIME_SECS,
        })
    }

    /// The destroy decision of a tombstoned user or computer
    /// ([`destroy_decision_id`]), live `keyd_types::MAX_DESTROY_DECISION_SECS`,
    /// no approvers (the decision is the `Delete`).
    /// Spec: docs/52 §4.3 (the `destroy_key_set` row); docs/51 §6, §9;
    /// docs/questions/Q-470 (A-105).
    pub(crate) fn of_tombstone(target: &TombstonedPrincipal) -> DecisionRegistration {
        DecisionRegistration {
            id: destroy_decision_id(target.guid()),
            operation: DecidedOperation::DestroyKeySet {
                principal: target.principal(),
            },
            approvers: Vec::new(),
            lifetime_secs: MAX_DESTROY_DECISION_SECS,
        }
    }

    /// The decision id.
    #[must_use]
    pub fn id(&self) -> DecisionId {
        self.id
    }

    /// The decided operation.
    #[must_use]
    pub fn operation(&self) -> &DecidedOperation {
        &self.operation
    }

    /// The approvers (dird verified each one's AP-REQ and PDP decision).
    #[must_use]
    pub fn approvers(&self) -> &[PrincipalId] {
        &self.approvers
    }

    /// The lifetime in seconds, by keyd's clock.
    #[must_use]
    pub fn lifetime_secs(&self) -> u32 {
        self.lifetime_secs
    }
}
