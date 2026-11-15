//! keyd's **decision table** (docs/52 R1) and its **ceremony state**
//! (docs/52 R3): decision A-102.
//!
//! # The rule (docs/52 §3.1, §4.2)
//!
//! keyd performs **no** state change for Role::Directory or Role::Admin
//! without a one-time, operation-bound decision that dird — Role::Ldap, the
//! PDP that owns the decision — registered ([`Keyd::register_decision`]).
//! keyd judges no policy: it compares the call with the decision and runs
//! **exactly** the registered parameters. The only exceptions are the
//! provisioning ceremony's `create_key` and initial-secret grants
//! ([`Keyd::grant_set_secret`]), which exist only while keyd is in
//! [`CeremonyState::Provisioning`] — until [`Keyd::seal_ceremony`].
//! `keyd_types::authz` pins at compile time that every operation Directory
//! or Admin may call is one of these (or `ping`, the seal, the destroy
//! listing), and crate state_change.rs pins it against the key-state
//! classification.
//!
//! # The table
//!
//! Three families, each in memory, bounded, with its own id space and
//! lifetime ceiling (`keyd_types::decision::DecisionFamily`):
//!
//! * **set-secret** — one entry per key target, keyed by handle (admind's
//!   `set_secret` names no id), at most one per handle (a newer decision or
//!   grant replaces it). Consumed by the next `set_secret` of the handle,
//!   whatever it decides (one attempt). Binding **and salt** must equal the
//!   call's (N4). An entry from the ceremony's grant (no decision id) also
//!   requires that the key set still does not exist (an initial secret).
//! * **key operation** (`RotateKrbtgt`, `RotateKey`, `RetireKvno`) and
//!   **destroy** (`DestroyKeySet`) — keyed by decision id. The executing
//!   operation names the id; a decision of another kind is refused and kept
//!   (`DecisionMismatch`). The first presentation consumes it and runs it;
//!   its result is **kept until the decision expires**, and a later
//!   presentation returns that result without running anything
//!   (`DecisionReplayed` — docs/52 §3.10 (a)).
//!
//! Expired entries are swept on every registration and every lookup. A full
//! family refuses the next registration (`Unavailable`), never evicting a
//! live entry. The table is lost at every start — which only makes keyd
//! stricter, so nothing is held after a start; dird re-registers on demand
//! (docs/52 §4.3, §4.4).
//!
//! # Destroy decisions and the key store (R6b)
//!
//! **A destroy registration is dird's statement that the principal is
//! deleted** (it registers one only after the `Delete` committed, or for a
//! tombstone). So, before anything else is decided about it, it discards
//! every live set-secret entry for the principal's two handles
//! (`PrincipalLongterm`, `Service`) — a dird decision or the ceremony's grant
//! — and records one `SecretDecisionDiscarded` record per entry discarded
//! (after the registration's own record). Without that, a password set begun
//! before the `Delete` (its decision live for 30 s) could still create a key
//! set for the deleted principal after the registration read "no key set ⇒
//! complete". The discard happens on a refused registration too: it is the
//! effect of the `Delete` decision, not of the destroy table. Afterwards no
//! key set can come to exist for the principal: `set_secret` needs a live
//! set-secret entry (none is left; dird registers new ones only for live
//! objects), `create_key` and Admin's grants exist only before the seal
//! (`authz::provisioning_only`), and the key-operation decisions (`rotate_*`,
//! `retire_kvno`) act only on an existing key set (`KeyNotFound`).
//!
//! A `DestroyKeySet` decision is registered only for a principal that still
//! has a key set it would destroy (its `PrincipalLongterm` or `Service` key
//! set); for any other principal the registration is the uniform `Denied`,
//! reason `KeyNotFound`, in its one record (after the intent, A-88), and it
//! takes no table slot. So "this principal's destruction is complete" is
//! read from keyd's **key store** — which survives a keyd start once it is
//! persistent (P-17) — and not from the decision table (memory only, an
//! executed entry kept 7 days at most): dird's re-registration of a
//! tombstone keyd already destroyed is refused, and nothing is scheduled
//! (docs/questions/Q-501 decision; Q-520).
//!
//! **The order of the two checks:** the key-store check comes **before** the
//! table. A principal without a key set is refused whatever the table holds
//! — also when it holds an identical decision (an executed one, kept for its
//! replay): the answer depends on the store alone, the one durable source.
//! While a key set exists, an identical live registration is still accepted
//! unchanged (Q-471 item 5), which is the case in which a retry after an
//! unknown outcome has anything left to do; without one, the retry's refusal
//! is just as harmless — nothing is left to destroy.
//!
//! # Audit
//!
//! A registration loosens keyd, so it takes the daemon's intent path (A-88,
//! [`crate::loosens_authorization`]); an execution changes key state
//! ([`crate::changes_key_state`]). Each record carries the decision id and
//! the decision's first two approvers (docs/52 §4.5). An execution refused
//! at the lookup (no decision, wrong kind) or a replay changes nothing: one
//! record, no intent.
//!
//! Spec: docs/52 §3.1, §3.3, §3.4, §3.10, §4, §7 R1, R3; docs/51 §4.3,
//! §5.6, §5.8, §6, §9; docs/10 §2, §6, §6א, §7, §10, §11; docs/questions/
//! Q-460, Q-461, Q-462 item 1 (A-102), Q-450, Q-451, Q-452, Q-365 (A-88).

use crate::audit::{AuditKeyRef, AuditOutcome, AuditReason, AuditRecord, AuditSink};
use crate::authz::{CallerId, HandleSlot, Operation, Role};
use crate::entropy::EntropySource;
use crate::error::{Deny, Error, Internal};
use crate::keyd::{AuditFields, Keyd};
use crate::model::{KeyHandle, KeyPurpose, Kvno, PrincipalBinding, PrincipalId};
use crate::store::KeyStore;
use crate::time::kerberos_time_seconds;
use keyd_types::decision::{set_secret_shape_fits, DecisionFamily};
use keyd_types::grant::max_grant_lifetime_secs;
use keyd_types::{
    AccountKind, CeremonyState, DecidedOperation, DecisionId, DecisionIntent, DestructionPage,
    PendingDestruction, SetSecretTarget, MAX_DECISION_APPROVERS, MAX_DESTROY_DECISION_PAGE,
    MAX_GRANT_TARGETS,
};
use krb_proto::KerberosTime;
use krb_proto::{PrincipalName, Realm};
use std::collections::{BTreeMap, HashMap};

/// One set-secret key target (module documentation).
/// Spec: docs/51 §5.8 option (b): `(handle, binding, expiry)`; docs/52 §4.2
/// (+ salt, N4).
#[derive(Debug, Clone)]
struct SecretEntry {
    /// The decision it came from; `None` for the ceremony's grant.
    decision: Option<DecisionId>,
    binding: PrincipalBinding,
    salt: String,
    /// The last second (on the [`kerberos_time_seconds`] scale) at which the
    /// entry is live.
    expires_at: i64,
    /// From the ceremony's grant (Role::Admin): an initial secret only
    /// (docs/questions/Q-451).
    initial_only: bool,
    /// The one operation that may redeem the entry: `SetSecret` (admind, a
    /// `DecidedOperation::SetSecret` decision or the ceremony's grant) or
    /// `CompleteChangePassword` (keyd's kpasswd completion, a
    /// `DecidedOperation::ChangePassword` decision). An entry is invisible to
    /// the other operation — admind cannot redeem a decision dird made for a
    /// user's own change, nor the reverse. Task K3 (class: a one-time
    /// authorization meant for one executor redeemable by another; AGENTS.md
    /// §6.1 — docs/questions/Q-662).
    executor: Operation,
    /// The account's name for the password policy's account-name rule: the
    /// name of the decision's **first** target's binding — the account's
    /// own key set (`PrincipalLongterm`, named by its sAMAccountName; docs/47
    /// §9.1) — kept with every target, so that a computer's second
    /// (`Service`) target, bound to its SPN, is checked against the same
    /// account name ([MS-SAMR] 3.1.1.7.2 item 3.2.2; docs/53 §6.2). Task K3.
    account_name: PrincipalName,
}

/// What a redeemed set-secret entry still requires of the `set_secret` that
/// consumed it, and the decision it came from (for the record).
/// Spec: docs/questions/Q-451 item 2; docs/52 §4.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Redeemed {
    /// The key set must not exist (an initial secret).
    pub(crate) initial_only: bool,
    /// The decision the entry came from.
    pub(crate) decision: Option<DecisionId>,
    /// The account name the password policy checks the password against
    /// (task K3; [MS-SAMR] 3.1.1.7.2 item 3.2.2).
    pub(crate) account_name: PrincipalName,
}

/// A set-secret entry redeemed by a change-password completion (task K3):
/// the binding and salt the install uses — **the decision's**, never the
/// caller's — the decision id, and the account name for the policy.
/// Spec: docs/53 §5.5 ("installs through set_secret_inner (salt from the
/// decision ...)"), §6.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedeemedForClient {
    pub(crate) binding: PrincipalBinding,
    pub(crate) salt: String,
    pub(crate) decision: Option<DecisionId>,
    pub(crate) account_name: PrincipalName,
}

/// The result of an executed key-operation or destroy decision, kept until
/// the decision expires (docs/52 §3.10 (a)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Recorded {
    /// A rotation: the new kvno.
    Kvno(Kvno),
    /// `retire_kvno` / `destroy_key_set` succeeded.
    Done,
    /// keyd refused it (the public error it answered).
    Refused(Error),
}

/// Whether a key-operation or destroy decision ran yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpState {
    Pending,
    Executed(Recorded),
}

/// One key-operation or destroy decision.
#[derive(Debug, Clone)]
struct OpEntry {
    operation: DecidedOperation,
    approvers: Vec<PrincipalId>,
    expires_at: i64,
    state: OpState,
}

/// The first two approvers of a decision, when it names two.
fn approver_pair(approvers: &[PrincipalId]) -> Option<[PrincipalId; 2]> {
    match approvers {
        [first, second, ..] => Some([*first, *second]),
        _ => None,
    }
}

/// What the lookup of an execution found (module documentation).
#[derive(Debug, Clone)]
pub(crate) enum Found {
    /// A pending decision: run it.
    Pending {
        operation: DecidedOperation,
        approvers: Vec<PrincipalId>,
    },
    /// Already executed: return the recorded result.
    Executed {
        operation: DecidedOperation,
        approvers: Vec<PrincipalId>,
        recorded: Recorded,
    },
}

/// The decision table (module documentation).
/// Spec: docs/52 §4.2; docs/questions/Q-450 items 1, 4; AGENTS.md §6
/// (bounded, fail closed).
#[derive(Debug, Default)]
pub(crate) struct DecisionTable {
    secrets: HashMap<KeyHandle, SecretEntry>,
    keys: BTreeMap<DecisionId, OpEntry>,
    destroys: BTreeMap<DecisionId, OpEntry>,
}

impl DecisionTable {
    pub(crate) fn new() -> DecisionTable {
        DecisionTable::default()
    }

    /// Remove every expired entry of every family.
    /// Spec: docs/questions/Q-450 item 4; docs/52 §4.2 ("purged on expiry").
    fn sweep(&mut self, now: i64) {
        self.secrets.retain(|_, e| now <= e.expires_at);
        self.keys.retain(|_, e| now <= e.expires_at);
        self.destroys.retain(|_, e| now <= e.expires_at);
    }

    /// The key-operation or destroy family's map.
    fn ops(&self, family: DecisionFamily) -> Option<&BTreeMap<DecisionId, OpEntry>> {
        match family {
            DecisionFamily::KeyOperation => Some(&self.keys),
            DecisionFamily::Destroy => Some(&self.destroys),
            DecisionFamily::SetSecret => None,
        }
    }

    fn ops_mut(&mut self, family: DecisionFamily) -> Option<&mut BTreeMap<DecisionId, OpEntry>> {
        match family {
            DecisionFamily::KeyOperation => Some(&mut self.keys),
            DecisionFamily::Destroy => Some(&mut self.destroys),
            DecisionFamily::SetSecret => None,
        }
    }

    /// Whether a live set-secret entry that `executor` may redeem names
    /// `handle` at `now`. Reads only.
    /// Spec: docs/questions/Q-450 item 1; task K3 (the executor, Q-662).
    pub(crate) fn is_live_secret(&self, handle: &KeyHandle, executor: Operation, now: i64) -> bool {
        self.secrets
            .get(handle)
            .is_some_and(|e| now <= e.expires_at && e.executor == executor)
    }

    /// Register one set-secret entry per target, both or none: refused (the
    /// table unchanged, beyond the sweep) when the targets would not fit
    /// beside the live entries of other handles; a live entry of the same
    /// handle is replaced. `full` is the reason of a full family.
    /// Spec: docs/questions/Q-450 items 2, 4.
    #[allow(clippy::too_many_arguments)]
    fn register_secrets(
        &mut self,
        decision: Option<DecisionId>,
        executor: Operation,
        targets: &[SetSecretTarget],
        expires_at: i64,
        initial_only: bool,
        now: i64,
        full: AuditReason,
    ) -> Internal<()> {
        self.sweep(now);
        // The account's own name: the first target's binding (the shape is
        // checked by the caller — a first target always exists).
        let account_name = targets
            .first()
            .map(|t| t.binding.name.clone())
            .ok_or(Deny::denied(full))?;
        let added = targets
            .iter()
            .filter(|t| !self.secrets.contains_key(&t.handle))
            .count();
        if self.secrets.len().saturating_add(added) > DecisionFamily::SetSecret.capacity() {
            return Err(Deny::unavailable(full));
        }
        for target in targets {
            self.secrets.insert(
                target.handle,
                SecretEntry {
                    decision,
                    binding: target.binding.clone(),
                    salt: target.salt.clone(),
                    expires_at,
                    initial_only,
                    executor,
                    account_name: account_name.clone(),
                },
            );
        }
        Ok(())
    }

    /// Consume the set-secret entry of `handle` for a `set_secret` naming
    /// `binding` and `salt`: the entry is removed on ANY presentation. No
    /// live entry ⇒ `NoGrant`; another binding or salt ⇒ `GrantMismatch`.
    /// Spec: docs/51 §5.8 option (b) ("refused unless a matching unexpired
    /// grant exists, and consumes it"); docs/questions/Q-450 item 7; docs/52
    /// §2 row 37 (N4: the salt).
    pub(crate) fn redeem_secret(
        &mut self,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
        salt: &str,
        now: i64,
    ) -> Internal<Redeemed> {
        let entry = self.secrets.remove(handle);
        self.sweep(now);
        let entry = entry.ok_or(Deny::denied(AuditReason::NoGrant))?;
        if now > entry.expires_at || entry.executor != Operation::SetSecret {
            return Err(Deny::denied(AuditReason::NoGrant));
        }
        if entry.binding != *binding || entry.salt != salt {
            return Err(Deny::denied(AuditReason::GrantMismatch));
        }
        Ok(Redeemed {
            initial_only: entry.initial_only,
            decision: entry.decision,
            account_name: entry.account_name,
        })
    }

    /// Consume the set-secret entry of `handle` for a change-password
    /// completion of the ticket client (`crealm`, `cname`) — task K3. The
    /// entry is removed on ANY presentation (one attempt per decision, as
    /// for `set_secret`). No live entry for this executor (a
    /// `DecidedOperation::ChangePassword` decision dird registered) ⇒
    /// `NoGrant`; its binding not identifying the ticket's client (RFC 4120
    /// 6.2 equivalence — the target is bound by keyd to the client keyd
    /// verified, never chosen by the caller) ⇒ `GrantMismatch`. The install
    /// then uses the entry's binding and salt.
    /// Spec: docs/53 R53-5, R53-8, §4.3, §5.5 ("a live SetSecret decision to
    /// the handle whose sole target carries binding ≡ (ctx.crealm,
    /// ctx.cname) (RFC 4120 §6.2; A-19) — else Denied (GrantMismatch)");
    /// RFC 4120 6.2; docs/questions/Q-450 item 7.
    pub(crate) fn redeem_secret_for_client(
        &mut self,
        handle: &KeyHandle,
        crealm: &Realm,
        cname: &PrincipalName,
        now: i64,
    ) -> Internal<RedeemedForClient> {
        let entry = self.secrets.remove(handle);
        self.sweep(now);
        let entry = entry.ok_or(Deny::denied(AuditReason::NoGrant))?;
        if now > entry.expires_at
            || entry.executor != Operation::CompleteChangePassword
            || entry.decision.is_none()
            || entry.initial_only
        {
            return Err(Deny::denied(AuditReason::NoGrant));
        }
        if !entry.binding.matches(crealm, cname) {
            return Err(Deny::denied(AuditReason::GrantMismatch));
        }
        Ok(RedeemedForClient {
            binding: entry.binding,
            salt: entry.salt,
            decision: entry.decision,
            account_name: entry.account_name,
        })
    }

    /// The decision id of the live set-secret entry of `handle`, if any (for
    /// the record of the `set_secret` that will consume it).
    pub(crate) fn secret_decision(&self, handle: &KeyHandle) -> Option<DecisionId> {
        self.secrets.get(handle).and_then(|e| e.decision)
    }

    /// The decision id of the set-secret entry of `handle` that `executor`
    /// may redeem, if any (task K3, Q-662: an operation's record never names
    /// a decision meant for the other executor).
    pub(crate) fn secret_decision_for(
        &self,
        handle: &KeyHandle,
        executor: Operation,
    ) -> Option<DecisionId> {
        self.secrets
            .get(handle)
            .filter(|e| e.executor == executor)
            .and_then(|e| e.decision)
    }

    /// Drop the set-secret entry of `handle`, if any (its key set was
    /// destroyed). Spec: docs/10 §7; docs/questions/Q-450 item 8.
    pub(crate) fn discard_secret(&mut self, handle: &KeyHandle) {
        self.secrets.remove(handle);
    }

    /// Drop the set-secret entry of `handle` (its principal was deleted —
    /// a destroy registration, R6b) and say whether a **live** one was
    /// dropped: `Some(its decision id)` (`Some(None)` for the ceremony's
    /// grant), `None` if there was none or it had expired.
    /// Spec: docs/questions/Q-501 (R6b), Q-520; docs/questions/Q-450 item 4.
    fn withdraw_secret(&mut self, handle: &KeyHandle, now: i64) -> Option<Option<DecisionId>> {
        let entry = self.secrets.remove(handle)?;
        (now <= entry.expires_at).then_some(entry.decision)
    }

    /// Register a key-operation or destroy decision. An identical live
    /// decision under the same id is accepted unchanged (a re-registration
    /// after an unknown outcome is harmless — docs/52 §4.3); a different
    /// one is `DecisionConflict`; a full family is `DecisionTableFull`.
    /// Spec: docs/52 §4.2, §4.3.
    fn register_op(
        &mut self,
        id: DecisionId,
        operation: &DecidedOperation,
        approvers: &[PrincipalId],
        expires_at: i64,
        now: i64,
    ) -> Internal<()> {
        self.sweep(now);
        let family = operation.family();
        let map = self
            .ops_mut(family)
            .ok_or(Deny::denied(AuditReason::DecisionInvalid))?;
        if let Some(existing) = map.get(&id) {
            return if existing.operation == *operation && existing.approvers == approvers {
                Ok(())
            } else {
                Err(Deny::denied(AuditReason::DecisionConflict))
            };
        }
        if map.len() >= family.capacity() {
            return Err(Deny::unavailable(AuditReason::DecisionTableFull));
        }
        map.insert(
            id,
            OpEntry {
                operation: operation.clone(),
                approvers: approvers.to_vec(),
                expires_at,
                state: OpState::Pending,
            },
        );
        Ok(())
    }

    /// The live decision `id` of `family`, if any.
    fn find(&self, family: DecisionFamily, id: DecisionId, now: i64) -> Option<&OpEntry> {
        self.ops(family)
            .and_then(|map| map.get(&id))
            .filter(|e| now <= e.expires_at)
    }

    /// Look the decision `id` of `family` up for an execution (or its
    /// intent): `NoDecision` if there is no live one.
    fn lookup(&self, family: DecisionFamily, id: DecisionId, now: i64) -> Internal<Found> {
        let entry = self
            .find(family, id, now)
            .ok_or(Deny::denied(AuditReason::NoDecision))?;
        Ok(match entry.state {
            OpState::Pending => Found::Pending {
                operation: entry.operation.clone(),
                approvers: entry.approvers.clone(),
            },
            OpState::Executed(recorded) => Found::Executed {
                operation: entry.operation.clone(),
                approvers: entry.approvers.clone(),
                recorded,
            },
        })
    }

    /// Record the result of decision `id`: it is consumed (module
    /// documentation).
    fn record(&mut self, family: DecisionFamily, id: DecisionId, recorded: Recorded) {
        if let Some(entry) = self.ops_mut(family).and_then(|map| map.get_mut(&id)) {
            entry.state = OpState::Executed(recorded);
        }
    }

    /// One page of the pending (not yet executed, live) destroy decisions
    /// strictly after `after`, ascending by id.
    /// Spec: docs/52 §4.6; docs/50 §3.3 (bounded replies).
    fn pending_destructions(&mut self, after: Option<DecisionId>, now: i64) -> DestructionPage {
        self.sweep(now);
        let mut entries = Vec::new();
        let mut next = None;
        for (id, entry) in &self.destroys {
            if after.is_some_and(|after| *id <= after) || entry.state != OpState::Pending {
                continue;
            }
            let DecidedOperation::DestroyKeySet { principal } = entry.operation else {
                continue;
            };
            if entries.len() == MAX_DESTROY_DECISION_PAGE {
                next = entries.last().map(|e: &PendingDestruction| e.decision);
                break;
            }
            entries.push(PendingDestruction {
                decision: *id,
                principal,
            });
        }
        DestructionPage { entries, next }
    }

    /// Entries held, every family (live or not yet swept).
    pub(crate) fn len(&self) -> usize {
        self.secrets
            .len()
            .saturating_add(self.keys.len())
            .saturating_add(self.destroys.len())
    }
}

/// The family whose decisions `op` executes by id, if any.
/// Spec: docs/52 §4.2.
pub(crate) const fn executes_family(op: Operation) -> Option<DecisionFamily> {
    match op {
        Operation::RotateKrbtgt | Operation::RotateKey | Operation::RetireKvno => {
            Some(DecisionFamily::KeyOperation)
        }
        Operation::DestroyKeySet => Some(DecisionFamily::Destroy),
        _ => None,
    }
}

/// The handle slots of `targets` for the authorization step: the first
/// target in the `Primary` slot, the second in the `Secondary` slot; a third
/// is not looked at here (the shape check refuses it).
/// Spec: docs/10 §2 (I3); keyd-types authz `purpose_permitted`.
fn slots(targets: &[SetSecretTarget]) -> Vec<(HandleSlot, &KeyHandle)> {
    targets
        .iter()
        .zip([HandleSlot::Primary, HandleSlot::Secondary])
        .map(|(target, slot)| (slot, &target.handle))
        .collect()
}

/// The audit fields of a decision: its id, the key sets and kvno it names,
/// its first two approvers.
/// Spec: docs/10 §10; docs/52 §4.5.
fn decision_fields(
    id: Option<DecisionId>,
    operation: &DecidedOperation,
    approvers: &[PrincipalId],
) -> AuditFields {
    let mut fields = operation
        .primary()
        .map(|h| AuditFields::for_handle(&h))
        .unwrap_or_default();
    fields.secondary = operation.secondary().map(|h| AuditKeyRef {
        principal: h.principal,
        purpose: h.purpose,
        kvno: None,
    });
    fields.kvno = operation.kvno();
    fields.approvers = approver_pair(approvers);
    fields.decision = id;
    fields
}

/// Whether `approvers` are at most [`MAX_DECISION_APPROVERS`], at least the
/// family's minimum, and pairwise distinct.
/// Spec: docs/51 §5.6 ("a second, *different* approver"); docs/52 §4.2.
fn approvers_fit(family: DecisionFamily, approvers: &[PrincipalId]) -> bool {
    approvers.len() <= MAX_DECISION_APPROVERS
        && approvers.len() >= family.min_approvers()
        && approvers
            .iter()
            .enumerate()
            .all(|(i, a)| approvers.iter().skip(i + 1).all(|b| a != b))
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// The ceremony state (docs/52 §4.4).
    #[must_use]
    pub fn ceremony_state(&self) -> CeremonyState {
        self.ceremony
    }

    /// The decision id of the live set-secret entry naming `handle`, if any
    /// (`None` also for the ceremony's grant, which has no id) — for the
    /// daemon's intent record of the `set_secret` (or, task K3, the
    /// `complete_change_password`) that will consume it (docs/52 §4.5). The
    /// daemon asks only after keyd's authorization step admitted the call,
    /// so the entry is the call's own executor's (Q-662). Reads only; not
    /// secret.
    #[must_use]
    pub fn secret_decision(&self, handle: &KeyHandle) -> Option<DecisionId> {
        self.decisions.secret_decision(handle)
    }

    /// `register_decision`: record dird's decision `id` to run `operation`,
    /// approved by `approvers` (dird verified each one's AP-REQ and PDP
    /// decision), live for `lifetime_secs` from `now` (keyd's own clock,
    /// R50-5). Role::Ldap only.
    ///
    /// In order — every refusal is the uniform `Denied` unless noted, with
    /// its reason in the one audit record:
    /// 1. the authorization step ([`Keyd::admit`]): the role (I2);
    /// 2. the decided operation: well formed (a set-secret decision's
    ///    shape, a kvno ≠ 0) and its key sets of the purposes the executing
    ///    operation accepts (I3) — `DecisionInvalid`;
    /// 3. the approvers: at most three, pairwise distinct, at least two for
    ///    a key operation — `DecisionInvalid`;
    /// 4. the lifetime: 1 to the family's ceiling — `DecisionInvalid`;
    /// 5. a `DestroyKeySet` decision: first every live set-secret entry for
    ///    the principal's two handles is discarded (one
    ///    `SecretDecisionDiscarded` record each, after this call's own
    ///    record), whatever follows; then the principal must still have a
    ///    `PrincipalLongterm` or `Service` key set — else `KeyNotFound`,
    ///    whatever the table holds, and no slot is taken (R6b; module
    ///    documentation, "Destroy decisions and the key store");
    /// 6. the table: a full family ⇒ `Unavailable` (`DecisionTableFull`); an
    ///    id that names a different live decision ⇒ `DecisionConflict`; the
    ///    same decision again ⇒ accepted, nothing changes.
    ///
    /// Bindings are not judged here: the `set_secret` that consumes a
    /// set-secret decision judges its binding as before (A-19), so a
    /// decision can only narrow what keyd accepts (docs/questions/Q-450
    /// item 7). No key is read or written (step 5 asks the store only
    /// whether a key set exists, and drops set-secret entries — names,
    /// salts, no key); nothing secret is taken or returned.
    ///
    /// Spec: docs/52 §4.2, §4.3, §4.5, §7 R1; docs/10 §2, §6א, §9, §10;
    /// docs/50 R50-5; docs/questions/Q-460 (A-102), Q-450, Q-452, Q-471 item
    /// 5, Q-501 (R6b).
    pub fn register_decision(
        &mut self,
        caller: &CallerId,
        id: DecisionId,
        operation: &DecidedOperation,
        approvers: &[PrincipalId],
        lifetime_secs: u32,
        now: &KerberosTime,
    ) -> Result<(), Error> {
        let fields = decision_fields(Some(id), operation, approvers);
        let mut discarded = Vec::new();
        let result = self.register_decision_inner(
            caller,
            id,
            operation,
            approvers,
            lifetime_secs,
            now,
            &mut discarded,
        );
        // The registration's own record first (the daemon commits the first
        // record into the slot it reserved for the outcome), then one record
        // per set-secret entry the destroy registration discarded (R6b).
        self.emit(caller, Operation::RegisterDecision, now, &fields, &result);
        for (handle, decision) in discarded {
            self.emit_discard(caller, now, &handle, decision);
        }
        result.map_err(Error::from)
    }

    // The arguments of `register_decision`, plus where the destroy
    // registration lists the set-secret entries it discarded.
    #[allow(clippy::too_many_arguments)]
    fn register_decision_inner(
        &mut self,
        caller: &CallerId,
        id: DecisionId,
        operation: &DecidedOperation,
        approvers: &[PrincipalId],
        lifetime_secs: u32,
        now: &KerberosTime,
        discarded: &mut Vec<(KeyHandle, Option<DecisionId>)>,
    ) -> Internal<()> {
        self.admit(caller, Operation::RegisterDecision, &[], now)?;
        if !operation.is_well_formed() || !operation.purposes_permitted() {
            return Err(Deny::denied(AuditReason::DecisionInvalid));
        }
        let family = operation.family();
        if !approvers_fit(family, approvers) {
            return Err(Deny::denied(AuditReason::DecisionInvalid));
        }
        if lifetime_secs == 0 || lifetime_secs > family.max_lifetime_secs() {
            return Err(Deny::denied(AuditReason::DecisionInvalid));
        }
        let now_s = kerberos_time_seconds(now);
        let expires_at = now_s
            .checked_add(i64::from(lifetime_secs))
            .ok_or(Deny::denied(AuditReason::DecisionInvalid))?;
        if let DecidedOperation::DestroyKeySet { principal } = operation {
            // R6b: the registration is dird's statement that the principal is
            // deleted — first, every live set-secret entry for its two
            // handles goes, whatever the rest decides, so no key set can come
            // to exist for it from here on (module documentation, "Destroy
            // decisions and the key store").
            for purpose in [KeyPurpose::PrincipalLongterm, KeyPurpose::Service] {
                let handle = KeyHandle::new(*principal, purpose);
                if let Some(decision) = self.decisions.withdraw_secret(&handle, now_s) {
                    discarded.push((handle, decision));
                }
            }
            // Then a destroy decision only for a principal that still has a
            // key set — before the table is looked at, so the answer for a
            // principal without one is the refusal whatever the table holds
            // (keyd's key store is the one source of "destroyed"), and it
            // takes no slot.
            if !self.holds_destroyable_key_set(principal) {
                return Err(Deny::denied(AuditReason::KeyNotFound));
            }
        }
        match operation {
            DecidedOperation::SetSecret { targets, .. } => self.decisions.register_secrets(
                Some(id),
                Operation::SetSecret,
                targets,
                expires_at,
                false,
                now_s,
                AuditReason::DecisionTableFull,
            ),
            // Task K3: a user's own change (dird after the PDP allowed
            // User-Change-Password on the account itself) — redeemable only
            // by keyd's completion of that user's request (docs/53 §4.4,
            // §5.5; Q-662).
            DecidedOperation::ChangePassword { target } => self.decisions.register_secrets(
                Some(id),
                Operation::CompleteChangePassword,
                core::slice::from_ref(target),
                expires_at,
                false,
                now_s,
                AuditReason::DecisionTableFull,
            ),
            DecidedOperation::RotateKrbtgt { .. }
            | DecidedOperation::RotateKey { .. }
            | DecidedOperation::RetireKvno { .. }
            | DecidedOperation::DestroyKeySet { .. } => self
                .decisions
                .register_op(id, operation, approvers, expires_at, now_s),
        }
    }

    /// Whether `principal` has a key set a destroy decision would destroy —
    /// its `PrincipalLongterm` or its `Service` key set (the two purposes
    /// `destroy_key_set` touches; never Krbtgt or AdminService). Reads the
    /// store only (no key is read).
    /// Spec: docs/questions/Q-501 item 5 and its decision (R6b); docs/10 §7
    /// (`destroy_key_set`: "the PrincipalLongterm and the Service of it").
    fn holds_destroyable_key_set(&self, principal: &PrincipalId) -> bool {
        [KeyPurpose::PrincipalLongterm, KeyPurpose::Service]
            .into_iter()
            .any(|purpose| {
                self.store
                    .get(&KeyHandle::new(*principal, purpose))
                    .is_some()
            })
    }

    /// `grant_set_secret`: the provisioning ceremony's grant of a first
    /// administrator's **initial** secret (Role::Admin, keyadm's ceremony —
    /// docs/51 §4.3 step 11; docs/questions/Q-451), live for
    /// `lifetime_secs` from `now`. It exists only before the seal
    /// (`keyd_types::authz::provisioning_only`; `CeremonySealed` after).
    ///
    /// In order — every refusal is the uniform `Denied` unless noted:
    /// 1. the authorization step ([`Keyd::admit`]): the role (Admin, I2),
    ///    the purposes (first target `PrincipalLongterm`, second `Service`,
    ///    I3), the ceremony state (`CeremonySealed`);
    /// 2. the shape of the targets for `kind` (`GrantInvalid`);
    /// 3. a lifetime of 1 to [`keyd_types::MAX_INITIAL_SECRET_GRANT_SECS`],
    ///    a user only, and only for a key set that does not exist yet
    ///    (`GrantInvalid`, `KeyExists`);
    /// 4. the table (`GrantTableFull` ⇒ `Unavailable`).
    ///
    /// Spec: docs/51 §4.3 steps 11-12, §5.8 option (b); docs/52 §4.4;
    /// docs/10 §2, §6א; docs/questions/Q-450, Q-451, Q-462 item 1 (A-102).
    pub fn grant_set_secret(
        &mut self,
        caller: &CallerId,
        kind: AccountKind,
        targets: &[SetSecretTarget],
        lifetime_secs: u32,
        now: &KerberosTime,
    ) -> Result<(), Error> {
        let mut fields = AuditFields::default();
        if let Some(first) = targets.first() {
            fields = AuditFields::for_handle(&first.handle);
        }
        if let Some(second) = targets.get(1) {
            fields.secondary = Some(AuditKeyRef {
                principal: second.handle.principal,
                purpose: second.handle.purpose,
                kvno: None,
            });
        }
        let result = self.grant_set_secret_inner(caller, kind, targets, lifetime_secs, now);
        self.emit(caller, Operation::GrantSetSecret, now, &fields, &result);
        result.map_err(Error::from)
    }

    fn grant_set_secret_inner(
        &mut self,
        caller: &CallerId,
        kind: AccountKind,
        targets: &[SetSecretTarget],
        lifetime_secs: u32,
        now: &KerberosTime,
    ) -> Internal<()> {
        self.admit(caller, Operation::GrantSetSecret, &slots(targets), now)?;
        if targets.len() > MAX_GRANT_TARGETS || !set_secret_shape_fits(kind, targets) {
            return Err(Deny::denied(AuditReason::GrantInvalid));
        }
        // The role passed the capability table, so it has a ceiling; any
        // other role would be refused here too (fail closed).
        let ceiling = max_grant_lifetime_secs(caller.role)
            .ok_or(Deny::denied(AuditReason::RoleNotPermitted))?;
        if lifetime_secs == 0 || lifetime_secs > ceiling {
            return Err(Deny::denied(AuditReason::GrantInvalid));
        }
        if caller.role != Role::Admin || kind != AccountKind::User {
            return Err(Deny::denied(AuditReason::GrantInvalid));
        }
        // An initial secret only: no key set yet (the binding itself is
        // judged by the `set_secret` that redeems the grant, as before —
        // A-19; docs/questions/Q-450 item 7).
        if targets
            .iter()
            .any(|target| self.store.get(&target.handle).is_some())
        {
            return Err(Deny::denied(AuditReason::KeyExists));
        }
        let now_s = kerberos_time_seconds(now);
        let expires_at = now_s
            .checked_add(i64::from(lifetime_secs))
            .ok_or(Deny::denied(AuditReason::GrantInvalid))?;
        self.decisions.register_secrets(
            None,
            Operation::SetSecret,
            targets,
            expires_at,
            true,
            now_s,
            AuditReason::GrantTableFull,
        )
    }

    /// `seal_ceremony`: end the provisioning ceremony — keyd moves to
    /// [`CeremonyState::Operational`] and `create_key` and Role::Admin's
    /// grants no longer exist. Sealing a sealed keyd changes nothing and
    /// succeeds (a re-run of the ceremony's last step is harmless). Grants
    /// registered before the seal live until they expire (the first
    /// administrators' `set_secret` follows the ceremony — docs/51 §4.3
    /// step 12). Role::Admin.
    ///
    /// The seal only ever makes keyd stricter, so it is one record, no
    /// intent (A-88). It is held in memory: a keyd started with an empty
    /// store is `Provisioning` again (development mode: every start —
    /// P-17, A-77; docs/52 §4.4 residual).
    ///
    /// Spec: docs/52 §4.4, §7 R3; docs/51 §4.3, §4.5; docs/questions/Q-462
    /// item 1 (A-102).
    pub fn seal_ceremony(&mut self, caller: &CallerId, now: &KerberosTime) -> Result<(), Error> {
        let fields = AuditFields::default();
        let result = self.admit(caller, Operation::SealCeremony, &[], now);
        if result.is_ok() {
            self.ceremony = CeremonyState::Operational;
        }
        self.emit(caller, Operation::SealCeremony, now, &fields, &result);
        result.map_err(Error::from)
    }

    /// `list_destroy_decisions`: one page (at most
    /// [`MAX_DESTROY_DECISION_PAGE`]) of the live destroy decisions not yet
    /// executed, strictly after `after`, ascending by id — what keyadm's
    /// `destroy-sweep` executes. Not secret (decision ids and tombstones'
    /// objectGUIDs). Role::Admin. One record.
    ///
    /// Spec: docs/52 §4.3, §4.6; docs/51 §6, §9; docs/questions/Q-460.
    pub fn list_destroy_decisions(
        &mut self,
        caller: &CallerId,
        after: Option<DecisionId>,
        now: &KerberosTime,
    ) -> Result<DestructionPage, Error> {
        let fields = AuditFields {
            decision: after,
            ..AuditFields::default()
        };
        let result = self
            .admit(caller, Operation::ListDestroyDecisions, &[], now)
            .map(|()| {
                self.decisions
                    .pending_destructions(after, kerberos_time_seconds(now))
            });
        self.emit(
            caller,
            Operation::ListDestroyDecisions,
            now,
            &fields,
            &result,
        );
        result.map_err(Error::from)
    }

    /// The authorization step of an execution by decision id: the role
    /// (I2), then a live decision of the operation's family under `id`
    /// (`NoDecision`), of the operation's kind (`DecisionMismatch` — not
    /// consumed), naming key sets of the purposes the operation accepts
    /// (I3, checked at registration and again here). Reads only.
    /// Spec: docs/52 §4.2; docs/10 §2.
    pub(crate) fn admit_decision(
        &self,
        caller: &CallerId,
        op: Operation,
        id: DecisionId,
        now: &KerberosTime,
    ) -> Internal<Found> {
        self.admit_base(caller, op, &[], now)?;
        let family = executes_family(op).ok_or(Deny::denied(AuditReason::NoDecision))?;
        let found = self
            .decisions
            .lookup(family, id, kerberos_time_seconds(now))?;
        let operation = match &found {
            Found::Pending { operation, .. } | Found::Executed { operation, .. } => operation,
        };
        if operation.executed_by() != op {
            return Err(Deny::denied(AuditReason::DecisionMismatch));
        }
        if !operation.purposes_permitted() {
            return Err(Deny::denied(AuditReason::PurposeMismatch));
        }
        Ok(found)
    }

    /// The intent of executing decision `id` with `op` as `caller` at
    /// `now`, for the daemon's intent record (A-86): `Some` only when the
    /// authorization step admits it and the decision has not run yet — a
    /// refused or replayed presentation changes nothing and takes the
    /// ordinary path (one record). The facts come from keyd's table, never
    /// from the request (docs/52 §4.5). Reads only; no record.
    /// Spec: docs/52 §4.2, §4.5; docs/questions/Q-346 (A-86), Q-365.
    #[must_use]
    pub fn decided_intent(
        &self,
        caller: &CallerId,
        op: Operation,
        id: DecisionId,
        now: &KerberosTime,
    ) -> Option<DecisionIntent> {
        match self.admit_decision(caller, op, id, now) {
            Ok(Found::Pending {
                operation,
                approvers,
            }) => Some(DecisionIntent {
                decision: id,
                primary: operation.primary(),
                secondary: operation.secondary(),
                kvno: operation.kvno(),
                approvers: approver_pair(&approvers),
            }),
            Ok(Found::Executed { .. }) | Err(_) => None,
        }
    }

    /// Run decision `id` with `op` (module documentation): the
    /// authorization step ([`Keyd::admit_decision`]); a decision that ran
    /// already returns its recorded result (`DecisionReplayed`, nothing
    /// run); a pending one is consumed, run by `run` on the **registered**
    /// operation and approvers, and its result recorded. One audit record,
    /// carrying the decision id and the decided parameters.
    /// Spec: docs/52 §3.10 (a), §4.2, §4.5.
    // The caller, operation, id and time of every keyd operation, plus the
    // decision's three per-operation pieces (run, record, replay).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_decision<T>(
        &mut self,
        caller: &CallerId,
        op: Operation,
        id: DecisionId,
        now: &KerberosTime,
        run: impl FnOnce(&mut Self, &DecidedOperation, &[PrincipalId], &mut AuditFields) -> Internal<T>,
        record_of: impl FnOnce(&T) -> Recorded,
        replay: impl FnOnce(Recorded) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let found = match self.admit_decision(caller, op, id, now) {
            Ok(found) => found,
            Err(deny) => {
                let fields = AuditFields {
                    decision: Some(id),
                    ..AuditFields::default()
                };
                let result: Internal<()> = Err(deny);
                self.emit(caller, op, now, &fields, &result);
                return Err(Error::from(deny));
            }
        };
        match found {
            Found::Executed {
                operation,
                approvers,
                recorded,
            } => {
                let fields = decision_fields(Some(id), &operation, &approvers);
                self.emit_replay(caller, op, now, &fields, recorded);
                replay(recorded)
            }
            Found::Pending {
                operation,
                approvers,
            } => {
                let mut fields = decision_fields(Some(id), &operation, &approvers);
                let result = run(self, &operation, &approvers, &mut fields);
                let recorded = match &result {
                    Ok(value) => record_of(value),
                    Err(deny) => Recorded::Refused(Error::from(*deny)),
                };
                if let Some(family) = executes_family(op) {
                    self.decisions.record(family, id, recorded);
                }
                self.emit(caller, op, now, &fields, &result);
                result.map_err(Error::from)
            }
        }
    }

    /// The record of one set-secret entry a destroy registration discarded
    /// (R6b): operation `RegisterDecision` (the call that discarded it),
    /// outcome `Success`, reason `SecretDecisionDiscarded`, the handle, and
    /// the discarded entry's decision id (`None`: the ceremony's grant).
    /// Spec: docs/10 §10, I8; docs/questions/Q-520.
    fn emit_discard(
        &mut self,
        caller: &CallerId,
        now: &KerberosTime,
        handle: &KeyHandle,
        decision: Option<DecisionId>,
    ) {
        self.audit.record(&AuditRecord {
            ts: *now,
            caller_role: caller.role,
            caller_uid: caller.uid,
            op: Operation::RegisterDecision,
            principal: Some(handle.principal),
            purpose: Some(handle.purpose),
            kvno: None,
            secondary: None,
            approvers: None,
            decision,
            result: AuditOutcome::Success,
            reason: AuditReason::SecretDecisionDiscarded,
        });
    }

    /// The one record of a replayed decision: the recorded outcome, reason
    /// `DecisionReplayed`.
    /// Spec: docs/10 §10, I8; docs/52 §3.10.
    fn emit_replay(
        &mut self,
        caller: &CallerId,
        op: Operation,
        now: &KerberosTime,
        fields: &AuditFields,
        recorded: Recorded,
    ) {
        let result = match recorded {
            Recorded::Kvno(_) | Recorded::Done => AuditOutcome::Success,
            Recorded::Refused(Error::Denied) => AuditOutcome::Denied,
            Recorded::Refused(Error::Unavailable) => AuditOutcome::Unavailable,
            Recorded::Refused(Error::RateLimited) => AuditOutcome::RateLimited,
        };
        self.audit.record(&AuditRecord {
            ts: *now,
            caller_role: caller.role,
            caller_uid: caller.uid,
            op,
            principal: fields.principal,
            purpose: fields.purpose,
            kvno: match recorded {
                Recorded::Kvno(kvno) => Some(kvno),
                _ => fields.kvno,
            },
            secondary: fields.secondary,
            approvers: fields.approvers,
            decision: fields.decision,
            result,
            reason: AuditReason::DecisionReplayed,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb_proto::{KerberosString, PrincipalName, Realm};

    fn target(byte: u8, purpose: KeyPurpose, name: &str) -> SetSecretTarget {
        SetSecretTarget {
            handle: KeyHandle::new(PrincipalId::from_bytes([byte; 16]), purpose),
            binding: PrincipalBinding::new(
                Realm::new("EXAMPLE.ORG").unwrap(),
                PrincipalName {
                    name_type: 1,
                    name_string: vec![KerberosString::new(name).unwrap()],
                },
            ),
            salt: format!("EXAMPLE.ORG{name}"),
        }
    }

    /// Q-450 items 1, 7; docs/52 N4: one presentation consumes the entry;
    /// another binding or another salt consumes it too and is refused; an
    /// expired entry is no entry.
    #[test]
    fn redeeming_consumes_and_binds_binding_and_salt() {
        let mut t = DecisionTable::new();
        let a = target(1, KeyPurpose::PrincipalLongterm, "a");
        let full = AuditReason::DecisionTableFull;
        let id = Some(DecisionId::new(9));
        assert!(t
            .register_secrets(
                id,
                Operation::SetSecret,
                std::slice::from_ref(&a),
                10,
                false,
                0,
                full
            )
            .is_ok());
        assert_eq!(t.secret_decision(&a.handle), id);
        assert_eq!(
            t.redeem_secret(&a.handle, &a.binding, &a.salt, 10),
            Ok(Redeemed {
                initial_only: false,
                decision: id,
                account_name: a.binding.name.clone(),
            })
        );
        assert_eq!(
            t.redeem_secret(&a.handle, &a.binding, &a.salt, 10)
                .map_err(|d| d.reason),
            Err(AuditReason::NoGrant)
        );
        // Another salt (N4).
        assert!(t
            .register_secrets(
                id,
                Operation::SetSecret,
                std::slice::from_ref(&a),
                10,
                false,
                0,
                full
            )
            .is_ok());
        assert_eq!(
            t.redeem_secret(&a.handle, &a.binding, "EXAMPLE.ORGother", 1)
                .map_err(|d| d.reason),
            Err(AuditReason::GrantMismatch)
        );
        assert!(!t.is_live_secret(&a.handle, Operation::SetSecret, 1));
        // Expired.
        assert!(t
            .register_secrets(
                None,
                Operation::SetSecret,
                std::slice::from_ref(&a),
                10,
                true,
                0,
                full
            )
            .is_ok());
        assert_eq!(
            t.redeem_secret(&a.handle, &a.binding, &a.salt, 11)
                .map_err(|d| d.reason),
            Err(AuditReason::NoGrant)
        );
        assert_eq!(t.len(), 0);
    }

    /// docs/53 §5.5 (task K3): a change-password completion redeems only a
    /// `ChangePassword` decision whose target's binding identifies the
    /// ticket's client (RFC 4120 6.2: the name-type is ignored); a decision
    /// for another principal is refused (and consumed); an admin-plane
    /// `SetSecret` decision or the ceremony's grant is invisible to it — and
    /// a `ChangePassword` decision is invisible to `set_secret` (Q-662). The
    /// redemption hands back the decision's binding and salt.
    #[test]
    fn a_completion_redeems_only_the_clients_own_user_decision() {
        let mut t = DecisionTable::new();
        let full = AuditReason::DecisionTableFull;
        let id = Some(DecisionId::new(11));
        let carol = target(3, KeyPurpose::PrincipalLongterm, "carol");
        let realm = carol.binding.realm.clone();
        let mut cname = carol.binding.name.clone();
        cname.name_type = 0; // a hint only (RFC 4120 6.2)
        let change = Operation::CompleteChangePassword;
        assert!(t
            .register_secrets(id, change, std::slice::from_ref(&carol), 10, false, 0, full)
            .is_ok());
        assert!(t.is_live_secret(&carol.handle, change, 1));
        assert!(!t.is_live_secret(&carol.handle, Operation::SetSecret, 1));
        assert_eq!(
            t.redeem_secret(&carol.handle, &carol.binding, &carol.salt, 1)
                .map_err(|d| d.reason),
            Err(AuditReason::NoGrant)
        );
        assert!(t
            .register_secrets(id, change, std::slice::from_ref(&carol), 10, false, 0, full)
            .is_ok());
        assert_eq!(
            t.redeem_secret_for_client(&carol.handle, &realm, &cname, 1),
            Ok(RedeemedForClient {
                binding: carol.binding.clone(),
                salt: carol.salt.clone(),
                decision: id,
                account_name: carol.binding.name.clone(),
            })
        );
        let refused = |t: &mut DecisionTable, name: &PrincipalName| {
            t.redeem_secret_for_client(&carol.handle, &realm, name, 1)
                .map_err(|d| d.reason)
        };
        // Consumed: no second redemption.
        assert_eq!(refused(&mut t, &cname), Err(AuditReason::NoGrant));
        // A decision whose target is another principal's name.
        let mallory = target(3, KeyPurpose::PrincipalLongterm, "mallory");
        assert!(t
            .register_secrets(
                id,
                change,
                std::slice::from_ref(&mallory),
                10,
                false,
                0,
                full
            )
            .is_ok());
        assert_eq!(refused(&mut t, &cname), Err(AuditReason::GrantMismatch));
        assert!(!t.is_live_secret(&carol.handle, change, 1));
        // An admin-plane decision for carol herself: not for this executor.
        assert!(t
            .register_secrets(
                id,
                Operation::SetSecret,
                std::slice::from_ref(&carol),
                10,
                false,
                0,
                full
            )
            .is_ok());
        assert_eq!(refused(&mut t, &cname), Err(AuditReason::NoGrant));
        // The ceremony's initial-secret grant (no decision id).
        assert!(t
            .register_secrets(
                None,
                Operation::SetSecret,
                std::slice::from_ref(&carol),
                10,
                true,
                0,
                full
            )
            .is_ok());
        assert_eq!(refused(&mut t, &cname), Err(AuditReason::NoGrant));
    }

    /// docs/52 §4.3: the same decision registered twice changes nothing; a
    /// different one under the same id conflicts; the family is bounded.
    #[test]
    fn op_registration_is_idempotent_conflicting_and_bounded() {
        let mut t = DecisionTable::new();
        let p = PrincipalId::from_bytes([3; 16]);
        let op = DecidedOperation::DestroyKeySet { principal: p };
        let other = DecidedOperation::DestroyKeySet {
            principal: PrincipalId::from_bytes([4; 16]),
        };
        let id = DecisionId::new(1);
        assert!(t.register_op(id, &op, &[], 100, 0).is_ok());
        assert!(t.register_op(id, &op, &[], 200, 0).is_ok());
        assert_eq!(
            t.register_op(id, &other, &[], 100, 0).map_err(|d| d.reason),
            Err(AuditReason::DecisionConflict)
        );
        for n in 2..=keyd_types::MAX_DESTROY_DECISIONS as u64 {
            assert!(t.register_op(DecisionId::new(n), &op, &[], 100, 0).is_ok());
        }
        assert_eq!(
            t.register_op(DecisionId::new(5000), &op, &[], 100, 0)
                .map_err(|d| d.reason),
            Err(AuditReason::DecisionTableFull)
        );
        // Expiry makes room.
        assert!(t
            .register_op(DecisionId::new(5000), &op, &[], 300, 101)
            .is_ok());
        assert_eq!(t.len(), 1);
    }

    /// docs/52 §4.6: the listing pages ascending, skips executed decisions,
    /// and says where the next page starts.
    #[test]
    fn destructions_page_in_order() {
        let mut t = DecisionTable::new();
        let count = MAX_DESTROY_DECISION_PAGE as u64 + 3;
        for n in 1..=count {
            let op = DecidedOperation::DestroyKeySet {
                principal: PrincipalId::from_bytes([n as u8; 16]),
            };
            assert!(t.register_op(DecisionId::new(n), &op, &[], 100, 0).is_ok());
        }
        t.record(DecisionFamily::Destroy, DecisionId::new(1), Recorded::Done);
        let first = t.pending_destructions(None, 0);
        assert_eq!(first.entries.len(), MAX_DESTROY_DECISION_PAGE);
        assert_eq!(first.entries[0].decision, DecisionId::new(2));
        let next = first.next.unwrap();
        let second = t.pending_destructions(Some(next), 0);
        assert_eq!(second.entries.len(), 2);
        assert_eq!(second.next, None);
    }

    /// docs/51 §5.6: at most three approvers, pairwise distinct, two for a
    /// key operation.
    #[test]
    fn approvers_are_bounded_distinct_and_dual_for_key_operations() {
        let a = PrincipalId::from_bytes([1; 16]);
        let b = PrincipalId::from_bytes([2; 16]);
        let c = PrincipalId::from_bytes([3; 16]);
        let d = PrincipalId::from_bytes([4; 16]);
        assert!(approvers_fit(DecisionFamily::KeyOperation, &[a, b]));
        assert!(approvers_fit(DecisionFamily::KeyOperation, &[a, b, c]));
        assert!(!approvers_fit(DecisionFamily::KeyOperation, &[a]));
        assert!(!approvers_fit(DecisionFamily::KeyOperation, &[a, a]));
        assert!(!approvers_fit(DecisionFamily::KeyOperation, &[a, b, c, d]));
        assert!(approvers_fit(DecisionFamily::Destroy, &[]));
        assert!(approvers_fit(DecisionFamily::SetSecret, &[]));
        assert!(!approvers_fit(DecisionFamily::Destroy, &[b, b]));
    }
}
