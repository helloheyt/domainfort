//! Which operations change keyd's key state, and the authorization step of
//! an operation run on its own — what a daemon needs to audit the intent of
//! a key-state change **before** keyd performs it (decision A-86).
//!
//! # Why (A-86, docs/questions/Q-346)
//!
//! An issuing operation's reply can be withheld when its audit record cannot
//! be kept (A-57, A-64): nothing leaves keyd unaudited. A key-state change
//! cannot be withheld that way — once keyd ran it, the key set exists, was
//! rotated or was destroyed, irreversibly. So for these operations the daemon
//! first has the record of the **intent** acknowledged by auditd, and only
//! then asks keyd to run the operation; "unavailable" then always means "not
//! done". The precedent is dird's admin writes (docs/51 §5.7 item 2: decision
//! acknowledged ⇒ commit ⇒ outcome).
//!
//! # What is key state
//!
//! [`changes_key_state`]: the six operations that install, rotate, retire or
//! destroy long-term key versions — `set_secret`, `create_key`, `rotate_key`,
//! `rotate_krbtgt`, `retire_kvno`, `destroy_key_set` (docs/10 §6, §7).
//!
//! **Not key state — bookkeeping.** The AS failure throttle and the
//! `verify_secret` throttle (A-34), the replay cache (D33) and the one-time
//! token tables (AuthnProof, TGS / armor / service contexts, D36) change too,
//! but they are bounded, in memory, lost at every start (docs/10 §11; the
//! hold-down covers the replay window), and every change to them only makes
//! keyd *more* restrictive (a counted failure, a remembered authenticator, a
//! consumed or expiring token) — none grants or replaces a key. The
//! operations that touch them keep the A-57 rule: their reply is withheld
//! unless their one record is in the audit window. An intent record for each
//! would put an auditd round trip (a disk sync) in front of every step of
//! every Kerberos exchange.
//!
//! # The authorization step
//!
//! [`Keyd::admits`] runs exactly the first step of every operation
//! ([`Keyd::admit`]: the role in the capability table, I2; each handle's
//! purpose, I3; then the startup hold-down) and nothing else: no key set,
//! token, throttle window or replay-cache entry is read or written, and no
//! audit record is emitted. A daemon uses it to tell an authorization refusal
//! — which changes nothing and is audited exactly as before, one record, no
//! intent — from an operation that may change key state.
//!
//! Spec: docs/10 §2 (I2, I3), §6, §7, §10, §11, §12 I8; docs/questions/Q-346
//! (A-86), Q-365 items 1-3; docs/51 §5.7 item 2 (A-85: the precedent);
//! docs/questions/Q-218 (A-57), Q-252 item 8 (A-64).

use crate::audit::AuditSink;
use crate::authz::{CallerId, HandleSlot, Operation};
use crate::entropy::EntropySource;
use crate::keyd::Keyd;
use crate::model::KeyHandle;
use crate::store::KeyStore;
use krb_proto::KerberosTime;

/// `true` if `op` installs, rotates, retires or destroys long-term key
/// versions: keyd's key state, which cannot be undone once the operation ran
/// (module documentation). The throttles, the replay cache and the token
/// tables are bookkeeping, not key state.
///
/// The match is exhaustive: a new operation does not compile until it is
/// classified here.
///
/// Spec: docs/10 §6 (`set_secret`), §7 (`create_key`, `rotate_key`,
/// `rotate_krbtgt`, `retire_kvno`, `destroy_key_set`); docs/questions/Q-346
/// (A-86).
#[must_use]
pub const fn changes_key_state(op: Operation) -> bool {
    match op {
        Operation::SetSecret
        | Operation::CreateKey
        | Operation::RotateKey
        | Operation::RotateKrbtgt
        | Operation::RetireKvno
        | Operation::DestroyKeySet => true,
        Operation::VerifyPreauth
        | Operation::IssueAsRep
        | Operation::OpenAndVerifyTgt
        | Operation::IssueTgsRep
        | Operation::VerifySecret
        | Operation::OpenFastArmor
        | Operation::SealFastError
        | Operation::OpenAndVerifyServiceTicket
        | Operation::DescribeConfig
        | Operation::Ping => false,
    }
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> Keyd<S, A, E> {
    /// Whether the first step of every operation — the role check (I2), the
    /// purpose check of each `(slot, handle)` (I3), then the startup
    /// hold-down — passes for `caller` running `op` at `now`. It is the same
    /// check the operation itself runs first ([`Keyd::admit`]); here it runs
    /// alone: nothing is read or written beyond the compile-time tables and
    /// the hold-down's end, and **no audit record is emitted** (the
    /// operation, when run, emits its one record as always, I8).
    ///
    /// `false` means the operation would be refused before it touched any
    /// state; `true` does not mean it will succeed (a later step may still
    /// refuse it — an existing key set, a binding, the dual control, an
    /// exhausted kvno — and that refusal is the operation's outcome).
    ///
    /// Spec: docs/10 §2 ("each operation checks: (a) the caller's Role has
    /// it in the table; (b) the handle's KeyPurpose matches"; "(c) — only
    /// after them — the startup hold-down"), §12 I2, I3; docs/questions/Q-346
    /// (A-86).
    #[must_use]
    pub fn admits(
        &self,
        caller: &CallerId,
        op: Operation,
        handles: &[(HandleSlot, &KeyHandle)],
        now: &KerberosTime,
    ) -> bool {
        self.admit(caller, op, handles, now).is_ok()
    }
}
