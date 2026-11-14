//! `keyadm ceremony`: create the krbtgt key set and the two service key sets
//! the provisioning manifest names, grant the first administrators' initial
//! secrets, and **seal** keyd's ceremony (docs/51 §4.3 step 11; A-102,
//! docs/52 R3).
//!
//! # The steps
//!
//! 1. **Contact** — one `ping` (every mapped role may call it, docs/50
//!    §3.4). The ipc-keyd client checks the peer uid of the new connection
//!    against the configured keyd uid **before it sends anything** (R50-3;
//!    A-63) — a process that took over the socket path receives nothing.
//!    `ping` creates nothing, so a failure here means no key set was
//!    touched.
//! 2. **`create_key` ×3, in order** — `(GUID_krbtgt, Krbtgt)` with
//!    NT-SRV-INST [krbtgt, REALM]; `(GUID_ldap, Service)` with NT-SRV-HST
//!    [ldap, fqdn]; `(GUID_admin, AdminService)` with NT-SRV-HST [admind,
//!    fqdn] — the admin service's own purpose, whose tickets keyd opens only
//!    bound to an operation (R2, docs/52 §5 item 3; A-102) (docs/51 §4.3
//!    step 11; docs/47 §1.4, §9.1; docs/10 §5ב, §7; A-19, A-73). The purpose
//!    comes from the manifest's key table. keyd draws the keys and chooses
//!    the kvno (A-35); keyadm only asks.
//! 3. **`grant_set_secret` for each first administrator, in the manifest's
//!    order** (task A15a; docs/questions/Q-451) — a user's one key target,
//!    `(GUID, PrincipalLongterm)` with its NT-PRINCIPAL [sAMAccountName]
//!    binding exactly as the manifest gives it to `provision
//!    first-admin-secret` **and the salt the manifest names for it**
//!    (`first_admin_salts`, written by `provision domain` with the
//!    directory's salt function — A-102, docs/52 N4: keyd binds the salt
//!    too), live for `MAX_INITIAL_SECRET_GRANT_SECS` (15 minutes). keyd
//!    refuses Role::Directory's `set_secret` without such a grant (docs/51
//!    §5.8 option (b)); dird, which registers the decisions of every later
//!    password set, does not run yet. keyd grants Role::Admin only a user's
//!    **initial** secret (no key set yet) — so this step can never be used to
//!    reset an existing password past dird's PDP. Every manifest names each
//!    first administrator's salt — `first_admin_salts` is a required key
//!    (A-105, docs/questions/Q-473) — so a manifest without one never
//!    reaches the ceremony: it does not parse.
//! 4. **`seal_ceremony`** (A-102, docs/52 R3; docs/questions/Q-462 item 1)
//!    — keyd moves from `Provisioning` to `Operational`: `create_key` and
//!    Role::Admin's grants **no longer exist** in keyd until it restarts
//!    with an empty store (in development mode, every restart — P-17,
//!    A-77). After the seal keyadm can do nothing in keyd that is not a
//!    decision dird registered. The grants registered in step 3 live until
//!    they expire, so `provision first-admin-secret` still runs after the
//!    seal, within their 15 minutes.
//!
//! # Stop at the first failure, never retry
//!
//! keyd's `create_key` refuses a handle that already has a key set
//! (crates/keyd admin.rs, `KeyExists`), but reports that — like every other
//! refusal before its work (wrong role, binding refused, store refusing a
//! critical key) — as the one uniform `Denied` (docs/10 §9; the reason goes
//! only to keyd's audit record). keyadm therefore cannot tell "already
//! created" from "refused", and does not guess: it stops at the first step
//! that did not succeed, and never repeats a request whose fate it does not
//! know (a repeat could only be refused — `create_key` never overwrites —
//! but a blind repeat would hide the earlier outcome). A ceremony that stops
//! before the seal leaves keyd **not sealed** (the report says so): restart
//! keyd, which loses every key in development mode (P-17) and starts in
//! `Provisioning` again, and run the whole ceremony again (A-77; docs/51
//! §4.5).
//!
//! # What each outcome means
//!
//! The ipc-keyd client says what it knows of a request keyd did not answer
//! (`KeydClient::call_with_fate`, `ipc_keyd::RequestFate`: not sent / not
//! performed / outcome unknown — docs/questions/Q-367, A-88); keyadm
//! reports exactly that.
//!
//! | outcome | created? |
//! |---|---|
//! | keyd answered `Ok(kvno)` | yes, with that kvno |
//! | keyd answered `Err(Denied / Unavailable / RateLimited)` | no — keyd refuses before it stores anything |
//! | not sent: peer uid not keyd's, connect failed, peer credentials unreadable, the deadline passed before sending, unencodable | no — nothing left this process |
//! | not performed: `Refused::Busy` / `Unavailable` / `Malformed` / `VersionMismatch` | no — keyd-daemon refuses a key-state change only before keyd runs it (A-88: `Busy` while auditd is away, `Unavailable` when the intent was not acknowledged in time — keyd's audit then holds the intent and a `NotPerformed` outcome) |
//! | outcome unknown: the request was sent and the connection failed, the deadline passed, or the reply could not be read | **maybe** — keyd's audit log holds the intent and the outcome; check it before anything else |
//!
//! Spec: docs/51 §4.3 steps 10-12, §4.5, §6; docs/10 §2, §7, §9, §10;
//! docs/50 R50-3, §3.4, §3.6, §3.7; docs/52 §4.2 (N4), §4.4 (R3); A-19;
//! A-35; A-63; A-73; A-77; docs/questions/Q-365, Q-367 (A-88), Q-462 item
//! 1 (A-102).

use ipc::Refused;
use ipc_keyd::{
    Answer, Call, CallFailure, Connector, KeydClient, RequestFate, TransportError, Unserved,
};
use keyd_types::{
    AccountKind, Error as KeydError, Kvno, SetSecretTarget, MAX_INITIAL_SECRET_GRANT_SECS,
};
use provision_manifest::{KeySet, Manifest};

/// The ceremony's key sets, in the order they are created.
/// Spec: docs/51 §4.3 step 11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// `(GUID_krbtgt, Krbtgt)`, NT-SRV-INST [krbtgt, REALM]. Spec: docs/47
    /// §1.4; RFC 4120 §7.3.
    Krbtgt,
    /// `(GUID_ldap, Service)`, NT-SRV-HST [ldap, fqdn]. Spec: docs/10 §5ב;
    /// RFC 4120 §6.2.1.
    LdapService,
    /// `(GUID_admin, AdminService)`, NT-SRV-HST [admind, fqdn]. Spec: A-73;
    /// docs/52 §5 item 3 (R2: the admin service's own purpose);
    /// RFC 4120 §6.2.1.
    AdminService,
}

impl Step {
    /// Every step, in order. Spec: docs/51 §4.3 step 11.
    pub const ALL: [Step; 3] = [Step::Krbtgt, Step::LdapService, Step::AdminService];

    /// A fixed label for the report.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Step::Krbtgt => "krbtgt",
            Step::LdapService => "ldap service",
            Step::AdminService => "admin service",
        }
    }

    /// The step's key set (handle and binding) as the manifest fixes it.
    /// Spec: docs/51 §4.3 steps 8, 11.
    #[must_use]
    pub fn key_set(self, manifest: &Manifest) -> &KeySet {
        match self {
            Step::Krbtgt => manifest.krbtgt(),
            Step::LdapService => manifest.ldap_service(),
            Step::AdminService => manifest.admin_service(),
        }
    }
}

/// Why a request never left this process.
/// Spec: docs/50 R50-3, §3.7; crates/ipc-keyd client (`Unserved`,
/// `RequestFate::NotSent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotSent {
    /// The socket's peer uid is not the configured keyd uid (R50-3). (Also
    /// a failed `DescribeConfig` check of a client that requires one —
    /// keyadm's never does.)
    PeerMismatch,
    /// The socket could not be connected.
    Connect,
    /// The socket's peer credentials could not be read (on any platform but
    /// Linux they never can — the ipc-keyd connector fails closed).
    PeerCredentials,
    /// The connection failed before the request was written — in keyadm,
    /// the deadline passed while the connection was being opened.
    Transport(TransportError),
    /// The request could not be encoded.
    Unencodable,
}

/// Why keyadm does not know what keyd did with a request it sent.
/// Spec: docs/50 §3.6, §3.7; crates/ipc-keyd client
/// (`RequestFate::OutcomeUnknown`); docs/questions/Q-367 (A-88).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unknown {
    /// The connection failed after the request was handed to it.
    Transport(TransportError),
    /// The reply did not decode.
    MalformedReply,
    /// The reply decoded but did not answer this operation.
    UnexpectedReply,
}

/// How one call to keyd ended, as far as keyadm can know.
/// Spec: module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome<T> {
    /// keyd ran the operation and answered.
    Answered(Result<T, KeydError>),
    /// Nothing reached keyd.
    NotSent(NotSent),
    /// keyd's transport refused the request: keyd did not perform it (A-88).
    NotPerformed(Refused),
    /// The request was sent and may or may not have been performed.
    Unknown(Unknown),
}

impl<T> Outcome<T> {
    /// `true` for `Answered(Ok(_))`.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(self, Outcome::Answered(Ok(_)))
    }

    /// `true` if the call may have changed keyd's state without keyadm
    /// knowing (only [`Outcome::Unknown`]).
    #[must_use]
    pub const fn outcome_unknown(&self) -> bool {
        matches!(self, Outcome::Unknown(_))
    }
}

/// Classify the result of one `KeydClient::call_with_fate`; `pick` takes
/// keyd's answer out of the [`Answer`] variant of the operation called.
///
/// The client's fate decides the class (it alone knows whether the request
/// was written); the `Unserved` reason only chooses the text. A combination
/// the client never produces — a refusal reported as not sent other than by
/// the `DescribeConfig` check, or anything but a `Refused` reported as not
/// performed — falls to the class that claims least: not sent ⇒ the peer
/// check, not performed ⇒ outcome unknown.
///
/// Spec: module documentation; crates/ipc-keyd client (`CallFailure`,
/// `RequestFate`); docs/questions/Q-367 (A-88).
pub fn classify<T>(
    result: Result<Answer, CallFailure>,
    pick: impl FnOnce(Answer) -> Option<Result<T, KeydError>>,
) -> Outcome<T> {
    let failure = match result {
        Ok(answer) => {
            return match pick(answer) {
                Some(answered) => Outcome::Answered(answered),
                None => Outcome::Unknown(Unknown::UnexpectedReply),
            }
        }
        Err(failure) => failure,
    };
    match (failure.fate, failure.unserved) {
        (RequestFate::NotSent, Unserved::Unencodable) => Outcome::NotSent(NotSent::Unencodable),
        (RequestFate::NotSent, Unserved::Transport(TransportError::Connect)) => {
            Outcome::NotSent(NotSent::Connect)
        }
        (RequestFate::NotSent, Unserved::Transport(TransportError::PeerCredentials)) => {
            Outcome::NotSent(NotSent::PeerCredentials)
        }
        (RequestFate::NotSent, Unserved::Transport(other)) => {
            Outcome::NotSent(NotSent::Transport(other))
        }
        (
            RequestFate::NotSent,
            Unserved::PeerMismatch
            | Unserved::Refused(_)
            | Unserved::MalformedReply(_)
            | Unserved::UnexpectedReply(_),
        ) => Outcome::NotSent(NotSent::PeerMismatch),
        (RequestFate::NotPerformed, Unserved::Refused(refused)) => Outcome::NotPerformed(refused),
        (RequestFate::NotPerformed | RequestFate::OutcomeUnknown, Unserved::Transport(error)) => {
            Outcome::Unknown(Unknown::Transport(error))
        }
        (RequestFate::NotPerformed | RequestFate::OutcomeUnknown, Unserved::MalformedReply(_)) => {
            Outcome::Unknown(Unknown::MalformedReply)
        }
        (
            RequestFate::NotPerformed | RequestFate::OutcomeUnknown,
            Unserved::UnexpectedReply(_)
            | Unserved::Refused(_)
            | Unserved::PeerMismatch
            | Unserved::Unencodable,
        ) => Outcome::Unknown(Unknown::UnexpectedReply),
    }
}

/// One `create_key` step and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    /// Which key set.
    pub step: Step,
    /// How the call ended (`Ok(kvno)` when created).
    pub outcome: Outcome<Kvno>,
}

/// One first administrator's initial-secret grant and how it ended (task
/// A15a).
/// Spec: docs/51 §4.3 steps 11-12, §5.8 option (b); docs/questions/Q-451.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantReport {
    /// The administrator's position in the manifest's `first_admins`.
    pub admin: usize,
    /// How the `grant_set_secret` call ended.
    pub outcome: Outcome<()>,
}

/// What the ceremony did: the contact, then the steps attempted (in order;
/// it stops after the first that did not succeed): the three key sets, the
/// first administrators' grants, then the seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyReport {
    /// The `ping` that opened (and verified) the connection.
    pub contact: Outcome<()>,
    /// The `create_key` steps attempted.
    pub steps: Vec<StepReport>,
    /// The `grant_set_secret` steps attempted (task A15a), after all three
    /// key sets were created.
    pub grants: Vec<GrantReport>,
    /// How many first administrators the manifest names (each needs its
    /// grant for the ceremony to be complete).
    pub first_admins: usize,
    /// The `seal_ceremony` call (A-102), sent once every key set was created
    /// and every grant registered; `None` when the ceremony stopped before.
    pub seal: Option<Outcome<()>>,
}

impl CeremonyReport {
    /// `true` if all three key sets were created, every first
    /// administrator's initial secret was granted, and keyd's ceremony was
    /// sealed (A-102).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.grants_registered() && self.is_sealed()
    }

    /// `true` if all three key sets were created and every first
    /// administrator's initial secret was granted (the seal may still be
    /// missing).
    #[must_use]
    pub fn grants_registered(&self) -> bool {
        self.key_sets_created()
            && self.grants.len() == self.first_admins
            && self.grants.iter().all(|grant| grant.outcome.succeeded())
    }

    /// `true` if keyd answered the seal `Ok` (A-102, docs/52 R3).
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        self.seal.as_ref().is_some_and(Outcome::succeeded)
    }

    /// `true` if all three key sets were created (the grants may still be
    /// missing).
    #[must_use]
    pub fn key_sets_created(&self) -> bool {
        self.contact.succeeded()
            && self.steps.len() == Step::ALL.len()
            && self.steps.iter().all(|step| step.outcome.succeeded())
    }

    /// The steps whose key set was created, with the kvno keyd chose.
    #[must_use]
    pub fn created(&self) -> Vec<(Step, Kvno)> {
        self.steps
            .iter()
            .filter_map(|report| match report.outcome {
                Outcome::Answered(Ok(kvno)) => Some((report.step, kvno)),
                _ => None,
            })
            .collect()
    }

    /// The steps never attempted (after the one that stopped the ceremony).
    #[must_use]
    pub fn not_attempted(&self) -> Vec<Step> {
        Step::ALL
            .iter()
            .copied()
            .filter(|step| !self.steps.iter().any(|report| report.step == *step))
            .collect()
    }
}

/// Run the ceremony for `manifest` through `client` (see the module
/// documentation): contact, then `create_key` for each [`Step`] in order,
/// then `grant_set_secret` for each first administrator in order, then
/// `seal_ceremony` — stopping at the first call that does not succeed.
/// Never retries. Each grant binds the salt the manifest names for its
/// administrator (every manifest names one — A-105, Q-473).
///
/// Spec: docs/51 §4.3 step 11, §5.8 option (b); docs/10 §7; docs/50 R50-3;
/// docs/52 §4.2 (N4), §4.4 (R3); A-19; A-35; A-77; docs/questions/Q-367
/// (A-88: each call's fate from the client), Q-451, Q-462 item 1.
pub fn run<C: Connector>(client: &mut KeydClient<C>, manifest: &Manifest) -> CeremonyReport {
    let contact = classify(client.call_with_fate(&Call::Ping), |answer| match answer {
        Answer::Ping(result) => Some(result),
        _ => None,
    });
    let first_admins = manifest.first_admins().len();
    let mut steps = Vec::with_capacity(Step::ALL.len());
    let mut grants = Vec::with_capacity(first_admins);
    if !contact.succeeded() {
        return CeremonyReport {
            contact,
            steps,
            grants,
            first_admins,
            seal: None,
        };
    }
    for step in Step::ALL {
        let key_set = step.key_set(manifest);
        let call = Call::CreateKey {
            handle: key_set.handle,
            binding: key_set.binding.clone(),
        };
        let outcome = classify(client.call_with_fate(&call), |answer| match answer {
            Answer::CreateKey(result) => Some(result),
            _ => None,
        });
        let stop = !outcome.succeeded();
        steps.push(StepReport { step, outcome });
        if stop {
            return CeremonyReport {
                contact,
                steps,
                grants,
                first_admins,
                seal: None,
            };
        }
    }
    for (admin, first_admin) in manifest.first_admins().iter().enumerate() {
        let key_set = first_admin.key_set();
        let call = Call::GrantSetSecret {
            kind: AccountKind::User,
            targets: vec![SetSecretTarget {
                handle: key_set.handle,
                binding: key_set.binding.clone(),
                salt: first_admin.salt().to_owned(),
            }],
            lifetime_secs: MAX_INITIAL_SECRET_GRANT_SECS,
        };
        let outcome = classify(client.call_with_fate(&call), |answer| match answer {
            Answer::GrantSetSecret(result) => Some(result),
            _ => None,
        });
        let stop = !outcome.succeeded();
        grants.push(GrantReport { admin, outcome });
        if stop {
            return CeremonyReport {
                contact,
                steps,
                grants,
                first_admins,
                seal: None,
            };
        }
    }
    // A-102 (docs/52 R3): the ceremony ends with the seal — after it keyd
    // offers Role::Admin nothing that is not a dird decision.
    let seal = classify(
        client.call_with_fate(&Call::SealCeremony),
        |answer| match answer {
            Answer::SealCeremony(result) => Some(result),
            _ => None,
        },
    );
    CeremonyReport {
        contact,
        steps,
        grants,
        first_admins,
        seal: Some(seal),
    }
}
