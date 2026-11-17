//! `keyadm ceremony`: create the krbtgt key set and the three service key
//! sets the provisioning manifest names, install the attestation key (task
//! PN9), grant the first administrators' initial secrets, and **seal**
//! keyd's ceremony (docs/51 §4.3 step 11; A-102, docs/52 R3; docs/59 §7.4,
//! §7.5).
//!
//! # The steps
//!
//! 1. **Contact** — one `ping` (every mapped role may call it, docs/50
//!    §3.4). The ipc-keyd client checks the peer uid of the new connection
//!    against the configured keyd uid **before it sends anything** (R50-3;
//!    A-63) — a process that took over the socket path receives nothing.
//!    `ping` creates nothing, so a failure here means no key set was
//!    touched.
//! 2. **`create_key` ×4, in order** — `(GUID_krbtgt, Krbtgt)` with
//!    NT-SRV-INST [krbtgt, REALM]; `(GUID_ldap, Service)` with NT-SRV-HST
//!    [ldap, fqdn]; `(GUID_admin, AdminService)` with NT-SRV-HST [admind,
//!    fqdn] — the admin service's own purpose, whose tickets keyd opens only
//!    bound to an operation (R2, docs/52 §5 item 3; A-102) (docs/51 §4.3
//!    step 11; docs/47 §1.4, §9.1; docs/10 §5b, §7; A-19, A-73); and (task
//!    K9) `(GUID_changepw, ChangePasswordService)` with NT-SRV-INST
//!    [kadmin, changepw] — the change-password service's own purpose, whose
//!    tickets keyd opens only in `open_change_password_request` (RFC 3244 §2;
//!    docs/53 R53-6, §5.2: its key drawn by a fourth `create_key`). The
//!    purpose comes from the manifest's key table. keyd draws the keys and
//!    chooses the kvno (A-35); keyadm only asks.
//! 3. **`install_attestation_key`** (task PN9; docs/59 §7.4, §7.5;
//!    docs/questions/Q-1011 item 2, Q-1033) — the key with which keyd
//!    verifies dird's name resolutions, read from its protected file (crate
//!    attestation_key — the copy `provision domain` writes, task PN12) before
//!    keyd was contacted. keyd installs it once per start, for Role::Admin,
//!    in the ceremony only (its capability table and ceremony state), with
//!    its intent acknowledged by auditd first (a key-state change, A-86);
//!    keyd never returns it, and keyadm never prints it. Every ceremony runs
//!    this step: the file is a required operand since task PN12 (A-183), and
//!    since task PN11 the library has no keyless entry either
//!    ([`run_with_attestation_key`] is the one) — keyd itself refuses to seal
//!    without the key (docs/questions/Q-1056 item 4, A-188), so a ceremony
//!    without it could never complete. After the key sets and before the
//!    grants, so that the grants' 15 minutes start as late as possible.
//! 4. **`grant_set_secret` for each first administrator, in the manifest's
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
//! 5. **`seal_ceremony`** (A-102, docs/52 R3; docs/questions/Q-462 item 1)
//!    — keyd moves from `Provisioning` to `Operational`: `create_key` and
//!    Role::Admin's grants **no longer exist** in keyd until it restarts
//!    with an empty store (in development mode, every restart — P-17,
//!    A-77). After the seal keyadm can do nothing in keyd that is not a
//!    decision dird registered. The grants registered in step 4 live until
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
//! Spec: docs/51 §4.3 steps 10-12, §4.5, §6; docs/53 §5.2, §10 (K9);
//! docs/10 §2, §7, §9, §10;
//! docs/50 R50-3, §3.4, §3.6, §3.7; docs/52 §4.2 (N4), §4.4 (R3); A-19;
//! A-35; A-63; A-73; A-77; docs/questions/Q-365, Q-367 (A-88), Q-462 item
//! 1 (A-102).

use ipc::Refused;
use ipc_keyd::{
    Answer, AttestationKeyOctets, Call, CallFailure, Connector, KeydClient, RequestFate,
    TransportError, Unserved,
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
    /// `(GUID_ldap, Service)`, NT-SRV-HST [ldap, fqdn]. Spec: docs/10 §5b;
    /// RFC 4120 §6.2.1.
    LdapService,
    /// `(GUID_admin, AdminService)`, NT-SRV-HST [admind, fqdn]. Spec: A-73;
    /// docs/52 §5 item 3 (R2: the admin service's own purpose);
    /// RFC 4120 §6.2.1.
    AdminService,
    /// `(GUID_changepw, ChangePasswordService)`, NT-SRV-INST [kadmin,
    /// changepw] (task K9). Spec: RFC 3244 §2; RFC 4120 §6.2; docs/53 R53-6,
    /// §5.2, §10 (K9).
    ChangePasswordService,
}

impl Step {
    /// Every step, in order. Spec: docs/51 §4.3 step 11; docs/53 §5.2 (the
    /// fourth `create_key`, task K9).
    pub const ALL: [Step; 4] = [
        Step::Krbtgt,
        Step::LdapService,
        Step::AdminService,
        Step::ChangePasswordService,
    ];

    /// A fixed label for the report.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Step::Krbtgt => "krbtgt",
            Step::LdapService => "ldap service",
            Step::AdminService => "admin service",
            Step::ChangePasswordService => "change-password service",
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
            Step::ChangePasswordService => manifest.change_password_service(),
        }
    }
}

/// Why a request never left this process.
/// Spec: docs/50 R50-3, §3.7; crates/ipc-keyd client (`Unserved`,
/// `RequestFate::NotSent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotSent {
    /// The socket's peer is not the keyd expected: its uid is not the
    /// configured keyd uid (R50-3), or the new connection's `Ping` probe
    /// failed — keyd does not give this account the Admin role, or refused
    /// or did not answer the probe (task R9; only the probe was sent).
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
/// the new connection's probe, or anything but a `Refused` reported as not
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

/// The attestation key step of a ceremony (task PN9). Every ceremony has
/// one (task PN11: no keyless entry — Q-1056 item 4, A-188).
/// Spec: docs/59 §7.4, §7.5; docs/questions/Q-1033, Q-1056.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationKeyStep {
    /// The ceremony stopped before this step.
    NotAttempted,
    /// The `install_attestation_key` call and how it ended.
    Attempted(Outcome<()>),
}

impl AttestationKeyStep {
    /// `true` if keyd answered the install `Ok`.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        match self {
            AttestationKeyStep::NotAttempted => false,
            AttestationKeyStep::Attempted(outcome) => outcome.succeeded(),
        }
    }
}

/// What the ceremony did: the contact, then the steps attempted (in order;
/// it stops after the first that did not succeed): the four key sets, the
/// attestation key (task PN9), the first administrators' grants, then the
/// seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyReport {
    /// The `ping` that opened (and verified) the connection.
    pub contact: Outcome<()>,
    /// The `create_key` steps attempted.
    pub steps: Vec<StepReport>,
    /// The attestation key step (task PN9), after all four key sets.
    pub attestation_key: AttestationKeyStep,
    /// The `grant_set_secret` steps attempted (task A15a), after all four
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
    /// `true` if all four key sets were created, every first
    /// administrator's initial secret was granted, and keyd's ceremony was
    /// sealed (A-102).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.grants_registered() && self.is_sealed()
    }

    /// `true` if all four key sets were created, the attestation key
    /// installed, and every first administrator's initial secret granted
    /// (the seal may still be missing).
    #[must_use]
    pub fn grants_registered(&self) -> bool {
        self.key_sets_created()
            && self.attestation_key.is_done()
            && self.grants.len() == self.first_admins
            && self.grants.iter().all(|grant| grant.outcome.succeeded())
    }

    /// `true` if keyd answered the attestation key's install `Ok` (task
    /// PN9). Spec: docs/59 §7.4.
    #[must_use]
    pub fn attestation_key_installed(&self) -> bool {
        matches!(
            self.attestation_key,
            AttestationKeyStep::Attempted(Outcome::Answered(Ok(())))
        )
    }

    /// `true` if keyd answered the seal `Ok` (A-102, docs/52 R3).
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        self.seal.as_ref().is_some_and(Outcome::succeeded)
    }

    /// `true` if all four key sets were created (the grants may still be
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
/// then — once the four key sets exist — `install_attestation_key` with
/// `attestation_key` (task PN9), then `grant_set_secret` for each first
/// administrator in order, then `seal_ceremony` — stopping at the first
/// call that does not succeed. Never retries. Each grant binds the salt the
/// manifest names for its administrator (every manifest names one — A-105,
/// Q-473). The key is consumed: its octets are wiped once the call returns,
/// and also when the ceremony stops before the step. The one entry since
/// task PN11: a ceremony without the key could never be sealed (keyd
/// refuses — docs/questions/Q-1056 item 4, A-188).
///
/// Spec: docs/51 §4.3 step 11, §5.8 option (b); docs/10 §7; docs/50 R50-3;
/// docs/52 §4.2 (N4), §4.4 (R3); A-19; A-35; A-77; docs/questions/Q-367
/// (A-88: each call's fate from the client), Q-451, Q-462 item 1; docs/59
/// §7.4, §7.5, §10 (PN9); docs/questions/Q-1011 items 2, 8 (A-173), Q-1033
/// (A-177), Q-1056 (A-188).
pub fn run_with_attestation_key<C: Connector>(
    client: &mut KeydClient<C>,
    manifest: &Manifest,
    attestation_key: AttestationKeyOctets,
) -> CeremonyReport {
    // Task R9: the client's probe of the new connection already checked
    // that keyd gives this account the Admin role; the role in the answer
    // is that one.
    let contact = classify(client.call_with_fate(&Call::Ping), |answer| match answer {
        Answer::Ping(result) => Some(result.map(|_caller_role| ())),
        _ => None,
    });
    let first_admins = manifest.first_admins().len();
    let mut report = CeremonyReport {
        contact,
        steps: Vec::with_capacity(Step::ALL.len()),
        attestation_key: AttestationKeyStep::NotAttempted,
        grants: Vec::with_capacity(first_admins),
        first_admins,
        seal: None,
    };
    if !report.contact.succeeded() {
        return report;
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
        report.steps.push(StepReport { step, outcome });
        if stop {
            return report;
        }
    }
    // Task PN9 (docs/59 §7.4, §7.5): the attestation key, before the seal —
    // keyd installs it only in the ceremony. The call (and with it the key)
    // is dropped, and wiped, when the client returns.
    let call = Call::InstallAttestationKey {
        key: attestation_key,
    };
    let outcome = classify(client.call_with_fate(&call), |answer| match answer {
        Answer::InstallAttestationKey(result) => Some(result),
        _ => None,
    });
    drop(call);
    let stop = !outcome.succeeded();
    report.attestation_key = AttestationKeyStep::Attempted(outcome);
    if stop {
        return report;
    }
    let grants = &mut report.grants;
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
            return report;
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
    report.seal = Some(seal);
    report
}
