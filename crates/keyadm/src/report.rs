//! The ceremony's report (fixed texts plus non-secret identifiers) and its
//! exit status.
//!
//! What may be printed: the realm, each key set's handle (objectGUID and
//! purpose), its binding, and the kvno keyd chose — all identifiers, none
//! secret (docs/47 §2.3; docs/10 §10: keyd's own audit record carries the
//! same fields). There is no key material to print: keyd never returns any
//! (docs/10 §7, I1). Every identifier printed was validated by the manifest
//! parser to be printable ASCII of a narrow alphabet.
//!
//! A call keyd did not answer is reported as the ipc-keyd client classed
//! it: nothing was sent, keyd did not perform it, or its outcome is unknown
//! (docs/questions/Q-367, A-88).
//!
//! Spec: docs/51 §6; docs/10 §7, §9, §10; docs/50 §8.2 (fixed messages, no
//! request octets); AGENTS.md §6; docs/questions/Q-367 (A-88).

use crate::ceremony::{CeremonyReport, NotSent, Outcome, Step, Unknown};
use ipc::Refused;
use ipc_keyd::TransportError;
use keyd_types::Error as KeydError;
use provision_manifest::Manifest;

/// Exit status: all three key sets created.
pub const EXIT_COMPLETE: u8 = 0;

/// Exit status: nothing was attempted on keyd's key store — a usage,
/// configuration, manifest or identity error, or the contact failed.
pub const EXIT_NOTHING_ATTEMPTED: u8 = 1;

/// Exit status: at least one `create_key` was attempted and the ceremony did
/// not complete (see the report for which key sets exist).
pub const EXIT_INCOMPLETE: u8 = 2;

/// The exit status of a ceremony.
/// Spec: docs/51 §4.3 step 11 (a repeated ceremony fails closed), §4.5.
#[must_use]
pub fn exit_code(report: &CeremonyReport) -> u8 {
    if report.is_complete() {
        EXIT_COMPLETE
    } else if report.steps.is_empty() {
        EXIT_NOTHING_ATTEMPTED
    } else {
        EXIT_INCOMPLETE
    }
}

/// Why nothing was sent, as a fixed text.
/// Spec: docs/50 R50-3, §3.6; docs/questions/Q-367 (A-88: not sent).
const fn not_sent_text(reason: NotSent) -> &'static str {
    match reason {
        NotSent::PeerMismatch => {
            "the keyd socket's peer uid is not the configured keyd_uid (nothing was sent)"
        }
        NotSent::Connect => "the keyd socket could not be connected (nothing was sent)",
        NotSent::PeerCredentials => {
            "the keyd socket's peer credentials could not be read; keyadm runs on Linux only (nothing was sent)"
        }
        NotSent::Transport(TransportError::DeadlineExceeded) => {
            "the deadline passed before the request was sent (nothing was sent)"
        }
        NotSent::Transport(_) => {
            "the connection to keyd failed before the request was sent (nothing was sent)"
        }
        NotSent::Unencodable => "the request could not be encoded (nothing was sent)",
    }
}

/// Why keyd did not perform a request, as a fixed text.
/// Spec: docs/10 §10 (A-88: keyd's `Unavailable` on a key-state change
/// means "not performed"); docs/questions/Q-365 item 7, Q-367.
const fn not_performed_text(refused: Refused) -> &'static str {
    match refused {
        Refused::Busy => "keyd is busy or cannot reach auditd (not performed)",
        Refused::Malformed => "keyd refused the request as malformed (not performed)",
        Refused::VersionMismatch => "keyd speaks another channel version (not performed)",
        Refused::Unavailable => "keyd answered unavailable (not performed)",
    }
}

/// Why an outcome is unknown, as a fixed text.
/// Spec: docs/50 §3.6, §3.7; docs/questions/Q-367 (A-88: outcome unknown).
const fn unknown_text(reason: Unknown) -> &'static str {
    match reason {
        Unknown::Transport(TransportError::Closed) => "keyd closed the connection",
        Unknown::Transport(TransportError::DeadlineExceeded) => "keyd did not answer in time",
        Unknown::Transport(TransportError::Framing) => "keyd's reply did not frame",
        Unknown::Transport(_) => "the connection to keyd failed",
        Unknown::MalformedReply | Unknown::UnexpectedReply => "keyd's reply could not be read",
    }
}

/// keyd's own refusal, as a fixed text.
const fn keyd_error_text(error: KeydError) -> &'static str {
    match error {
        KeydError::Denied => "denied",
        KeydError::Unavailable => "unavailable",
        KeydError::RateLimited => "rate limited",
    }
}

/// The identifiers of a step's key set: `principal <guid> purpose <p>
/// binding <b>`.
fn identifiers(step: Step, manifest: &Manifest) -> String {
    let key_set = step.key_set(manifest);
    format!(
        "principal {} purpose {:?} binding {}",
        key_set.guid_text(),
        key_set.handle.purpose,
        key_set.binding_text()
    )
}

/// The report's lines, for standard output.
/// Spec: module documentation.
#[must_use]
pub fn render(report: &CeremonyReport, manifest: &Manifest) -> Vec<String> {
    let mut lines = vec![format!(
        "keyadm ceremony: realm {}, {} key sets to create",
        manifest.realm().as_str(),
        Step::ALL.len()
    )];
    let contact = match report.contact {
        Outcome::Answered(Ok(())) => "keyd reached; its peer uid is the configured keyd_uid".to_owned(),
        Outcome::Answered(Err(error)) => format!(
            "keyd refused the contact ({}); no key set was touched",
            keyd_error_text(error)
        ),
        Outcome::NotSent(reason) => format!("contact failed: {}", not_sent_text(reason)),
        Outcome::NotPerformed(refused) => format!(
            "contact failed: {}; no key set was touched",
            not_performed_text(refused)
        ),
        Outcome::Unknown(Unknown::Transport(TransportError::Closed)) => {
            "contact failed: keyd closed the connection (is this account mapped to Admin in keyd's uid_roles?); no key set was touched".to_owned()
        }
        Outcome::Unknown(reason) => format!(
            "contact failed: {}; no key set was touched",
            unknown_text(reason)
        ),
    };
    lines.push(contact);
    for step in &report.steps {
        let label = step.step.label();
        let ids = identifiers(step.step, manifest);
        lines.push(match step.outcome {
            Outcome::Answered(Ok(kvno)) => format!("created {label}: {ids} kvno {}", kvno.get()),
            Outcome::Answered(Err(error)) => format!(
                "{label}: keyd refused ({}); not created: {ids}",
                keyd_error_text(error)
            ),
            Outcome::NotSent(reason) => {
                format!("{label}: {}; not created: {ids}", not_sent_text(reason))
            }
            Outcome::NotPerformed(refused) => {
                format!(
                    "{label}: {}; not created: {ids}",
                    not_performed_text(refused)
                )
            }
            Outcome::Unknown(reason) => format!(
                "{label}: {} after the request was sent; outcome unknown, the key set MAY have been created: {ids}",
                unknown_text(reason)
            ),
        });
    }
    let created = report.created().len();
    if report.is_complete() {
        lines.push(format!(
            "ceremony complete: {created} of {} key sets created",
            Step::ALL.len()
        ));
        return lines;
    }
    if report.steps.is_empty() {
        lines.push("ceremony not started: no create_key was sent".to_owned());
        return lines;
    }
    let skipped: Vec<&str> = report.not_attempted().iter().map(|s| s.label()).collect();
    lines.push(format!(
        "ceremony stopped: {created} of {} key sets created; not attempted: {}",
        Step::ALL.len(),
        if skipped.is_empty() {
            "none".to_owned()
        } else {
            skipped.join(", ")
        }
    ));
    if report
        .steps
        .iter()
        .any(|step| step.outcome == Outcome::Answered(Err(KeydError::Denied)))
    {
        lines.push(
            "keyd answers one uniform \"denied\" (docs/10 9): the key set may already exist, this account may not hold Role::Admin, or keyd refused the binding; keyd's audit record names the reason".to_owned(),
        );
    }
    if report
        .steps
        .iter()
        .any(|step| step.outcome.outcome_unknown())
    {
        lines.push(
            "outcome unknown: the request reached keyd but its answer did not come back; check keyd's audit log before anything else - it holds the create_key intent and its outcome (docs/10 10, A-88)".to_owned(),
        );
    }
    lines.push(
        "create_key never overwrites and keyadm never retries: in development mode restart keyd (every key is lost) and run the whole ceremony again (docs/51 4.5, A-77)".to_owned(),
    );
    lines
}

// ---------------------------------------------------------------------------
// The approved-request commands and the sweep (task A10).
// ---------------------------------------------------------------------------

/// The text of a GUID, in the provisioning manifest's form (crates/
/// provision-manifest value.rs `guid_text`; [MS-DTYP] 2.5.1.1 as cited
/// there).
fn guid_text(guid: &dtyp::Guid) -> String {
    let d = guid.data4;
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1, guid.data2, guid.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

/// A refusal status of admind / dird, as a fixed text.
/// Spec: crate ipc-admin `RefusalStatus`; A-26; A-55.
const fn status_text(status: ipc_admin::RefusalStatus) -> &'static str {
    use ipc_admin::RefusalStatus as S;
    match status {
        S::Denied => "denied (is this account keyadm_uid in admind's configuration?)",
        S::ApprovalRequired => "not approved yet: the approvals do not reach the quorum",
        S::NotFound => "no such pending request (unknown, expired, or dropped by a dird restart)",
        S::Invalid => "the request was refused as invalid",
        S::Conflict => "the request was already fetched (one approval, one execution)",
        S::Unavailable => "dird or admind could not serve it now (nothing was done)",
        S::OutcomeUnknown => "admind lost dird's answer: the request MAY have been consumed",
        S::Incomplete => "partly carried out",
    }
}

/// admind's failure, as a fixed text (with whether the request was sent).
fn admind_failure_text(failure: &ipc_admin::AdmindFailure) -> String {
    if failure.sent {
        format!("{failure} after the request was sent; its outcome is unknown")
    } else {
        format!("{failure} (nothing was sent)")
    }
}

/// The key operation, as identifiers.
fn key_operation_text(operation: &ipc_dird_admin::KeyOperation) -> String {
    use ipc_dird_admin::{KeyOperation as K, KeyRef};
    match operation {
        K::RotateKrbtgt => "rotate_krbtgt".to_owned(),
        K::RotateKey { service } => format!("rotate_key of service object {}", guid_text(service)),
        K::RetireKvno { key, kvno } => match key {
            KeyRef::Krbtgt => format!("retire_kvno {kvno} of the krbtgt key set"),
            KeyRef::Service(service) => format!(
                "retire_kvno {kvno} of service object {}",
                guid_text(service)
            ),
        },
    }
}

/// The exit status of an execution: 0 performed and recorded; 1 keyd was
/// not asked; 2 keyd was asked and something is left to check.
/// Spec: docs/51 §6; docs/questions/Q-370 item 12 (A-90: 2 = check keyd's
/// audit log).
#[must_use]
pub fn execution_exit_code(report: &crate::execute::ExecutionReport) -> u8 {
    if report.is_complete() {
        EXIT_COMPLETE
    } else if report.keyd_attempted() {
        EXIT_INCOMPLETE
    } else {
        EXIT_NOTHING_ATTEMPTED
    }
}

/// The lines of an execution's report.
/// Spec: docs/51 §6; docs/10 §10 (identifiers only).
#[must_use]
pub fn render_execution(report: &crate::execute::ExecutionReport) -> Vec<String> {
    use crate::execute::{Completion, Fetch, Mismatch};
    let mut lines = vec![format!(
        "keyadm {}: approved request {}",
        report.command.name(),
        report.id
    )];
    let approved = match &report.fetch {
        Fetch::Fetched(approved) => approved,
        Fetch::Refused(status) => {
            lines.push(format!("fetch refused: {}", status_text(*status)));
            lines.push("keyd was not asked; no key set was touched".to_owned());
            return lines;
        }
        Fetch::Failed(failure) => {
            lines.push(format!("fetch failed: {}", admind_failure_text(failure)));
            lines.push("keyd was not asked; no key set was touched".to_owned());
            return lines;
        }
    };
    let digest: String = approved.digest.iter().map(|b| format!("{b:02x}")).collect();
    lines.push(format!(
        "fetched: {} on principal {}; digest {digest}; requested by {}; approved by {}",
        key_operation_text(&approved.operation),
        guid_text(&approved.principal),
        guid_text(&approved.requester),
        approved
            .approvers
            .iter()
            .map(guid_text)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    match report.mismatch {
        Some(Mismatch::Command(operation)) => lines.push(format!(
            "not executed: the approved operation is {}, not {}; keyd was not asked",
            key_operation_text(&operation),
            report.command.name()
        )),
        Some(Mismatch::Incoherent) => lines.push(
            "not executed: dird's answer is not coherent (purpose, approvers or object); keyd was not asked".to_owned(),
        ),
        None => {}
    }
    if let Some(outcome) = &report.keyd {
        lines.push(match outcome {
            Outcome::Answered(Ok(Some(kvno))) => {
                format!("keyd performed it: new kvno {}", kvno.get())
            }
            Outcome::Answered(Ok(None)) => "keyd performed it".to_owned(),
            Outcome::Answered(Err(error)) => format!(
                "keyd refused ({}); nothing was changed",
                keyd_error_text(*error)
            ),
            Outcome::NotSent(reason) => format!("keyd: {}", not_sent_text(*reason)),
            Outcome::NotPerformed(refused) => format!("keyd: {}", not_performed_text(*refused)),
            Outcome::Unknown(reason) => format!(
                "keyd: {} after the request was sent; outcome unknown - check keyd's audit log (intent + outcome, docs/10 10, A-88) before anything else",
                unknown_text(*reason)
            ),
        });
    }
    match &report.completion {
        Some(Completion::Recorded) => lines.push("completion recorded in dird".to_owned()),
        Some(Completion::Refused(status)) => lines.push(format!(
            "completion NOT recorded in dird: {}",
            status_text(*status)
        )),
        Some(Completion::Failed(failure)) => lines.push(format!(
            "completion NOT recorded in dird: {}",
            admind_failure_text(failure)
        )),
        None => {}
    }
    lines
}

/// The exit status of a sweep: 0 complete; 1 no `destroy_key_set` was sent;
/// 2 stopped after one was — rerun it later (it is idempotent).
/// Spec: docs/51 §6, §9.
#[must_use]
pub fn sweep_exit_code(report: &crate::sweep::SweepReport) -> u8 {
    if report.is_complete() {
        EXIT_COMPLETE
    } else if report.keyd_attempted() {
        EXIT_INCOMPLETE
    } else {
        EXIT_NOTHING_ATTEMPTED
    }
}

/// The lines of a sweep's report.
/// Spec: docs/51 §6, §9; docs/10 §7, §10 (identifiers only).
#[must_use]
pub fn render_sweep(report: &crate::sweep::SweepReport) -> Vec<String> {
    use crate::sweep::Stopped;
    let mut lines = vec!["keyadm destroy-sweep".to_owned()];
    match report.contact {
        Outcome::Answered(Ok(())) => {}
        Outcome::Answered(Err(error)) => {
            lines.push(format!(
                "keyd refused the contact ({}); nothing was destroyed",
                keyd_error_text(error)
            ));
            return lines;
        }
        Outcome::NotSent(reason) => {
            lines.push(format!("contact failed: {}", not_sent_text(reason)));
            return lines;
        }
        Outcome::NotPerformed(refused) => {
            lines.push(format!("contact failed: {}", not_performed_text(refused)));
            return lines;
        }
        Outcome::Unknown(reason) => {
            lines.push(format!("contact failed: {}", unknown_text(reason)));
            return lines;
        }
    }
    for (guid, purpose) in &report.destroyed {
        lines.push(format!(
            "destroyed: principal {} purpose {purpose:?}",
            guid_text(guid)
        ));
    }
    lines.push(format!(
        "{} deleted account(s) listed; {} key set(s) destroyed now; {} already absent",
        report.accounts,
        report.destroyed.len(),
        report.absent
    ));
    match &report.stopped {
        None => lines.push("sweep complete".to_owned()),
        Some(Stopped::ListingRefused(status)) => lines.push(format!(
            "sweep stopped: the listing was refused: {}",
            status_text(*status)
        )),
        Some(Stopped::ListingFailed(failure)) => lines.push(format!(
            "sweep stopped: the listing failed: {}; run the sweep again later",
            admind_failure_text(failure)
        )),
        Some(Stopped::ListingLooped) => lines.push(
            "sweep stopped: the listing did not move forward; nothing more was asked".to_owned(),
        ),
        Some(Stopped::RetryLater {
            guid,
            purpose,
            outcome,
        }) => {
            let why = match outcome {
                Outcome::Answered(Err(error)) => {
                    format!("keyd answered {}", keyd_error_text(*error))
                }
                Outcome::Answered(Ok(())) => "keyd answered ok".to_owned(),
                Outcome::NotSent(reason) => not_sent_text(*reason).to_owned(),
                Outcome::NotPerformed(refused) => not_performed_text(*refused).to_owned(),
                Outcome::Unknown(reason) => format!(
                    "{} after the request was sent; outcome unknown",
                    unknown_text(*reason)
                ),
            };
            lines.push(format!(
                "sweep stopped at principal {} purpose {purpose:?}: {why}; retry later - the sweep is idempotent",
                guid_text(guid)
            ));
        }
    }
    lines
}
