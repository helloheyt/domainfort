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
//! request octets); AGENTS.md §6; docs/questions/Q-367 (A-88); docs/52
//! §3.10, §4.2, §4.4 (A-102).

use crate::ceremony::{CeremonyReport, MissingSalt, NotSent, Outcome, Step, Unknown};
use ipc::Refused;
use ipc_keyd::TransportError;
use keyd_types::{Error as KeydError, MAX_INITIAL_SECRET_GRANT_SECS};
use provision_manifest::Manifest;

/// Exit status: all three key sets created, every first administrator's
/// initial secret granted, and keyd's ceremony sealed (A-102).
pub const EXIT_COMPLETE: u8 = 0;

/// Exit status: nothing was attempted on keyd's key store — a usage,
/// configuration, manifest or identity error, or the contact failed.
pub const EXIT_NOTHING_ATTEMPTED: u8 = 1;

/// Exit status: at least one `create_key` was attempted and the ceremony did
/// not complete (see the report for which key sets exist and which grants
/// were registered).
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

/// The identifiers of a first administrator's grant: `<sam>: principal
/// <guid> purpose PrincipalLongterm binding <b>`.
fn grant_identifiers(admin: usize, manifest: &Manifest) -> String {
    match manifest.first_admins().get(admin) {
        Some(first_admin) => {
            let key_set = first_admin.key_set();
            format!(
                "{}: principal {} purpose {:?} binding {}",
                first_admin.sam_account_name(),
                key_set.guid_text(),
                key_set.handle.purpose,
                key_set.binding_text()
            )
        }
        // Cannot happen: the report's indexes come from this manifest.
        None => format!("administrator #{admin}"),
    }
}

/// The lines of the first administrators' grants (task A15a).
/// Spec: docs/51 §4.3 steps 11-12, §5.8 option (b); docs/questions/Q-451.
fn render_grants(report: &CeremonyReport, manifest: &Manifest, lines: &mut Vec<String>) {
    for grant in &report.grants {
        let ids = grant_identifiers(grant.admin, manifest);
        lines.push(match grant.outcome {
            Outcome::Answered(Ok(())) => format!(
                "granted the initial secret of first administrator {ids}; live for {} s",
                MAX_INITIAL_SECRET_GRANT_SECS
            ),
            Outcome::Answered(Err(error)) => format!(
                "first administrator {ids}: keyd refused the grant ({}); not granted",
                keyd_error_text(error)
            ),
            Outcome::NotSent(reason) => format!(
                "first administrator {ids}: {}; not granted",
                not_sent_text(reason)
            ),
            Outcome::NotPerformed(refused) => format!(
                "first administrator {ids}: {}; not granted",
                not_performed_text(refused)
            ),
            Outcome::Unknown(reason) => format!(
                "first administrator {ids}: {} after the request was sent; outcome unknown, the grant MAY have been registered",
                unknown_text(reason)
            ),
        });
    }
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
    render_grants(report, manifest, &mut lines);
    if let Some(seal) = report.seal {
        lines.push(match seal {
            Outcome::Answered(Ok(())) => "keyd's ceremony sealed".to_owned(),
            Outcome::Answered(Err(error)) => {
                format!("keyd refused the seal ({})", keyd_error_text(error))
            }
            Outcome::NotSent(reason) => format!("seal: {}", not_sent_text(reason)),
            Outcome::NotPerformed(refused) => format!("seal: {}", not_performed_text(refused)),
            Outcome::Unknown(reason) => format!(
                "seal: {} after the request was sent; outcome unknown, keyd MAY be sealed",
                unknown_text(reason)
            ),
        });
    }
    let created = report.created().len();
    let granted = report
        .grants
        .iter()
        .filter(|grant| grant.outcome.succeeded())
        .count();
    if report.is_complete() {
        lines.push(format!(
            "ceremony complete and sealed: {created} of {} key sets created; {granted} of {} first administrators' initial secrets granted",
            Step::ALL.len(),
            report.first_admins
        ));
        lines.push(
            "keyd is sealed: create_key and initial-secret grants no longer exist in keyd until it restarts with an empty store (development mode: every restart - P-17, A-77); from now on keyd changes keys only on decisions dird registers (docs/52 4.4, A-102)".to_owned(),
        );
        lines.push(format!(
            "run provision first-admin-secret within {} minutes: the grants registered before the seal live that long, and keyd refuses a set_secret without its grant (docs/51 5.8)",
            MAX_INITIAL_SECRET_GRANT_SECS / 60
        ));
        return lines;
    }
    if report.grants_registered() {
        lines.push(format!(
            "ceremony stopped at the seal: {created} of {} key sets created; {granted} of {} first administrators' initial secrets granted; keyd is NOT known to be sealed",
            Step::ALL.len(),
            report.first_admins
        ));
        lines.push(
            "keyadm never retries: restart keyd before running the ceremony again (development mode: every key is lost - docs/51 4.5, A-77)".to_owned(),
        );
        return lines;
    }
    if report.key_sets_created() {
        lines.push(format!(
            "ceremony stopped after the key sets: {created} of {} key sets created; {granted} of {} first administrators' initial secrets granted",
            Step::ALL.len(),
            report.first_admins
        ));
        if report
            .grants
            .iter()
            .any(|grant| grant.outcome == Outcome::Answered(Err(KeydError::Denied)))
        {
            lines.push(
                "keyd answers one uniform \"denied\": keyd grants keyadm only the initial secret of a user that has no key set yet; keyd's audit record names the reason".to_owned(),
            );
        }
        lines.push(
            "keyd is NOT sealed; keyadm never retries: restart keyd (development mode: every key is lost) and run the whole ceremony again (docs/51 4.5, A-77)".to_owned(),
        );
        return lines;
    }
    if report.steps.is_empty() {
        lines.push("ceremony not started: no create_key was sent; keyd is not sealed".to_owned());
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
        "keyd is NOT sealed; create_key never overwrites and keyadm never retries: restart keyd (development mode: every key is lost) and run the whole ceremony again (docs/51 4.5, A-77)".to_owned(),
    );
    lines
}

/// The lines of a ceremony refused before anything was sent: the manifest
/// names no salt for a first administrator (A-102, docs/52 N4).
/// Spec: docs/52 §4.2; docs/51 §4.3 steps 8, 11.
#[must_use]
pub fn render_missing_salt(missing: MissingSalt, manifest: &Manifest) -> Vec<String> {
    let who = manifest.first_admins().get(missing.admin).map_or_else(
        || format!("#{}", missing.admin),
        |admin| admin.sam_account_name().to_owned(),
    );
    vec![
        format!(
            "keyadm ceremony: the manifest names no salt for first administrator {who} (first_admin_salts); nothing was sent to keyd"
        ),
        "keyd binds each initial-secret grant's salt (docs/52 N4): re-run provision domain, which writes every first administrator's salt into the manifest".to_owned(),
    ]
}

// ---------------------------------------------------------------------------
// The decision commands and the sweep (task A10; A-102).
// ---------------------------------------------------------------------------

/// The text of a principal id, in the provisioning manifest's GUID form:
/// dtyp's one GUID text mapping (A-86 follow-up).
/// Spec: [MS-DTYP] 2.5.1.1; [MS-DRSR] 5.16.3.16; A-31; docs/47 §2.3
/// (`PrincipalId = objectGUID`).
fn principal_text(principal: &keyd_types::PrincipalId) -> String {
    dtyp::Guid::from_packet(principal.as_bytes()).to_text()
}

/// The exit status of an execution: 0 keyd performed the decided operation;
/// 1 keyd changed nothing it could have (not sent, not performed); 2 keyd
/// received it and something is left to check (refused — keyd's audit
/// names why — or outcome unknown).
/// Spec: docs/51 §6; docs/questions/Q-370 item 12 (A-90: 2 = check keyd's
/// audit log); docs/52 §3.10.
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
/// Spec: docs/51 §6; docs/52 §3.10, §4.2; docs/10 §10 (identifiers only).
#[must_use]
pub fn render_execution(report: &crate::execute::ExecutionReport) -> Vec<String> {
    let mut lines = vec![format!(
        "keyadm {}: decision {}",
        report.command.name(),
        report.decision.get()
    )];
    lines.push(match report.keyd {
        Outcome::Answered(Ok(Some(kvno))) => format!(
            "keyd ran the decided operation: new kvno {} (presenting this decision again returns this result; it never runs twice)",
            kvno.get()
        ),
        Outcome::Answered(Ok(None)) => "keyd ran the decided operation (presenting this decision again returns this result; it never runs twice)".to_owned(),
        Outcome::Answered(Err(error)) => format!(
            "keyd refused ({}): no such decision, a decision of another kind, expired, or this account is not Role::Admin - keyd's audit record names the reason; nothing was changed",
            keyd_error_text(error)
        ),
        Outcome::NotSent(reason) => format!("keyd: {}", not_sent_text(reason)),
        Outcome::NotPerformed(refused) => format!("keyd: {}", not_performed_text(refused)),
        Outcome::Unknown(reason) => format!(
            "keyd: {} after the request was sent; outcome unknown - run the same command again: keyd returns the recorded result of the decision, it never runs it twice (docs/52 3.10)",
            unknown_text(reason)
        ),
    });
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

/// An outcome without a success value, as a fixed text.
fn outcome_text(outcome: &Outcome<()>) -> String {
    match outcome {
        Outcome::Answered(Ok(())) => "keyd answered ok".to_owned(),
        Outcome::Answered(Err(error)) => format!("keyd answered {}", keyd_error_text(*error)),
        Outcome::NotSent(reason) => not_sent_text(*reason).to_owned(),
        Outcome::NotPerformed(refused) => not_performed_text(*refused).to_owned(),
        Outcome::Unknown(reason) => format!(
            "{} after the request was sent; outcome unknown",
            unknown_text(*reason)
        ),
    }
}

/// The lines of a sweep's report.
/// Spec: docs/51 §6, §9; docs/52 §4.3; docs/10 §7, §10 (identifiers only).
#[must_use]
pub fn render_sweep(report: &crate::sweep::SweepReport) -> Vec<String> {
    use crate::sweep::Stopped;
    let mut lines = vec!["keyadm destroy-sweep: the destroy decisions dird registered".to_owned()];
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
    for entry in &report.destroyed {
        lines.push(format!(
            "destroyed: decision {} principal {} (its PrincipalLongterm and Service key sets)",
            entry.decision.get(),
            principal_text(&entry.principal)
        ));
    }
    for entry in &report.skipped {
        lines.push(format!(
            "skipped: decision {} principal {}: keyd answered denied (expired or no longer pending - keyd's audit names the reason)",
            entry.decision.get(),
            principal_text(&entry.principal)
        ));
    }
    lines.push(format!(
        "{} pending destroy decision(s) listed; {} run now; {} skipped",
        report.listed,
        report.destroyed.len(),
        report.skipped.len()
    ));
    match &report.stopped {
        None => lines.push("sweep complete".to_owned()),
        Some(Stopped::Listing(outcome)) => lines.push(format!(
            "sweep stopped: the listing failed: {}; run the sweep again later",
            outcome_text(outcome)
        )),
        Some(Stopped::ListingLooped) => lines.push(
            "sweep stopped: the listing did not move forward; nothing more was asked".to_owned(),
        ),
        Some(Stopped::RetryLater { entry, outcome }) => lines.push(format!(
            "sweep stopped at decision {} principal {}: {}; retry later - the sweep is idempotent",
            entry.decision.get(),
            principal_text(&entry.principal),
            outcome_text(outcome)
        )),
    }
    lines
}
