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
//! Spec: docs/51 §6; docs/10 §7, §9, §10; docs/50 §8.2 (fixed messages, no
//! request octets); AGENTS.md §6.

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
const fn not_sent_text(reason: NotSent) -> &'static str {
    match reason {
        NotSent::PeerMismatch => {
            "the keyd socket's peer uid is not the configured keyd_uid (nothing was sent)"
        }
        NotSent::Connect => "the keyd socket could not be connected (nothing was sent)",
        NotSent::PeerCredentials => {
            "the keyd socket's peer credentials could not be read; keyadm runs on Linux only (nothing was sent)"
        }
        NotSent::Unencodable => "the request could not be encoded (nothing was sent)",
    }
}

/// Why keyd did not run a request, as a fixed text.
const fn not_run_text(refused: Refused) -> &'static str {
    match refused {
        Refused::Busy => "keyd is busy or cannot reach auditd (request not run)",
        Refused::Malformed => "keyd refused the request as malformed (request not run)",
        Refused::VersionMismatch => "keyd speaks another channel version (request not run)",
        Refused::Unavailable => "keyd is unavailable",
    }
}

/// Why an outcome is unknown, as a fixed text.
const fn unknown_text(reason: Unknown) -> &'static str {
    match reason {
        Unknown::Transport(TransportError::Closed) => "keyd closed the connection",
        Unknown::Transport(TransportError::DeadlineExceeded) => "keyd did not answer in time",
        Unknown::Transport(TransportError::Framing) => "keyd's reply did not frame",
        Unknown::Transport(_) => "the connection to keyd failed",
        Unknown::RefusedUnavailable => "keyd answered unavailable",
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
        Outcome::NotRun(refused) => format!(
            "contact failed: {}; no key set was touched",
            not_run_text(refused)
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
            Outcome::NotRun(refused) => {
                format!("{label}: {}; not created: {ids}", not_run_text(refused))
            }
            Outcome::Unknown(reason) => format!(
                "{label}: {}; the key set MAY have been created: {ids}",
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
    lines.push(
        "create_key never overwrites and keyadm never retries: in development mode restart keyd (every key is lost) and run the whole ceremony again (docs/51 4.5, A-77)".to_owned(),
    );
    lines
}
