//! What `provision first-admin-secret` did, and how it is printed: handles,
//! bindings and kvnos only — identifiers, none secret (docs/47 §2.3; docs/10
//! §10: keyd's own audit record carries the same fields). There is no
//! password in a report: it is never stored in one, and every text here is
//! fixed or an identifier the manifest parser validated.
//!
//! Exit status: 0 — every first administrator's password was set; 1 —
//! nothing was sent to keyd's `set_secret` (refused before, or keyd not
//! reached); 2 — stopped after a `set_secret` was attempted (the report
//! says which were set, which not, and which are unknown).
//!
//! Spec: docs/51 §4.3 step 12 ("→ kvno"), §4.4 ("no secret in the
//! output"), §4.5 (A-77); docs/10 §9, §10; A-35; A-88; A-90; docs/50 §8.2.

use keyd_types::{Error as KeydError, Kvno};

use super::keyd::{keyd_error_text, not_performed_text, not_sent_text, unknown_text, Outcome};

/// Exit status: every password set.
pub const EXIT_COMPLETE: u8 = 0;

/// Exit status: no `set_secret` was sent.
pub const EXIT_NOTHING_SENT: u8 = 1;

/// Exit status: stopped after a `set_secret` was attempted.
pub const EXIT_INCOMPLETE: u8 = 2;

/// One first administrator's key set, as the manifest names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminKeySet {
    /// The sAMAccountName.
    pub sam: String,
    /// The objectGUID (the handle's principal), as the manifest writes it.
    pub guid: String,
    /// The NT-PRINCIPAL binding, as the manifest writes it.
    pub binding: String,
}

/// One `set_secret` and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    /// Which first administrator (index into [`SecretReport::admins`]).
    pub admin: usize,
    /// How the call ended (`Ok(kvno)` when set).
    pub outcome: Outcome<Kvno>,
}

/// What the command did once every password was entered and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretReport {
    /// The realm.
    pub realm: String,
    /// The first administrators, in the manifest's order.
    pub admins: Vec<AdminKeySet>,
    /// The `ping` that opened (and verified) the connection to keyd.
    pub contact: Outcome<()>,
    /// The `set_secret` calls attempted, in order (the command stops after
    /// the first that did not succeed).
    pub steps: Vec<StepReport>,
}

impl SecretReport {
    /// Every first administrator's password was set.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.contact.succeeded()
            && self.steps.len() == self.admins.len()
            && self.steps.iter().all(|s| s.outcome.succeeded())
    }

    /// The administrators whose password was set, with keyd's kvno.
    #[must_use]
    pub fn set(&self) -> Vec<(&str, Kvno)> {
        self.steps
            .iter()
            .filter_map(|s| match s.outcome {
                Outcome::Answered(Ok(kvno)) => {
                    self.admins.get(s.admin).map(|a| (a.sam.as_str(), kvno))
                }
                _ => None,
            })
            .collect()
    }

    /// The administrators never attempted.
    #[must_use]
    pub fn not_attempted(&self) -> Vec<&str> {
        self.admins
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.steps.iter().any(|s| s.admin == *i))
            .map(|(_, a)| a.sam.as_str())
            .collect()
    }
}

/// The exit status of a report (module documentation).
#[must_use]
pub fn exit_code(report: &SecretReport) -> u8 {
    if report.is_complete() {
        EXIT_COMPLETE
    } else if report.steps.is_empty() {
        EXIT_NOTHING_SENT
    } else {
        EXIT_INCOMPLETE
    }
}

/// `principal <guid> purpose PrincipalLongterm binding <binding>`.
fn identifiers(admin: &AdminKeySet) -> String {
    format!(
        "principal {} purpose PrincipalLongterm binding {}",
        admin.guid, admin.binding
    )
}

/// The report's lines (without the `provision: ` prefix).
/// Spec: module documentation.
#[must_use]
pub fn render(report: &SecretReport) -> Vec<String> {
    let mut lines = vec![format!(
        "first-admin-secret: realm {}, {} first administrators",
        report.realm,
        report.admins.len()
    )];
    lines.push(match report.contact {
        Outcome::Answered(Ok(())) => {
            "keyd reached; its peer uid is admind's configured keyd_uid".to_owned()
        }
        Outcome::Answered(Err(error)) => format!(
            "keyd refused the contact ({}); no password was sent",
            keyd_error_text(error)
        ),
        Outcome::NotSent(reason) => format!(
            "contact failed: {} (nothing was sent); no password was sent",
            not_sent_text(reason)
        ),
        Outcome::NotPerformed(refused) => format!(
            "contact failed: {} (not performed); no password was sent",
            not_performed_text(refused)
        ),
        Outcome::Unknown(ipc_keyd::Unserved::Transport(ipc_keyd::TransportError::Closed)) => {
            "contact failed: keyd closed the connection (is admind's account mapped to Directory in keyd's uid_roles?); no password was sent".to_owned()
        }
        Outcome::Unknown(reason) => format!(
            "contact failed: {}; no password was sent",
            unknown_text(reason)
        ),
    });
    for step in &report.steps {
        let Some(admin) = report.admins.get(step.admin) else {
            continue;
        };
        let sam = &admin.sam;
        let ids = identifiers(admin);
        lines.push(match step.outcome {
            Outcome::Answered(Ok(kvno)) => format!("set {sam}: {ids} kvno {}", kvno.get()),
            Outcome::Answered(Err(error)) => format!(
                "{sam}: keyd refused ({}); password not set: {ids}",
                keyd_error_text(error)
            ),
            Outcome::NotSent(reason) => format!(
                "{sam}: {} (not sent); password not set: {ids}",
                not_sent_text(reason)
            ),
            Outcome::NotPerformed(refused) => format!(
                "{sam}: {} (not performed); password not set: {ids}",
                not_performed_text(refused)
            ),
            Outcome::Unknown(reason) => format!(
                "{sam}: {} after the request was sent; outcome unknown - check before retrying, the password MAY have been set: {ids}",
                unknown_text(reason)
            ),
        });
        if let Outcome::Answered(Ok(kvno)) = step.outcome {
            if kvno != Kvno::INITIAL {
                lines.push(format!(
                    "note: keyd already held a key set for {sam}, so this run installed kvno {} - a re-run against a keyd that still holds the keys simply sets a new kvno (A-35)",
                    kvno.get()
                ));
            }
        }
    }
    let done = report.set().len();
    let total = report.admins.len();
    if report.is_complete() {
        lines.push(format!(
            "complete: {done} of {total} first administrators' passwords set"
        ));
        lines.push(
            "development mode (A-77): keyd keeps keys in memory only - after every keyd restart run keyadm ceremony and then this command again; against a keyd that still holds the key sets this command sets the next kvno (A-35)".to_owned(),
        );
        return lines;
    }
    if report.steps.is_empty() {
        lines.push("not started: no set_secret was sent".to_owned());
        return lines;
    }
    let skipped = report.not_attempted();
    lines.push(format!(
        "stopped: {done} of {total} first administrators' passwords set; not attempted: {}",
        if skipped.is_empty() {
            "none".to_owned()
        } else {
            skipped.join(", ")
        }
    ));
    if report
        .steps
        .iter()
        .any(|s| s.outcome == Outcome::Answered(Err(KeydError::Denied)))
    {
        lines.push(
            "keyd answers one uniform \"denied\" (docs/10 9): admind's account may not be mapped to Directory in keyd's uid_roles, or keyd refused the binding; keyd's audit record names the reason".to_owned(),
        );
    }
    if report.steps.iter().any(|s| s.outcome.outcome_unknown()) {
        lines.push(
            "outcome unknown: the request reached keyd but its answer did not come back; check keyd's audit log before anything else - it holds the set_secret intent and its outcome (docs/10 10, A-88); a repeat installs the next kvno".to_owned(),
        );
    }
    lines.push(
        "this command never retries: run it again for every first administrator once the cause is fixed (keyd chooses the next kvno, A-35)".to_owned(),
    );
    lines
}
