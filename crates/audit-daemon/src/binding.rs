//! The source binding of the event shapes: each shape is accepted only from
//! the one process that sends it.
//!
//! | shape | only from | why |
//! |---|---|---|
//! | `Kdc` | kdc | `kdc::AuditEvent` (docs/50 §8.1) |
//! | `Keyd` | keyd | `keyd::AuditRecord` (docs/50 §8.1; docs/10 §10) |
//! | `Ldap` | dird | the LDAP events are written by dird, the PEP, not by the front (docs/50 §4.2; R49-14) |
//! | `DirAdmin` | dird | dird is the source of the admin write events (docs/51 §5.7 item 1) |
//! | `Admind` | admind | admind sends its own events (docs/51 §5.7 item 3) |
//! | `WindowSummary` | any mapped source | every sender's window writes one (Q-252 item 8, A-57) |
//!
//! ldap-front sends no events (crates/ldap-front audit.rs), so no shape is
//! bound to it.
//!
//! The source of every record is the connection's peer uid, never a field
//! (docs/50 §3.2, §8.1). A shape from any other source is a forgery attempt
//! by a mapped but compromised sender (docs/50 §8.1: "a compromised kdc can
//! add false records"): auditd refuses the whole batch — nothing of it is
//! persisted, the reply is `Refused::Malformed`, the connection closes, and
//! the refusal is counted for the next `Auditd` summary record
//! ([`crate::own_event::EventsMisbound`]), as an unmapped uid is (docs/50
//! §3.2: "closed + an audit record").
//!
//! The check reads only an event's format and shape octets
//! (`ipc_audit::peek_shape`): the payloads stay opaque and auditd gains no
//! event parser (AGENTS.md §6; crate::lib "payloads stored opaque"). A
//! payload that does not name a known shape in the current event format is
//! **not** bound and is stored as before (decided on docs/questions/Q-341:
//! option (a) — "opaque payloads keep their current behaviour").
//!
//! Spec: docs/50 §3.2, §4.2, §8.1, R50-3; docs/51 §5.7 (R51-12, A-72);
//! docs/questions/Q-252 item 8, Q-341 (option (a)).

use audit_log::Source;
use ipc_audit::{peek_shape, EventBytes, EventShape};

/// The one source allowed to send `shape`; `None` for `WindowSummary`,
/// which any mapped source may send.
///
/// Spec: this module's table; docs/50 §4.2, §8.1; docs/51 §5.7 items 1
/// and 3; docs/questions/Q-341 (option (a)).
#[must_use]
pub const fn bound_source(shape: EventShape) -> Option<Source> {
    match shape {
        EventShape::Kdc => Some(Source::Kdc),
        EventShape::Keyd => Some(Source::Keyd),
        EventShape::Ldap | EventShape::DirAdmin => Some(Source::Dird),
        EventShape::Admind => Some(Source::Admind),
        EventShape::WindowSummary => None,
    }
}

/// The binding table a listener enforces: for each shape, the one source
/// allowed to send it (`None` = any mapped source).
///
/// The daemon always enforces [`PRODUCTION`] ([`crate::listener::ListenerConfig::from_settings`];
/// the configuration file has no key for it). The table is a listener
/// parameter only so that a test harness whose senders all share one uid —
/// and therefore one mapped source (R50-3: one source per uid) — can enforce
/// the table that matches its own single-label world; per-daemon binding
/// with distinct uids is covered by this crate's tier-2 tests and the
/// tier-3 e2e test (docs/questions/Q-310, Q-341).
///
/// Spec: docs/50 §3.2, §8.1; docs/questions/Q-341 (option (a)), A-85.
pub type BindingTable = fn(EventShape) -> Option<Source>;

/// The table of this module's documentation: the only table the daemon
/// enforces.
///
/// Spec: this module's table; docs/questions/Q-341 (option (a)).
pub const PRODUCTION: BindingTable = bound_source;

/// Whether a connection whose peer uid maps to `source` may send `event`,
/// under the [`PRODUCTION`] table.
///
/// Spec: this module; docs/50 §3.2.
#[must_use]
pub fn permits(source: Source, event: &EventBytes) -> bool {
    permits_under(PRODUCTION, source, event)
}

/// Whether a connection whose peer uid maps to `source` may send `event`,
/// under `table`.
///
/// Spec: this module; docs/50 §3.2.
#[must_use]
pub fn permits_under(table: BindingTable, source: Source, event: &EventBytes) -> bool {
    match peek_shape(event.as_bytes()).and_then(table) {
        Some(required) => required == source,
        None => true,
    }
}

/// Whether `source` may send every event of a batch. One misbound event
/// refuses the whole batch (nothing of it is persisted).
///
/// Spec: this module; docs/50 §8.1 (a batch is persisted, then
/// acknowledged, as a whole).
#[must_use]
pub fn batch_permitted(source: Source, events: &[EventBytes]) -> bool {
    batch_permitted_under(PRODUCTION, source, events)
}

/// Whether `source` may send every event of a batch under `table`.
///
/// Spec: this module; docs/50 §8.1.
#[must_use]
pub fn batch_permitted_under(table: BindingTable, source: Source, events: &[EventBytes]) -> bool {
    events
        .iter()
        .all(|event| permits_under(table, source, event))
}
