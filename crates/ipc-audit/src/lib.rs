#![forbid(unsafe_code)]
//! `ipc-audit`: the audit channel over `ipc`, the canonical encoding of the
//! audit events, and the sender's bounded window (docs/50 R50-17, §8.1, §10
//! task P6 — the library half; the auditd binary is P6b).
//!
//! # Channel (`audit.sock`)
//!
//! Magic [`AUDIT_MAGIC`], version [`AUDIT_VERSION`] (exact), bounds
//! [`REQUEST_BODY_LIMIT`] / [`REPLY_BODY_LIMIT`]:
//!
//! | dir | kind | message | fields |
//! |---|---|---|---|
//! | request | `0x01` | [`Append`] | `first_seq: u64`, `events: seq<bytes<8192>, 16>` |
//! | request | `0x02` | `Ping` | — |
//! | reply | `0x01` | [`Ack`] | `through_seq: u64`, `head_hash: [u8; 32]` |
//! | reply | `0x02` | `Pong` | — |
//! | reply | `0xFF` | `ipc::Refused` | shared, every channel (A-59) |
//!
//! `Ack` comes only after auditd synced the batch (crate `audit-log`):
//! `through_seq` is the sender's number of the last event persisted,
//! `head_hash` the chain hash of its record. No message carries the source:
//! auditd takes it from the connection's peer uid (docs/50 §3.2).
//!
//! # Events
//!
//! [`encode_event`] / [`decode_event`]: `event_format (1) ‖ shape ‖ fields`,
//! one shape per source — [`KdcEvent`] (crates/kdc `AuditEvent`),
//! [`KeydRecord`] (crates/keyd `AuditRecord`), [`LdapEvent`] (crates/ldap
//! `AuditEvent`) — plus [`WindowSummary`]. Each carries exactly the
//! non-secret fields its source exposes; no field can hold a key, password,
//! ticket, PAC, plaintext, ciphertext, attribute value or request octets
//! (docs/37 §2; docs/10 I8; docs/49 §10.1). Client strings are kept only as
//! printable ASCII ≤ 256 octets, else a marker ([`AuditText`]). Codes come
//! from closed tables mirroring the source enumerations by name
//! (crate::codes). The conversions from the source types are behind the
//! features `kdc`, `keyd`, `ldap` — none on by default (decision A-66):
//! each daemon enables only the conversion it sends (keyd-daemon: `keyd`;
//! auditd and dird: none), so a whole-workspace build does not unify the
//! others into them.
//!
//! # Overflow policy (docs/questions/Q-218, A-57)
//!
//! [`SendWindow`]: gating events reserve a slot **before** the operation and
//! are refused when the window is full ([`WindowFull`] — the caller does not
//! issue; keyd answers `Busy`); unauthenticated noise may hold only a share
//! of the window and is otherwise counted into a [`WindowSummary`]; nothing
//! stops the process. "No unaudited issuance, and log overflow does not turn
//! into shutdown."
//!
//! # Security
//!
//! No `unsafe`; no panic, `unwrap` or indexing on a decode path; every
//! length and count is checked against a named bound before use; decoders
//! refuse trailing octets and non-canonical markers, and every decoder
//! round-trips (`encode(decode(b)) == b`, docs/50 §3.3). No error or `Debug`
//! output carries event octets (docs/50 §8.2).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! docs/50 (§1 R50-3, R50-4, R50-7, R50-16, R50-17; §2.4; §3.1-§3.3; §3.6;
//! §3.7; §7.5; §8; §9; §10 and the closing decision, A-58), docs/37 (all),
//! docs/07 §8, docs/questions/Q-218 (A-57), Q-225 (A-59), Q-230, OD-8,
//! PENDING-OWNER (A-57, A-58, P-1), and the public API of crates/ipc,
//! crates/kdc (audit, accounts, transport), crates/keyd (audit, authz,
//! model), crates/ldap (audit, engine), crates/pdp (model), crates/parse-ldap
//! (error, message), crates/dtyp (sid, guid), crates/krb-proto (basic). No
//! other implementation, serializer, RPC framework or audit format was
//! consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/50 R50-17, §3.3, §8.1, §10; docs/37 §2; Q-218 (A-57); A-59.

mod channel;
mod codes;
mod convert;
mod error;
mod event;
mod values;
mod window;

pub use channel::{
    decode_reply, decode_request, encode_reply, encode_request, Ack, Append, AppendCursor,
    AuditReply, AuditRequest, SeqRange, SequenceError, AUDIT_CHANNEL, AUDIT_MAGIC, AUDIT_VERSION,
    KIND_ACK, KIND_APPEND, KIND_PING, KIND_PONG, MAX_BATCH_EVENTS, REPLY_BODY_LIMIT,
    REQUEST_BODY_LIMIT,
};
pub use codes::{
    BindMechanismCode, CodecErrorCode, CodecLimit, EventShape, IpZone, KdcExchange, KdcOutcomeCode,
    KdcReason, KdcTransport, KeyPurposeCode, KeydOperation, KeydOutcome, KeydReason, KeydRole,
    LdapAction, LdapOperationCode, LdapReason, LdapTargetCode, LdapTransport, PdpReasonCode,
    SearchScope, UnsupportedOpCode,
};
pub use error::EventError;
pub use event::{
    decode_event, encode_event, event_round_trip_is_canonical, BindMechanism, EventBody,
    EventBytes, KdcEvent, KdcOutcome, KeyRef, KeydRecord, LdapBind, LdapEvent, LdapOperation,
    LdapSearch, LdapTarget, TransportSecurity, WindowSummary, EVENT_FORMAT, MAX_EVENT_OCTETS,
    MAX_FILTER_ATTRS,
};
pub use values::{
    AuditText, CalendarTime, CodecError, PdpReason, Principal, SidValue, MAX_NAME_COMPONENTS,
    MAX_SID_SUB_AUTHORITIES, MAX_TEXT_OCTETS,
};
pub use window::{NoiseAdmission, Reservation, SendWindow, WindowConfig, WindowError, WindowFull};
