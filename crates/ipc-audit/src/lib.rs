#![forbid(unsafe_code)]
//! `ipc-audit`: the audit channel over `ipc`, the canonical encoding of the
//! audit events, and the sender's bounded window (docs/50 R50-17, §8.1, §10
//! task P6 — the library half; the auditd binary is P6b). One dependency,
//! crate `ipc`; no feature (task IB1, below).
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
//! | reply | `0x02` | `Pong` | `source: u8` ([`EventSource`]) |
//! | reply | `0xFF` | `ipc::Refused` | shared, every channel (A-59) |
//!
//! `Ack` comes only after auditd synced the batch (crate `audit-log`):
//! `through_seq` is the sender's number of the last event persisted,
//! `head_hash` the chain hash of its record. No request carries the source:
//! auditd takes it from the connection's peer uid (docs/50 §3.2) — and
//! reports it in `Pong`, so that every sender checks on each new connection
//! that auditd records it under its own source (task R9b, docs/questions/
//! Q-512, Q-560).
//!
//! # The audit client and the gate: crate `ipc_audit_client`
//!
//! The one implementation of a sender's link to auditd (task R9b) and the
//! audit gate with the proof of an acknowledged intent it drives (task R6,
//! A-102) are crate `ipc_audit_client`'s, with its own non-optional tokio
//! (owner decision P-12). auditd links only this crate.
//!
//! # No feature changes the graph (task IB1)
//!
//! Until task IB1 this crate carried the client (feature `client`, an
//! optional tokio) and the conversions from the source crates' audit types
//! (features `kdc`, `keyd`, `ldap`, each pulling its source crate in as an
//! optional dependency). Decision A-66 kept them off by default, but cargo
//! unifies features within one build: in a shared build one daemon's
//! feature reached every daemon, linking keyd, krb-crypto and dirstore
//! into processes that must not contain them (class C40, docs/questions/
//! Q-851, decision A-144). Now no manifest of the workspace declares an
//! `optional` dependency: the client is crate `ipc_audit_client`, and each
//! conversion lives on the side that already links its source crate
//! (crates/kdc-daemon, crates/ipc-keyd-server, crates/directory-daemon —
//! each an `audit_convert` module) as plain functions (the orphan rule
//! allows no `From` impl between two foreign types there).
//!
//! # Events
//!
//! [`encode_event`] / [`decode_event`]: `event_format (1) ‖ shape ‖ fields`,
//! one shape per source — [`KdcEvent`] (crates/kdc `AuditEvent`),
//! [`KeydRecord`] (crates/keyd `AuditRecord`), [`LdapEvent`] (crates/ldap
//! `AuditEvent`; plus keyd-daemon's intent / not-performed phase records of
//! a key-state change, the outcome codes [`KeydOutcome::Intent`] and
//! [`KeydOutcome::NotPerformed`] — decision A-86, docs/questions/Q-365) —
//! plus [`WindowSummary`], and the admin-plane shapes
//! [`DirAdminEvent`] (sent by dird: the decision before each admin commit
//! and the outcome after it) and [`AdmindEvent`] (sent by admind) — docs/51
//! §5.7, task A7. Each carries exactly the
//! non-secret fields its source exposes; no field can hold a key, password,
//! ticket, PAC, plaintext, ciphertext, free attribute value or request
//! octets (docs/37 §2; docs/10 I8; docs/49 §10.1) — the only request values
//! kept are `DirAdmin`'s three closed forms (enable direction, accountExpires
//! never-or-FILETIME, one of six groupType codes; docs/questions/Q-340
//! item 5). Client strings are kept only as
//! printable ASCII ≤ 256 octets, else a marker ([`AuditText`]). Codes come
//! from closed tables mirroring the source enumerations by name
//! (crate::codes). The conversions from the source types are on the side
//! that links each source (task IB1, above). The admin-plane shapes have no
//! source crate and are built from this crate's types.
//!
//! [`peek_shape`] reads only an event's format and shape octets: auditd uses
//! it to accept each shape only from its one sender (`Kdc` ⇐ kdc, `Keyd` ⇐
//! keyd, `Ldap` / `DirAdmin` ⇐ dird, `Admind` ⇐ admind; `WindowSummary` from
//! any), without decoding payloads (docs/questions/Q-341, option (a)).
//!
//! # Overflow policy (docs/questions/Q-218, A-57)
//!
//! [`SendWindow`]: gating events reserve a slot **before** the operation and
//! are refused when the window is full ([`WindowFull`] — the caller does not
//! issue; keyd answers `Busy`); unauthenticated noise may hold only a share
//! of the window and is otherwise counted into a [`WindowSummary`]; nothing
//! stops the process. "No unaudited issuance, and log overflow does not turn
//! into shutdown." The summary also counts outcome records that could not be
//! committed after their intent or decision was recorded
//! ([`SendWindow::count_unrecorded_outcome`]; decision A-88,
//! docs/questions/Q-366, Q-395), so a lost outcome is in the log, not only
//! on stderr. Every `DirAdmin` event is gating; an `Admind` event is
//! noise exactly when it records a refused connection or a malformed frame
//! ([`AdmindEvent::is_noise`]), so neither can make admind unavailable.
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
//! (error, message), crates/dtyp (sid, guid), crates/krb-proto (basic). The
//! admin-plane shapes (task A7) were written only from docs/51 (§1, §2, §3,
//! §5.1-§5.8, §6, §7, §8.3, §9, §11, §12 and decision A-72), docs/50 §3, §8,
//! docs/37, docs/43 (D175), PENDING-OWNER (A-57, A-64, A-66..A-80),
//! docs/questions Q-218, Q-252, and the public API of crates/ipc (error,
//! refused) and crates/keyd-types (error). The third `WindowSummary` counter
//! and the three appended admin codes (task F4) were written only from
//! PENDING-OWNER (A-85, A-88, A-91), docs/questions Q-341, Q-366, Q-388,
//! Q-358, docs/50 §8, docs/37, docs/51 §5.7 / §7.4 and docs/11 §2 / §8 (as
//! cited there). The gate and the proof (task R6) were written only from
//! docs/52 (§2, §3.10, §3.11, §7 R6), docs/50 §3.6 / §8.1, docs/51 §5.7,
//! PENDING-OWNER (A-85, A-87, A-88, A-93, A-102, A-105), docs/questions
//! Q-313, Q-350, Q-365, Q-395, and this repository's four daemon gates
//! they replace. The source in `Pong` and the one client (task R9b) were
//! written only from docs/50 (R50-3, R50-16, R50-17, §2.4, §3.2, §3.3,
//! §3.6, §3.7, §7.5, §8.1), docs/52 (§3.11, §3.12, §7), PENDING-OWNER
//! (A-57, A-67, A-85, A-87, A-101, A-107, A-112), docs/questions Q-500,
//! Q-502, Q-510, Q-512, this repository's four daemon audit clients they
//! replace, and the docs.rs API pages of tokio 1.54.1 (the client and the
//! gate are crate `ipc_audit_client`'s since task IB1). The split of task
//! IB1 was written only from docs/questions/Q-851, PENDING-OWNER A-144 and
//! docs/research/r4-b §3.3, §5.6. No other implementation, serializer, RPC
//! framework or audit format was consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/50 R50-17, §3.3, §8.1, §10; docs/37 §2; Q-218 (A-57); A-59;
//! docs/51 §5.7 (A-72); A-88 (Q-366, Q-395); A-91 (Q-388, Q-397); docs/52
//! §3.11 R6 (A-102), §3.12 (task R9b, A-112; Q-512, Q-560); Decision:
//! A-144; Q-851 (task IB1).

mod admin;
mod channel;
mod codes;
mod error;
mod event;
mod values;
mod window;

pub use admin::{
    AccountExpiresValue, AdmindActivity, AdmindEvent, Allocation, DecisionResult, DirAdminEvent,
    DirAdminStage, OutcomeResult, PasswordResult, PasswordStep, TargetName, MAX_APPROVERS,
    MAX_REPORTED_KVNOS, MAX_TARGET_NAMES,
};
pub use channel::{
    decode_reply, decode_request, encode_reply, encode_request, Ack, Append, AppendCursor,
    AuditReply, AuditRequest, EventSource, SeqRange, SequenceError, AUDIT_CHANNEL, AUDIT_MAGIC,
    AUDIT_VERSION, KIND_ACK, KIND_APPEND, KIND_PING, KIND_PONG, MAX_BATCH_EVENTS, REPLY_BODY_LIMIT,
    REQUEST_BODY_LIMIT,
};
pub use codes::{
    AccountExpiresCode, AdminFailure, AdminNameKind, AdminPhase, AdminRefusal, AdmindActivityCode,
    BindMechanismCode, CodecErrorCode, CodecLimit, ConnectionRefusal, DecisionResultCode,
    DirAdminOperation, EnableDirection, EventShape, ForwardDecision, FrameErrorCode, GroupTypeCode,
    IpZone, KdcExchange, KdcOutcomeCode, KdcReason, KdcTransport, KeyPurposeCode, KeyadmOperation,
    KeydOperation, KeydOutcome, KeydReason, KeydRole, LdapAction, LdapOperationCode, LdapReason,
    LdapTargetCode, LdapTransport, OutcomeResultCode, PasswordFailure, PasswordResultCode,
    PasswordStepCode, PdpReasonCode, SearchScope, UnsupportedOpCode,
};
pub use error::EventError;
pub use event::{
    decode_event, encode_event, event_round_trip_is_canonical, peek_shape, BindMechanism,
    EventBody, EventBytes, KdcEvent, KdcOutcome, KeyRef, KeydRecord, LdapBind, LdapEvent,
    LdapOperation, LdapSearch, LdapTarget, TransportSecurity, WindowSummary, EVENT_FORMAT,
    MAX_EVENT_OCTETS, MAX_FILTER_ATTRS,
};
pub use values::{
    AuditText, BoundedSeq, CalendarTime, CodecError, PdpReason, Principal, ReportedAddress,
    SidValue, MAX_NAME_COMPONENTS, MAX_SID_SUB_AUTHORITIES, MAX_TEXT_OCTETS,
};
pub use window::{NoiseAdmission, Reservation, SendWindow, WindowConfig, WindowError, WindowFull};
