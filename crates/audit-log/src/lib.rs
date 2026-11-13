#![forbid(unsafe_code)]
//! `audit-log`: the append-only, hash-chained audit log format (docs/50
//! R50-17, §8.1; runtime build task P6, the library half — the auditd
//! binary is P6b).
//!
//! # Format
//!
//! ```text
//! Segment       := SegmentHeader ‖ Record*
//! SegmentHeader := magic "AUDCHAIN" ‖ format_version:u8 (= 1)
//!                  ‖ anchor_seq:u64 ‖ anchor_hash:[32]
//! Record        := record_len:u32 ‖ seq:u64 ‖ prev_hash:[32]
//!                  ‖ time_secs:u64 ‖ time_nanos:u32 ‖ source:u8 ‖ source_uid:u32
//!                  ‖ source_seq:u64 ‖ payload_len:u32 ‖ payload[1..=8192]
//! hash(record)  := SHA-256(the record's whole encoding, record_len included)
//! ```
//!
//! Big-endian, fixed width, one encoding per value ([`format`]). Record `n`
//! carries `prev_hash = hash(record n-1)`; record sequence numbers start at 1
//! and rise by one across segments; the first segment of a log is anchored at
//! the **genesis** head — sequence 0 and 32 zero octets
//! ([`ChainHead::GENESIS`], [`GENESIS_HASH`]). A later segment (after
//! rotation) is anchored at the head of the one before it, so a log is one
//! chain however many files it spans.
//!
//! The record's `source` and `source_uid` are the connection's peer
//! identity, set by auditd — never taken from the event payload; its `time`
//! is auditd's clock (docs/50 §3.2, R50-17). The payload is the sender's
//! canonical event encoding (crate `ipc-audit`), opaque here.
//!
//! # Writer
//!
//! [`LogWriter`] appends one batch at a time: encode and chain in memory,
//! one write, flush, sync — and only after the sync succeeded does it return
//! [`Persisted`] (the sequence number and hash an acknowledgement may carry,
//! docs/50 §8.1). A failed write, flush or sync acknowledges nothing and
//! poisons the writer (fail closed). A batch that would overflow the
//! segment's [`SegmentLimit`] is refused before anything is written
//! ([`AppendError::SegmentFull`]) and the caller rotates
//! ([`LogWriter::rotate`]): overflow is never shutdown (docs/questions/Q-218,
//! A-57; docs/07 §8). [`Storage`] abstracts the file ([`FileStorage`]).
//!
//! # Verifier
//!
//! [`verify_segment`], [`verify_log`] and [`SegmentReader`] walk segments with
//! bounded, streaming reads and report the first break as a [`VerifyError`]
//! ([`BreakKind`], the sequence number, the offset, the last good head):
//! a flipped octet, a deleted, inserted or reordered record, a cut tail. A
//! change to the last record or a cut at a record boundary needs a head held
//! outside the segment — the `checkpoint` argument (the last acknowledgement,
//! or a signed head).
//!
//! # Signing
//!
//! [`HeadSigner`] is a hook only: docs/37 §2 wants a signed segment, but the
//! signing key's custody is undecided (docs/questions/Q-251), so no scheme
//! and no key source are chosen here.
//!
//! # Security
//!
//! No `unsafe`; no panic, `unwrap` or indexing on the read path; every
//! length is checked against a named bound before allocation; no error
//! carries record octets (AGENTS.md §6). Event payloads are non-secret by
//! construction (docs/37 §2: "only identifiers and metadata").
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! docs/50 (§1 R50-16, R50-17; §2.4; §3.2; §3.3; §6.4; §7.5; §8; §9; §10 and
//! the closing decision, A-58), docs/37 (all), docs/07 §8,
//! docs/questions/Q-218 (A-57), OD-8, PENDING-OWNER (A-57, A-58, P-1, P-2),
//! crates/config `auditd` (the source names), and the docs.rs API pages of
//! `sha2` 0.11.1, `digest` 0.11.3 (`Digest`, `Output`) and `hybrid-array`
//! 0.4.11 (`Array`). The layout and every name are this project's own; no
//! existing audit-log, journal or hash-chain format or implementation was
//! consulted or recalled (AGENTS.md §1-3).
//!
//! Spec: docs/50 R50-17, §8.1, §10; docs/37 §2; docs/07 §8; Q-218 (A-57).

pub mod format;
mod sign;
mod verify;
mod writer;

pub use format::{
    ChainHead, ClockBeforeEpoch, Record, RecordHash, SegmentHeader, Source, Timestamp,
    FORMAT_VERSION, GENESIS_HASH, HASH_LEN, MAX_BATCH_RECORDS, MAX_PAYLOAD_LEN, MAX_RECORD_LEN,
    MIN_PAYLOAD_LEN, MIN_RECORD_LEN, RECORD_FIXED_BODY_LEN, RECORD_LEN_PREFIX, SEGMENT_HEADER_LEN,
    SEGMENT_MAGIC,
};
pub use sign::HeadSigner;
pub use verify::{
    verify_log, verify_segment, Anchor, BreakKind, LogBreak, SegmentReader, VerifiedSegment,
    VerifyError,
};
pub use writer::{AppendError, Entry, FileStorage, LogWriter, Persisted, SegmentLimit, Storage};
