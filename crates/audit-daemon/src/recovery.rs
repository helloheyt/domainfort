//! Start-up: verify the whole log, recover a torn tail, and hand the writer
//! a sink positioned at the head.
//!
//! # The walk
//!
//! Every segment ([`crate::segments`]) is verified in order with
//! crates/audit-log's [`SegmentReader`]: segment 1 against genesis, each next
//! one against the head the previous one ended at. No checkpoint exists in
//! phase 1 (unsigned chain, P-20), so none is passed.
//!
//! # Torn tails (docs/questions/Q-250 item 8)
//!
//! A segment that **ends inside its header or inside a record**
//! ([`TornKind`]) is what a crash during a write leaves behind. If it is the
//! last segment, the daemon **starts a new segment anchored at the
//! verifier's `last_good`** and writes, as that segment's first record, an
//! `Auditd` record describing the break ([`SegmentRecovered`]). The torn
//! segment is never truncated, rewritten or removed: it stays as evidence
//! and the log is still append-only (docs/37 §2).
//!
//! On every later start the torn segment is accepted **only** if the next
//! segment is anchored at its `last_good` and begins with exactly that
//! recovery record — re-derived from the torn segment (its number, break,
//! offset and length) and compared octet for octet. Anything appended to the
//! torn segment afterwards changes its length and is refused.
//!
//! One crash window is completed rather than refused: the recovery segment's
//! header was synced but the recovery record was not (the last segment holds
//! no record and is anchored at the pending `last_good`); the record is
//! written then.
//!
//! # Refusal (fail closed)
//!
//! Every other break — a link, sequence, length, source or timestamp fault,
//! an anchor mismatch, a torn segment in the middle without its recovery
//! record, a missing or stray segment file, or a second crash while a
//! recovery was being written — is a **chain break**: [`open_log`] returns
//! it and the daemon refuses to start (fixed text on stderr, non-zero exit).
//! A tail of zero octets left by a crash looks like a record whose length is
//! out of bounds and is refused too: the verifier cannot tell it from
//! tampering (docs/questions/Q-265 item 1).
//!
//! # The resend check's state
//!
//! The same walk hands every sender record that verifies — in log order,
//! including the records of a torn segment before its break — to the
//! resend check ([`crate::resend::PersistedTails::observe`], the function
//! the writer calls after each sync), so each source's last persisted
//! `source_seq` and remembered events survive a restart (decision A-98,
//! follow-up F8; docs/questions/Q-445).
//!
//! # The files (task R11b)
//!
//! Every segment is listed, read, appended to and created through
//! crates/protected-file's walk from `/` with auditd's account (`own_uid`)
//! as the owner (crate::segments; docs/52 R11; docs/questions/Q-481 item b,
//! Q-530). A directory or a segment that breaks the walk's or the segment
//! rule is an operational refusal ([`StartupError::SegmentPath`],
//! [`StartupError::SegmentRule`]), not a chain break: nothing about the
//! hash chain was observed.
//!
//! Spec: docs/50 R50-16 ("nothing binds until its dependencies are
//! verified"), §7.5 ("auditd — opens the file, verifies the hash chain");
//! docs/37 §2; docs/questions/Q-250 items 6, 8, 10 (A-64); Q-265 item 1;
//! docs/52 §7 R11; Q-530.

use crate::own_event::{AuditdEvent, SegmentRecovered, TornKind};
use crate::resend::PersistedTails;
use crate::segments::{list_segments, FileSegments, ListingError, FIRST_SEGMENT};
use crate::writer::{LogSink, PersistError};
use audit_log::{
    Anchor, AppendError, BreakKind, LogWriter, SegmentLimit, SegmentReader, Source,
    VerifiedSegment, VerifyError,
};
use core::fmt;
use protected_file::{OpenError, PathBreak, RuleBreak};
use std::io::{self, BufReader, Read};
use std::path::Path;

/// How the log was found at start.
///
/// Spec: docs/50 §7.5; docs/questions/Q-250 item 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartKind {
    /// No segment existed: segment 1 was created at genesis.
    Created,
    /// The log verified end to end; the writer continues its last segment.
    Resumed,
    /// A torn last segment was recovered (or a recovery interrupted after
    /// its header was completed); the record written describes it.
    Recovered(SegmentRecovered),
}

/// The verified log, ready for the writer.
#[derive(Debug)]
pub struct OpenedLog {
    /// The sink positioned at the head.
    pub sink: LogSink<FileSegments>,
    /// What start-up found.
    pub start: StartKind,
}

/// Why the daemon refuses to start.
///
/// No variant carries record octets (AGENTS.md §6; docs/50 §8.2).
///
/// Spec: docs/50 §7.5 ("every daemon exits with an error code on any
/// start-up failure"); docs/37 §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupError {
    /// The segment files are not a gap-free, well-named set.
    Listing(ListingError),
    /// A segment could not be opened, read or created.
    Io(io::ErrorKind),
    /// A directory on the path to a segment is a symbolic link or not a
    /// directory, is owned by neither root nor auditd's account, or is
    /// writable by group or others (crates/protected-file walk; task R11b).
    SegmentPath(PathBreak),
    /// An existing segment is not a regular file, not auditd's, or writable
    /// by group or others (crate::segments `segment_rule`; task R11b).
    SegmentRule(RuleBreak),
    /// A break that is not a recoverable torn tail.
    ChainBreak {
        /// The segment it is in.
        segment: u64,
        /// The verifier's break.
        kind: BreakKind,
        /// The sequence number where it broke.
        at_seq: u64,
    },
    /// Torn segment `segment` is not followed by its recovery record.
    RecoveryRecordMissing {
        /// The torn segment.
        segment: u64,
    },
    /// Starting or resuming a segment failed.
    Append(AppendError),
    /// The recovery record could not be written.
    RecoveryWrite,
}

impl StartupError {
    /// Whether this is evidence of a damaged or altered log (exit code
    /// "chain break") rather than an operational failure.
    ///
    /// Spec: docs/37 §2; docs/questions/Q-265 item 1.
    #[must_use]
    pub const fn is_chain_break(&self) -> bool {
        matches!(
            self,
            StartupError::ChainBreak { .. }
                | StartupError::RecoveryRecordMissing { .. }
                | StartupError::Listing(
                    ListingError::UnexpectedFile | ListingError::SegmentMissing { .. }
                )
        )
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupError::Listing(ListingError::BadBasePath) => {
                f.write_str("audit log path has no directory or file name")
            }
            StartupError::Listing(ListingError::Io(kind)) => {
                write!(f, "audit log directory unreadable: {kind}")
            }
            StartupError::Listing(ListingError::Directory(path)) => {
                write!(f, "audit log directory refused: its path {path}")
            }
            StartupError::Listing(ListingError::UnexpectedFile) => {
                f.write_str("unexpected file among the audit log segments")
            }
            StartupError::Listing(ListingError::SegmentMissing { expected }) => {
                write!(f, "audit log segment {expected} is missing")
            }
            StartupError::Io(kind) => write!(f, "audit log segment I/O failure: {kind}"),
            StartupError::SegmentPath(path) => {
                write!(f, "audit log segment refused: its path {path}")
            }
            StartupError::SegmentRule(RuleBreak::NotRegularFile) => {
                f.write_str("audit log segment refused: not a regular file")
            }
            StartupError::SegmentRule(RuleBreak::WrongOwner) => {
                f.write_str("audit log segment refused: not owned by auditd's account")
            }
            StartupError::SegmentRule(RuleBreak::WritableByGroupOrOthers) => {
                f.write_str("audit log segment refused: writable by group or others")
            }
            StartupError::ChainBreak {
                segment,
                kind,
                at_seq,
            } => write!(
                f,
                "audit chain break {kind:?} in segment {segment} at sequence {at_seq}"
            ),
            StartupError::RecoveryRecordMissing { segment } => write!(
                f,
                "torn audit log segment {segment} is not followed by its recovery record"
            ),
            StartupError::Append(error) => write!(f, "audit log segment start failed: {error}"),
            StartupError::RecoveryWrite => f.write_str("audit log recovery record write failed"),
        }
    }
}

impl std::error::Error for StartupError {}

/// The outcome of walking one segment.
enum Walk {
    /// Verified to its end (and, if a recovery record was pending, it was
    /// the first record).
    Complete(VerifiedSegment),
    /// Verified, holds no record, while a recovery record is pending for it.
    AwaitingRecoveryRecord(VerifiedSegment),
    /// Ends early: a torn write.
    Torn(VerifyError, TornKind),
}

/// The start-up refusal for a segment the walk or the segment rule refused,
/// or the system's error kind.
/// Spec: this module's documentation (task R11b); crate::segments.
fn segment_error(error: OpenError<RuleBreak>) -> StartupError {
    match error {
        OpenError::Io(kind) => StartupError::Io(kind),
        OpenError::Path(path) => StartupError::SegmentPath(path),
        OpenError::Refused(rule) => StartupError::SegmentRule(rule),
    }
}

fn io_error(error: &io::Error) -> StartupError {
    StartupError::Io(error.kind())
}

/// A break as start-up treats it: a torn end (only when no recovery record
/// is pending for this segment), or a refusal.
fn torn_or_refused(
    error: VerifyError,
    segment: u64,
    pending: Option<&SegmentRecovered>,
) -> Result<Walk, StartupError> {
    if let BreakKind::Io(kind) = error.kind {
        return Err(StartupError::Io(kind));
    }
    match (TornKind::of(error.kind), pending) {
        (Some(torn), None) => Ok(Walk::Torn(error, torn)),
        // The segment that should hold a recovery record is itself torn
        // before that record: a crash during the recovery (double fault).
        (Some(_), Some(expected)) => Err(StartupError::RecoveryRecordMissing {
            segment: expected.segment,
        }),
        (None, _) => Err(StartupError::ChainBreak {
            segment,
            kind: error.kind,
            at_seq: error.at_seq,
        }),
    }
}

/// Verify one segment against `anchor`; if `pending` is set, its first
/// record must be that recovery record. Every sender record that verifies
/// — in a torn segment, every record before the break — is handed to the
/// resend check's state (`tails`), in log order.
///
/// Spec: docs/37 §2; docs/questions/Q-250 item 8; this module's rules;
/// crate::resend (the state is recovered from the verified log; A-66,
/// A-98).
fn walk_segment<R: Read>(
    reader: R,
    segment: u64,
    anchor: Anchor,
    limit: SegmentLimit,
    pending: Option<&SegmentRecovered>,
    tails: &mut PersistedTails,
) -> Result<Walk, StartupError> {
    let mut walk = match SegmentReader::open(reader, anchor, limit, None) {
        Ok(walk) => walk,
        Err(error) => return torn_or_refused(error, segment, pending),
    };
    if let Some(expected) = pending {
        let missing = StartupError::RecoveryRecordMissing {
            segment: expected.segment,
        };
        match walk.next_record() {
            Ok(Some(record)) => {
                let wanted = AuditdEvent::SegmentRecovered(*expected).encode();
                if record.source != Source::Auditd || record.payload != wanted {
                    return Err(missing);
                }
            }
            Ok(None) => {
                return walk
                    .finish()
                    .map(Walk::AwaitingRecoveryRecord)
                    .map_err(|_| missing);
            }
            // The recovery record itself is broken: refuse (double fault or
            // tampering).
            Err(_) => return Err(missing),
        }
    }
    // Every record, as it verifies, to the resend check; the head after a
    // record is that record's own (auditd's own records are ignored there).
    loop {
        match walk.next_record() {
            Ok(Some(record)) => tails.observe(
                record.source,
                record.source_uid,
                record.source_seq,
                &record.payload,
                Some(walk.head()),
            ),
            Ok(None) => break,
            Err(error) => return torn_or_refused(error, segment, None),
        }
    }
    match walk.finish() {
        Ok(verified) => Ok(Walk::Complete(verified)),
        Err(error) => torn_or_refused(error, segment, None),
    }
}

/// Open segment `index` read-only (through the walk, under the segment
/// rule: crate::segments) and walk it; returns the walk and the file's
/// length.
fn walk_file(
    files: &FileSegments,
    index: u64,
    anchor: Anchor,
    limit: SegmentLimit,
    pending: Option<&SegmentRecovered>,
    tails: &mut PersistedTails,
) -> Result<(Walk, u64), StartupError> {
    let file = files.open_read(index).map_err(segment_error)?;
    let octets = file.metadata().map_err(|e| io_error(&e))?.len();
    let walk = walk_segment(BufReader::new(file), index, anchor, limit, pending, tails)?;
    Ok((walk, octets))
}

/// Verify the log based at `base` (`audit_log_path`) and return a sink at
/// its head, recovering a torn last segment. `limit` bounds every segment,
/// read and written; `own_uid` is auditd's account: its own records carry
/// it, and every segment and every directory on the log's path (besides
/// root's) must be its (crate::segments, task R11b). The sink's
/// resend check holds the per-source state the walk recovered from every
/// verified record (crate::resend), so a batch persisted before a stop and
/// resent after it is recognised.
///
/// # Errors
/// [`StartupError`]; [`StartupError::is_chain_break`] tells a damaged or
/// altered log from an operational failure.
///
/// Spec: docs/50 R50-16, §7.5; docs/37 §2; docs/questions/Q-250 items 6, 8;
/// this module's rules; crate::resend (A-98; Q-445).
pub fn open_log(base: &Path, limit: SegmentLimit, own_uid: u32) -> Result<OpenedLog, StartupError> {
    let mut tails = PersistedTails::new();
    let mut opened = open_walked(base, limit, own_uid, &mut tails)?;
    opened.sink.set_tails(tails);
    Ok(opened)
}

/// [`open_log`]'s walk, handing every verified record to `tails`.
fn open_walked(
    base: &Path,
    limit: SegmentLimit,
    own_uid: u32,
    tails: &mut PersistedTails,
) -> Result<OpenedLog, StartupError> {
    let files = FileSegments::new(base.to_path_buf(), own_uid);
    let indexes = list_segments(base, own_uid).map_err(StartupError::Listing)?;
    let Some((&last, earlier)) = indexes.split_last() else {
        let storage = files.create_segment(FIRST_SEGMENT).map_err(segment_error)?;
        let writer = LogWriter::create(storage, limit).map_err(StartupError::Append)?;
        let mut sink = LogSink::new(writer, FIRST_SEGMENT, files, own_uid);
        sink.sign_head();
        return Ok(OpenedLog {
            sink,
            start: StartKind::Created,
        });
    };

    let mut anchor = Anchor::Genesis;
    let mut pending: Option<SegmentRecovered> = None;
    for &index in earlier {
        let (walk, octets) = walk_file(&files, index, anchor, limit, pending.as_ref(), tails)?;
        match walk {
            Walk::Complete(verified) => {
                pending = None;
                anchor = Anchor::After(verified.head());
            }
            // An empty recovery segment followed by another segment cannot
            // come from this daemon (the record is written first).
            Walk::AwaitingRecoveryRecord(_) => {
                return Err(StartupError::RecoveryRecordMissing {
                    segment: pending.map_or(index, |expected| expected.segment),
                })
            }
            Walk::Torn(error, torn) => {
                pending = Some(SegmentRecovered {
                    segment: index,
                    torn,
                    last_good: error.last_good,
                    break_offset: error.offset,
                    segment_octets: octets,
                });
                anchor = Anchor::After(error.last_good);
            }
        }
    }

    let (walk, octets) = walk_file(&files, last, anchor, limit, pending.as_ref(), tails)?;
    match walk {
        Walk::Complete(verified) => {
            let storage = files.open_append(last).map_err(segment_error)?;
            let writer =
                LogWriter::resume(storage, &verified, limit).map_err(StartupError::Append)?;
            let mut sink = LogSink::new(writer, last, files, own_uid);
            sink.sign_head();
            Ok(OpenedLog {
                sink,
                start: StartKind::Resumed,
            })
        }
        Walk::AwaitingRecoveryRecord(verified) => {
            let Some(expected) = pending else {
                return Err(StartupError::RecoveryRecordMissing { segment: last });
            };
            let storage = files.open_append(last).map_err(segment_error)?;
            let writer =
                LogWriter::resume(storage, &verified, limit).map_err(StartupError::Append)?;
            let mut sink = LogSink::new(writer, last, files, own_uid);
            write_recovery_record(&mut sink, expected)?;
            Ok(OpenedLog {
                sink,
                start: StartKind::Recovered(expected),
            })
        }
        Walk::Torn(error, torn) => {
            let recovered = SegmentRecovered {
                segment: last,
                torn,
                last_good: error.last_good,
                break_offset: error.offset,
                segment_octets: octets,
            };
            let next = last.checked_add(1).ok_or(StartupError::RecoveryWrite)?;
            let storage = files.create_segment(next).map_err(segment_error)?;
            let writer = LogWriter::start_segment(storage, error.last_good, limit)
                .map_err(StartupError::Append)?;
            let mut sink = LogSink::new(writer, next, files, own_uid);
            write_recovery_record(&mut sink, recovered)?;
            Ok(OpenedLog {
                sink,
                start: StartKind::Recovered(recovered),
            })
        }
    }
}

/// Write the recovery record as the segment's first record, then call the
/// signing hook.
///
/// Spec: docs/questions/Q-250 item 8; docs/questions/Q-251.
fn write_recovery_record(
    sink: &mut LogSink<FileSegments>,
    recovered: SegmentRecovered,
) -> Result<(), StartupError> {
    match sink.append_own(&AuditdEvent::SegmentRecovered(recovered)) {
        Ok(_) => {
            sink.sign_head();
            Ok(())
        }
        Err(PersistError::Unavailable | PersistError::Fatal(_)) => Err(StartupError::RecoveryWrite),
    }
}
