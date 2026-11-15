//! The verifier: walks a segment and checks every link, sequence continuity
//! and every bound, and reports the first break as a typed error.
//!
//! Reading is streaming and bounded: the header, then one record at a time,
//! with the declared record length checked against [`MAX_RECORD_LEN`]
//! **before** the body is allocated or read (docs/CLEAN-ROOM.md: no allocation from
//! an attacker-supplied length beyond the bound). A segment is never read as
//! a whole.
//!
//! What is detected, and where (`at_seq` of the [`VerifyError`]):
//!
//! | change to the segment | detected as | `at_seq` |
//! |---|---|---|
//! | a record deleted, or two swapped | [`BreakKind::SequenceGap`] | the sequence expected where the wrong record stands |
//! | a record's `seq` altered | [`BreakKind::SequenceGap`] | that record's (expected) sequence |
//! | a record's `prev_hash` altered | [`BreakKind::LinkMismatch`] | that record |
//! | any other octet of record `n` altered | [`BreakKind::LinkMismatch`] at `n + 1`, or — for the last record — [`BreakKind::CheckpointMismatch`] against a checkpoint | `n + 1` / `n` |
//! | a length field altered | a length / truncation break | the record whose framing broke |
//! | the tail cut inside a record | [`BreakKind::RecordTruncated`] | the cut record |
//! | the tail cut at a record boundary | [`BreakKind::CheckpointNotReached`] against a checkpoint | the first missing record |
//!
//! A change to the **last** record, and a cut at a record boundary, leave a
//! valid chain behind: only a head held outside the segment can show them —
//! the last acknowledgement, a signed checkpoint (docs/questions/Q-251), or
//! the off-box copy (docs/37 §2). That is the `checkpoint` argument.
//!
//! A record yielded by [`SegmentReader::next_record`] has passed its own
//! checks and its link to its predecessor; its own content is vouched for
//! only once a later record links to it or a checkpoint matches it.
//!
//! Spec: docs/37 §2 ("deleting or changing a record breaks the chain and is
//! detected"), §8 ("trace deletion by an attacker | hash-chain + off-box");
//! docs/50 §7.5 (auditd verifies the chain at start); docs/questions/Q-250.

use crate::format::{
    parse_record_body, ChainHead, HeaderFault, Record, RecordFault, RecordHash, SegmentHeader,
    GENESIS_HASH, MAX_RECORD_LEN, MIN_RECORD_LEN, RECORD_LEN_PREFIX, SEGMENT_HEADER_LEN,
};
use crate::writer::SegmentLimit;
use core::fmt;
use std::io::{self, Read};

/// What the segment's header must say.
///
/// Spec: docs/37 §2; docs/questions/Q-250 item 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    /// The first segment of a log: anchored at [`ChainHead::GENESIS`].
    Genesis,
    /// A later segment: anchored at the head of the segment before it.
    After(ChainHead),
    /// Accept the header's anchor as given (the first retained segment after
    /// older ones were removed, or a single segment checked on its own). The
    /// segment is then only internally consistent; tying it to the log's
    /// start needs a signed checkpoint (docs/questions/Q-251).
    Trusted,
}

/// The kind of break found.
///
/// Spec: docs/37 §2; this crate's layout (crate::format).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakKind {
    /// The segment ends inside its header.
    HeaderTruncated,
    /// The header's magic is not this format's.
    BadMagic,
    /// The header's format version is not the one this build reads.
    UnsupportedVersion,
    /// The header's anchor is not the expected one ([`Anchor`]): a segment
    /// replaced, reordered, or cut from the front of the log.
    AnchorMismatch,
    /// The segment ends inside a record (a cut tail, or a torn write).
    RecordTruncated,
    /// A record's declared length is outside the record bounds.
    RecordLengthOutOfBounds,
    /// A record's `payload_len` disagrees with its `record_len`.
    PayloadLengthMismatch,
    /// A record's time is not canonical (nanoseconds of a second or more).
    InvalidTimestamp,
    /// A record's source code is outside the closed table.
    UnknownSource,
    /// A record's sequence number is not the next one: a record deleted,
    /// inserted or reordered, or its `seq` altered.
    SequenceGap {
        /// The sequence number found instead.
        found: u64,
    },
    /// A record's `prev_hash` is not the hash of the record before it: that
    /// field, or the previous record, was altered.
    LinkMismatch,
    /// The chain reached the checkpoint's sequence number with another hash.
    CheckpointMismatch,
    /// The segment ended before the checkpoint's sequence number: records
    /// cut from the tail.
    CheckpointNotReached,
    /// The segment is longer than the segment bound.
    SegmentTooLarge,
    /// Reading failed.
    Io(io::ErrorKind),
}

/// The first break in a segment.
///
/// No variant carries record octets (docs/CLEAN-ROOM.md; docs/50 §8.2).
///
/// Spec: docs/37 §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyError {
    /// What broke.
    pub kind: BreakKind,
    /// The sequence number at which it broke (see the module table).
    pub at_seq: u64,
    /// Octet offset in the segment of the header, record or end where it
    /// broke.
    pub offset: u64,
    /// The last head that verified before the break: a daemon may start a
    /// new segment from it (docs/questions/Q-250 item 8).
    pub last_good: ChainHead,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "audit chain break {:?} at sequence {} (offset {})",
            self.kind, self.at_seq, self.offset
        )
    }
}

impl std::error::Error for VerifyError {}

/// A segment that verified from its header to its last octet.
///
/// Only the verifier constructs one, so [`crate::LogWriter::resume`] can
/// trust it.
///
/// Spec: docs/50 §7.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedSegment {
    anchor: ChainHead,
    head: ChainHead,
    records: u64,
    len: u64,
}

impl VerifiedSegment {
    /// The head the segment continues from.
    #[must_use]
    pub fn anchor(&self) -> ChainHead {
        self.anchor
    }

    /// The head after the segment's last record (the anchor if it has none).
    #[must_use]
    pub fn head(&self) -> ChainHead {
        self.head
    }

    /// How many records the segment holds.
    #[must_use]
    pub fn records(&self) -> u64 {
        self.records
    }

    /// Octets in the segment, header included.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Always `false`: a verified segment has at least its header.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// How a bounded read ended.
enum Fill {
    /// The buffer was filled.
    Full,
    /// End of input before the first octet.
    Eof,
    /// End of input after some octets.
    Partial,
}

/// Fill `buffer` from `reader`, retrying interrupted reads.
fn fill<R: Read>(reader: &mut R, buffer: &mut [u8]) -> io::Result<Fill> {
    let mut filled = 0;
    while filled < buffer.len() {
        let rest = buffer.get_mut(filled..).unwrap_or_default();
        match reader.read(rest) {
            Ok(0) => {
                return Ok(if filled == 0 {
                    Fill::Eof
                } else {
                    Fill::Partial
                })
            }
            Ok(n) => filled = filled.saturating_add(n.min(rest.len())),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Fill::Full)
}

/// Walks one segment record by record, verifying as it goes.
///
/// Spec: docs/37 §2; docs/50 §7.5.
pub struct SegmentReader<R: Read> {
    reader: R,
    anchor: ChainHead,
    head: ChainHead,
    records: u64,
    offset: u64,
    limit: SegmentLimit,
    checkpoint: Option<ChainHead>,
    /// Whether the walk is still reading, ended cleanly, or broke.
    state: State,
}

/// The walk's state. A break is sticky: once reported, every later call
/// reports it again, so a caller that ignored it cannot conclude success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Reading,
    Ended,
    Broken(VerifyError),
}

impl<R: Read> fmt::Debug for SegmentReader<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SegmentReader")
            .field("anchor", &self.anchor)
            .field("head", &self.head)
            .field("records", &self.records)
            .field("offset", &self.offset)
            .finish()
    }
}

impl<R: Read> SegmentReader<R> {
    /// Read and check the header.
    ///
    /// `checkpoint`, when given, is a head held outside the segment (the
    /// last acknowledgement, a signed checkpoint): the chain must pass
    /// through it, and the segment must reach it.
    ///
    /// # Errors
    /// [`BreakKind::HeaderTruncated`], [`BreakKind::BadMagic`],
    /// [`BreakKind::UnsupportedVersion`], [`BreakKind::AnchorMismatch`],
    /// [`BreakKind::Io`]; [`BreakKind::CheckpointMismatch`] if the checkpoint
    /// names the anchor's sequence with another hash.
    pub fn open(
        mut reader: R,
        anchor: Anchor,
        limit: SegmentLimit,
        checkpoint: Option<ChainHead>,
    ) -> Result<SegmentReader<R>, VerifyError> {
        let expected = match anchor {
            Anchor::Genesis => Some(ChainHead::GENESIS),
            Anchor::After(head) => Some(head),
            Anchor::Trusted => None,
        };
        let before = expected.unwrap_or(ChainHead::GENESIS);
        let fail = |kind| VerifyError {
            kind,
            at_seq: before.seq.saturating_add(1),
            offset: 0,
            last_good: before,
        };
        let mut octets = [0u8; SEGMENT_HEADER_LEN];
        match fill(&mut reader, &mut octets) {
            Ok(Fill::Full) => {}
            Ok(Fill::Eof | Fill::Partial) => return Err(fail(BreakKind::HeaderTruncated)),
            Err(error) => return Err(fail(BreakKind::Io(error.kind()))),
        }
        let header = SegmentHeader::parse(&octets).map_err(|fault| {
            fail(match fault {
                HeaderFault::BadMagic => BreakKind::BadMagic,
                HeaderFault::UnsupportedVersion => BreakKind::UnsupportedVersion,
            })
        })?;
        if let Some(expected) = expected {
            if header.anchor != expected {
                return Err(fail(BreakKind::AnchorMismatch));
            }
        }
        // Genesis is only ever the anchor at sequence 0.
        if header.anchor.seq == 0 && header.anchor.hash != GENESIS_HASH {
            return Err(fail(BreakKind::AnchorMismatch));
        }
        let mut segment = SegmentReader {
            reader,
            anchor: header.anchor,
            head: header.anchor,
            records: 0,
            offset: SEGMENT_HEADER_LEN as u64,
            limit,
            checkpoint,
            state: State::Reading,
        };
        segment.check_checkpoint(0)?;
        Ok(segment)
    }

    /// Record `error` as the walk's (sticky) break and return it.
    fn fail(&mut self, error: VerifyError) -> VerifyError {
        self.state = State::Broken(error);
        error
    }

    /// A break at the next expected record.
    fn broken(&mut self, kind: BreakKind, offset: u64) -> VerifyError {
        let error = VerifyError {
            kind,
            at_seq: self.head.seq.saturating_add(1),
            offset,
            last_good: self.head,
        };
        self.fail(error)
    }

    /// If the head has just reached the checkpoint's sequence, compare.
    fn check_checkpoint(&mut self, offset: u64) -> Result<(), VerifyError> {
        if let Some(checkpoint) = self.checkpoint {
            if checkpoint.seq == self.head.seq && checkpoint.hash != self.head.hash {
                let error = VerifyError {
                    kind: BreakKind::CheckpointMismatch,
                    at_seq: self.head.seq,
                    offset,
                    last_good: self.head,
                };
                return Err(self.fail(error));
            }
        }
        Ok(())
    }

    /// The next record, verified against its predecessor; `None` at a clean
    /// end of the segment (a record boundary).
    ///
    /// # Errors
    /// The first break ([`BreakKind`]). A break is sticky: every later call
    /// returns it again. After a clean end, every call returns `Ok(None)`.
    pub fn next_record(&mut self) -> Result<Option<Record>, VerifyError> {
        match self.state {
            State::Reading => {}
            State::Ended => return Ok(None),
            State::Broken(error) => return Err(error),
        }
        let start = self.offset;
        let mut prefix = [0u8; RECORD_LEN_PREFIX];
        match fill(&mut self.reader, &mut prefix) {
            Ok(Fill::Full) => {}
            Ok(Fill::Eof) => {
                self.state = State::Ended;
                return Ok(None);
            }
            Ok(Fill::Partial) => return Err(self.broken(BreakKind::RecordTruncated, start)),
            Err(error) => return Err(self.broken(BreakKind::Io(error.kind()), start)),
        }
        // The declared length is checked against the record bounds before
        // the body is allocated or read.
        let body_len = usize::try_from(u32::from_be_bytes(prefix)).unwrap_or(usize::MAX);
        let min_body = MIN_RECORD_LEN - RECORD_LEN_PREFIX;
        let max_body = MAX_RECORD_LEN - RECORD_LEN_PREFIX;
        if !(min_body..=max_body).contains(&body_len) {
            return Err(self.broken(BreakKind::RecordLengthOutOfBounds, start));
        }
        let record_len = (RECORD_LEN_PREFIX + body_len) as u64;
        let end = start.saturating_add(record_len);
        if end > self.limit.max_octets() {
            return Err(self.broken(BreakKind::SegmentTooLarge, start));
        }
        let mut octets = vec![0u8; RECORD_LEN_PREFIX + body_len];
        let (prefix_room, body) = octets.split_at_mut(RECORD_LEN_PREFIX);
        prefix_room.copy_from_slice(&prefix);
        match fill(&mut self.reader, body) {
            Ok(Fill::Full) => {}
            Ok(Fill::Eof | Fill::Partial) => {
                return Err(self.broken(BreakKind::RecordTruncated, start))
            }
            Err(error) => return Err(self.broken(BreakKind::Io(error.kind()), start)),
        }
        let record = match parse_record_body(body) {
            Ok(record) => record,
            Err(fault) => {
                let kind = match fault {
                    RecordFault::PayloadLengthMismatch => BreakKind::PayloadLengthMismatch,
                    RecordFault::InvalidTimestamp => BreakKind::InvalidTimestamp,
                    RecordFault::UnknownSource => BreakKind::UnknownSource,
                };
                return Err(self.broken(kind, start));
            }
        };
        let expected_seq = self.head.seq.saturating_add(1);
        if self.head.seq == u64::MAX || record.seq != expected_seq {
            let found = record.seq;
            return Err(self.broken(BreakKind::SequenceGap { found }, start));
        }
        if record.prev_hash != self.head.hash {
            return Err(self.broken(BreakKind::LinkMismatch, start));
        }
        self.head = ChainHead {
            seq: record.seq,
            hash: RecordHash::of(&octets),
        };
        self.records = self.records.saturating_add(1);
        self.offset = end;
        self.check_checkpoint(start)?;
        Ok(Some(record))
    }

    /// The head after the records read so far.
    #[must_use]
    pub fn head(&self) -> ChainHead {
        self.head
    }

    /// The segment's anchor (from its header).
    #[must_use]
    pub fn anchor(&self) -> ChainHead {
        self.anchor
    }

    /// Read the remaining records and conclude.
    ///
    /// # Errors
    /// The first break; [`BreakKind::CheckpointNotReached`] if the segment
    /// ends before the checkpoint's sequence number.
    pub fn finish(self) -> Result<VerifiedSegment, VerifyError> {
        let verified = self.finish_without_reach()?;
        if let Some(checkpoint) = verified.checkpoint_short_of() {
            return Err(checkpoint);
        }
        Ok(verified.segment)
    }
}

/// Verify one whole segment.
///
/// # Errors
/// The first break ([`VerifyError`]).
///
/// Spec: docs/37 §2; docs/50 §7.5.
pub fn verify_segment<R: Read>(
    reader: R,
    anchor: Anchor,
    limit: SegmentLimit,
    checkpoint: Option<ChainHead>,
) -> Result<VerifiedSegment, VerifyError> {
    SegmentReader::open(reader, anchor, limit, checkpoint)?.finish()
}

/// A break in a multi-segment log: which segment, and the break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogBreak {
    /// Position of the segment in the order given (0 = first).
    pub segment: usize,
    /// The break.
    pub error: VerifyError,
}

impl fmt::Display for LogBreak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "segment {}: {}", self.segment, self.error)
    }
}

impl std::error::Error for LogBreak {}

/// Verify consecutive segments of one log, in order: the first against
/// `first`, each later one anchored at the head of the one before it. The
/// `checkpoint`, if any, must be passed somewhere in the log and reached by
/// its end. Returns the head after the last segment.
///
/// # Errors
/// The first break and the segment it is in.
///
/// Spec: docs/37 §2; docs/questions/Q-250 item 6 (one chain across
/// rotation).
pub fn verify_log<R: Read, I: IntoIterator<Item = R>>(
    segments: I,
    first: Anchor,
    limit: SegmentLimit,
    checkpoint: Option<ChainHead>,
) -> Result<ChainHead, LogBreak> {
    let mut anchor = first;
    let mut head = None;
    for (segment, reader) in segments.into_iter().enumerate() {
        // The checkpoint is checked in whichever segment holds its sequence;
        // "not reached" is decided once, after the last segment.
        let walked = SegmentReader::open(reader, anchor, limit, checkpoint)
            .and_then(SegmentReader::finish_without_reach)
            .map_err(|error| LogBreak { segment, error })?;
        anchor = Anchor::After(walked.segment.head);
        head = Some((segment, walked));
    }
    let Some((segment, last)) = head else {
        // No segment at all: the head is the first anchor, if it names one.
        return match first {
            Anchor::After(head) => Ok(head),
            Anchor::Genesis | Anchor::Trusted => Ok(ChainHead::GENESIS),
        };
    };
    if let Some(error) = last.checkpoint_short_of() {
        return Err(LogBreak { segment, error });
    }
    Ok(last.segment.head)
}

/// A segment walked to its end, with the checkpoint it was walked against.
struct Walked {
    segment: VerifiedSegment,
    checkpoint: Option<ChainHead>,
}

impl Walked {
    /// [`BreakKind::CheckpointNotReached`] if the walk ended before the
    /// checkpoint's sequence number.
    fn checkpoint_short_of(&self) -> Option<VerifyError> {
        let checkpoint = self.checkpoint?;
        let head = self.segment.head;
        (head.seq < checkpoint.seq).then_some(VerifyError {
            kind: BreakKind::CheckpointNotReached,
            at_seq: head.seq.saturating_add(1),
            offset: self.segment.len,
            last_good: head,
        })
    }
}

impl<R: Read> SegmentReader<R> {
    /// Read to the end without the "checkpoint reached" rule (decided by the
    /// caller: per segment, or once for a whole log).
    fn finish_without_reach(mut self) -> Result<Walked, VerifyError> {
        while self.next_record()?.is_some() {}
        Ok(Walked {
            segment: VerifiedSegment {
                anchor: self.anchor,
                head: self.head,
                records: self.records,
                len: self.offset,
            },
            checkpoint: self.checkpoint,
        })
    }
}
