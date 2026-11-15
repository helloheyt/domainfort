//! The writer: appends records to the current segment and acknowledges them
//! only after they are synced.
//!
//! One call appends one batch: every record of the batch is encoded and
//! chained in memory, written with one `write_all`, flushed, and synced; only
//! when the sync succeeded does the writer advance its head and return
//! [`Persisted`]. That return value is what an IPC acknowledgement may carry
//! (docs/50 §8.1: "auditd acknowledges the last sequence number persisted").
//! If the write, the flush or the sync fails, nothing is acknowledged and the
//! writer is **poisoned**: the segment may now end in a partial batch, so the
//! writer refuses every further append (fail closed) until the daemon
//! re-verifies the segment and starts a new one. A failed sync is never
//! retried and then reported as success.
//!
//! Overflow is not shutdown (docs/questions/Q-218, A-57): a batch that would
//! push the segment past its bound is refused with
//! [`AppendError::SegmentFull`] **before** anything is written, and the
//! caller rotates ([`LogWriter::rotate`]) — the chain continues in the next
//! segment. Nothing in this crate stops a process.
//!
//! Spec: docs/50 R50-17, §8.1; docs/37 §2; docs/07 §8 ("the log does not
//! bring the service down when it fills"; "a separate disk quota");
//! docs/questions/Q-218 (A-57), OD-8; docs/questions/Q-250.

use crate::format::{
    ChainHead, RecordFields, SegmentHeader, Source, Timestamp, MAX_BATCH_RECORDS, MAX_PAYLOAD_LEN,
    MAX_RECORD_LEN, MIN_PAYLOAD_LEN, SEGMENT_HEADER_LEN,
};
use crate::sign::HeadSigner;
use crate::verify::VerifiedSegment;
use core::fmt;
use std::io::{self, Write};

/// Where a segment's octets go: an append-only sink with an explicit flush
/// and an explicit durability barrier.
///
/// The writer calls, for every batch, exactly: [`Storage::write_all`] once,
/// then [`Storage::flush`], then [`Storage::sync`], and acknowledges only
/// after `sync` returned `Ok`. Tests implement this trait to observe that
/// order.
///
/// Spec: docs/50 §8.1 (persistence acknowledgements); docs/questions/Q-250
/// item 7.
pub trait Storage {
    /// Append `octets` at the end of the segment.
    ///
    /// # Errors
    /// Any I/O failure (the writer is then poisoned).
    fn write_all(&mut self, octets: &[u8]) -> io::Result<()>;

    /// Hand buffered octets to the operating system.
    ///
    /// # Errors
    /// Any I/O failure (the writer is then poisoned).
    fn flush(&mut self) -> io::Result<()>;

    /// The durability barrier: return only when the octets written so far
    /// are on stable storage.
    ///
    /// # Errors
    /// Any I/O failure (the writer is then poisoned; nothing is
    /// acknowledged).
    fn sync(&mut self) -> io::Result<()>;
}

/// A segment file on the local file system, held by its open descriptor.
///
/// This crate opens no file: the caller hands over a file it opened **in
/// append mode** (every write lands at the end; no existing octet is ever
/// overwritten) — auditd through crates/protected-file's walk
/// (`create_new_append`: exclusive, no link followed, owner-read-write only;
/// `open_append` for a verified segment), so no segment is ever reached by
/// a path a link could redirect (docs/52 R11; docs/questions/Q-481 item b,
/// Q-530). The durability barrier is `std::fs::File::sync_data`. Whether
/// `sync_data` also persists the grown file length is operating-system
/// semantics (docs/questions/Q-215); docs/questions/Q-250 item 7 records
/// the choice.
///
/// Spec: docs/50 §6.4 ("auditd: append write access to the audit file
/// only"), §8.1; docs/52 §3.13 (C13).
#[derive(Debug)]
pub struct FileStorage {
    file: std::fs::File,
}

impl FileStorage {
    /// The storage of the segment open in `file`, which the caller opened
    /// for appending (a new segment created exclusively, or a verified one,
    /// [`LogWriter::resume`]).
    ///
    /// Spec: docs/50 §6.4, §8.1; docs/questions/Q-530.
    #[must_use]
    pub fn new(file: std::fs::File) -> FileStorage {
        FileStorage { file }
    }
}

impl Storage for FileStorage {
    fn write_all(&mut self, octets: &[u8]) -> io::Result<()> {
        self.file.write_all(octets)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }

    fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }
}

/// The bound on one segment's size, header included.
///
/// At least [`SegmentLimit::MIN`] (a header and one full batch of largest
/// records, so every valid batch fits an empty segment and rotation always
/// makes progress) and at most [`SegmentLimit::CEILING`].
///
/// Spec: docs/07 §8 ("a separate disk quota"); OD-8 (retention: no number
/// given) — the values are project choices, docs/questions/Q-250 item 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentLimit(u64);

impl SegmentLimit {
    /// Smallest allowed bound: header + one batch of
    /// [`MAX_BATCH_RECORDS`] records of [`MAX_RECORD_LEN`] octets.
    pub const MIN: u64 = (SEGMENT_HEADER_LEN + MAX_BATCH_RECORDS * MAX_RECORD_LEN) as u64;

    /// Largest allowed bound: 1 GiB. Project choice.
    pub const CEILING: u64 = 1024 * 1024 * 1024;

    /// The default bound: 64 MiB. Project choice.
    pub const DEFAULT: SegmentLimit = SegmentLimit(64 * 1024 * 1024);

    /// The largest bound, for verifying segments of any allowed size.
    pub const LARGEST: SegmentLimit = SegmentLimit(Self::CEILING);

    /// A bound of `max_octets`, or `None` outside
    /// [`SegmentLimit::MIN`]`..=`[`SegmentLimit::CEILING`].
    #[must_use]
    pub const fn new(max_octets: u64) -> Option<SegmentLimit> {
        if max_octets < Self::MIN || max_octets > Self::CEILING {
            None
        } else {
            Some(SegmentLimit(max_octets))
        }
    }

    /// The bound in octets.
    #[must_use]
    pub const fn max_octets(self) -> u64 {
        self.0
    }
}

// The default lies inside the allowed range (compile-time check).
const _: () = assert!(SegmentLimit::DEFAULT.0 >= SegmentLimit::MIN);
const _: () = assert!(SegmentLimit::DEFAULT.0 <= SegmentLimit::CEILING);

/// One event to append. `source` and `source_uid` come from the connection
/// (the peer credentials), never from the payload.
///
/// Spec: docs/50 §3.2, §8.1, R50-17.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    /// The sending process, mapped from the peer uid.
    pub source: Source,
    /// The peer uid of the connection.
    pub source_uid: u32,
    /// The sender's sequence number for this event.
    pub source_seq: u64,
    /// The event payload ([`MIN_PAYLOAD_LEN`]`..=`[`MAX_PAYLOAD_LEN`]
    /// octets).
    pub payload: &'a [u8],
}

/// What a successful append acknowledges: the batch is on stable storage.
///
/// Spec: docs/50 §8.1 (persistence acknowledgement).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Persisted {
    /// Sequence number of the batch's first record.
    pub first_seq: u64,
    /// Sequence number and hash of the batch's last record — the new head.
    pub head: ChainHead,
}

/// Why an append (or a rotation) was refused.
///
/// Every refusal except the I/O ones happens before any octet is written.
/// No variant carries payload octets (docs/CLEAN-ROOM.md; docs/50 §8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendError {
    /// An earlier write, flush or sync failed; the segment's tail is unknown
    /// and the writer refuses everything (fail closed).
    Poisoned,
    /// The batch has no entry.
    EmptyBatch,
    /// The batch has more than [`MAX_BATCH_RECORDS`] entries.
    BatchTooLarge,
    /// The entry at `index` has a payload outside
    /// [`MIN_PAYLOAD_LEN`]`..=`[`MAX_PAYLOAD_LEN`].
    PayloadOutOfBounds {
        /// Position of the entry in the batch.
        index: usize,
    },
    /// The batch would push the segment past its [`SegmentLimit`]: rotate,
    /// then append again. Nothing was written.
    SegmentFull,
    /// The record sequence number would pass `u64::MAX` (never wraps).
    SequenceExhausted,
    /// The verified segment handed to [`LogWriter::resume`] is already
    /// larger than the limit.
    ResumeOverLimit,
    /// The storage failed; the writer is now poisoned.
    Io(io::ErrorKind),
}

impl fmt::Display for AppendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppendError::Poisoned => f.write_str("audit writer poisoned by an earlier I/O failure"),
            AppendError::EmptyBatch => f.write_str("empty batch"),
            AppendError::BatchTooLarge => f.write_str("batch has too many records"),
            AppendError::PayloadOutOfBounds { index } => {
                write!(f, "payload of entry {index} is out of bounds")
            }
            AppendError::SegmentFull => f.write_str("segment full: rotate"),
            AppendError::SequenceExhausted => f.write_str("record sequence exhausted"),
            AppendError::ResumeOverLimit => f.write_str("segment already over its limit"),
            AppendError::Io(kind) => write!(f, "storage failure: {kind}"),
        }
    }
}

impl std::error::Error for AppendError {}

/// Appends records to one segment at a time and acknowledges only synced
/// records.
///
/// Spec: docs/50 R50-17, §8.1; docs/37 §2; docs/questions/Q-218 (A-57).
pub struct LogWriter<S: Storage> {
    storage: S,
    /// The head the current segment continues from (its header).
    anchor: ChainHead,
    /// The head of the persisted chain: advanced only after a sync.
    head: ChainHead,
    /// Octets in the current segment, header included.
    segment_len: u64,
    limit: SegmentLimit,
    poisoned: bool,
}

impl<S: Storage> fmt::Debug for LogWriter<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogWriter")
            .field("anchor", &self.anchor)
            .field("head", &self.head)
            .field("segment_len", &self.segment_len)
            .field("limit", &self.limit)
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

/// Write `octets`, flush, sync — in that order. Spec: docs/50 §8.1.
fn write_synced<S: Storage>(storage: &mut S, octets: &[u8]) -> io::Result<()> {
    storage.write_all(octets)?;
    storage.flush()?;
    storage.sync()
}

impl<S: Storage> LogWriter<S> {
    /// Start a new segment in `storage` (which must be empty) continuing
    /// from `anchor`: write its header and sync it.
    ///
    /// [`ChainHead::GENESIS`] starts a new log; the head of the previous
    /// segment continues an existing one ([`LogWriter::rotate`] does this).
    ///
    /// # Errors
    /// [`AppendError::Io`] if the header cannot be written and synced.
    ///
    /// Spec: docs/37 §2; docs/questions/Q-250 items 2, 6.
    pub fn start_segment(
        mut storage: S,
        anchor: ChainHead,
        limit: SegmentLimit,
    ) -> Result<LogWriter<S>, AppendError> {
        let header = SegmentHeader { anchor }.encode();
        write_synced(&mut storage, &header).map_err(|error| AppendError::Io(error.kind()))?;
        Ok(LogWriter {
            storage,
            anchor,
            head: anchor,
            segment_len: SEGMENT_HEADER_LEN as u64,
            limit,
            poisoned: false,
        })
    }

    /// Start a new log (the first segment, anchored at genesis).
    ///
    /// # Errors
    /// As [`LogWriter::start_segment`].
    pub fn create(storage: S, limit: SegmentLimit) -> Result<LogWriter<S>, AppendError> {
        LogWriter::start_segment(storage, ChainHead::GENESIS, limit)
    }

    /// Continue appending to a segment the verifier has walked end to end:
    /// `storage` must append to exactly the octets `verified` describes.
    ///
    /// # Errors
    /// [`AppendError::ResumeOverLimit`] if the segment is already larger than
    /// `limit`.
    ///
    /// Spec: docs/50 §7.5 ("auditd — opens the file, verifies the hash
    /// chain from the last record, listens").
    pub fn resume(
        storage: S,
        verified: &VerifiedSegment,
        limit: SegmentLimit,
    ) -> Result<LogWriter<S>, AppendError> {
        if verified.len() > limit.max_octets() {
            return Err(AppendError::ResumeOverLimit);
        }
        Ok(LogWriter {
            storage,
            anchor: verified.anchor(),
            head: verified.head(),
            segment_len: verified.len(),
            limit,
            poisoned: false,
        })
    }

    /// Append one entry: a batch of one ([`LogWriter::append_batch`]).
    ///
    /// # Errors
    /// As [`LogWriter::append_batch`].
    pub fn append(&mut self, entry: &Entry<'_>, time: Timestamp) -> Result<Persisted, AppendError> {
        self.append_batch(core::slice::from_ref(entry), time)
    }

    /// Append a batch: encode and chain every record, write them with one
    /// write, flush, sync, and only then advance the head and return what
    /// was persisted. Every record of the batch carries `time` (auditd's
    /// clock, read once per batch).
    ///
    /// # Errors
    /// * Refused before anything is written: [`AppendError::Poisoned`],
    ///   [`AppendError::EmptyBatch`], [`AppendError::BatchTooLarge`],
    ///   [`AppendError::PayloadOutOfBounds`], [`AppendError::SequenceExhausted`],
    ///   [`AppendError::SegmentFull`] (rotate and retry).
    /// * [`AppendError::Io`]: the write, flush or sync failed; nothing is
    ///   acknowledged and the writer is poisoned.
    ///
    /// Spec: docs/50 §8.1 ("auditd acknowledges the last sequence number
    /// persisted"); docs/37 §2; docs/questions/Q-218 (A-57).
    pub fn append_batch(
        &mut self,
        entries: &[Entry<'_>],
        time: Timestamp,
    ) -> Result<Persisted, AppendError> {
        if self.poisoned {
            return Err(AppendError::Poisoned);
        }
        if entries.is_empty() {
            return Err(AppendError::EmptyBatch);
        }
        if entries.len() > MAX_BATCH_RECORDS {
            return Err(AppendError::BatchTooLarge);
        }
        for (index, entry) in entries.iter().enumerate() {
            if !(MIN_PAYLOAD_LEN..=MAX_PAYLOAD_LEN).contains(&entry.payload.len()) {
                return Err(AppendError::PayloadOutOfBounds { index });
            }
        }
        let count = u64::try_from(entries.len()).map_err(|_| AppendError::BatchTooLarge)?;
        let first_seq = self
            .head
            .seq
            .checked_add(1)
            .ok_or(AppendError::SequenceExhausted)?;
        // The last sequence number must also be representable.
        first_seq
            .checked_add(count.saturating_sub(1))
            .ok_or(AppendError::SequenceExhausted)?;

        // Encode and chain in memory; nothing touches the storage yet.
        let mut octets = Vec::new();
        let mut head = self.head;
        for entry in entries {
            let seq = head.seq.saturating_add(1);
            let hash = RecordFields {
                seq,
                prev_hash: head.hash,
                time,
                source: entry.source,
                source_uid: entry.source_uid,
                source_seq: entry.source_seq,
                payload: entry.payload,
            }
            .encode_into(&mut octets);
            head = ChainHead { seq, hash };
        }
        let batch_len = u64::try_from(octets.len()).map_err(|_| AppendError::SegmentFull)?;
        let new_len = self
            .segment_len
            .checked_add(batch_len)
            .ok_or(AppendError::SegmentFull)?;
        if new_len > self.limit.max_octets() {
            return Err(AppendError::SegmentFull);
        }

        if let Err(error) = write_synced(&mut self.storage, &octets) {
            self.poisoned = true;
            return Err(AppendError::Io(error.kind()));
        }
        // Synced: only now is the batch acknowledged.
        self.head = head;
        self.segment_len = new_len;
        Ok(Persisted { first_seq, head })
    }

    /// Rotation: start a new segment in `next` (which must be empty),
    /// anchored at the current head, sync its header, and switch to it. The
    /// previous segment's storage is returned so the caller can close it.
    /// The chain is unbroken: the next record links to the last record of
    /// the previous segment.
    ///
    /// Retention (which old segments are removed, and when) is the daemon's
    /// policy, not this crate's (OD-8; docs/questions/Q-250 item 6).
    ///
    /// # Errors
    /// [`AppendError::Poisoned`]; [`AppendError::Io`] if the new header
    /// cannot be written and synced (the writer keeps the previous segment,
    /// not poisoned — its octets are untouched).
    ///
    /// Spec: docs/07 §8 (the log does not bring the service down when it
    /// fills); docs/questions/Q-218 (A-57); OD-8.
    pub fn rotate(&mut self, next: S) -> Result<S, AppendError> {
        if self.poisoned {
            return Err(AppendError::Poisoned);
        }
        let mut next = next;
        let header = SegmentHeader { anchor: self.head }.encode();
        write_synced(&mut next, &header).map_err(|error| AppendError::Io(error.kind()))?;
        let previous = core::mem::replace(&mut self.storage, next);
        self.anchor = self.head;
        self.segment_len = SEGMENT_HEADER_LEN as u64;
        Ok(previous)
    }

    /// The head of the persisted (synced) chain.
    #[must_use]
    pub fn head(&self) -> ChainHead {
        self.head
    }

    /// The head the current segment continues from.
    #[must_use]
    pub fn segment_anchor(&self) -> ChainHead {
        self.anchor
    }

    /// Octets in the current segment, header included.
    #[must_use]
    pub fn segment_len(&self) -> u64 {
        self.segment_len
    }

    /// The segment bound.
    #[must_use]
    pub fn limit(&self) -> SegmentLimit {
        self.limit
    }

    /// Whether an I/O failure has poisoned the writer.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Ask `signer` to sign the persisted head (never an unsynced one). Where
    /// the signature is kept, and who holds the key, is undecided
    /// (docs/questions/Q-251).
    ///
    /// # Errors
    /// The signer's error.
    ///
    /// Spec: docs/37 §2 ("each DC signs its segment (signing key in an
    /// HSM)"), D157; docs/questions/Q-218 item 2, Q-251.
    pub fn sign_head<H: HeadSigner>(&self, signer: &mut H) -> Result<H::Signature, H::Error> {
        signer.sign_head(&self.head)
    }

    /// The storage of the current segment.
    #[must_use]
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Give up the writer and return the current segment's storage.
    #[must_use]
    pub fn into_storage(self) -> S {
        self.storage
    }
}
