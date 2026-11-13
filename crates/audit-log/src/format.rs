//! The on-disk layout: segment header, record, chain hash, and the named
//! bounds.
//!
//! ```text
//! Segment       := SegmentHeader ‖ Record*
//! SegmentHeader := magic:[8] ‖ format_version:u8 ‖ anchor_seq:u64 ‖ anchor_hash:[32]
//! Record        := record_len:u32 ‖ RecordBody            (record_len = |RecordBody|)
//! RecordBody    := seq:u64 ‖ prev_hash:[32] ‖ time_secs:u64 ‖ time_nanos:u32
//!                  ‖ source:u8 ‖ source_uid:u32 ‖ source_seq:u64
//!                  ‖ payload_len:u32 ‖ payload[payload_len]
//! ```
//!
//! All integers are fixed width, big-endian (the same convention as the IPC
//! codec, docs/50 §3.3). Every field has exactly one valid encoding: lengths
//! are cross-checked (`record_len = RECORD_FIXED_BODY_LEN + payload_len`),
//! `time_nanos` is below one second, `source` is from a closed table.
//!
//! The chain: the hash of a record is SHA-256 over its whole encoding, length
//! prefix included. Record `n`'s `prev_hash` is the hash of record `n - 1`;
//! the first record of a segment links to the segment's anchor, and the
//! anchor of the first segment of a log is [`ChainHead::GENESIS`]: sequence 0
//! and [`GENESIS_HASH`] (32 zero octets — "no predecessor"). Record sequence
//! numbers start at 1 and rise by exactly one, across segments.
//!
//! Spec: docs/37 §2 ("every audit record includes the hash of its predecessor
//! → deleting or changing a record breaks the chain"); docs/50 R50-17, §8.1
//! (SHA-256; the source set from the connection's uid; auditd's clock);
//! docs/50 §3.3 (8 KiB per audit event; big-endian fixed-width fields).
//! Project choices are marked as such and listed in docs/questions/Q-250.

use core::fmt;
use sha2::{Digest, Sha256};

/// Octets of a chain hash (SHA-256 output). Spec: docs/50 §8.1 (SHA-256).
pub const HASH_LEN: usize = 32;

/// The genesis value: what the first record of a log links to. 32 zero
/// octets, read as "no predecessor".
///
/// It binds nothing: a whole log rewritten from genesis is a valid chain.
/// The start of the log is protected by the signed chain head and the
/// off-box copy (docs/37 §2; docs/questions/Q-251), not by this constant.
///
/// Spec: docs/37 §2 (hash-chain); project choice (docs/questions/Q-250
/// item 2).
pub const GENESIS_HASH: RecordHash = RecordHash([0; HASH_LEN]);

/// The 8-octet magic that opens every segment file. Project choice.
/// Spec: docs/questions/Q-250 item 1.
pub const SEGMENT_MAGIC: [u8; 8] = *b"AUDCHAIN";

/// The one format version this build reads and writes (exact match; no
/// negotiation — the same rule as the IPC codec, docs/50 §3.3, D57).
pub const FORMAT_VERSION: u8 = 1;

/// Octets of the segment header: magic, version, anchor sequence, anchor
/// hash. Spec: this module's layout.
pub const SEGMENT_HEADER_LEN: usize = 8 + 1 + 8 + HASH_LEN;

/// Octets of a record's length prefix (`record_len:u32`).
pub const RECORD_LEN_PREFIX: usize = 4;

/// Octets of a record body before the payload: `seq`, `prev_hash`,
/// `time_secs`, `time_nanos`, `source`, `source_uid`, `source_seq`,
/// `payload_len`.
pub const RECORD_FIXED_BODY_LEN: usize = 8 + HASH_LEN + 8 + 4 + 1 + 4 + 8 + 4;

/// Largest event payload in one record: 8 KiB.
/// Spec: docs/50 §3.3 ("audit ≤ 8 KiB per event").
pub const MAX_PAYLOAD_LEN: usize = 8 * 1024;

/// Smallest event payload: one octet (a record always carries an event).
/// Project choice (docs/questions/Q-250 item 3).
pub const MIN_PAYLOAD_LEN: usize = 1;

/// Largest whole record, length prefix included.
pub const MAX_RECORD_LEN: usize = RECORD_LEN_PREFIX + RECORD_FIXED_BODY_LEN + MAX_PAYLOAD_LEN;

/// Smallest whole record, length prefix included.
pub const MIN_RECORD_LEN: usize = RECORD_LEN_PREFIX + RECORD_FIXED_BODY_LEN + MIN_PAYLOAD_LEN;

/// Most records one synced batch may hold (bounds the writer's buffer at
/// `MAX_BATCH_RECORDS × MAX_RECORD_LEN`). Project choice
/// (docs/questions/Q-250 item 4).
pub const MAX_BATCH_RECORDS: usize = 64;

/// Nanoseconds in one second: `time_nanos` must be below this.
const NANOS_PER_SECOND: u32 = 1_000_000_000;

// The record length is a u32 on disk and a usize in memory; both bounds must
// fit both types. Compile-time checks, not runtime panics.
const _: () = assert!(usize::BITS >= 32);
const _: () = assert!(MAX_RECORD_LEN <= u32::MAX as usize);

/// A chain hash: SHA-256 over one encoded record (or [`GENESIS_HASH`]).
///
/// `Debug` prints the hash in hexadecimal; a hash is public (it is what the
/// IPC acknowledgement carries, docs/50 §8.1).
///
/// Spec: docs/37 §2; docs/50 §8.1.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordHash([u8; HASH_LEN]);

impl RecordHash {
    /// Wrap 32 hash octets.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; HASH_LEN]) -> RecordHash {
        RecordHash(bytes)
    }

    /// The hash octets.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// SHA-256 of `octets`, through the approved `sha2` crate.
    ///
    /// Spec: docs/50 §8.1 ("SHA-256 from the approved RustCrypto"); AGENTS.md
    /// §6 (no primitive implemented here); docs.rs sha2 0.11.1 (`Digest`).
    #[must_use]
    pub fn of(octets: &[u8]) -> RecordHash {
        // `Output<Sha256>` is a 32-octet `Array`, which converts into
        // `[u8; 32]` (docs.rs hybrid-array 0.4.11 `From<Array<T, U>> for
        // [T; N]`); the size is fixed by the type, so this cannot fail.
        RecordHash(<[u8; HASH_LEN]>::from(Sha256::digest(octets)))
    }
}

impl fmt::Debug for RecordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordHash(")?;
        for octet in self.0 {
            write!(f, "{octet:02x}")?;
        }
        f.write_str(")")
    }
}

/// The head of a chain: the sequence number and hash of its last record, or
/// of the anchor when no record follows it.
///
/// Spec: docs/37 §2; docs/50 §8.1 (the acknowledgement names what was
/// persisted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainHead {
    /// Sequence number of the last record (0 = no record yet).
    pub seq: u64,
    /// Hash of the last record ([`GENESIS_HASH`] for an empty log).
    pub hash: RecordHash,
}

impl ChainHead {
    /// The head of an empty log: sequence 0, [`GENESIS_HASH`]. The first
    /// record of a log has sequence 1 and links to it.
    /// Spec: docs/questions/Q-250 item 2 (project choice).
    pub const GENESIS: ChainHead = ChainHead {
        seq: 0,
        hash: GENESIS_HASH,
    };
}

/// The process a record came from, set by auditd from the connection's peer
/// uid — never from the event body. Closed table; codes are a project
/// choice.
///
/// Spec: docs/50 §3.2 ("each marked as the event source — the source is set
/// from the uid, not from the event body"), §2.4 (the processes), R50-17;
/// docs/questions/Q-250 item 5 (`Auditd`, for auditd's own records).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// keyd. Spec: docs/50 §2.4.
    Keyd,
    /// dird (the LDAP engine's events, R49-14). Spec: docs/50 §2.4.
    Dird,
    /// kdc. Spec: docs/50 §2.4.
    Kdc,
    /// ldap-front. Spec: docs/50 §2.4.
    LdapFront,
    /// admind. Spec: docs/50 §2.4.
    Admind,
    /// auditd itself (for example: a connection from an unmapped uid was
    /// refused — docs/50 §3.2 "closed + an audit record").
    Auditd,
}

impl Source {
    /// Every source, in code order.
    pub const ALL: [Source; 6] = [
        Source::Keyd,
        Source::Dird,
        Source::Kdc,
        Source::LdapFront,
        Source::Admind,
        Source::Auditd,
    ];

    /// The on-disk code. Project choice; 0 is never a code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Source::Keyd => 1,
            Source::Dird => 2,
            Source::Kdc => 3,
            Source::LdapFront => 4,
            Source::Admind => 5,
            Source::Auditd => 6,
        }
    }

    /// The source for an on-disk code, or `None` outside the closed table.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Source> {
        match code {
            1 => Some(Source::Keyd),
            2 => Some(Source::Dird),
            3 => Some(Source::Kdc),
            4 => Some(Source::LdapFront),
            5 => Some(Source::Admind),
            6 => Some(Source::Auditd),
            _ => None,
        }
    }
}

/// A record's time, read from auditd's own clock (never from the sender):
/// seconds and nanoseconds since the Unix epoch (UTC).
///
/// Spec: docs/50 R50-17 (the record is auditd's), §3.5 (a daemon reads its
/// own clock rather than trusting a peer's).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    secs: u64,
    nanos: u32,
}

/// The system clock reads before the Unix epoch (fail closed: no record is
/// written with a time that cannot be represented).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockBeforeEpoch;

impl fmt::Display for ClockBeforeEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("system clock is before the Unix epoch")
    }
}

impl std::error::Error for ClockBeforeEpoch {}

impl Timestamp {
    /// A time of `secs` seconds and `nanos` nanoseconds after the epoch, or
    /// `None` when `nanos` is a second or more (one encoding per instant).
    #[must_use]
    pub const fn new(secs: u64, nanos: u32) -> Option<Timestamp> {
        if nanos < NANOS_PER_SECOND {
            Some(Timestamp { secs, nanos })
        } else {
            None
        }
    }

    /// The current time from the system clock (`std::time::SystemTime`).
    ///
    /// # Errors
    /// [`ClockBeforeEpoch`] if the clock reads before 1970.
    ///
    /// Spec: docs/50 R50-17, §3.5 (auditd's own clock).
    pub fn now() -> Result<Timestamp, ClockBeforeEpoch> {
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ClockBeforeEpoch)?;
        Ok(Timestamp {
            secs: since.as_secs(),
            nanos: since.subsec_nanos(),
        })
    }

    /// Whole seconds since the epoch.
    #[must_use]
    pub const fn secs(self) -> u64 {
        self.secs
    }

    /// Nanoseconds past [`Timestamp::secs`] (below one second).
    #[must_use]
    pub const fn nanos(self) -> u32 {
        self.nanos
    }
}

/// A segment's header: the head the segment continues from.
///
/// Spec: this module's layout; docs/questions/Q-250 item 6 (rotation keeps
/// one chain across segments).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    /// The head before the segment's first record (sequence `anchor.seq + 1`
    /// is the first record's).
    pub anchor: ChainHead,
}

/// Why a segment header is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderFault {
    /// The magic is not [`SEGMENT_MAGIC`].
    BadMagic,
    /// The version is not [`FORMAT_VERSION`].
    UnsupportedVersion,
}

impl SegmentHeader {
    /// The header's encoding.
    #[must_use]
    pub fn encode(&self) -> [u8; SEGMENT_HEADER_LEN] {
        let mut out = [0u8; SEGMENT_HEADER_LEN];
        let mut cursor = Out::new(&mut out);
        cursor.put(&SEGMENT_MAGIC);
        cursor.put(&[FORMAT_VERSION]);
        cursor.put(&self.anchor.seq.to_be_bytes());
        cursor.put(self.anchor.hash.as_bytes());
        out
    }

    /// Parse a header (exact magic and version).
    pub(crate) fn parse(octets: &[u8; SEGMENT_HEADER_LEN]) -> Result<SegmentHeader, HeaderFault> {
        let mut input = In::new(octets);
        let magic: [u8; 8] = input.take().ok_or(HeaderFault::BadMagic)?;
        if magic != SEGMENT_MAGIC {
            return Err(HeaderFault::BadMagic);
        }
        let [version]: [u8; 1] = input.take().ok_or(HeaderFault::UnsupportedVersion)?;
        if version != FORMAT_VERSION {
            return Err(HeaderFault::UnsupportedVersion);
        }
        let seq: [u8; 8] = input.take().ok_or(HeaderFault::BadMagic)?;
        let hash: [u8; HASH_LEN] = input.take().ok_or(HeaderFault::BadMagic)?;
        Ok(SegmentHeader {
            anchor: ChainHead {
                seq: u64::from_be_bytes(seq),
                hash: RecordHash(hash),
            },
        })
    }
}

/// One record, as read back by the verifier.
///
/// Spec: docs/50 R50-17, §8.1; docs/37 §2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The record's sequence number in the log.
    pub seq: u64,
    /// The hash of the previous record (or the segment anchor).
    pub prev_hash: RecordHash,
    /// auditd's clock when the record's batch was written.
    pub time: Timestamp,
    /// The sending process, from the connection's uid.
    pub source: Source,
    /// The connection's peer uid (the transport identity, docs/50 §3.2).
    pub source_uid: u32,
    /// The sender's own sequence number for the event (docs/50 §8.1: "with
    /// the source's sequence number"). The sender's claim; auditd checks it
    /// only for contiguity on a connection.
    pub source_seq: u64,
    /// The event payload octets (opaque here; the sender's canonical event
    /// encoding).
    pub payload: Vec<u8>,
}

/// Why a record body is refused. The verifier turns these into its typed
/// break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordFault {
    /// `payload_len` disagrees with `record_len`, or is out of bounds.
    PayloadLengthMismatch,
    /// `time_nanos` is a second or more.
    InvalidTimestamp,
    /// `source` is outside the closed table.
    UnknownSource,
}

/// The fields of a record about to be encoded.
pub(crate) struct RecordFields<'a> {
    pub(crate) seq: u64,
    pub(crate) prev_hash: RecordHash,
    pub(crate) time: Timestamp,
    pub(crate) source: Source,
    pub(crate) source_uid: u32,
    pub(crate) source_seq: u64,
    pub(crate) payload: &'a [u8],
}

impl RecordFields<'_> {
    /// Append the record's encoding (length prefix included) to `out` and
    /// return its chain hash. The caller has checked the payload bounds.
    ///
    /// Spec: this module's layout; docs/37 §2.
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) -> RecordHash {
        let start = out.len();
        let body_len = RECORD_FIXED_BODY_LEN + self.payload.len();
        // Both lengths are bounded by MAX_RECORD_LEN, which fits a u32
        // (compile-time check above); saturate rather than panic.
        let record_len = u32::try_from(body_len).unwrap_or(u32::MAX);
        let payload_len = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&record_len.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(self.prev_hash.as_bytes());
        out.extend_from_slice(&self.time.secs.to_be_bytes());
        out.extend_from_slice(&self.time.nanos.to_be_bytes());
        out.push(self.source.code());
        out.extend_from_slice(&self.source_uid.to_be_bytes());
        out.extend_from_slice(&self.source_seq.to_be_bytes());
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(self.payload);
        RecordHash::of(out.get(start..).unwrap_or_default())
    }
}

/// Parse a record body (the octets after `record_len`). The caller has
/// checked `body.len()` against the record bounds.
///
/// Spec: this module's layout.
pub(crate) fn parse_record_body(body: &[u8]) -> Result<Record, RecordFault> {
    let mut input = In::new(body);
    let fault = RecordFault::PayloadLengthMismatch;
    let seq = u64::from_be_bytes(input.take().ok_or(fault)?);
    let prev_hash = RecordHash(input.take().ok_or(fault)?);
    let secs = u64::from_be_bytes(input.take().ok_or(fault)?);
    let nanos = u32::from_be_bytes(input.take().ok_or(fault)?);
    let [source_code]: [u8; 1] = input.take().ok_or(fault)?;
    let source_uid = u32::from_be_bytes(input.take().ok_or(fault)?);
    let source_seq = u64::from_be_bytes(input.take().ok_or(fault)?);
    let payload_len = u32::from_be_bytes(input.take().ok_or(fault)?);
    let payload = input.rest();
    let declared = usize::try_from(payload_len).map_err(|_| fault)?;
    if declared != payload.len() || !(MIN_PAYLOAD_LEN..=MAX_PAYLOAD_LEN).contains(&declared) {
        return Err(fault);
    }
    let time = Timestamp::new(secs, nanos).ok_or(RecordFault::InvalidTimestamp)?;
    let source = Source::from_code(source_code).ok_or(RecordFault::UnknownSource)?;
    Ok(Record {
        seq,
        prev_hash,
        time,
        source,
        source_uid,
        source_seq,
        payload: payload.to_vec(),
    })
}

/// A bounds-checked reader over a byte slice (no indexing, no panic).
struct In<'a> {
    rest: &'a [u8],
}

impl<'a> In<'a> {
    fn new(input: &'a [u8]) -> In<'a> {
        In { rest: input }
    }

    /// The next `N` octets, or `None` if fewer remain.
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, tail) = self.rest.split_first_chunk::<N>()?;
        self.rest = tail;
        Some(*head)
    }

    /// Everything not yet taken.
    fn rest(self) -> &'a [u8] {
        self.rest
    }
}

/// A bounds-checked writer into a fixed array (no indexing, no panic; a
/// write past the end is dropped, which the fixed layout rules out).
struct Out<'a> {
    rest: &'a mut [u8],
}

impl<'a> Out<'a> {
    fn new(out: &'a mut [u8]) -> Out<'a> {
        Out { rest: out }
    }

    fn put(&mut self, octets: &[u8]) {
        let rest = core::mem::take(&mut self.rest);
        let split = octets.len().min(rest.len());
        let (head, tail) = rest.split_at_mut(split);
        head.copy_from_slice(octets.get(..split).unwrap_or_default());
        self.rest = tail;
    }
}
