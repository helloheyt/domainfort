//! Shared test helpers: an in-memory [`Storage`] that records the order of
//! operations and can be told to fail, and a builder for small logs.
//!
//! The payloads are arbitrary test octets made up here (the log treats them
//! as opaque); no fixture comes from any other implementation.
#![allow(dead_code)]

use audit_log::{ChainHead, Entry, LogWriter, Persisted, SegmentLimit, Source, Storage, Timestamp};
use std::cell::RefCell;
use std::io;
use std::rc::Rc;

/// One operation the writer performed on its storage, or the test's own
/// marker that it received an acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Write,
    Flush,
    Sync,
    Ack,
}

/// Which storage call should fail next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailAt {
    Nothing,
    Write,
    Flush,
    Sync,
}

/// Shared state behind [`MemStorage`].
#[derive(Debug)]
pub struct MemState {
    /// Every octet handed to `write_all`.
    pub written: Vec<u8>,
    /// Octets known to be durable (copied at each successful sync).
    pub durable: Vec<u8>,
    /// The order of operations (and the test's `Ack` markers).
    pub ops: Vec<Op>,
    /// The call that fails next.
    pub fail_at: FailAt,
}

/// An in-memory segment.
#[derive(Debug, Clone)]
pub struct MemStorage {
    pub state: Rc<RefCell<MemState>>,
}

impl MemStorage {
    pub fn new() -> MemStorage {
        MemStorage {
            state: Rc::new(RefCell::new(MemState {
                written: Vec::new(),
                durable: Vec::new(),
                ops: Vec::new(),
                fail_at: FailAt::Nothing,
            })),
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.state.borrow().written.clone()
    }

    pub fn durable(&self) -> Vec<u8> {
        self.state.borrow().durable.clone()
    }

    pub fn ops(&self) -> Vec<Op> {
        self.state.borrow().ops.clone()
    }

    pub fn mark_ack(&self) {
        self.state.borrow_mut().ops.push(Op::Ack);
    }

    pub fn fail_next(&self, at: FailAt) {
        self.state.borrow_mut().fail_at = at;
    }

    fn check(&self, at: FailAt) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        if state.fail_at == at {
            state.fail_at = FailAt::Nothing;
            return Err(io::Error::other("injected failure"));
        }
        Ok(())
    }
}

impl Storage for MemStorage {
    fn write_all(&mut self, octets: &[u8]) -> io::Result<()> {
        self.state.borrow_mut().ops.push(Op::Write);
        self.check(FailAt::Write)?;
        self.state.borrow_mut().written.extend_from_slice(octets);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.state.borrow_mut().ops.push(Op::Flush);
        self.check(FailAt::Flush)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.state.borrow_mut().ops.push(Op::Sync);
        self.check(FailAt::Sync)?;
        let mut state = self.state.borrow_mut();
        state.durable = state.written.clone();
        Ok(())
    }
}

/// A fixed test time.
pub fn time(secs: u64) -> Timestamp {
    Timestamp::new(secs, 123_456_789).expect("valid test time")
}

/// The payload of test event `n`: a few octets that differ per event.
pub fn payload(n: u64) -> Vec<u8> {
    let len = 1 + (n % 17) as usize;
    (0..len).map(|i| (n as u8).wrapping_add(i as u8)).collect()
}

/// The source of test event `n` (cycles through the closed table).
pub fn source(n: u64) -> Source {
    Source::ALL[(n % Source::ALL.len() as u64) as usize]
}

/// Append `count` test events one per batch; returns the storage, the
/// writer's head after each record (index 0 = genesis), and the writer.
pub fn build_log(count: u64) -> (MemStorage, Vec<ChainHead>, LogWriter<MemStorage>) {
    let storage = MemStorage::new();
    let mut writer = LogWriter::create(storage.clone(), SegmentLimit::DEFAULT).expect("create log");
    let mut heads = vec![writer.head()];
    for n in 1..=count {
        let data = payload(n);
        let persisted: Persisted = writer
            .append(
                &Entry {
                    source: source(n),
                    source_uid: 800 + n as u32,
                    source_seq: n,
                    payload: &data,
                },
                time(1_700_000_000 + n),
            )
            .expect("append");
        assert_eq!(persisted.first_seq, n);
        heads.push(persisted.head);
    }
    (storage, heads, writer)
}

/// Offsets of each record in a single-segment log (index `k` = start of the
/// record with sequence `k + 1`), plus the end offset last.
pub fn record_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut at = audit_log::SEGMENT_HEADER_LEN;
    while at + 4 <= bytes.len() {
        offsets.push(at);
        let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        at += 4 + len;
    }
    offsets.push(at);
    offsets
}

/// A unique, empty temporary directory for one test.
pub fn temp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "audit-log-test-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}
