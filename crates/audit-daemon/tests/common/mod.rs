//! Shared test helpers: temp directories, small logs written through
//! crates/audit-log, configuration text, a socket server harness and a
//! blocking client.
//!
//! Every payload is arbitrary test octets made up here (the log treats them
//! as opaque), except the admin-plane events, which are encoded with
//! crate `ipc-audit` from values made up here (docs/51 §5.7); expected
//! encodings are assembled from this project's own layouts (crate
//! `audit_daemon::own_event`, crate `audit-log` `format`). No fixture comes
//! from any other implementation.
#![allow(dead_code)]

use audit_daemon::listener::{self, ListenerConfig};
use audit_daemon::recovery::open_log;
use audit_daemon::segments::segment_path;
use audit_daemon::writer::{self, Inbox, WriterFailure};
use audit_log::{
    Anchor, ChainHead, Entry, FileStorage, LogWriter, Record, SegmentLimit, SegmentReader, Source,
    Timestamp, RECORD_FIXED_BODY_LEN, RECORD_LEN_PREFIX, SEGMENT_HEADER_LEN,
};
use config::AuditdSettings;
use ipc::Reply;
use ipc_audit::{AuditReply, AuditRequest, EventBody, EventBytes, AUDIT_CHANNEL};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

/// A unique, empty scratch directory inside the workspace, removed on drop
/// (crates/test-scratch: the log's segments are reached through
/// crates/protected-file's walk from `/`, which accepts its directories
/// with the test account as auditd's account — task R11b, Q-480, Q-530).
/// Short names keep socket paths under the Unix socket path limit.
pub struct TempDir(pub PathBuf, #[allow(dead_code)] test_scratch::ScratchDir);

impl TempDir {
    pub fn new() -> TempDir {
        let scratch = test_scratch::ScratchDir::new("adt").expect("create scratch dir");
        TempDir(scratch.path().to_path_buf(), scratch)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// The log base path (`audit_log_path`) inside the directory.
    pub fn base(&self) -> PathBuf {
        self.0.join("audit.log")
    }

    /// The socket path inside the directory.
    pub fn socket(&self) -> PathBuf {
        self.0.join("audit.sock")
    }
}

/// The uid of this test process, from the peer credentials of a socket pair
/// (tokio `UnixStream::peer_cred`: "effective credentials of the process
/// which called `connect` or `pair`").
pub fn own_uid() -> u32 {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let (one, _other) = tokio::net::UnixStream::pair().expect("pair");
        one.peer_cred().expect("peer_cred").uid()
    })
}

/// auditd's account in these tests: the test account itself, which owns
/// the scratch directories and the segments (crate
/// `audit_daemon::segments`: every segment and directory must be auditd's
/// or root's). Computed once.
pub fn log_uid() -> u32 {
    static UID: OnceLock<u32> = OnceLock::new();
    *UID.get_or_init(own_uid)
}

/// A new segment file opened the way auditd's are (append, exclusive,
/// owner-read-write only) — test code building a log by hand; auditd itself
/// goes through crates/protected-file `create_new_append`.
pub fn new_segment(path: &Path) -> FileStorage {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create segment");
    FileStorage::new(file)
}

/// A uid distinct from `others`, never 0 or all-ones.
pub fn other_uid(others: &[u32]) -> u32 {
    (4000u32..)
        .find(|candidate| !others.contains(candidate))
        .expect("a free uid")
}

/// Configuration text for auditd in `dir`, mapping `mapped_uid` to `kdc`.
/// Spec: docs/50 §7.1; crates/config `AuditdSettings`.
pub fn settings_text(dir: &TempDir, mapped_uid: u32, frame_timeout_secs: u32) -> String {
    settings_text_for(dir, mapped_uid, "kdc", frame_timeout_secs)
}

/// Configuration text for auditd in `dir`, mapping `mapped_uid` to the
/// source named `source` (a process name of docs/50 §2.4).
/// Spec: docs/50 §3.2, §7.1; crates/config `AuditdSettings`.
pub fn settings_text_for(
    dir: &TempDir,
    mapped_uid: u32,
    source: &str,
    frame_timeout_secs: u32,
) -> String {
    let run_as = other_uid(&[mapped_uid]);
    format!(
        "run_as_uid = {run_as}\nrun_as_gid = {run_as}\naudit_socket = {}\naudit_log_path = {}\n\
         uid_sources = {mapped_uid}:{source}\nframe_timeout = {frame_timeout_secs}s\n",
        dir.socket().display(),
        dir.base().display()
    )
}

/// Parsed settings for auditd in `dir`, mapping `mapped_uid` to `source`.
pub fn settings_for(
    dir: &TempDir,
    mapped_uid: u32,
    source: &str,
    frame_timeout_secs: u32,
) -> AuditdSettings {
    AuditdSettings::parse(settings_text_for(dir, mapped_uid, source, frame_timeout_secs).as_bytes())
        .expect("valid auditd settings")
}

/// Parsed settings for auditd in `dir`.
pub fn settings(dir: &TempDir, mapped_uid: u32, frame_timeout_secs: u32) -> AuditdSettings {
    AuditdSettings::parse(settings_text(dir, mapped_uid, frame_timeout_secs).as_bytes())
        .expect("valid auditd settings")
}

/// `count` arbitrary events of `len` octets, distinguished by `tag`.
pub fn events(count: usize, len: usize, tag: u8) -> Vec<EventBytes> {
    (0..count)
        .map(|i| {
            let octets = (0..len)
                .map(|j| tag ^ (i as u8).wrapping_mul(31) ^ (j as u8))
                .collect();
            EventBytes::new(octets).expect("event in bounds")
        })
        .collect()
}

/// Octets of one record with a payload of `payload_len` octets.
pub fn record_len(payload_len: usize) -> usize {
    RECORD_LEN_PREFIX + RECORD_FIXED_BODY_LEN + payload_len
}

/// What `build_log` wrote.
pub struct Built {
    /// Head after each record, in order (index 0 = record 1).
    pub heads: Vec<ChainHead>,
    /// Length of each segment file.
    pub lengths: Vec<u64>,
}

/// Write a log of `per_segment[i]` records in segment `i + 1` (payloads of
/// `payload_len` octets) through crates/audit-log, rotating by hand.
pub fn build_log(base: &Path, per_segment: &[usize], payload_len: usize) -> Built {
    let limit = SegmentLimit::DEFAULT;
    let mut heads = Vec::new();
    let mut lengths = Vec::new();
    let mut writer: Option<LogWriter<FileStorage>> = None;
    let time = Timestamp::new(1_700_000_000, 0).expect("time");
    let payload: Vec<u8> = (0..payload_len).map(|i| i as u8).collect();
    let mut seq_in_source = 0u64;
    for (i, &count) in per_segment.iter().enumerate() {
        let storage = new_segment(&segment_path(base, i as u64 + 1));
        match writer.as_mut() {
            None => writer = Some(LogWriter::create(storage, limit).expect("create log")),
            Some(w) => {
                lengths.push(w.segment_len());
                let _previous = w.rotate(storage).expect("rotate");
            }
        }
        let w = writer.as_mut().expect("writer");
        for _ in 0..count {
            seq_in_source += 1;
            let entry = Entry {
                source: Source::Kdc,
                source_uid: 1234,
                source_seq: seq_in_source,
                payload: &payload,
            };
            heads.push(w.append(&entry, time).expect("append").head);
        }
    }
    if let Some(w) = writer {
        lengths.push(w.segment_len());
    }
    Built { heads, lengths }
}

/// The octets of segment `index`.
pub fn segment_bytes(base: &Path, index: u64) -> Vec<u8> {
    std::fs::read(segment_path(base, index)).expect("read segment")
}

/// Read every record of segment `index` verified against `anchor` (the
/// segment must verify to its end).
pub fn read_segment(base: &Path, index: u64, anchor: Anchor) -> (Vec<Record>, ChainHead) {
    let file = std::fs::File::open(segment_path(base, index)).expect("open segment");
    let mut reader =
        SegmentReader::open(file, anchor, SegmentLimit::DEFAULT, None).expect("segment header");
    let mut records = Vec::new();
    while let Some(record) = reader.next_record().expect("record verifies") {
        records.push(record);
    }
    let head = reader.head();
    reader.finish().expect("segment verifies");
    (records, head)
}

/// The expected payload of a `SegmentRecovered` auditd record, assembled
/// from the layout documented in `audit_daemon::own_event`.
pub fn expected_recovered(
    segment: u64,
    torn_code: u8,
    last_good: ChainHead,
    break_offset: u64,
    segment_octets: u64,
) -> Vec<u8> {
    let mut out = vec![0xAD, 0x01];
    out.extend_from_slice(&segment.to_be_bytes());
    out.push(torn_code);
    out.extend_from_slice(&last_good.seq.to_be_bytes());
    out.extend_from_slice(last_good.hash.as_bytes());
    out.extend_from_slice(&break_offset.to_be_bytes());
    out.extend_from_slice(&segment_octets.to_be_bytes());
    out
}

/// The expected payload of a `PeersRefused` auditd record.
pub fn expected_refused(unmapped: u64, over_quota: u64, last_uid: u32) -> Vec<u8> {
    let mut out = vec![0xAD, 0x02];
    out.extend_from_slice(&unmapped.to_be_bytes());
    out.extend_from_slice(&over_quota.to_be_bytes());
    out.extend_from_slice(&last_uid.to_be_bytes());
    out
}

/// The expected payload of an `EventsMisbound` auditd record.
pub fn expected_misbound(refused_batches: u64, last_uid: u32) -> Vec<u8> {
    let mut out = vec![0xAD, 0x03];
    out.extend_from_slice(&refused_batches.to_be_bytes());
    out.extend_from_slice(&last_uid.to_be_bytes());
    out
}

/// The expected payload of a `ResendsRefused` auditd record (kind 0x04,
/// task F8).
pub fn expected_resends(mismatched: u64, unverifiable: u64, last_uid: u32) -> Vec<u8> {
    let mut out = vec![0xAD, 0x04];
    out.extend_from_slice(&mismatched.to_be_bytes());
    out.extend_from_slice(&unverifiable.to_be_bytes());
    out.extend_from_slice(&last_uid.to_be_bytes());
    out
}

// ---- admin-plane events (docs/51 §5.7), encoded with ipc-audit --------------

/// A `DirAdmin` event of `CreateUser` in `stage` (docs/51 §5.2 row 1).
pub fn dir_admin_event(operation_id: u64, stage: ipc_audit::DirAdminStage) -> EventBody {
    EventBody::DirAdmin(Box::new(ipc_audit::DirAdminEvent {
        time: ipc_audit::CalendarTime::new(2026, 11, 13, 10, 0, 0).expect("time"),
        operation_id,
        operation: ipc_audit::DirAdminOperation::CreateUser,
        stage,
        target: None,
        parent: Some([0x0A; 16]),
        member: None,
        requester: ipc_audit::SidValue::new([0, 0, 0, 0, 0, 5], vec![21, 1, 2, 3, 1105]),
        approvers: ipc_audit::BoundedSeq::empty(),
        pdp: Some(ipc_audit::PdpReason {
            code: ipc_audit::PdpReasonCode::Allowed,
            rule: None,
        }),
        names: ipc_audit::BoundedSeq::new(vec![ipc_audit::TargetName {
            kind: ipc_audit::AdminNameKind::SamAccountName,
            text: ipc_audit::AuditText::from_client("dave"),
        }])
        .expect("one name"),
        enable: None,
        account_expires: None,
        group_type: None,
        pending_request: None,
        key_operation: None,
        reported_kvnos: ipc_audit::BoundedSeq::empty(),
        operation_digest: [0x9C; 32],
        proposed: None,
        reason_ref: None,
        plan_digest: None,
    }))
}

/// The decision and the outcome of one `CreateUser` (docs/51 §5.7 item 2).
pub fn dir_admin_pair() -> Vec<EventBody> {
    vec![
        dir_admin_event(
            1,
            ipc_audit::DirAdminStage::Decision(ipc_audit::DecisionResult::Proceed),
        ),
        dir_admin_event(
            1,
            ipc_audit::DirAdminStage::Outcome(ipc_audit::OutcomeResult::Committed {
                allocated: Some(ipc_audit::Allocation {
                    guid: [0xC7; 16],
                    rid: Some(1106),
                }),
            }),
        ),
    ]
}

/// admind's events: a refused connection (noise) and a completed
/// `SetPassword` (docs/51 §5.7 item 3).
pub fn admind_events() -> Vec<EventBody> {
    let time = ipc_audit::CalendarTime::new(2026, 11, 13, 10, 0, 1).expect("time");
    vec![
        EventBody::Admind(Box::new(ipc_audit::AdmindEvent {
            time,
            peer_uid: Some(1500),
            activity: ipc_audit::AdmindActivity::ConnectionRefused {
                reason: ipc_audit::ConnectionRefusal::ConnectionLimit,
            },
        })),
        EventBody::Admind(Box::new(ipc_audit::AdmindEvent {
            time,
            peer_uid: Some(1500),
            activity: ipc_audit::AdmindActivity::SetPassword {
                target: [0x5E; 16],
                operation_digest: [0x9C; 32],
                kvnos: ipc_audit::BoundedSeq::new(vec![2]).expect("one kvno"),
                result: ipc_audit::PasswordResult::Completed,
            },
        })),
    ]
}

// ---- the older shapes, encoded with ipc-audit (for the source binding) ------

fn calendar() -> ipc_audit::CalendarTime {
    ipc_audit::CalendarTime::new(2026, 11, 13, 10, 0, 2).expect("time")
}

/// A minimal `Kdc` event (crates/kdc `AuditEvent` fields; values made up).
pub fn kdc_event() -> EventBody {
    EventBody::Kdc(Box::new(ipc_audit::KdcEvent {
        time: calendar(),
        transport: ipc_audit::KdcTransport::Tcp,
        exchange: Some(ipc_audit::KdcExchange::As),
        client: None,
        service: None,
        armor_principal: None,
        reply_armored: false,
        outcome: ipc_audit::KdcOutcome::Issued,
        reason: ipc_audit::KdcReason::Issued,
        policy_reason: None,
    }))
}

/// A minimal `Keyd` record (crates/keyd `AuditRecord` fields; values made
/// up).
pub fn keyd_record() -> EventBody {
    EventBody::Keyd(Box::new(ipc_audit::KeydRecord {
        ts: calendar(),
        caller_role: ipc_audit::KeydRole::Kdc,
        caller_uid: 803,
        op: ipc_audit::KeydOperation::VerifyPreauth,
        principal: None,
        purpose: None,
        kvno: None,
        secondary: None,
        approvers: None,
        result: ipc_audit::KeydOutcome::Success,
        reason: ipc_audit::KeydReason::None,
        decision: None,
    }))
}

/// A minimal `Ldap` event (crates/ldap `AuditEvent` fields; values made
/// up): an Unbind.
pub fn ldap_event() -> EventBody {
    EventBody::Ldap(Box::new(ipc_audit::LdapEvent {
        time: calendar(),
        connection_id: 7,
        source_zone: ipc_audit::IpZone::Internal,
        // The address ldap-front reported (docs/52 R14; test data).
        reported_peer: ipc_audit::ReportedAddress::new(core::net::IpAddr::V4(
            core::net::Ipv4Addr::new(10, 0, 0, 7),
        )),
        transport: ipc_audit::LdapTransport::Ldaps,
        transport_sec: ipc_audit::TransportSecurity {
            encrypted: true,
            sealed: false,
            channel_bound: false,
        },
        operation: ipc_audit::LdapOperation::Unbind,
        message_id: Some(3),
        principal: None,
        bind: None,
        target: None,
        search: None,
        result_code: None,
        notice: None,
        action: ipc_audit::LdapAction::Close,
        reason: ipc_audit::LdapReason::Unbind,
        policy_reason: None,
        codec_error: None,
    }))
}

/// A sender window's summary (any source may send one).
pub fn window_summary() -> EventBody {
    EventBody::WindowSummary(ipc_audit::WindowSummary {
        suppressed_noise: 1,
        refused_gating: 0,
        unrecorded_outcomes: 0,
    })
}

/// Encode events for an `Append`.
pub fn encoded(events: &[EventBody]) -> Vec<EventBytes> {
    events
        .iter()
        .map(|event| ipc_audit::encode_event(event).expect("encodes"))
        .collect()
}

/// Header length as a u64.
pub fn header_len() -> u64 {
    SEGMENT_HEADER_LEN as u64
}

// ---- tier 2: a server over a real temp-dir socket --------------------------

/// auditd's listener and writer, running in this process: a tokio runtime
/// for the listener and a thread for the writer (as in the daemon, where
/// the main thread is the writer).
pub struct Server {
    runtime: Option<tokio::runtime::Runtime>,
    writer: Option<JoinHandle<Result<(), WriterFailure>>>,
    held_inbox: Option<Inbox>,
    pub socket: PathBuf,
}

impl Server {
    /// Start on `settings` (log opened at its `audit_log_path`, socket at
    /// its `audit_socket`). Without `run_writer` the queue is held but never
    /// drained. auditd's account for its files and its own records is the
    /// test account ([`log_uid`]), not `run_as` — which crates/config keeps
    /// distinct from every mapped source uid, the test's own included —
    /// since the log lives in the test account's scratch directory.
    pub fn start(
        settings: &AuditdSettings,
        config: ListenerConfig,
        queue_capacity: usize,
        run_writer: bool,
    ) -> Server {
        Server::start_many(
            std::slice::from_ref(settings),
            config,
            queue_capacity,
            run_writer,
        )
    }

    /// As [`Server::start`], with one writer (on the log of the first
    /// settings) behind one listener per settings — each on its own
    /// `audit_socket` with its own `uid → source` map. A single-uid test
    /// world labels each sender with its own source this way: one uid
    /// carries one source per map (docs/50 R50-3, §3.2), and every sender
    /// requires its own source on each connection (task R9b,
    /// docs/questions/Q-560 item 6). Each listener has its own quota.
    pub fn start_many(
        listeners: &[AuditdSettings],
        config: ListenerConfig,
        queue_capacity: usize,
        run_writer: bool,
    ) -> Server {
        let first = listeners.first().expect("at least one listener");
        let opened = open_log(
            first.audit_log_path().as_path(),
            SegmentLimit::DEFAULT,
            log_uid(),
        )
        .expect("log opens");
        let (submitter, inbox) = writer::queue(queue_capacity);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_io()
            .enable_time()
            .build()
            .expect("runtime");
        let socket = first.audit_socket().as_path().to_path_buf();
        for settings in listeners {
            // auditd's post-drop bind removes nothing (task R15b,
            // docs/questions/Q-631): the stale socket of an earlier run is
            // removed by the root-side preparation alone (auditd's step 3b,
            // `protected_file::prepare_socket_directory`). A restart of this
            // in-process server stands in for that step by removing its own
            // earlier socket — the harness's sockets may lie outside a
            // directory the preparation's walk accepts (e2e, ldap-front).
            let _ = std::fs::remove_file(settings.audit_socket().as_path());
            let bound = {
                let _context = runtime.enter();
                listener::bind(settings.audit_socket().as_path()).expect("bind")
            };
            let _serving = runtime.spawn(listener::serve(
                bound,
                Arc::new(settings.uid_sources().clone()),
                submitter.clone(),
                config,
            ));
        }
        drop(submitter);
        let (writer, held_inbox) = if run_writer {
            let sink = opened.sink;
            (
                Some(std::thread::spawn(move || writer::run(sink, inbox))),
                None,
            )
        } else {
            (None, Some(inbox))
        };
        Server {
            runtime: Some(runtime),
            writer,
            held_inbox,
            socket,
        }
    }

    /// Stop the listener and wait for the writer to finish.
    pub fn stop(mut self) -> Option<Result<(), WriterFailure>> {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_secs(2));
        }
        self.held_inbox.take();
        self.writer.take().map(|w| w.join().expect("writer thread"))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// A blocking client connection with a read timeout.
pub fn connect(path: &Path) -> UnixStream {
    let stream = UnixStream::connect(path).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    stream
}

/// Send one request frame.
pub fn send(stream: &mut UnixStream, request: &AuditRequest) {
    let frame = ipc_audit::encode_request(request).expect("encode request");
    stream.write_all(frame.as_bytes()).expect("send");
}

/// What a read of one reply found.
#[derive(Debug, PartialEq, Eq)]
pub enum Got {
    Reply(Reply<AuditReply>),
    /// The server closed with no reply octet (end of stream or reset).
    Closed,
    /// No reply within the read timeout.
    Nothing,
}

/// Read one reply frame (or observe a close / silence).
pub fn receive(stream: &mut UnixStream) -> Got {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 256];
    loop {
        if let Some((reply, _)) =
            ipc::decode_reply_message::<AuditReply>(AUDIT_CHANNEL, &buffer).expect("reply decodes")
        {
            return Got::Reply(reply);
        }
        match stream.read(&mut chunk) {
            Ok(0) => {
                assert!(buffer.is_empty(), "partial reply before close");
                return Got::Closed;
            }
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::ConnectionReset => {
                assert!(buffer.is_empty(), "partial reply before reset");
                return Got::Closed;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                assert!(buffer.is_empty(), "partial reply before timeout");
                return Got::Nothing;
            }
            Err(e) => panic!("read failed: {e}"),
        }
    }
}
