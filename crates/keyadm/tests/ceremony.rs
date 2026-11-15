//! Tier 2 (docs/50 §9): `keyadm ceremony` against the real keyd daemon
//! (`keyd_daemon::serve`, the development key store) on a real Unix socket
//! in a 0700 temporary directory, with the test's own uid mapped in keyd's
//! `uid → Role` map to the role under test, keyd's own clock, real peer
//! credentials on both sides, and the minimal auditd of
//! crates/keyd-daemon/tests/support (reused through `#[path]`).
//!
//! keyd offers no operation that describes a key set (docs/10 §7: "no read
//! operation for a key — in any role"), so what keyd created is verified
//! through the client's results (the kvno of each `create_key`) and through
//! keyd's audit records as auditd received them (docs/10 §10: op, principal,
//! purpose, kvno, result, reason — no secret).
//!
//! Every test names its source. Every value is constructed by hand for these
//! tests (obviously fake); no vector comes from any other implementation.

#[path = "../../keyd-daemon/tests/support/mod.rs"]
mod support;

use dtyp::{Guid, Sid};
use ipc::{Direction, FrameReader, Refused};
use ipc_audit::{
    AuditReply, AuditRequest, EventBody, KeyPurposeCode, KeydOperation, KeydOutcome, KeydReason,
    KeydRecord, AUDIT_CHANNEL,
};
use ipc_keyd::{KeydClient, TransportError, DEFAULT_DEADLINE};
use keyadm::ceremony::{self, NotSent, Outcome, Step, Unknown};
use keyadm::report::{self, EXIT_COMPLETE, EXIT_INCOMPLETE, EXIT_NOTHING_ATTEMPTED};
use keyd::Role;
use keyd_daemon::startup::development_keyd;
use keyd_daemon::{CallerMap, SystemClock};
use keyd_types::{Error as KeydError, Kvno};
use krb_proto::Realm;
use provision_manifest::{Manifest, ManifestFields};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use support::{eventually, my_uid, params, skip_as_root, Daemon, FakeAuditd, TempDir};

#[cfg(target_os = "linux")]
mod connector {
    //! Linux: keyadm's own connector (rustix peer credentials).
    pub type KeydConnector = ipc_keyd::UnixConnector;

    pub fn new(path: &std::path::Path) -> KeydConnector {
        ipc_keyd::UnixConnector::new(path.to_path_buf())
    }
}

#[cfg(not(target_os = "linux"))]
mod connector {
    //! Other hosts (where the ipc-keyd connector fails closed): keyd's uid
    //! through tokio `UnixStream::peer_cred`, then
    //! `ipc_keyd::UnixConnection` for the exchanges — as
    //! crates/keyd-daemon/tests/kdc_flow.rs does (tokio 1.54.1 docs.rs:
    //! `from_std` needs a runtime context and a non-blocking stream;
    //! `into_std` returns it non-blocking).
    use ipc::FrameLimit;
    use ipc_keyd::{Connection, Connector, TransportError, UnixConnection};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use zeroize::Zeroizing;

    pub struct KeydConnector {
        path: PathBuf,
        runtime: tokio::runtime::Runtime,
    }

    pub fn new(path: &Path) -> KeydConnector {
        KeydConnector {
            path: path.to_path_buf(),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .unwrap(),
        }
    }

    pub struct PeerChecked {
        uid: u32,
        inner: UnixConnection,
    }

    impl Connector for KeydConnector {
        type Connection = PeerChecked;

        fn connect(&mut self) -> Result<PeerChecked, TransportError> {
            let stream = UnixStream::connect(&self.path).map_err(|_| TransportError::Connect)?;
            stream
                .set_nonblocking(true)
                .map_err(|_| TransportError::Connect)?;
            let (uid, stream) = {
                let _context = self.runtime.enter();
                let stream = tokio::net::UnixStream::from_std(stream)
                    .map_err(|_| TransportError::PeerCredentials)?;
                let uid = stream
                    .peer_cred()
                    .map_err(|_| TransportError::PeerCredentials)?
                    .uid();
                (
                    uid,
                    stream
                        .into_std()
                        .map_err(|_| TransportError::PeerCredentials)?,
                )
            };
            stream
                .set_nonblocking(false)
                .map_err(|_| TransportError::Connect)?;
            Ok(PeerChecked {
                uid,
                inner: UnixConnection::from_stream(stream),
            })
        }
    }

    impl Connection for PeerChecked {
        fn peer_uid(&self) -> Result<u32, TransportError> {
            Ok(self.uid)
        }

        fn exchange(
            &mut self,
            frame: &[u8],
            reply_limit: FrameLimit,
            deadline: Duration,
        ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
            self.inner.exchange(frame, reply_limit, deadline)
        }

        /// The wrapped connection's own idle check (docs/questions/Q-312;
        /// no default since task R9, Q-466 item 4).
        fn check_idle(&mut self) -> Result<(), TransportError> {
            self.inner.check_idle()
        }
    }
}

const REALM: &str = "EXAMPLE.TEST";

fn guid(last: u8) -> Guid {
    let mut packet = [0u8; 16];
    packet[15] = last;
    Guid::from_packet(&packet)
}

/// An obviously fake manifest whose realm is keyd's, with obviously fake
/// first-administrator salts (keyd binds whatever salt the grant names; no
/// `set_secret` follows in these tests — A-102, N4; the key is required —
/// A-105).
/// Source: docs/51 §4.3 step 8; [MS-DTYP] 2.4.2.4 (example domain SID).
fn manifest() -> Manifest {
    Manifest::new(&ManifestFields {
        realm: REALM.to_owned(),
        domain_sid: Sid::parse_sid_string("S-1-5-21-1-2-3").unwrap(),
        naming_context: vec!["example".to_owned(), "test".to_owned()],
        dc_fqdn: "dc1.example.test".to_owned(),
        krbtgt: guid(1),
        ldap_service: guid(2),
        admin_service: guid(3),
        // Task K9: the change-password service object (docs/53 §5.2).
        change_password_service: guid(6),
        first_admins: vec![(guid(4), "alice".to_owned()), (guid(5), "bob".to_owned())],
        first_admin_salts: vec!["test-salt-alice".to_owned(), "test-salt-bob".to_owned()],
    })
    .unwrap()
}

/// A running keyd (development store, realm EXAMPLE.TEST) whose map gives
/// the test's uid `role` — or maps only another uid when `role` is `None` —
/// and a fake auditd.
struct World {
    _dir: TempDir,
    auditd: FakeAuditd,
    daemon: Daemon,
    uid: u32,
}

fn world(role: Option<Role>) -> Option<World> {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return None;
    }
    let entries = match role {
        Some(role) => vec![(uid, role)],
        None => vec![(uid.wrapping_add(1000).max(1), Role::Kdc)],
    };
    let params = params(&dir, CallerMap::new(&entries).unwrap(), uid);
    let auditd = FakeAuditd::start(&params.audit.socket);
    let realm = Realm::new(REALM).unwrap();
    let daemon = Daemon::start(params, SystemClock, development_keyd(realm)).unwrap();
    Some(World {
        _dir: dir,
        auditd,
        daemon,
        uid,
    })
}

impl World {
    /// keyadm's client: the daemon's socket, expecting keyd to run as
    /// `keyd_uid` (in these tests keyd runs in-process, as the test's uid).
    fn client(&self, keyd_uid: u32) -> KeydClient<connector::KeydConnector> {
        KeydClient::new(
            connector::new(&self.daemon.socket),
            ipc_keyd::ExpectedPeer::new(keyd_uid, Role::Admin).unwrap(),
            DEFAULT_DEADLINE,
        )
    }

    /// keyd's CreateKey audit records received so far.
    /// The CreateKey **outcome** records. Since A-88 (docs/10 §10) each
    /// key-state change is recorded twice — an acknowledged `Intent`
    /// record before the change, then the outcome — so the intents are
    /// counted apart ([`World::create_key_intents`]).
    fn create_key_records(&self) -> Vec<KeydRecord> {
        self.create_key_events()
            .into_iter()
            .filter(|record| record.result != KeydOutcome::Intent)
            .collect()
    }

    /// The CreateKey `Intent` records (A-88; docs/questions/Q-365).
    fn create_key_intents(&self) -> Vec<KeydRecord> {
        self.create_key_events()
            .into_iter()
            .filter(|record| record.result == KeydOutcome::Intent)
            .collect()
    }

    fn create_key_events(&self) -> Vec<KeydRecord> {
        self.auditd
            .events()
            .into_iter()
            .filter_map(|event| match event {
                EventBody::Keyd(record) if record.op == KeydOperation::CreateKey => Some(*record),
                _ => None,
            })
            .collect()
    }

    /// Wait until `count` CreateKey records arrived; return them.
    fn wait_for_create_key_records(&self, count: usize) -> Vec<KeydRecord> {
        assert!(
            eventually(Duration::from_secs(10), || self.create_key_records().len()
                >= count),
            "audit records did not arrive"
        );
        self.create_key_records()
    }
}

/// docs/51 §4.3 step 11 (`create_key` with the manifest's handles and
/// bindings — four since task K9, the fourth the change-password service's,
/// docs/53 §5.2); docs/10 §7 (create_key returns the new kvno; A-35: keyd
/// chooses it — 1 for a new key set); docs/10 §10 (keyd audits each with
/// principal, purpose and kvno); A-19 (keyd checks the binding rule at
/// creation: a Krbtgt key bound to krbtgt/REALM, a ChangePasswordService key
/// to kadmin/changepw — RFC 3244 §2 —, service keys not).
#[test]
fn the_ceremony_creates_the_four_key_sets_with_their_bindings() {
    let Some(world) = world(Some(Role::Admin)) else {
        return;
    };
    let m = manifest();
    let mut client = world.client(world.uid);
    let report = ceremony::run(&mut client, &m);
    assert_eq!(report.contact, Outcome::Answered(Ok(())));
    assert!(report.is_complete(), "{report:?}");
    assert_eq!(
        report.created(),
        [
            (Step::Krbtgt, Kvno::INITIAL),
            (Step::LdapService, Kvno::INITIAL),
            (Step::AdminService, Kvno::INITIAL),
            (Step::ChangePasswordService, Kvno::INITIAL)
        ]
    );
    assert_eq!(report::exit_code(&report), EXIT_COMPLETE);
    let text = report::render(&report, &m).join("\n");
    assert!(
        text.contains("binding NT-SRV-INST:krbtgt/EXAMPLE.TEST kvno 1"),
        "{text}"
    );
    assert!(text.contains("binding NT-SRV-HST:ldap/dc1.example.test kvno 1"));
    assert!(text.contains("binding NT-SRV-HST:admind/dc1.example.test kvno 1"));
    assert!(text.contains("binding NT-SRV-INST:kadmin/changepw kvno 1"));

    let records = world.wait_for_create_key_records(4);
    let expected = [
        (guid(1), KeyPurposeCode::Krbtgt),
        (guid(2), KeyPurposeCode::Service),
        // R2 (docs/52 §5 item 3): the admin service's own purpose.
        (guid(3), KeyPurposeCode::AdminService),
        // Task K9 (docs/53 R53-6, §5.2): the change-password service's own
        // purpose.
        (guid(6), KeyPurposeCode::ChangePasswordService),
    ];
    assert_eq!(records.len(), 4);
    for (record, (g, purpose)) in records.iter().zip(expected) {
        assert_eq!(record.principal, Some(g.to_packet()));
        assert_eq!(record.purpose, Some(purpose));
        assert_eq!(record.kvno, Some(1));
        assert_eq!(record.result, KeydOutcome::Success);
        assert_eq!(record.caller_uid, world.uid);
    }
    // A-88: every change was preceded by its acknowledged intent.
    assert_eq!(world.create_key_intents().len(), 4);
    world.daemon.stop().unwrap();
}

/// docs/51 §4.3 step 11 ("a repeated ceremony on a keyd that was not
/// restarted fails closed"); docs/52 §4.4 (A-102, R3: the first ceremony
/// sealed keyd — `create_key` and Admin grants no longer exist); A-77
/// (repeat only after a keyd restart): the second run stops at the krbtgt
/// step with keyd's uniform Denied, attempts nothing after it, and keyd's
/// audit names the reason (CeremonySealed — refused at the authorization
/// step, so no intent); an Admin grant after the seal is refused likewise.
#[test]
fn a_repeated_ceremony_fails_closed_at_the_first_key_set() {
    let Some(world) = world(Some(Role::Admin)) else {
        return;
    };
    let m = manifest();
    assert!(ceremony::run(&mut world.client(world.uid), &m).is_complete());
    let again = ceremony::run(&mut world.client(world.uid), &m);
    assert_eq!(again.contact, Outcome::Answered(Ok(())));
    assert_eq!(again.steps.len(), 1);
    assert_eq!(again.steps[0].step, Step::Krbtgt);
    assert_eq!(
        again.steps[0].outcome,
        Outcome::Answered(Err(KeydError::Denied))
    );
    assert_eq!(again.created(), []);
    assert_eq!(
        again.not_attempted(),
        [
            Step::LdapService,
            Step::AdminService,
            Step::ChangePasswordService
        ]
    );
    assert_eq!(report::exit_code(&again), EXIT_INCOMPLETE);

    let records = world.wait_for_create_key_records(5);
    assert_eq!(records.len(), 5, "nothing after the refused step");
    let refused = &records[4];
    assert_eq!(refused.principal, Some(guid(1).to_packet()));
    assert_eq!(refused.result, KeydOutcome::Denied);
    assert_eq!(refused.reason, KeydReason::CeremonySealed);
    assert_eq!(
        world.create_key_intents().len(),
        4,
        "no intent after the seal"
    );
    let text = report::render(&again, &m).join("\n");
    assert!(text.contains("keyd is NOT sealed"), "{text}");

    // An Admin initial-secret grant after the seal: refused (CeremonySealed).
    let admin = &m.first_admins()[0];
    assert_eq!(
        world.client(world.uid).grant_set_secret(
            keyd_types::AccountKind::User,
            &[keyd_types::SetSecretTarget {
                handle: admin.key_set().handle,
                binding: admin.key_set().binding.clone(),
                salt: "test-salt-alice".to_owned(),
            }],
            keyd_types::MAX_INITIAL_SECRET_GRANT_SECS,
        ),
        Ok(Err(KeydError::Denied))
    );
    let sealed_grant = || {
        world.auditd.events().into_iter().any(|event| {
            matches!(event, EventBody::Keyd(record)
                if record.op == KeydOperation::GrantSetSecret
                    && record.reason == KeydReason::CeremonySealed)
        })
    };
    assert!(eventually(Duration::from_secs(10), sealed_grant));
    world.daemon.stop().unwrap();
}

/// docs/52 §2 row 37 (N4) — the ceremony binds the manifest's salt (every
/// manifest names one: `first_admin_salts` is required, A-105 — a manifest
/// without it does not parse, crates/provision-manifest
/// tests/rejections.rs): every grant names its salt and the ceremony ends
/// with the seal (one `SealCeremony` record, success, no intent: the seal
/// only makes keyd stricter — A-88).
#[test]
fn the_ceremony_binds_the_manifests_salts_and_ends_sealed() {
    let Some(world) = world(Some(Role::Admin)) else {
        return;
    };
    let m = manifest();
    let report = ceremony::run(&mut world.client(world.uid), &m);
    assert!(report.is_sealed(), "{report:?}");
    assert!(report.is_complete());
    let seals = || -> Vec<KeydRecord> {
        world
            .auditd
            .events()
            .into_iter()
            .filter_map(|event| match event {
                EventBody::Keyd(record) if record.op == KeydOperation::SealCeremony => {
                    Some(*record)
                }
                _ => None,
            })
            .collect()
    };
    assert!(eventually(Duration::from_secs(10), || !seals().is_empty()));
    let seals = seals();
    assert_eq!(seals.len(), 1);
    assert_eq!(seals[0].result, KeydOutcome::Success);
    assert_eq!(seals[0].caller_uid, world.uid);
    world.daemon.stop().unwrap();
}

/// docs/50 R50-3 ("the client verifies the server's uid … before sending
/// anything"; A-63): with a keyd_uid that is not the socket's peer uid,
/// nothing is sent — no create_key is attempted, and a ceremony with the
/// right uid afterwards creates all four key sets (so none existed).
#[test]
fn a_wrong_peer_uid_is_refused_before_anything_is_sent() {
    let Some(world) = world(Some(Role::Admin)) else {
        return;
    };
    let m = manifest();
    let wrong = world.uid.wrapping_add(1000).max(1);
    let report = ceremony::run(&mut world.client(wrong), &m);
    assert_eq!(report.contact, Outcome::NotSent(NotSent::PeerMismatch));
    assert!(report.steps.is_empty());
    assert_eq!(report::exit_code(&report), EXIT_NOTHING_ATTEMPTED);
    assert!(world.create_key_records().is_empty());

    let right = ceremony::run(&mut world.client(world.uid), &m);
    assert!(right.is_complete(), "{right:?}");
    world.daemon.stop().unwrap();
}

/// **Attack test** — docs/10 §2; docs/50 R50-3, §3.2, §3.7; docs/52 §3.12
/// (C12); docs/questions/Q-466 items 1-2 (A-102): a keyd that maps
/// keyadm's uid to **another role** (Directory) is found by the `Ping`
/// probe of keyadm's connection, before anything else is sent: the contact
/// fails as not sent (the peer is not the expected keyd), **no `create_key`
/// reaches keyd** (it records none), nothing is attempted (exit 1).
#[test]
fn a_keyd_giving_keyadm_another_role_receives_no_create_key() {
    let Some(world) = world(Some(Role::Directory)) else {
        return;
    };
    let m = manifest();
    let report = ceremony::run(&mut world.client(world.uid), &m);
    assert_eq!(report.contact, Outcome::NotSent(NotSent::PeerMismatch));
    assert!(report.steps.is_empty());
    assert_eq!(report::exit_code(&report), EXIT_NOTHING_ATTEMPTED);
    let text = report::render(&report, &m).join("\n");
    assert!(
        text.contains("keyd does not give this account the Admin role (nothing was sent)"),
        "{text}"
    );
    assert!(
        world.create_key_records().is_empty(),
        "keyd received no create_key"
    );
    world.daemon.stop().unwrap();
}

/// docs/50 R50-3, §3.2 ("an unmapped uid ⇒ the connection is closed"): the
/// contact fails — keyd closes the new connection at its probe, so nothing
/// was sent (task R9) — and no create_key is sent.
#[test]
fn an_unmapped_uid_attempts_no_key_set() {
    let Some(world) = world(None) else {
        return;
    };
    let m = manifest();
    let report = ceremony::run(&mut world.client(world.uid), &m);
    assert_eq!(
        report.contact,
        Outcome::NotSent(NotSent::Transport(ipc_keyd::TransportError::Closed))
    );
    assert!(report.steps.is_empty());
    assert_eq!(report::exit_code(&report), EXIT_NOTHING_ATTEMPTED);
    let text = report::render(&report, &m).join("\n");
    assert!(text.contains("mapped to Admin"), "{text}");
    world.daemon.stop().unwrap();
}

// ---- the fate of a create_key keyd did not answer (Q-367, A-88) ----------------------

/// One whole frame of at most `limit` octets from `stream`, or `None` at
/// the end of the stream (or on any failure).
fn read_one_frame(stream: &mut UnixStream, limit: ipc::FrameLimit) -> Option<Vec<u8>> {
    let mut reader = FrameReader::new(limit);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(body) = reader.body() {
            return Some(body.to_vec());
        }
        let wanted = reader.wanted().min(chunk.len());
        match stream.read(&mut chunk[..wanted]) {
            Ok(0) => return None,
            Ok(n) => {
                reader.push(&chunk[..n]).ok()?;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
}

/// An auditd that is reachable and stuck: it answers `Ping` with `Pong` and
/// never acknowledges an `Append` (written from the audit channel's own
/// message set, crates/ipc-audit; docs/50 §8.1). keyd's intent is therefore
/// never acknowledged (docs/10 §10, A-88).
struct StuckAuditd {
    stop: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<UnixStream>>>,
    thread: Option<JoinHandle<()>>,
}

impl StuckAuditd {
    fn start(path: &Path) -> StuckAuditd {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let (stop, connections) = (Arc::clone(&stop), Arc::clone(&connections));
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            connections
                                .lock()
                                .unwrap()
                                .push(stream.try_clone().unwrap());
                            std::thread::spawn(move || serve_stuck(stream));
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                }
            })
        };
        StuckAuditd {
            stop,
            connections,
            thread: Some(thread),
        }
    }

    fn stop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.stop.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        for stream in self.connections.lock().unwrap().drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl Drop for StuckAuditd {
    fn drop(&mut self) {
        self.stop();
    }
}

/// `Ping` → `Pong`; `Append` → nothing, ever.
fn serve_stuck(mut stream: UnixStream) {
    while let Some(body) = read_one_frame(&mut stream, AUDIT_CHANNEL.limit(Direction::Request)) {
        match ipc_audit::decode_request(&body) {
            Ok(AuditRequest::Ping) => {
                let frame = ipc_audit::encode_reply(&ipc::Reply::Message(AuditReply::Pong(
                    ipc_audit::EventSource::Keyd,
                )))
                .unwrap();
                if stream.write_all(frame.as_bytes()).is_err() {
                    return;
                }
            }
            Ok(AuditRequest::Append(_)) => {}
            Err(_) => return,
        }
    }
}

/// docs/10 §10 and docs/questions/Q-365 (A-88: when keyd's intent is not
/// acknowledged in time keyd-daemon answers `Unavailable` and keyd does
/// **not** perform the change); Q-367 (A-88: keyd's own `Unavailable` =
/// "not performed"): against the real keyd daemon whose auditd is reachable
/// but never acknowledges, the contact succeeds (`ping` needs no audit
/// acknowledgement) and the krbtgt `create_key` is answered unavailable —
/// reported as **not performed**, "not created", never "MAY have been
/// created"; the ceremony stops there (exit 2).
#[test]
fn keyds_unavailable_is_reported_as_not_performed() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let params = params(&dir, CallerMap::new(&[(uid, Role::Admin)]).unwrap(), uid);
    let mut auditd = StuckAuditd::start(&params.audit.socket);
    let daemon = Daemon::start(
        params,
        SystemClock,
        development_keyd(Realm::new(REALM).unwrap()),
    )
    .unwrap();
    let m = manifest();
    let mut client = KeydClient::new(
        connector::new(&daemon.socket),
        ipc_keyd::ExpectedPeer::new(uid, Role::Admin).unwrap(),
        DEFAULT_DEADLINE,
    );
    let report = ceremony::run(&mut client, &m);
    assert_eq!(report.contact, Outcome::Answered(Ok(())));
    assert_eq!(report.steps.len(), 1, "{report:?}");
    assert_eq!(
        report.steps[0].outcome,
        Outcome::NotPerformed(Refused::Unavailable)
    );
    assert_eq!(report::exit_code(&report), EXIT_INCOMPLETE);
    let text = report::render(&report, &m).join("\n");
    assert!(
        text.contains("krbtgt: keyd answered unavailable (not performed); not created"),
        "{text}"
    );
    assert!(!text.contains("MAY have been created"), "{text}");
    drop(client);
    auditd.stop();
    daemon.stop().unwrap();
}

/// docs/50 §3.6, §3.7; Q-367 (A-88: "a client-side deadline … **after** the
/// request was sent is reported as 'outcome unknown — check before
/// retrying'"): a keyd that answers the contact and then receives the
/// krbtgt `create_key` but never answers it (here a scripted keyd built from
/// ipc-keyd's own codec) — keyadm's deadline passes after sending: the step
/// is **outcome unknown**, reported as "MAY have been created" with the
/// pointer to keyd's audit log; the request was sent once and the ceremony
/// stops there (exit 2).
#[test]
fn a_create_key_keyd_never_answers_is_reported_as_outcome_unknown() {
    let dir = TempDir::new();
    let uid = my_uid(&dir);
    if skip_as_root(uid) {
        return;
    }
    let path = dir.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let (done, wait_done) = mpsc::channel::<()>();
    let keyd = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut received = Vec::new();
        while let Some(body) = read_one_frame(&mut stream, ipc_keyd::REQUEST_LIMIT) {
            let call = ipc_keyd::decode_request(&body).unwrap();
            received.push(call.operation());
            if matches!(call, ipc_keyd::Call::Ping) {
                // The role keyd resolves for keyadm (task R9): the
                // client's probe and keyadm's contact both ping.
                let answer = ipc_keyd::Answer::Ping(Ok(Role::Admin));
                stream
                    .write_all(ipc_keyd::encode_answer(&answer).unwrap().as_bytes())
                    .unwrap();
            } else {
                // Never answered; the connection stays open until the
                // client is done.
                wait_done.recv().unwrap();
                break;
            }
        }
        received
    });
    let m = manifest();
    let mut client = KeydClient::new(
        connector::new(&path),
        ipc_keyd::ExpectedPeer::new(uid, Role::Admin).unwrap(),
        Duration::from_millis(500),
    );
    let report = ceremony::run(&mut client, &m);
    done.send(()).unwrap();
    assert_eq!(
        keyd.join().unwrap(),
        [
            keyd::Operation::Ping,
            keyd::Operation::Ping,
            keyd::Operation::CreateKey
        ]
    );
    assert_eq!(report.contact, Outcome::Answered(Ok(())));
    assert_eq!(report.steps.len(), 1, "{report:?}");
    assert_eq!(
        report.steps[0].outcome,
        Outcome::Unknown(Unknown::Transport(TransportError::DeadlineExceeded))
    );
    assert_eq!(report::exit_code(&report), EXIT_INCOMPLETE);
    let text = report::render(&report, &m).join("\n");
    assert!(
        text.contains(
            "krbtgt: keyd did not answer in time after the request was sent; outcome unknown, the key set MAY have been created"
        ),
        "{text}"
    );
    assert!(text.contains("check keyd's audit log"), "{text}");
}

/// Task A15a (docs/51 §4.3 steps 11-12, §5.8 option (b); docs/questions/
/// Q-451): after the four key sets the ceremony grants each first
/// administrator's initial secret — one `grant_set_secret` per
/// administrator, in the manifest's order, by Role::Admin, each an
/// acknowledged intent then keyd's success, naming the administrator's
/// `(GUID, PrincipalLongterm)` key set; the report prints each grant and the
/// 15-minute window. Without the grants the ceremony is not complete.
#[test]
fn the_ceremony_grants_each_first_administrator_its_initial_secret() {
    let Some(world) = world(Some(Role::Admin)) else {
        return;
    };
    let m = manifest();
    let report = ceremony::run(&mut world.client(world.uid), &m);
    assert!(report.is_complete(), "{report:?}");
    assert_eq!(report.grants.len(), 2);
    assert!(report.grants.iter().all(|g| g.outcome.succeeded()));
    let text = report::render(&report, &m).join("\n");
    assert!(
        text.contains("granted the initial secret of first administrator alice"),
        "{text}"
    );
    assert!(text.contains("granted the initial secret of first administrator bob"));
    assert!(text.contains("within 15 minutes"));

    let grants = || -> Vec<KeydRecord> {
        world
            .auditd
            .events()
            .into_iter()
            .filter_map(|event| match event {
                EventBody::Keyd(record) if record.op == KeydOperation::GrantSetSecret => {
                    Some(*record)
                }
                _ => None,
            })
            .collect()
    };
    assert!(eventually(Duration::from_secs(10), || grants().len() >= 4));
    let records = grants();
    for (pair, last) in records.chunks(2).zip([4u8, 5u8]) {
        assert_eq!(pair[0].result, KeydOutcome::Intent);
        assert_eq!(pair[1].result, KeydOutcome::Success);
        assert_eq!(pair[1].principal, Some(guid(last).to_packet()));
        assert_eq!(pair[1].purpose, Some(KeyPurposeCode::PrincipalLongterm));
        assert_eq!(pair[1].caller_uid, world.uid);
    }
    world.daemon.stop().unwrap();
}
