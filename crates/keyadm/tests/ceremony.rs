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
use ipc_audit::{EventBody, KeyPurposeCode, KeydOperation, KeydOutcome, KeydReason, KeydRecord};
use ipc_keyd::{KeydClient, DEFAULT_DEADLINE};
use keyadm::ceremony::{self, NotSent, Outcome, Step, Unknown};
use keyadm::report::{self, EXIT_COMPLETE, EXIT_INCOMPLETE, EXIT_NOTHING_ATTEMPTED};
use keyd::Role;
use keyd_daemon::startup::development_keyd;
use keyd_daemon::{CallerMap, SystemClock};
use keyd_types::{Error as KeydError, Kvno};
use krb_proto::Realm;
use provision_manifest::{Manifest, ManifestFields};
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
    }
}

const REALM: &str = "EXAMPLE.TEST";

fn guid(last: u8) -> Guid {
    let mut packet = [0u8; 16];
    packet[15] = last;
    Guid::from_packet(&packet)
}

/// An obviously fake manifest whose realm is keyd's.
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
        first_admins: vec![(guid(4), "alice".to_owned()), (guid(5), "bob".to_owned())],
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
            keyd_uid,
            DEFAULT_DEADLINE,
        )
        .unwrap()
    }

    /// keyd's CreateKey audit records received so far.
    fn create_key_records(&self) -> Vec<KeydRecord> {
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

/// docs/51 §4.3 step 11 (`create_key` ×3 with the manifest's handles and
/// bindings); docs/10 §7 (create_key returns the new kvno; A-35: keyd
/// chooses it — 1 for a new key set); docs/10 §10 (keyd audits each with
/// principal, purpose and kvno); A-19 (keyd checks the binding rule at
/// creation: a Krbtgt key bound to krbtgt/REALM, service keys not).
#[test]
fn the_ceremony_creates_the_three_key_sets_with_their_bindings() {
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
            (Step::AdminService, Kvno::INITIAL)
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

    let records = world.wait_for_create_key_records(3);
    let expected = [
        (guid(1), KeyPurposeCode::Krbtgt),
        (guid(2), KeyPurposeCode::Service),
        (guid(3), KeyPurposeCode::Service),
    ];
    assert_eq!(records.len(), 3);
    for (record, (g, purpose)) in records.iter().zip(expected) {
        assert_eq!(record.principal, Some(g.to_packet()));
        assert_eq!(record.purpose, Some(purpose));
        assert_eq!(record.kvno, Some(1));
        assert_eq!(record.result, KeydOutcome::Success);
        assert_eq!(record.caller_uid, world.uid);
    }
    world.daemon.stop().unwrap();
}

/// docs/51 §4.3 step 11 ("`create_key` refuses an existing key set —
/// a repeated ceremony on a keyd that was not restarted fails closed");
/// A-35; A-77 (repeat only after a keyd restart): the second run stops at
/// the krbtgt step with keyd's uniform Denied, attempts nothing after it,
/// and keyd's audit names the reason (KeyExists).
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
        [Step::LdapService, Step::AdminService]
    );
    assert_eq!(report::exit_code(&again), EXIT_INCOMPLETE);

    let records = world.wait_for_create_key_records(4);
    assert_eq!(records.len(), 4, "nothing after the refused step");
    let refused = &records[3];
    assert_eq!(refused.principal, Some(guid(1).to_packet()));
    assert_eq!(refused.result, KeydOutcome::Denied);
    assert_eq!(refused.reason, KeydReason::KeyExists);
    world.daemon.stop().unwrap();
}

/// docs/50 R50-3 ("the client verifies the server's uid … before sending
/// anything"; A-63): with a keyd_uid that is not the socket's peer uid,
/// nothing is sent — no create_key is attempted, and a ceremony with the
/// right uid afterwards creates all three key sets (so none existed).
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

/// docs/10 §2 (I2: only Role::Admin holds `create_key`); docs/50 §3.2 (the
/// role comes from the uid map): a uid mapped to Directory reaches keyd
/// (`ping` is every role's) but its first `create_key` gets keyd's uniform
/// Denied, which is reported; nothing more is attempted.
#[test]
fn a_uid_mapped_to_another_role_gets_keyds_denied() {
    let Some(world) = world(Some(Role::Directory)) else {
        return;
    };
    let m = manifest();
    let report = ceremony::run(&mut world.client(world.uid), &m);
    assert_eq!(report.contact, Outcome::Answered(Ok(())));
    assert_eq!(report.steps.len(), 1);
    assert_eq!(
        report.steps[0].outcome,
        Outcome::Answered(Err(KeydError::Denied))
    );
    assert_eq!(report::exit_code(&report), EXIT_INCOMPLETE);
    let text = report::render(&report, &m).join("\n");
    assert!(
        text.contains("krbtgt: keyd refused (denied); not created"),
        "{text}"
    );

    let records = world.wait_for_create_key_records(1);
    assert_eq!(records[0].result, KeydOutcome::Denied);
    assert_eq!(records[0].reason, KeydReason::RoleNotPermitted);
    world.daemon.stop().unwrap();
}

/// docs/50 R50-3, §3.2 ("an unmapped uid ⇒ the connection is closed"): the
/// contact fails, no create_key is sent.
#[test]
fn an_unmapped_uid_attempts_no_key_set() {
    let Some(world) = world(None) else {
        return;
    };
    let m = manifest();
    let report = ceremony::run(&mut world.client(world.uid), &m);
    assert_eq!(
        report.contact,
        Outcome::Unknown(Unknown::Transport(ipc_keyd::TransportError::Closed))
    );
    assert!(report.steps.is_empty());
    assert_eq!(report::exit_code(&report), EXIT_NOTHING_ATTEMPTED);
    let text = report::render(&report, &m).join("\n");
    assert!(text.contains("mapped to Admin"), "{text}");
    world.daemon.stop().unwrap();
}
