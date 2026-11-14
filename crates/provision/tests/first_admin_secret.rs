//! `provision first-admin-secret` (task A6; docs/51 §4.3 step 12) against
//! the real keyd daemon (`keyd_daemon::serve`, the development key store,
//! the in-process fake auditd of crates/keyd-daemon/tests/support, reused
//! through `#[path]` as tests/ceremony.rs does), with
//!
//! - the **produced** files of `provision domain` (part A): the manifest
//!   and admind's configuration file, read through the command's own
//!   readers; the test's uid is provisioned as admind's, so the produced
//!   keyd configuration maps it to Role::Directory (A-73) and keyd's
//!   `uid → Role` map is built from that file;
//! - the privilege drop replaced by a recorder (the tests never run as
//!   root — task A6: "the privilege drop goes behind a trait"), and the
//!   terminal by a scripted one (a real TTY cannot be driven in CI);
//! - `keyadm ceremony` first (task A15a: keyd refuses Role::Directory's
//!   `set_secret` without a grant, and the ceremony grants each first
//!   administrator's initial secret — docs/51 §5.8, docs/questions/Q-451),
//!   through keyadm's public API on a second socket of the same keyd where
//!   the test's uid holds Role::Admin (keyd-daemon `ExtraListener`, tests
//!   only — docs/questions/Q-453).
//!
//! keyd offers no operation that reads a key (docs/10 §7), so what keyd set
//! is checked through `set_secret`'s kvno, through keyd verifying the
//! password the way the KDC does — `verify_preauth` of a PA-ENC-TIMESTAMP
//! under the key derived from it, on a third socket of the same keyd where
//! the test's uid is Role::Kdc (no role holds `verify_secret` since A-102,
//! docs/52 R4; the keyd clock is a test clock past the startup hold-down,
//! RFC 4120 §3.2.3) — and keyd's audit records (docs/10 §10).
//!
//! Since A-102 the ceremony ends with `seal_ceremony` (docs/52 R3) and its
//! grants bind the manifest's salts (`first_admin_salts`, N4): the grants
//! registered before the seal still redeem after it.
//!
//! Sources: docs/51 §4.3 steps 5, 7, 8, 12, §4.4, §4.5; docs/47 §3.3, §9.1;
//! docs/10 §2, §6, §9, §10; A-35; A-73; A-77; A-79; A-88; A-90; Q-401.
//! Every value (names, passwords, accounts, paths) is constructed by hand
//! for these tests; no vector comes from any other implementation.

#[path = "../../keyd-daemon/tests/support/mod.rs"]
mod support;

#[path = "../../kdc/tests/common/mod.rs"]
mod kdc_common;

mod common;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Duration;

use ipc::{FrameReader, Refused};
use ipc_audit::{EventBody, KeyPurposeCode, KeydOperation, KeydOutcome, KeydRecord};
use ipc_keyd::{
    ClientConfigError, ExpectedPeer, KeydClient, TransportError, Unserved, DEFAULT_DEADLINE,
};
use keyd_daemon::startup::development_keyd;
use keyd_daemon::test_seams::ExtraListener;
use keyd_daemon::{CallerMap, SystemClock};
use keyd_types::{Error as KeydError, Kvno};
use keyd_types::{KeyHandle, KeyPurpose};
use krb_proto::Realm;
use provision::first_admin::entry::{EntryError, Terminal};
use provision::first_admin::keyd::{KeydAccess, Outcome};
use provision::first_admin::password_file::FileRefusal;
use provision::first_admin::privilege::{hardening_plan, DropError, PrivilegeDrop};
use provision::first_admin::report::{
    exit_code, render, SecretReport, EXIT_COMPLETE, EXIT_INCOMPLETE, EXIT_NOTHING_SENT,
};
use provision::first_admin::{
    execute, run, Environment, FirstAdminSecret, PasswordFileArg, Refusal,
};
use provision::{provision_domain, Account, DomainInput, FilePath};
use provision_manifest::Manifest;
use support::{params, Daemon, FakeAuditd, TestClock};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
mod connector {
    //! Linux: the ipc-keyd connector (rustix peer credentials).
    pub type KeydConnector = ipc_keyd::UnixConnector;

    pub fn new(path: &std::path::Path) -> KeydConnector {
        ipc_keyd::UnixConnector::new(path.to_path_buf())
    }
}

#[cfg(not(target_os = "linux"))]
mod connector {
    //! Other hosts (where the ipc-keyd connector fails closed): keyd's uid
    //! through tokio `UnixStream::peer_cred`, then
    //! `ipc_keyd::UnixConnection` — as tests/ceremony.rs and
    //! crates/keyadm/tests/ceremony.rs do (tokio 1.54.1 docs.rs: `from_std`
    //! needs a runtime context and a non-blocking stream; `into_std`
    //! returns it non-blocking).
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

// ---- the injected environment ------------------------------------------------------

/// What the injected drop and terminal saw, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Drop(u32, u32),
    Prompt(String),
}

type Log = Rc<RefCell<Vec<Event>>>;

/// The test's privilege drop: records the account (it cannot change the
/// identity without root).
struct RecordingDrop {
    log: Log,
    fail: bool,
}

impl PrivilegeDrop for RecordingDrop {
    fn drop_to(&mut self, uid: u32, gid: u32) -> Result<(), DropError> {
        self.log.borrow_mut().push(Event::Drop(uid, gid));
        if self.fail {
            return Err(DropError::AlreadyUsed);
        }
        Ok(())
    }
}

/// A scripted terminal: each hidden entry answers the next line.
struct ScriptedTerminal {
    present: bool,
    lines: VecDeque<Vec<u8>>,
    log: Log,
}

impl Terminal for ScriptedTerminal {
    fn is_terminal(&self) -> bool {
        self.present
    }

    fn read_hidden(
        &mut self,
        prompt: &str,
        line: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), EntryError> {
        self.log.borrow_mut().push(Event::Prompt(prompt.to_owned()));
        line.clear();
        let next = self.lines.pop_front().ok_or(EntryError::EndOfInput)?;
        line.extend_from_slice(&next);
        Ok(())
    }
}

/// The test's keyd access: a socket and the uid keyd runs as (in-process:
/// the test's uid), ignoring admind's configured keyd endpoint; counts the
/// clients made (none ⇒ keyd was never contacted).
struct TestKeyd {
    socket: PathBuf,
    uid: u32,
    deadline: Duration,
    clients: u32,
}

impl KeydAccess for TestKeyd {
    type Connector = connector::KeydConnector;

    fn client(
        &mut self,
        _settings: &config::AdmindSettings,
    ) -> Result<KeydClient<connector::KeydConnector>, ClientConfigError> {
        self.clients += 1;
        // The command runs as admind's account: keyd must resolve it to
        // Role::Directory on every connection (task R9).
        Ok(KeydClient::new(
            connector::new(&self.socket),
            ExpectedPeer::new(self.uid, keyd_types::Role::Directory)?,
            self.deadline,
        ))
    }
}

// ---- the world ------------------------------------------------------------------------

/// Part A's files (the test's uid is admind's) and a running keyd whose
/// role map comes from the produced keyd configuration.
struct World {
    dir: common::TempDir,
    _keyd_dir: support::TempDir,
    uid: u32,
    input: DomainInput,
    manifest: Manifest,
    auditd: FakeAuditd,
    daemon: Option<Daemon>,
    /// The same keyd's second socket, where the test's uid is keyadm's
    /// Role::Admin (task A15a; tests only).
    admin_socket: PathBuf,
    /// The same keyd's third socket, where the test's uid is the KDC's
    /// Role::Kdc — the password check (A-102: `verify_preauth`).
    kdc_socket: PathBuf,
}

/// The test passwords (constructed by hand; obviously test data).
const ALICE_PW: &str = "Velvet-Harbor-Quince-58";
const BOB_PW: &str = "Cobalt-Meadow-Ferry-17";

/// The world after `keyadm ceremony` (its three key sets and the first
/// administrators' initial-secret grants, task A15a).
fn world() -> Option<World> {
    let world = world_without_ceremony()?;
    let report = world.ceremony();
    assert!(report.is_complete(), "{report:?}");
    Some(world)
}

/// The world before `keyadm ceremony`: keyd holds no key set and no grant.
fn world_without_ceremony() -> Option<World> {
    let dir = common::TempDir::new();
    let uid = common::my_uid(&dir);
    if common::skip_as_root(uid) {
        return None;
    }
    let mut input = common::input(&dir, 61002, 61007);
    input.accounts.admind = Account { uid, gid: uid };
    provision_domain(
        &input,
        common::now(),
        &mut common::CountingRandom::default(),
        &mut common::Recorder::new(uid),
        &mut common::HaltAt::never(),
    )
    .unwrap();
    let manifest =
        Manifest::parse(&std::fs::read(input.paths.manifest.as_path()).unwrap()).unwrap();
    let keyd_settings =
        config::KeydSettings::parse(&std::fs::read(input.paths.keyd_config.as_path()).unwrap())
            .unwrap();
    // A-73: the produced role map gives admind's account Role::Directory.
    assert_eq!(
        keyd_settings.uid_roles().role_of(uid),
        Some(config::RoleName::Directory)
    );
    let callers = CallerMap::from_role_map(keyd_settings.uid_roles()).unwrap();
    let keyd_dir = support::TempDir::new();
    let mut params = params(&keyd_dir, callers, uid);
    // keyadm's role on a second socket of the same keyd: one test uid
    // cannot be admind's and keyadm's in one uid map (R50-3), and the
    // ceremony's grants must be in the keyd that first-admin-secret uses.
    let admin_socket = keyd_dir.join("kx.sock");
    let kdc_socket = keyd_dir.join("kq.sock");
    params.extra_listeners = vec![
        ExtraListener {
            socket: admin_socket.clone(),
            callers: CallerMap::new(&[(uid, keyd::Role::Admin)]).unwrap(),
        },
        // The password check the KDC's way (A-102, docs/52 R4).
        ExtraListener {
            socket: kdc_socket.clone(),
            callers: CallerMap::new(&[(uid, keyd::Role::Kdc)]).unwrap(),
        },
    ];
    let auditd = FakeAuditd::start(&params.audit.socket);
    let realm = Realm::new(keyd_settings.realm()).unwrap();
    // keyd's own clock is a test clock: started at `keyd_started`, then
    // moved to `now` — past the startup hold-down of `verify_preauth`
    // (RFC 4120 §3.2.3, A-62), which the password check needs.
    let clock = TestClock::at(kdc_common::keyd_started());
    let daemon = Daemon::start(params, clock.clone(), development_keyd(realm)).unwrap();
    clock.set(kdc_common::now());
    std::fs::DirBuilder::new()
        .recursive(true)
        .create(dir.join("secrets"))
        .unwrap();
    Some(World {
        dir,
        _keyd_dir: keyd_dir,
        uid,
        input,
        manifest,
        auditd,
        daemon: Some(daemon),
        admin_socket,
        kdc_socket,
    })
}

impl World {
    fn keyd_socket(&self) -> PathBuf {
        self.daemon.as_ref().unwrap().socket.clone()
    }

    /// `keyadm ceremony` (its public API) as Role::Admin on the same keyd.
    fn ceremony(&self) -> keyadm::ceremony::CeremonyReport {
        let mut client = KeydClient::new(
            connector::new(&self.admin_socket),
            ExpectedPeer::new(self.uid, keyd_types::Role::Admin).unwrap(),
            DEFAULT_DEADLINE,
        );
        keyadm::ceremony::run(&mut client, &self.manifest)
    }

    /// keyd's GrantSetSecret outcome records so far (intents apart).
    fn grant_records(&self) -> Vec<KeydRecord> {
        self.auditd
            .events()
            .into_iter()
            .filter_map(|event| match event {
                EventBody::Keyd(record)
                    if record.op == KeydOperation::GrantSetSecret
                        && record.result != KeydOutcome::Intent =>
                {
                    Some(*record)
                }
                _ => None,
            })
            .collect()
    }

    fn keyd(&self) -> TestKeyd {
        TestKeyd {
            socket: self.keyd_socket(),
            uid: self.uid,
            deadline: DEFAULT_DEADLINE,
            clients: 0,
        }
    }

    /// A password file under the world's directory.
    fn file(&self, name: &str, content: &[u8], mode: u32) -> FilePath {
        let path = self.dir.join(&format!("secrets/{name}"));
        // A file of an earlier run may be read-only (0400).
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        FilePath::parse(path.to_str().unwrap()).unwrap()
    }

    /// The request with these password files.
    fn request(&self, files: Vec<(&str, FilePath)>) -> FirstAdminSecret {
        FirstAdminSecret {
            manifest: self.input.paths.manifest.clone(),
            admind_config: self.input.paths.admind_config.clone(),
            password_files: files
                .into_iter()
                .map(|(sam, path)| PasswordFileArg {
                    sam: sam.to_owned(),
                    path,
                })
                .collect(),
        }
    }

    /// Both first administrators' files, mode 0600 and 0400.
    fn both_files(&self, alice: &str, bob: &str) -> FirstAdminSecret {
        self.pair("std", alice, bob)
    }

    /// Both first administrators' files under names tagged `tag` (a request
    /// kept for later is not changed by another one's files).
    fn pair(&self, tag: &str, alice: &str, bob: &str) -> FirstAdminSecret {
        let a = self.file(
            &format!("{tag}-alice.pw"),
            format!("{alice}\n").as_bytes(),
            0o600,
        );
        let b = self.file(&format!("{tag}-bob.pw"), bob.as_bytes(), 0o400);
        self.request(vec![("alice", a), ("bob", b)])
    }

    /// keyd's SetSecret outcome records so far (A-88: intents apart).
    fn set_secret_records(&self) -> Vec<KeydRecord> {
        self.auditd
            .events()
            .into_iter()
            .filter_map(|event| match event {
                EventBody::Keyd(record)
                    if record.op == KeydOperation::SetSecret
                        && record.result != KeydOutcome::Intent =>
                {
                    Some(*record)
                }
                _ => None,
            })
            .collect()
    }

    /// keyd verifies `candidate` for first administrator `index` the way
    /// the KDC does: `verify_preauth` of a PA-ENC-TIMESTAMP (RFC 4120
    /// §5.2.7.2) under the key derived from `candidate` with the manifest's
    /// salt — the salt first-admin-secret presented (A-102, N4) — on the
    /// Role::Kdc socket (no role holds `verify_secret`, docs/52 R4). keyd's
    /// uniform refusal is `Denied`.
    fn verify(&self, index: usize, candidate: &str) -> Result<(), KeydError> {
        let admin = &self.manifest.first_admins()[index];
        let salt = admin.salt();
        let key = kdc_common::password_key(kdc_common::AES256, candidate, salt);
        // No kvno: the PA-ENC-TIMESTAMP names the current key.
        let mut padata = kdc_common::pa_enc_timestamp(&key, kdc_common::now());
        let mut sealed = krb_proto::EncryptedData::decode(&padata.padata_value).unwrap();
        sealed.kvno = None;
        padata.padata_value = sealed.encode().unwrap();
        let mut client = KeydClient::new(
            connector::new(&self.kdc_socket),
            ExpectedPeer::new(self.uid, keyd_types::Role::Kdc).unwrap(),
            DEFAULT_DEADLINE,
        );
        let handle = KeyHandle::new(
            admin.key_set().handle.principal,
            KeyPurpose::PrincipalLongterm,
        );
        match client.verify_preauth(&handle, &padata, None) {
            Ok(_) => Ok(()),
            Err(keyd_types::AuthnError::Denied) => Err(KeydError::Denied),
            Err(_) => Err(KeydError::Unavailable),
        }
    }

    fn stop(mut self) {
        if let Some(daemon) = self.daemon.take() {
            daemon.stop().unwrap();
        }
    }
}

/// A full environment over `drop`, `terminal`, `keyd`, files owned by the
/// test's uid.
fn env<'a>(
    world: &World,
    drop: &'a mut RecordingDrop,
    terminal: &'a mut ScriptedTerminal,
    keyd: &'a mut TestKeyd,
) -> Environment<'a, RecordingDrop, ScriptedTerminal, TestKeyd> {
    Environment {
        privilege: drop,
        terminal,
        keyd,
        root_uid: world.uid,
        running_uid: world.uid,
    }
}

fn recorder(log: &Log) -> RecordingDrop {
    RecordingDrop {
        log: Rc::clone(log),
        fail: false,
    }
}

fn no_terminal(log: &Log) -> ScriptedTerminal {
    ScriptedTerminal {
        present: false,
        lines: VecDeque::new(),
        log: Rc::clone(log),
    }
}

fn terminal(log: &Log, lines: &[&str]) -> ScriptedTerminal {
    ScriptedTerminal {
        present: true,
        lines: lines.iter().map(|l| l.as_bytes().to_vec()).collect(),
        log: Rc::clone(log),
    }
}

/// Run `request` with password files (no terminal), a recording drop and
/// the world's keyd; the result and the number of keyd clients made.
fn run_files(world: &World, request: &FirstAdminSecret) -> (Result<SecretReport, Refusal>, u32) {
    let log: Log = Rc::default();
    let mut drop = recorder(&log);
    let mut term = no_terminal(&log);
    let mut keyd = world.keyd();
    let result = run(request, &mut env(world, &mut drop, &mut term, &mut keyd));
    (result, keyd.clients)
}

// ---- the tests ------------------------------------------------------------------------

/// docs/51 §4.3 step 12: each first administrator's `(GUID,
/// PrincipalLongterm)` key set gets the password with its NT-PRINCIPAL
/// binding — kvno 1 for a new key set (A-35) — and keyd accepts exactly
/// that password (`verify_preauth`; the salt is the AccountSource's, R47-4,
/// the one the manifest carries — A-102); the drop asked for admind's account (from admind's file);
/// keyd's audit records the two set_secret calls (docs/10 §10).
#[test]
fn both_first_admins_get_kvno_1_and_keyd_verifies_each_password() {
    let Some(world) = world() else {
        return;
    };
    let log: Log = Rc::default();
    let mut drop = recorder(&log);
    let mut term = no_terminal(&log);
    let mut keyd = world.keyd();
    let request = world.both_files(ALICE_PW, BOB_PW);
    let report = run(&request, &mut env(&world, &mut drop, &mut term, &mut keyd)).unwrap();
    assert!(report.is_complete(), "{report:?}");
    assert_eq!(
        report.set(),
        [("alice", Kvno::INITIAL), ("bob", Kvno::INITIAL)]
    );
    assert_eq!(exit_code(&report), EXIT_COMPLETE);
    assert_eq!(*log.borrow(), [Event::Drop(world.uid, world.uid)]);
    let text = render(&report).join("\n");
    let alice = &world.manifest.first_admins()[0];
    assert!(
        text.contains(&format!(
            "set alice: principal {} purpose PrincipalLongterm binding NT-PRINCIPAL:alice kvno 1",
            alice.key_set().guid_text()
        )),
        "{text}"
    );
    assert!(text.contains("binding NT-PRINCIPAL:bob kvno 1"), "{text}");
    assert!(text.contains("complete: 2 of 2"), "{text}");
    assert!(text.contains("development mode (A-77)"), "{text}");
    assert!(!text.contains("note: keyd already held"), "{text}");
    let debug = format!("{report:?}");
    assert!(!debug.contains(ALICE_PW) && !debug.contains(BOB_PW));

    assert_eq!(world.verify(0, ALICE_PW), Ok(()));
    assert_eq!(world.verify(1, BOB_PW), Ok(()));
    assert_eq!(world.verify(0, BOB_PW), Err(KeydError::Denied));
    assert_eq!(world.verify(1, ALICE_PW), Err(KeydError::Denied));

    assert!(support::eventually(Duration::from_secs(10), || world
        .set_secret_records()
        .len()
        >= 2));
    let records = world.set_secret_records();
    for (record, admin) in records.iter().zip(world.manifest.first_admins()) {
        assert_eq!(
            record.principal,
            Some(*admin.key_set().handle.principal.as_bytes())
        );
        assert_eq!(record.purpose, Some(KeyPurposeCode::PrincipalLongterm));
        assert_eq!(record.kvno, Some(1));
        assert_eq!(record.result, KeydOutcome::Success);
        assert_eq!(record.caller_uid, world.uid);
    }
    world.stop();
}

/// Task A15a (docs/51 §5.8 option (b); docs/questions/Q-451): the
/// ceremony's grants are one-time and cover initial secrets only — a second
/// run against a keyd that still holds the key sets is refused at the first
/// administrator (keyd's uniform Denied, `NoGrant` in its audit), and
/// keyadm cannot grant a replacement (since A-102 the ceremony sealed keyd:
/// `CeremonySealed`; docs/52 R3): the provisioning path never resets a
/// password past dird's PDP. The first passwords stay.
#[test]
fn a_second_run_is_refused_without_a_new_grant() {
    let Some(world) = world() else {
        return;
    };
    let (first, _) = run_files(&world, &world.both_files(ALICE_PW, BOB_PW));
    assert!(first.unwrap().is_complete());
    let alice2 = "Amber-Quiver-Tundra-26";
    let bob2 = "Saffron-Pylon-Delta-93";
    let (second, _) = run_files(&world, &world.both_files(alice2, bob2));
    let second = second.unwrap();
    assert_eq!(second.steps.len(), 1, "stopped at the first administrator");
    assert_eq!(
        second.steps[0].outcome,
        Outcome::Answered(Err(KeydError::Denied))
    );
    assert_eq!(exit_code(&second), EXIT_INCOMPLETE);
    let text = render(&second).join("\n");
    assert!(text.contains("no live grant"), "{text}");
    assert!(support::eventually(Duration::from_secs(10), || world
        .auditd
        .events()
        .iter()
        .any(|e| matches!(e, EventBody::Keyd(r)
            if r.op == KeydOperation::SetSecret
                && r.reason == ipc_audit::KeydReason::NoGrant))));
    // keyadm cannot grant alice another initial secret: her key set exists.
    let mut admin = KeydClient::new(
        connector::new(&world.admin_socket),
        ExpectedPeer::new(world.uid, keyd_types::Role::Admin).unwrap(),
        DEFAULT_DEADLINE,
    );
    let alice = world.manifest.first_admins()[0].key_set();
    assert_eq!(
        admin.grant_set_secret(
            keyd_types::AccountKind::User,
            &[keyd_types::SetSecretTarget {
                handle: alice.handle,
                binding: alice.binding.clone(),
                salt: world.manifest.first_admins()[0].salt().to_owned(),
            }],
            keyd_types::MAX_INITIAL_SECRET_GRANT_SECS,
        ),
        Ok(Err(KeydError::Denied))
    );
    assert!(support::eventually(Duration::from_secs(10), || world
        .grant_records()
        .iter()
        .any(|r| r.reason == ipc_audit::KeydReason::CeremonySealed)));
    assert_eq!(world.verify(0, ALICE_PW), Ok(()));
    assert_eq!(world.verify(1, BOB_PW), Ok(()));
    assert_eq!(world.verify(0, alice2), Err(KeydError::Denied));
    world.stop();
}

/// Task A15a (the attack Q-291 describes, on the provisioning path): without
/// keyadm ceremony's grant a Directory client cannot set a first
/// administrator's secret — keyd's uniform Denied, `NoGrant` in its audit,
/// no key set created; the report explains it. After the ceremony the same
/// command succeeds, and the ceremony recorded one grant per administrator.
#[test]
fn without_the_ceremony_grant_the_first_admin_secret_is_denied() {
    let Some(world) = world_without_ceremony() else {
        return;
    };
    let (result, _) = run_files(&world, &world.both_files(ALICE_PW, BOB_PW));
    let report = result.unwrap();
    assert_eq!(report.steps.len(), 1);
    assert_eq!(
        report.steps[0].outcome,
        Outcome::Answered(Err(KeydError::Denied))
    );
    assert_eq!(exit_code(&report), EXIT_INCOMPLETE);
    let text = render(&report).join("\n");
    assert!(text.contains("run keyadm ceremony first"), "{text}");
    assert!(support::eventually(Duration::from_secs(10), || !world
        .set_secret_records()
        .is_empty()));
    let refused = &world.set_secret_records()[0];
    assert_eq!(refused.result, KeydOutcome::Denied);
    assert_eq!(refused.reason, ipc_audit::KeydReason::NoGrant);
    assert_eq!(world.verify(0, ALICE_PW), Err(KeydError::Denied));

    let ceremony = world.ceremony();
    assert!(ceremony.is_complete(), "{ceremony:?}");
    assert!(support::eventually(Duration::from_secs(10), || world
        .grant_records()
        .len()
        >= 2));
    let grants = world.grant_records();
    for (record, admin) in grants.iter().zip(world.manifest.first_admins()) {
        assert_eq!(record.result, KeydOutcome::Success);
        assert_eq!(record.caller_role, ipc_audit::KeydRole::Admin);
        assert_eq!(
            record.principal,
            Some(*admin.key_set().handle.principal.as_bytes())
        );
        assert_eq!(record.purpose, Some(KeyPurposeCode::PrincipalLongterm));
    }
    let (result, _) = run_files(&world, &world.both_files(ALICE_PW, BOB_PW));
    assert!(result.unwrap().is_complete());
    assert_eq!(world.verify(0, ALICE_PW), Ok(()));
    world.stop();
}

/// docs/51 §4.4 source (a): without password files each password is
/// entered twice at the terminal — every prompt **after** the drop (no
/// password before the process is not dumpable) — and set (kvno 1).
#[test]
fn the_terminal_entries_come_after_the_drop_and_are_set() {
    let Some(world) = world() else {
        return;
    };
    let log: Log = Rc::default();
    let mut drop = recorder(&log);
    let mut term = terminal(&log, &[ALICE_PW, ALICE_PW, BOB_PW, BOB_PW]);
    let mut keyd = world.keyd();
    let request = world.request(Vec::new());
    let report = run(&request, &mut env(&world, &mut drop, &mut term, &mut keyd)).unwrap();
    assert!(report.is_complete(), "{report:?}");
    let events = log.borrow().clone();
    assert_eq!(events.len(), 5);
    assert_eq!(events[0], Event::Drop(world.uid, world.uid));
    assert_eq!(
        events[1],
        Event::Prompt("provision: new password for first administrator alice: ".to_owned())
    );
    assert_eq!(
        events[3],
        Event::Prompt("provision: new password for first administrator bob: ".to_owned())
    );
    assert_eq!(world.verify(0, ALICE_PW), Ok(()));
    assert_eq!(world.verify(1, BOB_PW), Ok(()));
    world.stop();
}

/// docs/51 §4.4 ("entered twice and compared"): a mismatch for the second
/// administrator ends the run before keyd is contacted — the first
/// administrator's password is not sent either.
#[test]
fn a_terminal_mismatch_sends_nothing() {
    let Some(world) = world() else {
        return;
    };
    let log: Log = Rc::default();
    let mut drop = recorder(&log);
    let mut term = terminal(
        &log,
        &[ALICE_PW, ALICE_PW, BOB_PW, "Cobalt-Meadow-Ferry-18"],
    );
    let mut keyd = world.keyd();
    let request = world.request(Vec::new());
    let refusal = run(&request, &mut env(&world, &mut drop, &mut term, &mut keyd)).unwrap_err();
    assert_eq!(
        refusal,
        Refusal::Entry {
            sam: "bob".to_owned(),
            error: EntryError::Mismatch
        }
    );
    assert_eq!(keyd.clients, 0);
    assert!(world.set_secret_records().is_empty());
    world.stop();
}

/// docs/51 §4.4 (never argv or env): no password file and no terminal ⇒
/// refused before the drop.
#[test]
fn no_file_and_no_terminal_is_refused_before_the_drop() {
    let Some(world) = world() else {
        return;
    };
    let (result, clients) = run_files(&world, &world.request(Vec::new()));
    assert_eq!(result.unwrap_err(), Refusal::NoTerminal);
    assert_eq!(clients, 0);
    world.stop();
}

/// A failed privilege drop stops the run: nothing read, nothing sent.
#[test]
fn a_failed_drop_sends_nothing() {
    let Some(world) = world() else {
        return;
    };
    let log: Log = Rc::default();
    let mut drop = RecordingDrop {
        log: Rc::clone(&log),
        fail: true,
    };
    let mut term = terminal(&log, &[ALICE_PW, ALICE_PW, BOB_PW, BOB_PW]);
    let mut keyd = world.keyd();
    let request = world.request(Vec::new());
    let refusal = run(&request, &mut env(&world, &mut drop, &mut term, &mut keyd)).unwrap_err();
    assert_eq!(refusal, Refusal::Privilege(DropError::AlreadyUsed));
    assert_eq!(*log.borrow(), [Event::Drop(world.uid, world.uid)]);
    assert_eq!(keyd.clients, 0);
    world.stop();
}

/// [MS-SAMR] 3.1.1.7.2 items 2, 3.2.1, 3.2.2 (admind's rules, A-79 /
/// Q-401, crate admin-password-policy): each rule refuses the password —
/// here always the **second** administrator's, so a refusal is shown to
/// stop the first one being sent too — before keyd is contacted.
#[test]
fn each_password_rule_is_refused_before_keyd_is_contacted() {
    let Some(world) = world() else {
        return;
    };
    for (bad, rule) in [
        ("Short-pw-11", "minimum (12)"),
        (&"x".repeat(257)[..], "maximum (256 UTF-16 units)"),
        ("my-BOB-password-77", "account name"),
        ("xx-bOb-xx-xx-xx", "account name, mixed case"),
    ] {
        let (result, clients) = run_files(&world, &world.both_files(ALICE_PW, bad));
        assert_eq!(
            result.unwrap_err(),
            Refusal::PasswordRules {
                sam: "bob".to_owned(),
                min_chars: 12
            },
            "{rule}"
        );
        assert_eq!(clients, 0, "{rule}");
    }
    // The minimum comes from admind's configuration: 14 characters pass
    // with 12, not with 16.
    let fourteen = "Plum-Ridge-404";
    assert_eq!(fourteen.chars().count(), 14);
    let config_path = world.input.paths.admind_config.as_path().to_path_buf();
    let text = std::fs::read_to_string(&config_path).unwrap();
    assert!(text.contains("min_password_length = 12\n"));
    std::fs::write(
        &config_path,
        text.replace("min_password_length = 12\n", "min_password_length = 16\n"),
    )
    .unwrap();
    let (result, clients) = run_files(&world, &world.both_files(fourteen, BOB_PW));
    assert_eq!(
        result.unwrap_err(),
        Refusal::PasswordRules {
            sam: "alice".to_owned(),
            min_chars: 16
        }
    );
    assert_eq!(clients, 0);
    assert!(world.set_secret_records().is_empty());
    world.stop();
}

/// docs/51 §4.4 (the file rule): a symbolic link, the wrong owner, the
/// wrong mode, two lines, oversize, empty — each refused, with nothing
/// sent to keyd.
#[test]
fn password_files_are_refused_with_nothing_sent() {
    let Some(world) = world() else {
        return;
    };
    let good_bob = world.file("bob-good.pw", BOB_PW.as_bytes(), 0o600);
    let target = world.file("target.pw", ALICE_PW.as_bytes(), 0o600);
    let link = world.dir.join("secrets/link.pw");
    std::os::unix::fs::symlink(target.as_path(), &link).unwrap();
    let link = FilePath::parse(link.to_str().unwrap()).unwrap();
    let cases: Vec<(FilePath, FileRefusal)> = vec![
        (link, FileRefusal::Symlink),
        (
            world.file("m644.pw", ALICE_PW.as_bytes(), 0o644),
            FileRefusal::WrongMode,
        ),
        (
            world.file("m640.pw", ALICE_PW.as_bytes(), 0o640),
            FileRefusal::WrongMode,
        ),
        (
            world.file("m700.pw", ALICE_PW.as_bytes(), 0o700),
            FileRefusal::WrongMode,
        ),
        (
            world.file("two.pw", format!("{ALICE_PW}\nsecond\n").as_bytes(), 0o600),
            FileRefusal::NotOneLine,
        ),
        (
            world.file("crlf.pw", format!("{ALICE_PW}\r\n").as_bytes(), 0o600),
            FileRefusal::NotOneLine,
        ),
        (
            world.file("big.pw", &[b'a'; 1025], 0o600),
            FileRefusal::TooLarge,
        ),
        (world.file("empty.pw", b"", 0o600), FileRefusal::Empty),
        (world.file("lf.pw", b"\n", 0o600), FileRefusal::Empty),
    ];
    for (path, refusal) in cases {
        let request = world.request(vec![("alice", path), ("bob", good_bob.clone())]);
        let (result, clients) = run_files(&world, &request);
        assert_eq!(
            result.unwrap_err(),
            Refusal::PasswordFile {
                sam: "alice".to_owned(),
                refusal
            },
            "{refusal:?}"
        );
        assert_eq!(clients, 0, "{refusal:?}");
    }
    // The wrong owner: the file is the test's, the running uid another. The
    // walk from `/` (crates/protected-file, task R11b) refuses the first
    // directory of the test's account on the path before the file — the
    // file's own owner check is covered by `check_facts`' unit test.
    let request = world.both_files(ALICE_PW, BOB_PW);
    let log: Log = Rc::default();
    let mut drop = recorder(&log);
    let mut term = no_terminal(&log);
    let mut keyd = world.keyd();
    let mut e = env(&world, &mut drop, &mut term, &mut keyd);
    e.running_uid = world.uid.wrapping_add(1000);
    assert_eq!(
        run(&request, &mut e).unwrap_err(),
        Refusal::PasswordFile {
            sam: "alice".to_owned(),
            refusal: FileRefusal::Path(protected_file::PathBreak::DirectoryWrongOwner)
        }
    );
    assert!(log.borrow().is_empty(), "refused before the drop");
    assert_eq!(keyd.clients, 0);
    assert!(world.set_secret_records().is_empty());
    world.stop();
}

/// docs/51 §4.4: one `--password-file` for every first administrator, none
/// other, none twice.
#[test]
fn the_password_file_arguments_must_match_the_manifest() {
    let Some(world) = world() else {
        return;
    };
    let a = world.file("a.pw", ALICE_PW.as_bytes(), 0o600);
    let b = world.file("b.pw", BOB_PW.as_bytes(), 0o600);
    for (files, refusal) in [
        (
            vec![("alice", a.clone())],
            Refusal::MissingPasswordFile {
                sam: "bob".to_owned(),
            },
        ),
        (
            vec![
                ("alice", a.clone()),
                ("bob", b.clone()),
                ("carol", b.clone()),
            ],
            Refusal::UnknownPasswordFile {
                sam: "carol".to_owned(),
            },
        ),
        (
            vec![("alice", a.clone()), ("ALICE", b.clone())],
            Refusal::UnknownPasswordFile {
                sam: "ALICE".to_owned(),
            },
        ),
        (
            vec![("alice", a.clone()), ("alice", b.clone())],
            Refusal::DuplicatePasswordFile {
                sam: "alice".to_owned(),
            },
        ),
    ] {
        let (result, clients) = run_files(&world, &world.request(files));
        assert_eq!(result.unwrap_err(), refusal);
        assert_eq!(clients, 0);
    }
    world.stop();
}

/// The root-owned inputs: a manifest or admind file not owned by the
/// required owner, or writable by others, or a link, is refused first.
#[test]
fn the_manifest_and_admind_file_must_be_root_owned() {
    let Some(world) = world() else {
        return;
    };
    let request = world.both_files(ALICE_PW, BOB_PW);
    let log: Log = Rc::default();
    let mut drop = recorder(&log);
    let mut term = no_terminal(&log);
    let mut keyd = world.keyd();
    let mut e = env(&world, &mut drop, &mut term, &mut keyd);
    e.root_uid = world.uid.wrapping_add(1000);
    assert!(matches!(
        run(&request, &mut e).unwrap_err(),
        Refusal::AdmindConfig(provision::first_admin::root_files::RootFileError::NotRootOwned)
    ));
    let manifest = world.input.paths.manifest.as_path();
    std::fs::set_permissions(manifest, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(
        run_files(&world, &request).0.unwrap_err(),
        Refusal::Manifest(provision::first_admin::root_files::RootFileError::WritableByOthers)
    ));
    std::fs::set_permissions(manifest, std::fs::Permissions::from_mode(0o644)).unwrap();
    let link = world.dir.join("manifest-link");
    std::os::unix::fs::symlink(manifest, &link).unwrap();
    let mut linked = request.clone();
    linked.manifest = FilePath::parse(link.to_str().unwrap()).unwrap();
    assert!(matches!(
        run_files(&world, &linked).0.unwrap_err(),
        Refusal::Manifest(provision::first_admin::root_files::RootFileError::NotRegular)
    ));
    world.stop();
}

/// docs/52 §2 row 37 (N4, A-102): keyadm's ceremony grant binds the
/// manifest's salt, so a manifest whose salt is not the directory's is
/// refused before anything is entered or sent — keyd would refuse the
/// `set_secret` (`GrantMismatch`) anyway. (A manifest naming none does not
/// parse — `first_admin_salts` is required, A-105.)
#[test]
fn a_manifest_salt_other_than_the_directorys_is_refused() {
    let Some(world) = world() else {
        return;
    };
    let forged = world
        .manifest
        .with_first_admin_salts(&["not-the-salt".to_owned(), "nor-this".to_owned()])
        .unwrap();
    let path = world.dir.join("forged-manifest");
    std::fs::write(&path, forged.encode()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut request = world.both_files(ALICE_PW, BOB_PW);
    request.manifest = FilePath::parse(path.to_str().unwrap()).unwrap();
    let (result, clients) = run_files(&world, &request);
    assert_eq!(
        result.unwrap_err(),
        Refusal::SaltMismatch {
            sam: "alice".to_owned()
        }
    );
    assert_eq!(clients, 0, "keyd was not contacted");
    assert!(world.set_secret_records().is_empty());
    world.stop();
}

/// A-90 / A-88: keyd unreachable ⇒ "not sent" — the contact fails, no
/// set_secret is attempted, exit status 1.
#[test]
fn keyd_unreachable_is_not_sent() {
    let Some(world) = world() else {
        return;
    };
    let log: Log = Rc::default();
    let mut drop = recorder(&log);
    let mut term = no_terminal(&log);
    let mut keyd = world.keyd();
    keyd.socket = world.dir.join("no-keyd.sock");
    let request = world.both_files(ALICE_PW, BOB_PW);
    let report = run(&request, &mut env(&world, &mut drop, &mut term, &mut keyd)).unwrap();
    assert_eq!(
        report.contact,
        Outcome::NotSent(Unserved::Transport(TransportError::Connect))
    );
    assert!(report.steps.is_empty());
    assert_eq!(exit_code(&report), EXIT_NOTHING_SENT);
    let text = render(&report).join("\n");
    assert!(
        text.contains("contact failed: the keyd socket could not be connected (nothing was sent); no password was sent"),
        "{text}"
    );
    world.stop();
}

// ---- a scripted keyd (built from crates/ipc-keyd's own codec) -------------------------

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

/// What the scripted keyd does with a `set_secret`.
#[derive(Clone, Copy)]
enum OnSetSecret {
    /// Answer with the shared refusal.
    Refuse(Refused),
    /// Never answer (until the test is done).
    Silence,
}

/// A keyd at `path` that answers `Ping` and treats `set_secret` by `mode`;
/// returns the operations it received.
fn scripted_keyd(
    path: &Path,
    mode: OnSetSecret,
) -> (
    std::thread::JoinHandle<Vec<keyd::Operation>>,
    mpsc::Sender<()>,
) {
    let listener = UnixListener::bind(path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (done, wait_done) = mpsc::channel::<()>();
    let thread = std::thread::spawn(move || {
        let mut received = Vec::new();
        // Never wait forever for a client that does not come (a test that
        // went wrong earlier must fail, not hang).
        let start = std::time::Instant::now();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if start.elapsed() > Duration::from_secs(10) {
                        return received;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return received,
            }
        };
        stream.set_nonblocking(false).unwrap();
        while let Some(body) = read_one_frame(&mut stream, ipc_keyd::REQUEST_LIMIT) {
            let call = ipc_keyd::decode_request(&body).unwrap();
            received.push(call.operation());
            match (&call, mode) {
                (ipc_keyd::Call::Ping, _) => {
                    // The caller role keyd resolves for the command
                    // (task R9): the client's probe and its contact both
                    // ping.
                    let answer = ipc_keyd::Answer::Ping(Ok(keyd_types::Role::Directory));
                    stream
                        .write_all(ipc_keyd::encode_answer(&answer).unwrap().as_bytes())
                        .unwrap();
                }
                (_, OnSetSecret::Refuse(refused)) => {
                    let frame = ipc::encode_refused(ipc_keyd::KEYD_CHANNEL, refused).unwrap();
                    stream.write_all(frame.as_bytes()).unwrap();
                }
                (_, OnSetSecret::Silence) => {
                    let _ = wait_done.recv();
                    break;
                }
            }
        }
        received
    });
    (thread, done)
}

/// A-88 (keyd-daemon refuses a key-state change only before keyd runs it):
/// keyd refusing ⇒ "not performed" — the first set_secret is reported so,
/// nothing after it is attempted, exit status 2.
#[test]
fn keyd_refusing_is_not_performed() {
    let Some(world) = world() else {
        return;
    };
    let path = world.dir.join("scripted.sock");
    let (keyd_thread, done) = scripted_keyd(&path, OnSetSecret::Refuse(Refused::Busy));
    let log: Log = Rc::default();
    let mut drop = recorder(&log);
    let mut term = no_terminal(&log);
    let mut keyd = TestKeyd {
        socket: path,
        uid: world.uid,
        deadline: DEFAULT_DEADLINE,
        clients: 0,
    };
    let request = world.both_files(ALICE_PW, BOB_PW);
    let report = run(&request, &mut env(&world, &mut drop, &mut term, &mut keyd)).unwrap();
    let _ = done.send(());
    assert_eq!(
        keyd_thread.join().unwrap(),
        [
            keyd::Operation::Ping,
            keyd::Operation::Ping,
            keyd::Operation::SetSecret
        ]
    );
    assert_eq!(report.steps.len(), 1, "{report:?}");
    assert_eq!(
        report.steps[0].outcome,
        Outcome::NotPerformed(Refused::Busy)
    );
    assert_eq!(exit_code(&report), EXIT_INCOMPLETE);
    let text = render(&report).join("\n");
    assert!(
        text.contains(
            "alice: keyd is busy or cannot reach auditd (not performed); password not set"
        ),
        "{text}"
    );
    assert!(text.contains("not attempted: bob"), "{text}");
    assert!(!text.contains("MAY have been set"), "{text}");
    world.stop();
}

/// A-90 / Q-367: a keyd that never answers the set_secret ⇒ "outcome
/// unknown — check before retrying"; sent once, never retried.
#[test]
fn a_keyd_that_never_answers_is_outcome_unknown() {
    let Some(world) = world() else {
        return;
    };
    let path = world.dir.join("silent.sock");
    let (keyd_thread, done) = scripted_keyd(&path, OnSetSecret::Silence);
    let log: Log = Rc::default();
    let mut drop = recorder(&log);
    let mut term = no_terminal(&log);
    let mut keyd = TestKeyd {
        socket: path,
        uid: world.uid,
        deadline: Duration::from_millis(500),
        clients: 0,
    };
    let request = world.both_files(ALICE_PW, BOB_PW);
    let report = run(&request, &mut env(&world, &mut drop, &mut term, &mut keyd)).unwrap();
    let _ = done.send(());
    assert_eq!(
        keyd_thread.join().unwrap(),
        [
            keyd::Operation::Ping,
            keyd::Operation::Ping,
            keyd::Operation::SetSecret
        ]
    );
    assert_eq!(report.steps.len(), 1);
    assert_eq!(
        report.steps[0].outcome,
        Outcome::Unknown(Unserved::Transport(TransportError::DeadlineExceeded))
    );
    assert_eq!(exit_code(&report), EXIT_INCOMPLETE);
    let text = render(&report).join("\n");
    assert!(
        text.contains("alice: keyd did not answer in time after the request was sent; outcome unknown - check before retrying, the password MAY have been set"),
        "{text}"
    );
    assert!(text.contains("check keyd's audit log"), "{text}");
    world.stop();
}

/// **Attack test** — docs/10 §2; docs/50 R50-3, §3.7; docs/52 §3.12 (C12);
/// docs/questions/Q-403 option (c), Q-466 items 1-2 (A-102): admind's
/// account mapped to **another role** in keyd is found by the `Ping` probe
/// of the command's keyd connection, before anything else is sent: the
/// contact fails as not sent (the peer is not the expected keyd), **no
/// password is sent** (no step is attempted), explained.
#[test]
fn a_keyd_giving_another_role_receives_no_password() {
    let Some(mut world) = world() else {
        return;
    };
    world.daemon.take().unwrap().stop().unwrap();
    let keyd_dir = support::TempDir::new();
    let params = params(
        &keyd_dir,
        CallerMap::new(&[(world.uid, keyd::Role::Admin)]).unwrap(),
        world.uid,
    );
    let _auditd = FakeAuditd::start(&params.audit.socket);
    let daemon = Daemon::start(
        params,
        SystemClock,
        development_keyd(Realm::new("EXAMPLE.TEST").unwrap()),
    )
    .unwrap();
    world.daemon = Some(daemon);
    let (result, _) = run_files(&world, &world.both_files(ALICE_PW, BOB_PW));
    let report = result.unwrap();
    assert_eq!(report.contact, Outcome::NotSent(Unserved::PeerMismatch));
    assert!(report.steps.is_empty(), "no set_secret was sent");
    let text = render(&report).join("\n");
    assert!(
        text.contains("keyd does not give this account Role::Directory"),
        "{text}"
    );
    assert!(text.contains("no password was sent"), "{text}");
    world.stop();
}

/// docs/51 §4.4 ("no secret in the output"); AGENTS.md §6: across a
/// success, a re-run, each kind of refusal and each keyd failure, no
/// password appears in what the command prints (standard output and
/// error, captured), in a report's or refusal's `Debug`, or in keyd's audit
/// events.
#[test]
fn no_password_appears_in_any_output() {
    let Some(world) = world() else {
        return;
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut debug = String::new();
    // `twice`: run the command once for its Debug text, then printed. The
    // successful run is printed only: the ceremony's grants are one-time
    // (task A15a), so a second run would be refused.
    let mut run_one = |request: &FirstAdminSecret,
                       lines: &[&str],
                       keyd: &mut TestKeyd,
                       out: &mut Vec<u8>,
                       err: &mut Vec<u8>,
                       twice: bool| {
        let log: Log = Rc::default();
        let mut drop = recorder(&log);
        let mut term = if lines.is_empty() {
            no_terminal(&log)
        } else {
            terminal(&log, lines)
        };
        let mut e = env(&world, &mut drop, &mut term, keyd);
        if twice {
            debug.push_str(&format!("{:?}", run(request, &mut e)));
        }
        execute(request, &mut e, out, err)
    };
    let pw_short = "Short-pw-11";
    let pw_name = "my-BOB-password-77";
    let pw_mismatch = "Cobalt-Meadow-Ferry-18";
    let files = world.pair("ok", ALICE_PW, BOB_PW);
    let mut keyd = world.keyd();
    // Success (printed), then a re-run refused for want of a grant (task
    // A15a) — run twice.
    assert_eq!(
        run_one(&files, &[], &mut keyd, &mut out, &mut err, false),
        EXIT_COMPLETE
    );
    assert_eq!(
        run_one(&files, &[], &mut keyd, &mut out, &mut err, true),
        EXIT_INCOMPLETE
    );
    // Rule refusals.
    run_one(
        &world.pair("short", ALICE_PW, pw_short),
        &[],
        &mut keyd,
        &mut out,
        &mut err,
        true,
    );
    run_one(
        &world.pair("name", ALICE_PW, pw_name),
        &[],
        &mut keyd,
        &mut out,
        &mut err,
        true,
    );
    // A terminal mismatch, and terminal entries that succeed.
    let terminal_request = world.request(Vec::new());
    run_one(
        &terminal_request,
        &[ALICE_PW, ALICE_PW, BOB_PW, pw_mismatch],
        &mut keyd,
        &mut out,
        &mut err,
        true,
    );
    // keyd unreachable, refusing, silent.
    let mut gone = world.keyd();
    gone.socket = world.dir.join("gone.sock");
    run_one(&files, &[], &mut gone, &mut out, &mut err, true);
    for (name, mode) in [
        ("r1.sock", OnSetSecret::Refuse(Refused::Unavailable)),
        ("s1.sock", OnSetSecret::Silence),
    ] {
        // Two runs per scripted keyd (one connection each).
        for round in 0..2 {
            let path = world.dir.join(&format!("{round}{name}"));
            let (thread, done) = scripted_keyd(&path, mode);
            let mut scripted = TestKeyd {
                socket: path,
                uid: world.uid,
                deadline: Duration::from_millis(300),
                clients: 0,
            };
            let log: Log = Rc::default();
            let mut drop = recorder(&log);
            let mut term = no_terminal(&log);
            let mut e = env(&world, &mut drop, &mut term, &mut scripted);
            if round == 0 {
                debug.push_str(&format!("{:?}", run(&files, &mut e)));
            } else {
                execute(&files, &mut e, &mut out, &mut err);
            }
            let _ = done.send(());
            thread.join().unwrap();
        }
    }
    let audit = format!("{:?}", world.auditd.events());
    let out = String::from_utf8(out).unwrap();
    let err = String::from_utf8(err).unwrap();
    assert!(out.contains("set alice:"), "{out}");
    assert!(err.contains("no password was sent"), "{err}");
    for secret in [ALICE_PW, BOB_PW, pw_short, pw_name, pw_mismatch] {
        for (what, text) in [
            ("stdout", &out),
            ("stderr", &err),
            ("debug", &debug),
            ("audit", &audit),
        ] {
            assert!(!text.contains(secret), "{secret:?} in {what}");
        }
    }
    world.stop();
}

/// The binary as an operator runs it — here as the non-root test user:
/// `SandboxDrop` refuses to exist without root, so the binary refuses
/// before reading any file (exit 1), and prints no password.
#[test]
fn the_binary_refuses_without_root() {
    let Some(world) = world() else {
        return;
    };
    let pw = world.file("bin-alice.pw", ALICE_PW.as_bytes(), 0o600);
    let pb = world.file("bin-bob.pw", BOB_PW.as_bytes(), 0o600);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_provision"))
        .args([
            "first-admin-secret",
            "--manifest-path",
            world.input.paths.manifest.as_str(),
            "--admind-config",
            world.input.paths.admind_config.as_str(),
            "--password-file",
            &format!("alice={}", pw.as_str()),
            "--password-file",
            &format!("bob={}", pb.as_str()),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("must run as root"), "{stderr}");
    assert!(out.stdout.is_empty());
    assert!(!stderr.contains(ALICE_PW) && !stderr.contains(BOB_PW));
    world.stop();
}

/// docs/51 §4.4 (admind's profile): the drop's plan is admind's — the
/// identity, no_new_privs, every capability dropped, core 0, not dumpable,
/// mlockall with its limit — and refuses uid / gid 0 (as data; applying it
/// needs root and Linux, P-27).
#[test]
fn the_drop_plan_is_admind_profile() {
    let plan = hardening_plan(61006, 61006).unwrap();
    assert_eq!(
        plan.identity().map(|i| (i.uid(), i.gid())),
        Some((61006, 61006))
    );
    assert!(plan.sets_no_new_privs());
    assert!(plan.drops_capabilities());
    assert!(plan.disables_core_dumps());
    assert!(plan.makes_not_dumpable());
    assert!(plan.locks_all_memory());
    assert_eq!(plan.locked_memory_limit(), Some(256 * 1024 * 1024));
    assert_eq!(plan.file_mode_mask(), Some(0o077));
    assert!(hardening_plan(0, 61006).is_err());
    assert!(hardening_plan(61006, 0).is_err());
}
