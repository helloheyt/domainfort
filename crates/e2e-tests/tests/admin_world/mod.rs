//! The admin plane's world (task A13, docs/51 §12): a domain made by
//! `provision domain`, its key ceremony, every daemon over real sockets,
//! and the clients — the RFC-based Kerberos client of crates/kdc/tests/common
//! and a raw client of admind's `admin.sock`.
//!
//! # What runs, and in what order (docs/51 §4.3 steps 1-14; docs/50 §7.5)
//!
//! 1. **`provision domain`** as a library — `provision::provision_domain`
//!    with the installer's recording `Ownership` and `Progress` of A4's
//!    tests (crates/provision/tests/common, reused through `#[path]`),
//!    never root, into the run's 0700 temporary directory. Its database,
//!    integrity key, policy, manifest and seven configuration files are the
//!    daemons' inputs ([`World::provisioned`]).
//! 2. **The test-only workstation fixture** ([`Workstation`]; P-23 is open,
//!    docs/questions/Q-431): before dird starts, directly on the produced
//!    store, through the write PEP itself (crate directory-admin `prepare` /
//!    `apply` / commit, the way crates/provision/tests/admin_plane.rs drives
//!    it, with the verified-ticket facts of the first administrator
//!    injected): a computer `ws1$` in the workstations OU, a member of the
//!    bootstrap group, its password set, enabled. Its key set is set later
//!    through keyd's `set_secret` (Role::Directory). **Never part of
//!    provision.**
//! 3. **auditd → keyd (`Provisioning`: Admin on its socket) → `keyadm
//!    ceremony`** (library, over keyd's socket: the key sets and the first
//!    administrators' initial-secret grants, task A15a) → **`provision
//!    first-admin-secret`** (library, password files, the privilege drop
//!    recorded) against the **same** keyd under Directory on a second socket
//!    (the grants live in that keyd's memory), and the workstation's
//!    `set_secret` there too, after the test registers its grant as dird
//!    would (Ldap, a third socket) → **keyd (Kdc) → dird (with its admin
//!    service) → kdc → ldap-front → admind**.
//! 4. Then the phases of the run alternate keyd's role ([`KeydPhase`]):
//!    `Kerberos` (the kdc's AS / TGS) and `Admin` (dird verifies AP-REQs
//!    and registers the set_secret grants under Ldap on keyd's socket while
//!    admind's `set_secret` goes to the same keyd under Directory on a
//!    second socket — keyd-daemon `ExtraListener`, tests only,
//!    docs/questions/Q-453). How the keys survive keyd's restarts between
//!    phases: module [`custody`] (docs/questions/Q-430).
//!
//! # Identity: one test uid (A-82)
//!
//! Every daemon sees the test uid as each peer's; the configuration files
//! (which refuse one uid for two roles) give each daemon's **paths, realm,
//! naming context, timeouts and settings**, and the uids are injected:
//! keyd's `callers = [(uid, role)]`, dird's `kdc_uid` / `ldap_front_uid` /
//! `admind_uid`, every audit endpoint's uid, the clients' server uids. auditd
//! maps the one uid to one source label and binds every shape to it
//! (`support::single_label_binding`; Q-310 item 2). The produced files are
//! read through the daemons' own readers where those take the owner as a
//! parameter (the integrity key, the policy, the kdc's file, the manifest
//! and admind's file through provision's root-file reader), and parsed by
//! crates/config otherwise (their readers require root's ownership).
//!
//! # Time
//!
//! One world time ([`World::now`]), starting at the kdc fixtures' `now` and
//! moved forward by the tests; the kdc's and dird's clocks follow it
//! ([`SimClock`]); each keyd lifetime starts its own `TestClock` a day
//! earlier (its start-up hold-down long over, R50-6 / A-62) and is then set
//! to the world time; every Kerberos timestamp the client makes is the
//! world time. Provisioning happened at 09:00 and the fixture at 09:30 of
//! the same day, so every account's `whenCreated + 1 s` and `pwdLastSet`
//! precede its tickets (docs/47 §4.5).
//!
//! Sources: docs/51 §4.3, §4.5, §5.2, §5.3, §5.6, §5.7, §7, §9, §12 (A13);
//! docs/50 R50-3, §3, §7.5, §8.1, §9; docs/47 §3.3, §4.5, §9.1, §9.2;
//! RFC 4120 §3.1-§3.3, §5.5.1, §7.5.1; RFC 6113 §5.4; A-82, A-86, A-88,
//! A-91, A-94, A-96; P-10, P-17, P-22, P-23. Every value is hand-made test
//! data (obviously fake names and passwords).
#![allow(dead_code)]

pub mod custody;

#[path = "../../../provision/tests/common/mod.rs"]
pub mod provision_common;

use crate::common::{self, Armor, AsReqSpec, FastError, ServiceTicket, TgsReqSpec, Tgt};
use crate::support::kdcd::{self, connector, Kdcd};
use crate::support::keyd_support::{self, TestClock};
use crate::support::tls::{server_config, test_pki, TestPki};
use crate::support::{auditd as auditd_support, front_timeouts, single_label_binding, Front};
use crate::support::{eventually, skip_as_root, verified_log, LONG};
use audit_daemon::listener::ListenerConfig;
use config::{
    AdmindSettings, AuditdSettings, DirdSettings, KeyadmSettings, KeydSettings, LdapFrontSettings,
};
use core::time::Duration;
use custody::Custody;
use directory_admin::{
    AdminConfig, CreateComputer, DirectoryAdmin, KeyTarget, Membership, Operation as PepOperation,
    RandomError, RandomSource, Reply as PepReply, Request as PepRequest, SetEnabled,
    VerifiedTicket,
};
use directory_daemon::{
    serve_with_admin, AdminParams, DaemonControl as DirdControl, KeydTicketVerifier, SharedClock,
    StoreSource, TicketVerifier, VerifierFactory,
};
use directory_pip::{AccountKind, DirectoryContext, NamingContext};
use dtyp::Guid;
use ipc_audit::{decode_event, EventBody, WindowConfig};
use ipc_keyd::{Answer, Call, KeydClient};
use keyd::{Keyd, KeydConfig, Role};
use keyd_daemon::{CallerMap, ExtraListener, RecordBuffer};
use keyd_types::Kvno;
use krb_proto::constants::KRB_NT_PRINCIPAL;
use krb_proto::{AsRep, KerberosTime, PrincipalName, Realm};
use ldap_front::{ConnectionLimits, Endpoint, FrontParams};
use provision::first_admin::entry::{EntryError, Terminal};
use provision::first_admin::keyd::KeydAccess;
use provision::first_admin::privilege::{DropError, PrivilegeDrop};
use provision::first_admin::{self, Environment, FirstAdminSecret, PasswordFileArg};
use provision::{
    Account, Accounts, DomainInput, FilePath, Names, Network, ObjectRole, Paths, Plan,
};
use provision_common::{CountingRandom, HaltAt, Recorder};
use provision_manifest::Manifest;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;
use test_scratch::ScratchDir;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Test data.
// ---------------------------------------------------------------------------

/// The domain: the kdc fixtures' realm (crates/kdc/tests/common `REALM`),
/// so the client's names and `realm()` apply. A-53: the realm is the DNS
/// name upper-cased.
pub const REALM: &str = common::REALM;

/// The DC's host name (lower case).
pub const DC_FQDN: &str = "dc1.example.org";

/// The first administrators (P-22: at least two).
pub const ALICE: &str = "alice";
pub const BOB: &str = "bob";

/// The test-only workstation (fixture) — computer name and account name.
pub const WORKSTATION: &str = "ws1";
pub const WORKSTATION_SAM: &str = "ws1$";

/// The passwords of the run. Hand-made, distinctive, never written by any
/// component (docs/51 §4.4; docs/37 §2) — the tests search every log and
/// file for them. Each meets admind's rules (A-79: ≥ 12 characters, not
/// containing the account name).
pub const ALICE_PASSWORD: &str = "Tier0-Opening-Phrase-A1";
pub const BOB_PASSWORD: &str = "Tier0-Opening-Phrase-B2";
pub const WORKSTATION_PASSWORD: &str = "Workstation-Fixture-Secret-W9";
pub const NEW_USER_PASSWORD: &str = "Unclassified-User-Phrase-D4";
/// A password sent in a `SetPassword` that is refused (auditd down).
pub const REFUSED_PASSWORD: &str = "Another-Phrase-77";
/// A password a rogue Directory client sends straight to keyd with no
/// `BeginPasswordSet` before it — refused for want of a grant (task A15a).
pub const ROGUE_PASSWORD: &str = "Ungranted-Rogue-Phrase-R5";
pub const PASSWORDS: [&str; 6] = [
    ALICE_PASSWORD,
    BOB_PASSWORD,
    WORKSTATION_PASSWORD,
    NEW_USER_PASSWORD,
    REFUSED_PASSWORD,
    ROGUE_PASSWORD,
];

/// When `provision domain` ran (the day of the kdc fixtures' `now`).
pub fn provisioned_at() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 9, 0, 0).unwrap()
}

/// When the test-only workstation fixture was written.
pub fn fixture_at() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 9, 30, 0).unwrap()
}

/// A principal name of one component (RFC 4120 §6.2: NT-PRINCIPAL).
pub fn principal(sam: &str) -> PrincipalName {
    common::name(KRB_NT_PRINCIPAL, &[sam])
}

pub fn realm() -> Realm {
    Realm::new(REALM).unwrap()
}

/// A user's salt: the AccountSource's own function (R47-4; docs/47 §3.3),
/// the one dird's `BeginPasswordSet` and `provision first-admin-secret`
/// hand to keyd.
pub fn user_salt(sam: &str) -> String {
    directory_pip::account_salt(&realm(), AccountKind::User, sam)
        .unwrap()
        .as_str()
        .to_owned()
}

/// `true` if any password of the run occurs in `octets` (as UTF-8, or as
/// UTF-16LE — the encoding [MS-SAMR] 3.1.1.7.2 item 1 speaks of).
pub fn holds_a_password(octets: &[u8]) -> Option<&'static str> {
    PASSWORDS.into_iter().find(|password| {
        let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
        common::contains_bytes(octets, password.as_bytes())
            || common::contains_bytes(octets, &utf16)
    })
}

// ---------------------------------------------------------------------------
// Clocks.
// ---------------------------------------------------------------------------

/// The kdc's and dird's clock: the world time, moved by the test.
#[derive(Clone)]
pub struct SimClock(Arc<Mutex<KerberosTime>>);

impl SimClock {
    pub fn at(time: KerberosTime) -> SimClock {
        SimClock(Arc::new(Mutex::new(time)))
    }

    pub fn set(&self, time: KerberosTime) {
        *self.0.lock().unwrap() = time;
    }
}

impl kdc_daemon::Clock for SimClock {
    fn now(&self) -> Option<KerberosTime> {
        Some(*self.0.lock().unwrap())
    }
}

impl directory_daemon::Clock for SimClock {
    fn now(&self) -> Option<KerberosTime> {
        Some(*self.0.lock().unwrap())
    }
}

// ---------------------------------------------------------------------------
// Connectors (the host's way to read a server's uid).
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod dird_admin_connector {
    //! Linux: admind's own connector (rustix peer credentials).
    pub type Connector = ipc_dird_admin::UnixConnector;

    pub fn new(path: &std::path::Path) -> Connector {
        ipc_dird_admin::UnixConnector::new(path.to_path_buf())
    }
}

#[cfg(not(target_os = "linux"))]
mod dird_admin_connector {
    //! Other hosts (ipc-dird-admin's connector fails closed there): the
    //! server's uid through tokio `UnixStream::peer_cred`
    //! (crates/directory-daemon tests support `connector::connect_checked`),
    //! then the blocking connection — as crates/admin-daemon's tier-2
    //! support does.
    use crate::support::kdcd::dird::connector::{connect_checked, runtime};
    use ipc::FrameLimit;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use zeroize::Zeroizing;

    pub struct Connector {
        path: PathBuf,
        runtime: tokio::runtime::Runtime,
    }

    pub struct Checked {
        uid: u32,
        inner: ipc_dird_admin::UnixConnection,
    }

    pub fn new(path: &Path) -> Connector {
        Connector {
            path: path.to_path_buf(),
            runtime: runtime(),
        }
    }

    impl ipc_dird_admin::Connector for Connector {
        type Connection = Checked;
        fn connect(&mut self) -> Result<Checked, ipc_dird_admin::TransportError> {
            let (uid, stream) = connect_checked(&self.path, &self.runtime)
                .ok_or(ipc_dird_admin::TransportError::Connect)?;
            Ok(Checked {
                uid,
                inner: ipc_dird_admin::UnixConnection::from_stream(stream),
            })
        }
    }

    impl ipc_dird_admin::Connection for Checked {
        fn peer_uid(&self) -> Result<u32, ipc_dird_admin::TransportError> {
            Ok(self.uid)
        }
        fn exchange(
            &mut self,
            frame: &[u8],
            reply_limit: FrameLimit,
            deadline: Duration,
        ) -> Result<Zeroizing<Vec<u8>>, ipc_dird_admin::TransportError> {
            ipc_dird_admin::Connection::exchange(&mut self.inner, frame, reply_limit, deadline)
        }
        fn check_idle(&mut self) -> Result<(), ipc_dird_admin::TransportError> {
            ipc_dird_admin::Connection::check_idle(&mut self.inner)
        }
    }
}

/// keyd's intent-acknowledgement budget in these tests: the ceiling
/// (crates/keyd-daemon `MAX_INTENT_ACK_BUDGET`, 2 s) instead of the
/// production 1 s — the real auditd syncs its log before it acknowledges,
/// and a loaded machine can take longer (docs/questions/Q-415, A-95; Q-432).
pub fn intent_ack_budget() -> keyd_daemon::IntentAckBudget {
    keyd_daemon::IntentAckBudget::new(keyd_daemon::MAX_INTENT_ACK_BUDGET).unwrap()
}

/// The deadline of every test client whose calls change keyd's key state
/// (`create_key`, `set_secret`): twice the budget, so the A-88 rule —
/// budget ≤ half the client's deadline — holds against the test's own
/// clients (Q-415 item 5).
pub const KEY_STATE_DEADLINE: Duration = Duration::from_secs(4);

const _: () =
    assert!(keyd_daemon::MAX_INTENT_ACK_BUDGET.as_nanos() * 2 <= KEY_STATE_DEADLINE.as_nanos());

/// A keyd client for key-state changes ([`KEY_STATE_DEADLINE`]), expecting
/// keyd to resolve this process to `role` (task R9).
pub fn key_state_client(
    socket: &Path,
    uid: u32,
    role: Role,
) -> KeydClient<connector::KeydConnector> {
    KeydClient::new(
        connector::keyd(socket),
        ipc_keyd::ExpectedPeer::new(uid, role).unwrap(),
        KEY_STATE_DEADLINE,
    )
}

/// dird's decision-acknowledgement wait in these tests: twice the
/// production `DECISION_ACK_DEADLINE` (2 s), for the same reason as
/// [`intent_ack_budget`] (docs/questions/Q-417 item 3, A-95's follow-up;
/// Q-432). admind's dird deadline (20 s) still covers three keyd
/// verifications and this wait.
pub const DECISION_ACK_WAIT: Duration = Duration::from_secs(4);

/// The three worlds of this binary run one at a time: each runs six
/// daemons and the real auditd, whose log sync dominates under load.
pub static SERIAL: Mutex<()> = Mutex::new(());

/// Hold [`SERIAL`] (a panicked holder does not poison the others).
pub fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// keyd lifetimes.
// ---------------------------------------------------------------------------

/// keyd's roles in a phase of the run (module documentation; docs/10 §2,
/// the capability table). One keyd per phase; its first socket is the
/// produced `keyd_socket`, the others are test-only sockets of the same
/// keyd (keyd-daemon `ExtraListener`, docs/questions/Q-453).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeydPhase {
    /// The test uid is Admin on keyd's socket (`keyadm ceremony`:
    /// `create_key`, the first administrators' grants), Directory on the
    /// second socket (`provision first-admin-secret`, the workstation's
    /// `set_secret`) and Ldap on the third (the workstation's grant, as
    /// dird would register it — task A15a).
    Provisioning,
    /// The test uid is Kdc: the kdc's AS and TGS exchanges.
    Kerberos,
    /// The test uid is Ldap on keyd's socket (dird verifies AP-REQs and
    /// registers its decisions), Directory on the second socket (admind's
    /// `set_secret`) and Admin on the third (keyadm's sweep and key
    /// operations by decision id) — one keyd, so dird's decision is where
    /// admind's and keyadm's calls are checked (task A15a, A-102).
    Admin,
}

/// One running keyd and its clock.
pub struct KeydRun {
    pub daemon: keyd_support::Daemon,
    pub clock: TestClock,
    pub phase: KeydPhase,
}

// ---------------------------------------------------------------------------
// dird and admind on their own threads.
// ---------------------------------------------------------------------------

/// dird with its admin service on its own thread (as crates/admin-daemon's
/// tier-2 support runs it, over the produced database file).
pub struct DirdRun {
    control: DirdControl,
    thread: Option<JoinHandle<Result<usize, String>>>,
}

impl DirdRun {
    pub fn start(
        params: directory_daemon::DaemonParams,
        admin: AdminParams,
        source: StoreSource,
        policy: directory_daemon::policy::DevelopmentPolicy,
    ) -> Result<DirdRun, String> {
        let control = DirdControl::new();
        let thread = {
            let control = control.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let result = runtime.block_on(serve_with_admin(
                    params,
                    Some(admin),
                    source,
                    policy,
                    control,
                ));
                drop(runtime);
                match result {
                    Ok(stopped) => {
                        let unacknowledged = stopped.unacknowledged_audit_events();
                        stopped
                            .join()
                            .map_err(|_| String::from("engine panicked"))?;
                        Ok(unacknowledged)
                    }
                    Err(error) => Err(error.to_string()),
                }
            })
        };
        let start = Instant::now();
        while !control.is_serving() {
            if thread.is_finished() {
                return Err(thread.join().unwrap().err().unwrap_or_default());
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "dird did not start"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(DirdRun {
            control,
            thread: Some(thread),
        })
    }

    /// Stop dird; the audit events it could not deliver.
    pub fn stop(mut self) -> Result<usize, String> {
        self.control.stop();
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for DirdRun {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.control.stop();
            let _ = thread.join();
        }
    }
}

/// admind on its own thread.
pub struct AdmindRun {
    control: admin_daemon::DaemonControl,
    thread: Option<JoinHandle<Result<usize, String>>>,
}

impl AdmindRun {
    pub fn start(params: admin_daemon::DaemonParams) -> Result<AdmindRun, String> {
        let control = admin_daemon::DaemonControl::new();
        let thread = {
            let control = control.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let result = runtime.block_on(admin_daemon::serve(params, control));
                drop(runtime);
                match result {
                    Ok(stopped) => {
                        let unacknowledged = stopped.unacknowledged_audit_events();
                        stopped
                            .join()
                            .map_err(|_| String::from("worker panicked"))?;
                        Ok(unacknowledged)
                    }
                    Err(error) => Err(error.to_string()),
                }
            })
        };
        let start = Instant::now();
        while !control.is_serving() {
            if thread.is_finished() {
                return Err(thread.join().unwrap().err().unwrap_or_default());
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "admind did not start"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(AdmindRun {
            control,
            thread: Some(thread),
        })
    }

    /// Stop admind; the audit events it could not deliver.
    pub fn stop(mut self) -> Result<usize, String> {
        self.control.stop();
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for AdmindRun {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.control.stop();
            let _ = thread.join();
        }
    }
}

// ---------------------------------------------------------------------------
// A raw client of admin.sock (crate ipc-admin's codec).
// ---------------------------------------------------------------------------

/// What one exchange on `admin.sock` got.
#[derive(Debug, PartialEq, Eq)]
pub enum Got {
    /// One of the channel's replies.
    Reply(ipc_admin::Reply),
    /// The shared refusal (docs/50 §3.3, A-59).
    Refused(ipc::Refused),
    /// admind closed the connection without a reply.
    Closed,
    /// No reply within the read timeout.
    Nothing,
}

impl Got {
    pub fn reply(self) -> ipc_admin::Reply {
        match self {
            Got::Reply(reply) => reply,
            other => panic!("expected a reply, got {other:?}"),
        }
    }

    /// The status of a `Refused` reply.
    pub fn refusal(self) -> ipc_admin::RefusalStatus {
        match self {
            Got::Reply(ipc_admin::Reply::Refused(status)) => status,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The objectGUID of a `Created` reply.
    pub fn created(self) -> Guid {
        match self {
            Got::Reply(ipc_admin::Reply::Created { guid, .. }) => guid,
            other => panic!("expected Created, got {other:?}"),
        }
    }
}

/// One connection to `admin.sock`.
pub struct AdminConn {
    pub stream: UnixStream,
}

impl AdminConn {
    pub fn connect(path: &Path) -> std::io::Result<AdminConn> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        Ok(AdminConn { stream })
    }

    pub fn send(&mut self, request: &ipc_admin::Request) {
        let frame = ipc_admin::encode_request(request).unwrap();
        let _ = self.stream.write_all(frame.as_bytes());
    }

    pub fn receive(&mut self) -> Got {
        let mut reader = ipc::FrameReader::new(ipc_admin::REPLY_LIMIT);
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(body) = reader.body() {
                return match ipc_admin::decode_reply(body).unwrap() {
                    ipc::Reply::Message(reply) => Got::Reply(reply),
                    ipc::Reply::Refused(refused) => Got::Refused(refused),
                };
            }
            let wanted = reader.wanted().min(chunk.len());
            match self.stream.read(&mut chunk[..wanted]) {
                Ok(0) => return Got::Closed,
                Ok(n) => {
                    reader.push(&chunk[..n]).unwrap();
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e)
                    if matches!(e.kind(), ErrorKind::ConnectionReset | ErrorKind::BrokenPipe) =>
                {
                    return Got::Closed
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Got::Nothing
                }
                Err(e) => panic!("read failed: {e}"),
            }
        }
    }

    pub fn call(&mut self, request: &ipc_admin::Request) -> Got {
        self.send(request);
        self.receive()
    }
}

// ---------------------------------------------------------------------------
// provision first-admin-secret's environment in the tests.
// ---------------------------------------------------------------------------

/// The privilege drop, recorded (the test cannot change its uid — A6's
/// tests do the same).
#[derive(Debug, Default)]
pub struct RecordedDrop(pub Vec<(u32, u32)>);

impl PrivilegeDrop for RecordedDrop {
    fn drop_to(&mut self, uid: u32, gid: u32) -> Result<(), DropError> {
        self.0.push((uid, gid));
        Ok(())
    }
}

/// No terminal: the password files are given (docs/51 §4.4 source (b)).
pub struct NoTerminal;

impl Terminal for NoTerminal {
    fn is_terminal(&self) -> bool {
        false
    }

    fn read_hidden(
        &mut self,
        _prompt: &str,
        _line: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), EntryError> {
        Err(EntryError::Terminal)
    }
}

/// keyd for `first-admin-secret`: the socket admind's file names (checked
/// to be the produced keyd socket), keyd running as the test uid.
pub struct TestKeyd {
    /// The socket connected to (keyd's Directory socket of the phase).
    pub socket: PathBuf,
    /// The keyd socket admind's produced file names (asserted).
    pub produced: PathBuf,
    pub uid: u32,
}

impl KeydAccess for TestKeyd {
    type Connector = connector::KeydConnector;

    fn client(
        &mut self,
        settings: &AdmindSettings,
    ) -> Result<KeydClient<connector::KeydConnector>, ipc_keyd::ClientConfigError> {
        assert_eq!(settings.keyd().socket().as_path(), self.produced);
        assert!(settings.keyd_deadline() <= KEY_STATE_DEADLINE);
        // The command runs as admind's account: Role::Directory (task R9).
        Ok(KeydClient::new(
            connector::keyd(&self.socket),
            ipc_keyd::ExpectedPeer::new(self.uid, Role::Directory)?,
            KEY_STATE_DEADLINE,
        ))
    }
}

// ---------------------------------------------------------------------------
// The test-only workstation fixture.
// ---------------------------------------------------------------------------

/// objectGUIDs for the fixture's create (tests only — A-15: production
/// uses `OsRandom`), distinct from provisioning's draws.
#[derive(Debug, Default)]
struct FixtureRandom(u64);

impl RandomSource for FixtureRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        self.0 += 1;
        let mut pattern = [0xE2u8; 16];
        pattern[8..].copy_from_slice(&self.0.to_be_bytes());
        for (i, o) in out.iter_mut().enumerate() {
            *o = pattern[i % 16];
        }
        Ok(())
    }
}

/// **TEST-ONLY** — the workstation account whose TGT armors every user's
/// AS (RFC 6113 §5.4.1.1; mandatory FAST, A-39). P-23 (the armor source of
/// the first administrators' login) is open with the owner, and creating
/// it through the admin plane is circular (an administrator must already
/// be logged in, with armor). So it is written into the produced directory
/// **before dird starts**, through the write PEP (docs/questions/Q-431).
/// It is not, and must never become, part of `provision`.
#[derive(Debug, Clone)]
pub struct Workstation {
    pub guid: Guid,
    /// The key sets `BeginPasswordSet` named (one: no SPN — docs/47 §9.1).
    pub keys: Vec<KeyTarget>,
    /// The salt `BeginPasswordSet` named (R47-4).
    pub salt: String,
}

/// The fixture (module documentation, step 2): `CreateComputer` in the
/// workstations OU, `AddMember` to the bootstrap group (P-10: the computer
/// may bootstrap unarmored), `BeginPasswordSet` (pwdLastSet = now, docs/47
/// §9.2 step 2) and `SetEnabled(true)` — each `prepare` ⇒ `apply` ⇒ commit
/// on one `WriteTxn`, as dird's admin thread runs them, by the first
/// administrator (the workstations OU is unclassified: one Tier-0
/// administrator suffices, P-22 item 1).
fn workstation_fixture(plan: &Plan, input: &DomainInput, uid: u32) -> Workstation {
    let paths = &input.paths;
    let key =
        directory_daemon::startup::read_integrity_key(paths.integrity_key.as_path(), uid).unwrap();
    let schema = ad_schema::phase1().unwrap();
    let store =
        dirstore::Store::open(paths.database.as_path(), key, schema.schema().clone()).unwrap();
    let policy = directory_daemon::startup::read_policy(paths.policy.as_path(), uid).unwrap();
    let tiers = directory_daemon::policy::tier_map(&policy).unwrap();
    let snapshot = policy.snapshot().unwrap();
    let nc = NamingContext::new(&input.naming_context).unwrap();
    let ctx = DirectoryContext::new(
        ad_schema::phase1().unwrap(),
        &KeydConfig::new(realm()),
        nc.clone(),
    )
    .unwrap();
    let protected = directory_daemon::admin_service::protected_objects(&plan.manifest, &policy);
    let config = AdminConfig::new(
        Duration::from_secs(u64::from(provision::configs::ADMIN_TICKET_AGE_MAX_SECS)),
        provision::configs::ADMIN_QUORUM,
        realm(),
        nc,
        plan.node_id,
        protected,
    )
    .unwrap();
    let mut admin = DirectoryAdmin::new(config, &schema, FixtureRandom::default()).unwrap();
    let now = fixture_at();
    // The fixture runs the PEP without dird or keyd: the verified ticket's
    // facts are injected, its operation binding (R2) a made-up digest that
    // every fixture request carries — what keyd would have verified.
    let fixture_digest = keyd::OperationDigest::new([0xF1; 32]);
    let requester = VerifiedTicket {
        crealm: realm(),
        cname: principal(ALICE),
        authtime: KerberosTime::new(2026, 11, 13, 9, 29, 50).unwrap(),
        bound_operation: Some(fixture_digest),
    };
    let mut next_id = 0u64;
    let mut run = |operation: PepOperation| -> PepReply {
        next_id += 1;
        let request = PepRequest {
            operation_id: next_id,
            operation,
            operation_digest: fixture_digest,
            requester: requester.clone(),
            approvals: Vec::new(),
        };
        let mut txn = store.begin_write().unwrap();
        let view = ctx.view(&store, &tiers).unwrap();
        let prepared = admin
            .prepare(&request, &view, &snapshot, &now)
            .unwrap_or_else(|r| panic!("fixture refused: {:?}", r.event()));
        drop(view);
        let applied = admin
            .apply(acknowledged(prepared), &mut txn, &now)
            .unwrap_or_else(|r| panic!("fixture not applied: {:?}", r.event()));
        txn.commit().unwrap();
        applied.reply().clone()
    };
    let workstations = plan.object(ObjectRole::WorkstationsOu).unwrap().guid;
    let guid = match run(PepOperation::CreateComputer(CreateComputer {
        parent: workstations,
        name: WORKSTATION.into(),
        dns_host_name: format!("{WORKSTATION}.example.org"),
        spn: None,
    })) {
        PepReply::Created { guid, .. } => guid,
        other => panic!("{other:?}"),
    };
    run(PepOperation::AddMember(Membership {
        group: plan.object(ObjectRole::BootstrapGroup).unwrap().guid,
        member: guid,
    }));
    let (keys, salt) = match run(PepOperation::BeginPasswordSet { target: guid }) {
        PepReply::PasswordSet(reply) => (reply.keys, reply.salt.as_str().to_owned()),
        other => panic!("{other:?}"),
    };
    run(PepOperation::SetEnabled(SetEnabled {
        target: guid,
        enabled: true,
    }));
    Workstation { guid, keys, salt }
}

// ---------------------------------------------------------------------------
// The world.
// ---------------------------------------------------------------------------

/// A client of the run who holds an admin-service ticket.
pub struct Persona {
    pub sam: String,
    pub ticket: ServiceTicket,
}

/// The whole deployment of one test (module documentation).
pub struct World {
    /// The provisioned deployment: files the daemons and tools read through
    /// crates/protected-file and the sockets, in a scratch directory the
    /// walk from `/` accepts and whose paths are valid configuration paths
    /// (crates/test-scratch; Q-480). Socket paths under it stay short.
    pub dir: ScratchDir,
    pub uid: u32,
    pub input: DomainInput,
    pub plan: Plan,
    /// The manifest as installed (read back through provision's root-file
    /// reader, owner = the test uid).
    pub manifest: Manifest,
    /// keyd's second socket — the test uid as Directory (admind's
    /// `set_secret`, first-admin-secret, the workstation's `set_secret`);
    /// not a provisioned path (docs/questions/Q-430, Q-453).
    pub aux_keyd_socket: PathBuf,
    /// keyd's third socket — in the provisioning phase the test uid as
    /// Ldap, to register the workstation's decision as dird would (task
    /// A15a, A-102); in the admin phase the test uid as Admin, keyadm's role
    /// on the keyd dird registers its decisions in (A-102: keyadm runs them
    /// by id); not a provisioned path.
    pub grant_keyd_socket: PathBuf,
    pub workstation: Workstation,
    pub tls: TestPki,
    /// The world time (module documentation, "Time").
    pub now: KerberosTime,
    offset: i64,
    pub clock: SimClock,
    /// The key sets between keyd lifetimes (module `custody`).
    pub custody: Custody,
    pub keyd: Option<KeydRun>,
    pub auditd: Option<auditd_support::Server>,
    pub dird: Option<DirdRun>,
    pub kdcd: Option<Kdcd>,
    pub front: Option<Front>,
    pub admind: Option<AdmindRun>,
    /// Every line the tools printed (keyadm's and provision's reports) —
    /// searched for passwords.
    pub captured: Vec<String>,
    counter: u32,
}

impl World {
    /// `provision domain` into a fresh 0700 directory and the test-only
    /// workstation fixture; nothing runs yet. `None` as root (uid 0 is never
    /// mapped — docs/50 R50-3).
    pub fn provisioned() -> Option<World> {
        let dir = ScratchDir::new("e2e-world").expect("the scratch directory");
        let uid = dir.uid().expect("the scratch directory's owner");
        if skip_as_root(uid) {
            return None;
        }
        for sub in ["etc", "var"] {
            std::fs::DirBuilder::new()
                .mode(0o755)
                .create(dir.join(sub))
                .unwrap();
        }
        let input = domain_input(&dir, uid);
        let (plan, _installed) = provision::provision_domain(
            &input,
            provisioned_at(),
            &mut CountingRandom::default(),
            &mut Recorder::new(uid),
            &mut HaltAt::never(),
        )
        .expect("provision domain");
        let manifest =
            first_admin::root_files::read_manifest(input.paths.manifest.as_path(), uid).unwrap();
        assert_eq!(manifest, plan.manifest, "the installed manifest");
        // Each socket in its own directory (docs/50 §3.1), 0700 here: the
        // daemons' privileged set-up would create them as root.
        let aux_keyd_socket = dir.join("r/x/k.sock");
        let grant_keyd_socket = dir.join("r/y/k.sock");
        for socket in [
            input.paths.keyd_socket.as_path(),
            input.paths.dird_kdc_socket.as_path(),
            input.paths.dird_ldap_socket.as_path(),
            input.paths.dird_admin_socket.as_path(),
            input.paths.audit_socket.as_path(),
            input.paths.admin_socket.as_path(),
            aux_keyd_socket.as_path(),
            grant_keyd_socket.as_path(),
        ] {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(socket.parent().unwrap())
                .unwrap();
        }
        let workstation = workstation_fixture(&plan, &input, uid);
        let now = common::now();
        Some(World {
            dir,
            uid,
            input,
            plan,
            manifest,
            aux_keyd_socket,
            grant_keyd_socket,
            workstation,
            tls: test_pki(),
            now,
            offset: 0,
            clock: SimClock::at(now),
            custody: Custody::new(),
            keyd: None,
            auditd: None,
            dird: None,
            kdcd: None,
            front: None,
            admind: None,
            captured: Vec::new(),
            counter: 1000,
        })
    }

    /// A fresh number (nonces, cusecs, armor counters — RFC 4120 §3.2.3:
    /// no authenticator is used twice).
    pub fn fresh(&mut self) -> u32 {
        self.counter += 1;
        self.counter
    }

    /// Move the world time `secs` forward (every clock follows).
    pub fn advance(&mut self, secs: i64) {
        self.offset += secs;
        self.now = common::at(self.offset);
        self.clock.set(self.now);
        if let Some(run) = &self.keyd {
            run.clock.set(self.now);
        }
    }

    fn read(&self, path: &FilePath) -> Vec<u8> {
        std::fs::read(path.as_path()).unwrap()
    }

    // ---- auditd -----------------------------------------------------------

    /// auditd on the produced socket and log, the one test uid mapped to one
    /// source label (module documentation, "Identity"); its run-as account
    /// and frame timeout are the produced file's.
    pub fn start_auditd(&mut self) {
        assert!(self.auditd.is_none());
        let produced = AuditdSettings::parse(&self.read(&self.input.paths.auditd_config)).unwrap();
        let text = format!(
            "run_as_uid = {}\nrun_as_gid = {}\naudit_socket = {}\naudit_log_path = {}\n\
             uid_sources = {}:{}\nframe_timeout = {}s\n",
            produced.run_as().uid(),
            produced.run_as().gid(),
            produced.audit_socket().as_path().display(),
            produced.audit_log_path().as_path().display(),
            self.uid,
            crate::support::AUDIT_SOURCE_NAME,
            produced.frame_timeout().as_secs(),
        );
        let settings = AuditdSettings::parse(text.as_bytes()).unwrap();
        let config = ListenerConfig {
            frame_timeout: settings.frame_timeout(),
            // Six senders share the one uid (keyd ×2, dird, kdc, ldap-front,
            // admind), each with the daemon's quota under its own uid in
            // production (Q-310 item 3).
            max_connections_per_source: 8 * audit_daemon::listener::MAX_CONNECTIONS_PER_SOURCE,
            binding: single_label_binding,
        };
        self.auditd = Some(auditd_support::Server::start(&settings, config, 64, true));
    }

    pub fn stop_auditd(&mut self) {
        let server = self.auditd.take().expect("auditd runs");
        if let Some(writer) = server.stop() {
            writer.expect("auditd's writer ended cleanly");
        }
    }

    // ---- keyd -------------------------------------------------------------

    /// keyd's parameters from the produced keyd file, on the produced
    /// socket with the test uid mapped to `role`, plus `extra` sockets of the
    /// same keyd with the test uid mapped to their roles (tests only,
    /// docs/questions/Q-453).
    fn keyd_params(&self, role: Role, extra: &[(PathBuf, Role)]) -> keyd_daemon::DaemonParams {
        let settings = KeydSettings::parse(&self.read(&self.input.paths.keyd_config)).unwrap();
        assert_eq!(settings.realm(), REALM);
        let mut params = keyd_daemon::DaemonParams::from_settings(&settings).unwrap();
        assert_eq!(params.keyd_socket, self.input.paths.keyd_socket.as_path());
        assert!(params.extra_listeners.is_empty(), "never from the file");
        params.callers = CallerMap::new(&[(self.uid, role)]).unwrap();
        params.extra_listeners = extra
            .iter()
            .map(|(socket, role)| ExtraListener {
                socket: socket.clone(),
                callers: CallerMap::new(&[(self.uid, *role)]).unwrap(),
            })
            .collect();
        params.audit.uid = self.uid;
        params.intent_ack_budget = intent_ack_budget();
        params
    }

    /// One keyd lifetime for `phase` on the custody's key sets.
    fn start_keyd(&self, phase: KeydPhase) -> KeydRun {
        let (role, extra) = match phase {
            KeydPhase::Provisioning => (
                Role::Admin,
                vec![
                    (self.aux_keyd_socket.clone(), Role::Directory),
                    (self.grant_keyd_socket.clone(), Role::Ldap),
                ],
            ),
            KeydPhase::Kerberos => (Role::Kdc, Vec::new()),
            KeydPhase::Admin => (
                Role::Ldap,
                vec![
                    (self.aux_keyd_socket.clone(), Role::Directory),
                    (self.grant_keyd_socket.clone(), Role::Admin),
                ],
            ),
        };
        let params = self.keyd_params(role, &extra);
        let store = self.custody.lend();
        let clock = TestClock::at(common::keyd_started());
        let daemon = keyd_support::Daemon::start(params, clock.clone(), move |started| {
            Keyd::new(
                KeydConfig::new(realm()),
                store,
                RecordBuffer::new(),
                started,
            )
        })
        .expect("keyd starts");
        clock.set(self.now);
        KeydRun {
            daemon,
            clock,
            phase,
        }
    }

    /// Stop keyd and bring its key sets home.
    pub fn stop_keyds(&mut self) {
        if let Some(run) = self.keyd.take() {
            run.daemon.stop().expect("keyd stopped cleanly");
        }
        assert!(
            eventually(LONG, || self.custody.is_home()),
            "keyd handed its key sets back"
        );
    }

    /// Restart keyd for `phase` (module documentation) — unless it already
    /// runs in the provisioning phase (the provisioning keyd serves the ceremony, the
    /// first administrators' secrets and the workstation's in one lifetime:
    /// their grants live in its memory).
    pub fn keyd_phase(&mut self, phase: KeydPhase) {
        if phase == KeydPhase::Provisioning && self.keyd.as_ref().map(|k| k.phase) == Some(phase) {
            return;
        }
        self.stop_keyds();
        self.keyd = Some(self.start_keyd(phase));
    }

    /// `keyadm ceremony` (library, over keyd's socket, Role::Admin):
    /// `create_key` for krbtgt and the two service objects of the manifest
    /// (docs/51 §4.3 step 11), then the first administrators' initial-secret
    /// grants (task A15a; their salts from the manifest — A-102, N4), then
    /// the seal (A-102, docs/52 R3). keyadm's file names keyd's socket.
    pub fn ceremony(&mut self) -> keyadm::ceremony::CeremonyReport {
        self.keyd_phase(KeydPhase::Provisioning);
        let settings = KeyadmSettings::parse(&self.read(&self.input.paths.keyadm_config)).unwrap();
        assert_eq!(
            settings.keyd().socket().as_path(),
            self.input.paths.keyd_socket.as_path()
        );
        let mut client =
            key_state_client(settings.keyd().socket().as_path(), self.uid, Role::Admin);
        let report = keyadm::ceremony::run(&mut client, &self.manifest);
        self.captured
            .extend(keyadm::report::render(&report, &self.manifest));
        report
    }

    /// The first administrators' password files (docs/51 §4.4 source (b):
    /// a regular file of the running uid, mode 0600, one line).
    fn password_files(&self) -> Vec<PasswordFileArg> {
        [(ALICE, ALICE_PASSWORD), (BOB, BOB_PASSWORD)]
            .into_iter()
            .map(|(sam, password)| {
                let path = self.dir.join(format!("etc/{sam}.pw"));
                std::fs::write(&path, format!("{password}\n")).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
                PasswordFileArg {
                    sam: sam.to_owned(),
                    path: FilePath::parse(path.to_str().unwrap()).unwrap(),
                }
            })
            .collect()
    }

    /// `provision first-admin-secret` (library, Role::Directory on the
    /// provisioning keyd's second socket — the keyd that holds the
    /// ceremony's grants): admind's file and the manifest read through its
    /// root-file reader (owner = the test uid), the password files, the drop
    /// recorded; then the files are removed (the operator's step). Returns
    /// the report and the recorded drop.
    pub fn first_admin_secret(&mut self) -> (first_admin::report::SecretReport, Vec<(u32, u32)>) {
        self.keyd_phase(KeydPhase::Provisioning);
        let request = FirstAdminSecret {
            manifest: self.input.paths.manifest.clone(),
            admind_config: self.input.paths.admind_config.clone(),
            password_files: self.password_files(),
        };
        let mut drop = RecordedDrop::default();
        let mut keyd = TestKeyd {
            socket: self.aux_keyd_socket.clone(),
            produced: self.input.paths.keyd_socket.as_path().to_path_buf(),
            uid: self.uid,
        };
        let mut env = Environment {
            privilege: &mut drop,
            terminal: &mut NoTerminal,
            keyd: &mut keyd,
            root_uid: self.uid,
            running_uid: self.uid,
        };
        let report = first_admin::run(&request, &mut env).expect("first-admin-secret ran");
        self.captured.extend(first_admin::report::render(&report));
        for file in &request.password_files {
            std::fs::remove_file(file.path.as_path()).unwrap();
        }
        (report, drop.0)
    }

    /// The test-only workstation's key sets through keyd `set_secret`
    /// (Role::Directory; docs/47 §9.2 step 3), the targets and salt its
    /// `BeginPasswordSet` named — after the `SetSecret` decision dird would
    /// have registered for them (Role::Ldap; task A15a, A-102 — the salt
    /// bound too, N4), which the test registers here. (The ceremony sealed
    /// keyd; a decision dird registers is exactly what still works.)
    pub fn workstation_secret(&mut self) -> Vec<Kvno> {
        assert_eq!(
            self.keyd.as_ref().map(|k| k.phase),
            Some(KeydPhase::Provisioning)
        );
        let mut ldap = key_state_client(&self.grant_keyd_socket, self.uid, Role::Ldap);
        // The fixture is a computer (`CreateComputer`, no SPN: one key set).
        let kind = keyd::AccountKind::Computer;
        let targets: Vec<keyd::SetSecretTarget> = self
            .workstation
            .keys
            .iter()
            .map(|k| keyd::SetSecretTarget {
                handle: k.handle,
                binding: k.binding.clone(),
                salt: self.workstation.salt.clone(),
            })
            .collect();
        ldap.register_decision(
            keyd::DecisionId::new(1),
            &keyd::DecidedOperation::SetSecret { kind, targets },
            &[],
            keyd::MAX_SET_SECRET_GRANT_SECS,
        )
        .expect("keyd answered the workstation's decision")
        .expect("the workstation's decision");
        let mut client = key_state_client(&self.aux_keyd_socket, self.uid, Role::Directory);
        let mut kvnos = Vec::new();
        for target in self.workstation.keys.clone() {
            let call = Call::SetSecret {
                handle: target.handle,
                binding: target.binding.clone(),
                password: ipc_keyd::Password::new(Zeroizing::new(WORKSTATION_PASSWORD.to_owned())),
                salt: self.workstation.salt.clone(),
            };
            match client.call_with_fate(&call) {
                Ok(Answer::SetSecret(Ok(kvno))) => kvnos.push(kvno),
                other => panic!("the workstation's set_secret: {other:?}"),
            }
        }
        kvnos
    }

    // ---- dird, kdc, ldap-front, admind --------------------------------------

    /// dird with its admin service: the serving and admin parameters from
    /// the produced dird file (`directory_daemon::startup::{params,
    /// admin_params}`), the manifest it names, the produced integrity key,
    /// policy and database; injected: the peers' uids (the test uid), the
    /// clock, and keyd's verifier through the host's connector (Role::Ldap,
    /// the produced `keyd_socket`).
    pub fn start_dird(&mut self) {
        let paths = &self.input.paths;
        let settings = DirdSettings::parse(&self.read(&paths.dird_config)).unwrap();
        let mut params = directory_daemon::startup::params(&settings).unwrap();
        params.kdc_uid = self.uid;
        params.ldap_front_uid = self.uid;
        params.audit.uid = self.uid;
        params.clock = SharedClock::new(self.clock.clone());
        let manifest_path = settings
            .admin_service()
            .unwrap()
            .provision_manifest()
            .as_path()
            .to_path_buf();
        assert_eq!(manifest_path, paths.manifest.as_path());
        let manifest = first_admin::root_files::read_manifest(&manifest_path, self.uid).unwrap();
        let mut admin = directory_daemon::startup::admin_params(&settings, Some(manifest))
            .unwrap()
            .expect("the admin channel is configured");
        admin.admind_uid = self.uid;
        // dird's bounded decision-ack deadline at its ceiling (A-95 / F7).
        admin.ack_deadline =
            directory_daemon::admin_service::DecisionAckDeadline::new(DECISION_ACK_WAIT)
                .expect("within dird's ceiling");
        let keyd_socket = settings.keyd().unwrap().socket().as_path().to_path_buf();
        assert_eq!(keyd_socket, paths.keyd_socket.as_path());
        let uid = self.uid;
        let factory: VerifierFactory = Arc::new(move || {
            // Task R9: keyd's uid, the role Ldap and the realm, expected of
            // every keyd connection.
            let verifier: Box<dyn TicketVerifier> = Box::new(
                KeydTicketVerifier::new(
                    connector::keyd(&keyd_socket),
                    uid,
                    realm(),
                    ipc_keyd::DEFAULT_DEADLINE,
                )
                .ok()?,
            );
            Some(verifier)
        });
        admin.keyd = Some(factory);
        assert_eq!(
            settings.policy_store_path().as_path(),
            paths.policy.as_path()
        );
        assert_eq!(
            settings.integrity_key_path().as_path(),
            paths.integrity_key.as_path()
        );
        assert_eq!(settings.database_path().as_path(), paths.database.as_path());
        let policy =
            directory_daemon::startup::read_policy(settings.policy_store_path().as_path(), uid)
                .unwrap();
        let key = directory_daemon::startup::read_integrity_key(
            settings.integrity_key_path().as_path(),
            uid,
        )
        .unwrap();
        let source = StoreSource::File {
            path: settings.database_path().as_path().to_path_buf(),
            key,
            owner_uid: uid,
        };
        self.dird = Some(DirdRun::start(params, admin, source, policy).expect("dird starts"));
    }

    /// The kdc: its produced file read through the kdc's own reader (owner =
    /// the test uid) — its sockets checked against the produced layout, its
    /// policy file loaded through the kdc's own loader — and the tier-2
    /// parameters (crates/kdc-daemon support `kdc_params`) on the produced
    /// audit socket; loopback port 0 instead of the produced listen address.
    pub fn start_kdc(&mut self) {
        let paths = &self.input.paths;
        let settings =
            kdc_daemon::startup::read_settings(paths.kdc_config.as_path(), self.uid).unwrap();
        assert_eq!(
            settings.keyd().socket().as_path(),
            paths.keyd_socket.as_path()
        );
        assert_eq!(
            settings.dird().socket().as_path(),
            paths.dird_kdc_socket.as_path()
        );
        assert_eq!(
            settings.audit().socket().as_path(),
            paths.audit_socket.as_path()
        );
        let policy =
            kdc_daemon::startup::read_policy(settings.policy_store_path().as_path(), self.uid)
                .unwrap();
        let params = kdcd::kdc_params(paths.audit_socket.as_path(), self.uid);
        self.kdcd = Some(
            Kdcd::start(
                params,
                policy,
                paths.keyd_socket.as_path(),
                paths.dird_kdc_socket.as_path(),
                self.clock.clone(),
            )
            .expect("the kdc starts"),
        );
    }

    /// ldap-front on the produced dird LDAP and audit sockets, the per-run
    /// test certificate (support::tls) instead of the operator's files.
    pub fn start_front(&mut self) {
        let settings =
            LdapFrontSettings::parse(&self.read(&self.input.paths.ldap_front_config)).unwrap();
        let params = FrontParams {
            dird: Endpoint {
                socket: settings.dird().socket().as_path().to_path_buf(),
                uid: self.uid,
            },
            audit: Endpoint {
                socket: settings.audit().socket().as_path().to_path_buf(),
                uid: self.uid,
            },
            timeouts: front_timeouts(),
            limits: ConnectionLimits::DEFAULT,
            // The produced zone table (docs/52 R14), as provisioned.
            internal_networks: settings.internal_networks().to_vec(),
        };
        self.front = Some(Front::start(params, server_config(&self.tls)).expect("ldap-front"));
    }

    /// admind: its produced file (`admin.sock`, the dird and audit sockets,
    /// the frame timeout, `min_password_length`, keyd's deadline); injected:
    /// the servers' uids (the test uid) and keyd's endpoint — admind's own
    /// keyd of the admin phases (docs/questions/Q-430).
    pub fn start_admind(&mut self) {
        // provision's root-file reader (no link followed, owner checked —
        // the test uid here, root in production).
        let settings = first_admin::root_files::read_admind_settings(
            self.input.paths.admind_config.as_path(),
            self.uid,
        )
        .unwrap();
        assert_eq!(
            settings.keyd().socket().as_path(),
            self.input.paths.keyd_socket.as_path()
        );
        let dird: Box<dyn admin_daemon::DirdLink> = Box::new(
            ipc_dird_admin::AdminClient::new(
                dird_admin_connector::new(settings.dird().socket().as_path()),
                self.uid,
                ipc_dird_admin::DEFAULT_DEADLINE,
            )
            .unwrap(),
        );
        let keyd: Box<dyn admin_daemon::KeydLink> = Box::new(key_state_client(
            &self.aux_keyd_socket,
            self.uid,
            Role::Directory,
        ));
        let params = admin_daemon::DaemonParams {
            admin_socket: settings.admin_socket().as_path().to_path_buf(),
            audit: admin_daemon::AuditEndpoint {
                socket: settings.audit().socket().as_path().to_path_buf(),
                uid: self.uid,
            },
            frame_timeout: settings.frame_timeout(),
            min_password_length: settings.min_password_length(),
            dird,
            keyd,
            limits: admin_daemon::Limits::DEFAULT,
            queue_capacity: admin_daemon::WORKER_QUEUE_CAPACITY,
            audit_window: WindowConfig::DEFAULT,
        };
        self.admind = Some(AdmindRun::start(params).expect("admind starts"));
    }

    pub fn stop_admind(&mut self) {
        let unacknowledged = self.admind.take().expect("admind runs").stop().unwrap();
        assert_eq!(unacknowledged, 0, "admind delivered every audit event");
    }

    /// Stop everything in the reverse of the start order (each sender
    /// flushes its window, bounded), auditd last.
    pub fn stop_all(&mut self) {
        if self.admind.is_some() {
            self.stop_admind();
        }
        if let Some(front) = self.front.take() {
            front.stop().expect("ldap-front stopped cleanly");
        }
        if let Some(kdcd) = self.kdcd.take() {
            kdcd.stop().expect("the kdc stopped cleanly");
        }
        if let Some(dird) = self.dird.take() {
            dird.stop().expect("dird stopped cleanly");
        }
        if self.keyd.is_some() {
            self.stop_keyds();
        }
        if self.auditd.is_some() {
            self.stop_auditd();
        }
    }

    /// Everything up to the first administrators' login (module
    /// documentation, steps 1-3), with keyd left in its Kdc role.
    pub fn started() -> Option<World> {
        let mut world = World::provisioned()?;
        world.start_auditd();
        let ceremony = world.ceremony();
        assert!(
            ceremony.is_complete(),
            "keyadm ceremony: {:?}",
            world.captured
        );
        let (secrets, _) = world.first_admin_secret();
        assert!(secrets.is_complete(), "first-admin-secret");
        world.workstation_secret();
        world.keyd_phase(KeydPhase::Kerberos);
        world.start_dird();
        world.start_kdc();
        world.start_front();
        world.start_admind();
        Some(world)
    }

    // ---- the Kerberos client ------------------------------------------------

    /// One request to the kdc over TCP (RFC 4120 §7.2.2).
    pub fn kdc(&self, request: &[u8]) -> Vec<u8> {
        let kdc = self.kdcd.as_ref().expect("the kdc runs").tcp;
        kdcd::message(kdcd::tcp_send(kdc, request))
    }

    /// The workstation's TGT through the unarmored bootstrap AS (P-10,
    /// docs/48 §7.3): PA-ENC-TIMESTAMP with its password key (RFC 3962 §4,
    /// the salt `BeginPasswordSet` named) at the world time.
    /// Spec: RFC 4120 §3.1, §3.1.5, §5.2.7.2.
    pub fn bootstrap_workstation(&mut self) -> Tgt {
        let key =
            common::password_key(common::AES256, WORKSTATION_PASSWORD, &self.workstation.salt);
        let spec = AsReqSpec {
            nonce: self.fresh(),
            till: common::till_max(),
            ..AsReqSpec::for_client(realm(), principal(WORKSTATION_SAM))
        }
        .with_timestamp_at(&key, self.now);
        let reply = self.kdc(&spec.encode());
        let tgt = common::open_as_rep(&reply, &key);
        assert_eq!(
            tgt.rep.0.cname,
            principal(WORKSTATION_SAM),
            "RFC 4120 §3.1.5"
        );
        tgt
    }

    /// An armored AS for `sam` with `password` (RFC 6113 §5.4.1.1 armor on
    /// `armor_tgt`, the encrypted challenge of §5.4.6), at the world time:
    /// the TGT, or the armored KRB-ERROR opened (§5.4.4).
    pub fn armored_as(
        &mut self,
        armor_tgt: &Tgt,
        sam: &str,
        password: &str,
    ) -> Result<Tgt, Box<FastError>> {
        let key = common::password_key(common::AES256, password, &user_salt(sam));
        let n = self.fresh();
        let armor = Armor::new(armor_tgt, self.now, n);
        let spec = AsReqSpec {
            nonce: self.fresh(),
            ..AsReqSpec::for_client(realm(), principal(sam))
        }
        .with_challenge(&key);
        let reply = self.kdc(&spec.encode_armored(&armor, self.now));
        if AsRep::decode(&reply).is_ok() {
            let tgt = common::open_fast_as_rep(&reply, &armor.key, &key);
            assert_eq!(tgt.rep.0.cname, principal(sam), "RFC 4120 §3.1.5");
            Ok(tgt)
        } else {
            Err(Box::new(common::open_fast_error(
                kdc::KdcReply::Send(reply),
                &armor.key,
            )))
        }
    }

    /// An armored TGS (implicit armor, RFC 6113 §5.4.2) by the client of
    /// `tgt` for `sname`, at the world time; the service ticket it got.
    /// Spec: RFC 4120 §3.3, §3.3.1, §5.5.1.
    pub fn service_ticket(&mut self, tgt: &Tgt, sname: &PrincipalName) -> ServiceTicket {
        let spec = TgsReqSpec {
            sname: Some(sname.clone()),
            nonce: self.fresh(),
            ctime: self.now,
            cusec: self.fresh(),
            ..TgsReqSpec::service()
        }
        .for_client_of(tgt);
        let (request, _) = spec.encode(tgt);
        let reply = self.kdc(&request);
        let (rep, part) = common::open_tgs_rep(&reply, tgt, &spec);
        assert_eq!(&part.0.sname, sname, "RFC 4120 §3.3.4");
        assert_eq!(rep.0.cname, tgt.rep.0.cname);
        common::service_ticket(&rep, &part)
    }

    /// The admin service's name (the manifest's binding, docs/51 §4.3
    /// step 8; A-73).
    pub fn admin_service(&self) -> PrincipalName {
        self.manifest.admin_service().binding.name.clone()
    }

    /// The LDAP service's name.
    pub fn ldap_service(&self) -> PrincipalName {
        self.manifest.ldap_service().binding.name.clone()
    }

    /// A Persona: the admin-service ticket of the client of `tgt`.
    pub fn persona(&mut self, sam: &str, tgt: &Tgt) -> Persona {
        let sname = self.admin_service();
        Persona {
            sam: sam.to_owned(),
            ticket: self.service_ticket(tgt, &sname),
        }
    }

    // ---- the admin plane ------------------------------------------------------

    /// A fresh AP-REQ of `who` for the admin service at the world time
    /// (RFC 4120 §3.2.2), bound to the dird request `operation`: the
    /// Authenticator's `cksum` is the session key's MIC (key usage 10) over
    /// its operation digest (RFC 4120 §5.5.1, §7.5.1; R2, docs/52 §5).
    pub fn ap_req(&mut self, who: &Persona, operation: &ipc_dird_admin::Operation) -> Vec<u8> {
        let cusec = self.fresh();
        let digest = ipc_dird_admin::operation_digest(operation).unwrap();
        who.ticket.ap_req_bound(self.now, cusec, digest.as_bytes())
    }

    /// The `auth` field of `operation`: `requester`'s AP-REQ and one per
    /// approver (docs/51 §7.2), every one bound to `operation` (R2).
    pub fn auth(
        &mut self,
        requester: &Persona,
        approvers: &[&Persona],
        operation: &ipc_dird_admin::Operation,
    ) -> ipc_dird_admin::Auth {
        ipc_dird_admin::Auth {
            requester: self.ap_req(requester, operation),
            approvals: approvers
                .iter()
                .map(|a| self.ap_req(a, operation))
                .collect(),
        }
    }

    /// One request on a new `admin.sock` connection.
    pub fn admin(&self, request: &ipc_admin::Request) -> Got {
        let mut conn = AdminConn::connect(self.input.paths.admin_socket.as_path()).unwrap();
        conn.call(request)
    }

    /// A forwarded operation by `requester` with `approvers`.
    pub fn forward(
        &mut self,
        requester: &Persona,
        approvers: &[&Persona],
        operation: ipc_dird_admin::Operation,
    ) -> Got {
        let auth = self.auth(requester, approvers, &operation);
        self.admin(&ipc_admin::Request::Forward { auth, operation })
    }

    /// `SetPassword` by `requester` (two AP-REQs — A-94, docs/questions/
    /// Q-400 — plus one per approver).
    pub fn set_password(
        &mut self,
        requester: &Persona,
        approvers: &[&Persona],
        target: Guid,
        password: &str,
    ) -> Got {
        // R2 (docs/51 §7.6; docs/52 §5 items 1, 5): `auth` is bound to the
        // `BeginPasswordSet {target}` admind sends dird, `completion` to its
        // `CompletePasswordSet {target, …}` (whose digest covers the target
        // only — the outcome and kvnos are admind's report).
        let auth = self.auth(
            requester,
            approvers,
            &ipc_dird_admin::Operation::BeginPasswordSet { target },
        );
        let completion = self.ap_req(
            requester,
            &ipc_dird_admin::Operation::CompletePasswordSet {
                target,
                outcome: ipc_dird_admin::PasswordSetOutcome::Completed,
                kvnos: Vec::new(),
            },
        );
        self.admin(&ipc_admin::Request::SetPassword(ipc_admin::SetPassword {
            auth,
            completion,
            target,
            password: ipc_admin::Password::new(Zeroizing::new(password.to_owned())),
        }))
    }

    /// `attempt` until it is answered otherwise than `Unavailable` (bounded
    /// by `LONG`, one attempt per 500 ms): `Unavailable` means the request
    /// was not carried out (ipc-admin `RefusalStatus::Unavailable`), so
    /// repeating it — with fresh AP-REQs — is safe. For the seconds after a
    /// dependency came back (docs/50 §3.7, §8.1).
    pub fn settled(&mut self, mut attempt: impl FnMut(&mut World) -> Got) -> Got {
        let start = Instant::now();
        loop {
            let got = attempt(self);
            if got
                != Got::Reply(ipc_admin::Reply::Refused(
                    ipc_admin::RefusalStatus::Unavailable,
                ))
                || start.elapsed() > LONG
            {
                return got;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// The objectGUID of a provisioned object.
    pub fn guid(&self, role: ObjectRole) -> Guid {
        self.plan.object(role).unwrap().guid
    }

    // ---- the record of the run ------------------------------------------------

    /// Stop everything, verify auditd's whole log with crates/audit-log's
    /// verifier (support `verified_log`) and decode every daemon record —
    /// each from the one test uid, under the one label (docs/50 §3.2) — with
    /// its sequence number.
    ///
    /// A sender that lost auditd's acknowledgement (auditd stopped between
    /// persisting a batch and the sender reading the `Ack`) resends it on its
    /// next connection: "an event can be logged twice, never zero times",
    /// and the record's `source_seq` lets a reader spot the duplicate
    /// (docs/questions/Q-252 item 7, Q-265). The second copy — the same
    /// `source_seq` and the same payload — is folded here; the count of
    /// folded records is returned with the events.
    pub fn finish_counting_duplicates(&mut self) -> (Vec<(u64, EventBody)>, usize) {
        self.stop_all();
        let (head, records) =
            verified_log(self.input.paths.audit_log.as_path()).expect("the audit log verifies");
        assert_eq!(head.seq, records.len() as u64, "one chain from genesis");
        let mut seen: Vec<(u64, &[u8])> = Vec::new();
        let mut duplicates = 0usize;
        let mut events = Vec::new();
        for record in records
            .iter()
            .filter(|record| record.source != audit_log::Source::Auditd)
        {
            assert_eq!(record.source_uid, self.uid, "the sender's peer uid");
            assert_eq!(
                holds_a_password(&record.payload),
                None,
                "no password in an audit record"
            );
            let key = (record.source_seq, record.payload.as_slice());
            if seen.contains(&key) {
                duplicates += 1;
                continue;
            }
            seen.push(key);
            events.push((
                record.seq,
                decode_event(&record.payload).expect("every payload decodes"),
            ));
        }
        (events, duplicates)
    }

    /// [`World::finish_counting_duplicates`] for a run in which auditd never
    /// stopped: no record may be a duplicate.
    pub fn finish(&mut self) -> Vec<(u64, EventBody)> {
        let (events, duplicates) = self.finish_counting_duplicates();
        assert_eq!(duplicates, 0, "no resend without a lost acknowledgement");
        events
    }

    /// Every file the run left under its directory, with its octets.
    pub fn files(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        collect_files(self.dir.path(), &mut out);
        out
    }
}

impl Drop for World {
    /// Stop the daemons (reverse start order) before the directory goes.
    fn drop(&mut self) {
        drop(self.admind.take());
        drop(self.front.take());
        drop(self.kdcd.take());
        drop(self.dird.take());
        drop(self.keyd.take());
        drop(self.auditd.take());
    }
}

fn collect_files(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            collect_files(&path, out);
        } else if kind.is_file() {
            if let Ok(octets) = std::fs::read(&path) {
                out.push((path, octets));
            }
        }
    }
}

/// The input of `provision domain` under `dir` (obviously fake accounts;
/// the test uid as dird's account — the produced database must be its file,
/// docs/50 §6.4): realm EXAMPLE.ORG, two first administrators (P-22), the
/// loopback network as the internal one, short socket paths (a Unix socket
/// path is bounded in length).
fn domain_input(dir: &ScratchDir, uid: u32) -> DomainInput {
    let path = |rest: &str| FilePath::parse(dir.join(rest).to_str().unwrap()).unwrap();
    let account = |n: u32| Account { uid: n, gid: n };
    let fake = [61001, 61003, 61004, 61005, 61006, 61007, 61010];
    assert!(
        !fake.contains(&uid),
        "the test uid collides with a fake account"
    );
    DomainInput {
        realm: REALM.to_owned(),
        naming_context: vec!["example".to_owned(), "org".to_owned()],
        dc_fqdn: DC_FQDN.to_owned(),
        accounts: Accounts {
            keyd: account(61001),
            dird: account(uid),
            kdc: account(61003),
            ldap_front: account(61004),
            auditd: account(61005),
            admind: account(61006),
            keyadm_uid: 61007,
            admin_socket_group: 61010,
        },
        paths: Paths {
            staging: path("etc/staging"),
            database: path("var/directory.redb"),
            integrity_key: path("etc/integrity.key"),
            policy: path("etc/policy.store"),
            manifest: path("etc/provision.manifest"),
            audit_log: path("var/audit.log"),
            keyd_config: path("etc/keyd.conf"),
            dird_config: path("etc/dird.conf"),
            kdc_config: path("etc/kdc.conf"),
            ldap_front_config: path("etc/ldap-front.conf"),
            auditd_config: path("etc/auditd.conf"),
            admind_config: path("etc/admind.conf"),
            keyadm_config: path("etc/keyadm.conf"),
            keyd_socket: path("r/k/k.sock"),
            dird_kdc_socket: path("r/dk/d.sock"),
            dird_ldap_socket: path("r/dl/l.sock"),
            dird_admin_socket: path("r/da/a.sock"),
            audit_socket: path("r/au/a.sock"),
            admin_socket: path("r/ad/a.sock"),
            tls_certificate: path("etc/dc-cert.der"),
            tls_private_key: path("etc/dc-key.der"),
        },
        network: Network {
            kdc_listen: vec!["127.0.0.1:88".to_owned()],
            ldap_listen: Vec::new(),
            ldaps_listen: vec!["127.0.0.1:636".to_owned()],
            internal_networks: vec!["127.0.0.0/8".to_owned()],
        },
        names: Names {
            tier0_ou: "Tier0".to_owned(),
            workstations_ou: Some("Workstations".to_owned()),
            tier0_group: "tier0-admins".to_owned(),
            bootstrap_group: "machine-bootstrap".to_owned(),
            dc_name: "DC1".to_owned(),
            ldap_service_name: "ldapsvc".to_owned(),
            admin_service_name: "adminsvc".to_owned(),
            first_admins: vec![ALICE.to_owned(), BOB.to_owned()],
        },
    }
}

/// Play auditd for one prepared write (docs/51 §5.7 item 2, A-85; docs/52
/// §3.11 R6): commit its decision event into an `ipc_audit::AuditGate`,
/// acknowledge it as auditd does once it synced it (docs/50 §8.1), and take
/// the proof `apply` requires — the only way to obtain one.
fn acknowledged(
    prepared: directory_admin::Prepared,
) -> ipc_audit::AckedIntent<directory_admin::Prepared> {
    let gate = ipc_audit::AuditGate::new(ipc_audit::WindowConfig::DEFAULT);
    gate.set_reachable(true);
    let slot = gate.reserve().expect("a slot");
    let pending = gate.begin_intent(slot, prepared).expect("committed");
    let batch = gate.next_batch().expect("the decision event is sent");
    gate.acknowledge(&ipc_audit::Ack {
        through_seq: batch.last_seq(),
        head_hash: [0; 32],
    })
    .expect("auditd acknowledges");
    gate.wait_acknowledged(pending, std::time::Instant::now())
        .expect("acknowledged")
}
