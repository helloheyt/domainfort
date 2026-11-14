//! The five real daemons at once (docs/50 §9 tier 2 across all daemons;
//! §10 task P12).
//!
//! # What runs
//!
//! [`Harness::start`] starts, **in the docs/50 §7.5 order**:
//!
//! 1. **auditd** — the real listener and single writer (crates/audit-daemon
//!    `listener::serve`, `writer::run`, through its own tier-2 runner) over a
//!    hash-chained log in the temporary directory;
//! 2. **keyd** — `keyd_daemon::serve` (crates/keyd-daemon's runner): its
//!    `keyd.sock`, uid map, bounded queue, engine thread, own clock and
//!    hold-down, audit gate;
//! 3. **dird** — `directory_daemon::serve` (crates/directory-daemon's runner)
//!    over **its own redb file** opened through `StoreSource::File` (the
//!    file must exist, be owned by dird's account, mode 0600) with the
//!    integrity key **read from a 0400 key file** through dird's own
//!    `startup::read_integrity_key`, and the policy **read from the policy
//!    file** through dird's own `startup::read_policy`;
//! 4. **kdc** — `kdc_daemon::serve` (crates/kdc-daemon's runner) with its UDP
//!    socket and TCP listener on 127.0.0.1 port 0, the **same policy file**
//!    read through the kdc's own `startup::read_policy` (A-68, A-69), keyd
//!    and dird reached over their sockets;
//! 5. **ldap-front** — `ldap_front::serve` with its LDAP and LDAPS listeners
//!    on 127.0.0.1 port 0, the product's TLS configuration serving the DC's
//!    real test certificate through the production loader, verified by the
//!    clients against only the per-run test CA ([`super::tls`]; Q-320,
//!    A-81), dird's LDAP socket.
//!
//! Every daemon talks to the others **only** through those sockets — the
//! channels of docs/50 §3.1: `audit.sock` — one listener of the one auditd
//! per sender (files `a.sock` keyd's, `ad.sock` dird's, `ak.sock` the kdc's,
//! `af.sock` ldap-front's; "Identity" below) — `keyd.sock` (`k.sock`),
//! `dird-kdc.sock` (`d.sock`),
//! `dird-ldap.sock` (`l.sock`) — all in **one unique temporary directory,
//! mode 0700** (crates/keyd-daemon's `TempDir`). Each daemon can be stopped
//! and started again ([`Harness::stop_keyd`], [`Harness::start_keyd`], …);
//! every wait is a deadline poll inside the runners (10-15 s) or
//! [`eventually`] (bounded by [`LONG`]), and each test runs inside
//! [`within`] ([`TEST_BOUND`]).
//!
//! The three defects these tests first met are fixed (task F1, A-82) and
//! the assertions now hold them directly, with no workaround: the first kdc
//! request after keyd or dird is replaced is decided by the new process
//! (the clients check a held connection before reusing it —
//! docs/questions/Q-312); keyd restarted with the kdc's uid in another role
//! is 29 / silence, not 24 (the kdc's keyd client repeats its
//! `DescribeConfig` check on every new connection — Q-311); and dird's stop
//! waits, bounded, for auditd to acknowledge its audit window (Q-313), so
//! the tests stop dird without first waiting for its events.
//!
//! # Identity: one test uid
//!
//! The test process has one uid, and every daemon sees it as its peers'
//! uid. The configuration files cannot express that — crates/config refuses
//! one uid for two roles in a file (docs/50 §2.4, Q-230 item 6) — and that
//! check is **not** weakened: as the daemons' own tier-2 tests do, the
//! harness injects each daemon's **parameters** directly (docs/50 §9: "the
//! uid map is injected with the test's own uid for the role under test"):
//!
//! * keyd: `DaemonParams.callers = CallerMap [(uid, Kdc)]` (dird talks to
//!   keyd only from task L7 on, P-13 — no other role is needed);
//! * dird: `kdc_uid = ldap_front_uid = uid`; the kdc: `keyd_uid = dird_uid
//!   = uid`; ldap-front: `dird.uid = uid`; every daemon: `audit.uid = uid`;
//! * auditd: one writer behind **one listener per sender** (crates/
//!   audit-daemon tier-2 harness `Server::start_many`), each with its own
//!   `uid → source` map from configuration text (crates/config
//!   `AuditdSettings::parse`, every rule kept) naming the one uid as **that
//!   sender** ([`AUDIT_LABELS`]). One uid carries one source per map
//!   (R50-3), and every sender requires its own source on each connection
//!   (task R9b, docs/questions/Q-512, Q-560): so each daemon's audit socket
//!   is its own listener, the production binding table and quota apply
//!   unchanged (`ListenerConfig::from_settings`), and every record carries
//!   its sender's own source, as in production.
//!
//! What a single uid cannot show — distinct peer uids on one audit socket,
//! the production rustix peer-credential connectors on Linux — is the
//! tier-3 test (tests/tier3_distinct_uids.rs, ignored by default;
//! docs/questions/Q-310).
//!
//! # Clocks
//!
//! keyd's clock is a `TestClock` (crates/keyd-daemon): the keyd starts on
//! [`common::keyd_started`] and is moved to [`common::now`], past its
//! hold-down (R50-6, A-62), exactly as the daemons' flow tests do; a restart
//! takes a new clock the test moves across the 2×skew boundary. The kdc's
//! clock is the kdc support's `HeldClock` at `now`; dird's LDAP clock is
//! fixed at `now` (so its replies equal the in-process engine's octet for
//! octet). auditd stamps records with the system clock.
//!
//! # Fixtures (as the existing tests build them)
//!
//! * the directory of the kdc fixtures' identities (crates/directory-daemon
//!   support `Directory::standard`: alice, ws1$, files$, krbtgt, staff) —
//!   written twice, identically: dird's own file and a local reference copy
//!   for the in-process paths (crates/kdc-daemon tests/flow.rs);
//! * keyd's development store (`InMemoryKeyStore` allowing krbtgt — P-17,
//!   development only) with the directory's key sets under the directory's
//!   handles (crates/kdc-daemon support `directory_keyd`);
//! * the shared unsigned development policy file (crates/policy-store,
//!   A-68) with the mandatory-FAST entry (ws1$ as the bootstrap set, P-10),
//!   the Kerberos allow rule of the kdc fixtures, the rootDSE read rule and
//!   the internal anonymous rootDSE grant of the LDAP tests (A-51).
//!
//! Sources: docs/50 §1-§4, §7.5, §8.1, §9; docs/47 §9.1; docs/48 §7; A-51,
//! A-57, A-62, A-66..A-71, P-10, P-17. Every value is made by hand.
#![allow(dead_code, unused_imports)]

use super::auditd as auditd_support;
pub use super::kdcd::dird;
pub use super::kdcd::keyd_support;
use super::kdcd::{self, Handles, HeldClock, Kdcd};
use super::tls::{client_config, server_config, test_pki, TestPki};
use crate::common;
// auditd runs with its product listener configuration (one listener per
// sender since task R9b); the front's client write bound and connection
// bounds are its test seams (docs/52 C18, task R15; feature `test-seams`,
// enabled by the dev-dependencies).
use audit_daemon::listener::ListenerConfig;
use audit_daemon::segments::{list_segments, segment_path};
use audit_log::{verify_log, Anchor, ChainHead, Record, SegmentLimit, SegmentReader};
use config::AuditdSettings;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;
use directory_daemon::policy::DevelopmentPolicy;
use directory_daemon::{SharedClock, StoreSource};
use directory_pip::DirectoryContext;
use keyd::Role;
use keyd_daemon::CallerMap;
use krb_proto::KerberosTime;
use ldap_front::test_seams::FrontParams;
use ldap_front::{ConnectionLimits, DaemonControl, Endpoint, Listeners, Timeouts};
use pdp::{
    Action, ActionMatch, AnonymousGrant, AuthMatch, ContextMatch, Effect, IpScope, Match,
    ResourceMatch, Rule, RuleId, SubjectMatch, TransportSec,
};
use rustls::ClientConfig;
use std::fs::File;
use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;

pub use keyd_support::{eventually, my_uid, skip_as_root, TempDir, TestClock};

/// The policy version the harness's daemons share. Test data.
pub const POLICY_VERSION: u64 = 7;

/// The DNS host name of the DC in the rootDSE (crates/directory-daemon
/// support `params`). Test data.
pub const DNS_HOST_NAME: &str = "dc1.example.org";

/// The sources auditd's listeners name the one test uid as (module
/// documentation, "Identity"): each sender's own process name of docs/50
/// §2.4 (crates/config `AuditSource`).
pub const AUDIT_LABELS: [&str; 5] = ["keyd", "dird", "kdc", "ldap-front", "admind"];

/// auditd's configuration texts for the one-uid world: one per `(socket,
/// source name)` listener, all naming `mapped_uid` as that source, with one
/// log at `log`, run-as `run_as` (uid, gid) and `frame_timeout_secs`.
/// Spec: docs/50 §3.2, §7.1; crates/config `AuditdSettings`; task R9b.
pub fn labelled_auditd_settings(
    listeners: &[(PathBuf, &str)],
    mapped_uid: u32,
    run_as: (u32, u32),
    log: &Path,
    frame_timeout_secs: u64,
) -> Vec<AuditdSettings> {
    listeners
        .iter()
        .map(|(socket, source)| {
            assert!(AUDIT_LABELS.contains(source), "a sender's source: {source}");
            let text = format!(
                "run_as_uid = {}\nrun_as_gid = {}\naudit_socket = {}\naudit_log_path = {}\n\
                 uid_sources = {mapped_uid}:{source}\nframe_timeout = {frame_timeout_secs}s\n",
                run_as.0,
                run_as.1,
                socket.display(),
                log.display()
            );
            AuditdSettings::parse(text.as_bytes()).expect("valid auditd settings")
        })
        .collect()
}

/// Every daemon record of `records` was recorded under its sender's own
/// source (A-85: a shape bound to one sender came from that sender's
/// listener; `WindowSummary` names none), from the one test uid; auditd's
/// own records are skipped. Spec: docs/50 §3.2, §8.1; task R9b.
pub fn assert_recorded_under_their_senders(records: &[Record], uid: u32) {
    for record in records
        .iter()
        .filter(|record| record.source != audit_log::Source::Auditd)
    {
        assert_eq!(record.source_uid, uid, "the sender's peer uid");
        let shape = ipc_audit::peek_shape(&record.payload).expect("an event shape");
        if let Some(sender) = audit_daemon::binding::bound_source(shape) {
            assert_eq!(record.source, sender, "recorded under its sender's source");
        }
    }
}

/// The bound of every wait for a condition in the tests. Project choice:
/// above the daemons' audit backoff ceiling (5 s) plus their 1 s heartbeat.
pub const LONG: Duration = Duration::from_secs(20);

/// The bound of each whole test. Project choice.
pub const TEST_BOUND: Duration = Duration::from_secs(240);

/// Run `body` on its own thread and fail if it does not finish within
/// `limit` (task P12: "every test finishes in bounded time with explicit
/// timeouts"). A panic of `body` is the test's failure.
pub fn within(limit: Duration, body: impl FnOnce() + Send + 'static) {
    let (done, finished) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        body();
        let _ = done.send(());
    });
    match finished.recv_timeout(limit) {
        Ok(()) | Err(RecvTimeoutError::Disconnected) => {
            if let Err(panic) = thread.join() {
                std::panic::resume_unwind(panic);
            }
        }
        Err(RecvTimeoutError::Timeout) => panic!("the test did not finish within {limit:?}"),
    }
}

/// The directory context of the identities (realm EXAMPLE.ORG).
pub fn directory_context() -> DirectoryContext {
    kdcd::context()
}

/// dird's LDAP clock: the fixed test time (module documentation).
#[derive(Debug, Clone, Copy)]
pub struct FixedTime;

impl directory_daemon::Clock for FixedTime {
    fn now(&self) -> Option<KerberosTime> {
        Some(common::now())
    }
}

/// The rootDSE read rule of the LDAP tests (docs/49 §5.2; Q-170 → A-51):
/// Allow `DirRead` on the rootDSE for any subject — rule id 2 (rule 1 is
/// the kdc fixtures' Kerberos rule).
fn root_dse_rule() -> Rule {
    Rule {
        id: RuleId(2),
        effect: Effect::Allow,
        when: Match {
            action: ActionMatch::Exact(Action::DirRead),
            resource: ResourceMatch::RootDse,
            subject: SubjectMatch::Any,
            context: ContextMatch::ANY,
            auth: AuthMatch::ANY,
        },
        obligations: vec![],
    }
}

/// The shared policy of version `version` (module documentation,
/// "Fixtures"). Spec: docs/50 §7.2 (one file for kdc and dird); A-51; A-68;
/// P-10.
pub fn harness_policy(version: u64) -> DevelopmentPolicy {
    let mut policy = kdcd::shared_policy(version, vec![common::allow_kerberos(), root_dse_rule()]);
    policy.anonymous = vec![AnonymousGrant::new(
        ActionMatch::Exact(Action::DirRead),
        ResourceMatch::RootDse,
        TransportSec::NONE,
        IpScope::Internal,
    )
    .unwrap()];
    policy
}

/// ldap-front's zone table here: the loopback network is internal, so the
/// front serves its loopback listeners and client (docs/52 R14: it listens
/// only inside the internal networks and serves only internal sources);
/// dird decides the front's requests under the internal zone — the front's,
/// from its peer uid — so the A-51 internal anonymous rootDSE grant
/// applies. Test data.
pub fn loopback_internal() -> Vec<config::Network> {
    vec![config::Network::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8).unwrap()]
}

/// ldap-front's timeouts in the tests: short, but well above a loopback
/// exchange (docs/50 §4.2 names the policies; the values are test data).
pub fn front_timeouts() -> Timeouts {
    Timeouts {
        init_recv: Duration::from_secs(10),
        max_idle: Duration::from_secs(10),
        tls_handshake: Duration::from_secs(5),
        dird_deadline: Duration::from_secs(10),
        client_write: Duration::from_secs(5),
    }
}

/// The real ldap-front on its own thread with its own current-thread
/// runtime; its listeners on 127.0.0.1 at ports the system picks (never a
/// privileged port). Modelled on crates/ldap-front/tests/common/world.rs.
pub struct Front {
    control: DaemonControl,
    thread: Option<JoinHandle<Result<(), String>>>,
    pub ldap: SocketAddr,
    pub ldaps: SocketAddr,
}

impl Front {
    /// Bind, start `serve`, wait (bounded) until it serves; a start-up
    /// failure is returned as its message. Spec: docs/50 §7.5 step 5.
    pub fn start(
        params: FrontParams,
        tls: Arc<rustls::server::ServerConfig>,
    ) -> Result<Front, String> {
        let ldap = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let ldaps = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let (ldap_addr, ldaps_addr) = (
            ldap.local_addr().map_err(|e| e.to_string())?,
            ldaps.local_addr().map_err(|e| e.to_string())?,
        );
        let listeners = Listeners {
            ldap: vec![ldap],
            ldaps: vec![ldaps],
        };
        let control = DaemonControl::new();
        let thread = {
            let control = control.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let result = runtime.block_on(ldap_front::test_seams::serve(
                    params, tls, listeners, control,
                ));
                drop(runtime);
                result.map_err(|e| e.to_string())
            })
        };
        let start = Instant::now();
        while !control.is_serving() {
            if thread.is_finished() {
                return Err(thread
                    .join()
                    .map_err(|_| String::from("ldap-front panicked"))?
                    .err()
                    .unwrap_or_default());
            }
            if start.elapsed() > Duration::from_secs(10) {
                control.stop();
                return Err(String::from("ldap-front did not start within 10 s"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(Front {
            control,
            thread: Some(thread),
            ldap: ldap_addr,
            ldaps: ldaps_addr,
        })
    }

    /// Stop the front and wait for it.
    pub fn stop(mut self) -> Result<(), String> {
        self.control.stop();
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|_| String::from("ldap-front panicked"))?,
            None => Ok(()),
        }
    }
}

impl Drop for Front {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.control.stop();
            let _ = thread.join();
        }
    }
}

/// Where everything lives, inside the one temporary directory (0700) —
/// except the files the daemons reach through crates/protected-file — the
/// integrity key, the policy, dird's redb file and auditd's log (task
/// R11b) — which live in [`Harness::files`] (crates/test-scratch: a
/// directory the walk from `/` accepts; Q-480, Q-530). The socket
/// names are the daemons' tier-2 supports' (crates/keyd-daemon `params`,
/// crates/directory-daemon `params`); each sender's audit socket is its own
/// listener of the one auditd (module documentation, "Identity"): keyd's
/// `a.sock` (its support's), dird's, the kdc's and ldap-front's.
#[derive(Debug, Clone)]
pub struct Paths {
    pub audit_socket: PathBuf,
    pub dird_audit_socket: PathBuf,
    pub kdc_audit_socket: PathBuf,
    pub front_audit_socket: PathBuf,
    pub audit_log: PathBuf,
    pub keyd_socket: PathBuf,
    pub dird_kdc_socket: PathBuf,
    pub dird_ldap_socket: PathBuf,
    pub database: PathBuf,
    pub integrity_key: PathBuf,
    pub policy: PathBuf,
}

/// The whole deployment of one test (module documentation).
pub struct Harness {
    pub dir: TempDir,
    /// The files reached through crates/protected-file (the integrity key,
    /// the policy files, dird's redb file, auditd's log).
    pub files: test_scratch::ScratchDir,
    pub uid: u32,
    pub paths: Paths,
    /// The local reference copy of dird's directory (identical content).
    pub local: dird::Directory,
    pub handles: Handles,
    /// The policy as the daemons load it from [`Paths::policy`].
    pub policy: DevelopmentPolicy,
    pub keyd_clock: TestClock,
    pub kdc_clock: HeldClock,
    /// The per-run test CA and the DC's server certificate and key.
    pub tls_pki: TestPki,
    /// A client trusting only that CA.
    pub tls_client: Arc<ClientConfig>,
    pub auditd: Option<auditd_support::Server>,
    pub keyd: Option<keyd_support::Daemon>,
    pub dird: Option<dird::Dird>,
    pub kdcd: Option<Kdcd>,
    pub front: Option<Front>,
}

impl Harness {
    /// The fixtures only, nothing started; `None` as root (uid 0 is never
    /// mapped — docs/50 R50-3 — and tier 2 needs a non-root uid).
    pub fn fixtures() -> Option<Harness> {
        let dir = TempDir::new();
        let uid = my_uid(&dir);
        if skip_as_root(uid) {
            return None;
        }
        let files = test_scratch::ScratchDir::new("e2e").expect("the scratch directory");
        let paths = Paths {
            audit_socket: dir.join("a.sock"),
            dird_audit_socket: dir.join("ad.sock"),
            kdc_audit_socket: dir.join("ak.sock"),
            front_audit_socket: dir.join("af.sock"),
            audit_log: files.join("audit.log"),
            keyd_socket: dir.join("k.sock"),
            dird_kdc_socket: dir.join("d.sock"),
            dird_ldap_socket: dir.join("l.sock"),
            database: files.join("r.redb"),
            integrity_key: files.join("integrity.key"),
            policy: files.join("policy.store"),
        };
        // dird's own file (closed again: dird opens it), and the reference.
        drop(dird::Directory::standard(&paths.database));
        let local = dird::Directory::standard(&dir.join("l.redb"));
        let handles = Handles::read(&local.store);
        // The development integrity key file: 32 octets, mode 0400, owned
        // by dird's account (docs/50 §7.4; Q-213 interim).
        write_file(&paths.integrity_key, &dird::TEST_KEY, 0o400);
        // The one policy file both daemons load (A-68).
        write_policy(&paths.policy, POLICY_VERSION);
        let policy = kdc_daemon::startup::read_policy(&paths.policy, uid)
            .map_err(|e| e.to_string())
            .expect("the policy file loads");
        let tls_pki = test_pki();
        let tls_client = client_config(&tls_pki);
        Some(Harness {
            dir,
            files,
            uid,
            paths,
            local,
            handles,
            policy,
            keyd_clock: TestClock::at(common::keyd_started()),
            kdc_clock: HeldClock::at(common::now()),
            tls_pki,
            tls_client,
            auditd: None,
            keyd: None,
            dird: None,
            kdcd: None,
            front: None,
        })
    }

    /// The fixtures and all five daemons, in the docs/50 §7.5 order.
    pub fn start() -> Option<Harness> {
        let mut harness = Harness::fixtures()?;
        harness.start_auditd();
        harness.start_keyd_serving().expect("keyd starts");
        harness.start_dird().expect("dird starts");
        harness.start_kdc().expect("the kdc starts");
        harness.start_front().expect("ldap-front starts");
        Some(harness)
    }

    // ---- auditd -------------------------------------------------------------------

    /// auditd's listeners: each sender's audit socket naming `mapped_uid`
    /// as that sender ([`labelled_auditd_settings`]), the log in the
    /// directory, an account of its own (another uid).
    /// Spec: docs/50 §3.2, §7.1; crates/config `AuditdSettings`; task R9b.
    fn auditd_settings(&self, mapped_uid: u32, labels: [&str; 4]) -> Vec<AuditdSettings> {
        let run_as = auditd_support::other_uid(&[self.uid, mapped_uid]);
        let [keyd, dird, kdc, front] = labels;
        let listeners = [
            (self.paths.audit_socket.clone(), keyd),
            (self.paths.dird_audit_socket.clone(), dird),
            (self.paths.kdc_audit_socket.clone(), kdc),
            (self.paths.front_audit_socket.clone(), front),
        ];
        labelled_auditd_settings(
            &listeners,
            mapped_uid,
            (run_as, run_as),
            &self.paths.audit_log,
            5,
        )
    }

    /// Start auditd mapping `mapped_uid` (the test's uid unless a test
    /// cross-wires it) on every sender's listener, with the production
    /// limits and binding table. The log is verified at start (docs/50 §7.5
    /// step 1).
    pub fn start_auditd_mapping(&mut self, mapped_uid: u32) {
        self.start_auditd_with(mapped_uid, ["keyd", "dird", "kdc", "ldap-front"]);
    }

    /// Start auditd for the test's uid with `labels` — the source each
    /// sender's listener records it as, in the order keyd, dird, the kdc,
    /// ldap-front: a cross-wired map when a label is not that sender's
    /// (task R9b attack tests).
    pub fn start_auditd_labelled(&mut self, labels: [&str; 4]) {
        let uid = self.uid;
        self.start_auditd_with(uid, labels);
    }

    fn start_auditd_with(&mut self, mapped_uid: u32, labels: [&str; 4]) {
        assert!(self.auditd.is_none(), "auditd already runs");
        let settings = self.auditd_settings(mapped_uid, labels);
        let config = ListenerConfig::from_settings(&settings[0]);
        self.auditd = Some(auditd_support::Server::start_many(
            &settings, config, 64, true,
        ));
    }

    /// Start auditd for the test's uid.
    pub fn start_auditd(&mut self) {
        let uid = self.uid;
        self.start_auditd_mapping(uid);
    }

    /// Stop auditd; its writer must end cleanly.
    pub fn stop_auditd(&mut self) {
        let server = self.auditd.take().expect("auditd runs");
        if let Some(writer) = server.stop() {
            writer.expect("auditd's writer ended cleanly");
        }
    }

    // ---- keyd ---------------------------------------------------------------------

    /// keyd's default uid map: the test's uid is the Kdc (module
    /// documentation, "Identity").
    pub fn kdc_callers(&self) -> CallerMap {
        CallerMap::new(&[(self.uid, Role::Kdc)]).unwrap()
    }

    /// Start keyd with `callers`, its clock at `started` (the hold-down
    /// start, R50-6); the directory's key sets created inside keyd's
    /// constructor (crates/kdc-daemon support `directory_keyd`).
    pub fn start_keyd(&mut self, callers: CallerMap, started: KerberosTime) -> Result<(), String> {
        assert!(self.keyd.is_none(), "keyd already runs");
        let params = keyd_support::params(&self.dir, callers, self.uid);
        assert_eq!(params.keyd_socket, self.paths.keyd_socket);
        assert_eq!(params.audit.socket, self.paths.audit_socket);
        let clock = TestClock::at(started);
        let handles = self.handles;
        let daemon = keyd_support::Daemon::start(params, clock.clone(), move |started| {
            kdcd::directory_keyd(started, handles)
        })?;
        self.keyd_clock = clock;
        self.keyd = Some(daemon);
        Ok(())
    }

    /// Start keyd as the flows do: started a day before `now`, then its
    /// clock moved to `now` — past the hold-down.
    pub fn start_keyd_serving(&mut self) -> Result<(), String> {
        let callers = self.kdc_callers();
        self.start_keyd(callers, common::keyd_started())?;
        self.keyd_clock.set(common::now());
        Ok(())
    }

    /// Stop keyd (its window flushed, bounded — crates/keyd-daemon).
    pub fn stop_keyd(&mut self) {
        self.keyd
            .take()
            .expect("keyd runs")
            .stop()
            .expect("keyd stopped cleanly");
    }

    // ---- dird ---------------------------------------------------------------------

    /// Start dird reading the policy at `policy_path`, its kdc channel for
    /// `kdc_uid` and its LDAP channel for `front_uid` (both the test's uid
    /// unless a test cross-wires them).
    pub fn start_dird_with(
        &mut self,
        policy_path: &Path,
        kdc_uid: u32,
        front_uid: u32,
    ) -> Result<(), String> {
        assert!(self.dird.is_none(), "dird already runs");
        let mut params = dird::params(&self.dir, kdc_uid, self.uid, Duration::from_secs(5), 4);
        assert_eq!(params.kdc_socket, self.paths.dird_kdc_socket);
        assert_eq!(params.ldap_socket, self.paths.dird_ldap_socket);
        assert_eq!(params.dns_host_name, DNS_HOST_NAME);
        // dird's own audit listener (module documentation, "Identity").
        params.audit.socket = self.paths.dird_audit_socket.clone();
        params.ldap_front_uid = front_uid;
        params.clock = SharedClock::new(FixedTime);
        let policy = directory_daemon::startup::read_policy(policy_path, self.uid)
            .map_err(|e| e.to_string())?;
        let key =
            directory_daemon::startup::read_integrity_key(&self.paths.integrity_key, self.uid)
                .map_err(|e| e.to_string())?;
        let source = StoreSource::File {
            path: self.paths.database.clone(),
            key,
            owner_uid: self.uid,
        };
        self.dird = Some(dird::Dird::start(params, source, policy)?);
        Ok(())
    }

    /// Start dird on the shared policy file, for the test's uid.
    pub fn start_dird(&mut self) -> Result<(), String> {
        let (path, uid) = (self.paths.policy.clone(), self.uid);
        self.start_dird_with(&path, uid, uid)
    }

    /// Stop dird (both engines joined).
    pub fn stop_dird(&mut self) {
        self.dird
            .take()
            .expect("dird runs")
            .stop()
            .expect("dird stopped cleanly");
    }

    // ---- kdc ----------------------------------------------------------------------

    /// Start the kdc reading the policy at `policy_path` (crates/kdc-daemon
    /// support `kdc_params`: 127.0.0.0/8 internal, keyd / dird / auditd as
    /// the test's uid, every audit event to the kdc's own audit listener).
    pub fn start_kdc_with(&mut self, policy_path: &Path) -> Result<(), String> {
        assert!(self.kdcd.is_none(), "the kdc already runs");
        let policy =
            kdc_daemon::startup::read_policy(policy_path, self.uid).map_err(|e| e.to_string())?;
        let params = kdcd::kdc_params(&self.paths.kdc_audit_socket, self.uid);
        self.kdcd = Some(Kdcd::start(
            params,
            policy,
            &self.paths.keyd_socket,
            &self.paths.dird_kdc_socket,
            self.kdc_clock.clone(),
        )?);
        Ok(())
    }

    /// Start the kdc on the shared policy file.
    pub fn start_kdc(&mut self) -> Result<(), String> {
        let path = self.paths.policy.clone();
        self.start_kdc_with(&path)
    }

    /// Stop the kdc (its window flushed, bounded).
    pub fn stop_kdc(&mut self) {
        self.kdcd
            .take()
            .expect("the kdc runs")
            .stop()
            .expect("the kdc stopped cleanly");
    }

    /// The running kdc.
    pub fn kdcd(&self) -> &Kdcd {
        self.kdcd.as_ref().expect("the kdc runs")
    }

    // ---- ldap-front ---------------------------------------------------------------

    /// Start ldap-front: dird's LDAP socket and auditd as the test's uid,
    /// the product's TLS configuration (module documentation).
    pub fn start_front(&mut self) -> Result<(), String> {
        assert!(self.front.is_none(), "ldap-front already runs");
        let params = FrontParams {
            dird: Endpoint {
                socket: self.paths.dird_ldap_socket.clone(),
                uid: self.uid,
            },
            audit: Endpoint {
                socket: self.paths.front_audit_socket.clone(),
                uid: self.uid,
            },
            timeouts: front_timeouts(),
            limits: ConnectionLimits::DEFAULT,
            internal_networks: loopback_internal(),
        };
        self.front = Some(Front::start(params, server_config(&self.tls_pki))?);
        Ok(())
    }

    /// The running front.
    pub fn front(&self) -> &Front {
        self.front.as_ref().expect("ldap-front runs")
    }

    /// Stop ldap-front.
    pub fn stop_front(&mut self) {
        self.front
            .take()
            .expect("ldap-front runs")
            .stop()
            .expect("ldap-front stopped cleanly");
    }

    /// Stop every running daemon in the reverse of the start order (each
    /// sender flushes its audit window to auditd, bounded, before auditd
    /// stops).
    pub fn stop_all(&mut self) {
        if self.front.is_some() {
            self.stop_front();
        }
        if self.kdcd.is_some() {
            self.stop_kdc();
        }
        if self.dird.is_some() {
            self.stop_dird();
        }
        if self.keyd.is_some() {
            self.stop_keyd();
        }
        if self.auditd.is_some() {
            self.stop_auditd();
        }
    }

    // ---- policy files -------------------------------------------------------------

    /// Write another policy file (version `version`) next to the shared one
    /// and return its path.
    pub fn policy_file(&self, name: &str, version: u64) -> PathBuf {
        let path = self.files.join(name);
        write_policy(&path, version);
        path
    }

    // ---- the audit log ------------------------------------------------------------

    /// Verify auditd's whole log ([`verified_log`]) and return its head and
    /// records. Call with auditd stopped.
    pub fn verified_audit_log(&self) -> Result<(ChainHead, Vec<Record>), String> {
        assert!(self.auditd.is_none(), "stop auditd before reading its log");
        verified_log(&self.paths.audit_log)
    }

    /// The decoded events of every daemon record of the verified log (auditd
    /// stopped), each checked to carry the transport identity auditd gave it
    /// (docs/50 §3.2: the connection's peer uid, and the source its
    /// listener's map gives that uid — its sender's own,
    /// [`assert_recorded_under_their_senders`]). auditd's own records are
    /// skipped.
    pub fn audit_events(&self) -> Vec<ipc_audit::EventBody> {
        let (_, records) = self.verified_audit_log().expect("the log verifies");
        assert_recorded_under_their_senders(&records, self.uid);
        records
            .iter()
            .filter(|record| record.source != audit_log::Source::Auditd)
            .map(|record| ipc_audit::decode_event(&record.payload).expect("every payload decodes"))
            .collect()
    }

    /// dird's LDAP events of the verified log (auditd stopped).
    pub fn ldap_events(&self) -> Vec<ipc_audit::LdapEvent> {
        self.audit_events()
            .into_iter()
            .filter_map(|event| match event {
                ipc_audit::EventBody::Ldap(event) => Some(*event),
                _ => None,
            })
            .collect()
    }
}

impl Drop for Harness {
    /// Stop the daemons (reverse start order) before the temporary
    /// directory goes.
    fn drop(&mut self) {
        drop(self.front.take());
        drop(self.kdcd.take());
        drop(self.dird.take());
        drop(self.keyd.take());
        drop(self.auditd.take());
    }
}

/// Verify the whole log based at `base` with crates/audit-log's own
/// verifier — every segment in order, the first anchored at genesis, each
/// next one at the head of the one before (docs/37 §2; Q-250 item 6) — and
/// return its head and records. Its writer must be stopped (a running one
/// may be in the middle of a batch).
pub fn verified_log(base: &Path) -> Result<(ChainHead, Vec<Record>), String> {
    let indexes = list_segments(base, auditd_support::log_uid()).map_err(|e| format!("{e:?}"))?;
    if indexes.is_empty() {
        return Err(String::from("no audit segment"));
    }
    let open = |index: u64| {
        File::open(segment_path(base, index))
            .map(BufReader::new)
            .map_err(|e| e.to_string())
    };
    let files = indexes
        .iter()
        .map(|&index| open(index))
        .collect::<Result<Vec<_>, String>>()?;
    let head = verify_log(files, Anchor::Genesis, SegmentLimit::DEFAULT, None)
        .map_err(|e| e.to_string())?;
    let mut records = Vec::new();
    let mut anchor = Anchor::Genesis;
    for &index in &indexes {
        let mut reader = SegmentReader::open(open(index)?, anchor, SegmentLimit::DEFAULT, None)
            .map_err(|e| e.to_string())?;
        while let Some(record) = reader.next_record().map_err(|e| e.to_string())? {
            records.push(record);
        }
        anchor = Anchor::After(reader.head());
        reader.finish().map_err(|e| e.to_string())?;
    }
    Ok((head, records))
}

/// Write `octets` to `path` with `mode`.
pub fn write_file(path: &Path, octets: &[u8], mode: u32) {
    std::fs::write(path, octets).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Write the harness policy of `version` to `path` (mode 0644: owned by the
/// test's uid, not group/other-writable — the shared loader's rule, A-68).
pub fn write_policy(path: &Path, version: u64) {
    let file = harness_policy(version)
        .encode()
        .expect("the policy encodes");
    write_file(path, &file, 0o644);
}
