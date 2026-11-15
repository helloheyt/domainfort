//! Tier-1/2 support for the kdc daemon (docs/50 §9: "real servers run in the
//! test's threads; Unix sockets in a unique temporary directory (0700); UDP
//! / TCP on loopback at port 0 — the system picks a port read back with
//! `local_addr`; the uid map is injected with the test's own uid").
//!
//! * `dird` — crates/directory-daemon's tier-2 support, reused through
//!   `#[path]` (it reuses crates/keyd-daemon's in turn): [`TempDir`],
//!   [`my_uid`], [`skip_as_root`], [`FakeAuditd`], the real keyd daemon
//!   runner, the real dird runner, the directory of the kdc fixtures'
//!   identities, and the kdc side's connectors (Linux: the daemons' own,
//!   rustix peer credentials; elsewhere: the server's uid through tokio).
//! * [`Kdcd`] — the real `kdc_daemon::serve` on its own thread with its own
//!   runtime, its UDP socket and TCP listener bound on 127.0.0.1 at ports
//!   the system picks (never a privileged port).
//! * [`directory_keyd`] / [`Handles`] — keyd holding the directory's key
//!   sets under the directory's own handles (docs/47 §9.1), as
//!   crates/directory-daemon's flow test builds it.
//! * [`udp_send`], [`tcp_send`], [`tcp_raw`] — the client side of RFC 4120
//!   §7.2.1 / §7.2.2 written from the RFC (one datagram per message; a
//!   4-octet big-endian length before each message).
//!
//! Sources: docs/50 §4.1, §9; docs/47 §9.1; RFC 4120 §7.2.1, §7.2.2. Every
//! value is constructed by hand; no vector comes from any other
//! implementation.
#![allow(dead_code, unused_imports)] // each test binary uses a different subset

#[path = "../../../directory-daemon/tests/support/mod.rs"]
pub mod dird;

pub use dird::keyd as keyd_support;
pub use dird::{connector, eventually, my_uid, skip_as_root, FakeAuditd, TempDir, TestClock};

use crate::common::{
    alice_name, krbtgt_name, machine_name, now, realm, service_name, TestEntropy, ADMIN,
    ALICE_PASSWORD, ALICE_SALT, DIRECTORY, KRBTGT_KEY, MACHINE_KEY, SERVICE_KEY,
};
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;
use directory_daemon::policy::{DevelopmentPolicy, MandatoryFast};
use directory_pip::{DirectoryContext, TierMap};
use dirstore::Store;
// The zone table's entries are crates/config's networks — the one address
// match (task R15b, docs/questions/Q-632).
use config::Network;
use kdc_daemon::zones::ZoneTable;
// The full parameters and the generic `serve` are the daemon's test seams
// (docs/52 C18, task R15; feature `test-seams`, enabled by the
// dev-dependency).
use kdc_daemon::test_seams::{serve, DaemonParams};
use kdc_daemon::{AuditEndpoint, Clock, DaemonControl, Listeners, TcpLimits};
use keyd::{InMemoryKeyStore, KeyHandle, Keyd, PrincipalBinding};
use keyd_daemon::RecordBuffer;
use krb_proto::KerberosTime;
use pdp::{PolicyVersion, Rule, RuleId};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

/// keyd's handles of the directory's key sets (docs/47 §9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handles {
    pub krbtgt: KeyHandle,
    pub alice: KeyHandle,
    pub ws1: KeyHandle,
    pub files: KeyHandle,
}

/// The directory context of the identities (realm EXAMPLE.ORG).
pub fn context() -> DirectoryContext {
    DirectoryContext::new(
        ad_schema::phase1().unwrap(),
        &dird::keyd_config(),
        dird::naming_context(),
    )
    .unwrap()
}

impl Handles {
    /// Read from the directory (docs/47 R47-2, R47-3).
    pub fn read(store: &Store) -> Handles {
        let ctx = context();
        let tiers = TierMap::empty();
        let view = ctx.view(store, &tiers).unwrap();
        use kdc::AccountSource as _;
        Handles {
            krbtgt: view.krbtgt_handle(&dird::domain_sid()).unwrap(),
            alice: view.client(&realm(), &alice_name()).unwrap().unwrap().key,
            ws1: view.client(&realm(), &machine_name()).unwrap().unwrap().key,
            files: view
                .service(&realm(), &service_name())
                .unwrap()
                .unwrap()
                .key,
        }
    }
}

/// keyd with the directory's key sets (docs/47 §9.1, §9.2): krbtgt, files$
/// and ws1$ from `create_key` with the fixtures' scripted key octets, alice
/// from `set_secret` with her password and the directory's salt — under the
/// directory's handles; the set-up records dropped. One deterministic test
/// entropy, drawn in the same order every time.
pub fn directory_keyd(
    started: &KerberosTime,
    handles: Handles,
) -> Result<Keyd<InMemoryKeyStore, RecordBuffer, TestEntropy>, keyd::ConfigError> {
    let entropy = TestEntropy::default();
    let mut keyd = Keyd::with_entropy(
        dird::keyd_config(),
        InMemoryKeyStore::new_insecure_development_allowing_krbtgt(64),
        RecordBuffer::new(),
        entropy.clone(),
        started,
    )?;
    let enctypes: Vec<krb_crypto::EncType> = keyd
        .config()
        .enctypes
        .iter()
        .map(|e| krb_crypto::EncType::from_number(e.number()).unwrap())
        .collect();
    for (handle, binding, key) in [
        (handles.krbtgt, krbtgt_name(), KRBTGT_KEY),
        (handles.files, service_name(), SERVICE_KEY),
        (handles.ws1, machine_name(), MACHINE_KEY),
    ] {
        for e in &enctypes {
            entropy.push(&key[..e.key_length()]);
        }
        keyd.create_key(
            &ADMIN,
            &handle,
            &PrincipalBinding::new(realm(), binding),
            &now(),
        )
        .unwrap();
    }
    crate::common::grant_user(
        &mut keyd,
        &handles.alice,
        &PrincipalBinding::new(realm(), alice_name()),
        &now(),
    );
    keyd.set_secret(
        &DIRECTORY,
        &handles.alice,
        &PrincipalBinding::new(realm(), alice_name()),
        String::from(ALICE_PASSWORD).into(),
        ALICE_SALT,
        &now(),
    )
    .unwrap();
    let _ = keyd.audit_sink_mut().take();
    Ok(keyd)
}

/// The shared policy file of the flows: version `version`, the
/// mandatory-FAST entry naming ws1$ itself as the bootstrap set (rule ids
/// 100..=103; crates/pdp: the principal belongs to its own SID's set), and
/// `rules` of its own.
pub fn shared_policy(version: u64, rules: Vec<Rule>) -> DevelopmentPolicy {
    DevelopmentPolicy {
        version: PolicyVersion(version),
        principals: Default::default(),
        subtrees: Vec::new(),
        mandatory_fast: MandatoryFast {
            bootstrap_group: dird::sid_of(dird::WS1),
            first_rule_id: RuleId(100),
        },
        rules,
        anonymous: Vec::new(),
    }
}

/// The kdc's clock in the tests: a fixed time, and a latch that can hold
/// the engine inside `now()` (the engine reads it first for every job), so
/// a test can fill the queues deterministically.
#[derive(Clone)]
pub struct HeldClock {
    time: KerberosTime,
    held: Arc<(Mutex<bool>, Condvar)>,
    entered: Arc<AtomicUsize>,
}

impl HeldClock {
    pub fn at(time: KerberosTime) -> HeldClock {
        HeldClock {
            time,
            held: Arc::new((Mutex::new(false), Condvar::new())),
            entered: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Hold every later `now()` until [`HeldClock::release`].
    pub fn hold(&self) {
        *self.held.0.lock().unwrap() = true;
    }

    pub fn release(&self) {
        *self.held.0.lock().unwrap() = false;
        self.held.1.notify_all();
    }

    /// How many times `now()` was entered.
    pub fn entered(&self) -> usize {
        self.entered.load(Ordering::SeqCst)
    }
}

impl Clock for HeldClock {
    fn now(&self) -> Option<KerberosTime> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let mut held = self.held.0.lock().unwrap();
        while *held {
            held = self.held.1.wait(held).unwrap();
        }
        Some(self.time)
    }
}

/// The kdc parameters of a test in `dir`: keyd and dird running as `uid`,
/// the kdc's auditd at `audit` as `uid`, 127.0.0.0/8 internal, short TCP
/// deadlines.
pub fn kdc_params(audit: &Path, uid: u32) -> DaemonParams {
    DaemonParams {
        keyd_uid: uid,
        keyd_deadline: ipc_keyd::DEFAULT_DEADLINE,
        dird_uid: uid,
        dird_deadline: ipc_directory::DEFAULT_DEADLINE,
        audit: AuditEndpoint {
            socket: audit.to_path_buf(),
            uid,
        },
        zones: ZoneTable::new(vec![Network::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
            8,
        )
        .unwrap()]),
        tcp: TcpLimits {
            max_connections: 64,
            max_per_source: 16,
            first_frame_timeout: Duration::from_secs(5),
            frame_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(5),
            max_requests: 64,
        },
        udp: kdc_daemon::rate::SourceLimits {
            per_source: 1000,
            global: 10_000,
            window: Duration::from_secs(1),
        },
        as_queue_capacity: 16,
        tgs_queue_capacity: 16,
        window: ipc_audit::WindowConfig::DEFAULT,
        udp_max_reply_len: kdc::DEFAULT_UDP_MAX_REPLY_LEN,
    }
}

/// The real kdc daemon on its own thread.
pub struct Kdcd {
    control: DaemonControl,
    thread: Option<JoinHandle<Result<(), String>>>,
    pub udp: SocketAddr,
    pub tcp: SocketAddr,
}

impl Kdcd {
    /// Bind 127.0.0.1:0 on UDP and TCP, start `serve` and wait until it
    /// serves; a start-up failure is returned as its message.
    pub fn start<C: Clock>(
        params: DaemonParams,
        policy: DevelopmentPolicy,
        keyd_socket: &Path,
        dird_socket: &Path,
        clock: C,
    ) -> Result<Kdcd, String> {
        let udp = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let (udp_addr, tcp_addr) = (
            udp.local_addr().map_err(|e| e.to_string())?,
            tcp.local_addr().map_err(|e| e.to_string())?,
        );
        let listeners = Listeners {
            udp: vec![udp],
            tcp: vec![tcp],
        };
        let keyd = connector::keyd(keyd_socket);
        let dird = connector::dird(dird_socket);
        let control = DaemonControl::new();
        let thread = {
            let control = control.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let result =
                    runtime.block_on(serve(params, policy, listeners, keyd, dird, clock, control));
                drop(runtime);
                match result {
                    Ok(stopped) => {
                        let failed = stopped.engine_failed();
                        stopped
                            .join()
                            .map_err(|_| String::from("engine panicked"))?;
                        if failed {
                            Err(String::from("engine stopped early"))
                        } else {
                            Ok(())
                        }
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
                start.elapsed() < Duration::from_secs(15),
                "the kdc daemon did not start"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(Kdcd {
            control,
            thread: Some(thread),
            udp: udp_addr,
            tcp: tcp_addr,
        })
    }

    /// Stop the daemon and wait for it (engine joined).
    pub fn stop(mut self) -> Result<(), String> {
        self.control.stop();
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for Kdcd {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.control.stop();
            let _ = thread.join();
        }
    }
}

/// dird's parameters in a stack's `dir` (crates/directory-daemon support
/// `params`), its audit socket `da.sock`: dird's own fake auditd, which
/// records its peer under dird's source — one fake per daemon, since each
/// expects its own source on every connection (task R9b).
pub fn stack_dird_params(dir: &TempDir, uid: u32) -> directory_daemon::test_seams::DaemonParams {
    let mut params = dird::params(dir, uid, uid, Duration::from_secs(5), 4);
    params.audit.socket = dir.join("da.sock");
    params
}

/// The whole stack of a tier-2 test in its own directory: keyd's auditd,
/// dird's auditd, the kdc's own auditd (each records its peer under that
/// daemon's source — task R9b), the real keyd daemon, the real dird over an
/// opened directory of the fixtures' identities, and the kdc daemon.
pub struct Stack {
    pub dir: TempDir,
    pub uid: u32,
    pub directory: dird::Directory,
    pub handles: Handles,
    pub keyd_auditd: FakeAuditd,
    pub dird_auditd: FakeAuditd,
    pub kdc_auditd: FakeAuditd,
    pub keyd: Option<keyd_support::Daemon>,
    pub keyd_socket: PathBuf,
    pub dird: Option<dird::Dird>,
    pub dird_socket: PathBuf,
    pub clock: HeldClock,
    pub kdcd: Option<Kdcd>,
}

impl Stack {
    /// keyd, dird (policy version `dird_version`) and the kdc (policy
    /// version `kdc_version`, its parameters adjusted by `adjust`); `Ok(None)`
    /// when running as root (tier 2 needs a non-root uid, R50-3); a kdc
    /// start-up failure is `Err(message)`.
    pub fn start(
        kdc_version: u64,
        dird_version: u64,
        adjust: impl FnOnce(&mut DaemonParams),
    ) -> Result<Option<Stack>, String> {
        let dir = TempDir::new();
        let uid = my_uid(&dir);
        if skip_as_root(uid) {
            return Ok(None);
        }
        let directory = dird::Directory::standard(&dir.join("s.redb"));
        let handles = Handles::read(&directory.store);
        let keyd_params = keyd_support::params(
            &dir,
            keyd_daemon::CallerMap::new(&[(uid, keyd::Role::Kdc)]).unwrap(),
            uid,
        );
        let keyd_socket = keyd_params.keyd_socket.clone();
        let keyd_auditd = FakeAuditd::start(&keyd_params.audit.socket);
        let dird_auditd =
            FakeAuditd::start_recording_as(&dir.join("da.sock"), ipc_audit::EventSource::Dird);
        let kdc_auditd =
            FakeAuditd::start_recording_as(&dir.join("ka.sock"), ipc_audit::EventSource::Kdc);
        let keyd_clock = TestClock::at(crate::common::keyd_started());
        let keyd = keyd_support::Daemon::start(keyd_params, keyd_clock.clone(), move |started| {
            directory_keyd(started, handles)
        })?;
        keyd_clock.set(now());
        let dird = dird::Dird::start(
            stack_dird_params(&dir, uid),
            directory_daemon::test_seams::opened(Arc::clone(&directory.store)),
            shared_policy(dird_version, vec![crate::common::allow_kerberos()]),
        )?;
        let dird_socket = dird.socket.clone();
        let mut params = kdc_params(&dir.join("ka.sock"), uid);
        adjust(&mut params);
        let clock = HeldClock::at(now());
        let kdcd = Kdcd::start(
            params,
            shared_policy(kdc_version, vec![crate::common::allow_kerberos()]),
            &keyd_socket,
            &dird_socket,
            clock.clone(),
        )?;
        Ok(Some(Stack {
            dir,
            uid,
            directory,
            handles,
            keyd_auditd,
            dird_auditd,
            kdc_auditd,
            keyd: Some(keyd),
            keyd_socket,
            dird: Some(dird),
            dird_socket,
            clock,
            kdcd: Some(kdcd),
        }))
    }

    /// The kdc daemon.
    pub fn kdcd(&self) -> &Kdcd {
        self.kdcd.as_ref().unwrap()
    }

    /// Stop everything (kdc first).
    pub fn stop(mut self) {
        if let Some(kdcd) = self.kdcd.take() {
            kdcd.stop().unwrap();
        }
        if let Some(dird) = self.dird.take() {
            dird.stop().unwrap();
        }
        if let Some(keyd) = self.keyd.take() {
            keyd.stop().unwrap();
        }
    }
}

/// An unarmored AS-REQ of alice without padata, with `nonce`: answered
/// KDC_ERR_PREAUTH_REQUIRED (RFC 4120 §3.1.3; docs/48 §7.2 layer 1) — a
/// small reply that needs the directory and no key.
pub fn alice_probe(nonce: u32) -> Vec<u8> {
    let mut spec = crate::common::AsReqSpec::alice();
    spec.nonce = nonce;
    spec.encode()
}

/// The computer's bootstrap AS-REQ with `nonce` (needs keyd).
pub fn bootstrap(nonce: u32) -> Vec<u8> {
    let mut spec = crate::common::AsReqSpec::machine()
        .with_timestamp(&crate::common::machine_key(crate::common::AES256));
    spec.nonce = nonce;
    spec.encode()
}

// ---- the client side of RFC 4120 §7.2 ---------------------------------------------

/// RFC 4120 §7.2.1: one datagram with the request; the reply datagram, or
/// `None` if nothing came within `wait`.
pub fn udp_send(kdc: SocketAddr, request: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(wait)).unwrap();
    socket.send_to(request, kdc).unwrap();
    let mut buffer = vec![0u8; 65_536];
    match socket.recv_from(&mut buffer) {
        Ok((n, from)) => {
            assert_eq!(from, kdc, "RFC 4120 §7.2.1: the reply comes from the KDC");
            buffer.truncate(n);
            Some(buffer)
        }
        Err(_) => None,
    }
}

/// What came back on a TCP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpReply {
    /// One length-prefixed message.
    Message(Vec<u8>),
    /// The KDC closed the stream without a (whole) message.
    Closed,
}

/// Read one RFC 4120 §7.2.2 record from `stream`.
pub fn read_record(stream: &mut TcpStream) -> TcpReply {
    let mut prefix = [0u8; 4];
    if stream.read_exact(&mut prefix).is_err() {
        return TcpReply::Closed;
    }
    let length = u32::from_be_bytes(prefix);
    assert_eq!(
        length & 0x8000_0000,
        0,
        "RFC 4120 §7.2.2: the high bit is zero"
    );
    let mut message = vec![0u8; length as usize];
    if stream.read_exact(&mut message).is_err() {
        return TcpReply::Closed;
    }
    TcpReply::Message(message)
}

/// Whether the KDC closed `stream` (a read returns end of stream or a
/// reset within `wait`).
pub fn is_closed(stream: &mut TcpStream, wait: Duration) -> bool {
    stream.set_read_timeout(Some(wait)).unwrap();
    let mut one = [0u8; 1];
    match stream.read(&mut one) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
    }
}

/// A new connection to the KDC (read timeout 10 s).
pub fn tcp_connect(kdc: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(kdc).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
}

/// RFC 4120 §7.2.2: the request with its 4-octet length on a new
/// connection; the one reply record.
pub fn tcp_send(kdc: SocketAddr, request: &[u8]) -> TcpReply {
    let mut stream = tcp_connect(kdc);
    tcp_raw(&mut stream, &kdc::tcp_encode_frame(request).unwrap());
    read_record(&mut stream)
}

/// Write `octets` as they are.
pub fn tcp_raw(stream: &mut TcpStream, octets: &[u8]) {
    let _ = stream.write_all(octets);
}

/// The message of a TCP reply.
pub fn message(reply: TcpReply) -> Vec<u8> {
    match reply {
        TcpReply::Message(message) => message,
        TcpReply::Closed => panic!("expected a reply, the stream was closed"),
    }
}

/// Whether `message` is a KRB-ERROR with `code`.
pub fn is_error(message: &[u8], code: i32) -> bool {
    krb_proto::KrbError::decode(message).is_ok_and(|error| error.error_code == code)
}

/// The error code of a KRB-ERROR message.
pub fn error_code(message: &[u8]) -> i32 {
    krb_proto::KrbError::decode(message)
        .expect("a KRB-ERROR")
        .error_code
}
