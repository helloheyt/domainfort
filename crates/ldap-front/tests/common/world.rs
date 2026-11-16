//! Tier-2 support for ldap-front (docs/50 §9: "real servers run in the
//! test's threads; Unix sockets in a unique temporary directory (0700); TCP
//! on loopback at port 0 — the system picks a port read back with
//! `local_addr`; the uid map is injected with the test's own uid").
//!
//! * `dird_support` — crates/directory-daemon's tier-2 support, reused
//!   through `#[path]` (it reuses crates/keyd-daemon's in turn): the
//!   temporary directory, the directory of the kdc fixtures' identities,
//!   the real dird runner.
//! * `auditd_support` — crates/audit-daemon's tier-2 harness, reused
//!   through `#[path]`: the **real** auditd listener and writer over a log
//!   in the temporary directory.
//! * [`Front`] — the real `ldap_front::serve` on its own thread with its
//!   own current-thread runtime; its two listeners bound on 127.0.0.1 at
//!   ports the system picks (never a privileged port).
//! * [`World`] — auditd, dird (which decides the front's requests under the
//!   internal zone — the zone of the front, from its peer uid, docs/52 R14 —
//!   so the A-51 internal anonymous rootDSE grant applies), the front (whose
//!   zone table makes 127.0.0.0/8 internal: its loopback listeners and
//!   client are inside it) with the product's TLS configuration serving a
//!   real per-run certificate (tests/common/cert.rs, tests/common/tls.rs:
//!   rustls' standard verifier on the client side).
//! * [`direct`] — the LDAP engine called in-process over the same store,
//!   policy and time: the reference the replies must equal octet for octet.
//! * [`LdapReader`] and the TLS client — the client side of RFC 4511 §5.2
//!   (one PDU after another) over a TCP stream or a rustls stream.
//!
//! Sources: docs/50 R50-10, R50-16, §4.2, §9; docs/49 §5.2; RFC 4511
//! §4.1.1, §5.2. Every value is made by hand for these tests.
#![allow(dead_code, unused_imports)] // each test binary uses a different subset

#[path = "../../../directory-daemon/tests/support/mod.rs"]
pub mod dird_support;

#[path = "../../../audit-daemon/tests/common/mod.rs"]
pub mod auditd_support;

use crate::cert_support::TestPki;
use crate::tls_support::{client_config, server_config_for, server_name};
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;
use dird_support::{Dird, Directory, TempDir};
use directory_daemon::policy::DevelopmentPolicy;
use directory_daemon::{Clock, SharedClock, StoreSource};
use directory_pip::{DirectoryContext, TierMap};
use krb_proto::KerberosTime;
use ldap::{
    DirectoryInputs, Engine, EngineConfig, RateLimiter, RequestInputs, RootDseConfig, SearchClock,
    Session, TransportReport,
};
// The full parameters (the client write bound, the connection bounds) and
// their serve are the front's test seams (docs/52 C18, task R15; feature
// `test-seams`, enabled by the dev-dependency).
use ldap_front::test_seams::{serve, FrontParams};
use ldap_front::{ConnectionLimits, DaemonControl, Endpoint, Listeners, Timeouts};
use parse_ldap::{
    decode_message, encode_message, frame_length, AuthState, DecodeOptions,
    Direction as LdapDirection, Frame, LdapMessage, Profile, ProtocolOp, ResultCode,
    MAX_AUTH_MESSAGE_OCTETS,
};
use pdp::{
    Action, ActionMatch, AnonymousGrant, AuthMatch, ContextMatch, Effect, IpScope, Match,
    ResourceMatch, RlKey, Rule, RuleId, SubjectMatch, TransportSec,
};
use rustls::server::ServerConfig;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;

/// How long a test waits for anything.
pub const LONG: Duration = Duration::from_secs(10);

/// The test "now": 2026-11-13T10:00:00Z (dird's clock and the reference
/// engine's).
pub fn now() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap()
}

/// dird's clock in these tests: the fixed test time, so that the replies
/// can be compared octet for octet with the reference engine.
#[derive(Debug, Clone, Copy)]
struct FixedTime;

impl Clock for FixedTime {
    fn now(&self) -> Option<KerberosTime> {
        Some(now())
    }
}

/// The rootDSE policy of docs/49 §5.2 / Q-170 on top of dird's support
/// policy: Allow `DirRead` on the rootDSE, and the internal anonymous grant
/// with no transport minimum (A-51) — as crates/directory-daemon's LDAP
/// tests build it.
pub fn ldap_policy(version: u64) -> DevelopmentPolicy {
    let mut policy = dird_support::policy(version);
    policy.rules = vec![Rule {
        id: RuleId(1),
        effect: Effect::Allow,
        when: Match {
            action: ActionMatch::Exact(Action::DirRead),
            resource: ResourceMatch::RootDse,
            subject: SubjectMatch::Any,
            context: ContextMatch::ANY,
            auth: AuthMatch::ANY,
        },
        obligations: vec![],
    }];
    policy.anonymous = vec![AnonymousGrant::new(
        ActionMatch::Exact(Action::DirRead),
        ResourceMatch::RootDse,
        TransportSec::NONE,
        IpScope::Internal,
    )
    .unwrap()];
    policy
}

/// The front's zone table here: the loopback network is internal (test
/// data; docs/50 §4.1, docs/52 R14).
pub fn loopback_internal() -> Vec<config::Network> {
    vec![config::Network::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8).unwrap()]
}

/// The front's audit socket in `dir`: auditd's listener that records the
/// test's uid as ldap-front ([`start_auditd`]).
pub fn front_audit_socket(dir: &TempDir) -> PathBuf {
    dir.join("af.sock")
}

/// The real auditd (one writer) with its log in `logs` (a scratch directory
/// the protected-file walk accepts: crates/audit-daemon `segments`, task
/// R11b) and two listeners in `dir`: `a.sock` mapping `uid` to dird, and
/// [`front_audit_socket`] mapping `uid` to ldap-front — one uid carries one
/// source per map (docs/50 R50-3, §3.2), and the front requires its own
/// source (task R9b, docs/questions/Q-560 item 5).
pub fn start_auditd(
    dir: &TempDir,
    logs: &auditd_support::TempDir,
    uid: u32,
) -> auditd_support::Server {
    let run_as = auditd_support::other_uid(&[uid]);
    let settings = |socket: PathBuf, source: &str| {
        let text = format!(
            "run_as_uid = {run_as}\nrun_as_gid = {run_as}\naudit_socket = {}\n\
             audit_log_path = {}\nuid_sources = {uid}:{source}\nframe_timeout = 5s\n",
            socket.display(),
            logs.base().display()
        );
        config::AuditdSettings::parse(text.as_bytes()).unwrap()
    };
    let listeners = [
        settings(dir.join("a.sock"), "dird"),
        settings(front_audit_socket(dir), "ldap-front"),
    ];
    auditd_support::Server::start_many(
        &listeners,
        audit_daemon::listener::ListenerConfig::from_settings(&listeners[0]),
        64,
        true,
    )
}

/// The front's test timeouts (short, but well above a loopback exchange).
pub fn test_timeouts() -> Timeouts {
    Timeouts {
        init_recv: LONG,
        max_idle: LONG,
        tls_handshake: Duration::from_secs(5),
        dird_deadline: LONG,
        client_write: Duration::from_secs(5),
    }
}

/// The real front on its own thread.
pub struct Front {
    control: DaemonControl,
    thread: Option<JoinHandle<Result<(), String>>>,
    pub ldap: SocketAddr,
    pub ldaps: SocketAddr,
}

impl Front {
    /// Bind both listeners on 127.0.0.1 (system-chosen ports), start
    /// `serve`, and wait until it serves; a start-up failure is returned
    /// as its message.
    pub fn start(params: FrontParams, tls: Arc<ServerConfig>) -> Result<Front, String> {
        let ldap = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ldaps = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (ldap_addr, ldaps_addr) = (ldap.local_addr().unwrap(), ldaps.local_addr().unwrap());
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
                let result = runtime.block_on(serve(params, tls, listeners, control));
                drop(runtime);
                result.map_err(|e| e.to_string())
            })
        };
        let start = Instant::now();
        while !control.is_serving() {
            if thread.is_finished() {
                return Err(thread.join().unwrap().err().unwrap_or_default());
            }
            assert!(start.elapsed() < LONG, "the front did not start");
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(Front {
            control,
            thread: Some(thread),
            ldap: ldap_addr,
            ldaps: ldaps_addr,
        })
    }

    pub fn stop(mut self) -> Result<(), String> {
        self.control.stop();
        self.thread.take().unwrap().join().unwrap()
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

/// auditd, dird and the front, all real.
pub struct World {
    pub front: Front,
    pub dird: Option<Dird>,
    pub auditd: Option<auditd_support::Server>,
    pub directory: Directory,
    pub pki: TestPki,
    pub client: Arc<ClientConfig>,
    pub uid: u32,
    pub dir: TempDir,
    /// auditd's log directory (dropped last).
    pub logs: auditd_support::TempDir,
}

/// The world, after `tweak` adjusted the front's parameters; `None` as
/// root (uid 0 is never mapped, R50-3).
pub fn world(tweak: impl FnOnce(&mut FrontParams)) -> Option<World> {
    let dir = TempDir::new();
    let uid = dird_support::my_uid(&dir);
    if dird_support::skip_as_root(uid) {
        return None;
    }
    let logs = auditd_support::TempDir::new();
    let auditd = start_auditd(&dir, &logs, uid);
    let directory = Directory::standard(&dir.join("s.redb"));
    let mut params = dird_support::params(&dir, uid, uid, Duration::from_secs(5), 4);
    params.ldap_front_uid = uid;
    params.clock = SharedClock::new(FixedTime);
    let dird = Dird::start(
        params,
        directory_daemon::test_seams::opened(Arc::clone(&directory.store)),
        ldap_policy(1),
    )
    .unwrap();
    let pki = crate::tls_support::pki();
    let mut front_params = FrontParams {
        dird: Endpoint {
            socket: dird.ldap_socket.clone(),
            uid,
        },
        audit: Endpoint {
            socket: front_audit_socket(&dir),
            uid,
        },
        timeouts: test_timeouts(),
        limits: ConnectionLimits::DEFAULT,
        internal_networks: loopback_internal(),
    };
    tweak(&mut front_params);
    let front = Front::start(front_params, server_config_for(&pki)).unwrap();
    let client = client_config(&pki);
    Some(World {
        front,
        dird: Some(dird),
        auditd: Some(auditd),
        directory,
        pki,
        client,
        uid,
        dir,
        logs,
    })
}

struct AdmitAll;

impl RateLimiter for AdmitAll {
    fn admit(&mut self, _key: &RlKey, _now: &KerberosTime) -> bool {
        true
    }
}

struct FixedSearchClock;

impl SearchClock for FixedSearchClock {
    fn now(&self) -> KerberosTime {
        now()
    }
}

/// The engine called directly over the same store and policy, as dird
/// calls it (the reference path of docs/50 §9).
pub fn direct(
    world: &World,
    session: &mut Session,
    message: &[u8],
    tls: bool,
    input_pending: bool,
) -> ldap::Outcome {
    let policy = ldap_policy(1);
    let snapshot = policy.snapshot().unwrap();
    let tiers = TierMap::empty();
    let ctx = DirectoryContext::new(
        ad_schema::phase1().unwrap(),
        &dird_support::keyd_config(),
        dird_support::naming_context(),
    )
    .unwrap();
    let view = ctx.view(&world.directory.store, &tiers).unwrap();
    let engine = Engine::new(EngineConfig {
        root_dse: RootDseConfig {
            naming_context: dird_support::naming_context(),
            dns_host_name: String::from("dc1.example.org"),
        },
    })
    .unwrap();
    let mut rate = AdmitAll;
    engine.handle(
        session,
        message,
        RequestInputs {
            snapshot: &snapshot,
            pip: &view,
            subjects: &view,
            rate: &mut rate,
            now: now(),
            transport: TransportReport {
                src_net: IpScope::Internal,
                tls_established: tls,
                input_pending,
            },
            directory: Some(DirectoryInputs {
                view: directory_pip::PepView::new(&view),
                clock: &FixedSearchClock,
            }),
        },
    )
}

/// Reads one LDAPMessage at a time from a stream (RFC 4511 §5.2), keeping
/// what follows it.
#[derive(Default)]
pub struct LdapReader {
    buffer: Vec<u8>,
}

impl LdapReader {
    /// The next message, or `None` at the end of the stream (or garbage).
    pub fn next<R: Read>(&mut self, stream: &mut R) -> Option<Vec<u8>> {
        loop {
            match frame_length(&self.buffer, AuthState::Authenticated) {
                Ok(Frame::Complete { length }) => {
                    return Some(self.buffer.drain(..length).collect());
                }
                Ok(Frame::NeedMore) => {}
                Err(_) => return None,
            }
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(read) => self.buffer.extend_from_slice(&chunk[..read]),
            }
        }
    }

    /// Whether nothing is left over.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

/// Whether the peer closed `stream` (end of stream, a reset, or a TLS
/// closure) within [`LONG`], with no further octet; `Some(octets)` if
/// octets came instead.
pub fn closed<R: Read>(stream: &mut R) -> Result<(), Vec<u8>> {
    let mut chunk = [0u8; 1024];
    match stream.read(&mut chunk) {
        Ok(0) => Ok(()),
        Ok(read) => Err(chunk[..read].to_vec()),
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            Err(b"still open".to_vec())
        }
        Err(_) => Ok(()),
    }
}

/// A TCP connection to `address` with [`LONG`] read/write timeouts.
pub fn tcp(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(LONG)).unwrap();
    stream.set_write_timeout(Some(LONG)).unwrap();
    stream
}

/// A TLS client stream over `stream`, the handshake completed (or the
/// error).
pub fn tls_over(
    stream: TcpStream,
    config: &Arc<ClientConfig>,
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let mut connection =
        ClientConnection::new(Arc::clone(config), server_name()).map_err(|e| e.to_string())?;
    let mut stream = stream;
    while connection.is_handshaking() {
        connection
            .complete_io(&mut stream)
            .map_err(|e| e.to_string())?;
    }
    Ok(StreamOwned::new(connection, stream))
}

/// An LDAPMessage of `protocol_op` with messageID `id`, canonical.
pub fn encoded(id: u32, protocol_op: ProtocolOp) -> Vec<u8> {
    encode_message(&LdapMessage {
        message_id: parse_ldap::MessageId::new(id).unwrap(),
        protocol_op,
        controls: None,
    })
    .unwrap()
}

/// The rootDSE search (RFC 4511 §4.5.1; RFC 4512 §5.1).
pub fn root_dse(id: u32) -> Vec<u8> {
    encoded(
        id,
        ProtocolOp::SearchRequest(parse_ldap::SearchRequest {
            base_object: String::new(),
            scope: parse_ldap::Scope::BaseObject,
            deref_aliases: parse_ldap::DerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: parse_ldap::Filter::Present("objectClass".to_owned()),
            attributes: vec![],
        }),
    )
}

/// StartTLS (RFC 4511 §4.14.1).
pub fn start_tls(id: u32) -> Vec<u8> {
    encoded(
        id,
        ProtocolOp::ExtendedRequest(parse_ldap::ExtendedRequest {
            request_name: parse_ldap::START_TLS_OID.to_owned(),
            request_value: None,
        }),
    )
}

/// The decoded response (canonical profile, response direction).
pub fn decoded(response: &[u8]) -> LdapMessage {
    decode_message(
        response,
        &DecodeOptions {
            direction: LdapDirection::Response,
            profile: Profile::Canonical,
            max_message_octets: MAX_AUTH_MESSAGE_OCTETS,
        },
    )
    .unwrap()
}

/// The resultCode of an LDAPResult-bearing response.
pub fn result_code(response: &[u8]) -> ResultCode {
    match decoded(response).protocol_op {
        ProtocolOp::SearchResultDone(result) => result.result_code,
        ProtocolOp::ExtendedResponse(response) => response.result.result_code,
        ProtocolOp::BindResponse(response) => response.result.result_code,
        other => panic!("{other:?}"),
    }
}

/// The Notice of Disconnection with `code` (RFC 4511 §4.4.1), canonical.
pub fn notice(code: ResultCode) -> Vec<u8> {
    encode_message(&LdapMessage::notice_of_disconnection(code)).unwrap()
}
