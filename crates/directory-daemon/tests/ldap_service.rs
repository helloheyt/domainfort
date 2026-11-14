//! Tier 2 (docs/50 §9: "real servers run in the test's threads; Unix sockets
//! in a unique temporary directory (0700); the uid map is injected with the
//! test's own uid"): dird's LDAP service on `dird-ldap.sock`, reached by the
//! front's real client (`ipc_ldap::LdapChannelClient`) over the real socket.
//!
//! * the anonymous rootDSE end to end, octet for octet the engine's, with
//!   its audit event delivered to auditd;
//! * a peer that is not ldap-front is closed without a reply;
//! * one session per connection (StartTLS on one leaves the other alone);
//! * a full LDAP engine queue answers `Busy` and the front closes;
//! * the bound on concurrent sessions;
//! * dird down → the front's client reports the closure (and its Notice of
//!   Disconnection says unavailable);
//! * `TlsEstablished` before StartTLS is refused (the session rules);
//! * auditd unreachable → LDAP operations refused (A-57).
//!
//! Real peer credentials on both sides; the only injection is dird's clock
//! (a clock that can hold the LDAP engine thread, the kdc daemon's tier-2
//! pattern) and the parameters.
//!
//! Sources: docs/50 R50-3, R50-7, R50-10, R50-16, R50-17, §3.2, §3.3, §3.6,
//! §3.7, §4.2, §4.3, §8.1, §9; docs/49 R49-14, R49-16, §4.4, §5.2; RFC 4511
//! §4.4.1, §4.5.1, §4.14.1, App. A; docs/questions Q-218 (A-57), Q-252
//! item 8 (A-64), Q-280. Every value is hand-made.

mod support;

use core::net::{IpAddr, Ipv4Addr};
use core::time::Duration;
use directory_daemon::policy::DevelopmentPolicy;
use directory_daemon::{ldap_refused_peer_count, Clock, DaemonParams, SharedClock, StoreSource};
use directory_pip::{DirectoryContext, TierMap};
use ipc::{encode_frame, Direction, FrameReader, Refused, Reply};
use ipc_audit::EventBody;
use ipc_ldap::{
    notice_of_disconnection, ChannelFailure, ConnectionAction, LdapChannelClient, LdapReply,
    LdapRequest, Listener, TransportError, TransportFacts, LDAP_CHANNEL, REPLY_LIMIT,
};
use krb_proto::KerberosTime;
use ldap::{
    DirectoryInputs, Engine, EngineConfig, RateLimiter, RequestInputs, RootDseConfig, SearchClock,
    Session, TransportReport,
};
use parse_ldap::{
    decode_message, encode_message, DecodeOptions, DerefAliases, Direction as LdapDirection,
    ExtendedRequest, Filter, LdapMessage, MessageId, Profile, ProtocolOp, ResultCode, Scope,
    SearchRequest, MAX_AUTH_MESSAGE_OCTETS, START_TLS_OID,
};
use pdp::{
    Action, ActionMatch, AnonymousGrant, AuthMatch, ContextMatch, Effect, IpScope, Match,
    ResourceMatch, RlKey, Rule, RuleId, SubjectMatch, TransportSec,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use support::{eventually, Dird, Directory, FakeAuditd, TempDir};

/// The front's side of `dird-ldap.sock`. On Linux the front's own connector
/// (`ipc_ldap::UnixConnector`, rustix peer credentials, R50-3); elsewhere
/// (rustix `socket_peercred` is Linux-only — Q-245 item 11) a connector that
/// reads dird's uid through tokio `UnixStream::peer_cred` (the support
/// module's `connect_checked`) and hands the stream to the blocking
/// connection — so the same server-uid check is made on every host.
#[cfg(target_os = "linux")]
mod connector {
    pub type LdapConnector = ipc_ldap::UnixConnector;

    pub fn ldap(path: &std::path::Path) -> LdapConnector {
        ipc_ldap::UnixConnector::new(path.to_path_buf())
    }
}

#[cfg(not(target_os = "linux"))]
mod connector {
    use crate::support::connector::{connect_checked, runtime};
    use ipc::FrameLimit;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use zeroize::Zeroizing;

    pub struct LdapConnector {
        path: PathBuf,
        runtime: tokio::runtime::Runtime,
    }

    pub struct LdapChecked {
        uid: u32,
        inner: ipc_ldap::UnixConnection,
    }

    pub fn ldap(path: &Path) -> LdapConnector {
        LdapConnector {
            path: path.to_path_buf(),
            runtime: runtime(),
        }
    }

    impl ipc_ldap::Connector for LdapConnector {
        type Connection = LdapChecked;
        fn connect(&mut self) -> Result<LdapChecked, ipc_ldap::TransportError> {
            let (uid, stream) = connect_checked(&self.path, &self.runtime)
                .ok_or(ipc_ldap::TransportError::Connect)?;
            Ok(LdapChecked {
                uid,
                inner: ipc_ldap::UnixConnection::from_stream(stream),
            })
        }
    }

    impl ipc_ldap::Connection for LdapChecked {
        fn peer_uid(&self) -> Result<u32, ipc_ldap::TransportError> {
            Ok(self.uid)
        }
        fn send(
            &mut self,
            frame: &[u8],
            deadline: Duration,
        ) -> Result<(), ipc_ldap::TransportError> {
            self.inner.send(frame, deadline)
        }
        fn receive(
            &mut self,
            limit: FrameLimit,
            deadline: Duration,
        ) -> Result<Zeroizing<Vec<u8>>, ipc_ldap::TransportError> {
            self.inner.receive(limit, deadline)
        }
    }
}

const LONG: Duration = Duration::from_secs(10);
const CLEAR: TransportFacts = TransportFacts {
    tls_established: false,
    input_pending: false,
};
const TLS: TransportFacts = TransportFacts {
    tls_established: true,
    input_pending: false,
};

/// The test "now": 2026-11-13T10:00:00Z.
fn now() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap()
}

/// dird's clock in these tests: a fixed time that the test can hold, so
/// that the LDAP engine thread waits inside a request (docs/50 §9; the kdc
/// daemon's tier-2 pattern).
#[derive(Clone, Default)]
struct HoldClock {
    held: Arc<(Mutex<bool>, Condvar)>,
    entered: Arc<AtomicU64>,
}

impl HoldClock {
    fn hold(&self) {
        *self.held.0.lock().unwrap() = true;
    }
    fn release(&self) {
        *self.held.0.lock().unwrap() = false;
        self.held.1.notify_all();
    }
    fn entered(&self) -> u64 {
        self.entered.load(Ordering::SeqCst)
    }
}

impl Clock for HoldClock {
    fn now(&self) -> Option<KerberosTime> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let (lock, wake) = &*self.held;
        let mut held = lock.lock().ok()?;
        while *held {
            held = wake.wait(held).ok()?;
        }
        Some(now())
    }
}

/// The rootDSE policy of docs/49 §5.2 / Q-170 on top of the support policy:
/// an Allow rule for `DirRead` on the rootDSE and the internal anonymous
/// grant with no transport minimum (A-51).
fn ldap_policy(version: u64) -> DevelopmentPolicy {
    let mut policy = support::policy(version);
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

struct World {
    dir: TempDir,
    uid: u32,
    directory: Directory,
    auditd: FakeAuditd,
    dird: Dird,
    clock: HoldClock,
}

/// dird with the LDAP channel for `uid + front_uid_offset`, after `tweak`.
fn world(front_uid_offset: u32, tweak: impl FnOnce(&mut DaemonParams)) -> Option<World> {
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
    if support::skip_as_root(uid) {
        return None;
    }
    let directory = Directory::standard(&dir.join("s.redb"));
    let auditd = FakeAuditd::start(&dir.join("a.sock"));
    let clock = HoldClock::default();
    let mut params = support::params(&dir, uid, uid, Duration::from_secs(5), 4);
    params.ldap_front_uid = uid + front_uid_offset;
    params.clock = SharedClock::new(clock.clone());
    tweak(&mut params);
    let dird = Dird::start(
        params,
        StoreSource::Opened(Arc::clone(&directory.store)),
        ldap_policy(1),
    )
    .unwrap();
    Some(World {
        dir,
        uid,
        directory,
        auditd,
        dird,
        clock,
    })
}

fn peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))
}

type Client = LdapChannelClient<<connector::LdapConnector as ipc_ldap::Connector>::Connection>;

fn open(w: &World, listener: Listener) -> Result<Client, ChannelFailure> {
    let mut connector = connector::ldap(&w.dird.ldap_socket);
    LdapChannelClient::open(&mut connector, w.uid, listener, peer(), LONG)
        .map(|(client, _framing)| client)
}

fn id(n: u32) -> MessageId {
    MessageId::new(n).unwrap()
}

fn encoded(n: u32, protocol_op: ProtocolOp) -> Vec<u8> {
    encode_message(&LdapMessage {
        message_id: id(n),
        protocol_op,
        controls: None,
    })
    .unwrap()
}

/// A rootDSE search (RFC 4512 §5.1; docs/49 §5.2).
fn root_dse(n: u32) -> Vec<u8> {
    encoded(
        n,
        ProtocolOp::SearchRequest(SearchRequest {
            base_object: String::new(),
            scope: Scope::BaseObject,
            deref_aliases: DerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::Present("objectClass".to_owned()),
            attributes: vec![],
        }),
    )
}

/// StartTLS (RFC 4511 §4.14.1).
fn start_tls(n: u32) -> Vec<u8> {
    encoded(
        n,
        ProtocolOp::ExtendedRequest(ExtendedRequest {
            request_name: START_TLS_OID.to_owned(),
            request_value: None,
        }),
    )
}

/// The resultCode of the last response (an LDAPResult-bearing one).
fn last_code(responses: &[Vec<u8>]) -> ResultCode {
    let msg = decode_message(
        responses.last().unwrap(),
        &DecodeOptions {
            direction: LdapDirection::Response,
            profile: Profile::Canonical,
            max_message_octets: MAX_AUTH_MESSAGE_OCTETS,
        },
    )
    .unwrap();
    match msg.protocol_op {
        ProtocolOp::SearchResultDone(result) => result.result_code,
        ProtocolOp::ExtendedResponse(response) => response.result.result_code,
        ProtocolOp::BindResponse(response) => response.result.result_code,
        other => panic!("{other:?}"),
    }
}

/// The LDAP events auditd received so far.
fn ldap_events(w: &World) -> Vec<ipc_audit::LdapEvent> {
    w.auditd
        .events()
        .into_iter()
        .filter_map(|event| match event {
            EventBody::Ldap(event) => Some(*event),
            _ => None,
        })
        .collect()
}

struct AdmitAll;

impl RateLimiter for AdmitAll {
    fn admit(&mut self, _key: &RlKey, _now: &KerberosTime) -> bool {
        true
    }
}

struct FixedClock;

impl SearchClock for FixedClock {
    fn now(&self) -> KerberosTime {
        now()
    }
}

/// The engine called directly over the same store and policy (the
/// reference path of docs/50 §9 tier 1, here against the tier-2 replies).
fn direct(w: &World, session: &mut Session, message: &[u8], tls: bool) -> ldap::Outcome {
    let policy = ldap_policy(1);
    let snapshot = policy.snapshot().unwrap();
    let tiers = TierMap::empty();
    let ctx = DirectoryContext::new(
        ad_schema::phase1().unwrap(),
        &support::keyd_config(),
        support::naming_context(),
    )
    .unwrap();
    let view = ctx.view(&w.directory.store, &tiers).unwrap();
    let engine = Engine::new(EngineConfig {
        root_dse: RootDseConfig {
            naming_context: support::naming_context(),
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
            accounts: &view,
            rate: &mut rate,
            now: now(),
            transport: TransportReport {
                src_net: IpScope::Internal,
                tls_established: tls,
                input_pending: false,
            },
            directory: Some(DirectoryInputs {
                view: directory_pip::PepView::new(&view),
                clock: &FixedClock,
            }),
        },
    )
}

/// Read one reply frame body from a raw stream, or `None` at the end.
fn read_reply(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut reader = FrameReader::new(REPLY_LIMIT);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(body) = reader.body() {
            return Some(body.to_vec());
        }
        let wanted = reader.wanted().min(chunk.len());
        match stream.read(&mut chunk[..wanted]) {
            Ok(0) | Err(_) => return None,
            Ok(n) => {
                reader.push(&chunk[..n]).ok()?;
            }
        }
    }
}

fn request_frame(request: &LdapRequest) -> Vec<u8> {
    encode_frame(LDAP_CHANNEL, Direction::Request, request)
        .unwrap()
        .as_bytes()
        .to_vec()
}

/// docs/50 R50-10, §4.2; docs/49 §5.2 (R49-10), R49-14; R50-17: the
/// anonymous rootDSE through the real socket — the responses are octet for
/// octet the engine's over the same store and policy, the framing state
/// unauthenticated, and the operation's audit event reaches auditd with
/// dird's connection id.
#[test]
fn the_anonymous_root_dse_over_the_socket() {
    let Some(w) = world(0, |_| {}) else {
        return;
    };
    let mut client = open(&w, Listener::Ldap).unwrap();
    let exchange = client.message(&root_dse(1), CLEAR).unwrap();
    assert_eq!(exchange.action, ConnectionAction::Continue);
    assert_eq!(exchange.responses.len(), 2);
    assert_eq!(last_code(&exchange.responses), ResultCode::Success);
    let mut session = Session::new(1, ldap::Listener::Ldap);
    let outcome = direct(&w, &mut session, &root_dse(1), false);
    assert_eq!(exchange.responses, outcome.responses);
    assert!(
        eventually(LONG, || !ldap_events(&w).is_empty()),
        "the LDAP event reached auditd"
    );
    let events = ldap_events(&w);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].message_id, Some(1));
    client.close();
    let _ = w.dir.path();
    w.dird.stop().unwrap();
}

/// docs/50 R50-3, §3.2 ("dird-ldap.sock ← ldap-front"; an unmapped uid ⇒
/// the connection is closed): dird configured for another front uid closes
/// the test's connection without any reply; the front's client sees the
/// transport closed.
#[test]
fn a_peer_that_is_not_the_front_is_closed_without_a_reply() {
    let Some(w) = world(1, |_| {}) else {
        return;
    };
    let before = ldap_refused_peer_count();
    let mut raw = UnixStream::connect(&w.dird.ldap_socket).unwrap();
    raw.set_read_timeout(Some(LONG)).unwrap();
    let _ = raw.write_all(&request_frame(&LdapRequest::Open {
        listener: Listener::Ldap,
        peer_addr: peer(),
    }));
    let mut octets = Vec::new();
    let _ = raw.read_to_end(&mut octets);
    assert!(octets.is_empty(), "no reply to a refused peer");
    assert!(ldap_refused_peer_count() > before);
    assert!(matches!(
        open(&w, Listener::Ldap).err(),
        Some(ChannelFailure::Transport(
            TransportError::Closed | TransportError::Io
        ))
    ));
}

/// docs/50 R50-10 ("one Unix connection to dird per client connection;
/// dird creates `ldap::Session` per connection"): StartTLS on one session
/// leaves the other in cleartext; each has its own connection id in the
/// audit events.
#[test]
fn one_session_per_connection() {
    let Some(w) = world(0, |_| {}) else {
        return;
    };
    let mut first = open(&w, Listener::Ldap).unwrap();
    let mut second = open(&w, Listener::Ldap).unwrap();
    let started = first.message(&start_tls(1), CLEAR).unwrap();
    assert_eq!(started.action, ConnectionAction::StartTls);
    let cleartext = second.message(&root_dse(1), CLEAR).unwrap();
    assert_eq!(cleartext.action, ConnectionAction::Continue);
    assert_eq!(last_code(&cleartext.responses), ResultCode::Success);
    first.tls_established().unwrap();
    let protected = first.message(&root_dse(2), TLS).unwrap();
    assert_eq!(last_code(&protected.responses), ResultCode::Success);
    assert!(eventually(LONG, || ldap_events(&w).len() == 3));
    let events = ldap_events(&w);
    let mut ids: Vec<u64> = events.iter().map(|e| e.connection_id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 2, "two sessions, two connection ids");
}

/// Releases the clock when dropped.
struct Release(HoldClock);

impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// docs/50 R50-7 ("a bounded queue, `Busy` when full"), §4.2; docs/50 §3.7:
/// with the LDAP engine held inside a request and a queue of one, of two
/// further requests one is queued and the other refused `Busy` — the front
/// reads a failure whose notice is busy (51); once the engine runs again
/// every queued request is answered.
#[test]
fn a_full_queue_answers_busy() {
    let Some(w) = world(0, |p| p.ldap_queue_capacity = 1) else {
        return;
    };
    let mut a = open(&w, Listener::Ldap).unwrap();
    let b = open(&w, Listener::Ldap).unwrap();
    let c = open(&w, Listener::Ldap).unwrap();
    w.clock.hold();
    // Whatever happens below, the engine is released (a failed assertion
    // must not leave dird's LDAP thread held while the world is dropped).
    let _release = Release(w.clock.clone());
    let entered = w.clock.entered();
    let first = std::thread::spawn(move || a.message(&root_dse(1), CLEAR));
    assert!(
        eventually(LONG, || w.clock.entered() > entered),
        "engine held"
    );
    let busy_seen = Arc::new(AtomicBool::new(false));
    let spawn = |mut client: Client, flag: Arc<AtomicBool>| {
        std::thread::spawn(move || {
            let result = client.message(&root_dse(2), CLEAR);
            if matches!(result, Err(ChannelFailure::Refused(Refused::Busy))) {
                flag.store(true, Ordering::SeqCst);
            }
            result
        })
    };
    let second = spawn(b, Arc::clone(&busy_seen));
    let third = spawn(c, Arc::clone(&busy_seen));
    let seen = eventually(LONG, || busy_seen.load(Ordering::SeqCst));
    w.clock.release();
    let results = [second.join().unwrap(), third.join().unwrap()];
    assert!(seen, "one request refused Busy: {results:?}");
    assert!(first.join().unwrap().is_ok());
    let busy: Vec<&ChannelFailure> = results.iter().filter_map(|r| r.as_ref().err()).collect();
    assert_eq!(busy, vec![&ChannelFailure::Refused(Refused::Busy)]);
    assert!(notice_of_disconnection(busy[0]).is_some());
    assert_eq!(busy[0].notice_code(), ResultCode::Busy);
    assert!(results.iter().any(|r| r.is_ok()), "the queued one answered");
}

/// docs/50 §4.2 (dird bounds its sessions itself): with a bound of one
/// session, a second connection is refused `Busy` and closed; once the first
/// session ends, a new one is accepted.
#[test]
fn the_session_bound() {
    let Some(w) = world(0, |p| p.max_ldap_sessions = 1) else {
        return;
    };
    let first = open(&w, Listener::Ldap).unwrap();
    assert_eq!(
        open(&w, Listener::Ldap).err(),
        Some(ChannelFailure::Refused(Refused::Busy))
    );
    first.close();
    assert!(
        eventually(LONG, || open(&w, Listener::Ldap).is_ok()),
        "a session again after the first ended"
    );
}

/// docs/50 §3.7 ("ldap-front without dird ⇒ the connection is closed (no
/// answer without a PEP)"); RFC 4511 §4.4.1, App. A: once dird stops, an open
/// session's next message fails (refused `Unavailable`, or the connection
/// closed), and a new session cannot be opened — the notice the front sends
/// says unavailable (52).
#[test]
fn dird_down_the_front_reports_closure() {
    let Some(w) = world(0, |_| {}) else {
        return;
    };
    let mut client = open(&w, Listener::Ldaps).unwrap();
    assert!(client.message(&root_dse(1), TLS).is_ok());
    let World { dird, dir, .. } = w;
    let socket = dird.ldap_socket.clone();
    dird.stop().unwrap();
    let failure = client.message(&root_dse(2), TLS).unwrap_err();
    assert!(
        matches!(
            failure,
            ChannelFailure::Refused(Refused::Unavailable)
                | ChannelFailure::Transport(TransportError::Closed | TransportError::Io)
        ),
        "{failure:?}"
    );
    assert_eq!(failure.notice_code(), ResultCode::Unavailable);
    let mut connector = connector::ldap(&socket);
    let failure =
        LdapChannelClient::open(&mut connector, 1, Listener::Ldap, peer(), LONG).unwrap_err();
    assert_eq!(failure, ChannelFailure::Transport(TransportError::Connect));
    assert!(notice_of_disconnection(&failure).is_some());
    drop(dir);
}

/// docs/50 §4.3; docs/49 §4.4; crates/ldap session.rs (TLS only through
/// LDAPS or a successful StartTLS): a `TlsEstablished` before any StartTLS
/// is refused by dird (`Malformed`) and the connection closes; the front's
/// own state machine refuses to send it at all.
#[test]
fn tls_established_before_start_tls_is_refused() {
    let Some(w) = world(0, |_| {}) else {
        return;
    };
    let mut raw = UnixStream::connect(&w.dird.ldap_socket).unwrap();
    raw.set_read_timeout(Some(LONG)).unwrap();
    raw.write_all(&request_frame(&LdapRequest::Open {
        listener: Listener::Ldap,
        peer_addr: peer(),
    }))
    .unwrap();
    let opened = read_reply(&mut raw).unwrap();
    assert!(matches!(
        ipc::decode_reply::<LdapReply>(LDAP_CHANNEL, &opened).unwrap(),
        Reply::Message(LdapReply::Opened { .. })
    ));
    raw.write_all(&request_frame(&LdapRequest::TlsEstablished))
        .unwrap();
    let refused = read_reply(&mut raw).unwrap();
    assert_eq!(
        ipc::decode_reply::<LdapReply>(LDAP_CHANNEL, &refused).unwrap(),
        Reply::Refused(Refused::Malformed)
    );
    assert!(read_reply(&mut raw).is_none(), "closed after the refusal");

    let mut client = open(&w, Listener::Ldap).unwrap();
    assert_eq!(
        client.tls_established().err(),
        Some(ChannelFailure::OutOfSequence)
    );
}

/// docs/50 §8.1; docs/questions Q-218 (A-57), Q-252 item 8 (A-64: LDAP
/// operations gate on the audit window): once auditd is gone, an LDAP
/// operation is refused `Unavailable` (not performed), while nothing stops
/// the process.
#[test]
fn auditd_unreachable_refuses_ldap_operations() {
    let Some(mut w) = world(0, |_| {}) else {
        return;
    };
    let mut client = open(&w, Listener::Ldap).unwrap();
    assert!(client.message(&root_dse(1), CLEAR).is_ok());
    w.auditd.stop();
    assert!(
        eventually(LONG, || {
            match open(&w, Listener::Ldap) {
                Ok(mut probe) => matches!(
                    probe.message(&root_dse(1), CLEAR),
                    Err(ChannelFailure::Refused(Refused::Unavailable))
                ),
                Err(_) => false,
            }
        }),
        "LDAP refused while auditd is unreachable"
    );
}

// ---- the stop and the audit window (docs/questions/Q-313) -------------------------

/// An auditd for the stop tests, written from the audit channel's message
/// set (crates/ipc-audit): `Ping` → `Pong` at once; `Append` → its events
/// kept and its `Ack` sent only after `ack_delay` — or, with `None`, the
/// `Append` is read and never answered.
struct SlowAuditd {
    path: std::path::PathBuf,
    acknowledged: Arc<Mutex<Vec<EventBody>>>,
    appends: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<UnixStream>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SlowAuditd {
    fn start(path: &std::path::Path, ack_delay: Option<Duration>) -> SlowAuditd {
        let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let acknowledged = Arc::new(Mutex::new(Vec::new()));
        let appends = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let thread = {
            let (acknowledged, appends, stop, connections) = (
                Arc::clone(&acknowledged),
                Arc::clone(&appends),
                Arc::clone(&stop),
                Arc::clone(&connections),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            connections
                                .lock()
                                .unwrap()
                                .push(stream.try_clone().unwrap());
                            let (acknowledged, appends) =
                                (Arc::clone(&acknowledged), Arc::clone(&appends));
                            std::thread::spawn(move || {
                                serve_slowly(stream, ack_delay, &acknowledged, &appends)
                            });
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(5)),
                    }
                }
            })
        };
        SlowAuditd {
            path: path.to_path_buf(),
            acknowledged,
            appends,
            stop,
            connections,
            thread: Some(thread),
        }
    }

    /// The LDAP events of every acknowledged `Append`.
    fn acknowledged_ldap_events(&self) -> Vec<ipc_audit::LdapEvent> {
        self.acknowledged
            .lock()
            .unwrap()
            .iter()
            .filter_map(|event| match event {
                EventBody::Ldap(event) => Some((**event).clone()),
                _ => None,
            })
            .collect()
    }
}

impl Drop for SlowAuditd {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        for stream in self.connections.lock().unwrap().drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// One connection of [`SlowAuditd`].
fn serve_slowly(
    mut stream: UnixStream,
    ack_delay: Option<Duration>,
    acknowledged: &Mutex<Vec<EventBody>>,
    appends: &AtomicU64,
) {
    loop {
        let mut reader = FrameReader::new(ipc_audit::AUDIT_CHANNEL.limit(Direction::Request));
        let mut chunk = [0u8; 4096];
        let body = loop {
            if let Some(body) = reader.body() {
                break body.to_vec();
            }
            let wanted = reader.wanted().min(chunk.len());
            match stream.read(&mut chunk[..wanted]) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if reader.push(&chunk[..n]).is_err() {
                        return;
                    }
                }
            }
        };
        let reply = match ipc_audit::decode_request(&body) {
            Ok(ipc_audit::AuditRequest::Ping) => ipc_audit::AuditReply::Pong,
            Ok(ipc_audit::AuditRequest::Append(append)) => {
                appends.fetch_add(1, Ordering::SeqCst);
                let Some(delay) = ack_delay else {
                    continue;
                };
                std::thread::sleep(delay);
                let mut held = acknowledged.lock().unwrap();
                for event in append.events() {
                    held.push(ipc_audit::decode_event(event.as_bytes()).unwrap());
                }
                ipc_audit::AuditReply::Ack(ipc_audit::Ack {
                    through_seq: append.last_seq(),
                    head_hash: [0; 32],
                })
            }
            Err(_) => return,
        };
        let frame = ipc_audit::encode_reply(&Reply::Message(reply)).unwrap();
        if stream.write_all(frame.as_bytes()).is_err() {
            return;
        }
    }
}

/// How long the slow auditd holds each acknowledgement: well above a
/// loopback exchange, well below the stop's bound. Test data.
const ACK_DELAY: Duration = Duration::from_millis(400);

/// docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57), Q-252 item 9 (A-64),
/// Q-313 (A-82): an LDAP operation answered just before dird is stopped —
/// its event committed to the window, its acknowledgement still held by
/// auditd — is acknowledged before the stop returns: dird's stop waits
/// (bounded by `AUDIT_FLUSH_GRACE`) for auditd, reports no unacknowledged
/// event, and the event is in auditd's hands.
#[test]
fn a_stop_waits_for_auditd_to_acknowledge_the_ldap_events() {
    let dir = TempDir::new();
    let slow_path = dir.join("slow.sock");
    let slow = SlowAuditd::start(&slow_path, Some(ACK_DELAY));
    let Some(w) = world(0, |params| params.audit.socket = slow_path.clone()) else {
        return;
    };
    let mut client = open(&w, Listener::Ldap).unwrap();
    let exchange = client.message(&root_dse(1), CLEAR).unwrap();
    assert_eq!(last_code(&exchange.responses), ResultCode::Success);
    client.close();
    let World { dird, .. } = w;
    let start = std::time::Instant::now();
    assert_eq!(dird.stop_counting(), Ok(0), "nothing left unacknowledged");
    assert!(start.elapsed() < directory_daemon::AUDIT_FLUSH_GRACE + LONG);
    let events = slow.acknowledged_ldap_events();
    assert_eq!(events.len(), 1, "the event reached auditd before the stop");
    assert_eq!(events[0].message_id, Some(1));
}

/// docs/50 §8.1; Q-252 item 9 (the loss is bounded by the window), Q-313
/// (A-82: "reports how many events were not acknowledged"): auditd takes
/// the `Append` and never answers — the stop ends after its bound and
/// reports the one event left unacknowledged.
#[test]
fn a_stop_reports_the_ldap_events_auditd_did_not_acknowledge() {
    let dir = TempDir::new();
    let silent_path = dir.join("silent.sock");
    let silent = SlowAuditd::start(&silent_path, None);
    let Some(w) = world(0, |params| params.audit.socket = silent_path.clone()) else {
        return;
    };
    let mut client = open(&w, Listener::Ldap).unwrap();
    assert!(client.message(&root_dse(1), CLEAR).is_ok());
    client.close();
    assert!(
        eventually(LONG, || silent.appends.load(Ordering::SeqCst) >= 1),
        "dird sent the event"
    );
    let World { dird, .. } = w;
    let start = std::time::Instant::now();
    assert_eq!(dird.stop_counting(), Ok(1), "one event unacknowledged");
    assert!(start.elapsed() < directory_daemon::AUDIT_FLUSH_GRACE + LONG);
    assert!(silent.acknowledged_ldap_events().is_empty());
}
