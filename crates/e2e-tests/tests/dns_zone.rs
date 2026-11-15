//! End to end (tasks DN10a, DN10b; docs/54 §4.6, §4.8, §10 rows DN10 / DN13 /
//! DN14): a domain made by `provision domain`, then auditd, dird and dnsd
//! over their real sockets — dnsd fetches the zone image from dird over
//! `dird-dns.sock` and answers SOA, NS, the SRV set and the DC's A record
//! over real UDP and TCP sockets.
//!
//! # What runs (docs/50 §7.5; docs/54 §4.8: auditd → dird → dnsd)
//!
//! 1. **`provision domain`** as a library (crates/provision `provision_domain`
//!    with the recording installer of its tests — never root), into a 0700
//!    scratch directory: the database, the integrity key, the policy and the
//!    configuration files — dird's with its DNS channel and zone values,
//!    dnsd's naming the same `dird-dns.sock` (docs/questions/Q-1003 item 1).
//! 2. **The DC's host record — written by `provision domain` itself** (task
//!    DN10b; docs/54 §3.1: "written in `provision domain` only"): the input's
//!    `--dc-address` 192.0.2.10 (inside the internal network 192.0.2.0/24,
//!    hence in dird's registrable networks) goes with the DC account's create
//!    through the provisioning session, given the zone, and the one checker's
//!    host-record rule; that commit takes the zone serial (docs/questions/
//!    Q-1003 item 2, Q-1014). The test only reads the produced store to see
//!    it there (no write: the DN10a stand-in that wrote the record directly
//!    is gone).
//! 3. **auditd** — the real listener and writer on the produced log, one
//!    listener per sender (dird's, dnsd's) naming the test uid as that sender
//!    (tests/support `labelled_auditd_settings`; task R9b).
//! 4. **dird** — its serving parameters and DNS parameters from the produced
//!    file through its own product constructors (`startup::params`,
//!    `startup::dns_params`), the produced database, key and policy through
//!    its own readers; injected: the test uid as each peer's (kdc, ldap-front,
//!    auditd, **dnsd**). Its DNS service's start advances the zone serial
//!    once through the one checker, the decision acknowledged by the real
//!    auditd (task DN10b; docs/questions/Q-1002 item 4 (b)).
//! 5. **dnsd** — its parameters from the produced file
//!    (`DaemonParams::from_settings`), the test uid as dird's and auditd's;
//!    its UDP socket and TCP listener on 127.0.0.1 at system-chosen ports
//!    (inside the produced `internal_networks`); its two connections to the
//!    produced `dird-dns.sock` read dird's uid through tokio
//!    `UnixStream::peer_cred` (rustix `socket_peercred` is Linux-only — the
//!    tests/support pattern, Q-245 item 11).
//!
//! # Identity: one test uid (A-82)
//!
//! As every e2e world: the configuration files cannot name one uid for two
//! roles, so the produced files give the paths and settings and the uids are
//! injected. The negative test starts dird with the **produced** dnsd uid
//! (61009, a fake account) instead, so the test's own connections — dnsd's
//! among them — are not dnsd's.
//!
//! Sources: docs/54 §3.1 (the record set), §4.4, §4.6, §4.8, §5.4, §6.4
//! (answers), §6.6 ("dird not available ⇒ SERVFAIL"); RFC 1035 §3.3.13,
//! §4.1.1, §4.2.1, §4.2.2, §5.3 (the SOA timers provisioned), §8
//! (HOSTMASTER); RFC 2782 (SRV, Target addresses in Additional); RFC 4120
//! §7.2.3.2 (`_kerberos`, udp and tcp); [MS-ADTS] 6.3.2.3 (`_ldap`,
//! `_kpasswd`; ports 389, 88, 464); docs/questions/Q-1004 (A-172: one SRV
//! record per service that exists — `_kpasswd._tcp` only); RFC 2136 §2.2
//! (UPDATE), §3.6 (the SERIAL moves with the zone); RFC 3645 §5.1 / RFC 8945
//! §4.2 (a gss-tsig TSIG).
//! Every value is hand-made test data (obviously fake names, accounts and
//! addresses from 192.0.2.0/24); no octet comes from any other
//! implementation or capture.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

#[path = "../../provision/tests/common/mod.rs"]
mod provision_common;

use audit_daemon::listener::ListenerConfig;
use config::{AuditdSettings, DirdSettings, DnsdSettings};
use core::net::{Ipv4Addr, SocketAddr};
use core::time::Duration;
use directory_daemon::test_seams::{serve_with_dns, DnsParams};
use directory_daemon::{DaemonControl as DirdControl, StoreSource};
use dirstore::Store;
use dns_daemon::test_seams::DaemonParams as DnsdParams;
use dns_daemon::{DaemonControl as DnsdControl, DaemonError as DnsdError, Listeners};
use ipc::{encode_frame, Direction};
use ipc_audit::{ZoneSerialCause, ZoneSerialOutcome, ZoneSerialStage};
use ipc_dns::{Connection, Connector, DnsRequest, TransportError, DNS_CHANNEL};
use krb_proto::KerberosTime;
use parse_dns::{
    decode, Class, Header, Message, Name, Opcode, Profile, Question, RData, Rcode, RrType,
    Transport, TsigError, TsigMac, TsigRecord, TsigTime,
};
use provision::{Account, Accounts, DomainInput, FilePath, Names, Network, ObjectRole, Paths};
use provision_common::{CountingRandom, HaltAt, Recorder};
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;
use support::{auditd as auditd_support, labelled_auditd_settings, skip_as_root, within};
use test_scratch::ScratchDir;

// ---------------------------------------------------------------------------
// Test data.
// ---------------------------------------------------------------------------

/// The realm and its zone (A-53: the realm is the DNS name upper-cased).
const REALM: &str = "EXAMPLE.ORG";
const ZONE: [&str; 2] = ["example", "org"];

/// The DC's host name: `<dc-name>.<zone>` (the zone's host-name rule).
const DC_FQDN: &str = "dc1.example.org";

/// The DC's address (192.0.2.0/24, an internal network of the input).
const DC_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

/// The produced dnsd account (a fake uid of the input).
const PRODUCED_DNSD_UID: u32 = 61009;

/// When `provision domain` ran.
fn provisioned_at() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 9, 0, 0).unwrap()
}

/// A DNS name from dotted text (test data only).
fn name(dotted: &str) -> Name {
    Name::from_labels(dotted.split('.').map(str::as_bytes)).unwrap()
}

/// The input of `provision domain` under `dir`: obviously fake accounts (the
/// test uid as dird's — the produced database must be its file, docs/50
/// §6.4), two first administrators (P-22), the internal networks loopback
/// (the listeners) and 192.0.2.0/24 (the DC's address), short socket paths.
fn domain_input(dir: &ScratchDir, uid: u32) -> DomainInput {
    let path = |rest: &str| FilePath::parse(dir.join(rest).to_str().unwrap()).unwrap();
    let account = |n: u32| Account { uid: n, gid: n };
    assert!(
        !(61001..=61010).contains(&uid),
        "the test uid collides with a fake account"
    );
    DomainInput {
        realm: REALM.to_owned(),
        naming_context: ZONE.map(str::to_owned).to_vec(),
        dc_fqdn: DC_FQDN.to_owned(),
        accounts: Accounts {
            keyd: account(61001),
            dird: account(uid),
            kdc: account(61003),
            ldap_front: account(61004),
            auditd: account(61005),
            admind: account(61006),
            kpasswd_front: account(61008),
            dnsd: account(PRODUCED_DNSD_UID),
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
            kpasswd_front_config: path("etc/kpasswd-front.conf"),
            dnsd_config: path("etc/dnsd.conf"),
            keyd_socket: path("r/k/k.sock"),
            dird_kdc_socket: path("r/dk/d.sock"),
            dird_ldap_socket: path("r/dl/l.sock"),
            dird_admin_socket: path("r/da/a.sock"),
            dird_kpasswd_socket: path("r/dp/p.sock"),
            dird_dns_socket: path("r/dd/d.sock"),
            audit_socket: path("r/au/a.sock"),
            admin_socket: path("r/ad/a.sock"),
            tls_certificate: path("etc/dc-cert.der"),
            tls_private_key: path("etc/dc-key.der"),
            policy_next: path("v/dp/policy.next"),
        },
        network: Network {
            kdc_listen: vec!["127.0.0.1:88".to_owned()],
            ldap_listen: Vec::new(),
            ldaps_listen: vec!["127.0.0.1:636".to_owned()],
            internal_networks: vec!["127.0.0.0/8".to_owned(), "192.0.2.0/24".to_owned()],
            kpasswd_listen: vec!["127.0.0.1:464".to_owned()],
            dnsd_listen: vec!["127.0.0.1:53".to_owned()],
            // Task DN10b: the DC's host record (docs/54 §3.1).
            dc_addresses: vec![DC_ADDRESS.to_string()],
        },
        names: Names {
            tier0_ou: "Tier0".to_owned(),
            workstations_ou: Some("Workstations".to_owned()),
            tier0_group: "tier0-admins".to_owned(),
            bootstrap_group: "machine-bootstrap".to_owned(),
            dc_name: "DC1".to_owned(),
            ldap_service_name: "ldapsvc".to_owned(),
            admin_service_name: "adminsvc".to_owned(),
            change_password_service_name: "changepwsvc".to_owned(),
            first_admins: vec!["alice".to_owned(), "bob".to_owned()],
        },
    }
}

// ---------------------------------------------------------------------------
// dnsd's side of `dird-dns.sock` on every host.
// ---------------------------------------------------------------------------

/// Connects to dird's DNS socket and reads dird's uid through tokio
/// `UnixStream::peer_cred`, then hands the stream to ipc-dns's blocking
/// connection — the same server-uid check on every host (tests/support's
/// connector pattern).
struct DnsConnector {
    path: PathBuf,
    /// Taken only by `Drop` (below).
    runtime: Option<tokio::runtime::Runtime>,
}

impl DnsConnector {
    fn new(path: &Path) -> DnsConnector {
        DnsConnector {
            path: path.to_path_buf(),
            runtime: Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .build()
                    .unwrap(),
            ),
        }
    }
}

impl Drop for DnsConnector {
    /// dnsd drops a connector it did not move into a thread (its start
    /// failed) inside its own runtime: a runtime may not be dropped there,
    /// so this one is shut down in the background (tokio 1.54.1 docs.rs,
    /// `runtime::Runtime::shutdown_background`).
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

struct Checked {
    uid: u32,
    inner: ipc_dns::UnixConnection,
}

impl Connector for DnsConnector {
    type Connection = Checked;
    fn connect(&mut self) -> Result<Checked, TransportError> {
        let path = self.path.clone();
        let runtime = self.runtime.as_ref().ok_or(TransportError::Connect)?;
        let (uid, stream) = runtime
            .block_on(async move {
                let stream = tokio::net::UnixStream::connect(&path).await.ok()?;
                let uid = stream.peer_cred().ok()?.uid();
                let stream = stream.into_std().ok()?;
                stream.set_nonblocking(false).ok()?;
                Some((uid, stream))
            })
            .ok_or(TransportError::Connect)?;
        Ok(Checked {
            uid,
            inner: ipc_dns::UnixConnection::from_stream(stream),
        })
    }
}

impl Connection for Checked {
    fn peer_uid(&self) -> Result<u32, TransportError> {
        Ok(self.uid)
    }
    fn send(&mut self, frame: &[u8], deadline: Duration) -> Result<(), TransportError> {
        self.inner.send(frame, deadline)
    }
    fn receive(
        &mut self,
        limit: ipc::FrameLimit,
        deadline: Duration,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, TransportError> {
        self.inner.receive(limit, deadline)
    }
    fn check_idle(&mut self) -> Result<(), TransportError> {
        self.inner.check_idle()
    }
}

// ---------------------------------------------------------------------------
// The world.
// ---------------------------------------------------------------------------

/// dird on its own thread.
struct DirdRun {
    control: DirdControl,
    thread: Option<JoinHandle<Result<(), String>>>,
}

impl DirdRun {
    fn stop(mut self) -> Result<(), String> {
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

/// dnsd on its own thread, and its listeners' addresses.
struct DnsdRun {
    control: DnsdControl,
    thread: Option<JoinHandle<Result<(), DnsdError>>>,
    udp: SocketAddr,
    tcp: SocketAddr,
}

impl DnsdRun {
    fn stop(mut self) -> Result<(), DnsdError> {
        self.control.stop();
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for DnsdRun {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.control.stop();
            let _ = thread.join();
        }
    }
}

/// The deployment of one test.
struct World {
    /// The scratch directory, removed when the world is dropped.
    _dir: ScratchDir,
    uid: u32,
    input: DomainInput,
    auditd: Option<auditd_support::Server>,
}

impl World {
    /// `provision domain` — which writes the DC's host record itself (module
    /// documentation, step 2; the produced store is only read here); nothing
    /// runs yet. `None` as root.
    fn provisioned() -> Option<World> {
        let dir = ScratchDir::new("e2e-dns").expect("the scratch directory");
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
        // The DC's host record, as `provision domain` wrote it (module
        // documentation, step 2): read only — the DC object holds the
        // `--dc-address` value, and the zone serial counter was taken once
        // (that one write changed the zone — A-170). SERIAL is now 2.
        let dc = plan.object(ObjectRole::DcComputer).expect("the DC").guid;
        let key =
            directory_daemon::startup::read_integrity_key(input.paths.integrity_key.as_path(), uid)
                .unwrap();
        let schema = ad_schema::phase1().unwrap();
        let store =
            Store::open(input.paths.database.as_path(), key, schema.schema().clone()).unwrap();
        {
            let snapshot = store.snapshot().unwrap();
            let dc_object = snapshot.get_object(dc).unwrap().expect("the DC object");
            let addresses: Vec<Vec<u8>> = dc_object
                .attribute(directory_pip::HOST_ADDRESS)
                .map(|a| a.values.iter().map(|v| v.value.clone()).collect())
                .unwrap_or_default();
            assert_eq!(
                addresses,
                vec![directory_pip::host_address_value(DC_ADDRESS)]
            );
            let zone = snapshot
                .counter(directory_pip::DNS_ZONE_SERIAL_COUNTER)
                .unwrap()
                .expect("the zone serial counter");
            assert_eq!(directory_pip::zone_serial(&zone), Some(2));
        }
        drop(store);
        // Each socket in its own directory (docs/50 §3.1), 0700 here: the
        // daemons' privileged set-up would create them as root.
        for socket in [
            input.paths.dird_kdc_socket.as_path(),
            input.paths.dird_ldap_socket.as_path(),
            input.paths.dird_dns_socket.as_path(),
            input.paths.audit_socket.as_path(),
        ] {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(socket.parent().unwrap())
                .unwrap();
        }
        Some(World {
            _dir: dir,
            uid,
            input,
            auditd: None,
        })
    }

    fn read(&self, path: &FilePath) -> Vec<u8> {
        std::fs::read(path.as_path()).unwrap()
    }

    /// The audit listener of `sender`: siblings of the produced socket.
    fn audit_socket_of(&self, sender: &str) -> PathBuf {
        let produced = self.input.paths.audit_socket.as_path();
        match sender {
            "dird" => produced.with_file_name("ad.sock"),
            "dnsd" => produced.with_file_name("an.sock"),
            other => panic!("not a sender here: {other}"),
        }
    }

    /// auditd on the produced log: dird's and dnsd's listeners, each naming
    /// the test uid as that sender; the produced run-as account and frame
    /// timeout; the production binding table.
    fn start_auditd(&mut self) {
        let produced = AuditdSettings::parse(&self.read(&self.input.paths.auditd_config)).unwrap();
        let listeners: Vec<(PathBuf, &str)> = ["dird", "dnsd"]
            .iter()
            .map(|sender| (self.audit_socket_of(sender), *sender))
            .collect();
        let settings = labelled_auditd_settings(
            &listeners,
            self.uid,
            (produced.run_as().uid(), produced.run_as().gid()),
            produced.audit_log_path().as_path(),
            produced.frame_timeout().as_secs(),
        );
        let config = ListenerConfig::from_settings(&settings[0]);
        self.auditd = Some(auditd_support::Server::start_many(
            &settings, config, 64, true,
        ));
    }

    /// dird from its produced file, with its DNS service admitting
    /// `dnsd_uid` (module documentation, step 4).
    fn start_dird(&self, dnsd_uid: u32) -> DirdRun {
        let paths = &self.input.paths;
        let settings = DirdSettings::parse(&self.read(&paths.dird_config)).unwrap();
        let mut params = directory_daemon::test_seams::DaemonParams::from(
            directory_daemon::startup::params(&settings).unwrap(),
        );
        params.kdc_uid = self.uid;
        params.ldap_front_uid = self.uid;
        params.audit.uid = self.uid;
        assert_eq!(params.audit.socket, paths.audit_socket.as_path());
        params.audit.socket = self.audit_socket_of("dird");
        let mut dns = DnsParams::production(
            directory_daemon::startup::dns_params(&settings)
                .unwrap()
                .expect("dird's file has the DNS channel"),
        );
        assert_eq!(dns.socket, paths.dird_dns_socket.as_path());
        assert_eq!(dns.dnsd_uid, PRODUCED_DNSD_UID);
        dns.dnsd_uid = dnsd_uid;
        let policy = directory_daemon::startup::read_policy(
            settings.policy_store_path().as_path(),
            self.uid,
        )
        .unwrap();
        let key = directory_daemon::startup::read_integrity_key(
            settings.integrity_key_path().as_path(),
            self.uid,
        )
        .unwrap();
        let source = StoreSource::File {
            path: settings.database_path().as_path().to_path_buf(),
            key,
            owner_uid: self.uid,
        };
        let control = DirdControl::new();
        let thread = {
            let control = control.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let result = runtime.block_on(serve_with_dns(
                    params,
                    None,
                    None,
                    Some(dns),
                    source,
                    policy,
                    control,
                ));
                drop(runtime);
                let stopped = result.map_err(|e| e.to_string())?;
                stopped.join().map_err(|_| String::from("engine panicked"))
            })
        };
        let start = Instant::now();
        while !control.is_serving() {
            assert!(!thread.is_finished(), "dird ended at start");
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "dird did not start"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        DirdRun {
            control,
            thread: Some(thread),
        }
    }

    /// dnsd from its produced file (module documentation, step 5); `Err`
    /// when it did not come up (docs/54 §4.8).
    fn start_dnsd(&self) -> Result<DnsdRun, DnsdError> {
        let settings = DnsdSettings::parse(&self.read(&self.input.paths.dnsd_config)).unwrap();
        assert_eq!(
            settings.dird().socket().as_path(),
            self.input.paths.dird_dns_socket.as_path(),
            "dnsd names the socket dird serves"
        );
        let mut params = DnsdParams::from(dns_daemon::DaemonParams::from_settings(&settings));
        params.dird_uid = self.uid;
        params.audit.uid = self.uid;
        params.audit.socket = self.audit_socket_of("dnsd");
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (udp_address, tcp_address) = (udp.local_addr().unwrap(), tcp.local_addr().unwrap());
        let listeners = Listeners {
            udp: vec![udp],
            tcp: vec![tcp],
        };
        let socket = settings.dird().socket().as_path().to_path_buf();
        let control = DnsdControl::new();
        let thread = {
            let control = control.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let clock: Arc<dyn dns_daemon::clock::Clock> =
                    Arc::new(dns_daemon::clock::MonotonicClock::start());
                let result = runtime.block_on(dns_daemon::test_seams::serve(
                    params,
                    listeners,
                    DnsConnector::new(&socket),
                    DnsConnector::new(&socket),
                    clock,
                    control,
                ));
                drop(runtime);
                let stopped = result?;
                stopped.join().map_err(|_| DnsdError::Thread)
            })
        };
        let start = Instant::now();
        while !control.is_serving() {
            if thread.is_finished() {
                return Err(thread.join().unwrap().err().unwrap_or(DnsdError::Thread));
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "dnsd did not start"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(DnsdRun {
            control,
            thread: Some(thread),
            udp: udp_address,
            tcp: tcp_address,
        })
    }

    fn stop_auditd(&mut self) {
        if let Some(server) = self.auditd.take() {
            if let Some(writer) = server.stop() {
                writer.expect("auditd's writer ended cleanly");
            }
        }
    }
}

impl Drop for World {
    fn drop(&mut self) {
        self.stop_auditd();
    }
}

// ---------------------------------------------------------------------------
// DNS clients (RFC 1035 §4.2.1, §4.2.2), messages encoded and decoded by
// parse-dns.
// ---------------------------------------------------------------------------

/// A one-question QUERY of class IN. Spec: RFC 1035 §4.1.1, §4.1.2.
fn query(id: u16, qname: &str, qtype: RrType) -> Vec<u8> {
    parse_dns::encode(&Message {
        header: Header {
            id,
            qr: false,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            rcode: Rcode::NOERROR,
        },
        question: Some(Question {
            qname: name(qname),
            qtype,
            qclass: Class::IN,
        }),
        answer: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        tsig: None,
    })
    .unwrap()
}

/// An UPDATE of the zone signed with a `gss-tsig` TSIG (whose MAC no key
/// made — dird never gets as far as checking it): the form dnsd forwards to
/// dird. Spec: RFC 2136 §2.2, §2.3 (ZTYPE SOA, ZCLASS IN); RFC 8945 §4.2;
/// RFC 3645 §5.1; docs/54 §4.5 step 1.
fn signed_update(id: u16) -> Vec<u8> {
    parse_dns::encode(&Message {
        header: Header {
            id,
            qr: false,
            opcode: Opcode::Update,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            rcode: Rcode::NOERROR,
        },
        question: Some(Question {
            qname: name("example.org"),
            qtype: RrType::SOA,
            qclass: Class::IN,
        }),
        answer: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        tsig: Some(TsigRecord {
            key_name: name("key.example.org"),
            algorithm_name: name(parse_dns::GSS_TSIG_ALGORITHM),
            time_signed: TsigTime::new(1_700_000_000).unwrap(),
            fudge: 300,
            mac: TsigMac::new(vec![0x5A; 28]).unwrap(),
            original_id: id,
            error: TsigError::NOERROR,
            other_data: Vec::new(),
        }),
    })
    .unwrap()
}

/// Decode a reply. Spec: RFC 1035 §4.1 (parse-dns `Response` profile).
fn reply(octets: &[u8], transport: Transport) -> Message {
    decode(octets, Profile::Response(transport))
        .expect("the reply decodes")
        .into_message()
}

/// One datagram, one reply (RFC 1035 §4.2.1).
fn udp_exchange(server: SocketAddr, request: &[u8]) -> Message {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.send_to(request, server).unwrap();
    let mut buffer = [0u8; 2048];
    let (length, from) = client.recv_from(&mut buffer).expect("a UDP reply");
    assert_eq!(from, server);
    reply(&buffer[..length], Transport::Udp)
}

/// One message, one reply, each with its two-octet length (RFC 1035
/// §4.2.2), on a fresh connection.
fn tcp_exchange(server: SocketAddr, request: &[u8]) -> Message {
    let mut stream = TcpStream::connect(server).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut framed = u16::try_from(request.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(request);
    stream.write_all(&framed).unwrap();
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).expect("a TCP reply");
    let mut message = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut message).unwrap();
    reply(&message, Transport::Tcp)
}

/// An authoritative NOERROR reply to query `id` (docs/54 §6.4: AA = 1,
/// RA = 0). Spec: RFC 1035 §4.1.1.
fn assert_authoritative(message: &Message, id: u16) {
    assert_eq!(message.header.id, id);
    assert!(message.header.qr);
    assert!(message.header.aa, "authoritative");
    assert!(!message.header.ra, "no recursion");
    assert_eq!(message.header.rcode, Rcode::NOERROR);
}

/// The DC's A record (RFC 1035 §3.4.1): owner dc1.example.org, the zone's
/// host TTL as provisioned (600 s, above MINIMUM 60 — RFC 1035 §3.3.13).
fn assert_dc_address(records: &[parse_dns::ResourceRecord]) {
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].name, name(DC_FQDN));
    assert_eq!(records[0].class, Class::IN);
    assert_eq!(records[0].ttl, 600);
    assert_eq!(records[0].rdata, RData::A(DC_ADDRESS));
}

// ---------------------------------------------------------------------------
// The tests.
// ---------------------------------------------------------------------------

/// docs/54 §3.1, §4.4, §4.6, §4.8, §6.4 (task DN10a, and DN14's query
/// part): a provisioned dnsd comes up against a provisioned dird — auditd
/// verified, dird verified (`Pong` with the internal zone), the first image
/// fetched over `dird-dns.sock` — and answers, over UDP and over TCP:
///
/// * SOA of the apex: MNAME the DC, RNAME `hostmaster.example.org`
///   (provisioned — RFC 1035 §8), SERIAL 3 (2 after provisioning's write of
///   the DC record — A-170 — and one advance at dird's DNS service start,
///   task DN10b), the timers of RFC 1035 §5.3's example, TTL 3600 s;
/// * NS of the apex: the DC, its address in Additional (RFC 1034 §3.7.1);
/// * the SRV set — `_kerberos._udp`, `_kerberos._tcp` (RFC 4120 §7.2.3.2:
///   both), `_ldap._tcp` (389), and `_kpasswd._tcp` (464: the kpasswd
///   channel is provisioned, so kpasswd exists — docs/54 §3.1, A-119) —
///   priority 0, weight 0, Target the DC, its address in Additional (RFC
///   2782); and **no** `_kpasswd._udp` (NXDOMAIN): kpasswd-front serves TCP
///   only, one SRV record per service that exists (docs/questions/Q-1004,
///   A-172);
/// * A of the DC: 192.0.2.10.
///
/// And auditd's log holds dird's two `ZoneSerial` events of the start's
/// advance — the decision (cause `ServiceStart`, from 2), acknowledged
/// before the write, then the outcome (advanced to 3) — recorded under
/// dird's source (docs/51 §5.7 item 2; A-85; docs/questions/Q-1013).
#[test]
fn a_provisioned_dnsd_starts_and_answers_the_zone() {
    within(support::TEST_BOUND, || {
        let Some(mut world) = World::provisioned() else {
            return;
        };
        world.start_auditd();
        let dird = world.start_dird(world.uid);
        let dnsd = world.start_dnsd().expect("dnsd starts");

        for (id, ask) in [(0x1001u16, Transport::Udp), (0x1002, Transport::Tcp)] {
            let exchange = |request: &[u8]| match ask {
                Transport::Udp => udp_exchange(dnsd.udp, request),
                Transport::Tcp => tcp_exchange(dnsd.tcp, request),
            };

            let soa = exchange(&query(id, "example.org", RrType::SOA));
            assert_authoritative(&soa, id);
            assert_eq!(soa.answer.len(), 1);
            assert_eq!(soa.answer[0].name, name("example.org"));
            assert_eq!(soa.answer[0].ttl, 3600);
            let RData::Soa(fields) = &soa.answer[0].rdata else {
                panic!("an SOA record: {:?}", soa.answer[0]);
            };
            assert_eq!(fields.mname, name(DC_FQDN));
            assert_eq!(fields.rname, name("hostmaster.example.org"));
            assert_eq!(fields.serial, 3);
            assert_eq!(
                [fields.refresh, fields.retry, fields.expire, fields.minimum],
                [7200, 600, 3_600_000, 60]
            );

            let ns = exchange(&query(id, "example.org", RrType::NS));
            assert_authoritative(&ns, id);
            assert_eq!(ns.answer.len(), 1);
            assert_eq!(ns.answer[0].rdata, RData::Ns(name(DC_FQDN)));
            assert_dc_address(&ns.additional);

            for (owner, port) in [
                ("_kerberos._udp.example.org", 88),
                ("_kerberos._tcp.example.org", 88),
                ("_ldap._tcp.example.org", 389),
                ("_kpasswd._tcp.example.org", 464),
            ] {
                let srv = exchange(&query(id, owner, RrType::SRV));
                assert_authoritative(&srv, id);
                assert_eq!(srv.answer.len(), 1, "{owner}");
                assert_eq!(srv.answer[0].name, name(owner));
                let RData::Srv(fields) = &srv.answer[0].rdata else {
                    panic!("an SRV record: {:?}", srv.answer[0]);
                };
                assert_eq!(
                    (fields.priority, fields.weight, fields.port),
                    (0, 0, port),
                    "{owner}"
                );
                assert_eq!(fields.target, name(DC_FQDN));
                assert_dc_address(&srv.additional);
            }
            // One SRV record per service that exists (docs/questions/Q-1004,
            // A-172): no UDP kpasswd — the name does not exist.
            let udp_kpasswd = exchange(&query(id, "_kpasswd._udp.example.org", RrType::SRV));
            assert_eq!(udp_kpasswd.header.rcode, Rcode::NXDOMAIN);
            assert!(udp_kpasswd.answer.is_empty());

            let a = exchange(&query(id, DC_FQDN, RrType::A));
            assert_authoritative(&a, id);
            assert_dc_address(&a.answer);
        }

        dnsd.stop().expect("dnsd stops cleanly");
        dird.stop().expect("dird stops cleanly");
        world.stop_auditd();

        // dird's serial advance at its DNS service start, in auditd's
        // verified log, under dird's source (the transport identity).
        let (_, records) =
            support::verified_log(world.input.paths.audit_log.as_path()).expect("the log verifies");
        support::assert_recorded_under_their_senders(&records, world.uid);
        let zone_serial: Vec<(ZoneSerialCause, u32, ZoneSerialStage)> = records
            .iter()
            .filter(|record| record.source != audit_log::Source::Auditd)
            .filter_map(|record| {
                match ipc_audit::decode_event(&record.payload).expect("every payload decodes") {
                    ipc_audit::EventBody::ZoneSerial(event) => {
                        assert_eq!(record.source, audit_log::Source::Dird);
                        Some((event.cause, event.from.get(), event.stage))
                    }
                    _ => None,
                }
            })
            .collect();
        assert_eq!(
            zone_serial,
            vec![
                (ZoneSerialCause::ServiceStart, 2, ZoneSerialStage::Decision),
                (
                    ZoneSerialCause::ServiceStart,
                    2,
                    ZoneSerialStage::Outcome(ZoneSerialOutcome::Advanced {
                        serial: core::num::NonZeroU32::new(3).unwrap()
                    })
                ),
            ]
        );
    });
}

/// docs/54 §4.5, §6.6 ("dird not available ⇒ SERVFAIL"); docs/questions/
/// Q-1000 item 4: a signed UPDATE over TCP is forwarded by dnsd and refused
/// by dird with the channel's explicit refusal, unread (the DNS PEP is not
/// built — DN8, DN9): dnsd answers SERVFAIL, UPDATE opcode, zero counts; and
/// its queries are answered as before.
#[test]
fn an_update_is_refused_and_answered_servfail() {
    within(support::TEST_BOUND, || {
        let Some(mut world) = World::provisioned() else {
            return;
        };
        world.start_auditd();
        let dird = world.start_dird(world.uid);
        let dnsd = world.start_dnsd().expect("dnsd starts");
        let before = directory_daemon::dns_forward_refused_count();
        let answer = tcp_exchange(dnsd.tcp, &signed_update(0x2001));
        assert_eq!(answer.header.id, 0x2001);
        assert!(answer.header.qr);
        assert_eq!(answer.header.opcode, Opcode::Update);
        assert_eq!(answer.header.rcode, Rcode::SERVFAIL);
        assert!(answer.answer.is_empty() && answer.authority.is_empty());
        assert!(answer.tsig.is_none(), "unsigned: no key was involved");
        assert!(
            directory_daemon::dns_forward_refused_count() > before,
            "dird refused the forward"
        );
        let a = udp_exchange(dnsd.udp, &query(0x2002, DC_FQDN, RrType::A));
        assert_authoritative(&a, 0x2002);
        assert_dc_address(&a.answer);
        dnsd.stop().expect("dnsd stops cleanly");
        dird.stop().expect("dird stops cleanly");
        world.stop_auditd();
    });
}

/// docs/54 §4.6 ("dird accepts only `dnsd_uid` (R50-3)"), §4.8 ("dird down
/// at start ⇒ dnsd does not come up"); docs/50 §3.2: dird admitting the
/// produced dnsd account (61009) closes the test's connection without a
/// reply — a raw `Ping` gets end of stream — and dnsd running as the test's
/// uid does not come up (its dird check fails).
#[test]
fn dird_refuses_a_peer_that_is_not_dnsd() {
    within(support::TEST_BOUND, || {
        let Some(mut world) = World::provisioned() else {
            return;
        };
        world.start_auditd();
        let dird = world.start_dird(PRODUCED_DNSD_UID);
        let before = directory_daemon::dns_refused_peer_count();
        let mut raw = UnixStream::connect(world.input.paths.dird_dns_socket.as_path()).unwrap();
        raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let ping = encode_frame(DNS_CHANNEL, Direction::Request, &DnsRequest::Ping).unwrap();
        let _ = raw.write_all(ping.as_bytes());
        let mut octets = Vec::new();
        let _ = raw.read_to_end(&mut octets);
        assert!(octets.is_empty(), "no reply to a peer that is not dnsd");
        assert!(directory_daemon::dns_refused_peer_count() > before);
        match world.start_dnsd() {
            Err(DnsdError::Dird(_)) => {}
            Err(other) => panic!("expected dnsd's dird check to fail, got {other:?}"),
            Ok(_) => panic!("dnsd came up against a dird that refuses it"),
        }
        dird.stop().expect("dird stops cleanly");
        world.stop_auditd();
    });
}
