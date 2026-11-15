//! Tier 2 (docs/50 §9: real temp-dir sockets, the uid map injected with the
//! test's own uid): dird's DNS service (task DN10a) through the serve path —
//! `dird-dns.sock`, peer credentials, the DNS thread, the channel's real
//! dispatcher (crate ipc-dns-server) and dnsd's real client (crate ipc-dns
//! `DnsClient`, its uid and zone checks included).
//!
//! * `Ping` ⇒ `Pong` naming the internal zone; `FetchZoneImage { None }` ⇒
//!   the zone image of the one projection (apex, SERIAL, the DC's name and
//!   record, the synthesized SRV set); `FetchZoneImage { Some(serial) }` ⇒
//!   `Unchanged` (docs/54 §4.4, §4.6);
//! * a peer that is not dnsd's uid is closed without a reply (docs/54 §4.6;
//!   docs/50 R50-3);
//! * a `Forward` (a signed UPDATE) is refused `Unavailable`, unread — the DNS
//!   PEP is not built (tasks DN8, DN9; docs/questions/Q-1000 item 4) — and
//!   the next connection is served again;
//! * a directory whose zone cannot be projected (no DC host address) starts
//!   no DNS service: nothing is bound, dird's other services run (docs/54
//!   §4.8 — dnsd then does not come up);
//! * the product constructor of the parameters (`startup::dns_params`): the
//!   zone values from dird's file, the `_kpasswd` switch from its kpasswd
//!   channel (docs/54 §3.1; docs/questions/Q-1001 item 5).
//!
//! Sources: docs/54 §3.1, §4.4, §4.6, §4.8; docs/50 R50-3, §3.2, §9; RFC
//! 1035 §3.3.13, §5.3 (the SOA timers of its master file example), §8 (the
//! mailbox HOSTMASTER); RFC 4120 §7.2.3.2 / [MS-ADTS] 6.3.2.3 (the SRV set).
//! Addresses are from 192.0.2.0/24; every value is hand-made (tests/support).

mod support;

use ad_schema::flags::user_account_control as uac;
use config::{DirdSettings, Network};
use core::net::{IpAddr, Ipv4Addr};
use core::time::Duration;
use directory_daemon::test_seams::{self, DnsParams};
use directory_daemon::{
    dns_forward_refused_count, dns_refused_peer_count, DaemonControl, StoreSource,
};
use directory_pip::{DnsName, KpasswdService, SoaParameters, ZoneParameters};
use dirstore::{AttrId, NewObject};
use dtyp::{Control, SecurityDescriptor, Sid, SECURITY_NT_AUTHORITY};
use ipc::{encode_frame, Direction, Refused};
use ipc_dns::{
    Connection, Connector, DnsClient, DnsMessage, DnsReply, DnsRequest, ExpectedDird,
    ForwardRequest, FrontZone, ImageFetch, PeerAddress, Serial, Transport, TransportError,
    Unserved, DNS_CHANNEL,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;
use support::{Directory, FakeAuditd, TempDir};

/// The DC's small id (GUID = guid(id), RID 1000 + id).
const DC: u32 = 50;

/// The DC's address (192.0.2.0/24, hand-made).
const DC_ADDRESS: [u8; 4] = [192, 0, 2, 10];

/// A canonical self-relative security descriptor (as tests/support's).
fn sd_value() -> Vec<u8> {
    SecurityDescriptor {
        sbz1: 0,
        control: Control(Control::SELF_RELATIVE),
        owner_sid: Some(Sid::new(SECURITY_NT_AUTHORITY, &[18]).unwrap()),
        group_sid: Some(Sid::new(SECURITY_NT_AUTHORITY, &[32, 544]).unwrap()),
        sacl: None,
        dacl: None,
    }
    .encode()
    .unwrap()
}

/// The standard directory (tests/support) plus the DC's computer account —
/// userAccountControl ST, `dc1$`, dNSHostName `dc1.example.org` (the
/// host-name rule: `<computerName>.<zone>`, docs/54 §5.3) and, when
/// `address` is set, its host record — and the `dns-zone-serial` counter
/// (A-83: created at provisioning; written here directly, test only).
fn dc_directory(path: &Path, address: bool) -> Directory {
    let d = Directory::standard(path);
    let attr = |name: &str| -> AttrId { d.p1.attribute_by_name(name).unwrap() };
    let class = d.p1.class_by_name("computer").unwrap();
    let mut attributes = vec![
        (attr("cn"), vec![b"dc1".to_vec()]),
        (attr("sAMAccountName"), vec![b"dc1$".to_vec()]),
        (attr("objectSid"), vec![support::sid_of(DC).encode()]),
        (
            attr("whenCreated"),
            vec![support::WHEN_CREATED.to_be_bytes().to_vec()],
        ),
        (
            attr("userAccountControl"),
            vec![uac::ADS_UF_SERVER_TRUST_ACCOUNT.to_be_bytes().to_vec()],
        ),
        (attr("dNSHostName"), vec![b"dc1.example.org".to_vec()]),
        (attr("nTSecurityDescriptor"), vec![sd_value()]),
    ];
    if address {
        attributes.push((directory_pip::HOST_ADDRESS, vec![DC_ADDRESS.to_vec()]));
    }
    let dc = NewObject {
        guid: support::guid(DC),
        parent: Some(support::guid(support::USERS)),
        classes: d.p1.class(class).unwrap().object_class.clone(),
        attributes,
    };
    d.create_all(vec![dc]);
    let mut txn = d.store.begin_write().unwrap();
    txn.create_counter(
        directory_pip::DNS_ZONE_SERIAL_COUNTER,
        directory_pip::DNS_ZONE_SERIAL_FIRST,
        directory_pip::DNS_ZONE_SERIAL_END_EXCLUSIVE,
    )
    .unwrap();
    txn.commit().unwrap();
    d
}

/// The zone values: RNAME hostmaster.example.org (RFC 1035 §8), the timers
/// of RFC 1035 §5.3's example, hand-made TTLs, 7 days, 192.0.2.0/24.
fn zone(kpasswd: KpasswdService) -> ZoneParameters {
    ZoneParameters {
        soa: SoaParameters {
            rname: DnsName::from_labels(["hostmaster", "example", "org"].map(str::as_bytes))
                .unwrap(),
            refresh: 7200,
            retry: 600,
            expire: 3_600_000,
            minimum: 60,
        },
        infrastructure_ttl: 3600,
        host_ttl: 600,
        kpasswd,
        max_record_age: 7 * 24 * 60 * 60,
        registrable_networks: vec![
            Network::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap()
        ],
    }
}

/// dird with its DNS service on its own thread.
struct DnsDird {
    control: DaemonControl,
    thread: Option<JoinHandle<Result<(), String>>>,
    dns_socket: PathBuf,
    ldap_socket: PathBuf,
}

impl DnsDird {
    fn start(dir: &TempDir, uid: u32, dnsd_uid: u32, directory: &Directory) -> DnsDird {
        let params = support::params(dir, uid, uid, Duration::from_secs(5), 4);
        let ldap_socket = params.ldap_socket.clone();
        let dns_socket = dir.join("n.sock");
        let dns = DnsParams {
            socket: dns_socket.clone(),
            dnsd_uid,
            zone: zone(KpasswdService::Absent),
            max_connections: directory_daemon::MAX_DNS_CONNECTIONS,
            queue_capacity: directory_daemon::DNS_QUEUE_CAPACITY,
        };
        let source: StoreSource = test_seams::opened(Arc::clone(&directory.store));
        let control = DaemonControl::new();
        let thread = {
            let control = control.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let result = runtime.block_on(test_seams::serve_with_dns(
                    params,
                    None,
                    None,
                    Some(dns),
                    source,
                    support::policy(1),
                    control,
                ));
                drop(runtime);
                let stopped = result.map_err(|e| e.to_string())?;
                let failed = stopped.engine_failed();
                stopped
                    .join()
                    .map_err(|_| String::from("engine panicked"))?;
                if failed {
                    Err(String::from("an engine stopped early"))
                } else {
                    Ok(())
                }
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
        DnsDird {
            control,
            thread: Some(thread),
            dns_socket,
            ldap_socket,
        }
    }

    fn stop(mut self) -> Result<(), String> {
        self.control.stop();
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for DnsDird {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.control.stop();
            let _ = thread.join();
        }
    }
}

/// dnsd's side of `dird-dns.sock` on every host: the server's uid read
/// through tokio `UnixStream::peer_cred`, then the stream handed to ipc-dns's
/// blocking connection (tests/support's `connector` pattern — rustix
/// `socket_peercred` is Linux-only, Q-245 item 11).
struct DnsConnector {
    path: PathBuf,
    runtime: tokio::runtime::Runtime,
}

struct Checked {
    uid: u32,
    inner: ipc_dns::UnixConnection,
}

impl Connector for DnsConnector {
    type Connection = Checked;
    fn connect(&mut self) -> Result<Checked, TransportError> {
        let path = self.path.clone();
        let (uid, stream) = self
            .runtime
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

/// dnsd's client of dird (dird runs as the test's uid).
fn client(socket: &Path, dird_uid: u32) -> DnsClient<DnsConnector> {
    DnsClient::new(
        DnsConnector {
            path: socket.to_path_buf(),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .unwrap(),
        },
        ExpectedDird::new(dird_uid, FrontZone::Internal).unwrap(),
        ipc_dns::DEFAULT_DEADLINE,
    )
}

/// docs/54 §4.4, §4.6, §5.4: dnsd's `Ping` is answered with the internal
/// zone; its first fetch gets the projection's image — apex example.org,
/// SERIAL 1 (the counter's next value before any take — Q-991 item 6), the
/// DC `dc1.example.org` as the one host, the three SRV records of a zone
/// without kpasswd (RFC 4120 §7.2.3.2, [MS-ADTS] 6.3.2.3); a fetch naming
/// that SERIAL is `Unchanged`. dird's other channels still listen.
#[test]
fn dird_serves_the_zone_image_to_dnsd() {
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    let directory = dc_directory(&dir.join("s.redb"), true);
    let _auditd = FakeAuditd::start_recording_as(&dir.join("a.sock"), ipc_audit::EventSource::Dird);
    let dird = DnsDird::start(&dir, uid, uid, &directory);
    assert!(dird.ldap_socket.exists(), "the LDAP channel listens");
    let mut dnsd = client(&dird.dns_socket, uid);
    dnsd.ping().expect("Pong with the internal zone");
    let image = match dnsd.fetch_zone_image(None).expect("the image") {
        ImageFetch::Image(image) => image,
        ImageFetch::Unchanged(_) => panic!("no image held yet"),
    };
    assert_eq!(
        image.apex(),
        &DnsName::from_labels([&b"example"[..], b"org"]).unwrap()
    );
    assert_eq!(image.serial(), 1);
    assert_eq!(
        image.dc_name(),
        &DnsName::from_labels([&b"dc1"[..], b"example", b"org"]).unwrap()
    );
    assert_eq!(image.host_count(), 1);
    assert_eq!(image.srv_services().count(), 3);
    assert_eq!(image.minimum(), 60);
    let serial = Serial::new(1).unwrap();
    assert_eq!(
        dnsd.fetch_zone_image(Some(serial)).expect("confirmed"),
        ImageFetch::Unchanged(serial)
    );
    drop(dnsd);
    dird.stop().expect("clean stop");
}

/// docs/54 §4.6 ("dird accepts only `dnsd_uid` (R50-3)"); docs/50 §3.2: dird
/// configured for another uid closes the test's connection without a reply —
/// dnsd's client sees the transport closed, the refusal is counted.
#[test]
fn a_peer_that_is_not_dnsd_is_closed_without_a_reply() {
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    let directory = dc_directory(&dir.join("s.redb"), true);
    let _auditd = FakeAuditd::start_recording_as(&dir.join("a.sock"), ipc_audit::EventSource::Dird);
    let dird = DnsDird::start(&dir, uid, uid + 1, &directory);
    let before = dns_refused_peer_count();
    let mut dnsd = client(&dird.dns_socket, uid);
    match dnsd.ping() {
        Err(Unserved::Transport(TransportError::Closed | TransportError::Io)) => {}
        other => panic!("expected a closed connection, got {other:?}"),
    }
    assert!(dns_refused_peer_count() > before);
    dird.stop().expect("clean stop");
}

/// Send `requests` on one raw connection to `socket`, then read every reply
/// frame until the server closes (or 5 s pass): the replies, decoded by the
/// channel's own codec.
/// Spec: docs/50 §3.3 (the frame layout; `Refused` + close).
fn raw_exchange(socket: &Path, requests: &[DnsRequest]) -> Vec<ipc::Reply<DnsReply>> {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    for request in requests {
        let frame = encode_frame(DNS_CHANNEL, Direction::Request, request).unwrap();
        stream.write_all(frame.as_bytes()).unwrap();
    }
    let mut octets = Vec::new();
    let _ = stream.read_to_end(&mut octets);
    let mut replies = Vec::new();
    let mut rest = octets.as_slice();
    while let Some((reply, used)) =
        ipc::decode_reply_message::<DnsReply>(DNS_CHANNEL, rest).unwrap()
    {
        replies.push(reply);
        rest = &rest[used..];
    }
    assert!(rest.is_empty(), "no partial frame");
    replies
}

/// An UPDATE header (RFC 2136 §2.2: opcode 5), every count zero, forwarded
/// as dnsd forwards one it received over TCP.
fn forwarded_update() -> ForwardRequest {
    let message = DnsMessage::new(&[0x12, 0x34, 0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    ForwardRequest::new(
        Transport::Tcp,
        PeerAddress::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77))),
        message,
    )
    .unwrap()
}

/// docs/54 §4.5, §6.6; docs/questions/Q-1000 item 4: a forwarded UPDATE is
/// answered with the channel's shared refusal `Unavailable`, and the
/// connection closes (dnsd then answers SERVFAIL) — without the message
/// being read: its octets here are a bare header, which no DNS PEP would
/// accept either. dnsd's real client sees the refusal (or, where the
/// platform reports the closed socket first, a transport failure — either
/// way SERVFAIL) and its next call, on a new connection, is served.
#[test]
fn a_forwarded_message_is_refused_unread() {
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    let directory = dc_directory(&dir.join("s.redb"), true);
    let _auditd = FakeAuditd::start_recording_as(&dir.join("a.sock"), ipc_audit::EventSource::Dird);
    let dird = DnsDird::start(&dir, uid, uid, &directory);
    let before = dns_forward_refused_count();
    let replies = raw_exchange(
        &dird.dns_socket,
        &[DnsRequest::Ping, DnsRequest::Forward(forwarded_update())],
    );
    assert_eq!(
        replies,
        vec![
            ipc::Reply::Message(DnsReply::Pong {
                zone: FrontZone::Internal
            }),
            ipc::Reply::Refused(Refused::Unavailable),
        ],
        "Pong, then the shared refusal, then the close"
    );
    assert!(dns_forward_refused_count() > before);
    let mut dnsd = client(&dird.dns_socket, uid);
    match dnsd.forward(&forwarded_update()) {
        Err(Unserved::Refused(Refused::Unavailable) | Unserved::Transport(_)) => {}
        other => panic!("expected the refusal, got {other:?}"),
    }
    dnsd.ping().expect("served again on a new connection");
    dird.stop().expect("clean stop");
}

/// docs/54 §3.1 (the DC's A record comes from its computer object), §4.8:
/// without the DC's host address the zone cannot be projected — dird starts,
/// its other channels listen, `dird-dns.sock` is not bound.
#[test]
fn no_dns_service_without_the_dc_host_record() {
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    let directory = dc_directory(&dir.join("s.redb"), false);
    let _auditd = FakeAuditd::start_recording_as(&dir.join("a.sock"), ipc_audit::EventSource::Dird);
    let dird = DnsDird::start(&dir, uid, uid, &directory);
    assert!(dird.ldap_socket.exists(), "dird's other services run");
    assert!(!dird.dns_socket.exists(), "no DNS service");
    dird.stop().expect("clean stop");
}

/// A dird file with the DNS channel (hand-made; docs/questions/Q-619 item
/// 5): the zone keys, and — when `kpasswd` — the admin and kpasswd channels.
fn dird_file(kpasswd: bool) -> String {
    let mut text = String::from(
        "run_as_uid = 802\nrun_as_gid = 802\nrealm = EXAMPLE.ORG\n\
         naming_context = dc=example,dc=org\ndns_host_name = dc1.example.org\n\
         database_path = /var/lib/dird/directory.redb\n\
         integrity_key_source = insecure-development-file\n\
         integrity_key_path = /etc/dird/integrity.key\n\
         policy_store_path = /etc/domain/policy.store\n\
         policy_store_format = unsigned-development\n\
         dird_kdc_socket = /run/dird/kdc/dird-kdc.sock\nkdc_uid = 803\n\
         dird_ldap_socket = /run/dird/ldap/dird-ldap.sock\nldap_front_uid = 804\n\
         audit_socket = /run/auditd/audit.sock\nauditd_uid = 805\n\
         dird_dns_socket = /run/dird/dns/dird-dns.sock\ndnsd_uid = 809\n\
         dns_registrable_networks = 192.0.2.0/24, 198.51.100.0/24\n\
         dns_soa_rname = hostmaster.example.org\ndns_soa_refresh = 7200s\n\
         dns_soa_retry = 600s\ndns_soa_expire = 3600000s\ndns_soa_minimum = 60s\n\
         dns_infrastructure_ttl = 3600s\ndns_host_ttl = 600s\n\
         dns_record_max_age = 86400s\n",
    );
    if kpasswd {
        text.push_str(
            "dird_admin_socket = /run/dird/admin/dird-admin.sock\nadmind_uid = 806\n\
             node_id = 0123456789abcdef00112233445566ff\nadmin_ticket_age_max = 600s\n\
             admin_quorum = 2\nprovision_manifest = /etc/domain/provision.manifest\n\
             dird_kpasswd_socket = /run/dird/kpasswd/dird-kpasswd.sock\n\
             kpasswd_front_uid = 807\n",
        );
    }
    text
}

/// docs/54 §3.1 ("`_kpasswd` … synthesized only when kpasswd exists"),
/// §4.6; docs/questions/Q-1001 item 5: the product constructor reads the
/// channel and every zone value from dird's file, RNAME as the DNS name of
/// its labels, and the `_kpasswd` switch from the kpasswd channel — present
/// with it, absent without; no DNS channel ⇒ no DNS service.
#[test]
fn the_dns_parameters_come_from_dirds_file() {
    for (kpasswd, expected) in [
        (false, KpasswdService::Absent),
        (true, KpasswdService::Present),
    ] {
        let settings = DirdSettings::parse(dird_file(kpasswd).as_bytes()).unwrap();
        let dns = directory_daemon::startup::dns_params(&settings)
            .unwrap()
            .expect("the DNS channel");
        assert_eq!(dns.socket, Path::new("/run/dird/dns/dird-dns.sock"));
        assert_eq!(dns.dnsd_uid, 809);
        let mut want = zone(expected);
        want.max_record_age = 86_400;
        want.registrable_networks
            .push(Network::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24).unwrap());
        assert_eq!(dns.zone, want);
    }
    let without = dird_file(false)
        .lines()
        .filter(|l| !l.starts_with("dird_dns_socket") && !l.starts_with("dnsd_uid"))
        .filter(|l| !l.starts_with("dns_") || l.starts_with("dns_host_name"))
        .map(|l| format!("{l}\n"))
        .collect::<String>();
    let settings = DirdSettings::parse(without.as_bytes()).unwrap();
    assert!(directory_daemon::startup::dns_params(&settings)
        .unwrap()
        .is_none());
}
