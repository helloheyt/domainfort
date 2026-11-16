//! Tier-2 support for dird (docs/50 §9: "real servers run in the test's
//! threads; Unix sockets in a unique temporary directory (0700); the uid map
//! is injected with the test's own uid").
//!
//! * `keyd` — crates/keyd-daemon's own tier-2 support, reused through
//!   `#[path]`: [`TempDir`], [`my_uid`], [`skip_as_root`], [`FakeAuditd`]
//!   (the audit channel's message set), the real keyd daemon runner and its
//!   clock.
//! * [`Directory`] — a directory for the identities of the kdc fixtures
//!   (crates/kdc/tests/common: realm EXAMPLE.ORG, alice, the computer
//!   account ws1$, the service host/files.example.org, the krbtgt account),
//!   built through dirstore with the phase-1 schema, in a file of its own —
//!   beneath the one checker, so it writes what the checker would have
//!   (task PN4b; docs/59 §5.1, §5.5; docs/questions/Q-1031): the
//!   `principal-namespace` marker when the store is made, and every
//!   principal [`Directory::create_all`] creates gets its namespace keys in
//!   the same transaction, through [`namespace`] — crates/directory-pip's
//!   one fixture helper, reused through `#[path]`, which also serves this
//!   crate's own provisioned fixtures (tests/admin_service.rs,
//!   tests/kpasswd_service.rs) and crates/admin-daemon's.
//! * [`Dird`] — the real `directory_daemon::serve` on its own thread with
//!   its own current-thread runtime, stopped through `DaemonControl`.
//! * [`connector`] — the kdc's side of both sockets. On Linux the daemons'
//!   own connectors (`ipc_directory::UnixConnector`,
//!   `ipc_keyd::UnixConnector`, rustix peer credentials, R50-3); elsewhere
//!   (rustix `socket_peercred` is Linux-only — Q-245 item 11) a connector
//!   that reads the server's uid through tokio `UnixStream::peer_cred` and
//!   then hands the stream to the blocking connection — so the same
//!   server-uid check is made on every host.
//!
//! Real peer credentials on both sides; no test-only seam in the daemon.
//!
//! dird's name-resolution attestation key (task PN10; docs/59 §7.4) is the
//! fixtures' test key ([`TEST_ATTESTATION_KEY`], [`attestation_key`]) in
//! every [`params`]; a directory context a test builds for the KDC's
//! account source carries the product's signer under that key
//! ([`resolution_signer`] — `directory_daemon::ResolutionSigner`), as dird's
//! directory-view (KDC channel) context does — the only one of dird's
//! contexts with a signer (task PN10b; docs/questions/Q-1047): a context
//! for a subject check (the admin plane, kpasswd, DNS, the LDAP re-check)
//! needs none.
//!
//! **One clock per test world** (task PN11, A-190; docs/questions/Q-1063
//! items 1-2): keyd judges a resolution's age on its own clock (30 s —
//! docs/59 §7.2 step 3, R50-5), and the fixtures' keyd runs at the kdc
//! fixtures' `now` ([`fixture_now`]). So both of this support's dird clocks
//! issue at that `now`: [`params`]' clock ([`FixtureClock`]) and
//! [`resolution_signer`]. This support offers no signer at the system clock;
//! a test that needs dird's clock to move sets `DaemonParams::clock` itself
//! (tests/admin_service.rs, kpasswd_service.rs, dns_service.rs,
//! ldap_service.rs).
//!
//! Sources: docs/50 §3.1-§3.7, §9; docs/46 §4.4 (musts per class), §5.4;
//! docs/47 §1.3, §1.4, §4, §9.1 (what an account object carries; the krbtgt
//! user, RID 502); [MS-DTYP] 2.4.2.4 (SID layout). Every value is constructed
//! by hand for these tests (the times are those of crates/directory-pip's
//! fixtures, derived there in comments); no vector comes from any other
//! implementation.
#![allow(dead_code, unused_imports)] // each test binary uses a different subset

#[path = "../../../keyd-daemon/tests/support/mod.rs"]
pub mod keyd;

#[path = "../../../directory-pip/tests/common/namespace.rs"]
pub mod namespace;

pub use keyd::{eventually, my_uid, skip_as_root, FakeAuditd, TempDir, TestClock};

use ad_schema::{flags::user_account_control as uac, phase1, Phase1Schema};
use core::time::Duration;
use directory_daemon::policy::{DevelopmentPolicy, MandatoryFast};
// The full parameters and the generic `serve` are dird's test seams
// (docs/52 C18, task R15; feature `test-seams`, enabled by the
// dev-dependency).
use directory_daemon::test_seams::{serve, DaemonParams};
use directory_daemon::{
    AuditEndpoint, Clock, DaemonControl, ResolutionSigner, SharedAttestationKey, SharedClock,
    StoreSource, ATTESTATION_KEY_LEN, ENGINE_QUEUE_CAPACITY, LDAP_QUEUE_CAPACITY,
    MAX_LDAP_SESSIONS,
};
use directory_pip::{DirectoryContext, NameResolutionSigner, NamingContext};
use dirstore::{AttrId, IntegrityKey, NewObject, NodeId, Origin, Store, Timestamp};
use dtyp::{Control, Guid, SecurityDescriptor, Sid, SECURITY_NT_AUTHORITY};
use keyd_types::KeydConfig;
use krb_proto::KerberosTime;
use pdp::PolicyVersion;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;

/// The realm of the kdc fixtures, and its naming context dc=example,dc=org
/// (A-53: the DNS name example.org, upper-cased, is the realm).
pub const REALM: &str = "EXAMPLE.ORG";

/// The integrity key of the test directories (test data).
pub const TEST_KEY: [u8; 32] = [0x5D; 32];

/// whenCreated: 2026-11-01T00:00:00Z as DSTIME (derivation in
/// crates/directory-pip/tests/common `WHEN_CREATED`).
pub const WHEN_CREATED: i64 = 13_437_964_800;

/// pwdLastSet: 2026-11-05T12:00:00.5Z as FILETIME (derivation in
/// crates/directory-pip/tests/common `PWD_LAST_SET`).
pub const PWD_LAST_SET: i64 = 134_383_536_005_000_000;

/// The objects' small ids (GUID = guid(id)) and RIDs.
pub const ROOT: u32 = 1;
pub const USERS: u32 = 2;
pub const ALICE: u32 = 10;
pub const WS1: u32 = 20;
pub const FILES: u32 = 21;
pub const STAFF: u32 = 30;
pub const KRBTGT: u32 = 40;

/// A distinct, non-NULL GUID per small integer (test data).
pub fn guid(n: u32) -> Guid {
    Guid {
        data1: n,
        data2: 0xD1,
        data3: 0x0050,
        data4: [5, 0, 5, 0, 5, 0, 5, 0],
    }
}

/// S-1-5-21-7-8-9 ([MS-DTYP] 2.4.2.4 layout; the sub-authorities of the kdc
/// fixtures' SIDs).
pub fn domain_sid() -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 7, 8, 9]).unwrap()
}

/// The SID of object `id`: RID 1000 + id, krbtgt 502 ([MS-SAMR] 2.2.1.14).
pub fn sid_of(id: u32) -> Sid {
    let rid = if id == KRBTGT { 502 } else { 1000 + id };
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 7, 8, 9, rid]).unwrap()
}

/// The naming context dc=example,dc=org.
pub fn naming_context() -> NamingContext {
    NamingContext::new(&["example", "org"]).unwrap()
}

/// keyd's configuration as the kdc fixtures build it (`Setup::new`): aes256
/// then aes128, library defaults otherwise — dird advertises the same
/// enctypes and s2kparams (docs/47 R47-10).
pub fn keyd_config() -> KeydConfig {
    let mut config = KeydConfig::new(krb_proto::Realm::new(REALM).unwrap());
    config.enctypes = vec![
        keyd_types::EncTypeId::Aes256CtsHmacSha196,
        keyd_types::EncTypeId::Aes128CtsHmacSha196,
    ];
    config
}

/// A canonical self-relative security descriptor with owner and group.
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

/// dird's attestation key in these fixtures — test data, made up here (the
/// value crates/kdc tests/common and crates/directory-pip's test signer use
/// too). Spec: docs/59 §7.4.
pub const TEST_ATTESTATION_KEY: [u8; ATTESTATION_KEY_LEN] = [0x4B; ATTESTATION_KEY_LEN];

/// dird's attestation key, as its parameters carry it (task PN10).
pub fn attestation_key() -> SharedAttestationKey {
    SharedAttestationKey::from_bytes(&TEST_ATTESTATION_KEY).expect("a non-zero test key")
}

/// The kdc fixtures' `now` — crates/kdc tests/common `now`
/// (20261113100000Z), the time the fixtures' keyd runs at (module
/// documentation, "One clock per test world").
pub fn fixture_now() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 10, 0, 0).expect("a valid time")
}

/// dird's clock in these fixtures: always [`fixture_now`] (a
/// `directory_daemon::Clock` — the daemon's clock seam,
/// `DaemonParams::clock`).
#[derive(Debug, Clone, Copy)]
pub struct FixtureClock;

impl Clock for FixtureClock {
    fn now(&self) -> Option<KerberosTime> {
        Some(fixture_now())
    }
}

/// dird's own signer — `directory_daemon::ResolutionSigner` — under the test
/// key, issuing at [`fixture_now`] (the clock keyd judges the resolution's
/// age on — module documentation), for a directory context a test builds
/// itself (docs/59 §7.1, §7.2 step 3, §7.4).
pub fn resolution_signer() -> Arc<dyn NameResolutionSigner> {
    Arc::new(ResolutionSigner::new(
        attestation_key(),
        Arc::new(|| Some(fixture_now())),
    ))
}

/// A directory in its own redb file.
pub struct Directory {
    pub p1: Phase1Schema,
    pub path: PathBuf,
    pub store: Arc<Store>,
    seq: Cell<u64>,
}

impl Directory {
    /// A store at `path` with no object (mode 0600, as dird requires), and
    /// the `principal-namespace` marker (module documentation).
    pub fn empty(path: &Path) -> Directory {
        Directory::empty_marked(path, true)
    }

    /// The standard directory at `path` WITHOUT the `principal-namespace`
    /// marker: a store whose principals did not all get their keys from the
    /// one checker (from before task PN5) — the store dird refuses to open
    /// (task PN10; docs/59 §5.5).
    pub fn standard_without_namespace_marker(path: &Path) -> Directory {
        let d = Directory::empty_marked(path, false);
        d.create_all(d.standard_objects());
        d
    }

    /// A store at `path` with no object, with or without the marker.
    fn empty_marked(path: &Path, marked: bool) -> Directory {
        let p1 = phase1().unwrap();
        let store = Store::open(
            path,
            IntegrityKey::from_bytes(&TEST_KEY),
            p1.schema().clone(),
        )
        .unwrap();
        if marked {
            let mut txn = store.begin_write().unwrap();
            namespace::create_namespace_marker(&mut txn);
            txn.commit().unwrap();
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        Directory {
            p1,
            path: path.to_path_buf(),
            store: Arc::new(store),
            seq: Cell::new(0),
        }
    }

    /// The directory of the kdc fixtures' identities at `path`:
    /// - domainDNS dc=example (objectSid S-1-5-21-7-8-9)
    ///   - cn=Users: alice (user), ws1$ (computer, WT, SPN host/ws1.example.org),
    ///     files$ (computer, WT, SPN host/files.example.org), staff (global
    ///     security group: alice), krbtgt (user, RID 502)
    pub fn standard(path: &Path) -> Directory {
        let d = Directory::empty(path);
        d.create_all(d.standard_objects());
        d
    }

    fn attr(&self, name: &str) -> AttrId {
        self.p1.attribute_by_name(name).unwrap()
    }

    pub fn origin(&self) -> Origin {
        let seq = self.seq.get() + 1;
        self.seq.set(seq);
        Origin {
            wall_clock: Timestamp(2000 + seq),
            origin_node: NodeId([0xDD; 16]),
            origin_seq: seq,
        }
    }

    fn object(
        &self,
        id: u32,
        parent: Option<u32>,
        class: &str,
        attrs: &[(&str, Vec<Vec<u8>>)],
    ) -> NewObject {
        let mut attributes: Vec<(AttrId, Vec<Vec<u8>>)> = attrs
            .iter()
            .map(|(n, v)| (self.attr(n), v.clone()))
            .collect();
        attributes.push((self.attr("nTSecurityDescriptor"), vec![sd_value()]));
        let class_id = self.p1.class_by_name(class).unwrap();
        NewObject {
            guid: guid(id),
            parent: parent.map(guid),
            classes: self.p1.class(class_id).unwrap().object_class.clone(),
            attributes,
        }
    }

    fn principal(
        &self,
        class: &str,
        id: u32,
        sam: &str,
        extra: &[(&str, Vec<Vec<u8>>)],
    ) -> NewObject {
        let mut attrs = vec![
            ("cn", vec![sam.as_bytes().to_vec()]),
            ("sAMAccountName", vec![sam.as_bytes().to_vec()]),
            ("objectSid", vec![sid_of(id).encode()]),
        ];
        if class != "group" {
            attrs.push(("whenCreated", vec![WHEN_CREATED.to_be_bytes().to_vec()]));
        }
        attrs.extend(extra.iter().cloned());
        self.object(id, Some(USERS), class, &attrs)
    }

    pub fn standard_objects(&self) -> Vec<NewObject> {
        let flags = |v: u32| vec![v.to_be_bytes().to_vec()];
        let pwd = || ("pwdLastSet", vec![PWD_LAST_SET.to_be_bytes().to_vec()]);
        vec![
            self.object(
                ROOT,
                None,
                "domainDNS",
                &[
                    ("dc", vec![b"example".to_vec()]),
                    ("objectSid", vec![domain_sid().encode()]),
                ],
            ),
            self.object(
                USERS,
                Some(ROOT),
                "container",
                &[("cn", vec![b"Users".to_vec()])],
            ),
            self.principal(
                "user",
                ALICE,
                "alice",
                &[
                    ("userAccountControl", flags(uac::ADS_UF_NORMAL_ACCOUNT)),
                    pwd(),
                ],
            ),
            self.principal(
                "computer",
                WS1,
                "ws1$",
                &[
                    (
                        "userAccountControl",
                        flags(uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT),
                    ),
                    pwd(),
                    (
                        "servicePrincipalName",
                        vec![b"host/ws1.example.org".to_vec()],
                    ),
                ],
            ),
            self.principal(
                "computer",
                FILES,
                "files$",
                &[
                    (
                        "userAccountControl",
                        flags(uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT),
                    ),
                    pwd(),
                    (
                        "servicePrincipalName",
                        vec![b"host/files.example.org".to_vec()],
                    ),
                ],
            ),
            self.principal(
                "group",
                STAFF,
                "staff",
                &[
                    ("groupType", vec![(i32::MIN | 0x2).to_be_bytes().to_vec()]),
                    ("member", vec![guid(ALICE).to_packet().to_vec()]),
                ],
            ),
            self.principal(
                "user",
                KRBTGT,
                "krbtgt",
                &[
                    ("userAccountControl", flags(uac::ADS_UF_NORMAL_ACCOUNT)),
                    pwd(),
                ],
            ),
        ]
    }

    /// Create every object in one committed transaction, each principal with
    /// its namespace keys as the one checker writes them (module
    /// documentation; this world holds no provisioned service object).
    pub fn create_all(&self, objects: Vec<NewObject>) {
        let ctx = DirectoryContext::new(self.p1.clone(), &keyd_config(), naming_context()).unwrap();
        let mut txn = self.store.begin_write().unwrap();
        let mut created = Vec::with_capacity(objects.len());
        for obj in objects {
            let origin = self.origin();
            created.push((obj.guid, origin));
            txn.create_object(obj, &origin).unwrap();
        }
        namespace::write_namespace_keys(&self.store, &mut txn, &ctx, &created);
        txn.commit().unwrap();
    }

    /// Disable alice (a write committed by the test).
    pub fn disable_alice(&self) {
        let mut txn = self.store.begin_write().unwrap();
        let origin = self.origin();
        txn.modify_object(
            guid(ALICE),
            vec![dirstore::AttributeChange::Replace {
                id: self.attr("userAccountControl"),
                values: vec![(uac::ADS_UF_NORMAL_ACCOUNT | uac::ADS_UF_ACCOUNT_DISABLE)
                    .to_be_bytes()
                    .to_vec()],
            }],
            &origin,
        )
        .unwrap();
        txn.commit().unwrap();
    }
}

/// The unsigned development policy of version `version`: no tier entry, no
/// rule of its own, no anonymous grant; the mandatory-FAST entry names the
/// computer account ws1$ itself as the bootstrap set (crates/pdp: the
/// principal is a member of its own SID's set) with rule ids 100..=103
/// (format 2 requires the entry, A-68; test data).
pub fn policy(version: u64) -> DevelopmentPolicy {
    DevelopmentPolicy {
        version: PolicyVersion(version),
        principals: BTreeMap::new(),
        subtrees: Vec::new(),
        mandatory_fast: MandatoryFast {
            bootstrap_group: sid_of(WS1),
            first_rule_id: pdp::RuleId(100),
        },
        rules: Vec::new(),
        anonymous: Vec::new(),
    }
}

/// dird's parameters in `dir`: `d.sock`, kdc uid `kdc_uid`, auditd at
/// `a.sock` as `auditd_uid`, view lifetime `lifetime`, `max_views` views;
/// the LDAP channel at `l.sock` for the same uid as the kdc's, the daemon's
/// session bound and queue, the fixtures' clock ([`FixtureClock`]: one
/// clock per test world — module documentation).
pub fn params(
    dir: &TempDir,
    kdc_uid: u32,
    auditd_uid: u32,
    lifetime: Duration,
    max_views: usize,
) -> DaemonParams {
    DaemonParams {
        kdc_socket: dir.join("d.sock"),
        kdc_uid,
        audit: AuditEndpoint {
            socket: dir.join("a.sock"),
            uid: auditd_uid,
        },
        frame_timeout: Duration::from_secs(1),
        view_lifetime: lifetime,
        max_views,
        max_connections: 8,
        queue_capacity: ENGINE_QUEUE_CAPACITY,
        naming_context: naming_context(),
        keyd: keyd_config(),
        ldap_socket: dir.join("l.sock"),
        ldap_front_uid: kdc_uid,
        max_ldap_sessions: MAX_LDAP_SESSIONS,
        ldap_queue_capacity: LDAP_QUEUE_CAPACITY,
        dns_host_name: String::from("dc1.example.org"),
        audit_window: ipc_audit::WindowConfig::DEFAULT,
        clock: SharedClock::new(FixtureClock),
        attestation_key: attestation_key(),
    }
}

/// The real dird on its own thread.
pub struct Dird {
    control: DaemonControl,
    /// The thread's result: the LDAP audit events left unacknowledged at
    /// the stop (`Stopped::unacknowledged_audit_events`, Q-313), or why it
    /// failed.
    thread: Option<JoinHandle<Result<usize, String>>>,
    pub socket: PathBuf,
    pub ldap_socket: PathBuf,
}

impl Dird {
    /// Start `serve` and wait until it listens; a start-up failure is
    /// returned as its message.
    pub fn start(
        params: DaemonParams,
        source: StoreSource,
        policy: DevelopmentPolicy,
    ) -> Result<Dird, String> {
        let control = DaemonControl::new();
        let socket = params.kdc_socket.clone();
        let ldap_socket = params.ldap_socket.clone();
        let thread = {
            let control = control.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                let result = runtime.block_on(serve(params, source, policy, control));
                drop(runtime);
                match result {
                    Ok(stopped) => {
                        let failed = stopped.engine_failed();
                        let unacknowledged = stopped.unacknowledged_audit_events();
                        stopped
                            .join()
                            .map_err(|_| String::from("engine panicked"))?;
                        if failed {
                            Err(String::from("engine stopped early"))
                        } else {
                            Ok(unacknowledged)
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
                start.elapsed() < Duration::from_secs(10),
                "dird did not start"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(Dird {
            control,
            thread: Some(thread),
            socket,
            ldap_socket,
        })
    }

    /// Stop dird and wait for it (engine joined).
    pub fn stop(self) -> Result<(), String> {
        self.stop_counting().map(|_| ())
    }

    /// Stop dird and wait for it; the LDAP audit events auditd had not
    /// acknowledged when dird ended its audit task (docs/questions/Q-313).
    pub fn stop_counting(mut self) -> Result<usize, String> {
        self.control.stop();
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for Dird {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.control.stop();
            let _ = thread.join();
        }
    }
}

#[cfg(target_os = "linux")]
pub mod connector {
    //! Linux: the kdc daemon's own connectors (rustix peer credentials).
    pub type DirdConnector = ipc_directory::UnixConnector;
    pub type KeydConnector = ipc_keyd::UnixConnector;

    pub fn dird(path: &std::path::Path) -> DirdConnector {
        ipc_directory::UnixConnector::new(path.to_path_buf())
    }

    pub fn keyd(path: &std::path::Path) -> KeydConnector {
        ipc_keyd::UnixConnector::new(path.to_path_buf())
    }
}

#[cfg(not(target_os = "linux"))]
pub mod connector {
    //! Other hosts: the server's uid through tokio `UnixStream::peer_cred`,
    //! then the blocking connection for the exchanges (tokio 1.54.1 docs.rs:
    //! `from_std` needs a runtime context and a non-blocking stream;
    //! `into_std` returns it non-blocking).
    use ipc::FrameLimit;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use zeroize::Zeroizing;

    /// Connect and read the server's uid from the kernel.
    pub fn connect_checked(
        path: &Path,
        runtime: &tokio::runtime::Runtime,
    ) -> Option<(u32, UnixStream)> {
        let stream = UnixStream::connect(path).ok()?;
        stream.set_nonblocking(true).ok()?;
        let _context = runtime.enter();
        let stream = tokio::net::UnixStream::from_std(stream).ok()?;
        let uid = stream.peer_cred().ok()?.uid();
        let stream = stream.into_std().ok()?;
        stream.set_nonblocking(false).ok()?;
        Some((uid, stream))
    }

    pub fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap()
    }

    pub struct DirdConnector {
        path: PathBuf,
        runtime: tokio::runtime::Runtime,
    }

    pub struct DirdChecked {
        uid: u32,
        inner: ipc_directory::UnixConnection,
    }

    pub fn dird(path: &Path) -> DirdConnector {
        DirdConnector {
            path: path.to_path_buf(),
            runtime: runtime(),
        }
    }

    impl ipc_directory::Connector for DirdConnector {
        type Connection = DirdChecked;
        fn connect(&mut self) -> Result<DirdChecked, ipc_directory::TransportError> {
            let (uid, stream) = connect_checked(&self.path, &self.runtime)
                .ok_or(ipc_directory::TransportError::Connect)?;
            Ok(DirdChecked {
                uid,
                inner: ipc_directory::UnixConnection::from_stream(stream),
            })
        }
    }

    impl ipc_directory::Connection for DirdChecked {
        fn peer_uid(&self) -> Result<u32, ipc_directory::TransportError> {
            Ok(self.uid)
        }
        fn exchange(
            &mut self,
            frame: &[u8],
            reply_limit: FrameLimit,
            deadline: Duration,
        ) -> Result<Zeroizing<Vec<u8>>, ipc_directory::TransportError> {
            self.inner.exchange(frame, reply_limit, deadline)
        }
        /// The blocking connection's own idle check (docs/questions/Q-312).
        fn check_idle(&mut self) -> Result<(), ipc_directory::TransportError> {
            self.inner.check_idle()
        }
    }

    pub struct KeydConnector {
        path: PathBuf,
        runtime: tokio::runtime::Runtime,
    }

    pub struct KeydChecked {
        uid: u32,
        inner: ipc_keyd::UnixConnection,
    }

    pub fn keyd(path: &Path) -> KeydConnector {
        KeydConnector {
            path: path.to_path_buf(),
            runtime: runtime(),
        }
    }

    impl ipc_keyd::Connector for KeydConnector {
        type Connection = KeydChecked;
        fn connect(&mut self) -> Result<KeydChecked, ipc_keyd::TransportError> {
            let (uid, stream) = connect_checked(&self.path, &self.runtime)
                .ok_or(ipc_keyd::TransportError::Connect)?;
            Ok(KeydChecked {
                uid,
                inner: ipc_keyd::UnixConnection::from_stream(stream),
            })
        }
    }

    impl ipc_keyd::Connection for KeydChecked {
        fn peer_uid(&self) -> Result<u32, ipc_keyd::TransportError> {
            Ok(self.uid)
        }
        fn exchange(
            &mut self,
            frame: &[u8],
            reply_limit: FrameLimit,
            deadline: Duration,
        ) -> Result<Zeroizing<Vec<u8>>, ipc_keyd::TransportError> {
            self.inner.exchange(frame, reply_limit, deadline)
        }
        /// The blocking connection's own idle check (docs/questions/Q-312).
        fn check_idle(&mut self) -> Result<(), ipc_keyd::TransportError> {
            self.inner.check_idle()
        }
    }
}
