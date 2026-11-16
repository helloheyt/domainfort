//! Tier 2 (docs/50 §9: real temp-dir sockets, the uid map injected with the
//! test's own uid): dird's directory-view service through `serve` — the
//! listener, peer credentials, the engine thread, the view table.
//!
//! * a peer that is not the kdc's uid is closed without a reply (R50-3,
//!   §3.2);
//! * auditd is verified first — without it nothing is bound (R50-16);
//! * the redb file must be dird's own, and the integrity key the store's
//!   (§6.4, §7.5 step 3);
//! * a store without the `principal-namespace` marker is not opened (task
//!   PN10; docs/59 §5.5);
//! * view pinning over the socket: a write committed after `BeginView` is
//!   invisible to that view until a new one (§3.4; D39);
//! * the view lifetime and the bound on concurrent views (§3.4);
//! * `DescribeDomain` and `Ping` (§3.4, §7.5).
//!
//! Sources: docs/50 R50-2, R50-3, R50-16, §3.2, §3.4, §6.4, §7.5, §9;
//! docs/32 §6 (D39); docs/59 §5.5. Every value is hand-made
//! (tests/support).

mod support;

use core::time::Duration;
use directory_daemon::{refused_peer_count, StoreSource};
use dirstore::IntegrityKey;
use ipc::{encode_frame, Direction};
use ipc_directory::typed::Request;
use ipc_directory::{DirectoryClient, TransportError, Unserved, ViewFailure, DIRECTORY_CHANNEL};
use kdc::{AccountSource, AccountSourceError};
use krb_proto::constants::KRB_NT_PRINCIPAL;
use krb_proto::{KerberosString, PrincipalName, Realm};
use pdp::PolicyVersion;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use support::{connector, Dird, Directory, FakeAuditd, TempDir};

fn alice() -> PrincipalName {
    PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![KerberosString::new("alice").unwrap()],
    }
}

fn realm() -> Realm {
    Realm::new(support::REALM).unwrap()
}

/// The kdc's client of `dird` (the test is the kdc and runs as dird's uid).
fn client(dird: &Dird, uid: u32, version: u64) -> DirectoryClient<connector::DirdConnector> {
    DirectoryClient::connect(
        connector::dird(&dird.socket),
        uid,
        ipc_directory::DEFAULT_DEADLINE,
        PolicyVersion(version),
    )
    .unwrap()
}

/// A running dird over a standard directory (shared with the test through
/// the opened store) and its auditd.
struct World {
    dir: TempDir,
    uid: u32,
    directory: Directory,
    _auditd: FakeAuditd,
    dird: Dird,
}

fn world(kdc_uid_offset: u32, lifetime: Duration, max_views: usize) -> Option<World> {
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
    if support::skip_as_root(uid) {
        return None;
    }
    let directory = Directory::standard(&dir.join("s.redb"));
    let auditd = FakeAuditd::start_recording_as(&dir.join("a.sock"), ipc_audit::EventSource::Dird);
    let dird = Dird::start(
        support::params(&dir, uid + kdc_uid_offset, uid, lifetime, max_views),
        directory_daemon::test_seams::opened(Arc::clone(&directory.store)),
        support::policy(1),
    )
    .unwrap();
    Some(World {
        dir,
        uid,
        directory,
        _auditd: auditd,
        dird,
    })
}

/// docs/50 R50-3, §3.2 ("dird-kdc.sock ← kdc's uid only"; an unmapped uid ⇒
/// the connection is closed): dird configured for another uid closes the
/// test's connection without any reply — a raw request sees end of stream,
/// the kdc's client sees the transport closed.
#[test]
fn a_peer_that_is_not_the_kdc_is_closed_without_a_reply() {
    let Some(w) = world(1, Duration::from_secs(5), 4) else {
        return;
    };
    let before = refused_peer_count();
    let mut raw = UnixStream::connect(&w.dird.socket).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let ping = encode_frame(
        DIRECTORY_CHANNEL,
        Direction::Request,
        &Request::Ping.to_wire().unwrap(),
    )
    .unwrap();
    let _ = raw.write_all(ping.as_bytes());
    let mut octets = Vec::new();
    let _ = raw.read_to_end(&mut octets);
    assert!(octets.is_empty(), "no reply to a refused peer");
    assert!(refused_peer_count() > before);
    // The kdc's client of such a dird: its start-time DescribeDomain is
    // closed unanswered — no client (task R9).
    let kdc_side = DirectoryClient::connect(
        connector::dird(&w.dird.socket),
        w.uid,
        ipc_directory::DEFAULT_DEADLINE,
        PolicyVersion(1),
    );
    assert!(matches!(
        kdc_side.err(),
        Some(ipc_directory::ConnectError::Unserved(Unserved::Transport(
            TransportError::Closed | TransportError::Io
        )))
    ));
}

/// docs/50 R50-16, §7.5 ("auditd → keyd → dird …; a daemon binds nothing
/// until its dependencies were verified"): without auditd, or with a process
/// of the wrong uid on the audit socket, dird does not start and the
/// dird-kdc socket is never created.
#[test]
fn auditd_is_verified_first() {
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    let directory = Directory::standard(&dir.join("s.redb"));
    let start = |auditd_uid| {
        Dird::start(
            support::params(&dir, uid, auditd_uid, Duration::from_secs(5), 4),
            directory_daemon::test_seams::opened(Arc::clone(&directory.store)),
            support::policy(1),
        )
    };
    let error = start(uid).err().unwrap();
    assert!(error.contains("auditd not verified"), "{error}");
    assert!(!dir.join("d.sock").exists());
    let _auditd = FakeAuditd::start_recording_as(&dir.join("a.sock"), ipc_audit::EventSource::Dird);
    let error = start(uid + 1).err().unwrap();
    assert!(error.contains("not the configured auditd uid"), "{error}");
    assert!(!dir.join("d.sock").exists());
    start(uid).unwrap().stop().unwrap();
}

/// Attack — task R9b (docs/questions/Q-512, Q-560; docs/50 §3.2: the source
/// is set from the uid): an auditd whose map gives dird's uid another
/// source is refused at its first `Pong`, before any event is sent; dird
/// does not start and the dird-kdc socket is never created.
#[test]
fn an_auditd_recording_dird_under_another_source_is_refused() {
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    let directory = Directory::standard(&dir.join("s.redb"));
    for other in ipc_audit::EventSource::ALL
        .into_iter()
        .filter(|s| *s != ipc_audit::EventSource::Dird)
    {
        let auditd = FakeAuditd::start_recording_as(&dir.join("a.sock"), other);
        let error = Dird::start(
            support::params(&dir, uid, uid, Duration::from_secs(5), 4),
            directory_daemon::test_seams::opened(Arc::clone(&directory.store)),
            support::policy(1),
        )
        .err()
        .unwrap();
        assert!(error.contains("another source"), "{other:?}: {error}");
        assert!(!dir.join("d.sock").exists(), "{other:?}");
        assert!(auditd.events().is_empty(), "{other:?}: nothing sent");
    }
}

/// docs/50 R50-2, §6.4 ("the redb file owned by dird, 0600"), §7.5 step 3
/// (`Store::open` with the IntegrityKey — a wrong key ⇒ `Error::Tamper`);
/// docs/questions/Q-270 item 3: dird opens only its own, existing file, and
/// only with the key the store was sealed with.
#[test]
fn the_redb_file_must_be_dirds_own_and_the_key_the_stores() {
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    // The store inside the workspace (crates/test-scratch): dird reaches it
    // through the protected-file walk from `/` (task R11b, Q-530).
    let files = test_scratch::ScratchDir::new("dird-store").unwrap();
    let path = files.join("s.redb");
    drop(Directory::standard(&path));
    let _auditd = FakeAuditd::start_recording_as(&dir.join("a.sock"), ipc_audit::EventSource::Dird);
    let start = |path: std::path::PathBuf, key: [u8; 32], owner_uid: u32| {
        Dird::start(
            support::params(&dir, uid, uid, Duration::from_secs(5), 4),
            StoreSource::File {
                path,
                key: IntegrityKey::from_bytes(&key),
                owner_uid,
            },
            support::policy(1),
        )
    };
    let missing = start(files.join("none.redb"), support::TEST_KEY, uid)
        .err()
        .unwrap();
    assert!(missing.contains("directory file"), "{missing}");
    let other_owner = start(path.clone(), support::TEST_KEY, uid + 1)
        .err()
        .unwrap();
    assert!(other_owner.contains("directory file"), "{other_owner}");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let open_to_group = start(path.clone(), support::TEST_KEY, uid).err().unwrap();
    assert!(open_to_group.contains("directory file"), "{open_to_group}");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let wrong_key = start(path.clone(), [0x11; 32], uid).err().unwrap();
    assert!(wrong_key.contains("could not be opened"), "{wrong_key}");
    assert!(!dir.join("d.sock").exists());
    start(path, support::TEST_KEY, uid).unwrap().stop().unwrap();
}

/// docs/59 §5.2 (c), §5.5; docs/questions/Q-1008 item 5, Q-1043 (A-185:
/// "dird refuses a store without the marker"): a store without the
/// `principal-namespace` marker — its principals did not all get their keys
/// from the one checker — is not opened, whichever source hands it over (an
/// opened store or dird's file): dird does not start, binds nothing, and
/// says why without a value; the same store with the marker starts.
#[test]
fn a_store_without_the_principal_namespace_marker_is_refused() {
    let dir = TempDir::new();
    let uid = support::my_uid(&dir);
    if support::skip_as_root(uid) {
        return;
    }
    let _auditd = FakeAuditd::start_recording_as(&dir.join("a.sock"), ipc_audit::EventSource::Dird);
    let unmarked = Directory::standard_without_namespace_marker(&dir.join("u.redb"));
    let error = Dird::start(
        support::params(&dir, uid, uid, Duration::from_secs(5), 4),
        directory_daemon::test_seams::opened(Arc::clone(&unmarked.store)),
        support::policy(1),
    )
    .err()
    .unwrap();
    assert!(error.contains("principal-namespace"), "{error}");
    assert!(error.contains("re-provision"), "{error}");
    assert!(!dir.join("d.sock").exists());
    drop(unmarked);
    // From dird's own file too.
    let files = test_scratch::ScratchDir::new("dird-unmarked").unwrap();
    let path = files.join("u.redb");
    drop(Directory::standard_without_namespace_marker(&path));
    let error = Dird::start(
        support::params(&dir, uid, uid, Duration::from_secs(5), 4),
        StoreSource::File {
            path,
            key: IntegrityKey::from_bytes(&support::TEST_KEY),
            owner_uid: uid,
        },
        support::policy(1),
    )
    .err()
    .unwrap();
    assert!(error.contains("principal-namespace"), "{error}");
    assert!(!dir.join("d.sock").exists());
    // The marked standard store starts.
    let marked = Directory::standard(&dir.join("m.redb"));
    Dird::start(
        support::params(&dir, uid, uid, Duration::from_secs(5), 4),
        directory_daemon::test_seams::opened(Arc::clone(&marked.store)),
        support::policy(1),
    )
    .unwrap()
    .stop()
    .unwrap();
}

/// docs/50 §3.4 ("each connection pins one snapshot"); docs/32 §6 (D39):
/// over the real socket, a write committed after `BeginView` is not
/// visible through that view; the next view sees it.
#[test]
fn a_pinned_view_does_not_see_a_later_write() {
    let Some(w) = world(0, Duration::from_secs(5), 4) else {
        return;
    };
    let mut kdc_side = client(&w.dird, w.uid, 1);
    {
        let view = kdc_side.begin_view().unwrap();
        let before = view.client(&realm(), &alice()).unwrap().unwrap();
        assert!(before.state.enabled);
        w.directory.disable_alice();
        let again = view.client(&realm(), &alice()).unwrap().unwrap();
        // The same record from the same snapshot — every field, and a
        // resolution of the same lookup (only its issue time is the second
        // dird attested it in — task PN10, docs/59 §7.1).
        assert_eq!(again.key, before.key);
        assert_eq!(again.sid, before.sid);
        assert_eq!(again.groups, before.groups);
        assert_eq!(again.tier, before.tier);
        assert_eq!(again.state, before.state);
        assert_eq!(again.etype_info, before.etype_info);
        assert_eq!(again.kind, before.kind);
        assert_eq!(again.armor_policy, before.armor_policy);
        let (now, then) = (
            again.resolution.resolution(),
            before.resolution.resolution(),
        );
        assert_eq!(now.name_as_sent(), then.name_as_sent());
        assert_eq!(now.canonical_name(), then.canonical_name());
        assert_eq!(now.principal(), then.principal());
        assert_eq!(now.snapshot(), then.snapshot());
        view.end().unwrap();
    }
    let view = kdc_side.begin_view().unwrap();
    assert!(
        !view
            .client(&realm(), &alice())
            .unwrap()
            .unwrap()
            .state
            .enabled
    );
    drop(view);
    drop(w.dir);
}

/// docs/50 §3.4 ("expires after ≤ 5 s"): with a 1 s lifetime, a view older
/// than that is released by dird; the kdc's query is then `Unavailable`
/// (never an answer from a stale snapshot), and the next view is served.
#[test]
fn a_view_expires_after_its_lifetime() {
    let Some(w) = world(0, Duration::from_secs(1), 4) else {
        return;
    };
    let mut kdc_side = client(&w.dird, w.uid, 1);
    {
        let view = kdc_side.begin_view().unwrap();
        assert!(view.client(&realm(), &alice()).unwrap().is_some());
        std::thread::sleep(Duration::from_millis(1200));
        assert_eq!(
            view.client(&realm(), &alice()).err(),
            Some(AccountSourceError::Unavailable)
        );
        assert!(!view.is_open());
    }
    let view = kdc_side.begin_view().unwrap();
    assert!(view.client(&realm(), &alice()).unwrap().is_some());
}

/// docs/50 §3.4 (a bound on concurrent views; one view per connection):
/// with two views allowed, a third connection's `BeginView` is refused
/// (`ViewLimit` ⇒ the kdc answers through `UnavailableDirectory`); when a
/// connection ends, its view is released and the third is served.
#[test]
fn concurrent_views_are_bounded() {
    let Some(w) = world(0, Duration::from_secs(5), 2) else {
        return;
    };
    let mut first = client(&w.dird, w.uid, 1);
    let mut second = client(&w.dird, w.uid, 1);
    let mut third = client(&w.dird, w.uid, 1);
    let one = first.begin_view().unwrap();
    let two = second.begin_view().unwrap();
    assert_eq!(
        third.begin_view().err(),
        Some(Unserved::View(ViewFailure::ViewLimit))
    );
    drop(two);
    drop(second);
    // The release travels through the engine queue; retry briefly.
    assert!(support::eventually(Duration::from_secs(5), || third
        .begin_view()
        .is_ok()));
    assert!(one.client(&realm(), &alice()).unwrap().is_some());
}

/// docs/50 §3.4, §7.5: `DescribeDomain` gives the realm, the naming
/// context, the krbtgt handle and the policy version; `Ping` answers; the
/// kdc refuses a view whose policy version is not its own (R50-2).
#[test]
fn describe_domain_ping_and_the_policy_version() {
    let Some(w) = world(0, Duration::from_secs(5), 4) else {
        return;
    };
    let mut kdc_side = client(&w.dird, w.uid, 1);
    let domain = kdc_side.describe_domain().unwrap();
    assert_eq!(domain.realm, realm());
    assert_eq!(domain.naming_context, ["example", "org"]);
    assert_eq!(domain.policy_version, PolicyVersion(1));
    assert_eq!(
        domain.krbtgt.principal.as_bytes(),
        &support::guid(support::KRBTGT).to_packet()
    );
    assert_eq!(kdc_side.ping(), Ok(()));
    // A kdc of another policy version gets no client at all (task R9: its
    // start-time DescribeDomain is refused).
    let other_version = DirectoryClient::connect(
        connector::dird(&w.dird.socket),
        w.uid,
        ipc_directory::DEFAULT_DEADLINE,
        PolicyVersion(2),
    );
    assert_eq!(
        other_version.err(),
        Some(ipc_directory::ConnectError::Unserved(
            Unserved::PolicyVersionMismatch {
                dird: PolicyVersion(1)
            }
        ))
    );
}
