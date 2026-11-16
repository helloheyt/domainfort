//! Part B starts from part A's files: `keyadm ceremony` (task A5, through
//! its public API) against the real keyd daemon (`keyd_daemon::serve`, the
//! development key store, an in-process fake auditd — the harness of
//! crates/keyd-daemon/tests/support, reused through `#[path]` as
//! crates/keyadm/tests does), with
//!
//! - keyd's `uid → Role` map taken from the **produced** keyd configuration
//!   file (`CallerMap::from_role_map` of its parsed `uid_roles`; the test's
//!   uid is provisioned as keyadm's, so keyd gives it Role::Admin — A-73);
//! - the **produced** manifest file, parsed back.
//!
//! - (task PN12) keyadm's **produced** attestation-key copy, read through
//!   keyadm's own reader, which the ceremony installs in keyd before the
//!   seal.
//!
//! The ceremony creates the four key sets of the manifest (docs/51 §4.3
//! step 11; docs/53 §5.2 for the fourth, task K9): krbtgt, the LDAP service,
//! the admin service and the change-password service (`kadmin/changepw`,
//! RFC 3244 §2) — and installs the attestation key (task PN9).
//!
//! Sources: docs/51 §4.3 steps 7-8, 11; A-73 (keyd's role map); A-86 (the
//! manifest and the ceremony); docs/10 §7 (`create_key` returns kvno 1 for
//! a new key set — A-35); docs/59 §7.4, §10 (PN9, PN12), docs/questions/
//! Q-1039 items 1-2 (A-183). Fixtures: tests/common.

#[path = "../../keyd-daemon/tests/support/mod.rs"]
mod support;

mod common;

use ipc_keyd::{KeydClient, DEFAULT_DEADLINE};
use keyadm::ceremony;
use keyd_daemon::startup::development_keyd;
use keyd_daemon::{CallerMap, SystemClock};
use krb_proto::Realm;
use provision::provision_domain;
use provision_manifest::Manifest;
use support::{params, Daemon, FakeAuditd};

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
    //! `ipc_keyd::UnixConnection` — as crates/keyadm/tests/ceremony.rs
    //! does (tokio 1.54.1 docs.rs: `from_std` needs a runtime context and
    //! a non-blocking stream; `into_std` returns it non-blocking).
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

/// docs/51 §4.3 steps 7, 8, 11: the produced keyd configuration gives the
/// keyadm uid Role::Admin, and the produced manifest drives a complete
/// ceremony (four key sets created — task K9 added the change-password
/// service's, docs/53 §5.2; exactly the manifest's, each kvno 1).
#[test]
fn keyadm_ceremony_completes_with_the_produced_manifest_and_role_map() {
    let dir = common::TempDir::new();
    let uid = common::my_uid(&dir);
    if common::skip_as_root(uid) {
        return;
    }
    // The test's uid is keyadm's here; dird gets another (fake) uid.
    let input = common::input(&dir, 61002, uid);
    let (plan, _) = provision_domain(
        &input,
        common::now(),
        &mut common::CountingRandom::default(),
        &mut common::Recorder::new(uid),
        &mut common::HaltAt::never(),
    )
    .unwrap();
    let keyd_settings =
        config::KeydSettings::parse(&std::fs::read(input.paths.keyd_config.as_path()).unwrap())
            .unwrap();
    assert_eq!(
        keyd_settings.uid_roles().role_of(uid),
        Some(config::RoleName::Admin)
    );
    let callers = CallerMap::from_role_map(keyd_settings.uid_roles()).unwrap();
    let manifest =
        Manifest::parse(&std::fs::read(input.paths.manifest.as_path()).unwrap()).unwrap();
    assert_eq!(manifest, plan.manifest);

    let keyd_dir = support::TempDir::new();
    let params = params(&keyd_dir, callers, uid);
    let _auditd = FakeAuditd::start(&params.audit.socket);
    let realm = Realm::new(keyd_settings.realm()).unwrap();
    let daemon = Daemon::start(params, SystemClock, development_keyd(realm)).unwrap();
    // keyd runs in-process, as the test's uid.
    let mut client = KeydClient::new(
        connector::new(&daemon.socket),
        ipc_keyd::ExpectedPeer::new(uid, keyd::Role::Admin).unwrap(),
        DEFAULT_DEADLINE,
    );
    // A-102 (N4): the produced manifest carries every first administrator's
    // salt (a required key — A-105), so the ceremony grants them and ends
    // with the seal (R3).
    assert!(manifest.first_admins().iter().all(|a| !a.salt().is_empty()));
    // Task PN12 (docs/59 §7.4; A-183 on docs/questions/Q-1039 item 2): the
    // ceremony's second operand is the copy this run produced for keyadm
    // (the test's uid stands in for keyadm's account — no chown here); the
    // ceremony installs it in keyd after the key sets, before the grants.
    let key = common::keyadm_attestation_key(&input.paths, uid);
    let report = ceremony::run_with_attestation_key(&mut client, &manifest, key);
    assert!(report.is_complete(), "{report:?}");
    assert!(report.is_sealed());
    assert!(report.attestation_key_installed(), "{report:?}");
    assert_eq!(
        report.created(),
        [
            (ceremony::Step::Krbtgt, keyd_types::Kvno::INITIAL),
            (ceremony::Step::LdapService, keyd_types::Kvno::INITIAL),
            (ceremony::Step::AdminService, keyd_types::Kvno::INITIAL),
            (
                ceremony::Step::ChangePasswordService,
                keyd_types::Kvno::INITIAL
            ),
        ]
    );
    // The fourth key set is the produced change-password service object's:
    // `(GUID, ChangePasswordService)` bound to kadmin/changepw.
    let changepw = manifest.change_password_service();
    assert_eq!(
        changepw.handle.principal.as_bytes(),
        &plan
            .object(provision::ObjectRole::ChangePasswordService)
            .unwrap()
            .guid
            .to_packet()
    );
    assert_eq!(
        changepw.handle.purpose,
        keyd_types::KeyPurpose::ChangePasswordService
    );
    assert_eq!(changepw.binding_text(), "NT-SRV-INST:kadmin/changepw");
    daemon.stop().unwrap();
}
