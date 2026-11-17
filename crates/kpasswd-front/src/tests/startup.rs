//! The start-up checks of `serve`, each failing closed before anything is
//! served — and the product start against the real auditd: with the front's
//! uid mapped to `kpasswd-front` it passes the audit check and goes on to
//! the next real dependency, dird; without that mapping it fails closed.
//!
//! Sources: docs/50 R50-16 ("a daemon does not bind a network port until
//! its dependencies are verified (configuration, keyd, dird, audit)"), §3.2
//! ("the source is set from the uid"), §7.5 (fail closed); docs/53 §3.3
//! (every listen address inside `internal_networks`), §5.6 step 1 (dird's
//! uid and zone), §5.7 (the realm of the KRB-ERROR), §9; docs/52 R14, §3.12,
//! §3.18 (C18: the product parameters only); docs/questions/Q-955 item 1
//! (A-158), Q-960 (task DN12: the source `kpasswd-front`, code 8). Uids,
//! paths and the realm are hand-made test values.

#![cfg(unix)]

use super::auditd_support;
use super::world::*;
use crate::audit::FRONT_AUDIT_SOURCE;
use crate::{serve, DaemonControl, DaemonError, Listeners};
use audit_daemon::listener::ListenerConfig;
use config::Network;
use core::net::{IpAddr, Ipv4Addr};
use ipc_audit::EventSource;
use ipc_audit_client::AuditLinkError;
use ipc_kpasswd::{TransportError, Unserved};

fn loopback_listener() -> Listeners {
    Listeners {
        tcp: vec![std::net::TcpListener::bind("127.0.0.1:0").unwrap()],
    }
}

/// The real auditd, its log in a scratch directory, mapping `mapped_uid` to
/// the source named `source` (docs/50 §3.2, §7.1).
pub(super) fn real_auditd(
    mapped_uid: u32,
    source: &str,
) -> (auditd_support::TempDir, auditd_support::Server) {
    let logs = auditd_support::TempDir::new();
    let settings = auditd_support::settings_for(&logs, mapped_uid, source, 5);
    let server = auditd_support::Server::start(
        &settings,
        ListenerConfig::from_settings(&settings),
        64,
        true,
    );
    (logs, server)
}

/// Run the product `serve` with the product parameters — the test's auditd
/// at `audit`, no dird at `dird` — to its end.
fn product_start(
    audit: &auditd_support::Server,
    dird: std::path::PathBuf,
    uid: u32,
) -> Result<(), DaemonError> {
    let front = params(dird, audit.socket.clone(), uid);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let control = DaemonControl::new();
    let result = runtime.block_on(serve(front, loopback_listener(), control.clone()));
    assert!(!control.is_serving(), "nothing was served");
    result
}

/// docs/53 §9; docs/questions/Q-955 item 1, Q-960: the source the front
/// expects is its own, `kpasswd-front`, code 8.
#[test]
fn the_front_expects_its_own_audit_source() {
    assert_eq!(FRONT_AUDIT_SOURCE, EventSource::KpasswdFront);
    assert_eq!(FRONT_AUDIT_SOURCE.code(), 8);
}

/// docs/50 R50-16, §3.2, §7.5; docs/53 §9; task DN12: the product start —
/// `serve` with the product parameters — against a real auditd whose
/// `uid_sources` maps the front's uid to `kpasswd-front` passes the audit
/// check and goes on to the next real dependency, dird, which is absent
/// here: the start ends there (docs/53 §5.6 step 1), not at the audit check.
#[test]
fn the_product_start_passes_an_auditd_that_maps_the_front() {
    let Some((dird, _, uid)) = start_paths() else {
        return;
    };
    let (_logs, server) = real_auditd(uid, "kpasswd-front");
    assert_eq!(
        product_start(&server, dird, uid),
        Err(DaemonError::Dird(Unserved::Transport(
            TransportError::Connect
        )))
    );
    assert_eq!(server.stop(), Some(Ok(())));
}

/// docs/50 R50-16, §3.2, §7.5; docs/52 §3.12 (C12); docs/questions/Q-955
/// item 1: a real auditd that maps the front's uid to another source names
/// that source — the front does not serve and dird is never asked; one that
/// does not map the uid at all closes the connection without a reply — the
/// front does not serve either.
#[test]
fn the_product_start_fails_closed_without_the_front_mapping() {
    let Some((dird, _, uid)) = start_paths() else {
        return;
    };
    for other in ["kdc", "ldap-front", "dnsd"] {
        let (_logs, server) = real_auditd(uid, other);
        assert_eq!(
            product_start(&server, dird.clone(), uid),
            Err(DaemonError::Audit(AuditLinkError::SourceMismatch)),
            "{other}"
        );
    }
    let (_logs, server) = real_auditd(auditd_support::other_uid(&[uid]), "kpasswd-front");
    let result = product_start(&server, dird, uid);
    assert!(
        matches!(
            result,
            Err(DaemonError::Audit(
                AuditLinkError::Closed | AuditLinkError::Io
            ))
        ),
        "{result:?}"
    );
}

/// docs/53 §3.3; docs/52 R14: a listener outside every internal network
/// stops the start; so does no listener at all.
#[test]
fn listeners_must_be_internal_and_present() {
    let Some((dird, audit, uid)) = start_paths() else {
        return;
    };
    let mut outside = params(dird.clone(), audit.clone(), uid);
    outside.internal_networks =
        vec![Network::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).unwrap()];
    assert_eq!(
        start_error(outside, loopback_listener(), false, None),
        Some(DaemonError::ListenerNotInternal)
    );
    assert_eq!(
        start_error(params(dird, audit, uid), Listeners::default(), false, None),
        Some(DaemonError::NoListener)
    );
}

/// RFC 4120 §5.2.1, §5.2.2 (KerberosString); docs/53 §5.7: a realm the
/// KRB-ERROR cannot carry stops the start.
#[test]
fn the_realm_must_be_a_kerberos_realm() {
    let Some((dird, audit, uid)) = start_paths() else {
        return;
    };
    for realm in ["", "EXAMPLE\u{7f}TEST", "\u{e9}XAMPLE"] {
        let mut bad = params(dird.clone(), audit.clone(), uid);
        bad.realm = realm.to_owned();
        assert!(matches!(
            start_error(bad, loopback_listener(), false, None),
            Some(DaemonError::Realm(_))
        ));
    }
}

/// docs/50 R50-3, R50-16 (auditd verified first, by uid and source):
/// auditd absent, auditd under another uid, or an auditd that records the
/// front under another source — every other source of the closed table —
/// stops the start.
#[test]
fn auditd_must_be_verified() {
    let Some((dird, audit, uid)) = start_paths() else {
        return;
    };
    assert_eq!(
        start_error(
            params(dird.clone(), audit.clone(), uid),
            loopback_listener(),
            false,
            None
        ),
        Some(DaemonError::Audit(AuditLinkError::Connect))
    );
    let Some((dird, audit, uid)) = start_paths() else {
        return;
    };
    let mut wrong_uid = params(dird, audit, uid);
    wrong_uid.audit.uid = uid + 1;
    assert_eq!(
        start_error(
            wrong_uid,
            loopback_listener(),
            false,
            Some(FRONT_AUDIT_SOURCE)
        ),
        Some(DaemonError::Audit(AuditLinkError::PeerMismatch))
    );
    for other in EventSource::ALL
        .into_iter()
        .filter(|s| *s != FRONT_AUDIT_SOURCE)
    {
        let Some((dird, audit, uid)) = start_paths() else {
            return;
        };
        assert_eq!(
            start_error(
                params(dird, audit, uid),
                loopback_listener(),
                false,
                Some(other)
            ),
            Some(DaemonError::Audit(AuditLinkError::SourceMismatch)),
            "{other:?}"
        );
    }
}

/// docs/53 §5.6 step 1; docs/50 R50-3, §7.5 (dird verified before the
/// listeners serve): dird absent, or dird under another uid, stops the
/// start; dird's uid 0 is refused outright.
#[test]
fn dird_must_be_verified() {
    let Some((dird, audit, uid)) = start_paths() else {
        return;
    };
    assert_eq!(
        start_error(
            params(dird, audit, uid),
            loopback_listener(),
            false,
            Some(FRONT_AUDIT_SOURCE)
        ),
        Some(DaemonError::Dird(Unserved::Transport(
            TransportError::Connect
        )))
    );
    let Some((dird, audit, uid)) = start_paths() else {
        return;
    };
    let mut wrong_uid = params(dird, audit, uid);
    wrong_uid.dird.uid = uid + 1;
    assert_eq!(
        start_error(
            wrong_uid,
            loopback_listener(),
            true,
            Some(FRONT_AUDIT_SOURCE)
        ),
        Some(DaemonError::Dird(Unserved::PeerMismatch))
    );
    let Some((dird, audit, uid)) = start_paths() else {
        return;
    };
    let mut root = params(dird, audit, uid);
    root.dird.uid = 0;
    assert!(matches!(
        start_error(root, loopback_listener(), false, Some(FRONT_AUDIT_SOURCE)),
        Some(DaemonError::DirdConfig(_))
    ));
}

/// docs/53 R53-3 (TCP only — A-117: no UDP code path); docs/50 §6.2: the
/// binding makes one TCP listener per address and nothing else. The file
/// names port 464 only (crates/config `NonStandardPort`, task DN10c —
/// docs/questions/Q-1024), so the binding is exercised here, in-crate, on a
/// loopback port the system picks, through the crate-private
/// `bind_addresses` (moved from tests/settings.rs).
#[test]
fn only_tcp_listeners_are_bound() {
    // A port the system picks, then freed.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let address = core::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listeners = crate::startup::bind_addresses(&[address]).unwrap();
    assert_eq!(listeners.tcp.len(), 1);
    assert_eq!(listeners.tcp[0].local_addr().unwrap(), address);
    // The UDP port of the same number is still free: no UDP socket exists.
    assert!(std::net::UdpSocket::bind(address).is_ok());
}
