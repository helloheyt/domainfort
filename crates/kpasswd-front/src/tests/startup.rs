//! The start-up checks of `serve`, each failing closed before anything is
//! served — and the product start, which fails closed today at the audit
//! check (no audit source exists for the front).
//!
//! Sources: docs/50 R50-16 ("a daemon does not bind a network port until
//! its dependencies are verified (configuration, keyd, dird, audit)"), §7.5
//! (fail closed); docs/53 §3.3 (every listen address inside
//! `internal_networks`), §5.6 step 1 (dird's uid and zone), §5.7 (the realm
//! of the KRB-ERROR); docs/52 R14, §3.18 (C18: the product parameters
//! only); docs/questions/Q-955 item 1.

#![cfg(unix)]

use super::world::*;
use crate::audit::{AuditCheckError, FRONT_AUDIT_SOURCE};
use crate::{serve, DaemonControl, DaemonError, Listeners};
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

/// docs/50 R50-16, §7.5; docs/53 §9; docs/questions/Q-955 item 1: no audit
/// source exists for the front, so the product start — `serve` with the
/// product parameters — refuses at the audit check, before dird is asked
/// and before anything is served.
#[test]
fn the_product_start_fails_closed_at_the_audit_check() {
    assert_eq!(FRONT_AUDIT_SOURCE, None);
    let Some((dird, audit, uid)) = start_paths() else {
        return;
    };
    let params = params(dird, audit, uid).front;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let control = DaemonControl::new();
    let result = runtime.block_on(serve(params, loopback_listener(), control.clone()));
    assert_eq!(
        result,
        Err(DaemonError::Audit(AuditCheckError::SourceUndefined))
    );
    assert!(!control.is_serving());
}

/// docs/53 §3.3; docs/52 R14: a listener outside every internal network
/// stops the start; so does no listener at all.
#[test]
fn listeners_must_be_internal_and_present() {
    let Some((dird, audit, uid)) = start_paths() else {
        return;
    };
    let mut outside = params(dird.clone(), audit.clone(), uid);
    outside.front.internal_networks =
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
        bad.front.realm = realm.to_owned();
        assert!(matches!(
            start_error(bad, loopback_listener(), false, None),
            Some(DaemonError::Realm(_))
        ));
    }
}

/// docs/50 R50-3, R50-16 (auditd verified first, by uid and source):
/// auditd absent, auditd under another uid, or an auditd that records the
/// front under another source stops the start.
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
        Some(DaemonError::Audit(AuditCheckError::Link(
            AuditLinkError::Connect
        )))
    );
    let Some((dird, audit, uid)) = start_paths() else {
        return;
    };
    let mut wrong_uid = params(dird, audit, uid);
    wrong_uid.front.audit.uid = uid + 1;
    assert_eq!(
        start_error(
            wrong_uid,
            loopback_listener(),
            false,
            Some(EventSource::LdapFront)
        ),
        Some(DaemonError::Audit(AuditCheckError::Link(
            AuditLinkError::PeerMismatch
        )))
    );
    let Some((dird, audit, uid)) = start_paths() else {
        return;
    };
    assert_eq!(
        start_error(
            params(dird, audit, uid),
            loopback_listener(),
            false,
            Some(EventSource::Kdc)
        ),
        Some(DaemonError::Audit(AuditCheckError::Link(
            AuditLinkError::SourceMismatch
        )))
    );
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
            Some(EventSource::LdapFront)
        ),
        Some(DaemonError::Dird(Unserved::Transport(
            TransportError::Connect
        )))
    );
    let Some((dird, audit, uid)) = start_paths() else {
        return;
    };
    let mut wrong_uid = params(dird, audit, uid);
    wrong_uid.front.dird.uid = uid + 1;
    assert_eq!(
        start_error(
            wrong_uid,
            loopback_listener(),
            true,
            Some(EventSource::LdapFront)
        ),
        Some(DaemonError::Dird(Unserved::PeerMismatch))
    );
    let Some((dird, audit, uid)) = start_paths() else {
        return;
    };
    let mut root = params(dird, audit, uid);
    root.front.dird.uid = 0;
    assert!(matches!(
        start_error(
            root,
            loopback_listener(),
            false,
            Some(EventSource::LdapFront)
        ),
        Some(DaemonError::DirdConfig(_))
    ));
}
