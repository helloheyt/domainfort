//! The test seams of dird (docs/52 §3.18, class C18; task R15).
//!
//! **Not part of the product API.** This module exists only in a build with
//! the feature `test-seams`, which only `[dev-dependencies]` enable (cargo's
//! resolver 2 activates a dev-dependency's features only in builds of test
//! targets), and no product source names it (the source scan in crates/e2e-tests
//! `tests/no_test_seams_in_product.rs`). A product dird is built only from its
//! configuration and manifest — [`crate::startup::params`],
//! [`crate::startup::admin_params`] — and run by [`crate::serve`] /
//! [`crate::serve_with_admin`], which supply every value below themselves.
//!
//! | seam | what it varies | production value |
//! |---|---|---|
//! | [`DaemonParams::max_views`], `max_connections`, `queue_capacity`, `max_ldap_sessions`, `ldap_queue_capacity` | the view, connection and session bounds and the queues | `MAX_OPEN_VIEWS`, `MAX_KDC_CONNECTIONS`, `ENGINE_QUEUE_CAPACITY`, `MAX_LDAP_SESSIONS`, `LDAP_QUEUE_CAPACITY` |
//! | [`DaemonParams::audit_window`] | the LDAP events' window (A-57) | `WindowConfig::DEFAULT` |
//! | [`DaemonParams::clock`] | the LDAP and admin engines' clock | the system clock |
//! | [`AdminParams::keyd`] | the admin service's keyd client — any [`crate::TicketVerifier`] | `KeydTicketVerifier` over `ipc_keyd::UnixConnector` (Role::Ldap, task R9) |
//! | [`AdminParams::max_connections`], [`AdminParams::queue_capacity`] | the admin channel's bounds | `MAX_ADMIN_CONNECTIONS`, `ADMIN_QUEUE_CAPACITY` |
//! | [`AdminParams::ack_deadline`] | the decision-acknowledgement wait, bounded by its type at `MAX_DECISION_ACK_DEADLINE` (A-95) | `DecisionAckDeadline::PRODUCTION` |
//! | [`AdminParams::request_lifetime`], [`AdminParams::requests_per_requester`] | a pending request's lifetime; the open requests one requester may hold (task D2-c) | `directory_admin::REQUEST_LIFETIME`, `directory_admin::REQUESTS_PER_REQUESTER` |
//! | [`AdminParams::destroy_reconcile_interval`] | the re-registration interval, kept within `MIN_/MAX_DESTROY_RECONCILE_INTERVAL` (A-105) | `DESTROY_RECONCILE_INTERVAL` |
//! | [`opened`] | an already-opened store, skipping the file checks | the redb file (`StoreSource::File`) |
//! | [`KpasswdParams::keyd`] | the kpasswd service's keyd client — any [`crate::KpasswdKeyd`] (task K7) | `KeydKpasswdClient` over `ipc_keyd::UnixConnector` (Role::Ldap) |
//! | [`KpasswdParams::max_connections`], [`KpasswdParams::queue_capacity`] | the kpasswd channel's bounds | `MAX_KPASSWD_CONNECTIONS`, `KPASSWD_QUEUE_CAPACITY` |
//! | [`DnsParams::max_connections`], [`DnsParams::queue_capacity`] | the DNS channel's bounds (task DN10a) | `MAX_DNS_CONNECTIONS`, `DNS_QUEUE_CAPACITY` |
//!
//! Spec: docs/52 §3.18, §7 R15; docs/questions/Q-415, Q-432 (A-95), Q-501
//! (A-105), Q-570.
//!
//! Written only from this project's documents (docs/52 §3.18, §7 R15; the
//! questions cited; the dev-only feature precedent of docs/questions/Q-500
//! item 6, A-107) and this repository's own code. No other implementation
//! was consulted or recalled (AGENTS.md §1-3).

use crate::admin_service::{AdminServeParams, DecisionAckDeadline};
use crate::daemon::{DaemonControl, DaemonError, OpenedStore, Stopped, StoreSource};
use crate::dns_service::DnsServeParams;
use crate::kpasswd_service::KpasswdServeParams;
use crate::policy::DevelopmentPolicy;
use crate::policy_next::PolicyNextFile;
use core::time::Duration;
use dirstore::{NodeId, Store};
use provision_manifest::Manifest;
use std::path::PathBuf;
use std::sync::Arc;

pub use crate::admin_service::VerifierFactory;
pub use crate::daemon::ServeParams as DaemonParams;
pub use crate::kpasswd_service::KpasswdKeydFactory;

/// Everything the admin service runs with — the product
/// [`crate::AdminParams`] plus its seams (module documentation). The same
/// fields, in the same order, as the admin service's own parameters.
/// Spec: docs/51 §4.6, §5.5, §5.6, §7.1, §7.5; A-73; P-22.
#[derive(Clone)]
pub struct AdminParams {
    /// `dird_admin_socket`.
    pub socket: PathBuf,
    /// `admind_uid`: the only peer admitted (docs/51 §7.1).
    pub admind_uid: u32,
    /// The admin thread's keyd client (any [`crate::TicketVerifier`]); `None` ⇒
    /// the admin service does not start.
    pub keyd: Option<VerifierFactory>,
    /// `admin_ticket_age_max` (R51-10).
    pub ticket_age_max: Duration,
    /// `admin_quorum` (P-22).
    pub quorum: usize,
    /// `node_id` (docs/51 §4.6).
    pub node_id: NodeId,
    /// The provisioning manifest (docs/51 §4.3 step 8).
    pub manifest: Manifest,
    /// Connections admind may hold.
    pub max_connections: usize,
    /// The admin queue.
    pub queue_capacity: usize,
    /// The decision-acknowledgement wait (bounded by its type).
    pub ack_deadline: DecisionAckDeadline,
    /// The lifetime of a pending request (task D2-c).
    pub request_lifetime: Duration,
    /// The open pending requests one requester may hold (task D2-c).
    pub requests_per_requester: usize,
    /// How often the admin thread re-registers lost destroy decisions
    /// (kept within the crate's bounds by the admin thread).
    pub destroy_reconcile_interval: Duration,
    /// `policy_next_path` and its owner (task A16) — a configured value,
    /// passed through as the product [`crate::AdminParams`] carries it.
    pub policy_next: Option<PolicyNextFile>,
}

impl From<AdminParams> for AdminServeParams {
    fn from(admin: AdminParams) -> AdminServeParams {
        AdminServeParams {
            socket: admin.socket,
            admind_uid: admin.admind_uid,
            keyd: admin.keyd,
            ticket_age_max: admin.ticket_age_max,
            quorum: admin.quorum,
            node_id: admin.node_id,
            manifest: admin.manifest,
            max_connections: admin.max_connections,
            queue_capacity: admin.queue_capacity,
            ack_deadline: admin.ack_deadline,
            request_lifetime: admin.request_lifetime,
            requests_per_requester: admin.requests_per_requester,
            destroy_reconcile_interval: admin.destroy_reconcile_interval,
            policy_next: admin.policy_next,
        }
    }
}

impl AdminParams {
    /// The product admin parameters with every production value (the
    /// production keyd client for `realm` included) — a starting point for
    /// a test that changes one seam.
    #[must_use]
    pub fn production(admin: crate::AdminParams, realm: &krb_proto::Realm) -> AdminParams {
        let full = AdminServeParams::production(admin, realm);
        AdminParams {
            socket: full.socket,
            admind_uid: full.admind_uid,
            keyd: full.keyd,
            ticket_age_max: full.ticket_age_max,
            quorum: full.quorum,
            node_id: full.node_id,
            manifest: full.manifest,
            max_connections: full.max_connections,
            queue_capacity: full.queue_capacity,
            ack_deadline: full.ack_deadline,
            request_lifetime: full.request_lifetime,
            requests_per_requester: full.requests_per_requester,
            destroy_reconcile_interval: full.destroy_reconcile_interval,
            policy_next: full.policy_next,
        }
    }
}

/// Everything the kpasswd service runs with — the product
/// [`crate::KpasswdParams`] plus its seams (module documentation; task K7).
/// Spec: docs/53 §5.6; docs/52 C18.
#[derive(Clone)]
pub struct KpasswdParams {
    /// `dird_kpasswd_socket`.
    pub socket: PathBuf,
    /// `kpasswd_front_uid`: the only peer admitted.
    pub front_uid: u32,
    /// The kpasswd thread's keyd client (any [`crate::KpasswdKeyd`]);
    /// `None` ⇒ the kpasswd service does not start.
    pub keyd: Option<KpasswdKeydFactory>,
    /// Connections the front may hold.
    pub max_connections: usize,
    /// The kpasswd queue.
    pub queue_capacity: usize,
}

impl From<KpasswdParams> for KpasswdServeParams {
    fn from(kpasswd: KpasswdParams) -> KpasswdServeParams {
        KpasswdServeParams {
            socket: kpasswd.socket,
            front_uid: kpasswd.front_uid,
            keyd: kpasswd.keyd,
            max_connections: kpasswd.max_connections,
            queue_capacity: kpasswd.queue_capacity,
        }
    }
}

/// Everything the DNS service runs with — the product
/// [`crate::DnsParams`] plus its seams (module documentation; task DN10a).
/// Spec: docs/54 §4.6; docs/52 C18.
#[derive(Debug, Clone)]
pub struct DnsParams {
    /// `dird_dns_socket`.
    pub socket: PathBuf,
    /// `dnsd_uid`: the only peer admitted.
    pub dnsd_uid: u32,
    /// The zone values of the image.
    pub zone: directory_pip::ZoneParameters,
    /// Connections dnsd may hold.
    pub max_connections: usize,
    /// The DNS queue.
    pub queue_capacity: usize,
}

impl From<DnsParams> for DnsServeParams {
    fn from(dns: DnsParams) -> DnsServeParams {
        DnsServeParams {
            socket: dns.socket,
            dnsd_uid: dns.dnsd_uid,
            zone: dns.zone,
            max_connections: dns.max_connections,
            queue_capacity: dns.queue_capacity,
        }
    }
}

impl DnsParams {
    /// The product DNS parameters with every production value — a starting
    /// point for a test that changes one seam.
    #[must_use]
    pub fn production(dns: crate::DnsParams) -> DnsParams {
        let full = DnsServeParams::production(dns);
        DnsParams {
            socket: full.socket,
            dnsd_uid: full.dnsd_uid,
            zone: full.zone,
            max_connections: full.max_connections,
            queue_capacity: full.queue_capacity,
        }
    }
}

/// A store already opened in this process ([`StoreSource::Opened`]).
#[must_use]
pub fn opened(store: Arc<Store>) -> StoreSource {
    StoreSource::Opened(OpenedStore(store))
}

/// `crate::serve` with every value given (no admin service).
///
/// # Errors
/// [`DaemonError`].
pub async fn serve(
    params: DaemonParams,
    source: StoreSource,
    policy: DevelopmentPolicy,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    crate::daemon::serve_with(params, None, None, None, source, policy, control).await
}

/// `crate::serve_with_admin` with every value given.
///
/// # Errors
/// [`DaemonError`].
pub async fn serve_with_admin(
    params: DaemonParams,
    admin: Option<AdminParams>,
    source: StoreSource,
    policy: DevelopmentPolicy,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    crate::daemon::serve_with(
        params,
        admin.map(Into::into),
        None,
        None,
        source,
        policy,
        control,
    )
    .await
}

/// `crate::serve_with_services` with every value given (task K7).
///
/// # Errors
/// [`DaemonError`].
pub async fn serve_with_kpasswd(
    params: DaemonParams,
    admin: Option<AdminParams>,
    kpasswd: Option<KpasswdParams>,
    source: StoreSource,
    policy: DevelopmentPolicy,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    crate::daemon::serve_with(
        params,
        admin.map(Into::into),
        kpasswd.map(Into::into),
        None,
        source,
        policy,
        control,
    )
    .await
}

/// `crate::serve_with_services` with every value given, the DNS service
/// included (task DN10a).
///
/// # Errors
/// [`DaemonError`].
pub async fn serve_with_dns(
    params: DaemonParams,
    admin: Option<AdminParams>,
    kpasswd: Option<KpasswdParams>,
    dns: Option<DnsParams>,
    source: StoreSource,
    policy: DevelopmentPolicy,
    control: DaemonControl,
) -> Result<Stopped, DaemonError> {
    crate::daemon::serve_with(
        params,
        admin.map(Into::into),
        kpasswd.map(Into::into),
        dns.map(Into::into),
        source,
        policy,
        control,
    )
    .await
}
