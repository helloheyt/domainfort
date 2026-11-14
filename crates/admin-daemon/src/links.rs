//! admind's two clients: dird's admin channel and keyd's channel.
//!
//! Both are this project's synchronous clients, used through their public
//! API only, behind two small traits so that the worker owns them as boxed
//! values and the tier-2 tests can supply connectors that read the server's
//! uid on hosts where rustix's peer credentials are not available (as every
//! daemon's tests do):
//!
//! * **dird** — `ipc_dird_admin::AdminClient`: dird's uid checked on every
//!   new connection before anything is sent (A-63, docs/51 §7.1), one
//!   request in flight, the held connection checked before reuse and never
//!   a resend (A-87), replies decoded strictly and checked to answer the
//!   request; deadline `ipc_dird_admin::DEFAULT_DEADLINE` (24 s, A-100; Q-389
//!   item 5).
//! * **keyd** — `ipc_keyd::KeydClient` under Role::Directory (keyd's
//!   `uid_roles` maps admind's uid to Directory, A-57, A-73): keyd's uid
//!   checked on every new connection before anything is sent (A-63);
//!   `set_secret` always through `call_with_fate` (A-90), so a request that
//!   reached keyd without a usable answer is reported as "outcome unknown",
//!   never as "not done". Role::Directory may not call `DescribeConfig`
//!   (docs/10 §2, A-90), so admind does not require a description: a keyd
//!   that maps admind's uid to another role refuses `set_secret` at its
//!   authorization step (role, docs/10 §2 I2) with `Denied` before any
//!   intent — nothing changes, the `SetPassword` fails at its `SetSecret`
//!   step, and keyd's own record says `RoleNotPermitted`
//!   (docs/questions/Q-403).
//!
//! Spec: docs/51 §5.1, §7.1, §7.6; docs/50 R50-3, §3.6, §3.7; docs/10 §2,
//! §6; A-57; A-63; A-73; A-87; A-90.

use core::time::Duration;
use ipc_dird_admin::{AdminClient, Reply, Request, Unserved};
use ipc_keyd::{Answer, Call, CallFailure, KeydClient};
use std::path::Path;

/// One call on dird's admin channel.
/// Spec: docs/51 §7.1, §7.3.
pub trait DirdLink: Send {
    /// Send `request` to dird and return its reply (dird's own answers,
    /// refusals included, are `Ok`).
    ///
    /// # Errors
    /// [`Unserved`] (crate ipc-dird-admin `AdminClient::call`).
    fn call(&mut self, request: &Request) -> Result<Reply, Unserved>;
}

impl<C> DirdLink for AdminClient<C>
where
    C: ipc_dird_admin::Connector + Send,
    C::Connection: Send,
{
    fn call(&mut self, request: &Request) -> Result<Reply, Unserved> {
        AdminClient::call(self, request)
    }
}

/// One call on keyd's channel, with the fate of a request keyd did not
/// answer.
/// Spec: docs/50 §3.7 (A-88, A-90); docs/questions/Q-367, Q-370.
pub trait KeydLink: Send {
    /// Send `call` to keyd.
    ///
    /// # Errors
    /// [`CallFailure`] (crate ipc-keyd `KeydClient::call_with_fate`).
    fn call_with_fate(&mut self, call: &Call) -> Result<Answer, CallFailure>;
}

impl<C> KeydLink for KeydClient<C>
where
    C: ipc_keyd::Connector + Send,
    C::Connection: Send,
{
    fn call_with_fate(&mut self, call: &Call) -> Result<Answer, CallFailure> {
        KeydClient::call_with_fate(self, call)
    }
}

/// Why a client could not be built (a server uid of 0 — the configuration
/// refuses it already).
/// Spec: docs/50 §3.2 ("uid 0 is never mapped").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootServerUid;

/// admind's client of dird over its Unix socket (rustix peer credentials on
/// Linux; elsewhere the peer check fails closed — crate ipc-dird-admin).
///
/// # Errors
/// [`RootServerUid`].
///
/// Spec: docs/51 §7.1, §7.5; docs/50 R50-3.
pub fn unix_dird(socket: &Path, dird_uid: u32) -> Result<Box<dyn DirdLink>, RootServerUid> {
    AdminClient::new(
        ipc_dird_admin::UnixConnector::new(socket.to_path_buf()),
        dird_uid,
        ipc_dird_admin::DEFAULT_DEADLINE,
    )
    .map(|client| Box::new(client) as Box<dyn DirdLink>)
    .map_err(|_| RootServerUid)
}

/// admind's client of keyd over its Unix socket, with `deadline`
/// (`keyd_deadline`, ≤ 2 s — docs/50 §3.6).
///
/// # Errors
/// [`RootServerUid`].
///
/// Spec: docs/50 R50-3, §3.6; A-63.
pub fn unix_keyd(
    socket: &Path,
    keyd_uid: u32,
    deadline: Duration,
) -> Result<Box<dyn KeydLink>, RootServerUid> {
    KeydClient::new(
        ipc_keyd::UnixConnector::new(socket.to_path_buf()),
        keyd_uid,
        deadline,
    )
    .map(|client| Box::new(client) as Box<dyn KeydLink>)
    .map_err(|_| RootServerUid)
}
