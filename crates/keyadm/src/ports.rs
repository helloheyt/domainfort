//! keyadm's two peers behind two small traits — keyd (its key operations,
//! Role::Admin) and admind (`admin.sock`: `FetchApproved`, `Complete`,
//! `ListPendingDestruction`) — so the command logic is written once over
//! the project's real clients and can be exercised against scripted peers.
//!
//! * [`KeydPort`] is `ipc_keyd::KeydClient::call_with_fate` (A-90: the
//!   request's fate — not sent / not performed / outcome unknown).
//! * [`AdmindPort`] is `ipc_admin::AdmindClient::call` (admind's uid checked
//!   on every new connection before anything is sent, A-63; never a resend,
//!   A-87).
//!
//! Spec: docs/51 §6; docs/50 R50-3, §3.6, §3.7; A-63; A-87; A-90.

use ipc_admin::{AdmindClient, AdmindFailure, Reply, Request};
use ipc_keyd::{Answer, Call, CallFailure, KeydClient};

/// One call to keyd, with the fate of a request keyd did not answer.
/// Spec: docs/50 §3.7; A-90.
pub trait KeydPort {
    /// Send `call` to keyd.
    ///
    /// # Errors
    /// [`CallFailure`] (crate ipc-keyd `KeydClient::call_with_fate`).
    fn call_with_fate(&mut self, call: &Call) -> Result<Answer, CallFailure>;
}

impl<C: ipc_keyd::Connector> KeydPort for KeydClient<C> {
    fn call_with_fate(&mut self, call: &Call) -> Result<Answer, CallFailure> {
        KeydClient::call_with_fate(self, call)
    }
}

/// One call to admind on `admin.sock`.
/// Spec: docs/51 §6, §7.6.
pub trait AdmindPort {
    /// Send `request` to admind and return its reply (admind's and dird's
    /// own answers, refusals included, are `Ok`).
    ///
    /// # Errors
    /// [`AdmindFailure`] (crate ipc-admin `AdmindClient::call`).
    fn call(&mut self, request: &Request) -> Result<Reply, AdmindFailure>;
}

impl<C: ipc_dird_admin::Connector> AdmindPort for AdmindClient<C> {
    fn call(&mut self, request: &Request) -> Result<Reply, AdmindFailure> {
        AdmindClient::call(self, request)
    }
}
