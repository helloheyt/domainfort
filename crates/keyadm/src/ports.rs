//! keyadm's one peer behind a small trait — keyd (its key operations,
//! Role::Admin) — so the command logic is written once over the project's
//! real client and can be exercised against scripted peers.
//!
//! * [`KeydPort`] is `ipc_keyd::KeydClient::call_with_fate` (A-90: the
//!   request's fate — not sent / not performed / outcome unknown).
//!
//! keyadm talks to **keyd only** (docs/51 §6; A-102, docs/52 §4.6): the
//! admind port of task A10 (`FetchApproved`, `Complete`,
//! `ListPendingDestruction` on `admin.sock`) is gone with the channel —
//! keyadm runs the decisions dird registered in keyd, by decision id.
//!
//! Spec: docs/51 §6; docs/50 R50-3, §3.6, §3.7; docs/52 §4.6; A-90.

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
