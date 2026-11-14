//! The LDAP engine thread: one dedicated OS thread runs `ldap::Engine` over
//! dird's store, fed through its own bounded queue (task P10).
//!
//! # Design (docs/50 R50-7, R50-10, §3.6, §4.2; docs/49 §4.4, §11)
//!
//! * **A second thread and a second bounded queue**, beside the
//!   directory-view engine (crate::engine). A directory search may run for
//!   up to the engine's 60-second query bound (crates/ldap search/limits.rs
//!   `MAX_QUERY_SECONDS`); on the directory-view thread it would hold up the
//!   kdc's account lookups behind it (KDC_ERR_SVC_UNAVAILABLE for the
//!   whole wait). Both threads read the same `dirstore::Store` through
//!   their own snapshots (redb serves concurrent readers; dird is still the
//!   only process that opens the file — R50-2). docs/questions/Q-280 item 4.
//! * Each channel connection's state — its `ldap::Session` inside an
//!   [`LdapConnection`] — **travels with the request**: the connection task
//!   moves it into the job, the engine thread runs the dispatcher over it
//!   and hands it back with the reply. One request per connection is in
//!   flight (strict request → reply, R50-7), so no table of sessions is
//!   needed, and a session dies with its connection (docs/50 §4.2: "and
//!   destroys it at close").
//! * Queue full → `Refused::Busy` at once ([`LdapEngineHandle::submit`] uses
//!   `try_send`); never an unbounded queue (R50-7).
//! * Per request, the engine thread's host ([`LdapHost`]) reserves the audit
//!   slot (crate::ldap_audit, A-57), takes **one fresh snapshot** of the
//!   store as the PIP, the account source and the directory (docs/49 §4.4,
//!   R49-15: authorization derived again for every operation from a fresh
//!   view; docs/47 §8.1: one view serves as both), reads `now` from dird's
//!   clock, runs the engine, and commits the event — with the client address
//!   the front reported, as an unverified observation — before the reply
//!   leaves (Q-252 item 9). The bound-identity re-check uses this view's own
//!   `AccountSource` — in process, since dird owns the store.
//! * **No zone table** (docs/52 R14): the request's zone arrives fixed in
//!   its `TransportReport` — the zone of the front the connection came
//!   from, derived from the peer uid by the listener. Nothing here can turn
//!   the reported address into a zone.
//!
//! # Threads and hardening
//!
//! Spawned by [`LdapService::spawn`], which the daemon calls only inside its
//! tokio runtime — after `main` applied the process-wide hardening on the
//! then only thread (R50-14). The thread inherits the hardened identity.
//!
//! Spec: docs/50 R50-2, R50-7, R50-10, R50-14, §3.6, §4.2; docs/49 R49-14,
//! R49-15, §11; docs/47 §8.1; docs/11 §6; docs/questions Q-218 (A-57),
//! Q-252 (A-64).

use crate::clock::{SearchTime, SharedClock};
use crate::engine::{EngineError, EngineThread, OnExit, SubmitError};
use crate::ldap_audit::AuditGate;
use crate::rate::ObligationLimiter;
use core::fmt;
use directory_pip::{DirectoryContext, PepView, TierMap};
use dirstore::Store;
use ipc_ldap::ReportedPeer;
use ipc_ldap_server::{Dispatch, LdapConnection, RequestHost, Unserved};
use ldap::{DirectoryInputs, Engine, Outcome, RequestInputs, TransportReport};
use pdp::PolicySnapshot;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

/// Largest LDAP engine queue accepted by [`LdapService::spawn`]. Project
/// bound (AGENTS.md §6).
pub const MAX_LDAP_QUEUE_CAPACITY: usize = 1024;

/// What a connection gets back from the engine thread: its connection state
/// and the dispatch.
pub(crate) type Answered = (Box<LdapConnection>, Dispatch);

/// One job for the LDAP engine: a request body, the connection's state, and
/// where the answer goes.
/// Spec: docs/50 R50-7, R50-10.
pub(crate) struct LdapJob {
    connection: Box<LdapConnection>,
    body: Zeroizing<Vec<u8>>,
    reply: oneshot::Sender<Answered>,
}

/// The sending side of the LDAP engine queue; one clone per connection
/// task.
/// Spec: docs/50 R50-7.
#[derive(Debug, Clone)]
pub struct LdapEngineHandle {
    queue: SyncSender<LdapJob>,
}

impl LdapEngineHandle {
    /// Queue one request without waiting: a full queue is
    /// [`SubmitError::Busy`]. The connection state comes back with the
    /// answer.
    /// Spec: docs/50 R50-7 ("queue full ⇒ immediate `Busy`").
    pub(crate) fn submit(
        &self,
        connection: Box<LdapConnection>,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<oneshot::Receiver<Answered>, SubmitError> {
        let (reply, answer) = oneshot::channel();
        match self.queue.try_send(LdapJob {
            connection,
            body,
            reply,
        }) {
            Ok(()) => Ok(answer),
            Err(TrySendError::Full(_)) => Err(SubmitError::Busy),
            Err(TrySendError::Disconnected(_)) => Err(SubmitError::Stopped),
        }
    }
}

/// What the LDAP engine thread owns: the store, its own directory context
/// and tier map (of the loaded policy), the policy snapshot, the engine,
/// the audit gate and the clock — no zone table (docs/52 R14).
/// Spec: docs/50 R50-2, §4.2, §7.2; docs/49 §11.
pub struct LdapService {
    /// The store (shared with the directory-view engine; read-only here).
    pub store: Arc<Store>,
    /// The directory context (A-53).
    pub ctx: DirectoryContext,
    /// The tier map of the loaded policy (docs/47 §6.3).
    pub tiers: TierMap,
    /// The PDP's snapshot of the same policy file (docs/50 §7.2; A-68).
    pub policy: PolicySnapshot,
    /// The engine (docs/49 §11).
    pub engine: Engine,
    /// The A-57 gate (crate::ldap_audit).
    pub gate: Arc<AuditGate>,
    /// dird's clock.
    pub clock: SharedClock,
}

impl fmt::Debug for LdapService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapService")
            .field("policy_version", &self.policy.version())
            .finish_non_exhaustive()
    }
}

/// One request's host on the engine thread (module documentation).
/// Spec: docs/49 §4.4, §11; docs/50 §4.2, §8.1.
struct LdapHost<'a> {
    store: &'a Store,
    ctx: &'a DirectoryContext,
    tiers: &'a TierMap,
    policy: &'a PolicySnapshot,
    gate: &'a AuditGate,
    clock: &'a SharedClock,
    rate: &'a mut ObligationLimiter,
}

impl RequestHost for LdapHost<'_> {
    /// Spec: docs/49 §4.4 (R49-15), §10.1 (R49-14), §11; docs/50 §8.1;
    /// docs/questions Q-218 (A-57), Q-252 item 9 (A-64); docs/52 R14 (the
    /// reported address goes to the record, never into the inputs).
    fn serve(
        &mut self,
        transport: TransportReport,
        reported_peer: ReportedPeer,
        run: &mut dyn FnMut(RequestInputs<'_>) -> Outcome,
    ) -> Result<Outcome, Unserved> {
        // The audit slot first: no slot, no operation (A-57).
        let Some(reservation) = self.gate.admit() else {
            return Err(Unserved::Unavailable);
        };
        // One fresh snapshot for this operation (R49-15).
        let Ok(view) = self.ctx.view(self.store, self.tiers) else {
            self.gate.release(reservation);
            return Err(Unserved::Unavailable);
        };
        let Some(now) = self.clock.now() else {
            self.gate.release(reservation);
            return Err(Unserved::Unavailable);
        };
        let search_clock = SearchTime {
            clock: self.clock,
            start: now,
        };
        let outcome = run(RequestInputs {
            snapshot: self.policy,
            pip: &view,
            accounts: &view,
            rate: &mut *self.rate,
            now,
            transport,
            // The PEP receives the gate-only view, never the snapshot
            // (docs/52 R-a; A-103 on docs/questions/Q-486).
            directory: Some(DirectoryInputs {
                view: PepView::new(&view),
                clock: &search_clock,
            }),
        });
        // Commit, then reply (Q-252 item 9).
        self.gate
            .record(reservation, &outcome.audit, reported_peer)
            .map_err(|_| Unserved::Unavailable)?;
        Ok(outcome)
    }
}

impl LdapService {
    /// Move the service onto its own OS thread behind a queue of `capacity`
    /// jobs. `on_exit` runs when the thread ends — normally (every handle
    /// dropped) or by unwinding — so the daemon stops instead of serving
    /// without an engine.
    ///
    /// # Errors
    /// [`EngineError::QueueCapacity`], [`EngineError::Spawn`].
    ///
    /// Spec: docs/50 R50-7, R50-14, §3.6.
    pub(crate) fn spawn<X>(
        self,
        capacity: usize,
        on_exit: X,
    ) -> Result<(LdapEngineHandle, EngineThread), EngineError>
    where
        X: FnOnce() + Send + 'static,
    {
        if capacity == 0 || capacity > MAX_LDAP_QUEUE_CAPACITY {
            return Err(EngineError::QueueCapacity);
        }
        let (queue, jobs) = sync_channel::<LdapJob>(capacity);
        let service = self;
        let thread = std::thread::Builder::new()
            .name(String::from("dird-ldap"))
            .spawn(move || {
                let _exit = OnExit(Some(on_exit));
                let mut rate = ObligationLimiter::new();
                while let Ok(job) = jobs.recv() {
                    let LdapJob {
                        mut connection,
                        body,
                        reply,
                    } = job;
                    let mut host = LdapHost {
                        store: &service.store,
                        ctx: &service.ctx,
                        tiers: &service.tiers,
                        policy: &service.policy,
                        gate: &service.gate,
                        clock: &service.clock,
                        rate: &mut rate,
                    };
                    let dispatch = connection.handle(&service.engine, &body, &mut host);
                    drop(body);
                    // The connection may be gone; its answer is dropped.
                    let _ = reply.send((connection, dispatch));
                }
            })
            .map_err(|_| EngineError::Spawn)?;
        Ok((LdapEngineHandle { queue }, EngineThread { thread }))
    }
}
