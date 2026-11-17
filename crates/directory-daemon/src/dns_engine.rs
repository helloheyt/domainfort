//! The DNS thread (task DN10a): one dedicated OS thread runs the dnsd ↔
//! dird channel's dispatcher (crate ipc-dns-server `DnsConnection::handle`)
//! over [`crate::dns_service::DnsWorker`], fed through its own bounded queue
//! — so a slow projection never holds the LDAP engine, the admin thread or
//! the kpasswd thread, and they never hold it (docs/54 §4.6: "a DNS thread
//! in dird with a bounded queue"; docs/07 §1, "a separate pool").
//!
//! # Design (the kpasswd thread's, docs/50 R50-7)
//!
//! * Each channel connection's state — its `DnsConnection`, whose zone the
//!   listener fixed from dnsd's peer uid — **travels with the request** into
//!   the job; this thread runs the dispatcher over it (the one place a
//!   request is decoded and answered) and hands it back with the dispatch.
//! * Queue full ⇒ `Refused::Busy` at once (`try_send`); dnsd answers
//!   SERVFAIL (docs/54 §4.6, §6.6).
//! * The thread reads the store (one snapshot per fetch) and writes it only
//!   through the serial-only checked write (task DN10b; crate::dns_service,
//!   docs/questions/Q-1002): at its start, before the queue is served, and
//!   when the clock changed the content under the current SERIAL.
//! * **The start runs on this thread** ([`DnsWorker::start`]: the zone
//!   projects, the start's serial advance — whose decision auditd must
//!   acknowledge — the first projection): the wait for the acknowledgement
//!   blocks this thread, never the runtime the audit client runs on. Its
//!   result goes back through a `oneshot` the daemon awaits; a failed start
//!   ends the thread **before** the exit hook is armed, so dird's other
//!   services run on (the hook stops dird only when a serving DNS thread
//!   ends).
//!
//! Spec: docs/54 §4.6, §4.8; docs/50 R50-7, R50-14; docs/questions/Q-1002
//! item 4 (b).

use crate::dns_service::{DnsNotStarted, DnsWorker, MAX_DNS_QUEUE_CAPACITY};
use crate::engine::{EngineError, EngineThread, OnExit, SubmitError};
use ipc_dns_server::{Dispatch, DnsConnection};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

/// What a connection gets back from the DNS thread: its connection state
/// and the dispatch.
pub(crate) type Answered = (DnsConnection, Dispatch);

/// One job for the DNS thread: a request body, the connection's state, and
/// where the answer goes.
/// Spec: docs/50 R50-7; docs/54 §4.6.
pub(crate) struct DnsJob {
    connection: DnsConnection,
    body: Zeroizing<Vec<u8>>,
    reply: oneshot::Sender<Answered>,
}

/// The sending side of the DNS queue; one clone per connection task.
/// Spec: docs/50 R50-7; docs/54 §4.6.
#[derive(Debug, Clone)]
pub(crate) struct DnsEngineHandle {
    queue: SyncSender<DnsJob>,
}

impl DnsEngineHandle {
    /// Queue one request without waiting: a full queue is
    /// [`SubmitError::Busy`]. The connection state comes back with the
    /// answer.
    /// Spec: docs/54 §4.6 ("full ⇒ `Busy` ⇒ dnsd answers SERVFAIL"); docs/50
    /// R50-7.
    pub(crate) fn submit(
        &self,
        connection: DnsConnection,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<oneshot::Receiver<Answered>, SubmitError> {
        let (reply, answer) = oneshot::channel();
        match self.queue.try_send(DnsJob {
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

impl DnsWorker {
    /// Move the worker onto its own OS thread behind a queue of `capacity`
    /// jobs (0 < capacity ≤ [`MAX_DNS_QUEUE_CAPACITY`]). The thread first
    /// runs [`DnsWorker::start`] and sends its result on `started` (the
    /// zone's SERIAL, or why the service does not start — the thread then
    /// ends at once, without running `on_exit`). Once started, `on_exit`
    /// runs when the thread ends, so the daemon stops instead of serving
    /// without it.
    ///
    /// # Errors
    /// [`EngineError::QueueCapacity`], [`EngineError::Spawn`].
    ///
    /// Spec: docs/54 §4.6, §4.8; docs/50 R50-7, R50-14; module documentation.
    pub(crate) fn spawn<X>(
        self,
        capacity: usize,
        started: oneshot::Sender<Result<u32, DnsNotStarted>>,
        on_exit: X,
    ) -> Result<(DnsEngineHandle, EngineThread), EngineError>
    where
        X: FnOnce() + Send + 'static,
    {
        if capacity == 0 || capacity > MAX_DNS_QUEUE_CAPACITY {
            return Err(EngineError::QueueCapacity);
        }
        let (queue, jobs) = sync_channel::<DnsJob>(capacity);
        let mut worker = self;
        let thread = std::thread::Builder::new()
            .name(String::from("dird-dns"))
            .spawn(move || {
                let start = worker.start();
                let serving = start.is_ok();
                // The daemon may have stopped waiting; then nothing serves.
                if started.send(start).is_err() || !serving {
                    return;
                }
                let _exit = OnExit(Some(on_exit));
                while let Ok(job) = jobs.recv() {
                    let DnsJob {
                        mut connection,
                        body,
                        reply,
                    } = job;
                    let dispatch = connection.handle(&body, &mut worker);
                    drop(body);
                    // The connection may be gone; its answer is dropped.
                    let _ = reply.send((connection, dispatch));
                }
            })
            .map_err(|_| EngineError::Spawn)?;
        Ok((DnsEngineHandle { queue }, EngineThread { thread }))
    }
}
