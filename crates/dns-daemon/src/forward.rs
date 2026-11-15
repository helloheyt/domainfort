//! Forwarding signed UPDATE messages to dird, and relaying dird's answer.
//!
//! dnsd holds no key, so it decides nothing about an UPDATE: dns-zone marks
//! a request to forward only when dird may verify it (an UPDATE over TCP
//! carrying a `gss-tsig` TSIG — dns-zone rows 7–10; dird never sees an
//! unsigned UPDATE, docs/54 §4.5 step 1), and dnsd hands dird the client's
//! **exact octets** (the TSIG MAC covers the whole message, RFC 8945
//! §4.3.2; a server that shares no key with the originator "MUST forward the
//! message unchanged including the TSIG", RFC 8945 §5.5) together with the
//! two facts only dnsd owns — the transport and the source address
//! (`ForwardRequest`, A-140; docs/research/r3-c-dns.md §6 W21: dnsd owns the
//! socket). dird is the PEP (docs/54 §4.5).
//!
//! # The queue and the thread
//!
//! A TCP connection that holds a forward verdict puts one job on a bounded
//! queue ([`crate::limits::FORWARD_QUEUE_CAPACITY`]) without waiting; a full
//! queue ⇒ SERVFAIL (docs/54 §6.7: "bounded queue (32) ⇒ SERVFAIL — a flood
//! does not reach dird and keyd"). One thread takes the jobs in order and
//! owns its own `DnsClient` — its own connection to dird, verified on every
//! connection (`ExpectedDird`; C12) — and, per job:
//!
//! 1. a job whose connection gave up waiting is dropped unsent (nobody would
//!    receive the reply);
//! 2. `Forward` → `Forwarded { reply, serial }`, or a failure ⇒ SERVFAIL
//!    (docs/54 §6.6 last row; the client never resends a request — Q-312);
//! 3. if `serial` differs from the image served, the zone thread is asked to
//!    fetch the new image and the reply waits for it (bounded by one dird
//!    deadline) — "immediately after every UPDATE it forwarded that changed
//!    the SERIAL, **before** it returns the answer to the client" (docs/54
//!    §4.4 (a); RFC 2136 §3.6: "If the zone appears to change, the SOA must
//!    appear to change as well"). If that fetch fails, the reply is relayed
//!    anyway — dird committed the change before answering (RFC 2136 §3.5),
//!    withholding the answer would only make the client retry an applied
//!    update — and the periodic check fetches the image (docs/questions/
//!    Q-952 item 3);
//! 4. the outcome goes back to the connection: dird's reply octets, or
//!    `None` — close without a reply (docs/54 §4.6: "`None` ⇒ dnsd closes
//!    without a reply").
//!
//! RFC 2136 §6.4: "The forwarder will not respond to its requestor until it
//! receives a response from its forward server" — the connection waits for
//! the outcome (bounded, crate::limits::FORWARD_ANSWER_TIMEOUT).
//!
//! Spec: docs/54 §4.4, §4.5, §4.6, §6.6, §6.7; A-140; RFC 2136 §3.5, §3.6,
//! §6.2, §6.4, §7.9; RFC 8945 §4.3.2, §5.5; docs/questions/Q-921 item 6.

use crate::log::{FORWARD_REFRESH_FAILED, FORWARD_UNAVAILABLE};
use crate::zone::{RefreshNow, ZoneView};
use core::time::Duration;
use ipc_dns::{Connector, DnsClient, DnsMessage, ForwardRequest, Unserved};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::thread::JoinHandle;
use tokio::sync::{mpsc, oneshot};

/// One forwarded message and where its outcome goes.
#[derive(Debug)]
pub(crate) struct ForwardJob {
    pub(crate) request: ForwardRequest,
    pub(crate) answer: oneshot::Sender<ForwardOutcome>,
}

/// What became of one forwarded message.
/// Spec: docs/54 §4.6, §6.6.
#[derive(Debug)]
pub(crate) enum ForwardOutcome {
    /// dird answered: send these octets, or (`None`) send nothing — over TCP
    /// close the connection without a reply.
    Relay(Option<DnsMessage>),
    /// dird did not serve it: answer the client SERVFAIL (dns-zone's
    /// fallback reply).
    Unavailable,
}

/// Everything the forwarding thread runs with.
pub(crate) struct ForwardThread<C: Connector> {
    pub(crate) client: DnsClient<C>,
    pub(crate) jobs: mpsc::Receiver<ForwardJob>,
    pub(crate) zone: ZoneView,
    pub(crate) refresh: SyncSender<RefreshNow>,
    pub(crate) refresh_wait: Duration,
    /// The start check: dird verified on this thread's connection.
    pub(crate) ready: oneshot::Sender<Result<(), Unserved>>,
}

/// Spawn the forwarding thread (module documentation).
///
/// # Errors
/// The thread could not be spawned.
///
/// Spec: docs/54 §4.6, §6.7.
pub(crate) fn spawn<C>(thread: ForwardThread<C>) -> std::io::Result<JoinHandle<()>>
where
    C: Connector + Send + 'static,
    C::Connection: Send,
{
    std::thread::Builder::new()
        .name("dnsd-forward".to_owned())
        .spawn(move || run(thread))
}

/// The forwarding thread's body. Spec: module documentation.
fn run<C: Connector>(thread: ForwardThread<C>) {
    let ForwardThread {
        mut client,
        mut jobs,
        zone,
        refresh,
        refresh_wait,
        ready,
    } = thread;
    // The start check (docs/54 §4.8): this connection is verified too —
    // dird's uid, then a `Pong` naming the expected zone.
    let verified = client.ping();
    let failed = verified.is_err();
    if ready.send(verified).is_err() || failed {
        return;
    }
    // `blocking_recv`: this is a thread of its own, outside the runtime
    // (tokio 1.54.1 docs.rs, `sync::mpsc::Receiver::blocking_recv`).
    while let Some(job) = jobs.blocking_recv() {
        if job.answer.is_closed() {
            continue;
        }
        let outcome = match client.forward(&job.request) {
            Ok(forwarded) => {
                let serial = Some(forwarded.serial.get());
                if zone.serial() != serial {
                    fetch_now(&refresh, refresh_wait);
                    if zone.serial() != serial {
                        FORWARD_REFRESH_FAILED.hit();
                    }
                }
                ForwardOutcome::Relay(forwarded.reply)
            }
            Err(_) => {
                FORWARD_UNAVAILABLE.hit();
                ForwardOutcome::Unavailable
            }
        };
        let _ = job.answer.send(outcome);
    }
}

/// Ask the zone thread to fetch now and wait (at most `wait`) until it has
/// tried. The caller checks the SERIAL afterwards; the zone thread counts a
/// failed fetch. Spec: docs/54 §4.4 (a).
fn fetch_now(refresh: &SyncSender<RefreshNow>, wait: Duration) {
    let (done, finished) = sync_channel(1);
    if refresh.try_send(RefreshNow { done }).is_ok() {
        let _ = finished.recv_timeout(wait);
    }
}
