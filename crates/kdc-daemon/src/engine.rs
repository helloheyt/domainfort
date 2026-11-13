//! The engine: one dedicated OS thread owns the `Kdc`, its keyd client and
//! its directory client, fed by the two bounded queues (crate::queues).
//!
//! # Start (docs/50 R50-16, §7.5 step 4)
//!
//! The thread is spawned before anything is verified, holding the
//! connectors, and waits for the daemon's go-ahead — given only once auditd
//! was verified (R50-16: auditd first). Then, on this thread (the calls
//! block, and the clients live here):
//!
//! 1. the snapshot of the loaded policy (`policy_store`; a refused policy
//!    cannot reach here — it was refused at load);
//! 2. keyd: `IpcKeyd::connect` through the connector — the server uid
//!    checked before anything is sent (R50-3), then `DescribeConfig`, whose
//!    caller role must be `Kdc` (Q-351);
//! 3. dird: `DirectoryClient` (server uid checked, R50-3) →
//!    `DescribeDomain` → the realm and the krbtgt handle (§3.4, §7.5);
//! 4. **the policy version**: dird's must equal the version of the policy
//!    the kdc loaded (R50-2, §3.4, §7.2), else the daemon does not start;
//! 5. `Kdc::new(KdcConfig::new(realm, krbtgt), …)` — validated against
//!    keyd's configuration (the realms agree, the krbtgt handle's purpose,
//!    the UDP limit, §7.5 step 4).
//!
//! Only then does the daemon bind its listeners to the runtime and serve.
//!
//! # Every new connection repeats the start checks (Q-311, Q-351)
//!
//! The keyd description and caller role (`IpcKeyd::connect`) and the
//! domain description (`DirectoryClient::require_domain`) the engine started
//! from are required of **every new connection** the clients open later —
//! after keyd or dird was restarted, say — before anything else is sent on
//! it: keyd's `DescribeConfig` (callable only by the Kdc and Ldap roles)
//! must answer the same description and name the caller role keyd resolved
//! for the kdc's uid as `Kdc` (so the Ldap role is refused too), dird's
//! `DescribeDomain` the same realm, naming context, krbtgt handle and
//! policy version. A mismatch drops that
//! connection and the request is answered as for an unavailable keyd or
//! directory: KDC_ERR_SVC_UNAVAILABLE (29) over TCP, silence over UDP — so a
//! keyd that now maps this uid to another role never reaches the client as
//! keyd's uniform `Denied` (a wrong password, 24). A request that failed
//! after it was sent is 29 too, whatever the keyd client knows of its fate
//! (docs/questions/Q-367, A-88: issuance is not a key-state change, nothing
//! was handed out). Both clients also check
//! a held connection before reusing it (crates/ipc-keyd, crates/
//! ipc-directory; Q-312), so the first request after such a restart is
//! decided by the new process.
//!
//! # Per request (docs/50 R50-2, §4.1)
//!
//! own clock (`now`) → audit slot (crate::audit; none ⇒ keyd gated off and
//! no directory view) → a view pinned for this request (`BeginView`; the
//! view is the request's `AccountSource` and its PIP, docs/47 R47-14) →
//! `Kdc::handle(request, peer, now, &PolicyInputs, &view)` → the view ended
//! (`EndView`) → the event recorded → the answer. A view that cannot be
//! pinned (dird down, a deadline, Busy, the policy version) makes the
//! request go through `ipc_directory::UnavailableDirectory`:
//! KDC_ERR_SVC_UNAVAILABLE over TCP, silence over UDP (R50-8, A-56).
//!
//! There is no policy reload: a policy-version mismatch at run time (dird
//! restarted with another file) is answered as unavailable and logged; the
//! kdc must be restarted with the same file (docs/questions/Q-275 item 7).
//!
//! # Threads and hardening
//!
//! The thread is spawned inside the runtime that `main` builds only after
//! `daemon_sandbox::apply` (R50-14), so it inherits the hardened identity.
//!
//! Spec: docs/50 R50-2, R50-3, R50-7, R50-8, R50-9, R50-14, R50-16, §3.4,
//! §3.6, §3.7, §4.1, §7.2, §7.5; docs/47 §8.1 (R47-14); A-56; A-57; A-68;
//! A-69; docs/questions/Q-311, Q-312 (A-82).

use crate::audit::{is_issued, AuditGate, EventBuffer, Recorded};
use crate::clock::Clock;
use crate::custody::GatedCustody;
use crate::log::{Note, Thinned};
use crate::queues::{Answer, RequestQueues, Work};
use crate::rate::ObligationLimiter;
use core::fmt;
use core::time::Duration;
use ipc_directory::{DirectoryClient, UnavailableDirectory, Unserved};
use ipc_keyd::{IpcKeyd, KeydClient};
use kdc::{Kdc, KdcConfig, KdcReply, Peer, PolicyInputs};
use krb_proto::KerberosTime;
use pdp::{PolicySnapshot, PolicyVersion};
use policy_store::{DevelopmentPolicy, PolicyError};
use std::sync::mpsc;
use std::sync::Arc;
use tokio::sync::oneshot;

/// Thinned log counter: dird's policy version is not the kdc's.
static VERSION_MISMATCH: Thinned = Thinned::new(Note::PolicyVersionMismatch);

/// The KDC of the daemon: keyd over IPC behind the audit gate, the event
/// buffer, the obligation limiter.
pub(crate) type DaemonKdc<KC> = Kdc<GatedCustody<IpcKeyd<KC>>, EventBuffer, ObligationLimiter>;

/// Why the engine did not start. Carries no secret and no octet of any
/// message (docs/50 §8.2).
/// Spec: docs/50 §7.5 ("every daemon exits with an error code on any
/// start-up failure").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    /// The loaded policy gave no snapshot.
    Policy(PolicyError),
    /// keyd's uid in the configuration is refused (0).
    KeydUid,
    /// keyd did not answer `DescribeConfig` (not reachable, wrong uid,
    /// refused).
    Keyd(keyd_types::Error),
    /// dird's uid in the configuration is refused (0).
    DirdUid,
    /// dird did not answer `DescribeDomain`.
    Dird(Unserved),
    /// dird's policy version is not the version of the kdc's policy file
    /// (R50-2): the daemon does not start.
    PolicyVersionMismatch {
        /// The kdc's.
        kdc: PolicyVersion,
        /// dird's.
        dird: PolicyVersion,
    },
    /// `Kdc::new` refused the configuration (realm, krbtgt, UDP limit).
    Kdc(kdc::ConfigError),
    /// The start was cancelled before the go-ahead.
    Cancelled,
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::Policy(error) => write!(f, "policy: {error}"),
            StartError::KeydUid => f.write_str("keyd uid refused"),
            StartError::Keyd(error) => write!(f, "keyd not verified: {error:?}"),
            StartError::DirdUid => f.write_str("dird uid refused"),
            StartError::Dird(error) => write!(f, "dird not verified: {error}"),
            StartError::PolicyVersionMismatch { kdc, dird } => write!(
                f,
                "policy version mismatch: the kdc's policy file is version {}, dird's is version {}",
                kdc.0, dird.0
            ),
            StartError::Kdc(error) => write!(f, "kdc configuration refused: {error}"),
            StartError::Cancelled => f.write_str("engine start cancelled"),
        }
    }
}

impl std::error::Error for StartError {}

/// What the engine needs to start (module documentation).
pub(crate) struct EngineSetup<KC, DC, C> {
    pub(crate) keyd: KC,
    pub(crate) keyd_uid: u32,
    pub(crate) keyd_deadline: Duration,
    pub(crate) dird: DC,
    pub(crate) dird_uid: u32,
    pub(crate) dird_deadline: Duration,
    pub(crate) policy: DevelopmentPolicy,
    pub(crate) udp_max_reply_len: usize,
    pub(crate) clock: C,
    pub(crate) gate: Arc<AuditGate>,
}

/// The engine (module documentation).
pub(crate) struct Engine<KC: ipc_keyd::Connector, DC: ipc_directory::Connector, C: Clock> {
    kdc: DaemonKdc<KC>,
    directory: DirectoryClient<DC>,
    snapshot: PolicySnapshot,
    gate: Arc<AuditGate>,
    clock: C,
}

impl<KC, DC, C> Engine<KC, DC, C>
where
    KC: ipc_keyd::Connector,
    DC: ipc_directory::Connector,
    C: Clock,
{
    /// Steps 1-5 of the module documentation; the keyd and domain
    /// descriptions then required of every new connection (Q-311).
    ///
    /// # Errors
    /// [`StartError`].
    ///
    /// Spec: docs/50 R50-2, R50-3, R50-16, §3.4, §7.2, §7.5 step 4;
    /// docs/questions/Q-311 (A-82).
    pub(crate) fn start(setup: EngineSetup<KC, DC, C>) -> Result<Self, StartError> {
        let snapshot = setup.policy.snapshot().map_err(StartError::Policy)?;
        let version = snapshot.version();
        let client = KeydClient::new(setup.keyd, setup.keyd_uid, setup.keyd_deadline)
            .map_err(|_| StartError::KeydUid)?;
        let custody = IpcKeyd::connect(client).map_err(StartError::Keyd)?;
        let mut directory =
            DirectoryClient::new(setup.dird, setup.dird_uid, setup.dird_deadline, version)
                .map_err(|_| StartError::DirdUid)?;
        let domain = directory.describe_domain().map_err(StartError::Dird)?;
        if domain.policy_version != version {
            return Err(StartError::PolicyVersionMismatch {
                kdc: version,
                dird: domain.policy_version,
            });
        }
        // Q-311: every later dird connection must describe the same domain
        // (keyd's description is required by `IpcKeyd::connect`).
        directory.require_domain(domain.clone());
        let mut config = KdcConfig::new(domain.realm, domain.krbtgt);
        config.udp_max_reply_len = setup.udp_max_reply_len;
        let kdc = Kdc::new(
            config,
            GatedCustody::new(custody),
            EventBuffer::new(),
            ObligationLimiter::new(),
        )
        .map_err(StartError::Kdc)?;
        Ok(Engine {
            kdc,
            directory,
            snapshot,
            gate: setup.gate,
            clock: setup.clock,
        })
    }

    /// The policy version in force.
    pub(crate) fn policy_version(&self) -> PolicyVersion {
        self.snapshot.version()
    }

    /// Answer one job (module documentation).
    /// Spec: docs/50 §4.1; docs/questions/Q-218 (A-57), Q-252 item 9.
    pub(crate) fn serve(&mut self, work: Work, peer: Peer) -> Answer {
        // docs/50 §4.1: the kdc's own clock, per request; unreadable ⇒
        // nothing is answered (fail closed).
        let Some(now) = self.clock.now() else {
            return Answer::Withheld;
        };
        let (reply, admission) = match work {
            // A framing error decodes nothing: noise, no slot.
            Work::RejectFrame(error) => (self.kdc.reject_frame(error, peer, now), None),
            Work::Request(body) => {
                let admission = self.gate.admit();
                let reply = self.handle(&body, peer, now, admission.is_some());
                (reply, admission)
            }
        };
        let (events, overflowed) = self.kdc.audit_sink_mut().take();
        match self.gate.record(admission, &events, overflowed) {
            Ok(Recorded::Gating) => Answer::Reply(reply),
            // No issuing reply without its event in the window.
            Ok(Recorded::Noise) if events.iter().any(is_issued) => Answer::Withheld,
            Ok(Recorded::Noise) => Answer::Reply(reply),
            Err(_) => Answer::Withheld,
        }
    }

    /// `Kdc::handle` with keyd gated by `admitted` and a view pinned for
    /// this request, or the unavailable directory.
    /// Spec: docs/50 R50-2, R50-8, §3.4; docs/47 R47-14.
    fn handle(&mut self, body: &[u8], peer: Peer, now: KerberosTime, admitted: bool) -> KdcReply {
        self.kdc.custody_mut().set_serving(admitted);
        if admitted {
            match self.directory.begin_view() {
                Ok(view) => {
                    let inputs = PolicyInputs {
                        snapshot: &self.snapshot,
                        pip: &view,
                    };
                    let reply = self.kdc.handle(body, peer, now, &inputs, &view);
                    // Ends the view (EndView), releasing dird's snapshot.
                    drop(view);
                    return reply;
                }
                Err(Unserved::PolicyVersionMismatch { .. }) => VERSION_MISMATCH.hit(),
                Err(_) => {}
            }
        }
        let none = UnavailableDirectory;
        let inputs = PolicyInputs {
            snapshot: &self.snapshot,
            pip: &none,
        };
        self.kdc.handle(body, peer, now, &inputs, &none)
    }
}

/// The engine thread, to be joined after the daemon stopped.
#[derive(Debug)]
pub struct EngineThread {
    thread: std::thread::JoinHandle<()>,
}

/// The engine thread ended by unwinding (a defect).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnginePanicked;

impl EngineThread {
    /// Wait for the engine thread (it ends when the queues are closed and
    /// drained, or when its start failed or was cancelled).
    ///
    /// # Errors
    /// [`EnginePanicked`].
    pub fn join(self) -> Result<(), EnginePanicked> {
        self.thread.join().map_err(|_| EnginePanicked)
    }
}

/// Runs a closure when dropped — on normal return and on unwinding.
struct OnExit<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for OnExit<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

/// Spawn the engine thread: it waits for `go`, starts (module
/// documentation), reports through `started`, then serves `queues` until
/// they are closed and drained. `on_exit` runs when the thread ends after a
/// successful start (the daemon then stops instead of serving without an
/// engine).
///
/// # Errors
/// `std::io::Error` if the operating system refused the thread.
///
/// Spec: docs/50 R50-7, R50-9, R50-14, R50-16.
pub(crate) fn spawn<KC, DC, C, X>(
    setup: EngineSetup<KC, DC, C>,
    queues: Arc<RequestQueues>,
    go: mpsc::Receiver<()>,
    started: oneshot::Sender<Result<PolicyVersion, StartError>>,
    on_exit: X,
) -> std::io::Result<EngineThread>
where
    KC: ipc_keyd::Connector + Send + 'static,
    DC: ipc_directory::Connector + Send + 'static,
    C: Clock,
    X: FnOnce() + Send + 'static,
{
    let thread = std::thread::Builder::new()
        .name(String::from("kdc-engine"))
        .spawn(move || {
            if go.recv().is_err() {
                // The daemon gave up before the go-ahead; the connectors
                // are dropped here, on this thread.
                let _ = started.send(Err(StartError::Cancelled));
                return;
            }
            let mut engine = match Engine::start(setup) {
                Ok(engine) => engine,
                Err(error) => {
                    let _ = started.send(Err(error));
                    return;
                }
            };
            let _exit = OnExit(Some(on_exit));
            let _ = started.send(Ok(engine.policy_version()));
            while let Some(job) = queues.next() {
                let answer = engine.serve(job.work, job.peer);
                // The requester may be gone; its answer is dropped.
                let _ = job.reply.send(answer);
            }
        })?;
    Ok(EngineThread { thread })
}
