//! The single-thread guard (docs/50 R50-14: drop uid/gid "before creating any
//! thread — the functions act on the calling thread").
//!
//! # Design: a proof token, not a thread count
//!
//! rustix documents that `set_thread_res_uid`, `set_thread_res_gid` and
//! `set_thread_groups` change the ids "only for the current thread, not the
//! entire process", and `set_no_new_privs` acts on "the calling thread". A
//! thread that already exists when they run keeps the old identity. The guard
//! must therefore make `apply` refuse once other threads exist.
//!
//! The rustix API pages offer no thread-count query, and the only other
//! unsafe-free route (listing the process's tasks under procfs) rests on
//! operating-system documentation that is not an allowed source
//! (docs/questions/Q-215, owner item P-18). So the guard is a proof token:
//!
//! * [`SingleThreadProof::claim`] is called as the **first statement of
//!   `main`**, before any runtime is built or any library can start a thread
//!   (Rust runs no user code before `main`). At that point the process has
//!   exactly one thread.
//! * At most **one proof per process**: a second `claim`, from any thread,
//!   fails with [`ThreadGuardError::AlreadyClaimed`]. A thread that starts
//!   later cannot obtain one.
//! * The proof is neither `Send` nor `Sync`: it cannot be moved or shared to
//!   another thread (compile-time), so [`apply`](crate::apply) — which
//!   consumes it — runs on the thread that claimed it. `apply` also re-checks
//!   the thread at run time and refuses with
//!   [`ThreadGuardError::WrongThread`].
//! * Consuming the proof makes `apply` run at most once per process.
//!
//! **Residual (documented, not detectable here):** a thread spawned *between*
//! `claim` and `apply` is not detected. The contract is that `main` claims,
//! builds its plan, and applies before it spawns anything (docs/50 §6.2: only
//! then is the tokio runtime built). See docs/questions/Q-235.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::ThreadId;

use crate::error::ThreadGuardError;

/// Set once, by the first successful [`SingleThreadProof::claim`].
// Spec: docs/50 R50-14 (one drop, before any thread exists).
static CLAIMED: AtomicBool = AtomicBool::new(false);

/// Evidence that the caller claimed the process's one hardening slot on the
/// thread it will apply from, before spawning any thread (docs/50 R50-14).
///
/// Contract: claim as the first statement of `main`; one proof per process;
/// the proof is neither `Send` nor `Sync`; [`apply`](crate::apply) consumes
/// it. A thread spawned between `claim` and `apply` is not detected — the
/// rustix API offers no thread-count query (docs/questions/Q-235).
///
/// ```
/// let proof = daemon_sandbox::SingleThreadProof::claim();
/// assert!(proof.is_ok());
/// // Only one proof exists per process.
/// assert!(daemon_sandbox::SingleThreadProof::claim().is_err());
/// ```
///
/// The proof cannot be moved to another thread:
///
/// ```compile_fail,E0277
/// let proof = daemon_sandbox::SingleThreadProof::claim();
/// std::thread::spawn(move || drop(proof));
/// ```
// Spec: docs/50 R50-14; rustix 1.1.6 thread::set_thread_res_uid (per-thread
// warning), thread::set_no_new_privs ("the calling thread").
#[derive(Debug)]
pub struct SingleThreadProof {
    thread: ThreadId,
    /// A raw-pointer marker makes the type neither `Send` nor `Sync`.
    _not_send_or_sync: PhantomData<*const ()>,
}

impl SingleThreadProof {
    /// Claim the proof. Call as the first statement of `main`. Fails if a
    /// proof was already claimed in this process.
    pub fn claim() -> Result<Self, ThreadGuardError> {
        if CLAIMED
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(ThreadGuardError::AlreadyClaimed);
        }
        Ok(Self {
            thread: std::thread::current().id(),
            _not_send_or_sync: PhantomData,
        })
    }

    /// Refuse unless called on the claiming thread (defence in depth: the
    /// type is already `!Send`).
    pub(crate) fn confirm_current_thread(&self) -> Result<(), ThreadGuardError> {
        if std::thread::current().id() == self.thread {
            Ok(())
        } else {
            Err(ThreadGuardError::WrongThread)
        }
    }
}
