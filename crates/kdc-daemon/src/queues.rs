//! The two bounded engine queues — AS and TGS — and the classification that
//! picks one by the request's first identifier octet.
//!
//! # Classification (docs/50 §4.1)
//!
//! "the network tasks put into two bounded queues — AS and TGS — by **a peek
//! at the first identifier octet only** ('AS-REQ ::= [APPLICATION 10]
//! KDC-REQ', 'TGS-REQ ::= [APPLICATION 12] KDC-REQ', RFC 4120 §5.4.1),
//! without decoding — queue choice only, not a decision (another octet ⇒ the
//! AS queue, and `Kdc::handle` decides)". The identifier octet of a tag
//! numbered 0 to 30 is one octet: bits 8-7 the class (Application = `01`,
//! X.690 8.1.2.2 a), Table 1), bit 6 set for a constructed encoding (8.1.2.5;
//! RFC 4120's module uses EXPLICIT TAGS, so `[APPLICATION n] KDC-REQ` wraps
//! the SEQUENCE and is constructed), bits 5-1 the number (8.1.2.2 c)) — so
//! the AS-REQ starts with [`AS_REQ_IDENTIFIER`] and the TGS-REQ with
//! [`TGS_REQ_IDENTIFIER`]. A framing error found before any message
//! (`Kdc::reject_frame`) goes to the AS queue too.
//!
//! # The queues (docs/50 R50-9; docs/07 §1)
//!
//! Each queue holds at most its capacity of jobs; a full queue refuses the
//! job at once ([`SubmitError::Full`]: UDP drops it, TCP closes — docs/50
//! §4.1: "full queue ⇒ UDP silence, TCP close"). The one engine thread takes
//! jobs alternately from the two queues whenever both hold one, otherwise
//! from the one that does: a flood into either queue fills only that queue
//! and takes at most every other engine turn, so it cannot starve the other
//! (docs/07 §1: "a separate pool for authenticated vs unauthenticated, so
//! an unauthenticated flood does not starve the authenticated"). The first
//! octet is the client's claim, so the protection is symmetric: a flood of
//! octets that look like TGS requests cannot starve the AS either.
//!
//! The queues are a `Mutex` + `Condvar` pair: a submit holds the lock for a
//! constant-time push (never waits), the engine waits on the condition.
//!
//! Spec: docs/50 R50-9, §4.1; docs/07 §1; RFC 4120 §5.4.1; X.690 8.1.2.2,
//! 8.1.2.5.

use kdc::{FramingError, KdcReply, Peer};
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use tokio::sync::oneshot;

/// The class bits of an Application tag, in place (X.690 8.1.2.2 a),
/// Table 1: bit 8 = 0, bit 7 = 1).
const CLASS_APPLICATION: u8 = 0b0100_0000;
/// The constructed bit (X.690 8.1.2.5: bit 6).
const CONSTRUCTED: u8 = 0b0010_0000;
/// AS-REQ ::= [APPLICATION 10]. Spec: RFC 4120 §5.4.1.
const AS_REQ_TAG: u8 = 10;
/// TGS-REQ ::= [APPLICATION 12]. Spec: RFC 4120 §5.4.1.
const TGS_REQ_TAG: u8 = 12;

/// The first octet of an AS-REQ. Spec: RFC 4120 §5.4.1; X.690 8.1.2.2,
/// 8.1.2.5.
pub const AS_REQ_IDENTIFIER: u8 = CLASS_APPLICATION | CONSTRUCTED | AS_REQ_TAG;
/// The first octet of a TGS-REQ. Spec: as [`AS_REQ_IDENTIFIER`].
pub const TGS_REQ_IDENTIFIER: u8 = CLASS_APPLICATION | CONSTRUCTED | TGS_REQ_TAG;

/// Which engine queue. Spec: docs/50 §4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Queue {
    /// AS requests, and everything that is not a TGS request.
    As,
    /// TGS requests.
    Tgs,
}

/// The queue of a request, by its first octet only — classification, not
/// a decision. Spec: docs/50 §4.1.
#[must_use]
pub fn queue_of(request: &[u8]) -> Queue {
    match request.first() {
        Some(&TGS_REQ_IDENTIFIER) => Queue::Tgs,
        _ => Queue::As,
    }
}

/// What the engine is asked to do.
pub(crate) enum Work {
    /// One request message (a UDP datagram, or one TCP record without its
    /// length prefix): `Kdc::handle`.
    Request(Vec<u8>),
    /// A TCP framing error: `Kdc::reject_frame` (RFC 4120 §7.2.2).
    RejectFrame(FramingError),
}

/// Never the request octets (docs/50 §8.2: "never logged: raw request
/// bytes"), only their length.
impl core::fmt::Debug for Work {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Work::Request(body) => f.debug_struct("Request").field("len", &body.len()).finish(),
            Work::RejectFrame(error) => f.debug_tuple("RejectFrame").field(error).finish(),
        }
    }
}

/// The engine's answer to one job.
/// Spec: RFC 4120 §7.2.1, §7.2.2; docs/questions/Q-218 (A-57).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// What `Kdc` answered.
    Reply(KdcReply),
    /// Nothing may be sent: the record of an issuing reply could not be put
    /// into the audit window, or the clock could not be read. UDP: silence;
    /// TCP: close without a reply.
    Withheld,
}

/// One job: the work, how it arrived, where the answer goes.
#[derive(Debug)]
pub(crate) struct Job {
    pub(crate) work: Work,
    pub(crate) peer: Peer,
    pub(crate) reply: oneshot::Sender<Answer>,
}

/// Why a job was not queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitError {
    /// That queue is full (UDP: drop; TCP: close).
    Full,
    /// The engine is stopping or stopped.
    Stopped,
}

#[derive(Debug, Default)]
struct State {
    as_jobs: VecDeque<Job>,
    tgs_jobs: VecDeque<Job>,
    /// Whose turn it is when both queues hold a job.
    tgs_turn: bool,
    closed: bool,
}

/// The two bounded queues in front of the engine (module documentation).
#[derive(Debug)]
pub struct RequestQueues {
    state: Mutex<State>,
    ready: Condvar,
    as_capacity: usize,
    tgs_capacity: usize,
}

impl RequestQueues {
    /// Queues of the given capacities (each at least 1).
    #[must_use]
    pub fn new(as_capacity: usize, tgs_capacity: usize) -> RequestQueues {
        RequestQueues {
            state: Mutex::new(State::default()),
            ready: Condvar::new(),
            as_capacity: as_capacity.max(1),
            tgs_capacity: tgs_capacity.max(1),
        }
    }

    /// Queue `work` without waiting; the receiver yields the engine's
    /// answer (it fails if the engine drops the job unanswered).
    ///
    /// # Errors
    /// [`SubmitError`].
    ///
    /// Spec: docs/50 §4.1 ("full queue ⇒ UDP silence, TCP close").
    pub(crate) fn submit(
        &self,
        queue: Queue,
        work: Work,
        peer: Peer,
    ) -> Result<oneshot::Receiver<Answer>, SubmitError> {
        let mut state = self.state.lock().map_err(|_| SubmitError::Stopped)?;
        if state.closed {
            return Err(SubmitError::Stopped);
        }
        let (target, capacity) = match queue {
            Queue::As => (&mut state.as_jobs, self.as_capacity),
            Queue::Tgs => (&mut state.tgs_jobs, self.tgs_capacity),
        };
        if target.len() >= capacity {
            return Err(SubmitError::Full);
        }
        let (reply, answer) = oneshot::channel();
        target.push_back(Job { work, peer, reply });
        drop(state);
        self.ready.notify_one();
        Ok(answer)
    }

    /// The next job for the engine, alternating between the queues when both
    /// hold one; waits while both are empty. `None` once the queues are
    /// closed and empty (queued jobs are served first).
    /// Spec: docs/50 R50-9; docs/07 §1.
    pub(crate) fn next(&self) -> Option<Job> {
        let mut state = self.state.lock().ok()?;
        loop {
            let take_tgs = match (state.as_jobs.is_empty(), state.tgs_jobs.is_empty()) {
                (false, false) => state.tgs_turn,
                (true, false) => true,
                (false, true) => false,
                (true, true) => {
                    if state.closed {
                        return None;
                    }
                    state = self.ready.wait(state).ok()?;
                    continue;
                }
            };
            state.tgs_turn = !take_tgs;
            let job = if take_tgs {
                state.tgs_jobs.pop_front()
            } else {
                state.as_jobs.pop_front()
            };
            if job.is_some() {
                return job;
            }
        }
    }

    /// Refuse new jobs; the engine serves what is queued, then ends.
    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
        }
        self.ready.notify_all();
    }

    /// Jobs waiting in each queue (AS, TGS).
    #[must_use]
    pub fn lengths(&self) -> (usize, usize) {
        self.state
            .lock()
            .map(|s| (s.as_jobs.len(), s.tgs_jobs.len()))
            .unwrap_or((0, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdc::Transport;
    use pdp::IpScope;

    fn peer() -> Peer {
        Peer {
            transport: Transport::Udp,
            src_net: IpScope::Internal,
        }
    }

    fn label(job: &Job) -> u8 {
        match &job.work {
            Work::Request(body) => body.get(1).copied().unwrap_or(0),
            Work::RejectFrame(_) => 0,
        }
    }

    /// RFC 4120 §5.4.1 with X.690 8.1.2.2 / 8.1.2.5: [APPLICATION 10] and
    /// [APPLICATION 12], constructed, are one identifier octet each
    /// (`01` ‖ `1` ‖ `01010` and `01` ‖ `1` ‖ `01100`); every other first
    /// octet, and the empty request, goes to the AS queue.
    #[test]
    fn the_first_octet_chooses_the_queue() {
        assert_eq!(AS_REQ_IDENTIFIER, 0b0110_1010);
        assert_eq!(TGS_REQ_IDENTIFIER, 0b0110_1100);
        assert_eq!(queue_of(&[TGS_REQ_IDENTIFIER, 0x82]), Queue::Tgs);
        assert_eq!(queue_of(&[AS_REQ_IDENTIFIER, 0x82]), Queue::As);
        assert_eq!(queue_of(&[]), Queue::As);
        for octet in 0..=u8::MAX {
            if octet != TGS_REQ_IDENTIFIER {
                assert_eq!(queue_of(&[octet]), Queue::As, "{octet:#04x}");
            }
        }
    }

    /// docs/50 §4.1 ("full queue ⇒ drop / close"); docs/07 §1 (a flood of
    /// one kind does not starve the other): a full AS queue still admits TGS
    /// jobs and the inverse; the engine alternates when both hold jobs;
    /// closing serves what is queued and then ends.
    #[test]
    fn each_queue_is_bounded_and_the_engine_alternates() {
        let queues = RequestQueues::new(2, 2);
        let mut answers = Vec::new();
        for n in 1..=2u8 {
            answers.push(
                queues
                    .submit(Queue::As, Work::Request(vec![AS_REQ_IDENTIFIER, n]), peer())
                    .unwrap(),
            );
        }
        assert_eq!(
            queues
                .submit(Queue::As, Work::Request(vec![AS_REQ_IDENTIFIER, 3]), peer())
                .err(),
            Some(SubmitError::Full)
        );
        for n in 11..=12u8 {
            answers.push(
                queues
                    .submit(
                        Queue::Tgs,
                        Work::Request(vec![TGS_REQ_IDENTIFIER, n]),
                        peer(),
                    )
                    .unwrap(),
            );
        }
        assert_eq!(
            queues
                .submit(
                    Queue::Tgs,
                    Work::Request(vec![TGS_REQ_IDENTIFIER, 13]),
                    peer()
                )
                .err(),
            Some(SubmitError::Full)
        );
        assert_eq!(queues.lengths(), (2, 2));
        let order: Vec<u8> = (0..4).map(|_| label(&queues.next().unwrap())).collect();
        assert_eq!(order, [1, 11, 2, 12]);
        // One kind only: served in order.
        queues
            .submit(
                Queue::Tgs,
                Work::Request(vec![TGS_REQ_IDENTIFIER, 21]),
                peer(),
            )
            .unwrap();
        queues
            .submit(
                Queue::Tgs,
                Work::Request(vec![TGS_REQ_IDENTIFIER, 22]),
                peer(),
            )
            .unwrap();
        queues.close();
        assert_eq!(
            queues
                .submit(Queue::As, Work::Request(vec![AS_REQ_IDENTIFIER, 9]), peer())
                .err(),
            Some(SubmitError::Stopped)
        );
        assert_eq!(label(&queues.next().unwrap()), 21);
        assert_eq!(label(&queues.next().unwrap()), 22);
        assert!(queues.next().is_none());
        drop(answers);
    }
}
