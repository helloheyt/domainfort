//! The sender's bounded window of unacknowledged events, and the decided
//! overflow policy.
//!
//! # The policy (docs/questions/Q-218, option (a), decided A-57)
//!
//! "No unaudited issuance (docs/37), and log overflow does not turn into
//! shutdown (docs/07 §8)." In this window that is:
//!
//! * **Gating events** — the record of an operation that must not happen
//!   unaudited (every keyd operation; every KDC request that may issue) —
//!   take a slot **before** the operation: [`SendWindow::reserve`]. When the
//!   window is full of unacknowledged events, the reservation is refused
//!   ([`WindowFull`]) and the caller does not perform the operation (keyd
//!   answers `Busy`; the KDC refuses instead of issuing). The refusal is
//!   counted and reported later in a [`WindowSummary`] event. After the
//!   operation, the caller commits the event into its slot
//!   ([`SendWindow::commit`]) and only then sends its reply — so no reply
//!   that issues anything leaves without its event in the window.
//! * **Noise** — unauthenticated events such as an undecodable datagram or a
//!   malformed frame — may hold at most [`WindowConfig::noise_limit`] slots,
//!   so a flood can never take the slots gating events need. Beyond that
//!   share, noise is counted, not queued ([`SendWindow::offer_noise`]), and
//!   the count goes into the next [`WindowSummary`]: summarised in counters,
//!   and limited to the share of the window that acknowledgements free. A
//!   sender whose noise has no event shape at all (dnsd: docs/54 §9, "only
//!   counters") counts every occurrence ([`SendWindow::count_noise`]) into
//!   the same summary.
//! * **Lost outcomes** — for an operation recorded in two events (an intent
//!   or decision acknowledged first, then its outcome: keyd-daemon's
//!   key-state changes, dird's admin writes), an outcome record that could
//!   not be committed into its reserved slot — is counted by the caller
//!   ([`SendWindow::count_unrecorded_outcome`]) and the count goes into the
//!   next [`WindowSummary`] beside the other two (decision A-88;
//!   docs/questions/Q-366 option (a), Q-395). A refused reservation means
//!   "not done"; a lost outcome means "an intent without its outcome — the
//!   operation may have been done": they are kept apart.
//! * **No shutdown.** Nothing here stops the process or signals that it
//!   should: a full window only refuses new gating reservations and counts
//!   noise. The service stays up and answers; it just does not issue without
//!   a record (Q-218: "the service is 'alive' but does not issue without
//!   evidence").
//!
//! Which events are gating and which are noise is each daemon's call
//! (docs/questions/Q-252 item 8 lists the open cases).
//!
//! # The protocol
//!
//! [`SendWindow::next_batch`] hands out the oldest committed events as one
//! `Append` (at most [`crate::MAX_BATCH_EVENTS`]); only one batch is in
//! flight at a time (docs/50 §3.6: strict request → reply). The matching
//! `Ack` ([`SendWindow::acknowledge`]) frees their slots. A lost connection
//! or a `Refused` reply puts the in-flight batch back at the front
//! ([`SendWindow::connection_lost`]), to be resent with the same numbers.
//!
//! Residual: events in the window are in the sender's memory until
//! acknowledged; if the sender process dies, up to `capacity` of them are
//! lost — the window's size is that bound (docs/questions/Q-252 item 9).
//!
//! Spec: docs/50 R50-17 ("processes deliver events in a bounded window and
//! wait for persistence acknowledgements"), §8.1, §3.6; docs/questions/Q-218
//! (A-57); docs/07 §8; docs/37 §2 (no code path disables audit for a
//! sensitive operation, D63); docs/questions/Q-366 (A-88), Q-395 (the
//! lost-outcome count).

use crate::channel::{Ack, Append, MAX_BATCH_EVENTS};
use crate::error::EventError;
use crate::event::{encode_event, EventBody, EventBytes, WindowSummary};
use core::fmt;
use std::collections::VecDeque;

/// The window's size and its noise share.
///
/// Spec: docs/50 R50-17 (a bounded window); docs/questions/Q-218 (A-57);
/// docs/questions/Q-230 item 4 (docs/50 gives no number: constants here,
/// docs/questions/Q-252 item 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowConfig {
    capacity: u32,
    noise_limit: u32,
}

impl WindowConfig {
    /// Largest window: 1024 events. Project choice.
    pub const MAX_CAPACITY: u32 = 1024;

    /// The default: 64 events, of which noise may hold 16. Project choice.
    pub const DEFAULT: WindowConfig = WindowConfig {
        capacity: 64,
        noise_limit: 16,
    };

    /// A window of `capacity` slots (1..=[`WindowConfig::MAX_CAPACITY`]) of
    /// which noise may hold at most `noise_limit` (< `capacity`, so a slot
    /// is always left for gating events), or `None`.
    #[must_use]
    pub const fn new(capacity: u32, noise_limit: u32) -> Option<WindowConfig> {
        if capacity == 0 || capacity > Self::MAX_CAPACITY || noise_limit >= capacity {
            None
        } else {
            Some(WindowConfig {
                capacity,
                noise_limit,
            })
        }
    }

    /// Slots in the window.
    #[must_use]
    pub const fn capacity(self) -> u32 {
        self.capacity
    }

    /// Most slots noise may hold.
    #[must_use]
    pub const fn noise_limit(self) -> u32 {
        self.noise_limit
    }
}

/// A slot taken for a gating event. Commit it ([`SendWindow::commit`]) once
/// the operation's outcome is known, or give it back
/// ([`SendWindow::release`]) if no event will be produced.
///
/// Spec: docs/questions/Q-218 (A-57: no unaudited issuance).
#[must_use = "a reserved slot must be committed or released"]
#[derive(Debug, PartialEq, Eq)]
pub struct Reservation {
    _slot: (),
}

/// The window is full of unacknowledged events: the gating operation must
/// not be performed. Spec: docs/questions/Q-218 (A-57).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowFull;

impl fmt::Display for WindowFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("audit window full: operation refused")
    }
}

impl std::error::Error for WindowFull {}

/// What happened to a noise event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseAdmission {
    /// Queued with this sequence number.
    Queued {
        /// The event's sequence number.
        seq: u64,
    },
    /// Counted for the next summary, not queued.
    Counted,
}

/// Why a window operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowError {
    /// The event could not be encoded (the slot was given back).
    Encode(EventError),
    /// The sequence numbers are exhausted.
    SequenceExhausted,
    /// An `Ack` that does not match the batch in flight (close the
    /// connection, then [`SendWindow::connection_lost`]).
    UnexpectedAck,
}

impl fmt::Display for WindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WindowError::Encode(error) => write!(f, "audit event not encodable: {error}"),
            WindowError::SequenceExhausted => f.write_str("audit sequence exhausted"),
            WindowError::UnexpectedAck => f.write_str("acknowledgement does not match"),
        }
    }
}

impl std::error::Error for WindowError {}

/// One event held in the window.
#[derive(Debug, Clone)]
struct Slot {
    seq: u64,
    event: EventBytes,
    noise: bool,
}

/// The sender's window. See the module documentation for the policy.
///
/// Spec: docs/50 R50-17, §8.1; docs/questions/Q-218 (A-57).
#[derive(Debug)]
pub struct SendWindow {
    config: WindowConfig,
    next_seq: u64,
    /// Committed events not yet sent, oldest first.
    pending: VecDeque<Slot>,
    /// The batch sent and not yet acknowledged.
    in_flight: Vec<Slot>,
    /// Outstanding reservations.
    reserved: u32,
    /// Noise events in `pending` and `in_flight`.
    noise_held: u32,
    suppressed_noise: u64,
    refused_gating: u64,
    /// Lost outcome records counted since the last summary (A-88).
    unrecorded_outcomes: u64,
    last_ack: Option<Ack>,
}

impl SendWindow {
    /// An empty window; the first event gets sequence number 1.
    #[must_use]
    pub fn new(config: WindowConfig) -> SendWindow {
        SendWindow {
            config,
            next_seq: 1,
            pending: VecDeque::new(),
            in_flight: Vec::new(),
            reserved: 0,
            noise_held: 0,
            suppressed_noise: 0,
            refused_gating: 0,
            unrecorded_outcomes: 0,
            last_ack: None,
        }
    }

    /// Slots in use: unacknowledged events and outstanding reservations.
    #[must_use]
    pub fn used(&self) -> u32 {
        let events = self.pending.len().saturating_add(self.in_flight.len());
        u32::try_from(events)
            .unwrap_or(u32::MAX)
            .saturating_add(self.reserved)
    }

    /// Whether every slot is in use (gating reservations are refused).
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.used() >= self.config.capacity
    }

    /// Reserve a slot for a gating event **before** the operation.
    ///
    /// # Errors
    /// [`WindowFull`]: do not perform the operation (keyd: `Busy`; KDC:
    /// refuse instead of issuing). The refusal is counted for the next
    /// [`WindowSummary`].
    ///
    /// Spec: docs/questions/Q-218 (A-57: "no unaudited issuance").
    pub fn reserve(&mut self) -> Result<Reservation, WindowFull> {
        if self.is_full() {
            self.refused_gating = self.refused_gating.saturating_add(1);
            return Err(WindowFull);
        }
        self.reserved = self.reserved.saturating_add(1);
        Ok(Reservation { _slot: () })
    }

    /// Put the gating event into its reserved slot; returns its sequence
    /// number. Send the operation's reply only after this succeeded.
    ///
    /// # Errors
    /// [`WindowError::Encode`] (cannot happen for events built from this
    /// crate's types; the slot is given back and the caller must not send
    /// an issuing reply), [`WindowError::SequenceExhausted`].
    ///
    /// Spec: docs/questions/Q-218 (A-57); docs/50 §8.1.
    pub fn commit(
        &mut self,
        reservation: Reservation,
        event: &EventBody,
    ) -> Result<u64, WindowError> {
        let Reservation { _slot: () } = reservation;
        self.reserved = self.reserved.saturating_sub(1);
        let event = encode_event(event).map_err(WindowError::Encode)?;
        self.push(event, false)
    }

    /// Give back a reserved slot without an event (for an operation that
    /// produced none).
    pub fn release(&mut self, reservation: Reservation) {
        let Reservation { _slot: () } = reservation;
        self.reserved = self.reserved.saturating_sub(1);
    }

    /// Offer an unauthenticated noise event: queued if noise holds fewer
    /// than [`WindowConfig::noise_limit`] slots and a slot is free,
    /// otherwise counted for the next [`WindowSummary`].
    ///
    /// # Errors
    /// [`WindowError::Encode`], [`WindowError::SequenceExhausted`] (the
    /// event is then counted as suppressed).
    ///
    /// Spec: docs/questions/Q-218 (A-57: noise "summarised in counters and
    /// rate-limited").
    pub fn offer_noise(&mut self, event: &EventBody) -> Result<NoiseAdmission, WindowError> {
        if self.noise_held >= self.config.noise_limit || self.is_full() {
            self.suppressed_noise = self.suppressed_noise.saturating_add(1);
            return Ok(NoiseAdmission::Counted);
        }
        let encoded = encode_event(event).map_err(|error| {
            self.suppressed_noise = self.suppressed_noise.saturating_add(1);
            WindowError::Encode(error)
        })?;
        let seq = self.push(encoded, true).inspect_err(|_| {
            self.suppressed_noise = self.suppressed_noise.saturating_add(1);
        })?;
        Ok(NoiseAdmission::Queued { seq })
    }

    /// Count one noise occurrence that has no event of its own — a sender
    /// whose noise is reported **only** as counters (dnsd: docs/54 §9,
    /// "only counters (`WindowSummary` — noise: dropped / limited /
    /// malformed / refused)"; "no record per query"). The count goes into
    /// the next [`WindowSummary`] (`suppressed_noise`), exactly as noise
    /// beyond the noise share does in [`SendWindow::offer_noise`]; it takes
    /// no slot, so it can never crowd out a gating event. Saturates instead
    /// of wrapping.
    ///
    /// Spec: docs/questions/Q-218 (A-57: noise "summarised in counters and
    /// rate-limited"); docs/54 §9; docs/questions/Q-961.
    pub fn count_noise(&mut self) {
        self.count_noise_n(1);
    }

    /// Count `occurrences` noise occurrences at once — [`SendWindow::count_noise`]
    /// in one step (one addition, not one per occurrence), for a sender that
    /// already holds a count (docs/questions/Q-988 item 5). Into the next
    /// [`WindowSummary`] (`suppressed_noise`); no slot; saturates instead of
    /// wrapping; 0 counts nothing.
    ///
    /// Spec: docs/questions/Q-218 (A-57); docs/54 §9; docs/questions/Q-961,
    /// Q-989 item 3 (A-165: "plus a bulk `count_noise_n(u64)`").
    pub fn count_noise_n(&mut self, occurrences: u64) {
        self.suppressed_noise = self.suppressed_noise.saturating_add(occurrences);
    }

    /// Count an outcome record that could not be committed (its
    /// [`SendWindow::commit`] failed, or the caller had no record to commit)
    /// although its operation's intent or decision is already recorded: the
    /// count goes into the next [`WindowSummary`] (`unrecorded_outcomes`), so
    /// the log says that an intent there has no outcome. Additive to the
    /// window's other counters; takes no slot. Saturates instead of
    /// wrapping.
    ///
    /// Not for a refused reservation — [`SendWindow::reserve`] counts that
    /// itself, as `refused_gating` ("not done").
    ///
    /// Spec: decision A-88 (a lost-outcome count in the shared summary);
    /// docs/questions/Q-366 option (a), Q-346 (A-86: "the gap is
    /// surfaced"), Q-395; docs/37 §5.
    pub fn count_unrecorded_outcome(&mut self) {
        self.unrecorded_outcomes = self.unrecorded_outcomes.saturating_add(1);
    }

    /// Append an encoded event to the pending queue.
    fn push(&mut self, event: EventBytes, noise: bool) -> Result<u64, WindowError> {
        let seq = self.next_seq;
        self.next_seq = seq.checked_add(1).ok_or(WindowError::SequenceExhausted)?;
        if noise {
            self.noise_held = self.noise_held.saturating_add(1);
        }
        self.pending.push_back(Slot { seq, event, noise });
        Ok(seq)
    }

    /// If anything was counted and a slot is free, queue the summary event
    /// (the three counters together; each starts again from 0 once queued).
    /// Spec: docs/questions/Q-218 (A-57), Q-366 (A-88), Q-395.
    fn queue_summary(&mut self) {
        let nothing_counted =
            self.suppressed_noise == 0 && self.refused_gating == 0 && self.unrecorded_outcomes == 0;
        if nothing_counted || self.is_full() {
            return;
        }
        let summary = EventBody::WindowSummary(WindowSummary {
            suppressed_noise: self.suppressed_noise,
            refused_gating: self.refused_gating,
            unrecorded_outcomes: self.unrecorded_outcomes,
        });
        if let Ok(event) = encode_event(&summary) {
            if self.push(event, false).is_ok() {
                self.suppressed_noise = 0;
                self.refused_gating = 0;
                self.unrecorded_outcomes = 0;
            }
        }
    }

    /// The next batch to send, if nothing is in flight and anything is
    /// pending: the oldest events, at most [`MAX_BATCH_EVENTS`]. A pending
    /// summary of counted events is queued first, when a slot is free.
    ///
    /// Spec: docs/50 §3.6 (one request in flight), §8.1.
    pub fn next_batch(&mut self) -> Option<Append> {
        if !self.in_flight.is_empty() {
            return None;
        }
        self.queue_summary();
        let take = self.pending.len().min(MAX_BATCH_EVENTS as usize);
        if take == 0 {
            return None;
        }
        self.in_flight = self.pending.drain(..take).collect();
        let first_seq = self.in_flight.first().map(|slot| slot.seq)?;
        let events = self
            .in_flight
            .iter()
            .map(|slot| slot.event.clone())
            .collect();
        let append = Append::new(first_seq, events);
        if append.is_none() {
            // Cannot happen (1..=MAX_BATCH_EVENTS events, numbers in range);
            // keep the events rather than lose them.
            self.connection_lost();
        }
        append
    }

    /// Apply auditd's acknowledgement of the batch in flight; returns how
    /// many slots it freed.
    ///
    /// # Errors
    /// [`WindowError::UnexpectedAck`] if nothing is in flight or
    /// `through_seq` is not the batch's last number: close the connection and
    /// call [`SendWindow::connection_lost`].
    ///
    /// Spec: docs/50 §8.1 (persistence acknowledgement).
    pub fn acknowledge(&mut self, ack: &Ack) -> Result<usize, WindowError> {
        let last = self.in_flight.last().map(|slot| slot.seq);
        if last != Some(ack.through_seq) {
            return Err(WindowError::UnexpectedAck);
        }
        let freed = self.in_flight.len();
        let noise = self.in_flight.iter().filter(|slot| slot.noise).count();
        self.noise_held = self
            .noise_held
            .saturating_sub(u32::try_from(noise).unwrap_or(u32::MAX));
        self.in_flight.clear();
        self.last_ack = Some(*ack);
        Ok(freed)
    }

    /// The connection dropped (or auditd answered `Refused`): the batch in
    /// flight goes back to the front, to be resent with the same numbers.
    ///
    /// Spec: docs/50 §3.7 (reconnect with bounded backoff), §8.1.
    pub fn connection_lost(&mut self) {
        for slot in self.in_flight.drain(..).rev() {
            self.pending.push_front(slot);
        }
    }

    /// Unacknowledged events (pending and in flight).
    #[must_use]
    pub fn unacknowledged(&self) -> usize {
        self.pending.len().saturating_add(self.in_flight.len())
    }

    /// Outstanding reservations.
    #[must_use]
    pub fn reserved(&self) -> u32 {
        self.reserved
    }

    /// Noise events counted since the last summary.
    #[must_use]
    pub fn suppressed_noise(&self) -> u64 {
        self.suppressed_noise
    }

    /// Gating reservations refused since the last summary.
    #[must_use]
    pub fn refused_gating(&self) -> u64 {
        self.refused_gating
    }

    /// Lost outcome records counted since the last summary
    /// ([`SendWindow::count_unrecorded_outcome`]).
    #[must_use]
    pub fn unrecorded_outcomes(&self) -> u64 {
        self.unrecorded_outcomes
    }

    /// The last acknowledgement received.
    #[must_use]
    pub fn last_ack(&self) -> Option<Ack> {
        self.last_ack
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> WindowConfig {
        self.config
    }
}
