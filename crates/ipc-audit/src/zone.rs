//! The `ZoneSerial` shape (task DN10b): dird's serial-only zone write — the
//! advance of the zone's SOA SERIAL without a content write, through the
//! one write checker (crates/directory-admin `ZoneSerialWriter`;
//! docs/questions/Q-1002, decision A-172).
//!
//! # Why its own shape (docs/questions/Q-1013 item 3)
//!
//! The write changes exactly one value — the SERIAL — for one of two
//! reasons ([`ZoneSerialCause`]). `DirAdmin` has a field for neither: its
//! events record a requester's operation on directory objects (target,
//! names, PDP decision, operation digest), and a serial advance has no
//! requester, no object and no PDP decision. This shape records only what
//! the write is: dird's number for it, the cause, the SERIAL it advances
//! past, and — in the outcome — the new SERIAL (docs/54 §9 already names
//! "the new SERIAL" among a DNS write's audit fields). It is **not** the
//! `Dns` shape of docs/54 §9 (TKEY / UPDATE, Q-962 — waiting for DN8 and
//! Q-619 item 3), whose fields this shape does not pre-empt.
//!
//! # Who sends it
//!
//! dird only — the one writer (A-85: every shape is accepted only from its
//! sender; crates/audit-daemon `binding`). Like every dird state change it
//! is gating: the `Decision` event is acknowledged by auditd **before** the
//! write commits, the `Outcome` event follows the commit (docs/51 §5.7 item
//! 2; docs/52 §3.11 R6).
//!
//! # Encoding
//!
//! ```text
//! ZoneSerial := time ‖ operation_id:u64 ‖ cause:u8 ‖ from:u32 ‖ stage
//! stage      := 1 Decision | 2 Outcome ‖ outcome
//! outcome    := 1 Advanced ‖ serial:u32 | 2 NotNeeded | 3 Failed ‖ failure:u8
//! ```
//!
//! A SERIAL is never 0 (RFC 2136 §7.11): `from` and `serial` are
//! [`NonZeroU32`], and a 0 on the wire is refused
//! ([`EventError::InvalidSerial`]) — one encoding per value, each value
//! meaningful (docs/50 §3.3). No field can hold an address, a name or any
//! directory value (docs/37 §2).
//!
//! Spec: RFC 2136 §3.6, §7.10, §7.11; docs/54 §5.4, §9; docs/50 §3.3, §8.1;
//! docs/51 §5.7 item 2; A-57; A-85; docs/questions/Q-1002 (A-172), Q-1013.
//!
//! Written only from, opened in this session: AGENT-ONBOARDING, AGENTS,
//! docs/54 (§3.1, §4.4–§4.8, §5, §9, §10), docs/50 §8, docs/questions
//! Q-962, Q-991..Q-994, Q-1000..Q-1004, PENDING-OWNER (A-85, A-119, A-160,
//! A-163, A-167, A-170, A-172), the pinned RFC 2136 §3.6, §7.10, §7.11
//! (SHA-256 verified against tools/spec-pin/manifest.json) and this crate's
//! own codec. No other implementation was consulted or recalled (AGENTS.md
//! §1-3).

use core::num::NonZeroU32;

use crate::codes::{ZoneSerialCause, ZoneSerialFailure, ZoneSerialOutcomeCode, ZoneSerialPhase};
use crate::error::EventError;
use crate::values::CalendarTime;
use ipc::{Reader, Writer};

/// What a `ZoneSerial` outcome says.
/// Spec: module documentation; docs/questions/Q-1013.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZoneSerialOutcome {
    /// The write committed: the zone's new SOA SERIAL.
    Advanced {
        /// The SERIAL after the write (never 0 — RFC 2136 §7.11).
        serial: NonZeroU32,
    },
    /// The counter moved after the decision (another write advanced it):
    /// the advance was not needed and nothing was written (RFC 2136 §7.10:
    /// serial numbers are conserved).
    NotNeeded,
    /// Nothing was written.
    Failed(ZoneSerialFailure),
}

/// The phase of a `ZoneSerial` event and, for an outcome, its result. A
/// decision has no result of its own: dird records one only when it
/// proceeds (a serial advance it cannot decide is not attempted).
/// Spec: docs/51 §5.7 item 2; module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZoneSerialStage {
    /// Before the write; acknowledged by auditd before it commits.
    Decision,
    /// After the commit (or its failure).
    Outcome(ZoneSerialOutcome),
}

/// One `ZoneSerial` event (module documentation).
/// Spec: docs/questions/Q-1013; RFC 2136 §3.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSerialEvent {
    /// dird's clock when it recorded the event.
    pub time: CalendarTime,
    /// dird's number for the write: its `Decision` and `Outcome` events
    /// carry the same number, drawn from dird's one counter of operation
    /// numbers (shared with its `DirAdmin` events — never equal).
    pub operation_id: u64,
    /// Why the serial is advanced.
    pub cause: ZoneSerialCause,
    /// The zone's SERIAL when the advance was decided — the SERIAL it
    /// advances past.
    pub from: NonZeroU32,
    /// Decision or outcome.
    pub stage: ZoneSerialStage,
}

/// A SERIAL field: `u32`, never 0.
/// Spec: RFC 2136 §7.11; docs/50 §3.3.
fn read_serial(reader: &mut Reader<'_>) -> Result<NonZeroU32, EventError> {
    NonZeroU32::new(reader.read_u32()?).ok_or(EventError::InvalidSerial)
}

impl ZoneSerialEvent {
    /// The fields in declaration order (module documentation, "Encoding").
    /// Spec: docs/50 §3.3 (positional fields, one encoding per value).
    pub(crate) fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        self.time.write(writer)?;
        writer.write_u64(self.operation_id)?;
        writer.write_enum(self.cause.code())?;
        writer.write_u32(self.from.get())?;
        match self.stage {
            ZoneSerialStage::Decision => writer.write_enum(ZoneSerialPhase::Decision.code())?,
            ZoneSerialStage::Outcome(outcome) => {
                writer.write_enum(ZoneSerialPhase::Outcome.code())?;
                match outcome {
                    ZoneSerialOutcome::Advanced { serial } => {
                        writer.write_enum(ZoneSerialOutcomeCode::Advanced.code())?;
                        writer.write_u32(serial.get())?;
                    }
                    ZoneSerialOutcome::NotNeeded => {
                        writer.write_enum(ZoneSerialOutcomeCode::NotNeeded.code())?;
                    }
                    ZoneSerialOutcome::Failed(failure) => {
                        writer.write_enum(ZoneSerialOutcomeCode::Failed.code())?;
                        writer.write_enum(failure.code())?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Spec: this type's layout; docs/50 §3.3 (strict; closed tables; the
    /// caller refuses trailing octets); RFC 2136 §7.11 (no SERIAL 0).
    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<ZoneSerialEvent, EventError> {
        let time = CalendarTime::read(reader)?;
        let operation_id = reader.read_u64()?;
        let cause = reader.read_enum(ZoneSerialCause::from_code)?;
        let from = read_serial(reader)?;
        let stage = match reader.read_enum(ZoneSerialPhase::from_code)? {
            ZoneSerialPhase::Decision => ZoneSerialStage::Decision,
            ZoneSerialPhase::Outcome => ZoneSerialStage::Outcome(
                match reader.read_enum(ZoneSerialOutcomeCode::from_code)? {
                    ZoneSerialOutcomeCode::Advanced => ZoneSerialOutcome::Advanced {
                        serial: read_serial(reader)?,
                    },
                    ZoneSerialOutcomeCode::NotNeeded => ZoneSerialOutcome::NotNeeded,
                    ZoneSerialOutcomeCode::Failed => {
                        ZoneSerialOutcome::Failed(reader.read_enum(ZoneSerialFailure::from_code)?)
                    }
                },
            ),
        };
        Ok(ZoneSerialEvent {
            time,
            operation_id,
            cause,
            from,
            stage,
        })
    }
}
