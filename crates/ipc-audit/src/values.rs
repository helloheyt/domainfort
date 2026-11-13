//! The value types the event shapes are built from, and their canonical
//! field encodings.
//!
//! Every type here can hold only what docs/37 §2 allows in the log —
//! identifiers and metadata — and only within a fixed bound, so the largest
//! event of every shape fits [`crate::MAX_EVENT_OCTETS`] and encoding an
//! event built from these types cannot fail on size. A client-supplied
//! string is kept only when it is printable ASCII of at most
//! [`MAX_TEXT_OCTETS`] octets; otherwise a fixed marker is kept (docs/50
//! §8.2; docs/49 §10.1; docs/07 §8 "no free-text concatenation").
//!
//! The field encodings use the `ipc` primitives with their one valid
//! encoding each (docs/50 §3.3): an optional value is the `bool` marker
//! `00`/`01` followed by the value, a sequence is a `u32` count within its
//! bound followed by the items — the same octets as `ipc`'s
//! `Option<T>` / `seq<T,max>`.
//!
//! Spec: docs/50 §3.3, §8.1, §8.2; docs/37 §2; docs/49 §10.1.

use crate::error::EventError;
use ipc::{Reader, Writer};

/// Longest client-supplied string kept: 256 octets of printable ASCII.
/// Spec: docs/50 §8.2 ("only if printable ASCII ≤ 256 bytes, otherwise a
/// fixed marker"); docs/49 §10.1.
pub const MAX_TEXT_OCTETS: usize = 256;

/// [`MAX_TEXT_OCTETS`] as a wire bound.
const MAX_TEXT_WIRE: u32 = 256;

/// Most name components a [`Principal`] keeps; a name with more is
/// withheld. Project choice (bounds the event size; docs/questions/Q-252
/// item 5).
pub const MAX_NAME_COMPONENTS: usize = 4;

/// Most sub-authorities in a SID. Spec: crates/dtyp `SID_MAX_SUB_AUTHORITIES`
/// ([MS-DTYP] 2.4.2).
pub const MAX_SID_SUB_AUTHORITIES: usize = 15;

/// A client-supplied (or otherwise free-form) string, kept only when safe to
/// log.
///
/// Spec: docs/50 §8.2; docs/49 §10.1; docs/07 §8.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditText(Option<String>);

impl AuditText {
    /// The fixed marker: the string was not printable ASCII or was too long.
    pub const WITHHELD: AuditText = AuditText(None);

    /// Keep `text` if it is printable ASCII (0x20..=0x7E) of at most
    /// [`MAX_TEXT_OCTETS`] octets; otherwise the marker.
    /// Spec: docs/50 §8.2; docs/49 §10.1.
    #[must_use]
    pub fn from_client(text: &str) -> AuditText {
        if is_printable(text.as_bytes()) {
            AuditText(Some(text.to_owned()))
        } else {
            AuditText::WITHHELD
        }
    }

    /// The kept text, or `None` for the marker.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        self.0.as_deref()
    }

    /// Whether this is the marker.
    #[must_use]
    pub fn is_withheld(&self) -> bool {
        self.0.is_none()
    }

    pub(crate) fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        write_opt(writer, self.0.as_ref(), |text, w| {
            Ok(w.write_bytes(text.as_bytes(), MAX_TEXT_WIRE)?)
        })
    }

    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<AuditText, EventError> {
        let text = read_opt(reader, |r| {
            let octets = r.read_bytes(MAX_TEXT_WIRE)?;
            if !is_printable(octets) {
                return Err(EventError::InvalidText);
            }
            // Printable ASCII is valid UTF-8.
            core::str::from_utf8(octets)
                .map(str::to_owned)
                .map_err(|_| EventError::InvalidText)
        })?;
        Ok(AuditText(text))
    }
}

/// Printable ASCII of at most [`MAX_TEXT_OCTETS`] octets.
fn is_printable(octets: &[u8]) -> bool {
    octets.len() <= MAX_TEXT_OCTETS && octets.iter().all(|b| (0x20..=0x7E).contains(b))
}

/// A UTC calendar time with whole seconds — the fields of the sources'
/// `KerberosTime` (the time the caller handed the library; auditd's own
/// clock is in the log record).
///
/// Decoding checks each field's range (year ≤ 9999, month 1-12, day 1-31,
/// hour ≤ 23, minute ≤ 59, second ≤ 59); the day is not checked against the
/// month (docs/questions/Q-252 item 6).
///
/// Spec: RFC 4120 5.2.3 (as cited by crates/krb-proto `KerberosTime`);
/// crates/kdc, keyd, ldap audit (`time` / `ts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CalendarTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl CalendarTime {
    /// 1970-01-01 00:00:00 — used only as an unreachable fallback.
    pub const EPOCH: CalendarTime = CalendarTime {
        year: 1970,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    };

    /// A time from its fields, or `None` if one is out of range.
    #[must_use]
    pub const fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Option<CalendarTime> {
        let valid = year <= 9999
            && month >= 1
            && month <= 12
            && day >= 1
            && day <= 31
            && hour <= 23
            && minute <= 59
            && second <= 59;
        if valid {
            Some(CalendarTime {
                year,
                month,
                day,
                hour,
                minute,
                second,
            })
        } else {
            None
        }
    }

    /// Year (0-9999).
    #[must_use]
    pub const fn year(self) -> u16 {
        self.year
    }
    /// Month (1-12).
    #[must_use]
    pub const fn month(self) -> u8 {
        self.month
    }
    /// Day of the month (1-31).
    #[must_use]
    pub const fn day(self) -> u8 {
        self.day
    }
    /// Hour (0-23).
    #[must_use]
    pub const fn hour(self) -> u8 {
        self.hour
    }
    /// Minute (0-59).
    #[must_use]
    pub const fn minute(self) -> u8 {
        self.minute
    }
    /// Second (0-59).
    #[must_use]
    pub const fn second(self) -> u8 {
        self.second
    }

    pub(crate) fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_u16(self.year)?;
        writer.write_u8(self.month)?;
        writer.write_u8(self.day)?;
        writer.write_u8(self.hour)?;
        writer.write_u8(self.minute)?;
        writer.write_u8(self.second)?;
        Ok(())
    }

    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<CalendarTime, EventError> {
        let year = reader.read_u16()?;
        let month = reader.read_u8()?;
        let day = reader.read_u8()?;
        let hour = reader.read_u8()?;
        let minute = reader.read_u8()?;
        let second = reader.read_u8()?;
        CalendarTime::new(year, month, day, hour, minute, second).ok_or(EventError::InvalidTime)
    }
}

/// A Kerberos principal as recorded: realm, name-type and name components,
/// each kept by the [`AuditText`] rule; a name of more than
/// [`MAX_NAME_COMPONENTS`] components is withheld as a whole.
///
/// Spec: crates/kdc `NamedPrincipal` (RFC 4120 5.2.2 as cited there);
/// docs/48 §2.4 (the armor principal "is not secret"); docs/50 §8.2.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Principal {
    realm: AuditText,
    name_type: i32,
    components: Option<Vec<AuditText>>,
}

impl Principal {
    /// A principal; `components` beyond [`MAX_NAME_COMPONENTS`] withhold the
    /// whole name.
    #[must_use]
    pub fn new(realm: AuditText, name_type: i32, components: Vec<AuditText>) -> Principal {
        let components = (components.len() <= MAX_NAME_COMPONENTS).then_some(components);
        Principal {
            realm,
            name_type,
            components,
        }
    }

    /// The realm.
    #[must_use]
    pub fn realm(&self) -> &AuditText {
        &self.realm
    }

    /// The name-type (RFC 4120 5.2.2).
    #[must_use]
    pub fn name_type(&self) -> i32 {
        self.name_type
    }

    /// The name components, or `None` if the name was withheld.
    #[must_use]
    pub fn components(&self) -> Option<&[AuditText]> {
        self.components.as_deref()
    }

    pub(crate) fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        self.realm.write(writer)?;
        writer.write_u32(u32::from_be_bytes(self.name_type.to_be_bytes()))?;
        write_opt(writer, self.components.as_ref(), |components, w| {
            write_seq(w, components, MAX_NAME_COMPONENTS, AuditText::write)
        })
    }

    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Principal, EventError> {
        let realm = AuditText::read(reader)?;
        let name_type = i32::from_be_bytes(reader.read_u32()?.to_be_bytes());
        let components = read_opt(reader, |r| {
            read_seq(r, MAX_NAME_COMPONENTS, AuditText::read)
        })?;
        Ok(Principal {
            realm,
            name_type,
            components,
        })
    }
}

/// A security identifier: the 6-octet identifier authority and up to
/// [`MAX_SID_SUB_AUTHORITIES`] sub-authorities.
///
/// Spec: crates/dtyp `Sid` ([MS-DTYP] 2.4.2 as cited there); docs/49 §10.1
/// (`principal: Option<Sid>`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SidValue {
    authority: [u8; 6],
    sub_authorities: Vec<u32>,
}

impl SidValue {
    /// A SID, or `None` with more than [`MAX_SID_SUB_AUTHORITIES`]
    /// sub-authorities.
    #[must_use]
    pub fn new(authority: [u8; 6], sub_authorities: Vec<u32>) -> Option<SidValue> {
        (sub_authorities.len() <= MAX_SID_SUB_AUTHORITIES).then_some(SidValue {
            authority,
            sub_authorities,
        })
    }

    /// A SID keeping at most [`MAX_SID_SUB_AUTHORITIES`] sub-authorities
    /// (more cannot occur from a `dtyp::Sid`).
    #[cfg(feature = "ldap")]
    pub(crate) fn clamped(authority: [u8; 6], sub_authorities: &[u32]) -> SidValue {
        let kept = sub_authorities.len().min(MAX_SID_SUB_AUTHORITIES);
        SidValue {
            authority,
            sub_authorities: sub_authorities.get(..kept).unwrap_or_default().to_vec(),
        }
    }

    /// The identifier authority.
    #[must_use]
    pub fn authority(&self) -> [u8; 6] {
        self.authority
    }

    /// The sub-authorities.
    #[must_use]
    pub fn sub_authorities(&self) -> &[u32] {
        &self.sub_authorities
    }

    pub(crate) fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_array(&self.authority)?;
        write_seq(
            writer,
            &self.sub_authorities,
            MAX_SID_SUB_AUTHORITIES,
            |value, w| Ok(w.write_u32(*value)?),
        )
    }

    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<SidValue, EventError> {
        let authority = reader.read_array::<6>()?;
        let sub_authorities = read_seq(reader, MAX_SID_SUB_AUTHORITIES, |r| Ok(r.read_u32()?))?;
        Ok(SidValue {
            authority,
            sub_authorities,
        })
    }
}

/// The PDP's internal reason: the code, and the rule id for `CoarseDeny`.
///
/// Spec: crates/pdp `ReasonCode`, `RuleId` (docs/11 §1b, §3, §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PdpReason {
    /// The reason code.
    pub code: crate::PdpReasonCode,
    /// The global rule's id (set for `CoarseDeny`).
    pub rule: Option<u32>,
}

impl PdpReason {
    pub(crate) fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_enum(self.code.code())?;
        write_opt(
            writer,
            self.rule.as_ref(),
            |rule, w| Ok(w.write_u32(*rule)?),
        )
    }

    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<PdpReason, EventError> {
        let code = reader.read_enum(crate::PdpReasonCode::from_code)?;
        let rule = read_opt(reader, |r| Ok(r.read_u32()?))?;
        Ok(PdpReason { code, rule })
    }
}

/// The LDAP codec error behind a `Malformed` reason, and its limit for
/// `LimitExceeded`.
///
/// Spec: crates/parse-ldap `Error`, `Limit` (docs/49 §2.3, §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodecError {
    /// The rule that failed.
    pub error: crate::CodecErrorCode,
    /// The bound, for `LimitExceeded`.
    pub limit: Option<crate::CodecLimit>,
}

impl CodecError {
    pub(crate) fn write(&self, writer: &mut Writer) -> Result<(), EventError> {
        writer.write_enum(self.error.code())?;
        write_opt(writer, self.limit.as_ref(), |limit, w| {
            Ok(w.write_enum(limit.code())?)
        })
    }

    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<CodecError, EventError> {
        let error = reader.read_enum(crate::CodecErrorCode::from_code)?;
        let limit = read_opt(reader, |r| Ok(r.read_enum(crate::CodecLimit::from_code)?))?;
        Ok(CodecError { error, limit })
    }
}

/// A sequence of at most `MAX` items. The bound is part of the type, so an
/// event built from it always encodes (docs/50 §3.3: "`seq<T,max>`"), and
/// decoding checks the count against `MAX` before reading any item.
///
/// Spec: docs/50 §3.3; AGENTS.md §6 (no unbounded allocation from a decoded
/// count).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedSeq<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> BoundedSeq<T, MAX> {
    /// No items.
    #[must_use]
    pub const fn empty() -> Self {
        BoundedSeq(Vec::new())
    }

    /// `items`, or `None` with more than `MAX` of them.
    #[must_use]
    pub fn new(items: Vec<T>) -> Option<Self> {
        (items.len() <= MAX).then_some(BoundedSeq(items))
    }

    /// The items.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Number of items (at most `MAX`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there is no item.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `u32` count, then the items (`seq<T, MAX>`).
    pub(crate) fn write(
        &self,
        writer: &mut Writer,
        write_item: impl FnMut(&T, &mut Writer) -> Result<(), EventError>,
    ) -> Result<(), EventError> {
        write_seq(writer, &self.0, MAX, write_item)
    }

    /// Read a sequence written by [`BoundedSeq::write`].
    pub(crate) fn read<'a>(
        reader: &mut Reader<'a>,
        read_item: impl FnMut(&mut Reader<'a>) -> Result<T, EventError>,
    ) -> Result<Self, EventError> {
        read_seq(reader, MAX, read_item).map(BoundedSeq)
    }
}

impl<T, const MAX: usize> Default for BoundedSeq<T, MAX> {
    fn default() -> Self {
        Self::empty()
    }
}

// ---- field helpers ----------------------------------------------------------

/// An optional field: the `bool` marker then the value — the octets of
/// `ipc`'s `Option<T>` (docs/50 §3.3: "`Option<T>` = `00` | `01 T`").
pub(crate) fn write_opt<T>(
    writer: &mut Writer,
    value: Option<&T>,
    write_value: impl FnOnce(&T, &mut Writer) -> Result<(), EventError>,
) -> Result<(), EventError> {
    writer.write_bool(value.is_some())?;
    match value {
        Some(value) => write_value(value, writer),
        None => Ok(()),
    }
}

/// Read an optional field written by [`write_opt`]. A marker other than
/// `00`/`01` is refused (by `read_bool`).
pub(crate) fn read_opt<'a, T>(
    reader: &mut Reader<'a>,
    read_value: impl FnOnce(&mut Reader<'a>) -> Result<T, EventError>,
) -> Result<Option<T>, EventError> {
    if reader.read_bool()? {
        read_value(reader).map(Some)
    } else {
        Ok(None)
    }
}

/// A sequence: a `u32` count of at most `max`, then the items — the octets
/// of `ipc`'s `seq<T,max>` (docs/50 §3.3).
pub(crate) fn write_seq<T>(
    writer: &mut Writer,
    items: &[T],
    max: usize,
    mut write_item: impl FnMut(&T, &mut Writer) -> Result<(), EventError>,
) -> Result<(), EventError> {
    if items.len() > max {
        return Err(EventError::Codec(ipc::Error::CountOverBound));
    }
    let count = u32::try_from(items.len()).map_err(|_| ipc::Error::CountOverBound)?;
    writer.write_u32(count)?;
    for item in items {
        write_item(item, writer)?;
    }
    Ok(())
}

/// Read a sequence written by [`write_seq`]. The count is checked against
/// `max` before any item is read; the vector grows only as items decode.
pub(crate) fn read_seq<'a, T>(
    reader: &mut Reader<'a>,
    max: usize,
    mut read_item: impl FnMut(&mut Reader<'a>) -> Result<T, EventError>,
) -> Result<Vec<T>, EventError> {
    let count = usize::try_from(reader.read_u32()?).unwrap_or(usize::MAX);
    if count > max {
        return Err(EventError::Codec(ipc::Error::CountOverBound));
    }
    let mut items = Vec::new();
    for _ in 0..count {
        items.push(read_item(reader)?);
    }
    Ok(items)
}
