//! Domain names: the value type and the compression-aware decoder.
//!
//! # The value
//!
//! A [`Name`] holds a domain name in its uncompressed wire form — a sequence
//! of labels, each a length octet followed by that many octets, ending with
//! the zero length octet of the root (RFC 1035 §3.1; RFC 1034 §3.1). Every
//! constructor enforces the bounds (label ≤ 63 octets, name ≤ 255 octets), so
//! a `Name` is always encodable. Case is preserved as received (RFC 1035
//! §2.3.3); equality and hashing are case-insensitive for ASCII letters and
//! exact for every other octet (RFC 1035 §3.1: "Name servers and resolvers must
//! compare labels in a case-insensitive manner (i.e., A=a), assuming ASCII
//! with zero parity. Non-alphabetic codes must match exactly").
//!
//! # Compression (RFC 1035 §4.1.4) — one hop per name, by construction
//!
//! A name in a message is a sequence of labels ending either in a zero octet
//! or in a pointer, and the pointer refers to "a prior occurance of the same
//! name". The decoder takes that literally: it records every position at
//! which a name it has already decoded has an occurrence — the start of each
//! label, the position of its pointer, the position of its terminating zero
//! octet — together with the (already fully decoded, already bounded) suffix
//! that begins there. A pointer is accepted only if its OFFSET is strictly
//! less than its own position (docs/54 §6.3) **and** is one of those recorded
//! positions; the suffix is then copied, and the name is complete.
//!
//! Consequences, all by construction rather than by counting:
//!
//! * one pointer hop per name — chains of pointers are resolved by lookup,
//!   never by walking, so no hop counter exists or is needed;
//! * no pointer loop — a name's own positions are recorded only after it is
//!   complete, so a name can never point into itself, and every target is a
//!   name that already terminated;
//! * no pointer into the header, into the middle of a label, or into an
//!   integer field — none of those positions is ever recorded.
//!
//! Names inside RDATA the codec does not model are not decoded, so they are
//! not valid targets (docs/questions/Q-640 records this choice).

use crate::error::{Error, Result};
use crate::limits::{MAX_LABEL_OCTETS, MAX_NAME_OCTETS};
use core::fmt;
use core::hash::{Hash, Hasher};

/// A domain name in uncompressed wire form, bounded and case-preserving.
///
/// Spec: RFC 1035 §3.1, §2.3.3, §2.3.4; RFC 1034 §3.1.
#[derive(Clone)]
pub struct Name {
    /// Length-prefixed labels ending in the zero octet of the root label.
    /// Invariant: every label is 1..=63 octets, the whole is ≤ 255 octets, and
    /// the only zero length octet is the last octet.
    wire: Vec<u8>,
}

impl Name {
    /// The root name: a single zero length octet. Spec: RFC 1035 §3.1.
    pub fn root() -> Name {
        Name { wire: vec![0] }
    }

    /// Builds a name from its labels, most specific first, without the root
    /// label. An empty iterator gives the root.
    ///
    /// Spec: RFC 1035 §3.1 (labels 1..=63 octets of any value, total ≤ 255
    /// octets including length octets); RFC 1034 §3.1 (the null label is
    /// reserved for the root).
    pub fn from_labels<I, L>(labels: I) -> Result<Name>
    where
        I: IntoIterator<Item = L>,
        L: AsRef<[u8]>,
    {
        let mut wire = Vec::new();
        for label in labels {
            let label = label.as_ref();
            if label.is_empty() {
                return Err(Error::EmptyLabel);
            }
            if label.len() > MAX_LABEL_OCTETS {
                return Err(Error::LabelTooLong);
            }
            // The +1 at the end keeps room for the root's zero octet.
            if wire.len() + 1 + label.len() + 1 > MAX_NAME_OCTETS {
                return Err(Error::NameTooLong);
            }
            wire.push(label.len() as u8);
            wire.extend_from_slice(label);
        }
        wire.push(0);
        Ok(Name { wire })
    }

    /// Builds a name from its printed form: labels separated by ".", with an
    /// optional trailing "." (an absolute name); "." alone is the root.
    ///
    /// There is no escape syntax: every character between two dots is a label
    /// octet. Names whose labels contain a "." octet are built with
    /// [`Name::from_labels`].
    ///
    /// Spec: RFC 1034 §3.1 (labels "separated by dots"; "a complete domain name
    /// ends with the root label, this leads to a printed form which ends in a
    /// dot").
    pub fn from_dotted(text: &str) -> Result<Name> {
        if text == "." {
            return Ok(Name::root());
        }
        let body = text.strip_suffix('.').unwrap_or(text);
        if body.is_empty() {
            return Err(Error::EmptyLabel);
        }
        Name::from_labels(body.split('.').map(str::as_bytes))
    }

    /// Decodes exactly one uncompressed name occupying all of `wire` — for
    /// names carried outside a DNS message (no message, so no pointer target
    /// can exist).
    ///
    /// Spec: RFC 1035 §3.1; §4.1.4 (pointers are offsets into a message);
    /// docs/50 §3.3 (no trailing octet).
    pub fn decode_uncompressed(wire: &[u8]) -> Result<Name> {
        let mut out = Vec::new();
        let mut at = 0usize;
        loop {
            let octet = *wire.get(at).ok_or(Error::Truncated)?;
            match octet & 0xC0 {
                0x00 => {
                    let len = usize::from(octet);
                    if len == 0 {
                        out.push(0);
                        at += 1;
                        break;
                    }
                    let label = wire.get(at + 1..at + 1 + len).ok_or(Error::Truncated)?;
                    if out.len() + 1 + len + 1 > MAX_NAME_OCTETS {
                        return Err(Error::NameTooLong);
                    }
                    out.push(octet);
                    out.extend_from_slice(label);
                    at += 1 + len;
                }
                0xC0 => return Err(Error::CompressionNotAllowed),
                _ => return Err(Error::ReservedLabelType),
            }
        }
        if at != wire.len() {
            return Err(Error::TrailingData);
        }
        Ok(Name { wire: out })
    }

    /// The uncompressed wire form (length-prefixed labels and the zero octet
    /// of the root), case as received. Spec: RFC 1035 §3.1.
    pub fn as_wire(&self) -> &[u8] {
        &self.wire
    }

    /// Octets of the uncompressed wire form (1..=255). Spec: RFC 1035 §3.1.
    pub fn wire_len(&self) -> usize {
        self.wire.len()
    }

    /// The labels, most specific first, without the root label.
    pub fn labels(&self) -> Labels<'_> {
        Labels { rest: &self.wire }
    }

    /// Number of labels, without the root label (0..=127).
    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// Whether this is the root name.
    pub fn is_root(&self) -> bool {
        self.wire.len() == 1
    }

    /// Whether this name is at or below `domain`: its labels end with all of
    /// `domain`'s labels (compared case-insensitively). A name is at or below
    /// itself, and every name is at or below the root.
    ///
    /// Spec: RFC 1034 §3.1 ("A domain is identified by a domain name, and
    /// consists of that part of the domain name space that is at or below the
    /// domain name"; the relationship "can be tested by seeing if the
    /// subdomain's name ends with the containing domain's name"); RFC 2136 §1.2.
    pub fn is_subdomain_of(&self, domain: &Name) -> bool {
        let want = domain.wire.len();
        let mut at = 0usize;
        loop {
            let rest = &self.wire[at..];
            if rest.len() == want {
                return rest.eq_ignore_ascii_case(&domain.wire);
            }
            if rest.len() < want {
                return false;
            }
            // `rest` starts at a label boundary and is longer than the root.
            at += 1 + usize::from(rest[0]);
        }
    }
}

/// Iterator over the labels of a [`Name`] (root label excluded).
#[derive(Debug, Clone)]
pub struct Labels<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let (&len, tail) = self.rest.split_first()?;
        if len == 0 {
            return None;
        }
        let len = usize::from(len);
        let label = tail.get(..len)?;
        self.rest = tail.get(len..)?;
        Some(label)
    }
}

impl PartialEq for Name {
    /// Case-insensitive for ASCII letters, exact for every other octet. Length
    /// octets (≤ 0x3F) are never letters, so the label structure must match
    /// exactly. Spec: RFC 1035 §3.1, §2.3.3.
    fn eq(&self, other: &Name) -> bool {
        self.wire.eq_ignore_ascii_case(&other.wire)
    }
}

impl Eq for Name {}

impl Hash for Name {
    /// Consistent with [`PartialEq`]: hashes the ASCII-lowercased wire form.
    fn hash<H: Hasher>(&self, state: &mut H) {
        for octet in &self.wire {
            state.write_u8(octet.to_ascii_lowercase());
        }
    }
}

impl fmt::Debug for Name {
    /// The printed form (RFC 1034 §3.1), with every octet outside printable
    /// ASCII — and "." and "\" inside a label — shown as `\xHH`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Name(\"")?;
        if self.is_root() {
            f.write_str(".")?;
        }
        for label in self.labels() {
            for &octet in label {
                if (0x21..=0x7E).contains(&octet) && octet != b'.' && octet != b'\\' {
                    write!(f, "{}", octet as char)?;
                } else {
                    write!(f, "\\x{octet:02x}")?;
                }
            }
            f.write_str(".")?;
        }
        f.write_str("\")")
    }
}

// ---- decoding inside a message ------------------------------------------------

/// One recorded occurrence of an already-decoded name suffix: the message
/// offset where it occurs, and the suffix's range in the arena.
#[derive(Debug, Clone, Copy)]
struct Occurrence {
    offset: usize,
    start: usize,
    end: usize,
}

/// The positions of every name decoded so far in one message, each with the
/// fully decoded suffix that begins there (see the module documentation).
///
/// Offsets are pushed in strictly increasing order because a message is
/// decoded strictly front to back, so lookup is a binary search. Under a
/// profile that forbids compression everywhere nothing can be a target, so
/// nothing is recorded.
#[derive(Debug)]
pub(crate) struct NameTable {
    recording: bool,
    occurrences: Vec<Occurrence>,
    arena: Vec<u8>,
}

impl NameTable {
    pub(crate) fn new(compression: Compression) -> NameTable {
        NameTable {
            recording: compression == Compression::Allowed,
            occurrences: Vec::new(),
            arena: Vec::new(),
        }
    }

    /// The decoded suffix occurring at `offset`, if a decoded name has an
    /// occurrence there. Spec: RFC 1035 §4.1.4.
    fn suffix_at(&self, offset: usize) -> Option<&[u8]> {
        let index = self
            .occurrences
            .binary_search_by_key(&offset, |o| o.offset)
            .ok()?;
        let occurrence = self.occurrences[index];
        self.arena.get(occurrence.start..occurrence.end)
    }

    /// Records a completed name: `positions` pairs each message offset of an
    /// occurrence with the index in `wire` where its suffix begins.
    fn commit(&mut self, wire: &[u8], positions: &[(usize, usize)]) {
        if !self.recording {
            return;
        }
        let base = self.arena.len();
        self.arena.extend_from_slice(wire);
        let end = self.arena.len();
        for &(offset, at) in positions {
            debug_assert!(self.occurrences.last().is_none_or(|o| o.offset < offset));
            self.occurrences.push(Occurrence {
                offset,
                start: base + at,
                end,
            });
        }
    }
}

/// Whether compression pointers may appear in the name being decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Compression {
    /// Owner names, QNAME/ZNAME, and the RDATA names of NS and SOA.
    /// Spec: RFC 1035 §3.3 ("all domain names in the RDATA section of these
    /// RRs may be compressed"), §4.1.4.
    Allowed,
    /// SRV Target (RFC 2782), TSIG Algorithm Name (RFC 8945 §4.2), and every
    /// name under the canonical profile (docs/54 §6.3).
    Forbidden,
}

/// Decodes the name starting at `start` in `message`, reading no octet at or
/// beyond `limit` (the end of the message, or of the enclosing RDATA).
/// Returns the name and the offset just after its encoding in the message.
///
/// Spec: RFC 1035 §3.1, §4.1.4; docs/54 §6.2, §6.3.
pub(crate) fn decode_name(
    message: &[u8],
    start: usize,
    limit: usize,
    compression: Compression,
    table: &mut NameTable,
) -> Result<(Name, usize)> {
    let limit = limit.min(message.len());
    let mut wire: Vec<u8> = Vec::new();
    // At most one entry per label, plus the terminator or the pointer.
    let mut positions: Vec<(usize, usize)> = Vec::new();
    let mut at = start;
    let next = loop {
        if at >= limit {
            return Err(Error::Truncated);
        }
        let octet = message[at];
        match octet & 0xC0 {
            0x00 => {
                let len = usize::from(octet);
                positions.push((at, wire.len()));
                if len == 0 {
                    wire.push(0);
                    break at + 1;
                }
                let end = at + 1 + len;
                if end > limit {
                    return Err(Error::Truncated);
                }
                if wire.len() + 1 + len + 1 > MAX_NAME_OCTETS {
                    return Err(Error::NameTooLong);
                }
                wire.extend_from_slice(&message[at..end]);
                at = end;
            }
            0xC0 => {
                if compression == Compression::Forbidden {
                    return Err(Error::CompressionNotAllowed);
                }
                if at + 2 > limit {
                    return Err(Error::Truncated);
                }
                let target = (usize::from(octet & 0x3F) << 8) | usize::from(message[at + 1]);
                if target >= at {
                    return Err(Error::PointerNotBackward);
                }
                let suffix = table.suffix_at(target).ok_or(Error::PointerTarget)?;
                if wire.len() + suffix.len() > MAX_NAME_OCTETS {
                    return Err(Error::NameTooLong);
                }
                positions.push((at, wire.len()));
                wire.extend_from_slice(suffix);
                break at + 2;
            }
            _ => return Err(Error::ReservedLabelType),
        }
    };
    table.commit(&wire, &positions);
    Ok((Name { wire }, next))
}
