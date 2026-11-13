//! OID → ATTRTYP: the `MakeAttid` procedure over the default prefix table
//! `NewPrefixTable()`, both as [MS-DRSR] 5.16.4 defines them, with the OID's
//! binary form ("contents octets") as ITU-T X.690 8.19 defines it.
//!
//! Spec: [MS-DRSR] v20260309 5.16.4 (PrefixTable, prefix of an OID,
//! `ToBinaryOID`, `MakeAttid`, `NewPrefixTable`); ITU-T X.690 (02/2021) 8.19.2
//! - 8.19.5; docs/46 §3.3 (R46-3).
//!
//! Deviation from [MS-DRSR] 5.16.4, by decision (docs/46 R46-3): an OID whose
//! prefix is not in `NewPrefixTable()` is **refused**
//! ([`OidError::PrefixNotInTable`]). `MakeAttid` would instead call
//! `AddPrefixTableEntry`, which gives the new prefix a *random* index — not a
//! stable identifier. No random entry is ever added here (fail closed).

/// Longest OID string accepted, in bytes. A project bound on input work
/// (docs/32 §8 style); every phase-1 OID is far shorter. Project choice.
pub const MAX_OID_LEN: usize = 256;

/// Why an OID could not be mapped to an ATTRTYP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OidError {
    /// Not an OID in dotted-decimal form: empty or longer than
    /// [`MAX_OID_LEN`], an empty arc, a non-digit, a leading zero, an arc
    /// above `u32::MAX`, fewer than two arcs, or a first / second arc outside
    /// what X.690 8.19.4 can pack (first arc 0..=2; second arc 0..=39 when
    /// the first is 0 or 1).
    Malformed,
    /// The OID's prefix is not in `NewPrefixTable()`. Spec: docs/46 R46-3.
    PrefixNotInTable,
}

/// One tuple of a prefix table. Spec: [MS-DRSR] 5.16.4 ("type PrefixTable =
/// sequence of [ prefixString: unicodestring, prefixIndex: integer ]").
struct PrefixTableEntry {
    /// The prefix of an OID, in binary form.
    prefix_string: &'static [u8],
    /// Its prefix index, in `[0 .. 0x0000ffff]`.
    prefix_index: u16,
}

/// The tuples `NewPrefixTable()` inserts — all 19, in the printed order.
/// Spec: [MS-DRSR] v20260309 5.16.4, procedure NewPrefixTable(), table
/// "prefixString / Length of prefixString / prefixIndex".
const NEW_PREFIX_TABLE: [PrefixTableEntry; 19] = [
    // Spec: [MS-DRSR] 5.16.4 — "\x55\x4", length 2, index 0.
    PrefixTableEntry {
        prefix_string: &[0x55, 0x04],
        prefix_index: 0,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x55\x6", length 2, index 1.
    PrefixTableEntry {
        prefix_string: &[0x55, 0x06],
        prefix_index: 1,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x2A\x86\x48\x86\xF7\x14\x01\x02", 8, 2.
    PrefixTableEntry {
        prefix_string: &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x02],
        prefix_index: 2,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x2A\x86\x48\x86\xF7\x14\x01\x03", 8, 3.
    PrefixTableEntry {
        prefix_string: &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x03],
        prefix_index: 3,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x60\x86\x48\x01\x65\x02\x02\x01", 8, 4.
    PrefixTableEntry {
        prefix_string: &[0x60, 0x86, 0x48, 0x01, 0x65, 0x02, 0x02, 0x01],
        prefix_index: 4,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x60\x86\x48\x01\x65\x02\x02\x03", 8, 5.
    PrefixTableEntry {
        prefix_string: &[0x60, 0x86, 0x48, 0x01, 0x65, 0x02, 0x02, 0x03],
        prefix_index: 5,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x60\x86\x48\x01\x65\x02\x01\x05", 8, 6.
    PrefixTableEntry {
        prefix_string: &[0x60, 0x86, 0x48, 0x01, 0x65, 0x02, 0x01, 0x05],
        prefix_index: 6,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x60\x86\x48\x01\x65\x02\x01\x04", 8, 7.
    PrefixTableEntry {
        prefix_string: &[0x60, 0x86, 0x48, 0x01, 0x65, 0x02, 0x01, 0x04],
        prefix_index: 7,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x55\x5", length 2, index 8.
    PrefixTableEntry {
        prefix_string: &[0x55, 0x05],
        prefix_index: 8,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x2A\x86\x48\x86\xF7\x14\x01\x04", 8, 9.
    PrefixTableEntry {
        prefix_string: &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x04],
        prefix_index: 9,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x2A\x86\x48\x86\xF7\x14\x01\x05", 8, 10.
    PrefixTableEntry {
        prefix_string: &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x05],
        prefix_index: 10,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x09\x92\x26\x89\x93\xF2\x2C\x64", 8, 19.
    PrefixTableEntry {
        prefix_string: &[0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64],
        prefix_index: 19,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x60\x86\x48\x01\x86\xF8\x42\x03", 8, 20.
    PrefixTableEntry {
        prefix_string: &[0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x03],
        prefix_index: 20,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x09\x92\x26\x89\x93\xF2\x2C\x64\x01", 9,
    // 21.
    PrefixTableEntry {
        prefix_string: &[0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01],
        prefix_index: 21,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x60\x86\x48\x01\x86\xF8\x42\x03\x01", 9,
    // 22.
    PrefixTableEntry {
        prefix_string: &[0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x03, 0x01],
        prefix_index: 22,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x2A\x86\x48\x86\xF7\x14\x01\x05\xB6\x58",
    // 10, 23.
    PrefixTableEntry {
        prefix_string: &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x05, 0xB6, 0x58],
        prefix_index: 23,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x55\x15", length 2, index 24.
    PrefixTableEntry {
        prefix_string: &[0x55, 0x15],
        prefix_index: 24,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x55\x12", length 2, index 25.
    PrefixTableEntry {
        prefix_string: &[0x55, 0x12],
        prefix_index: 25,
    },
    // Spec: [MS-DRSR] 5.16.4 — "\x55\x14", length 2, index 26.
    PrefixTableEntry {
        prefix_string: &[0x55, 0x14],
        prefix_index: 26,
    },
];

/// The arcs ("object identifier components") of a dotted-decimal OID
/// string, strictly parsed and bounded (see [`OidError::Malformed`]).
///
/// The dotted form is the "original form" of [MS-DRSR] 5.16.4 (e.g.
/// "2.5.6.2"). Leading zeros and arcs above `u32::MAX` are refused: a
/// project choice for one canonical spelling and bounded arithmetic (the
/// spec sets no limit). The first-two-arc limits follow X.690 8.19.4 and its
/// NOTE ("only three values are allocated from the root node, and at most 39
/// subsequent values from nodes reached by X = 0 and X = 1").
fn parse_arcs(oid: &str) -> Result<Vec<u32>, OidError> {
    if oid.is_empty() || oid.len() > MAX_OID_LEN {
        return Err(OidError::Malformed);
    }
    let mut arcs = Vec::new();
    for part in oid.split('.') {
        let digits_only = !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
        if !digits_only || (part.len() > 1 && part.starts_with('0')) {
            return Err(OidError::Malformed);
        }
        arcs.push(part.parse::<u32>().map_err(|_| OidError::Malformed)?);
    }
    match arcs.as_slice() {
        [first, second, ..] if *first <= 2 && (*first == 2 || *second <= 39) => Ok(arcs),
        _ => Err(OidError::Malformed),
    }
}

/// Append one subidentifier: base-128 digits, most significant first, bit 8
/// set on every octet but the last, in the fewest possible octets.
/// Spec: X.690 8.19.2.
fn push_subidentifier(out: &mut Vec<u8>, value: u64) {
    // 7-bit groups, least significant first.
    let mut groups = Vec::with_capacity(10);
    let mut rest = value;
    loop {
        // Masked to 7 bits, so the narrowing is exact.
        groups.push((rest & 0x7F) as u8);
        rest >>= 7;
        if rest == 0 {
            break;
        }
    }
    // The least significant group (index 0) is the last octet: bit 8 clear.
    for (i, group) in groups.iter().enumerate().rev() {
        out.push(if i == 0 { *group } else { *group | 0x80 });
    }
}

/// `ToBinaryOID`: the BER contents octets of an OID given by its arcs (at
/// least two, checked by [`parse_arcs`]). Spec: [MS-DRSR] 5.16.4
/// ("ToBinaryOID ... as described in [ITUX690] section 8.19"); X.690 8.19.3
/// (N = components − 1), 8.19.4 (first subidentifier = X*40 + Y), 8.19.5.
fn to_binary_oid(arcs: &[u32]) -> Result<Vec<u8>, OidError> {
    let [first, second, rest @ ..] = arcs else {
        return Err(OidError::Malformed);
    };
    let mut out = Vec::new();
    // Spec: X.690 8.19.4 — "(X*40) + Y" (computed in u64: no overflow).
    push_subidentifier(&mut out, u64::from(*first) * 40 + u64::from(*second));
    // Spec: X.690 8.19.5.
    for arc in rest {
        push_subidentifier(&mut out, u64::from(*arc));
    }
    Ok(out)
}

/// `MakeAttid(NewPrefixTable(), o)`: the ATTRTYP of the OID `o`, refusing an
/// OID whose prefix is not in the default table (docs/46 R46-3).
///
/// Follows the procedure of [MS-DRSR] 5.16.4 step by step:
/// `lastValue` = the arc after the last '.'; `binaryOID = ToBinaryOid(o)`;
/// the prefix is `binaryOID` without its last byte if `lastValue < 128`,
/// else without its last two bytes; `upperWord` = the prefix index of that
/// prefix; `lowerWord = lastValue mod 16384`, plus 32768 if
/// `lastValue ≥ 16384`; result `upperWord * 65536 + lowerWord`.
///
/// Consequence of following the procedure literally: when
/// `lastValue ≥ 16384` the last arc takes three or more octets, so the
/// two-byte cut leaves part of it in the prefix. Such a prefix ends in an
/// octet with bit 8 set, and no `NewPrefixTable()` prefix does, so the OID
/// is refused as [`OidError::PrefixNotInTable`]. The same holds for a
/// two-arc OID, whose last arc is packed into the first subidentifier. No
/// phase-1 OID is affected (docs/46 §4.2, §5.2).
///
/// Spec: [MS-DRSR] v20260309 5.16.4 (MakeAttid, NewPrefixTable); X.690
/// 8.19; docs/46 §3.3 (R46-3).
pub fn make_attid(oid: &str) -> Result<u32, OidError> {
    let arcs = parse_arcs(oid)?;
    // lastValue := ToInteger(the string after the last '.').
    let last_value = *arcs.last().ok_or(OidError::Malformed)?;
    let binary = to_binary_oid(&arcs)?;
    // "if lastValue < 128 then oidPrefix := SubBinary(binaryOID, 0,
    // binaryOID.length - 2) else SubBinary(binaryOID, 0, binaryOID.length -
    // 3)" — SubBinary is inclusive, so one or two trailing bytes are cut.
    let cut = if last_value < 128 { 1 } else { 2 };
    let prefix = binary
        .len()
        .checked_sub(cut)
        .and_then(|n| binary.get(..n))
        .ok_or(OidError::PrefixNotInTable)?;
    // Search the prefix in the table; never add one (R46-3).
    let entry = NEW_PREFIX_TABLE
        .iter()
        .find(|e| e.prefix_string == prefix)
        .ok_or(OidError::PrefixNotInTable)?;
    // "lowerWord := lastValue mod 16384; if lastValue ≥ 16384 then
    // lowerWord := lowerWord + 32768".
    let mut lower_word = last_value % 16384;
    if last_value >= 16384 {
        lower_word += 32768;
    }
    // "attr := upperWord * 65536 + lowerWord".
    Ok((u32::from(entry.prefix_index) << 16) | lower_word)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Source: ITU-T X.690 (02/2021) 8.19.5 EXAMPLE — {2 999 3} has the
    // first subidentifier 1079 and the contents octets 88 37 03.
    #[test]
    fn x690_example_contents_octets() {
        let arcs = parse_arcs("2.999.3").unwrap();
        assert_eq!(to_binary_oid(&arcs).unwrap(), [0x88, 0x37, 0x03]);
    }

    // Source: [MS-DRSR] 5.16.4 — the printed "Binary:" line of each example
    // (e.g. 2.5.4.6 → \x55\x04\x06; 0.9.2342.19200300.100.1.1 →
    // \x09\x92\x26\x89\x93\xF2\x2C\x64\x01\x01;
    // 1.2.840.113556.1.5.7000.53 → ...\x05\xB6\x58\x35).
    #[test]
    fn drsr_example_binary_forms() {
        let cases: [(&str, &[u8]); 4] = [
            ("2.5.4.6", &[0x55, 0x04, 0x06]),
            (
                "1.2.840.113556.1.2.1",
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x02, 0x01],
            ),
            (
                "0.9.2342.19200300.100.1.1",
                &[0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01],
            ),
            (
                "1.2.840.113556.1.5.7000.53",
                &[
                    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x05, 0xB6, 0x58, 0x35,
                ],
            ),
        ];
        for (oid, binary) in cases {
            assert_eq!(to_binary_oid(&parse_arcs(oid).unwrap()).unwrap(), binary);
        }
    }

    // Source: [MS-DRSR] 5.16.4 — the table has 19 tuples; "each prefixString
    // MUST occur at most once in the table, and each prefixIndex MUST occur
    // at most once in the table".
    #[test]
    fn new_prefix_table_is_one_to_one() {
        assert_eq!(NEW_PREFIX_TABLE.len(), 19);
        for (i, a) in NEW_PREFIX_TABLE.iter().enumerate() {
            for b in NEW_PREFIX_TABLE.iter().skip(i + 1) {
                assert_ne!(a.prefix_string, b.prefix_string);
                assert_ne!(a.prefix_index, b.prefix_index);
            }
        }
    }
}
