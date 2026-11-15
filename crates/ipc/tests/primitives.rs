//! Field primitives: round trips, the exact canonical octets, and rejection of
//! every non-canonical or over-bound encoding.
//!
//! Source: docs/50 §3.3 (primitives row: "`u8/u16/u32/u64` fixed width
//! big-endian; `bool` = `00`/`01` only; `Option<T>` = `00` | `01 T`;
//! `bytes<max>` = `u32` length ≤ max + bytes; `seq<T,max>` = `u32` count ≤ max +
//! items; enum = `u8` from a closed table" — "a single encoding per value";
//! no-trailing-byte row; Kerberos values as `bytes<max>` holding DER), R50-4,
//! and docs/CLEAN-ROOM.md (recursion-depth limits) for the nesting bound.

use ipc::{
    decode_payload, encode_payload, DerBlob, Error, FrameLimit, Reader, Secret, Writer, MAX_NESTING,
};

const LIMIT: FrameLimit = match FrameLimit::new(4096) {
    Some(limit) => limit,
    None => panic!("valid"),
};

/// Encode with one closure on a fresh writer.
fn encode(write: impl FnOnce(&mut Writer) -> ipc::Result<()>) -> ipc::Result<Vec<u8>> {
    let mut writer = Writer::new(LIMIT);
    write(&mut writer)?;
    Ok(writer.into_payload().to_vec())
}

/// Decode with one closure, then require the end of input.
fn decode<'a, T>(
    octets: &'a [u8],
    read: impl FnOnce(&mut Reader<'a>) -> ipc::Result<T>,
) -> ipc::Result<T> {
    let mut reader = Reader::new(octets);
    let value = read(&mut reader)?;
    reader.finish()?;
    Ok(value)
}

// ---- unsigned integers ------------------------------------------------------

#[test]
fn unsigned_integers_are_fixed_width_big_endian() {
    assert_eq!(encode(|w| w.write_u8(0xAB)), Ok(vec![0xAB]));
    assert_eq!(encode(|w| w.write_u16(0x1234)), Ok(vec![0x12, 0x34]));
    assert_eq!(
        encode(|w| w.write_u32(0x0102_0304)),
        Ok(vec![0x01, 0x02, 0x03, 0x04])
    );
    assert_eq!(
        encode(|w| w.write_u64(0x0102_0304_0506_0708)),
        Ok(vec![1, 2, 3, 4, 5, 6, 7, 8])
    );
    // Zero keeps its full width (no minimal form).
    assert_eq!(encode(|w| w.write_u32(0)), Ok(vec![0, 0, 0, 0]));
}

#[test]
fn unsigned_integers_round_trip_at_the_edges() {
    for value in [0u8, 1, 0x7F, 0x80, u8::MAX] {
        let octets = encode(|w| w.write_u8(value)).unwrap();
        assert_eq!(decode(&octets, |r| r.read_u8()), Ok(value));
    }
    for value in [0u16, 1, 0x00FF, 0xFF00, u16::MAX] {
        let octets = encode(|w| w.write_u16(value)).unwrap();
        assert_eq!(decode(&octets, |r| r.read_u16()), Ok(value));
    }
    for value in [0u32, 1, 0x00FF_FF00, u32::MAX] {
        let octets = encode(|w| w.write_u32(value)).unwrap();
        assert_eq!(decode(&octets, |r| r.read_u32()), Ok(value));
    }
    for value in [0u64, 1, 0x00FF_0000_0000_FF00, u64::MAX] {
        let octets = encode(|w| w.write_u64(value)).unwrap();
        assert_eq!(decode(&octets, |r| r.read_u64()), Ok(value));
    }
}

#[test]
fn short_integers_are_truncated() {
    assert_eq!(decode(&[], |r| r.read_u8()), Err(Error::Truncated));
    assert_eq!(decode(&[0x12], |r| r.read_u16()), Err(Error::Truncated));
    assert_eq!(decode(&[1, 2, 3], |r| r.read_u32()), Err(Error::Truncated));
    assert_eq!(
        decode(&[1, 2, 3, 4, 5, 6, 7], |r| r.read_u64()),
        Err(Error::Truncated)
    );
}

// ---- fixed-length octets ----------------------------------------------------

#[test]
fn fixed_arrays_have_no_prefix() {
    let handle = [0x5Au8; 16];
    let octets = encode(|w| w.write_array(&handle)).unwrap();
    assert_eq!(octets, handle.to_vec());
    assert_eq!(decode(&octets, |r| r.read_array::<16>()), Ok(handle));
    assert_eq!(
        decode(&octets[..15], |r| r.read_array::<16>()),
        Err(Error::Truncated)
    );
}

// ---- booleans ---------------------------------------------------------------

#[test]
fn booleans_are_00_or_01() {
    assert_eq!(encode(|w| w.write_bool(false)), Ok(vec![0x00]));
    assert_eq!(encode(|w| w.write_bool(true)), Ok(vec![0x01]));
    assert_eq!(decode(&[0x00], |r| r.read_bool()), Ok(false));
    assert_eq!(decode(&[0x01], |r| r.read_bool()), Ok(true));
}

#[test]
fn every_other_boolean_octet_is_rejected() {
    for octet in 0x02..=0xFF {
        assert_eq!(
            decode(&[octet], |r| r.read_bool()),
            Err(Error::InvalidBoolean),
            "octet {octet:#04x}"
        );
    }
    assert_eq!(decode(&[], |r| r.read_bool()), Err(Error::Truncated));
}

// ---- byte strings -----------------------------------------------------------

#[test]
fn byte_strings_are_u32_length_then_octets() {
    assert_eq!(
        encode(|w| w.write_bytes(b"ab", 4)),
        Ok(vec![0, 0, 0, 2, b'a', b'b'])
    );
    assert_eq!(encode(|w| w.write_bytes(b"", 0)), Ok(vec![0, 0, 0, 0]));
    assert_eq!(
        decode(&[0, 0, 0, 2, b'a', b'b'], |r| r.read_bytes(4)),
        Ok(&b"ab"[..])
    );
    // Exactly at the bound is accepted.
    assert_eq!(
        decode(&[0, 0, 0, 4, 1, 2, 3, 4], |r| r.read_bytes(4)),
        Ok(&[1u8, 2, 3, 4][..])
    );
}

#[test]
fn byte_string_length_over_the_bound_is_rejected() {
    // Declared 5 with a bound of 4: refused from the length alone, whether or
    // not the octets are present.
    assert_eq!(
        decode(&[0, 0, 0, 5, 1, 2, 3, 4, 5], |r| r.read_bytes(4)),
        Err(Error::LengthOverBound)
    );
    assert_eq!(
        decode(&[0, 0, 0, 5], |r| r.read_bytes(4)),
        Err(Error::LengthOverBound)
    );
    // A huge declared length allocates nothing and is refused.
    assert_eq!(
        decode(&[0xFF, 0xFF, 0xFF, 0xFF], |r| r.read_bytes(1024)),
        Err(Error::LengthOverBound)
    );
}

#[test]
fn byte_string_shorter_than_declared_is_truncated() {
    assert_eq!(
        decode(&[0, 0, 0, 3, 1, 2], |r| r.read_bytes(8)),
        Err(Error::Truncated)
    );
    assert_eq!(
        decode(&[0, 0, 0], |r| r.read_bytes(8)),
        Err(Error::Truncated)
    );
}

#[test]
fn writer_refuses_a_byte_string_over_its_bound() {
    assert_eq!(
        encode(|w| w.write_bytes(b"abcde", 4)),
        Err(Error::LengthOverBound)
    );
    // Nothing was written by the refused field.
    let mut writer = Writer::new(LIMIT);
    assert_eq!(writer.write_bytes(b"abcde", 4), Err(Error::LengthOverBound));
    assert_eq!(writer.body_len(), 0);
}

// ---- DER blobs and secrets (byte strings with their own types) ------------

#[test]
fn der_blob_travels_as_an_opaque_byte_string() {
    // The octets are not interpreted: even a non-DER value passes through,
    // for krb-proto to judge (docs/50 §3.3).
    let blob = DerBlob::from_slice(&[0x30, 0x00]);
    let octets = encode(|w| w.write_der(&blob, 16)).unwrap();
    assert_eq!(octets, vec![0, 0, 0, 2, 0x30, 0x00]);
    assert_eq!(decode(&octets, |r| r.read_der(16)), Ok(blob));
    let not_der = DerBlob::from_slice(&[0xFF, 0xFF, 0xFF]);
    let octets = encode(|w| w.write_der(&not_der, 16)).unwrap();
    assert_eq!(decode(&octets, |r| r.read_der(16)), Ok(not_der));
    assert_eq!(
        decode(&octets, |r| r.read_der(2)),
        Err(Error::LengthOverBound)
    );
}

#[test]
fn secret_travels_as_a_byte_string() {
    let secret = Secret::from_slice(b"pw");
    let octets = encode(|w| w.write_secret(&secret, 8)).unwrap();
    assert_eq!(octets, vec![0, 0, 0, 2, b'p', b'w']);
    let read = decode(&octets, |r| r.read_secret(8)).unwrap();
    assert_eq!(read.expose(), b"pw");
    assert_eq!(
        decode(&octets, |r| r.read_secret(1)).map(|s| s.len()),
        Err(Error::LengthOverBound)
    );
    assert_eq!(
        encode(|w| w.write_secret(&secret, 1)),
        Err(Error::LengthOverBound)
    );
}

// ---- optional fields --------------------------------------------------------

#[test]
fn optional_is_00_or_01_then_value() {
    assert_eq!(
        encode(|w| w.write_option(None::<&u16>, |w, v| w.write_u16(*v))),
        Ok(vec![0x00])
    );
    assert_eq!(
        encode(|w| w.write_option(Some(&0x1234u16), |w, v| w.write_u16(*v))),
        Ok(vec![0x01, 0x12, 0x34])
    );
    assert_eq!(
        decode(&[0x00], |r| r.read_option(|r| r.read_u16())),
        Ok(None)
    );
    assert_eq!(
        decode(&[0x01, 0x12, 0x34], |r| r.read_option(|r| r.read_u16())),
        Ok(Some(0x1234))
    );
}

#[test]
fn every_other_option_marker_is_rejected() {
    for marker in 0x02..=0xFF {
        assert_eq!(
            decode(&[marker, 0x12, 0x34], |r| r.read_option(|r| r.read_u16())),
            Err(Error::InvalidOptionMarker),
            "marker {marker:#04x}"
        );
    }
    // Present marker without its value.
    assert_eq!(
        decode(&[0x01, 0x12], |r| r.read_option(|r| r.read_u16())),
        Err(Error::Truncated)
    );
    // Absent marker followed by a value is a trailing octet, not a value.
    assert_eq!(
        decode(&[0x00, 0x12, 0x34], |r| r.read_option(|r| r.read_u16())),
        Err(Error::TrailingBytes)
    );
}

// ---- sequences --------------------------------------------------------------

#[test]
fn sequences_are_u32_count_then_items() {
    let items = [0x0102u16, 0x0304];
    let octets = encode(|w| w.write_seq(&items, 2, |w, v| w.write_u16(*v))).unwrap();
    assert_eq!(octets, vec![0, 0, 0, 2, 0x01, 0x02, 0x03, 0x04]);
    assert_eq!(
        decode(&octets, |r| r.read_seq(2, |r| r.read_u16())),
        Ok(items.to_vec())
    );
    let empty: [u16; 0] = [];
    let octets = encode(|w| w.write_seq(&empty, 0, |w, v| w.write_u16(*v))).unwrap();
    assert_eq!(octets, vec![0, 0, 0, 0]);
    assert_eq!(
        decode(&octets, |r| r.read_seq(0, |r| r.read_u16())),
        Ok(Vec::new())
    );
}

#[test]
fn sequence_count_over_the_bound_is_rejected() {
    assert_eq!(
        decode(&[0, 0, 0, 3, 0, 1, 0, 2, 0, 3], |r| r
            .read_seq(2, |r| r.read_u16())),
        Err(Error::CountOverBound)
    );
    // A huge count is refused from the count alone (nothing reserved).
    assert_eq!(
        decode(&[0xFF, 0xFF, 0xFF, 0xFF], |r| r
            .read_seq(16, |r| r.read_u8())),
        Err(Error::CountOverBound)
    );
    let items = [1u8, 2, 3];
    assert_eq!(
        encode(|w| w.write_seq(&items, 2, |w, v| w.write_u8(*v))),
        Err(Error::CountOverBound)
    );
}

#[test]
fn sequence_with_fewer_items_than_its_count_is_truncated() {
    assert_eq!(
        decode(&[0, 0, 0, 3, 0, 1, 0, 2], |r| r
            .read_seq(4, |r| r.read_u16())),
        Err(Error::Truncated)
    );
}

#[test]
fn sequence_items_are_checked_with_their_own_rules() {
    // A sequence of booleans holding a 0x02.
    assert_eq!(
        decode(&[0, 0, 0, 2, 0x01, 0x02], |r| r
            .read_seq(4, |r| r.read_bool())),
        Err(Error::InvalidBoolean)
    );
}

// ---- enumerations -----------------------------------------------------------

fn colour(code: u8) -> Option<&'static str> {
    match code {
        1 => Some("red"),
        2 => Some("green"),
        _ => None,
    }
}

#[test]
fn enumerations_are_one_octet_from_a_closed_table() {
    assert_eq!(encode(|w| w.write_enum(2)), Ok(vec![0x02]));
    assert_eq!(decode(&[0x01], |r| r.read_enum(colour)), Ok("red"));
    assert_eq!(decode(&[0x02], |r| r.read_enum(colour)), Ok("green"));
    for code in [0x00, 0x03, 0x80, 0xFF] {
        assert_eq!(
            decode(&[code], |r| r.read_enum(colour)),
            Err(Error::UnknownCode)
        );
    }
}

// ---- end of payload ---------------------------------------------------------

#[test]
fn trailing_octets_are_rejected() {
    assert_eq!(
        decode(&[0x01, 0x00], |r| r.read_bool()),
        Err(Error::TrailingBytes)
    );
    assert_eq!(
        decode(&[0, 0, 0, 1, 0xAA, 0xBB], |r| r.read_bytes(8)),
        Err(Error::TrailingBytes)
    );
    let reader = Reader::new(&[0x00]);
    assert_eq!(reader.remaining(), 1);
    assert_eq!(reader.finish(), Err(Error::TrailingBytes));
    assert_eq!(Reader::new(&[]).finish(), Ok(()));
}

// ---- nesting ----------------------------------------------------------------

/// `depth` optional fields nested inside one another around a `u8`.
fn write_nested(writer: &mut Writer, depth: usize) -> ipc::Result<()> {
    if depth == 0 {
        writer.write_u8(0x2A)
    } else {
        writer.write_option(Some(&()), |w, ()| write_nested(w, depth - 1))
    }
}

fn read_nested(reader: &mut Reader<'_>, depth: usize) -> ipc::Result<u8> {
    if depth == 0 {
        reader.read_u8()
    } else {
        reader
            .read_option(|r| read_nested(r, depth - 1))?
            .ok_or(Error::Truncated)
    }
}

#[test]
fn nesting_up_to_the_limit_round_trips() {
    let octets = encode(|w| write_nested(w, MAX_NESTING)).unwrap();
    assert_eq!(octets.len(), MAX_NESTING + 1);
    assert_eq!(decode(&octets, |r| read_nested(r, MAX_NESTING)), Ok(0x2A));
}

#[test]
fn nesting_past_the_limit_is_refused_both_ways() {
    let deeper = MAX_NESTING + 1;
    assert_eq!(
        encode(|w| write_nested(w, deeper)),
        Err(Error::NestingTooDeep)
    );
    // Hand-built: deeper present-markers then the value.
    let mut octets = vec![0x01; deeper];
    octets.push(0x2A);
    assert_eq!(
        decode(&octets, |r| read_nested(r, deeper)),
        Err(Error::NestingTooDeep)
    );
}

// ---- body bound -------------------------------------------------------------

#[test]
fn writer_refuses_to_pass_the_body_bound() {
    let small = FrameLimit::new(6).unwrap();
    let mut writer = Writer::new(small);
    assert_eq!(writer.write_u32(1), Ok(()));
    assert_eq!(writer.write_u16(2), Ok(()));
    assert_eq!(writer.write_u8(3), Err(Error::BodyOverBound));
    assert_eq!(writer.body_len(), 6);
    // A byte string that would cross the bound writes neither its length nor
    // its octets.
    let mut writer = Writer::new(small);
    assert_eq!(writer.write_bytes(b"abc", 8), Err(Error::BodyOverBound));
    assert_eq!(writer.body_len(), 0);
}

#[test]
fn writer_grows_across_many_fields() {
    // Many small writes force several growth steps; the result is exact.
    let mut writer = Writer::new(LIMIT);
    for value in 0..1000u32 {
        writer.write_u32(value).unwrap();
    }
    let octets = writer.into_payload();
    assert_eq!(octets.len(), 4000);
    let mut reader = Reader::new(&octets);
    for value in 0..1000u32 {
        assert_eq!(reader.read_u32(), Ok(value));
    }
    assert_eq!(reader.finish(), Ok(()));
}

// ---- standalone payload helpers ----------------------------------------------

#[test]
fn standalone_payload_helpers_round_trip() {
    let encoded = encode_payload(&ipc::Refused::Busy, LIMIT).unwrap();
    assert_eq!(encoded.as_slice(), &[0x02]);
    assert_eq!(
        decode_payload::<ipc::Refused>(&encoded),
        Ok(ipc::Refused::Busy)
    );
    assert_eq!(
        decode_payload::<ipc::Refused>(&[0x02, 0x00]),
        Err(Error::TrailingBytes)
    );
}
