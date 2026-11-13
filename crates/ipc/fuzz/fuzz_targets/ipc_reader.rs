#![no_main]
//! Fuzz target for the IPC field decoder: `ipc::Reader` through
//! `ipc::decode_body`.
//!
//! AGENTS.md §6 / docs/50 §9 (R50-19): arbitrary bytes → decoder; never a
//! panic, bounded allocation. Three parts:
//!
//! 1. The input is a frame body of a fuzz-local message set whose two kinds
//!    use every field primitive (fixed-width integers, boolean, fixed array,
//!    enumeration, DER blob, secret, optional, bounded sequence, nested
//!    optional-of-sequence). Whatever decodes must re-encode to exactly the
//!    input (docs/50 §3.3: "a single encoding per value"; "round-trip: every
//!    decoder checks `encode(decode(b)) == b`").
//! 2. The same input as a reply body through `ipc::decode_reply`: the
//!    reserved `REFUSED_KIND` must decode only as the shared `Refused`, and
//!    every accepted reply — refusals included — must re-encode to exactly
//!    the input (A-59).
//! 3. The input drives a short program of raw `Reader` calls with
//!    input-chosen bounds, in input-chosen order, to reach every primitive
//!    from every position.
//!
//! The message set below is a fuzz-only definition, not a real channel.
//!
//! Spec: docs/50 §3.3; R50-4; A-59.

use ipc::{
    decode_reply, reply_round_trip_is_canonical, round_trip_is_canonical, Channel, DerBlob,
    Direction, Error, FrameLimit, MessageSet, Payload, Reader, Reply, Result, Secret, Writer,
    REFUSED_KIND,
};
use libfuzzer_sys::fuzz_target;

const LIMIT: FrameLimit = match FrameLimit::new(4096) {
    Some(limit) => limit,
    None => panic!("valid frame limit"),
};
const CHANNEL: Channel = Channel::new(0xF022, 1, LIMIT, LIMIT);

const KIND_FIXED: u8 = 0x01;
const KIND_VARIABLE: u8 = 0x02;

/// Every fixed-width primitive.
struct Fixed {
    a: u8,
    b: u16,
    c: u32,
    d: u64,
    flag: bool,
    handle: [u8; 16],
    code: u8,
}

fn code_from(code: u8) -> Option<u8> {
    (1..=3).contains(&code).then_some(code)
}

impl Payload for Fixed {
    fn write_fields(&self, w: &mut Writer) -> Result<()> {
        w.write_u8(self.a)?;
        w.write_u16(self.b)?;
        w.write_u32(self.c)?;
        w.write_u64(self.d)?;
        w.write_bool(self.flag)?;
        w.write_array(&self.handle)?;
        w.write_enum(self.code)
    }

    fn read_fields(r: &mut Reader<'_>) -> Result<Fixed> {
        let a = r.read_u8()?;
        let b = r.read_u16()?;
        let c = r.read_u32()?;
        let d = r.read_u64()?;
        let flag = r.read_bool()?;
        let handle = r.read_array()?;
        let code = r.read_enum(code_from)?;
        Ok(Fixed {
            a,
            b,
            c,
            d,
            flag,
            handle,
            code,
        })
    }
}

/// Every variable-length primitive.
struct Variable {
    blob: DerBlob,
    secret: Secret,
    optional: Option<u32>,
    names: Vec<Vec<u8>>,
    nested: Option<Vec<Option<bool>>>,
}

impl Payload for Variable {
    fn write_fields(&self, w: &mut Writer) -> Result<()> {
        w.write_der(&self.blob, 64)?;
        w.write_secret(&self.secret, 32)?;
        w.write_option(self.optional.as_ref(), |w, v| w.write_u32(*v))?;
        w.write_seq(&self.names, 4, |w, name| w.write_bytes(name, 8))?;
        w.write_option(self.nested.as_ref(), |w, items| {
            w.write_seq(items, 3, |w, item| {
                w.write_option(item.as_ref(), |w, flag| w.write_bool(*flag))
            })
        })
    }

    fn read_fields(r: &mut Reader<'_>) -> Result<Variable> {
        let blob = r.read_der(64)?;
        let secret = r.read_secret(32)?;
        let optional = r.read_option(|r| r.read_u32())?;
        let names = r.read_seq(4, |r| r.read_bytes(8).map(<[u8]>::to_vec))?;
        let nested = r.read_option(|r| r.read_seq(3, |r| r.read_option(|r| r.read_bool())))?;
        Ok(Variable {
            blob,
            secret,
            optional,
            names,
            nested,
        })
    }
}

enum Fuzzed {
    Fixed(Fixed),
    Variable(Variable),
}

impl MessageSet for Fuzzed {
    const KINDS: &'static [u8] = &[KIND_FIXED, KIND_VARIABLE];

    fn kind(&self) -> u8 {
        match self {
            Fuzzed::Fixed(_) => KIND_FIXED,
            Fuzzed::Variable(_) => KIND_VARIABLE,
        }
    }

    fn write_payload(&self, w: &mut Writer) -> Result<()> {
        match self {
            Fuzzed::Fixed(m) => m.write_fields(w),
            Fuzzed::Variable(m) => m.write_fields(w),
        }
    }

    fn read_payload(kind: u8, r: &mut Reader<'_>) -> Result<Fuzzed> {
        match kind {
            KIND_FIXED => Fixed::read_fields(r).map(Fuzzed::Fixed),
            KIND_VARIABLE => Variable::read_fields(r).map(Fuzzed::Variable),
            _ => Err(Error::UnknownKind),
        }
    }
}

/// Part 2: a program of raw reads. Each op octet picks a primitive (low
/// nibble) and a bound (high nibble).
fn run_program(ops: &[u8], input: &[u8]) {
    let mut reader = Reader::new(input);
    for &op in ops {
        let bound = u32::from(op >> 4) * 3;
        let before = reader.remaining();
        let step = match op & 0x0F {
            0 => reader.read_u8().map(drop),
            1 => reader.read_u16().map(drop),
            2 => reader.read_u32().map(drop),
            3 => reader.read_u64().map(drop),
            4 => reader.read_bool().map(drop),
            5 => reader.read_array::<16>().map(drop),
            6 => reader.read_bytes(bound).map(|b| assert!(b.len() <= bound as usize)),
            7 => reader.read_der(bound).map(|b| assert!(b.len() <= bound as usize)),
            8 => reader.read_secret(bound).map(|s| assert!(s.len() <= bound as usize)),
            9 => reader.read_option(|r| r.read_u16()).map(drop),
            10 => reader
                .read_seq(bound, |r| r.read_u8())
                .map(|v| assert!(v.len() <= bound as usize)),
            11 => reader.read_enum(code_from).map(drop),
            12 => reader
                .read_option(|r| r.read_seq(bound, |r| r.read_option(|r| r.read_bool())))
                .map(drop),
            _ => reader.read_u32().map(drop),
        };
        if step.is_err() {
            return;
        }
        assert!(reader.remaining() <= before, "reads only move forward");
    }
    let _ = reader.finish();
}

fuzz_target!(|data: &[u8]| {
    // Part 1: canonical round trip of whatever decodes.
    if let Ok(canonical) = round_trip_is_canonical::<Fuzzed>(CHANNEL, Direction::Request, data) {
        assert!(canonical, "a decoded body re-encodes to the same octets");
    }

    // Part 2: the input as a reply body; the reserved kind is never the set's.
    if let Ok(reply) = decode_reply::<Fuzzed>(CHANNEL, data) {
        let kind = data.get(3).copied();
        match reply {
            Reply::Refused(_) => assert_eq!(kind, Some(REFUSED_KIND)),
            Reply::Message(_) => assert_ne!(kind, Some(REFUSED_KIND)),
        }
        assert_eq!(
            reply_round_trip_is_canonical::<Fuzzed>(CHANNEL, data),
            Ok(true),
            "a decoded reply re-encodes to the same octets"
        );
    }

    // Part 3: raw reads, the first octet giving the program length.
    if let Some((&count, rest)) = data.split_first() {
        let count = usize::from(count & 0x0F).min(rest.len());
        let (ops, input) = rest.split_at(count);
        run_program(ops, input);
    }
});
