//! The envelope: magic, exact version, closed kind table, body bound, and the
//! shared `Refused` reply.
//!
//! Source: docs/50 §3.3 (body := magic:u16 ‖ version:u8 ‖ kind:u8 ‖ payload;
//! "`magic` per channel: mismatch ⇒ close"; "exact version: `version` ≠ current
//! ⇒ reply `Refused{VersionMismatch}` + close; no negotiation and no fallback";
//! "`kind` closed: unknown op ⇒ close"; trailing octets ⇒ "`Malformed` +
//! close"; errors row "`Busy`, `Unavailable`"), §3.6, §3.7, §10 (shared
//! `Refused`), R50-4; docs/questions/Q-225 items 2 and 3; A-59 (one reply
//! kind, `REFUSED_KIND = 0xFF`, reserved on every channel and enforced in
//! ipc).

mod common;

use common::{
    raw_frame, SampleReply, SampleRequest, KIND_ACK, KIND_DONE, KIND_LOOKUP, KIND_STORE, SAMPLE,
};
use ipc::{
    decode_body, decode_message, decode_reply, decode_reply_message, encode_frame, encode_refused,
    encode_reply, kinds_exclude_refused, reply_round_trip_is_canonical, Channel, Direction, Error,
    FrameLimit, MessageSet, Payload, Reader, Refused, Reply, Result, Writer, MIN_BODY_LIMIT,
    REFUSED_KIND,
};
use std::sync::atomic::{AtomicUsize, Ordering};

const ALL_REFUSED: [Refused; 4] = [
    Refused::VersionMismatch,
    Refused::Busy,
    Refused::Unavailable,
    Refused::Malformed,
];

fn lookup_payload() -> Vec<u8> {
    let mut payload = vec![0x22; 16];
    payload.push(0x01);
    payload.push(0x00);
    payload
}

fn body_of(frame: &[u8]) -> &[u8] {
    &frame[4..]
}

#[test]
fn a_hand_built_frame_decodes() {
    let frame = raw_frame(
        SAMPLE.magic(),
        SAMPLE.version(),
        KIND_LOOKUP,
        &lookup_payload(),
    );
    let message: SampleRequest = decode_body(SAMPLE, Direction::Request, body_of(&frame)).unwrap();
    match message {
        SampleRequest::Lookup(lookup) => {
            assert_eq!(lookup.handle, [0x22; 16]);
            assert_eq!(lookup.purpose, 1);
            assert!(!lookup.wanted);
        }
        SampleRequest::Store(_) => panic!("wrong kind"),
    }
}

#[test]
fn wrong_magic_is_refused() {
    for magic in [0x0000, 0x7E56, 0x577E, 0xFFFF] {
        let frame = raw_frame(magic, SAMPLE.version(), KIND_LOOKUP, &lookup_payload());
        assert_eq!(
            decode_body::<SampleRequest>(SAMPLE, Direction::Request, body_of(&frame)).map(|_| ()),
            Err(Error::WrongMagic),
            "magic {magic:#06x}"
        );
    }
}

#[test]
fn any_other_version_is_refused_without_negotiation() {
    for version in (0..=u8::MAX).filter(|v| *v != SAMPLE.version()) {
        let frame = raw_frame(SAMPLE.magic(), version, KIND_LOOKUP, &lookup_payload());
        assert_eq!(
            decode_body::<SampleRequest>(SAMPLE, Direction::Request, body_of(&frame)).map(|_| ()),
            Err(Error::VersionMismatch),
            "version {version}"
        );
    }
}

#[test]
fn a_kind_outside_the_table_is_refused() {
    for kind in (0..=u8::MAX).filter(|k| !SampleRequest::KINDS.contains(k)) {
        let frame = raw_frame(SAMPLE.magic(), SAMPLE.version(), kind, &lookup_payload());
        assert_eq!(
            decode_body::<SampleRequest>(SAMPLE, Direction::Request, body_of(&frame)).map(|_| ()),
            Err(Error::UnknownKind),
            "kind {kind:#04x}"
        );
    }
    // A reply kind is not a request kind, and the other way round.
    let frame = raw_frame(SAMPLE.magic(), SAMPLE.version(), KIND_DONE, &[0, 0, 0, 1]);
    assert_eq!(
        decode_body::<SampleRequest>(SAMPLE, Direction::Request, body_of(&frame)).map(|_| ()),
        Err(Error::UnknownKind)
    );
    let frame = raw_frame(SAMPLE.magic(), SAMPLE.version(), KIND_STORE, &[]);
    assert_eq!(
        decode_body::<SampleReply>(SAMPLE, Direction::Reply, body_of(&frame)),
        Err(Error::UnknownKind)
    );
}

#[test]
fn the_envelope_is_checked_magic_then_version_then_kind() {
    let frame = raw_frame(0x0000, 0xEE, 0xEE, &[]);
    assert_eq!(
        decode_body::<SampleReply>(SAMPLE, Direction::Reply, body_of(&frame)),
        Err(Error::WrongMagic)
    );
    let frame = raw_frame(SAMPLE.magic(), 0xEE, 0xEE, &[]);
    assert_eq!(
        decode_body::<SampleReply>(SAMPLE, Direction::Reply, body_of(&frame)),
        Err(Error::VersionMismatch)
    );
}

#[test]
fn trailing_octets_after_the_last_field_are_refused() {
    let mut payload = lookup_payload();
    payload.push(0x00);
    let frame = raw_frame(SAMPLE.magic(), SAMPLE.version(), KIND_LOOKUP, &payload);
    assert_eq!(
        decode_body::<SampleRequest>(SAMPLE, Direction::Request, body_of(&frame)).map(|_| ()),
        Err(Error::TrailingBytes)
    );
}

#[test]
fn a_body_shorter_than_the_envelope_is_refused() {
    for body in [&[][..], &[0x7E], &[0x7E, 0x57], &[0x7E, 0x57, 0x03]] {
        assert_eq!(
            decode_body::<SampleReply>(SAMPLE, Direction::Reply, body),
            Err(Error::FrameTooShort)
        );
    }
}

#[test]
fn a_body_over_the_direction_bound_is_refused() {
    let body = vec![0u8; common::REPLY_LIMIT.max_body() as usize + 1];
    assert_eq!(
        decode_body::<SampleReply>(SAMPLE, Direction::Reply, &body),
        Err(Error::FrameTooLarge)
    );
}

#[test]
fn encoded_frames_carry_the_channel_envelope() {
    let frame = encode_frame(SAMPLE, Direction::Reply, &SampleReply::Done { kvno: 7 }).unwrap();
    assert_eq!(
        frame.as_bytes(),
        &[0, 0, 0, 8, 0x7E, 0x57, 0x03, KIND_DONE, 0, 0, 0, 7]
    );
    assert_eq!(frame.body(), &frame.as_bytes()[4..]);
    assert_eq!(frame.len(), 12);
    assert!(!frame.is_empty());
    assert_eq!(
        decode_message::<SampleReply>(SAMPLE, Direction::Reply, frame.as_bytes()),
        Ok(Some((SampleReply::Done { kvno: 7 }, 12)))
    );
    assert_eq!(
        decode_message::<SampleReply>(SAMPLE, Direction::Reply, &frame.as_bytes()[..11]),
        Ok(None)
    );
}

#[test]
fn a_message_reporting_a_kind_outside_its_table_is_not_encoded() {
    /// A broken definition: its kind is not in its own table.
    struct Rogue;
    impl MessageSet for Rogue {
        const KINDS: &'static [u8] = &[0x01];
        fn kind(&self) -> u8 {
            0x02
        }
        fn write_payload(&self, _writer: &mut Writer) -> Result<()> {
            Ok(())
        }
        fn read_payload(_kind: u8, _reader: &mut Reader<'_>) -> Result<Rogue> {
            Ok(Rogue)
        }
    }
    assert_eq!(
        encode_frame(SAMPLE, Direction::Request, &Rogue).map(|_| ()),
        Err(Error::UnknownKind)
    );

    /// A broken definition that reports the reserved kind (not in its table).
    struct Impostor;
    impl MessageSet for Impostor {
        const KINDS: &'static [u8] = &[0x01];
        fn kind(&self) -> u8 {
            REFUSED_KIND
        }
        fn write_payload(&self, writer: &mut Writer) -> Result<()> {
            writer.write_u8(0x02)
        }
        fn read_payload(_kind: u8, _reader: &mut Reader<'_>) -> Result<Impostor> {
            Ok(Impostor)
        }
    }
    assert_eq!(
        encode_frame(SAMPLE, Direction::Reply, &Impostor).map(|_| ()),
        Err(Error::UnknownKind)
    );
}

#[test]
fn encoding_past_the_direction_bound_is_refused() {
    /// A reply whose payload is `size` octets of a byte string.
    struct Big(usize);
    impl MessageSet for Big {
        const KINDS: &'static [u8] = &[0x01];
        fn kind(&self) -> u8 {
            0x01
        }
        fn write_payload(&self, writer: &mut Writer) -> Result<()> {
            writer.write_bytes(&vec![0xAB; self.0], u32::MAX)
        }
        fn read_payload(_kind: u8, reader: &mut Reader<'_>) -> Result<Big> {
            reader.read_bytes(u32::MAX).map(|b| Big(b.len()))
        }
    }
    // Reply bound 64 = 4 envelope + 4 length + 56 octets.
    assert!(encode_frame(SAMPLE, Direction::Reply, &Big(56)).is_ok());
    assert_eq!(
        encode_frame(SAMPLE, Direction::Reply, &Big(57)).map(|_| ()),
        Err(Error::BodyOverBound)
    );
    // The request direction has its own, larger bound.
    assert!(encode_frame(SAMPLE, Direction::Request, &Big(57)).is_ok());
}

#[test]
fn channel_accessors() {
    let request = FrameLimit::new(100).unwrap();
    let reply = FrameLimit::new(200).unwrap();
    let channel = Channel::new(0xABCD, 9, request, reply);
    assert_eq!(channel.magic(), 0xABCD);
    assert_eq!(channel.version(), 9);
    assert_eq!(channel.limit(Direction::Request), request);
    assert_eq!(channel.limit(Direction::Reply), reply);
}

// ---- Refused ------------------------------------------------------------------

#[test]
fn refused_codes_form_a_closed_table() {
    let all = [
        Refused::VersionMismatch,
        Refused::Busy,
        Refused::Unavailable,
        Refused::Malformed,
    ];
    for refused in all {
        assert_eq!(Refused::from_code(refused.code()), Some(refused));
    }
    let codes: Vec<u8> = all.iter().map(|r| r.code()).collect();
    assert_eq!(codes, vec![0x01, 0x02, 0x03, 0x04]);
    for code in (0..=u8::MAX).filter(|c| !codes.contains(c)) {
        assert_eq!(Refused::from_code(code), None);
    }
}

#[test]
fn refused_payload_is_one_code_octet() {
    let mut writer = Writer::new(FrameLimit::new(MIN_BODY_LIMIT).unwrap());
    Refused::Malformed.write_fields(&mut writer).unwrap();
    assert_eq!(writer.into_payload().as_slice(), &[0x04]);
}

#[test]
fn refused_round_trips_with_the_reserved_kind_on_the_sample_channel() {
    assert_eq!(REFUSED_KIND, 0xFF);
    for refused in ALL_REFUSED {
        let frame = encode_refused(SAMPLE, refused).unwrap();
        assert_eq!(
            frame.as_bytes(),
            &[0, 0, 0, 5, 0x7E, 0x57, 0x03, REFUSED_KIND, refused.code()]
        );
        assert_eq!(
            decode_reply::<SampleReply>(SAMPLE, frame.body()),
            Ok(Reply::Refused(refused))
        );
        assert_eq!(
            decode_reply_message::<SampleReply>(SAMPLE, frame.as_bytes()),
            Ok(Some((Reply::Refused(refused), 9)))
        );
        assert_eq!(
            reply_round_trip_is_canonical::<SampleReply>(SAMPLE, frame.body()),
            Ok(true)
        );
        let via_reply = encode_reply::<SampleReply>(SAMPLE, &Reply::Refused(refused)).unwrap();
        assert_eq!(via_reply.as_bytes(), frame.as_bytes());
    }
    // Incomplete frame: not yet a reply.
    let frame = encode_refused(SAMPLE, Refused::Busy).unwrap();
    assert_eq!(
        decode_reply_message::<SampleReply>(SAMPLE, &frame.as_bytes()[..8]),
        Ok(None)
    );
}

#[test]
fn ordinary_replies_still_go_through_the_set() {
    let done = Reply::Message(SampleReply::Done { kvno: 9 });
    let frame = encode_reply(SAMPLE, &done).unwrap();
    assert_eq!(
        frame.as_bytes(),
        &[0, 0, 0, 8, 0x7E, 0x57, 0x03, KIND_DONE, 0, 0, 0, 9]
    );
    assert_eq!(decode_reply(SAMPLE, frame.body()), Ok(done));
    let ack = Reply::Message(SampleReply::Ack);
    let frame = encode_reply(SAMPLE, &ack).unwrap();
    assert_eq!(frame.as_bytes(), &[0, 0, 0, 4, 0x7E, 0x57, 0x03, KIND_ACK]);
    assert_eq!(decode_reply(SAMPLE, frame.body()), Ok(ack));
    assert_eq!(
        reply_round_trip_is_canonical::<SampleReply>(SAMPLE, frame.body()),
        Ok(true)
    );
    // A kind in neither the set nor the reserved slot.
    for kind in (0..=u8::MAX).filter(|k| !SampleReply::KINDS.contains(k) && *k != REFUSED_KIND) {
        let frame = raw_frame(SAMPLE.magic(), SAMPLE.version(), kind, &[]);
        assert_eq!(
            decode_reply::<SampleReply>(SAMPLE, body_of(&frame)),
            Err(Error::UnknownKind),
            "kind {kind:#04x}"
        );
    }
}

#[test]
fn refused_replies_are_decoded_strictly() {
    let refused = |version: u8, payload: &[u8]| {
        let frame = raw_frame(SAMPLE.magic(), version, REFUSED_KIND, payload);
        decode_reply::<SampleReply>(SAMPLE, body_of(&frame))
    };
    let v = SAMPLE.version();
    assert_eq!(refused(v, &[0x09]), Err(Error::UnknownCode));
    assert_eq!(refused(v, &[0x00]), Err(Error::UnknownCode));
    assert_eq!(refused(v, &[]), Err(Error::Truncated));
    assert_eq!(refused(v, &[0x02, 0x00]), Err(Error::TrailingBytes));
    // The exact-version rule applies to the reserved kind too.
    assert_eq!(refused(v + 1, &[0x01]), Err(Error::VersionMismatch));
    let frame = raw_frame(0x0000, v, REFUSED_KIND, &[0x01]);
    assert_eq!(
        decode_reply::<SampleReply>(SAMPLE, body_of(&frame)),
        Err(Error::WrongMagic)
    );
}

/// Calls of [`Tattle::read_payload`] (used by one test only).
static TATTLE_CALLS: AtomicUsize = AtomicUsize::new(0);

/// A reply set whose handler counts every call.
#[derive(Debug, PartialEq)]
struct Tattle;

impl MessageSet for Tattle {
    const KINDS: &'static [u8] = &[0x01, 0x02];
    fn kind(&self) -> u8 {
        0x01
    }
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        writer.write_u8(0x00)
    }
    fn read_payload(_kind: u8, reader: &mut Reader<'_>) -> Result<Tattle> {
        TATTLE_CALLS.fetch_add(1, Ordering::SeqCst);
        reader.read_u8().map(|_| Tattle)
    }
}

#[test]
fn the_reserved_kind_never_reaches_the_sets_handler() {
    let busy = raw_frame(SAMPLE.magic(), SAMPLE.version(), REFUSED_KIND, &[0x02]);
    assert_eq!(
        decode_reply::<Tattle>(SAMPLE, body_of(&busy)),
        Ok(Reply::Refused(Refused::Busy))
    );
    // A malformed refusal is judged by the Refused rules, not by the handler.
    let bad = raw_frame(SAMPLE.magic(), SAMPLE.version(), REFUSED_KIND, &[0x09]);
    assert_eq!(
        decode_reply::<Tattle>(SAMPLE, body_of(&bad)),
        Err(Error::UnknownCode)
    );
    // Outside the reply decoder the reserved kind is in no table: refused as
    // an unknown kind, in both directions.
    for direction in [Direction::Reply, Direction::Request] {
        assert_eq!(
            decode_body::<Tattle>(SAMPLE, direction, body_of(&busy)),
            Err(Error::UnknownKind)
        );
    }
    assert_eq!(TATTLE_CALLS.load(Ordering::SeqCst), 0);
    // Control: a kind of the set does reach the handler.
    let own = raw_frame(SAMPLE.magic(), SAMPLE.version(), 0x01, &[0x00]);
    assert_eq!(
        decode_reply::<Tattle>(SAMPLE, body_of(&own)),
        Ok(Reply::Message(Tattle))
    );
    assert_eq!(TATTLE_CALLS.load(Ordering::SeqCst), 1);
}

#[test]
fn a_table_listing_the_reserved_kind_is_detected() {
    // The build-time rejection of such a set is the `compile_fail` doctest on
    // `ipc::MessageSet`; this checks the predicate it is built on.
    assert!(kinds_exclude_refused(SampleRequest::KINDS));
    assert!(kinds_exclude_refused(SampleReply::KINDS));
    assert!(kinds_exclude_refused(Tattle::KINDS));
    assert!(kinds_exclude_refused(&[]));
    assert!(kinds_exclude_refused(&[0x00, 0x7F, 0xFE]));
    assert!(!kinds_exclude_refused(&[REFUSED_KIND]));
    assert!(!kinds_exclude_refused(&[0x01, 0x02, REFUSED_KIND]));
    assert!(!kinds_exclude_refused(&[REFUSED_KIND, 0x01]));
}

#[test]
fn every_frame_limit_has_room_for_the_refused_reply() {
    assert_eq!(MIN_BODY_LIMIT, 5);
    assert_eq!(FrameLimit::new(MIN_BODY_LIMIT - 1), None);
    let tight = FrameLimit::new(MIN_BODY_LIMIT).unwrap();
    let channel = Channel::new(0x0001, 1, tight, tight);
    for refused in ALL_REFUSED {
        let frame = encode_refused(channel, refused).unwrap();
        assert_eq!(frame.len(), 9);
        assert_eq!(
            decode_reply::<SampleReply>(channel, frame.body()),
            Ok(Reply::Refused(refused))
        );
    }
}

#[test]
fn errors_map_to_the_shared_refusal_or_to_a_plain_close() {
    // docs/50 §3.3: version ≠ ⇒ Refused{VersionMismatch} + close.
    assert_eq!(
        Error::VersionMismatch.refusal(),
        Some(Refused::VersionMismatch)
    );
    // docs/50 §3.3: trailing ⇒ Malformed + close (Q-225 item 3: every payload error).
    for error in [
        Error::Truncated,
        Error::TrailingBytes,
        Error::InvalidBoolean,
        Error::InvalidOptionMarker,
        Error::LengthOverBound,
        Error::CountOverBound,
        Error::UnknownCode,
        Error::NestingTooDeep,
    ] {
        assert_eq!(error.refusal(), Some(Refused::Malformed), "{error:?}");
    }
    // docs/50 §3.3: length, magic, kind ⇒ close without a reply.
    for error in [
        Error::FrameTooShort,
        Error::FrameTooLarge,
        Error::WrongMagic,
        Error::UnknownKind,
        Error::BodyOverBound,
    ] {
        assert_eq!(error.refusal(), None, "{error:?}");
    }
}

#[test]
fn error_text_is_fixed_and_carries_no_octets() {
    let text = Error::LengthOverBound.to_string();
    assert_eq!(text, "byte string length over the field bound");
    let as_std: &dyn std::error::Error = &Error::WrongMagic;
    assert_eq!(as_std.to_string(), "frame magic is not this channel's");
}
