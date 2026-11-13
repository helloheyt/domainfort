//! A sample channel defined with the message-definition pattern: canonical
//! round trips, the exact octets, truncation and mutation sweeps, and the
//! round-trip property catching a broken definition.
//!
//! Source: docs/50 §3.3 (layout; primitives; "a single encoding per value";
//! "round-trip: every decoder checks `encode(decode(b)) == b` in property
//! tests"; no trailing byte), §3.4 (a request kind and a reply kind per
//! operation), §9 (layer 1: "round-trip for each op, canonicity, every bound,
//! every unknown kind, trailing byte, wrong version"), R50-4.

mod common;

use common::{
    full_store, same_store, sparse_store, Lookup, SampleReply, SampleRequest, KIND_LOOKUP,
    KIND_STORE, SAMPLE,
};
use ipc::{
    decode_body, decode_reply, encode_frame, encode_reply, reply_round_trip_is_canonical,
    round_trip_is_canonical, Direction, Error, MessageSet, Payload, Reader, Refused, Reply, Result,
    Writer,
};

fn encode_request(message: &SampleRequest) -> Vec<u8> {
    encode_frame(SAMPLE, Direction::Request, message)
        .unwrap()
        .as_bytes()
        .to_vec()
}

#[test]
fn lookup_has_the_documented_octets() {
    let lookup = Lookup {
        handle: [0x10; 16],
        purpose: 0x02,
        wanted: true,
    };
    let frame = encode_request(&SampleRequest::Lookup(lookup.clone()));
    let mut expected = vec![0x00, 0x00, 0x00, 0x16, 0x7E, 0x57, 0x03, KIND_LOOKUP];
    expected.extend_from_slice(&[0x10; 16]);
    expected.extend_from_slice(&[0x02, 0x01]);
    assert_eq!(frame, expected);
    match decode_body(SAMPLE, Direction::Request, &frame[4..]).unwrap() {
        SampleRequest::Lookup(decoded) => assert_eq!(decoded, lookup),
        SampleRequest::Store(_) => panic!("wrong kind"),
    }
}

#[test]
fn store_has_the_documented_octets() {
    let frame = encode_request(&SampleRequest::Store(sparse_store()));
    let mut expected = vec![0x7E, 0x57, 0x03, KIND_STORE];
    expected.extend_from_slice(&[0x00; 16]); // handle
    expected.extend_from_slice(&[0, 0, 0, 0]); // kvno
    expected.extend_from_slice(&[0; 8]); // serial
    expected.extend_from_slice(&[0, 0]); // port
    expected.push(0x00); // enabled = false
    expected.push(0x01); // mode = Create
    expected.push(0x00); // armor absent
    expected.extend_from_slice(&[0, 0, 0, 0]); // padata: empty
    expected.extend_from_slice(&[0, 0, 0, 0]); // password: empty
    expected.extend_from_slice(&[0, 0, 0, 0]); // names: count 0
    expected.push(0x00); // groups absent
    let mut framed = u32::try_from(expected.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(&expected);
    assert_eq!(frame, framed);
}

#[test]
fn every_sample_message_round_trips_canonically() {
    for store in [full_store(), sparse_store()] {
        let frame = encode_request(&SampleRequest::Store(store));
        let body = &frame[4..];
        let decoded: SampleRequest = decode_body(SAMPLE, Direction::Request, body).unwrap();
        // Re-encoding the decoded value gives the same octets.
        assert_eq!(encode_request(&decoded), frame);
        assert_eq!(
            round_trip_is_canonical::<SampleRequest>(SAMPLE, Direction::Request, body),
            Ok(true)
        );
    }
    let full = full_store();
    let frame = encode_request(&SampleRequest::Store(full_store()));
    match decode_body(SAMPLE, Direction::Request, &frame[4..]).unwrap() {
        SampleRequest::Store(decoded) => assert!(same_store(&decoded, &full)),
        SampleRequest::Lookup(_) => panic!("wrong kind"),
    }
    for reply in [
        SampleReply::Done { kvno: 0 },
        SampleReply::Done { kvno: u32::MAX },
        SampleReply::Ack,
    ] {
        let frame = encode_frame(SAMPLE, Direction::Reply, &reply).unwrap();
        assert_eq!(
            decode_body(SAMPLE, Direction::Reply, frame.body()),
            Ok(reply)
        );
        assert_eq!(
            round_trip_is_canonical::<SampleReply>(SAMPLE, Direction::Reply, frame.body()),
            Ok(true)
        );
    }
    // Replies, the shared refusal included (A-59: REFUSED_KIND on every channel).
    for reply in [
        Reply::Message(SampleReply::Done { kvno: 7 }),
        Reply::Message(SampleReply::Ack),
        Reply::Refused(Refused::VersionMismatch),
        Reply::Refused(Refused::Busy),
        Reply::Refused(Refused::Unavailable),
        Reply::Refused(Refused::Malformed),
    ] {
        let frame = encode_reply(SAMPLE, &reply).unwrap();
        assert_eq!(decode_reply(SAMPLE, frame.body()), Ok(reply));
        assert_eq!(
            reply_round_trip_is_canonical::<SampleReply>(SAMPLE, frame.body()),
            Ok(true)
        );
    }
}

#[test]
fn no_single_octet_change_of_a_reply_yields_a_second_encoding() {
    // The same mutation sweep over replies, refusals included: the reserved
    // kind and the set's kinds never decode one value from two encodings.
    for reply in [
        Reply::Message(SampleReply::Done { kvno: 0x0102_0304 }),
        Reply::Refused(Refused::Unavailable),
    ] {
        let body = encode_reply(SAMPLE, &reply).unwrap().body().to_vec();
        for index in 0..body.len() {
            for value in 0..=u8::MAX {
                let mut mutated = body.clone();
                mutated[index] = value;
                if let Ok(canonical) =
                    reply_round_trip_is_canonical::<SampleReply>(SAMPLE, &mutated)
                {
                    assert!(canonical, "index {index} value {value:#04x}");
                }
            }
        }
    }
}

#[test]
fn every_truncation_of_a_body_is_refused() {
    let frame = encode_request(&SampleRequest::Store(full_store()));
    let body = &frame[4..];
    for cut in 0..body.len() {
        let result = decode_body::<SampleRequest>(SAMPLE, Direction::Request, &body[..cut]);
        assert!(result.is_err(), "cut {cut} decoded");
        let expected = if cut < 4 {
            Error::FrameTooShort
        } else {
            Error::Truncated
        };
        assert_eq!(result.map(|_| ()), Err(expected), "cut {cut}");
    }
}

#[test]
fn no_single_octet_change_yields_a_second_encoding() {
    // Every one-octet mutation of a valid body is either refused or decodes
    // to a value whose encoding is exactly the mutated body: no value has two
    // encodings.
    let frame = encode_request(&SampleRequest::Store(full_store()));
    let body = frame[4..].to_vec();
    let mut accepted = 0usize;
    for index in 0..body.len() {
        for value in 0..=u8::MAX {
            if value == body[index] {
                continue;
            }
            let mut mutated = body.clone();
            mutated[index] = value;
            if let Ok(canonical) =
                round_trip_is_canonical::<SampleRequest>(SAMPLE, Direction::Request, &mutated)
            {
                assert!(canonical, "index {index} value {value:#04x}");
                accepted += 1;
            }
        }
    }
    // Fixed-width fields accept every value; the sweep exercised both paths.
    assert!(accepted > 0);
}

#[test]
fn appending_any_octet_is_refused() {
    let frame = encode_request(&SampleRequest::Store(full_store()));
    for extra in [0x00, 0x01, 0xFF] {
        let mut body = frame[4..].to_vec();
        body.push(extra);
        assert_eq!(
            decode_body::<SampleRequest>(SAMPLE, Direction::Request, &body).map(|_| ()),
            Err(Error::TrailingBytes)
        );
    }
}

#[test]
fn field_bounds_hold_on_both_sides() {
    // Five names when the bound is four: the writer refuses ...
    let mut store = sparse_store();
    store.names = vec![Vec::new(); 5];
    assert_eq!(
        encode_frame(SAMPLE, Direction::Request, &SampleRequest::Store(store)).map(|_| ()),
        Err(Error::CountOverBound)
    );
    // ... and a hand-edited count of five is refused by the reader.
    let frame = encode_request(&SampleRequest::Store(sparse_store()));
    let mut body = frame[4..].to_vec();
    // names count sits after header 4 + handle 16 + kvno 4 + serial 8 + port 2
    // + enabled 1 + mode 1 + armor 1 + padata 4 + password 4 = 45.
    assert_eq!(&body[45..49], &[0, 0, 0, 0]);
    body[48] = 5;
    assert_eq!(
        decode_body::<SampleRequest>(SAMPLE, Direction::Request, &body).map(|_| ()),
        Err(Error::CountOverBound)
    );
}

#[test]
fn the_round_trip_property_catches_a_broken_definition() {
    /// A broken definition: writes two fields, reads them in the other order.
    #[derive(Debug)]
    struct Swapped {
        first: u16,
        second: u16,
    }
    impl Payload for Swapped {
        fn write_fields(&self, writer: &mut Writer) -> Result<()> {
            writer.write_u16(self.first)?;
            writer.write_u16(self.second)
        }
        fn read_fields(reader: &mut Reader<'_>) -> Result<Swapped> {
            let second = reader.read_u16()?;
            let first = reader.read_u16()?;
            Ok(Swapped { first, second })
        }
    }
    impl MessageSet for Swapped {
        const KINDS: &'static [u8] = &[0x01];
        fn kind(&self) -> u8 {
            0x01
        }
        fn write_payload(&self, writer: &mut Writer) -> Result<()> {
            self.write_fields(writer)
        }
        fn read_payload(_kind: u8, reader: &mut Reader<'_>) -> Result<Swapped> {
            Swapped::read_fields(reader)
        }
    }
    let frame = encode_frame(
        SAMPLE,
        Direction::Request,
        &Swapped {
            first: 1,
            second: 2,
        },
    )
    .unwrap();
    assert_eq!(
        round_trip_is_canonical::<Swapped>(SAMPLE, Direction::Request, frame.body()),
        Ok(false)
    );
}
