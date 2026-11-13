//! The element-level reader and writer (`split_element`, `encode_element`).
//!
//! Every vector names its source: byte sequences hand-derived from the named
//! ITU-T X.690 (02/2021) clause, or the clause's own EXAMPLE. No vector comes
//! from any other implementation's test suite.

use parse_asn1::{decode, encode, encode_element, split_element, Error, Tag, TagClass, Value};

fn tag(class: TagClass, constructed: bool, number: u32) -> Tag {
    Tag {
        class,
        constructed,
        number,
    }
}

/// X.690 8.1 / 8.19 EXAMPLE ({2 999 3} encodes as 06 03 88 37 03): the
/// element is split off, the rest is returned untouched, and the element's
/// encoding decodes with the value model.
#[test]
fn splits_one_element_and_returns_the_rest() {
    let input = [0x06, 0x03, 0x88, 0x37, 0x03, 0xAA, 0xBB];
    let (element, rest) = split_element(&input).unwrap();
    assert_eq!(element.tag, tag(TagClass::Universal, false, 6));
    assert_eq!(element.contents, &[0x88, 0x37, 0x03]);
    assert_eq!(element.encoding, &input[..5]);
    assert_eq!(rest, &[0xAA, 0xBB]);
    assert_eq!(
        decode(element.encoding).unwrap(),
        Value::ObjectIdentifier(vec![2, 999, 3])
    );
}

/// X.690 8.1.2.2 (class bits), 8.1.2.5 (constructed bit), 8.14.4 (an
/// implicit tag is primitive when the base encoding is): a primitive
/// context-specific [2] and a type outside the value model (UNIVERSAL 23,
/// UTCTime — X.680 Table 1) are read at the element level.
#[test]
fn reads_tags_outside_the_value_model() {
    // [2] primitive, two contents octets: 0x82 = 10 0 00010.
    let (element, rest) = split_element(&[0x82, 0x02, b'a', b'b']).unwrap();
    assert_eq!(element.tag, tag(TagClass::ContextSpecific, false, 2));
    assert_eq!(element.contents, b"ab");
    assert!(rest.is_empty());
    // UNIVERSAL 23 primitive: 0x17. X.690 11.8.4 example "920521000000Z".
    let mut utc = vec![0x17, 13];
    utc.extend_from_slice(b"920521000000Z");
    let (element, _) = split_element(&utc).unwrap();
    assert_eq!(element.tag, tag(TagClass::Universal, false, 23));
    assert_eq!(element.contents, b"920521000000Z");
}

/// X.690 10.1 (DER: definite form, minimum number of octets), 8.1.3.6
/// (indefinite form 0x80), 8.1.3.5 c) (0xFF reserved), 8.1.3.3 (the length
/// counts octets that must be present).
#[test]
fn refuses_every_non_der_length() {
    // Long form for a length that fits the short form: 04 81 01 00.
    assert_eq!(
        split_element(&[0x04, 0x81, 0x01, 0x00]),
        Err(Error::NonMinimalLength)
    );
    // Leading zero length octet: 04 82 00 80 ….
    let mut padded = vec![0x04, 0x82, 0x00, 0x80];
    padded.extend_from_slice(&[0u8; 0x80]);
    assert_eq!(split_element(&padded), Err(Error::NonMinimalLength));
    // Indefinite length: 30 80 00 00.
    assert_eq!(
        split_element(&[0x30, 0x80, 0x00, 0x00]),
        Err(Error::IndefiniteLength)
    );
    // Reserved length octet.
    assert_eq!(
        split_element(&[0x04, 0xFF]),
        Err(Error::ReservedLengthOctet)
    );
    // Declared length beyond the input.
    assert_eq!(
        split_element(&[0x04, 0x05, 0x00]),
        Err(Error::LengthExceedsInput)
    );
    // Nothing at all, and a tag with no length.
    assert_eq!(split_element(&[]), Err(Error::Truncated));
    assert_eq!(split_element(&[0x04]), Err(Error::Truncated));
    // Long form whose length octets are missing.
    assert_eq!(split_element(&[0x04, 0x82, 0x01]), Err(Error::Truncated));
}

/// X.690 8.1.2.4.2 c) (the first subsequent octet's bits 7-1 are not all
/// zero) and 8.1.2.2 (numbers below 31 use the single-octet form).
#[test]
fn refuses_non_minimal_tag_numbers() {
    assert_eq!(
        split_element(&[0x1F, 0x80, 0x1F, 0x00]),
        Err(Error::NonMinimalTagNumber)
    );
    assert_eq!(
        split_element(&[0x1F, 0x05, 0x00]),
        Err(Error::NonMinimalTagNumber)
    );
}

/// X.690 8.1.2, 8.1.3.4, 8.1.3.5, 10.1: the writer produces the identifier
/// and the minimal length, short and long form, and the reader reads it
/// back; for a type in the value model the result equals `encode`.
#[test]
fn the_writer_is_canonical_and_round_trips() {
    let short = encode_element(tag(TagClass::Universal, false, 4), &[1, 2, 3]);
    assert_eq!(short, vec![0x04, 0x03, 1, 2, 3]);
    assert_eq!(
        short,
        encode(&Value::OctetString(vec![1, 2, 3])).unwrap(),
        "same octets as the value-model encoder"
    );
    // 200 contents octets: long form, one length octet (0x81 0xC8).
    let long = encode_element(tag(TagClass::ContextSpecific, true, 3), &[0u8; 200]);
    assert_eq!(&long[..3], &[0xA3, 0x81, 0xC8]);
    let (element, rest) = split_element(&long).unwrap();
    assert_eq!(element.tag, tag(TagClass::ContextSpecific, true, 3));
    assert_eq!(element.contents.len(), 200);
    assert!(rest.is_empty());
    // 300 octets: two length octets (0x82 0x01 0x2C).
    let longer = encode_element(tag(TagClass::Universal, false, 12), &[b'x'; 300]);
    assert_eq!(&longer[..4], &[0x0C, 0x82, 0x01, 0x2C]);
    assert_eq!(split_element(&longer).unwrap().0.contents.len(), 300);
    // High tag number (31): 0x1F then one subsequent octet.
    let high = encode_element(tag(TagClass::Application, false, 31), &[]);
    assert_eq!(high, vec![0x5F, 0x1F, 0x00]);
    assert_eq!(
        split_element(&high).unwrap().0.tag,
        tag(TagClass::Application, false, 31)
    );
}
