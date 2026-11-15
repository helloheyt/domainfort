//! The zone-image transfer: the canonical encoding of dns-zone's
//! `ZoneImageParts`, the one division into chunks, dird's validated
//! `ImageTransfer`, and dnsd's bounded `ImageAssembly` (whole images only,
//! built by `ZoneImage::new`).
//!
//! Sources: docs/54 §4.4 (the image's fields; atomic replacement), §4.6
//! (`FetchZoneImage`: chunks ≤ 1 MiB, total ≤ 8 MiB); A-124 (`ZoneImage::new`
//! validates every part); docs/50 §3.3 (one encoding per value, no trailing
//! octet, round trip); RFC 1035 §2.3.4, §3.1 (label / name bounds), §3.4.1
//! (32-bit address); RFC 2136 §3.7 (no partial view), §7.11 (SERIAL ≠ 0);
//! RFC 2782 "Fictional example" (the zone of the fixtures).

mod common;

use common::{host, large_parts, long_label, name, rfc2782_parts, TTL};
use ipc::Error;
use ipc_dns::channel::codes;
use ipc_dns::{
    decode_image, encode_image, split_image, ImageAssembly, ImageChunk, ImageError, ImageTransfer,
    KpasswdService, ZoneImage, ZoneImageError, MAX_IMAGE_CHUNK, MAX_IMAGE_CHUNKS, MAX_IMAGE_OCTETS,
};

const CHUNK: usize = MAX_IMAGE_CHUNK as usize;

/// Feed every chunk of `chunks` to a new assembly; the result of the last
/// (or the first error).
fn assemble(chunks: &[ImageChunk]) -> Result<Option<ZoneImage>, ImageError> {
    let mut assembly = ImageAssembly::new();
    let mut last = None;
    for chunk in chunks {
        last = assembly.push(chunk)?;
    }
    Ok(last)
}

/// docs/50 §3.3: the image encoding round-trips exactly, on the octets and on
/// the parts (kpasswd absent and present).
#[test]
fn the_image_round_trips() {
    for kpasswd in [KpasswdService::Absent, KpasswdService::Present] {
        let mut parts = rfc2782_parts();
        parts.kpasswd = kpasswd;
        let payload = encode_image(&parts).expect("encodes");
        let decoded = decode_image(&payload).expect("decodes");
        assert_eq!(decoded, parts);
        assert_eq!(encode_image(&decoded).expect("re-encodes"), payload);
    }
}

/// docs/54 §4.4: the encoding is exactly the documented field order — apex,
/// SERIAL, RNAME, four timers, the infrastructure TTL, the DC, the member
/// hosts, the kpasswd flag — and nothing else (crate image documentation).
#[test]
fn the_image_layout_is_the_documented_one() {
    let mut parts = rfc2782_parts();
    parts.hosts.clear();
    let payload = encode_image(&parts).expect("encodes");
    let mut expected = Vec::new();
    let put_name = |out: &mut Vec<u8>, dotted: &str| {
        let wire = name(dotted).as_wire().to_vec();
        out.extend_from_slice(&(wire.len() as u32).to_be_bytes());
        out.extend_from_slice(&wire);
    };
    put_name(&mut expected, "example.com");
    expected.extend_from_slice(&1_995_032_001u32.to_be_bytes());
    put_name(&mut expected, "root.example.com");
    for value in [3600u32, 3600, 604_800, 86_400, TTL] {
        expected.extend_from_slice(&value.to_be_bytes());
    }
    // dc: label, one address, TTL.
    expected.extend_from_slice(&6u32.to_be_bytes());
    expected.extend_from_slice(b"server");
    expected.extend_from_slice(&1u32.to_be_bytes());
    expected.extend_from_slice(&[172, 30, 79, 10]);
    expected.extend_from_slice(&TTL.to_be_bytes());
    // no member hosts.
    expected.extend_from_slice(&0u32.to_be_bytes());
    expected.push(codes::KPASSWD_ABSENT);
    assert_eq!(payload, expected);
}

/// docs/54 §4.6 / Q-280 part rule: one division per payload — full chunks,
/// then the rest; a multiple of the chunk size ends with a full last chunk.
#[test]
fn an_image_has_one_division_into_chunks() {
    assert!(split_image(&[]).is_none());
    assert!(split_image(&vec![0; MAX_IMAGE_OCTETS + 1]).is_none());

    let small = split_image(&[1, 2, 3]).expect("splits");
    assert_eq!(small.len(), 1);
    assert!(!small[0].more());

    let exact = split_image(&vec![7; 2 * CHUNK]).expect("splits");
    assert_eq!(exact.len(), 2);
    assert!(exact[0].more() && !exact[1].more());
    assert_eq!(exact[1].octets().len(), CHUNK);

    let ragged = split_image(&vec![7; 2 * CHUNK + 5]).expect("splits");
    assert_eq!(ragged.len(), 3);
    assert_eq!(ragged[2].octets().len(), 5);

    let full = split_image(&vec![7; MAX_IMAGE_OCTETS]).expect("splits");
    assert_eq!(full.len(), MAX_IMAGE_CHUNKS);
    assert_eq!(MAX_IMAGE_CHUNKS, 8);
}

/// A-124 / docs/54 §4.4: dird can only send a valid zone — `ImageTransfer`
/// refuses parts `ZoneImage::new` refuses.
#[test]
fn only_a_valid_zone_can_be_sent() {
    let transfer = ImageTransfer::new(&rfc2782_parts()).expect("valid");
    assert_eq!(transfer.serial().get(), 1_995_032_001);
    assert_eq!(transfer.chunks().len(), 1);

    let mut zero = rfc2782_parts();
    zero.serial = 0;
    assert_eq!(
        ImageTransfer::new(&zero),
        Err(ImageError::Zone(ZoneImageError::SerialZero))
    );
    let mut wildcard = rfc2782_parts();
    wildcard.hosts.push(host(b"*", &[[10, 0, 0, 1]], TTL));
    assert_eq!(
        ImageTransfer::new(&wildcard),
        Err(ImageError::Zone(ZoneImageError::HostLabelNotLdh))
    );
    let mut duplicate = rfc2782_parts();
    duplicate.hosts.push(host(b"SERVER", &[[10, 0, 0, 1]], TTL));
    assert_eq!(
        ImageTransfer::new(&duplicate),
        Err(ImageError::Zone(ZoneImageError::DuplicateHost))
    );
}

/// docs/54 §4.4, §4.6: what dird sends, dnsd rebuilds into the same zone —
/// only after the last chunk, and only whole.
#[test]
fn a_transfer_reassembles_into_the_same_zone() {
    let parts = rfc2782_parts();
    let transfer = ImageTransfer::new(&parts).expect("valid");
    let image = assemble(transfer.chunks())
        .expect("assembles")
        .expect("complete");
    assert_eq!(image, ZoneImage::new(parts).expect("valid"));
}

/// docs/54 §4.6 ("total ≤ 8 MiB"), dns-zone's bounds: the largest image —
/// 65535 member hosts, every label 63 octets, eight addresses each — fits
/// the transfer, travels in several chunks and reassembles.
#[test]
fn the_largest_image_fits_and_reassembles() {
    let parts = large_parts(65_535);
    let transfer = ImageTransfer::new(&parts).expect("the largest image is valid and fits");
    let chunks = transfer.chunks();
    assert!(chunks.len() > 1 && chunks.len() <= MAX_IMAGE_CHUNKS);
    assert!(chunks[..chunks.len() - 1].iter().all(ImageChunk::more));
    assert!(!chunks[chunks.len() - 1].more());
    let image = assemble(chunks).expect("assembles").expect("complete");
    assert_eq!(image.host_count(), 65_536);
    assert_eq!(image.serial(), 1_995_032_001);
}

/// dns-zone `MAX_HOST_RECORDS`: one more member host has no wire form.
#[test]
fn one_host_too_many_has_no_wire_form() {
    // The count field alone is refused, before any host is read.
    let mut parts = rfc2782_parts();
    parts.hosts.clear();
    let mut payload = encode_image(&parts).expect("encodes");
    let at = payload.len() - 1 - 4;
    payload[at..at + 4].copy_from_slice(&65_536u32.to_be_bytes());
    assert_eq!(decode_image(&payload), Err(Error::CountOverBound));
}

/// docs/54 §4.6 / Q-280: reassembly is bounded — chunks past 8 MiB are
/// refused, and nothing comes after the last chunk.
#[test]
fn reassembly_is_bounded() {
    let full = ImageChunk::new(&vec![0; CHUNK], true).expect("chunk");
    let mut assembly = ImageAssembly::new();
    for _ in 0..MAX_IMAGE_CHUNKS {
        assert_eq!(assembly.push(&full), Ok(None));
    }
    assert_eq!(
        assembly.push(&ImageChunk::new(&[0], false).expect("chunk")),
        Err(ImageError::OverBound)
    );
    // Spent after the error.
    assert_eq!(
        assembly.push(&ImageChunk::new(&[0], false).expect("chunk")),
        Err(ImageError::OverBound)
    );

    let transfer = ImageTransfer::new(&rfc2782_parts()).expect("valid");
    let mut done = ImageAssembly::new();
    assert!(done.push(&transfer.chunks()[0]).expect("ok").is_some());
    assert_eq!(done.push(&transfer.chunks()[0]), Err(ImageError::OverBound));
}

/// docs/50 §3.3 ("replies are decoded with the same strictness"): dnsd
/// refuses a payload that does not decode, and parts that are not a zone.
#[test]
fn dnsd_validates_what_it_reassembles() {
    // Not an image payload.
    let garbage = split_image(&[0xFF; 40]).expect("splits");
    assert!(matches!(assemble(&garbage), Err(ImageError::Payload(_))));

    // Decodes, but two hosts share a label (dird's `ImageTransfer` could
    // never send it; a compromised or broken dird could).
    let mut duplicate = rfc2782_parts();
    duplicate
        .hosts
        .push(host(b"Old-Slow-Box", &[[10, 0, 0, 9]], TTL));
    let payload = encode_image(&duplicate).expect("encodes without validation");
    let chunks = split_image(&payload).expect("splits");
    assert_eq!(
        assemble(&chunks),
        Err(ImageError::Zone(ZoneImageError::DuplicateHost))
    );

    // Trailing octets after the kpasswd flag.
    let mut trailing = encode_image(&rfc2782_parts()).expect("encodes");
    trailing.push(0);
    assert_eq!(decode_image(&trailing), Err(Error::TrailingBytes));
    assert!(matches!(
        assemble(&split_image(&trailing).expect("splits")),
        Err(ImageError::Payload(Error::TrailingBytes))
    ));
}

/// RFC 1035 §2.3.4, §3.1, §3.4.1; RFC 2136 §7.11; docs/54 §4.4: every field
/// of the image keeps its bound and domain on the wire.
#[test]
fn every_image_field_is_bounded() {
    // A 64-octet label has no wire form.
    let mut long = rfc2782_parts();
    let mut label = long_label(1);
    label.push(b'z');
    long.hosts.push(host(&label, &[[10, 0, 0, 1]], TTL));
    assert_eq!(encode_image(&long), Err(Error::LengthOverBound));

    // Nine addresses have no wire form.
    let mut nine = rfc2782_parts();
    nine.hosts.push(host(
        b"many",
        &(1..=9u8).map(|d| [10, 0, 0, d]).collect::<Vec<_>>(),
        TTL,
    ));
    assert_eq!(encode_image(&nine), Err(Error::CountOverBound));

    // A zero SERIAL has no wire form, and is refused on decoding.
    let mut zero = rfc2782_parts();
    zero.serial = 0;
    assert_eq!(encode_image(&zero), Err(Error::UnknownCode));
    let mut payload = encode_image(&rfc2782_parts()).expect("encodes");
    let apex_field = 4 + name("example.com").as_wire().len();
    payload[apex_field..apex_field + 4].copy_from_slice(&[0, 0, 0, 0]);
    assert_eq!(decode_image(&payload), Err(Error::UnknownCode));

    // An unknown kpasswd code.
    let mut payload = encode_image(&rfc2782_parts()).expect("encodes");
    let last = payload.len() - 1;
    payload[last] = 0x03;
    assert_eq!(decode_image(&payload), Err(Error::UnknownCode));

    // A compressed apex (no message to point into).
    let mut payload = encode_image(&rfc2782_parts()).expect("encodes");
    payload[4 + 8] = 0xC0;
    assert_eq!(decode_image(&payload), Err(Error::UnknownCode));

    // Over the transfer bound: refused before decoding.
    assert_eq!(
        decode_image(&vec![0; MAX_IMAGE_OCTETS + 1]),
        Err(Error::FrameTooLarge)
    );

    // Every truncation is refused.
    let payload = encode_image(&rfc2782_parts()).expect("encodes");
    for cut in 0..payload.len() {
        assert!(decode_image(&payload[..cut]).is_err(), "cut {cut}");
    }
}

/// docs/54 §9: no `Debug` output of the transfer prints zone content in
/// bulk or payload octets.
#[test]
fn debug_output_shows_no_content() {
    let transfer = ImageTransfer::new(&rfc2782_parts()).expect("valid");
    let printed = format!("{transfer:?} {:?}", transfer.chunks()[0]);
    assert!(!printed.contains("server"), "{printed}");
    assert!(printed.contains("serial"), "{printed}");
}
