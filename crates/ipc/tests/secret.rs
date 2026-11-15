//! Secret handling: redacted `Debug`, zeroizing, and no payload octets in any
//! diagnostic output.
//!
//! Source: docs/50 §3.3 (secret-bearing buffers: "the `SetSecret` /
//! `VerifySecret` body (password) is read into `Zeroizing`, the frame buffer
//! zeroized after decoding, in both sides"), §8.2 (no raw request octets in
//! logs; secret-bearing types without a `Debug` that prints content), R50-4;
//! docs/10 I7; docs/CLEAN-ROOM.md
//!
//! Observing the memory of a dropped value would need `unsafe` (reading freed
//! memory), which this workspace forbids. The drop path is therefore verified
//! through what is observable without it: `Secret` implements
//! `ZeroizeOnDrop` (checked at compile time below), its only field is a
//! `zeroize::Zeroizing` buffer (whose drop zeroizes, docs.rs zeroize 1.9.1),
//! and the explicit `Zeroize::zeroize` — the same wipe — is observed to clear
//! every octet.

mod common;

use common::{full_store, SampleRequest, SAMPLE};
use ipc::{
    decode_frame, encode_frame, DerBlob, Direction, FrameReader, FrameStatus, Reader, Secret,
    Writer,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Compile-time check: the type promises to zeroize itself when dropped.
fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

const PASSWORD: &[u8] = b"correct horse";

#[test]
fn secret_debug_shows_neither_octets_nor_length() {
    let secret = Secret::from_slice(PASSWORD);
    let shown = format!("{secret:?}");
    assert_eq!(shown, "Secret(<redacted>)");
    assert!(!shown.contains("correct"));
    assert!(!shown.contains(&PASSWORD.len().to_string()));
    let pretty = format!("{secret:#?}");
    assert_eq!(pretty, "Secret(<redacted>)");
}

#[test]
fn secret_is_zeroize_on_drop() {
    assert_zeroize_on_drop::<Secret>();
}

#[test]
fn explicit_zeroize_wipes_every_octet() {
    let mut secret = Secret::from_slice(PASSWORD);
    assert_eq!(secret.expose(), PASSWORD);
    assert_eq!(secret.len(), PASSWORD.len());
    assert!(!secret.is_empty());
    secret.zeroize();
    assert!(secret.expose().iter().all(|octet| *octet == 0));
}

#[test]
fn secret_moves_in_and_out_of_zeroizing_buffers_without_a_copy() {
    let buffer = Zeroizing::new(PASSWORD.to_vec());
    let address = buffer.as_ptr();
    let secret = Secret::from_zeroizing(buffer);
    assert_eq!(secret.expose().as_ptr(), address);
    let back = secret.into_zeroizing();
    assert_eq!(back.as_ptr(), address);
    assert_eq!(back.as_slice(), PASSWORD);
}

#[test]
fn a_decoded_message_holds_its_secret_in_a_secret() {
    let store = full_store();
    let frame = encode_frame(SAMPLE, Direction::Request, &SampleRequest::Store(store)).unwrap();
    let decoded: SampleRequest =
        ipc::decode_body(SAMPLE, Direction::Request, frame.body()).unwrap();
    let shown = format!("{decoded:?}");
    assert!(shown.contains("Secret(<redacted>)"), "{shown}");
    assert!(!shown.contains("correct"), "{shown}");
    match decoded {
        SampleRequest::Store(store) => assert_eq!(store.password.expose(), PASSWORD),
        SampleRequest::Lookup(_) => panic!("wrong kind"),
    }
}

#[test]
fn diagnostic_output_never_prints_payload_octets() {
    let store = full_store();
    let frame = encode_frame(SAMPLE, Direction::Request, &SampleRequest::Store(store)).unwrap();
    // The frame holds the password octets ...
    assert!(frame
        .as_bytes()
        .windows(PASSWORD.len())
        .any(|w| w == PASSWORD));
    // ... but no Debug output of a frame-holding type shows octets.
    let mut outputs = vec![format!("{frame:?}")];
    let status = decode_frame(frame.as_bytes(), common::REQUEST_LIMIT).unwrap();
    assert!(matches!(status, FrameStatus::Complete { .. }));
    outputs.push(format!("{status:?}"));
    let mut reader = FrameReader::new(common::REQUEST_LIMIT);
    reader.push(frame.as_bytes()).unwrap();
    outputs.push(format!("{reader:?}"));
    outputs.push(format!("{:?}", Reader::new(frame.body())));
    let mut writer = Writer::new(common::REQUEST_LIMIT);
    writer.write_bytes(PASSWORD, 64).unwrap();
    outputs.push(format!("{writer:?}"));
    outputs.push(format!("{:?}", DerBlob::from_slice(PASSWORD)));
    for shown in &outputs {
        assert!(!shown.contains("99, 111"), "{shown}"); // 'c', 'o' as numbers
        assert!(!shown.contains("correct"), "{shown}");
        assert!(!shown.contains("[0, 0"), "{shown}");
    }
    assert_eq!(
        outputs[0],
        format!("EncodedFrame {{ len: {} }}", frame.len())
    );
    assert_eq!(outputs[5], "DerBlob { len: 13 }");
}
