//! Wrap tokens without confidentiality — one test per statement of RFC 4121
//! §2, §4.2.2–§4.2.6.2, §4.4 / §6 that the codec enforces, the rotation
//! example of §4.2.5, and the docs/60 §10.1 rows for these sections
//! (profile: Q-1093 items 4, 6; RFC 4752 §3.1–§3.3).
//!
//! Tokens are built by hand from the RFC 4121 §4.2.6.2 layout
//! (`common::wrap_header`); checksums are stand-in octets — no checksum is
//! computed in this crate (docs/60 §3.3).

mod common;

use common::*;
use core::num::NonZeroU16;
use gss_token::{
    Error, OutgoingWrapToken, ReceivedWrapToken, Sender, WrapExpectation, WrapHeader,
    FLAG_ACCEPTOR_SUBKEY, FLAG_SEALED, FLAG_SENT_BY_ACCEPTOR, MAX_WRAP_TOKEN_LEN, WRAP_FILLER,
    WRAP_TOK_ID,
};

/// A stand-in checksum length (the AES-SHA1 enctypes' is 12 octets; the
/// value is the caller's input here).
const CKSUM_LEN: u16 = 12;

fn cksum_len(n: u16) -> NonZeroU16 {
    NonZeroU16::new(n).unwrap()
}

/// What keyd expects of the client's selection (docs/60 §3.4): from the
/// initiator, AcceptorSubkey set (Q-1093 item 4), EC = the checksum length.
fn selection_expectation() -> WrapExpectation {
    WrapExpectation {
        sender: Sender::Initiator,
        acceptor_subkey: true,
        checksum_len: cksum_len(CKSUM_LEN),
    }
}

/// A selection-shaped token: flags AcceptorSubkey (initiator), the RFC 4752
/// §3.2 selection 01 00 00 00 as plaintext, a stand-in checksum, RRC = 0.
fn selection_token(snd_seq: u64) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let plaintext = vec![0x01, 0x00, 0x00, 0x00];
    let checksum: Vec<u8> = (0..CKSUM_LEN as u8).map(|i| 0xC0 | i).collect();
    let header = wrap_header(FLAG_ACCEPTOR_SUBKEY, CKSUM_LEN, 0, snd_seq);
    let mut data = plaintext.clone();
    data.extend_from_slice(&checksum);
    (wrap_token(header, &data), plaintext, checksum)
}

// ---------------------------------------------------------------------------
// RFC 4121 §4.2.6.2 / §4.2.2 — the header, structurally
// ---------------------------------------------------------------------------

/// RFC 4121 §4.2.6.2: TOK_ID 05 04, Filler FF; RFC 4121 §4.2.2: the three
/// flag bits.
#[test]
fn constants_are_those_of_rfc4121() {
    assert_eq!(WRAP_TOK_ID, [0x05, 0x04]);
    assert_eq!(WRAP_FILLER, 0xFF);
    assert_eq!(
        [FLAG_SENT_BY_ACCEPTOR, FLAG_SEALED, FLAG_ACCEPTOR_SUBKEY],
        [1 << 0, 1 << 1, 1 << 2]
    );
}

/// RFC 4121 §4.2.6.2: the header fields at their octets, EC / RRC / SND_SEQ
/// big-endian.
#[test]
fn the_header_reads_every_field_big_endian() {
    let header = wrap_header(0x05, 0x0102, 0x0304, 0x0506_0708_090A_0B0C);
    let read = WrapHeader::read(&header).unwrap();
    assert_eq!(read.flags(), 0x05);
    assert_eq!(read.sender(), Sender::Acceptor);
    assert!(!read.sealed());
    assert!(read.acceptor_subkey());
    assert_eq!(read.ec(), 0x0102);
    assert_eq!(read.rrc(), 0x0304);
    assert_eq!(read.snd_seq(), 0x0506_0708_090A_0B0C);
    assert_eq!(read.octets(), header);
}

/// RFC 4121 §4.2.6.2: fewer than 16 octets is no header.
#[test]
fn a_token_shorter_than_the_header_is_refused() {
    let header = wrap_header(0x04, CKSUM_LEN, 0, 1);
    for len in 0..16 {
        assert_eq!(
            WrapHeader::read(&header[..len]),
            Err(Error::Truncated),
            "{len}"
        );
        assert_eq!(
            ReceivedWrapToken::parse(&header[..len], selection_expectation()),
            Err(Error::Truncated)
        );
    }
}

/// RFC 4121 §4.4 / §6: a first octet 0x60 marks the generic framing of the
/// older format ⇒ refused (docs/60 §3.4).
#[test]
fn a_framed_token_is_refused() {
    let mut token = wrap_header(0x04, CKSUM_LEN, 0, 1).to_vec();
    token[0] = 0x60;
    for second in [0x00, 0x04, 0xFF] {
        token[1] = second;
        assert_eq!(WrapHeader::read(&token), Err(Error::FramedToken));
    }
}

/// RFC 4121 §4.2.6.2: TOK_ID other than 05 04 — the MIC token's 04 04, the
/// context tokens' 01 00 / 02 00, octet-swapped 04 05 — ⇒ refused.
#[test]
fn a_tok_id_other_than_05_04_is_refused() {
    for tok_id in [
        [0x04, 0x04],
        [0x01, 0x00],
        [0x02, 0x00],
        [0x04, 0x05],
        [0x05, 0x05],
    ] {
        let mut token = wrap_header(0x04, CKSUM_LEN, 0, 1).to_vec();
        token[0..2].copy_from_slice(&tok_id);
        assert_eq!(
            WrapHeader::read(&token),
            Err(Error::NotWrapToken),
            "{tok_id:02x?}"
        );
    }
}

/// RFC 4121 §4.2.6.2: the Filler "Contains the hex value FF".
#[test]
fn a_filler_other_than_ff_is_refused() {
    for filler in [0x00, 0xFE, 0x7F] {
        let mut token = wrap_header(0x04, CKSUM_LEN, 0, 1).to_vec();
        token[3] = filler;
        assert_eq!(WrapHeader::read(&token), Err(Error::BadFiller));
    }
}

// ---------------------------------------------------------------------------
// The profile — Sealed, direction, AcceptorSubkey, EC, bound
// ---------------------------------------------------------------------------

/// docs/60 §10.1 row RFC 4752 §3.2, §3.3: Sealed = 1 ⇒ refused (the selection
/// is wrapped with conf_flag FALSE, RFC 4752 §3.1; Q-1093 item 6).
#[test]
fn a_sealed_token_is_refused() {
    let (mut token, _, _) = selection_token(7);
    token[2] |= FLAG_SEALED;
    assert_eq!(
        ReceivedWrapToken::parse(&token, selection_expectation()),
        Err(Error::Sealed)
    );
}

/// RFC 4121 §4.2.2: the direction indicator — a token whose SentByAcceptor
/// flag names the other sender is refused, both ways. docs/60 §10.1 row
/// RFC 4121 §4.2.2 / §9 K12: the server's offer sent back as the selection
/// fails here.
#[test]
fn the_direction_flag_must_name_the_expected_sender() {
    let (mut token, _, _) = selection_token(7);
    token[2] |= FLAG_SENT_BY_ACCEPTOR;
    assert_eq!(
        ReceivedWrapToken::parse(&token, selection_expectation()),
        Err(Error::DirectionMismatch)
    );
    let (token, _, _) = selection_token(7);
    let from_acceptor = WrapExpectation {
        sender: Sender::Acceptor,
        ..selection_expectation()
    };
    assert_eq!(
        ReceivedWrapToken::parse(&token, from_acceptor),
        Err(Error::DirectionMismatch)
    );
}

/// docs/60 §10.1 / K12: the offer built for the client (from the acceptor),
/// reflected as the client's selection ⇒ refused by the direction flag.
#[test]
fn a_reflected_offer_is_refused() {
    let offer = OutgoingWrapToken::new(
        Sender::Acceptor,
        true,
        99,
        &[0x01, 0x00, 0x00, 0x00],
        cksum_len(CKSUM_LEN),
    )
    .unwrap()
    .finish(&[0xAA; CKSUM_LEN as usize])
    .unwrap();
    assert_eq!(
        ReceivedWrapToken::parse(&offer, selection_expectation()),
        Err(Error::DirectionMismatch)
    );
}

/// RFC 4121 §2: when the acceptor asserted a subkey, tokens "MUST be flagged
/// with AcceptorSubkey" — the flag must match the caller's knowledge, both
/// ways (Q-1093 item 4).
#[test]
fn the_acceptor_subkey_flag_must_match() {
    let (mut token, _, _) = selection_token(7);
    token[2] &= !FLAG_ACCEPTOR_SUBKEY;
    assert_eq!(
        ReceivedWrapToken::parse(&token, selection_expectation()),
        Err(Error::AcceptorSubkeyMismatch)
    );
    let (token, _, _) = selection_token(7);
    let no_subkey = WrapExpectation {
        acceptor_subkey: false,
        ..selection_expectation()
    };
    assert_eq!(
        ReceivedWrapToken::parse(&token, no_subkey),
        Err(Error::AcceptorSubkeyMismatch)
    );
}

/// RFC 4121 §4.2.3: without confidentiality EC is "the number of octets in
/// the trailing checksum" ⇒ EC ≠ the caller's checksum length is refused.
#[test]
fn ec_must_equal_the_checksum_length() {
    for ec in [0u16, CKSUM_LEN - 1, CKSUM_LEN + 1, 16, u16::MAX] {
        let mut token = selection_token(7).0;
        token[4..6].copy_from_slice(&ec.to_be_bytes());
        assert_eq!(
            ReceivedWrapToken::parse(&token, selection_expectation()),
            Err(Error::EcMismatch),
            "EC {ec}"
        );
    }
}

/// RFC 4121 §4.2.4: the data must hold the EC-octet checksum.
#[test]
fn data_shorter_than_ec_is_refused() {
    let header = wrap_header(FLAG_ACCEPTOR_SUBKEY, CKSUM_LEN, 0, 7);
    for len in 0..CKSUM_LEN as usize {
        assert_eq!(
            ReceivedWrapToken::parse(
                &wrap_token(header, &vec![0u8; len]),
                selection_expectation()
            ),
            Err(Error::WrapBodyTooShort),
            "{len} data octets"
        );
    }
    // Exactly EC octets: an empty plaintext and the checksum.
    let token = wrap_token(header, &[0x5A; CKSUM_LEN as usize]);
    let received = ReceivedWrapToken::parse(&token, selection_expectation()).unwrap();
    assert_eq!(received.checksum(), &[0x5A; CKSUM_LEN as usize]);
}

/// docs/60 R60-11: a Wrap token over 1 KiB ⇒ refused (before the rotation is
/// undone); exactly 1 KiB is accepted. The builder refuses the same bound.
#[test]
fn the_1_kib_bound_holds_both_ways() {
    let header = wrap_header(FLAG_ACCEPTOR_SUBKEY, CKSUM_LEN, 0, 7);
    let exact = wrap_token(header, &vec![0x11; MAX_WRAP_TOKEN_LEN - 16]);
    assert!(ReceivedWrapToken::parse(&exact, selection_expectation()).is_ok());
    let over = wrap_token(header, &vec![0x11; MAX_WRAP_TOKEN_LEN - 15]);
    assert_eq!(
        ReceivedWrapToken::parse(&over, selection_expectation()),
        Err(Error::WrapTokenTooLong)
    );
    let fits = vec![0x22; MAX_WRAP_TOKEN_LEN - 16 - CKSUM_LEN as usize];
    assert!(OutgoingWrapToken::new(Sender::Acceptor, true, 1, &fits, cksum_len(CKSUM_LEN)).is_ok());
    let too_big = vec![0x22; MAX_WRAP_TOKEN_LEN - 15 - CKSUM_LEN as usize];
    assert_eq!(
        OutgoingWrapToken::new(Sender::Acceptor, true, 1, &too_big, cksum_len(CKSUM_LEN)),
        Err(Error::WrapTokenTooLong)
    );
}

/// RFC 4121 §4.2.2: "The receiver MUST ignore unknown flags" — bits 3–7 set
/// do not change the outcome, and stay in the checksummed header (so the
/// checksum covers exactly what was sent).
#[test]
fn unknown_flags_are_ignored_and_kept_in_the_checksum_header() {
    let (mut token, plaintext, checksum) = selection_token(7);
    token[2] |= 0xF8;
    let received = ReceivedWrapToken::parse(&token, selection_expectation()).unwrap();
    assert_eq!(received.header().flags(), FLAG_ACCEPTOR_SUBKEY | 0xF8);
    let mut expected_input = plaintext;
    expected_input.extend_from_slice(&wrap_header(FLAG_ACCEPTOR_SUBKEY | 0xF8, 0, 0, 7));
    assert_eq!(received.checksum_input(), &expected_input[..]);
    assert_eq!(received.checksum(), &checksum[..]);
}

// ---------------------------------------------------------------------------
// RFC 4121 §4.2.4 — the octets to MAC; release only after verification
// ---------------------------------------------------------------------------

/// RFC 4121 §4.2.4: the checksum is "calculated first over the to-be-signed
/// plaintext data, and then over the first 16 octets of the Wrap token", with
/// "Both the EC field and the RRC field ... filled with zeroes". The parsed
/// token lays out exactly that, and the trailing EC octets as the checksum;
/// SND_SEQ is returned for keyd's comparison (Q-1093 item 7).
#[test]
fn the_checksum_input_is_plaintext_then_header_with_ec_and_rrc_zeroed() {
    let (token, plaintext, checksum) = selection_token(0x0102_0304);
    let received = ReceivedWrapToken::parse(&token, selection_expectation()).unwrap();
    let mut expected_input = plaintext.clone();
    expected_input.extend_from_slice(&wrap_header(FLAG_ACCEPTOR_SUBKEY, 0, 0, 0x0102_0304));
    assert_eq!(received.checksum_input(), &expected_input[..]);
    assert_eq!(received.checksum(), &checksum[..]);
    assert_eq!(received.snd_seq(), 0x0102_0304);
    assert_eq!(received.header().ec(), CKSUM_LEN);
}

/// RFC 4121 §4.2.4; RFC 4752 §3 (a failed GSS_Unwrap fails the exchange):
/// the plaintext is released only when the caller's verification of exactly
/// (checksum input, checksum) succeeds.
#[test]
fn the_plaintext_is_released_only_after_verification() {
    let (token, plaintext, checksum) = selection_token(5);
    let received = ReceivedWrapToken::parse(&token, selection_expectation()).unwrap();
    let expected_input = received.checksum_input().to_vec();
    let released = received
        .clone()
        .into_verified_plaintext(|input, mac| {
            assert_eq!(input, &expected_input[..]);
            assert_eq!(mac, &checksum[..]);
            true
        })
        .unwrap();
    assert_eq!(released, plaintext);
    assert_eq!(
        received.into_verified_plaintext(|_, _| false),
        Err(Error::ChecksumMismatch)
    );
}

// ---------------------------------------------------------------------------
// RFC 4121 §4.2.5 — RRC
// ---------------------------------------------------------------------------

/// docs/60 §10.1 row RFC 4121 §4.2.5 — the rotation example of the section:
/// RRC = 3 and the token {"header" | aa | bb | cc | dd | ee | ff | gg | hh}
/// is sent as {"header" | ff | gg | hh | aa | bb | cc | dd | ee}. With EC = 3
/// here, undoing the rotation yields plaintext {aa … ee} and checksum
/// {ff gg hh}. (Octet values stand for the letters.)
#[test]
fn rfc4121_section_4_2_5_rotation_example() {
    let (aa, bb, cc, dd, ee, ff, gg, hh) = (0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x99, 0x88);
    let header = wrap_header(FLAG_ACCEPTOR_SUBKEY, 3, 3, 1);
    let token = wrap_token(header, &[ff, gg, hh, aa, bb, cc, dd, ee]);
    let expectation = WrapExpectation {
        checksum_len: cksum_len(3),
        ..selection_expectation()
    };
    let received = ReceivedWrapToken::parse(&token, expectation).unwrap();
    assert_eq!(received.checksum(), &[ff, gg, hh]);
    let plaintext = received.into_verified_plaintext(|_, _| true).unwrap();
    assert_eq!(plaintext, vec![aa, bb, cc, dd, ee]);
}

/// RFC 4121 §4.2.5: "The receiver MUST be able to interpret all possible
/// rotation count values, including rotation counts greater than the length
/// of the token" — RRC = 3 + k·8 reads like RRC = 3 for the 8 data octets of
/// the example, RRC = 8·k like no rotation, up to the largest RRC.
#[test]
fn rotation_counts_greater_than_the_length_are_interpreted() {
    let data_rotated_by_3 = [0xF0, 0x99, 0x88, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let data_unrotated = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x99, 0x88];
    let expectation = WrapExpectation {
        checksum_len: cksum_len(3),
        ..selection_expectation()
    };
    let read = |rrc: u16, data: &[u8]| {
        let token = wrap_token(wrap_header(FLAG_ACCEPTOR_SUBKEY, 3, rrc, 1), data);
        ReceivedWrapToken::parse(&token, expectation)
            .unwrap()
            .into_verified_plaintext(|_, _| true)
            .unwrap()
    };
    let expected = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    for rrc in [3u16, 11, 19, 803, 65_531] {
        // 65_531 = 8 · 8191 + 3.
        assert_eq!(read(rrc, &data_rotated_by_3), expected, "RRC {rrc}");
    }
    for rrc in [0u16, 8, 16, 1000, 65_528] {
        assert_eq!(read(rrc, &data_unrotated), expected, "RRC {rrc}");
    }
}

// ---------------------------------------------------------------------------
// Building — the offer (docs/60 §3.4 step 6)
// ---------------------------------------------------------------------------

/// docs/60 §10.1 rows RFC 4121 §2, §4.2.2, §4.2.4, §4.2.6.2 and RFC 4752
/// §3.2, §3.3: the offer = data 01 00 00 00 ("1 No security layer", max 0),
/// Flags = SentByAcceptor + AcceptorSubkey, Filler FF, EC = the checksum
/// length, RRC = 0, SND_SEQ = the acceptor's sequence number; the checksum
/// input is data ‖ header with EC = RRC = 0; the token is header ‖ data ‖
/// checksum.
#[test]
fn the_offer_is_built_as_docs60_specifies() {
    let offer_data = [0x01, 0x00, 0x00, 0x00];
    let pending = OutgoingWrapToken::new(
        Sender::Acceptor,
        true,
        0x00AB_CDEF,
        &offer_data,
        cksum_len(CKSUM_LEN),
    )
    .unwrap();
    let header = pending.header();
    assert_eq!(header.flags(), FLAG_SENT_BY_ACCEPTOR | FLAG_ACCEPTOR_SUBKEY);
    assert!(!header.sealed());
    assert_eq!(
        (header.ec(), header.rrc(), header.snd_seq()),
        (CKSUM_LEN, 0, 0x00AB_CDEF)
    );
    let mut expected_input = offer_data.to_vec();
    expected_input.extend_from_slice(&wrap_header(0x05, 0, 0, 0x00AB_CDEF));
    assert_eq!(pending.checksum_input(), &expected_input[..]);
    let checksum = [0x3C; CKSUM_LEN as usize];
    let token = pending.finish(&checksum).unwrap();
    let mut expected = wrap_header(0x05, CKSUM_LEN, 0, 0x00AB_CDEF).to_vec();
    expected.extend_from_slice(&offer_data);
    expected.extend_from_slice(&checksum);
    assert_eq!(token, expected);
}

/// RFC 4121 §4.2.3, §4.2.4: the checksum handed back must be EC octets.
#[test]
fn finishing_with_a_checksum_of_another_length_is_refused() {
    for len in [0usize, 1, CKSUM_LEN as usize - 1, CKSUM_LEN as usize + 1] {
        let pending = OutgoingWrapToken::new(
            Sender::Acceptor,
            true,
            1,
            &[1, 0, 0, 0],
            cksum_len(CKSUM_LEN),
        )
        .unwrap();
        assert_eq!(
            pending.finish(&vec![0u8; len]),
            Err(Error::ChecksumLengthMismatch),
            "{len}"
        );
    }
}

/// RFC 4121 §4.2.2 ("reserved ... MUST be cleared"); docs/60 §9 K13 (no
/// confidentiality): every token built has Sealed and the reserved bits
/// clear, whatever the inputs.
#[test]
fn no_built_token_is_sealed_or_carries_reserved_bits() {
    for sender in [Sender::Initiator, Sender::Acceptor] {
        for subkey in [false, true] {
            let pending =
                OutgoingWrapToken::new(sender, subkey, 3, &[1, 0, 0, 0], cksum_len(CKSUM_LEN))
                    .unwrap();
            let flags = pending.header().flags();
            assert_eq!(flags & !(FLAG_SENT_BY_ACCEPTOR | FLAG_ACCEPTOR_SUBKEY), 0);
            assert_eq!(pending.header().sender(), sender);
            assert_eq!(pending.header().acceptor_subkey(), subkey);
        }
    }
}

/// Round trip: a selection built from the initiator side (as a test client
/// would, docs/60 §10 LE1) parses back by the profile to the same plaintext,
/// checksum input and checksum.
#[test]
fn a_built_selection_parses_back() {
    let selection = [0x01, 0x00, 0x00, 0x00];
    let pending = OutgoingWrapToken::new(
        Sender::Initiator,
        true,
        42,
        &selection,
        cksum_len(CKSUM_LEN),
    )
    .unwrap();
    let input = pending.checksum_input().to_vec();
    let checksum = [0x77; CKSUM_LEN as usize];
    let token = pending.finish(&checksum).unwrap();
    let received = ReceivedWrapToken::parse(&token, selection_expectation()).unwrap();
    assert_eq!(received.checksum_input(), &input[..]);
    assert_eq!(received.checksum(), &checksum);
    assert_eq!(received.snd_seq(), 42);
    assert_eq!(
        received.into_verified_plaintext(|_, _| true).unwrap(),
        selection.to_vec()
    );
}

/// docs/CLEAN-ROOM.md: `Debug` of a received token shows the header and lengths,
/// not the plaintext octets.
#[test]
fn debug_shows_no_data_octets() {
    let header = wrap_header(FLAG_ACCEPTOR_SUBKEY, CKSUM_LEN, 0, 7);
    let mut data = b"dn:secret".to_vec();
    data.extend_from_slice(&[0u8; CKSUM_LEN as usize]);
    let received =
        ReceivedWrapToken::parse(&wrap_token(header, &data), selection_expectation()).unwrap();
    let shown = format!("{received:?}");
    assert!(shown.contains("plaintext_len: 9"), "{shown}");
    assert!(!shown.contains("100, 110"), "{shown}"); // 'd', 'n'
}
