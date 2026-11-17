//! The authenticator checksum — one test per statement of RFC 4121 §4.1.1,
//! §4.1.1.1, §4.1.1.2 and RFC 4120 §5.5.1 that the parser enforces, and per
//! entry of the docs/60 §10.1 rows for these sections (profile: Q-1093
//! items 1, 2, 3, 5; docs/60 R60-1).
//!
//! Checksum fields are built by hand from the RFC 4121 §4.1.1 layout
//! (`common::checksum`); the RFC has no example octets.

mod common;

use common::*;
use gss_token::{
    AuthenticatorChecksum, ChecksumField, Error, GSS_CHECKSUM_TYPE, GSS_C_CONF_FLAG,
    GSS_C_DELEG_FLAG, GSS_C_INTEG_FLAG, GSS_C_MUTUAL_FLAG, GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG,
    MAX_CONTEXT_TOKEN_LEN,
};

fn field(checksum: &[u8]) -> Option<ChecksumField<'_>> {
    Some(ChecksumField {
        cksumtype: GSS_CHECKSUM_TYPE,
        checksum,
    })
}

fn accept(checksum: &[u8]) -> Result<AuthenticatorChecksum, Error> {
    AuthenticatorChecksum::from_authenticator(field(checksum), Some(0x0102_0304))
}

/// RFC 4121 §4.1.1.1: the flag values, as RFC 4121 lists them from RFC 2744.
#[test]
fn flag_values_are_those_of_rfc4121_4_1_1_1() {
    assert_eq!(
        [
            GSS_C_DELEG_FLAG,
            GSS_C_MUTUAL_FLAG,
            GSS_C_REPLAY_FLAG,
            GSS_C_SEQUENCE_FLAG,
            GSS_C_CONF_FLAG,
            GSS_C_INTEG_FLAG
        ],
        [1, 2, 4, 8, 16, 32]
    );
    // RFC 4121 §4.1.1: "The checksum type MUST be 0x8003."
    assert_eq!(GSS_CHECKSUM_TYPE, 0x8003);
}

/// RFC 4121 §4.1.1: Lgth = 16 ‖ Bnd ‖ Flags, 24 octets, with INTEG and
/// MUTUAL (Q-1093 items 1, 2) and a non-zero Bnd ⇒ accepted; the Bnd, the
/// flags and the Authenticator's seq-number come back.
#[test]
fn a_well_formed_checksum_is_accepted() {
    let c = checksum(16, BND, INTEG_MUTUAL, &[]);
    assert_eq!(c.len(), 24);
    let accepted = accept(&c).unwrap();
    assert_eq!(accepted.bnd().octets(), &BND);
    assert_eq!(accepted.flags().bits(), INTEG_MUTUAL);
    assert!(accepted.flags().integ() && accepted.flags().mutual());
    assert!(!accepted.flags().deleg());
    assert_eq!(accepted.initiator_seq_number(), 0x0102_0304);
}

/// RFC 4121 §4.1.1: Lgth and Flags are little-endian. The same flag value
/// written big-endian reads as other bits (here: none of INTEG / MUTUAL), and
/// Lgth 16 written big-endian is not 16.
#[test]
fn lgth_and_flags_are_little_endian() {
    let mut c = checksum(16, BND, 0, &[]);
    c[20..24].copy_from_slice(&INTEG_MUTUAL.to_be_bytes());
    assert_eq!(accept(&c), Err(Error::IntegFlagMissing));
    let mut c = checksum(16, BND, INTEG_MUTUAL, &[]);
    c[0..4].copy_from_slice(&16u32.to_be_bytes());
    assert_eq!(accept(&c), Err(Error::LgthNot16));
}

/// docs/60 §10.1 row RFC 4121 §4.1.1: no cksum ⇒ refused ("MUST include ...
/// the checksum field").
#[test]
fn an_authenticator_without_cksum_is_refused() {
    assert_eq!(
        AuthenticatorChecksum::from_authenticator(None, Some(1)),
        Err(Error::MissingChecksum)
    );
}

/// docs/60 §10.1 row RFC 4121 §4.1.1: no seq-number ⇒ refused ("MUST include
/// the optional sequence number"), although RFC 4120 §5.5.1 lets an
/// implementation accept an omitted one as zero (Q-1093 item 5).
#[test]
fn an_authenticator_without_seq_number_is_refused() {
    let c = checksum(16, BND, INTEG_MUTUAL, &[]);
    assert_eq!(
        AuthenticatorChecksum::from_authenticator(field(&c), None),
        Err(Error::MissingSequenceNumber)
    );
    // Zero is a value like any other once present.
    let accepted = AuthenticatorChecksum::from_authenticator(field(&c), Some(0)).unwrap();
    assert_eq!(accepted.initiator_seq_number(), 0);
}

/// docs/60 §10.1 row RFC 4121 §4.1.1: type ≠ 0x8003 ⇒ refused — including
/// the octet-swapped value and negative values.
#[test]
fn a_checksum_type_other_than_0x8003_is_refused() {
    let c = checksum(16, BND, INTEG_MUTUAL, &[]);
    for cksumtype in [0, 1, 0x8002, 0x8004, 0x0380, -0x8003, i32::MIN, i32::MAX] {
        assert_eq!(
            AuthenticatorChecksum::from_authenticator(
                Some(ChecksumField {
                    cksumtype,
                    checksum: &c
                }),
                Some(1)
            ),
            Err(Error::WrongChecksumType),
            "cksumtype {cksumtype:#x}"
        );
    }
}

/// docs/60 §10.1 row RFC 4121 §4.1.1: length < 24 ⇒ refused ("MUST be at
/// least 24 octets when GSS_C_DELEG_FLAG is not set").
#[test]
fn a_checksum_shorter_than_24_octets_is_refused() {
    let c = checksum(16, BND, INTEG_MUTUAL, &[]);
    for len in 0..24 {
        assert_eq!(
            accept(&c[..len]),
            Err(Error::ChecksumTooShort),
            "length {len}"
        );
    }
}

/// docs/60 §10.1 row RFC 4121 §4.1.1: Lgth ≠ 16 ⇒ refused ("Currently
/// contains hex value 10 00 00 00 (16)").
#[test]
fn lgth_other_than_16_is_refused() {
    for lgth in [0u32, 1, 15, 17, 32, 0x1000_0000, u32::MAX] {
        assert_eq!(
            accept(&checksum(lgth, BND, INTEG_MUTUAL, &[])),
            Err(Error::LgthNot16),
            "Lgth {lgth}"
        );
    }
}

/// docs/60 §10.1 row RFC 4121 §4.1.1: Exts are ignored — "Acceptors that do
/// not understand the Extensions MUST ignore any octets past ... the Flags
/// field" (DELEG clear: Exts start at octet 24). Any trailing octets, the
/// result unchanged.
#[test]
fn extensions_past_the_flags_are_ignored() {
    let plain = accept(&checksum(16, BND, INTEG_MUTUAL, &[])).unwrap();
    for exts in [
        &[0x00u8][..],
        &[0xFF; 4][..],
        &[0x01, 0x00, 0x10, 0x00][..],
        &[0xAB; 4096][..],
    ] {
        assert_eq!(
            accept(&checksum(16, BND, INTEG_MUTUAL, exts)),
            Ok(plain),
            "{} octets of Exts",
            exts.len()
        );
    }
}

/// docs/60 §10.1 row RFC 4121 §4.1.1.1: DELEG ⇒ refused (no KRB_CRED path;
/// Q-1093 item 3) — with or without the DlgOpt/Dlgth/Deleg octets it implies.
#[test]
fn delegation_is_refused() {
    let flags = INTEG_MUTUAL | GSS_C_DELEG_FLAG;
    assert_eq!(
        accept(&checksum(16, BND, flags, &[])),
        Err(Error::DelegationRefused)
    );
    // DlgOpt = 1 and Dlgth = 2 (little-endian), then two Deleg octets.
    let deleg = [0x01, 0x00, 0x02, 0x00, 0x76, 0x00];
    assert_eq!(
        accept(&checksum(16, BND, flags, &deleg)),
        Err(Error::DelegationRefused)
    );
}

/// docs/60 §10.1 row RFC 4121 §4.1.1.1: no INTEG ⇒ refused (RFC 4752 §3.1:
/// the client MUST pass integ_req_flag TRUE; Q-1093 item 2).
#[test]
fn a_checksum_without_integ_is_refused() {
    assert_eq!(
        accept(&checksum(16, BND, GSS_C_MUTUAL_FLAG, &[])),
        Err(Error::IntegFlagMissing)
    );
}

/// docs/60 §10.1 row RFC 4121 §4.1.1.1: no MUTUAL ⇒ refused (Q-1093 item 1).
#[test]
fn a_checksum_without_mutual_is_refused() {
    assert_eq!(
        accept(&checksum(16, BND, GSS_C_INTEG_FLAG, &[])),
        Err(Error::MutualFlagMissing)
    );
}

/// docs/60 §10.1 row RFC 4121 §4.1.1.1: unknown flags are ignored ("unknown
/// flags MUST be ignored by the receiver") — the vendor range 4096..524288
/// and the reserved high bits — and kept in `bits()`.
#[test]
fn unknown_flags_are_ignored() {
    for extra in [64u32, 128, 1 << 12, 1 << 19, 1 << 20, 1 << 31, 0xFFFF_FFC0] {
        let flags = INTEG_MUTUAL | extra;
        let accepted = accept(&checksum(16, BND, flags, &[])).unwrap();
        assert_eq!(accepted.flags().bits(), flags, "extra {extra:#x}");
    }
}

/// RFC 4752 §3.1: REPLAY, SEQUENCE and CONF are requested by a client only
/// for a security layer, and none is offered — the profile neither requires
/// nor refuses them (docs/questions/Q-1110).
#[test]
fn replay_sequence_and_conf_are_neither_required_nor_refused() {
    let with = INTEG_MUTUAL | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_CONF_FLAG;
    let accepted = accept(&checksum(16, BND, with, &[])).unwrap();
    assert!(accepted.flags().replay() && accepted.flags().sequence() && accepted.flags().conf());
    let without = accept(&checksum(16, BND, INTEG_MUTUAL, &[])).unwrap();
    assert!(!without.flags().replay() && !without.flags().sequence() && !without.flags().conf());
}

/// docs/60 §10.1 row RFC 4121 §4.1.1.2 (3): Bnd = 16 zero octets (the value
/// for GSS_C_NO_BINDINGS) ⇒ refused — channel binding is mandatory
/// (docs/60 R60-1). One non-zero octet anywhere is a binding.
#[test]
fn bnd_of_sixteen_zero_octets_is_refused() {
    assert_eq!(
        accept(&checksum(16, [0; 16], INTEG_MUTUAL, &[])),
        Err(Error::NoChannelBindings)
    );
    for at in 0..16 {
        let mut bnd = [0u8; 16];
        bnd[at] = 1;
        assert!(
            accept(&checksum(16, bnd, INTEG_MUTUAL, &[])).is_ok(),
            "octet {at}"
        );
    }
}

/// docs/60 R60-11 / docs/CLEAN-ROOM.md: a checksum field longer than a token can
/// hold ⇒ refused.
#[test]
fn a_checksum_longer_than_a_token_is_refused() {
    let c = checksum(16, BND, INTEG_MUTUAL, &vec![0u8; MAX_CONTEXT_TOKEN_LEN]);
    assert_eq!(accept(&c), Err(Error::ChecksumTooLong));
}

/// docs/60 §7 / docs/CLEAN-ROOM.md: `Debug` of the Bnd shows no octet.
#[test]
fn debug_shows_no_bnd_octets() {
    let accepted = accept(&checksum(16, BND, INTEG_MUTUAL, &[])).unwrap();
    let shown = format!("{accepted:?}");
    assert!(shown.contains("Bnd(<16 octets>)"), "{shown}");
    for needle in ["17", "34", "51", "238"] {
        assert!(!shown.contains(&format!(" {needle},")), "{shown}");
    }
}
