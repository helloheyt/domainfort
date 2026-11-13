//! Test vectors for the Kerberos AES encryption and checksum profile.
//!
//! Every vector names its source. Sources are allowed per AGENTS.md §3/§4.5:
//! RFC 3961 Appendix A.1 (n-fold), RFC 3962 Appendix B (PBKDF2 string-to-key
//! with DK), RFC 8009 Appendix A (string-to-key, key derivation, sample
//! encryptions, sample checksums, PRF) and RFC 6113 Appendix A (KRB-FX-CF2).
//! Rejection tests are derived from the named clauses. No vector comes from
//! any other implementation's test suite.
//!
//! The RFC 3962 Appendix B ciphertext-stealing vectors and the RFC 8009
//! Appendix A "AES Output" values exercise crate-private functions and live
//! in the unit tests of `src/cts.rs`.

use krb_crypto::{
    decrypt, derive_key, encrypt, get_mic, iteration_count, krb_fx_cf2, n_fold, pseudo_random,
    random_to_key, string_to_key, verify_mic, ChecksumType, EncType, Error, KeyUsage, ProtocolKey,
    SpecificKeyKind,
};

/// Parse whitespace-separated hex (as printed in the RFCs) into octets.
fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    assert!(s.len().is_multiple_of(2), "odd hex length in test vector");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex16(s: &str) -> [u8; 16] {
    hex(s).try_into().expect("16 octets")
}

fn usage(n: u32) -> KeyUsage {
    KeyUsage::new(n).expect("non-zero usage")
}

/// Iteration count as the four-octet big-endian s2kparams block.
/// Spec: RFC 3962 §4.
fn s2kparams(iterations: u32) -> [u8; 4] {
    iterations.to_be_bytes()
}

// ---------------------------------------------------------------------------
// RFC 3961 Appendix A.1 — n-fold
// ---------------------------------------------------------------------------

#[test]
fn rfc3961_a1_nfold_64_012345() {
    // Source: RFC 3961 A.1 — 64-fold("012345") = be072631276b1955.
    assert_eq!(hex("303132333435"), b"012345");
    assert_eq!(n_fold(b"012345", 8).unwrap(), hex("be072631276b1955"));
}

#[test]
fn rfc3961_a1_nfold_56_password() {
    // Source: RFC 3961 A.1 — 56-fold("password") = 78a07b6caf85fa.
    assert_eq!(n_fold(b"password", 7).unwrap(), hex("78a07b6caf85fa"));
}

#[test]
fn rfc3961_a1_nfold_64_rough_consensus() {
    // Source: RFC 3961 A.1 — 64-fold("Rough Consensus, and Running Code").
    let input = b"Rough Consensus, and Running Code";
    assert_eq!(
        input.as_slice(),
        hex("526f75676820436f6e73656e7375732c20616e642052756e 6e696e6720436f6465")
    );
    assert_eq!(n_fold(input, 8).unwrap(), hex("bb6ed30870b7f0e0"));
}

#[test]
fn rfc3961_a1_nfold_168_password() {
    // Source: RFC 3961 A.1 — 168-fold("password").
    assert_eq!(
        n_fold(b"password", 21).unwrap(),
        hex("59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e")
    );
}

#[test]
fn rfc3961_a1_nfold_192_massachvsetts() {
    // Source: RFC 3961 A.1 — 192-fold("MASSACHVSETTS INSTITVTE OF TECHNOLOGY").
    let input = b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY";
    assert_eq!(
        input.as_slice(),
        hex("4d41535341434856534554545320494e5354495456544520 4f4620544543484e4f4c4f4759")
    );
    assert_eq!(
        n_fold(input, 24).unwrap(),
        hex("db3b0d8f0b061e603282b308a50841229ad798fab9540c1b")
    );
}

#[test]
fn rfc3961_a1_nfold_168_q() {
    // Source: RFC 3961 A.1 — 168-fold("Q").
    assert_eq!(
        n_fold(b"Q", 21).unwrap(),
        hex("518a54a2 15a8452a 518a54a2 15a8452a 518a54a2 15")
    );
}

#[test]
fn rfc3961_a1_nfold_168_ba() {
    // Source: RFC 3961 A.1 — 168-fold("ba").
    assert_eq!(
        n_fold(b"ba", 21).unwrap(),
        hex("fb25d531 ae897449 9f52fd92 ea9857c4 ba24cf29 7e")
    );
}

#[test]
fn rfc3961_a1_nfold_kerberos() {
    // Source: RFC 3961 A.1 — folded values of "kerberos" (64, 128, 168, 256).
    assert_eq!(n_fold(b"kerberos", 8).unwrap(), hex("6b657262 65726f73"));
    assert_eq!(
        n_fold(b"kerberos", 16).unwrap(),
        hex("6b657262 65726f73 7b9b5b2b 93132b93")
    );
    assert_eq!(
        n_fold(b"kerberos", 21).unwrap(),
        hex("8372c236 344e5f15 50cd0747 e15d62ca 7a5a3bce a4")
    );
    assert_eq!(
        n_fold(b"kerberos", 32).unwrap(),
        hex("6b657262 65726f73 7b9b5b2b 93132b93 5c9bdcda d95c9899 c4cae4de e6d6cae4")
    );
}

// ---------------------------------------------------------------------------
// RFC 3962 Appendix B — PBKDF2 HMAC-SHA1 string-to-key (with DK "kerberos")
// ---------------------------------------------------------------------------

/// Check both key sizes of one RFC 3962 Appendix B string-to-key sample.
fn check_rfc3962_s2k(passphrase: &str, salt: &str, iterations: u32, k128: &str, k256: &str) {
    let params = s2kparams(iterations);
    let key = string_to_key(
        EncType::Aes128CtsHmacSha196,
        passphrase,
        salt,
        Some(&params),
        iterations,
    )
    .unwrap();
    assert_eq!(key.enc_type(), EncType::Aes128CtsHmacSha196);
    assert_eq!(key.octets(), hex(k128).as_slice(), "128-bit AES key");

    let key = string_to_key(
        EncType::Aes256CtsHmacSha196,
        passphrase,
        salt,
        Some(&params),
        iterations,
    )
    .unwrap();
    assert_eq!(key.enc_type(), EncType::Aes256CtsHmacSha196);
    assert_eq!(key.octets(), hex(k256).as_slice(), "256-bit AES key");
}

#[test]
fn rfc3962_b_s2k_iter1() {
    // Source: RFC 3962 Appendix B — iteration count 1, "password",
    // salt "ATHENA.MIT.EDUraeburn".
    check_rfc3962_s2k(
        "password",
        "ATHENA.MIT.EDUraeburn",
        1,
        "42 26 3c 6e 89 f4 fc 28 b8 df 68 ee 09 79 9f 15",
        "fe 69 7b 52 bc 0d 3c e1 44 32 ba 03 6a 92 e6 5b
         bb 52 28 09 90 a2 fa 27 88 39 98 d7 2a f3 01 61",
    );
}

#[test]
fn rfc3962_b_s2k_iter2() {
    // Source: RFC 3962 Appendix B — iteration count 2.
    check_rfc3962_s2k(
        "password",
        "ATHENA.MIT.EDUraeburn",
        2,
        "c6 51 bf 29 e2 30 0a c2 7f a4 69 d6 93 bd da 13",
        "a2 e1 6d 16 b3 60 69 c1 35 d5 e9 d2 e2 5f 89 61
         02 68 56 18 b9 59 14 b4 67 c6 76 22 22 58 24 ff",
    );
}

#[test]
fn rfc3962_b_s2k_iter1200() {
    // Source: RFC 3962 Appendix B — iteration count 1200.
    check_rfc3962_s2k(
        "password",
        "ATHENA.MIT.EDUraeburn",
        1200,
        "4c 01 cd 46 d6 32 d0 1e 6d be 23 0a 01 ed 64 2a",
        "55 a6 ac 74 0a d1 7b 48 46 94 10 51 e1 e8 b0 a7
         54 8d 93 b0 ab 30 a8 bc 3f f1 62 80 38 2b 8c 2a",
    );
}

#[test]
fn rfc3962_b_s2k_iter5_binary_salt() {
    // Source: RFC 3962 Appendix B — iteration count 5, salt
    // 0x1234567878563412 (all octets < 0x80, so valid UTF-8).
    let salt_octets = hex("12 34 56 78 78 56 34 12");
    let salt = std::str::from_utf8(&salt_octets).unwrap();
    check_rfc3962_s2k(
        "password",
        salt,
        5,
        "e9 b2 3d 52 27 37 47 dd 5c 35 cb 55 be 61 9d 8e",
        "97 a4 e7 86 be 20 d8 1a 38 2d 5e bc 96 d5 90 9c
         ab cd ad c8 7c a4 8f 57 45 04 15 9f 16 c3 6e 31",
    );
}

#[test]
fn rfc3962_b_s2k_passphrase_equals_block_size() {
    // Source: RFC 3962 Appendix B — iteration count 1200, 64 'X'
    // characters, salt "pass phrase equals block size".
    let pass = "X".repeat(64);
    check_rfc3962_s2k(
        &pass,
        "pass phrase equals block size",
        1200,
        "59 d1 bb 78 9a 82 8b 1a a5 4e f9 c2 88 3f 69 ed",
        "89 ad ee 36 08 db 8b c7 1f 1b fb fe 45 94 86 b0
         56 18 b7 0c ba e2 20 92 53 4e 56 c5 53 ba 4b 34",
    );
}

#[test]
fn rfc3962_b_s2k_passphrase_exceeds_block_size() {
    // Source: RFC 3962 Appendix B — iteration count 1200, 65 'X'
    // characters, salt "pass phrase exceeds block size".
    let pass = "X".repeat(65);
    check_rfc3962_s2k(
        &pass,
        "pass phrase exceeds block size",
        1200,
        "cb 80 05 dc 5f 90 17 9a 7f 02 10 4c 00 18 75 1d",
        "d7 8c 5c 9c b8 72 a8 c9 da d4 69 7f 0b b5 b2 d2
         14 96 c8 2b eb 2c ae da 21 12 fc ee a0 57 40 1b",
    );
}

#[test]
fn rfc3962_b_s2k_gclef_utf8() {
    // Source: RFC 3962 Appendix B — iteration count 50, pass phrase g-clef
    // (0xf09d849e), salt "EXAMPLE.COMpianist".
    let gclef = "\u{1D11E}";
    assert_eq!(gclef.as_bytes(), hex("f0 9d 84 9e").as_slice());
    check_rfc3962_s2k(
        gclef,
        "EXAMPLE.COMpianist",
        50,
        "f1 49 c1 f2 e1 54 a7 34 52 d4 3e 7f e6 2a 56 e5",
        "4b 6d 98 39 f8 44 06 df 1f 09 cc 16 6d b4 b8 3c
         57 18 48 b7 84 a3 d6 bd c3 46 58 9a 3e 39 3f 9e",
    );
}

// ---------------------------------------------------------------------------
// Fixed byte strings for the round-trip tests below (not vectors). They are
// the key and plaintext of the RFC 3962 Appendix B CTS samples, reused only
// as convenient fixed bytes.
// ---------------------------------------------------------------------------

const FIXED_16: &str = "63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69";

const FIXED_TEXT: &str = "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65
                          20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43
                          68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c 20
                          61 6e 64 20 77 6f 6e 74 6f 6e 20 73 6f 75 70 2e";

// ---------------------------------------------------------------------------
// RFC 8009 Appendix A — string-to-key
// ---------------------------------------------------------------------------

/// The RFC 8009 Appendix A salt: a random 16-byte valid UTF-8 sequence
/// followed by "ATHENA.MIT.EDUraeburn" (the saltp minus its enctype-name
/// prefix and 0x00 separator).
fn rfc8009_salt() -> String {
    let octets = hex("10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61
         41 54 48 45 4E 41 2E 4D 49 54 2E 45 44 55 72 61
         65 62 75 72 6E");
    String::from_utf8(octets).expect("RFC 8009 states the salt is valid UTF-8")
}

#[test]
fn rfc8009_a_s2k_128() {
    // Source: RFC 8009 Appendix A — string-to-key, iteration count 32768,
    // "password", 128-bit base-key. The iteration count is the RFC 8009
    // default, so absent parameters must give the same key.
    let expected = hex("08 9B CA 48 B1 05 EA 6E A7 7C A5 D2 F3 9D C5 E7");
    let salt = rfc8009_salt();
    let explicit = string_to_key(
        EncType::Aes128CtsHmacSha256128,
        "password",
        &salt,
        Some(&s2kparams(32768)),
        32768,
    )
    .unwrap();
    assert_eq!(explicit.octets(), expected.as_slice());
    let default = string_to_key(
        EncType::Aes128CtsHmacSha256128,
        "password",
        &salt,
        None,
        32768,
    )
    .unwrap();
    assert_eq!(default.octets(), expected.as_slice());
}

#[test]
fn rfc8009_a_s2k_256() {
    // Source: RFC 8009 Appendix A — string-to-key, iteration count 32768,
    // "password", 256-bit base-key.
    let expected = hex("45 BD 80 6D BF 6A 83 3A 9C FF C1 C9 45 89 A2 22
         36 7A 79 BC 21 C4 13 71 89 06 E9 F5 78 A7 84 67");
    let salt = rfc8009_salt();
    let explicit = string_to_key(
        EncType::Aes256CtsHmacSha384192,
        "password",
        &salt,
        Some(&s2kparams(32768)),
        32768,
    )
    .unwrap();
    assert_eq!(explicit.octets(), expected.as_slice());
    let default = string_to_key(
        EncType::Aes256CtsHmacSha384192,
        "password",
        &salt,
        None,
        32768,
    )
    .unwrap();
    assert_eq!(default.octets(), expected.as_slice());
}

// ---------------------------------------------------------------------------
// RFC 8009 Appendix A — key derivation (key usage 2)
// ---------------------------------------------------------------------------

fn rfc8009_base_key_128() -> ProtocolKey {
    // Source: RFC 8009 Appendix A — "128-bit base-key" of the key derivation,
    // encryption, checksum and PRF samples.
    random_to_key(
        EncType::Aes128CtsHmacSha256128,
        &hex("37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C"),
    )
    .unwrap()
}

fn rfc8009_base_key_256() -> ProtocolKey {
    // Source: RFC 8009 Appendix A — "256-bit base-key".
    random_to_key(
        EncType::Aes256CtsHmacSha384192,
        &hex("6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98
             00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52"),
    )
    .unwrap()
}

#[test]
fn rfc8009_a_key_derivation_128() {
    // Source: RFC 8009 Appendix A — key derivation, enctype
    // aes128-cts-hmac-sha256-128, key usage 2.
    let base = rfc8009_base_key_128();
    let u = usage(2);
    let kc = derive_key(&base, u, SpecificKeyKind::Kc).unwrap();
    let ke = derive_key(&base, u, SpecificKeyKind::Ke).unwrap();
    let ki = derive_key(&base, u, SpecificKeyKind::Ki).unwrap();
    assert_eq!(kc.kind(), SpecificKeyKind::Kc);
    assert_eq!(
        kc.octets(),
        hex("B3 1A 01 8A 48 F5 47 76 F4 03 E9 A3 96 32 5D C3").as_slice()
    );
    assert_eq!(
        ke.octets(),
        hex("9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E").as_slice()
    );
    assert_eq!(
        ki.octets(),
        hex("9F DA 0E 56 AB 2D 85 E1 56 9A 68 86 96 C2 6A 6C").as_slice()
    );
}

#[test]
fn rfc8009_a_key_derivation_256() {
    // Source: RFC 8009 Appendix A — key derivation, enctype
    // aes256-cts-hmac-sha384-192, key usage 2 (Kc, Ki 192 bits; Ke 256 bits).
    let base = rfc8009_base_key_256();
    let u = usage(2);
    let kc = derive_key(&base, u, SpecificKeyKind::Kc).unwrap();
    let ke = derive_key(&base, u, SpecificKeyKind::Ke).unwrap();
    let ki = derive_key(&base, u, SpecificKeyKind::Ki).unwrap();
    assert_eq!(
        kc.octets(),
        hex("EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4
             BA 41 F2 8F AF 69 E7 3D")
        .as_slice()
    );
    assert_eq!(
        ke.octets(),
        hex("56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7
             A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49")
        .as_slice()
    );
    assert_eq!(
        ki.octets(),
        hex("69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6
             22 C4 D0 0F FC 23 ED 1F")
        .as_slice()
    );
}

// ---------------------------------------------------------------------------
// RFC 8009 Appendix A — sample encryptions (default cipher state, usage 2)
// ---------------------------------------------------------------------------

fn check_rfc8009_encryption(
    key: &ProtocolKey,
    plaintext: &str,
    confounder: &str,
    ciphertext: &str,
) {
    let plaintext = hex(plaintext);
    let confounder = hex16(confounder);
    let ciphertext = hex(ciphertext);
    let u = usage(2);

    let out = encrypt(key, u, &confounder, &plaintext).unwrap();
    assert_eq!(out, ciphertext, "ciphertext (AES output | truncated HMAC)");

    let back = decrypt(key, u, &ciphertext).unwrap();
    assert_eq!(back.as_slice(), plaintext.as_slice(), "decrypted plaintext");
}

#[test]
fn rfc8009_a_encrypt_128_empty() {
    // Source: RFC 8009 Appendix A — aes128-cts-hmac-sha256-128, plaintext
    // (empty).
    check_rfc8009_encryption(
        &rfc8009_base_key_128(),
        "",
        "7E 58 95 EA F2 67 24 35 BA D8 17 F5 45 A3 71 48",
        "EF 85 FB 89 0B B8 47 2F 4D AB 20 39 4D CA 78 1D
         AD 87 7E DA 39 D5 0C 87 0C 0D 5A 0A 8E 48 C7 18",
    );
}

#[test]
fn rfc8009_a_encrypt_128_less_than_block() {
    // Source: RFC 8009 Appendix A — aes128-cts-hmac-sha256-128, plaintext
    // length less than block size.
    check_rfc8009_encryption(
        &rfc8009_base_key_128(),
        "00 01 02 03 04 05",
        "7B CA 28 5E 2F D4 13 0F B5 5B 1A 5C 83 BC 5B 24",
        "84 D7 F3 07 54 ED 98 7B AB 0B F3 50 6B EB 09 CF
         B5 54 02 CE F7 E6 87 7C E9 9E 24 7E 52 D1 6E D4
         42 1D FD F8 97 6C",
    );
}

#[test]
fn rfc8009_a_encrypt_128_equals_block() {
    // Source: RFC 8009 Appendix A — aes128-cts-hmac-sha256-128, plaintext
    // length equals block size.
    check_rfc8009_encryption(
        &rfc8009_base_key_128(),
        "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
        "56 AB 21 71 3F F6 2C 0A 14 57 20 0F 6F A9 94 8F",
        "35 17 D6 40 F5 0D DC 8A D3 62 87 22 B3 56 9D 2A
         E0 74 93 FA 82 63 25 40 80 EA 65 C1 00 8E 8F C2
         95 FB 48 52 E7 D8 3E 1E 7C 48 C3 7E EB E6 B0 D3",
    );
}

#[test]
fn rfc8009_a_encrypt_128_greater_than_block() {
    // Source: RFC 8009 Appendix A — aes128-cts-hmac-sha256-128, plaintext
    // length greater than block size.
    check_rfc8009_encryption(
        &rfc8009_base_key_128(),
        "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14",
        "A7 A4 E2 9A 47 28 CE 10 66 4F B6 4E 49 AD 3F AC",
        "72 0F 73 B1 8D 98 59 CD 6C CB 43 46 11 5C D3 36
         C7 0F 58 ED C0 C4 43 7C 55 73 54 4C 31 C8 13 BC
         E1 E6 D0 72 C1 86 B3 9A 41 3C 2F 92 CA 9B 83 34
         A2 87 FF CB FC",
    );
}

#[test]
fn rfc8009_a_encrypt_256_empty() {
    // Source: RFC 8009 Appendix A — aes256-cts-hmac-sha384-192, plaintext
    // (empty).
    check_rfc8009_encryption(
        &rfc8009_base_key_256(),
        "",
        "F7 64 E9 FA 15 C2 76 47 8B 2C 7D 0C 4E 5F 58 E4",
        "41 F5 3F A5 BF E7 02 6D 91 FA F9 BE 95 91 95 A0
         58 70 72 73 A9 6A 40 F0 A0 19 60 62 1A C6 12 74
         8B 9B BF BE 7E B4 CE 3C",
    );
}

#[test]
fn rfc8009_a_encrypt_256_less_than_block() {
    // Source: RFC 8009 Appendix A — aes256-cts-hmac-sha384-192, plaintext
    // length less than block size.
    check_rfc8009_encryption(
        &rfc8009_base_key_256(),
        "00 01 02 03 04 05",
        "B8 0D 32 51 C1 F6 47 14 94 25 6F FE 71 2D 0B 9A",
        "4E D7 B3 7C 2B CA C8 F7 4F 23 C1 CF 07 E6 2B C7
         B7 5F B3 F6 37 B9 F5 59 C7 F6 64 F6 9E AB 7B 60
         92 23 75 26 EA 0D 1F 61 CB 20 D6 9D 10 F2",
    );
}

#[test]
fn rfc8009_a_encrypt_256_equals_block() {
    // Source: RFC 8009 Appendix A — aes256-cts-hmac-sha384-192, plaintext
    // length equals block size.
    check_rfc8009_encryption(
        &rfc8009_base_key_256(),
        "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
        "53 BF 8A 0D 10 52 65 D4 E2 76 42 86 24 CE 5E 63",
        "BC 47 FF EC 79 98 EB 91 E8 11 5C F8 D1 9D AC 4B
         BB E2 E1 63 E8 7D D3 7F 49 BE CA 92 02 77 64 F6
         8C F5 1F 14 D7 98 C2 27 3F 35 DF 57 4D 1F 93 2E
         40 C4 FF 25 5B 36 A2 66",
    );
}

#[test]
fn rfc8009_a_encrypt_256_greater_than_block() {
    // Source: RFC 8009 Appendix A — aes256-cts-hmac-sha384-192, plaintext
    // length greater than block size.
    check_rfc8009_encryption(
        &rfc8009_base_key_256(),
        "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14",
        "76 3E 65 36 7E 86 4F 02 F5 51 53 C7 E3 B5 8A F1",
        "40 01 3E 2D F5 8E 87 51 95 7D 28 78 BC D2 D6 FE
         10 1C CF D5 56 CB 1E AE 79 DB 3C 3E E8 64 29 F2
         B2 A6 02 AC 86 FE F6 EC B6 47 D6 29 5F AE 07 7A
         1F EB 51 75 08 D2 C1 6B 41 92 E0 1F 62",
    );
}

// ---------------------------------------------------------------------------
// RFC 8009 Appendix A — sample checksums (usage 2)
// ---------------------------------------------------------------------------

const CHECKSUM_PLAINTEXT: &str = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14";

#[test]
fn rfc8009_a_checksum_hmac_sha256_128_aes128() {
    // Source: RFC 8009 Appendix A — checksum type hmac-sha256-128-aes128.
    let key = rfc8009_base_key_128();
    let msg = hex(CHECKSUM_PLAINTEXT);
    let expected = hex("D7 83 67 18 66 43 D6 7B 41 1C BA 91 39 FC 1D EE");
    let ct = ChecksumType::HmacSha256128Aes128;
    assert_eq!(get_mic(&key, ct, usage(2), &msg).unwrap(), expected);
    verify_mic(&key, ct, usage(2), &msg, &expected).unwrap();
}

#[test]
fn rfc8009_a_checksum_hmac_sha384_192_aes256() {
    // Source: RFC 8009 Appendix A — checksum type hmac-sha384-192-aes256.
    let key = rfc8009_base_key_256();
    let msg = hex(CHECKSUM_PLAINTEXT);
    let expected = hex("45 EE 79 15 67 EE FC A3 7F 4A C1 E0 22 2D E8 0D
         43 C3 BF A0 66 99 67 2A");
    let ct = ChecksumType::HmacSha384192Aes256;
    assert_eq!(get_mic(&key, ct, usage(2), &msg).unwrap(), expected);
    verify_mic(&key, ct, usage(2), &msg, &expected).unwrap();
}

// ---------------------------------------------------------------------------
// RFC 8009 Appendix A — sample PRF invocations
// ---------------------------------------------------------------------------

#[test]
fn rfc8009_a_prf_128() {
    // Source: RFC 8009 Appendix A — PRF, input "test" (0x74657374),
    // aes128-cts-hmac-sha256-128.
    assert_eq!(hex("74657374"), b"test");
    let out = pseudo_random(&rfc8009_base_key_128(), b"test").unwrap();
    assert_eq!(
        out.as_slice(),
        hex("9D 18 86 16 F6 38 52 FE 86 91 5B B8 40 B4 A8 86
             FF 3E 6B B0 F8 19 B4 9B 89 33 93 D3 93 85 42 95")
        .as_slice()
    );
}

#[test]
fn rfc8009_a_prf_256() {
    // Source: RFC 8009 Appendix A — PRF, input "test",
    // aes256-cts-hmac-sha384-192.
    let out = pseudo_random(&rfc8009_base_key_256(), b"test").unwrap();
    assert_eq!(
        out.as_slice(),
        hex("98 01 F6 9A 36 8C 2B F6 75 E5 95 21 E1 77 D9 A0
             7F 67 EF E1 CF DE 8D 3C 8D 6F 6A 02 56 E3 B1 7D
             B3 C1 B6 2A D1 B8 55 33 60 D1 73 67 EB 15 14 D2")
        .as_slice()
    );
}

// ---------------------------------------------------------------------------
// Round trips for etypes 17/18 (no RFC 3962 encryption sample exists), keyed
// with RFC 3962 Appendix B string-to-key outputs.
// ---------------------------------------------------------------------------

/// RFC 3962 Appendix B iteration-count-1 keys, rebuilt with random-to-key
/// (identity) from the listed AES key octets.
fn rfc3962_key(enc_type: EncType) -> ProtocolKey {
    let octets = match enc_type {
        EncType::Aes128CtsHmacSha196 => hex("42 26 3c 6e 89 f4 fc 28 b8 df 68 ee 09 79 9f 15"),
        _ => hex("fe 69 7b 52 bc 0d 3c e1 44 32 ba 03 6a 92 e6 5b
             bb 52 28 09 90 a2 fa 27 88 39 98 d7 2a f3 01 61"),
    };
    random_to_key(enc_type, &octets).unwrap()
}

fn all_keys() -> Vec<ProtocolKey> {
    vec![
        rfc3962_key(EncType::Aes128CtsHmacSha196),
        rfc3962_key(EncType::Aes256CtsHmacSha196),
        rfc8009_base_key_128(),
        rfc8009_base_key_256(),
    ]
}

#[test]
fn round_trip_all_enctypes_all_length_classes() {
    // Property from RFC 3961 §3 (decrypt(encrypt(M)) = M; any plaintext is
    // accepted by encrypt). Lengths cover empty, partial block, exact block,
    // and multi-block plaintexts; confounder and plaintext are fixed bytes.
    let confounder = hex16(FIXED_16);
    let source = hex(FIXED_TEXT);
    for key in all_keys() {
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 64] {
            let pt = &source[..len];
            let ct = encrypt(&key, usage(3), &confounder, pt).unwrap();
            assert_eq!(
                ct.len(),
                len + key.enc_type().min_ciphertext_length(),
                "CTS adds no padding: |ct| = c + |pt| + h"
            );
            let back = decrypt(&key, usage(3), &ct).unwrap();
            assert_eq!(back.as_slice(), pt);
        }
    }
}

#[test]
fn rfc3962_checksum_length_and_verify() {
    // RFC 3962 §6/§7: hmac-sha1-96-aes128/256 produce 96-bit (12-octet)
    // checksums; verify_mic accepts what get_mic produced.
    for (enc_type, ct) in [
        (EncType::Aes128CtsHmacSha196, ChecksumType::HmacSha196Aes128),
        (EncType::Aes256CtsHmacSha196, ChecksumType::HmacSha196Aes256),
    ] {
        let key = rfc3962_key(enc_type);
        let mic = get_mic(&key, ct, usage(17), b"message").unwrap();
        assert_eq!(mic.len(), 12);
        verify_mic(&key, ct, usage(17), b"message", &mic).unwrap();
    }
}

// ---------------------------------------------------------------------------
// Rejection tests (fail closed)
// ---------------------------------------------------------------------------

#[test]
fn reject_tampered_ciphertext() {
    // RFC 3961 §3 / §5.3; RFC 8009 §5: an altered ciphertext must produce an
    // error indication. Every single-bit flip, in the AES part and in the
    // HMAC part, is rejected for every enctype.
    let confounder = [0x5Au8; 16];
    for key in all_keys() {
        let ct = encrypt(&key, usage(2), &confounder, b"seventeen octets!").unwrap();
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 0x01;
            assert_eq!(
                decrypt(&key, usage(2), &bad).err(),
                Some(Error::IntegrityCheckFailed),
                "flip at octet {i} of {:?}",
                key.enc_type()
            );
        }
    }
}

#[test]
fn reject_wrong_key_usage() {
    // RFC 3961 §2/§5.3; RFC 8009 §5: Ke/Ki depend on the key usage, so a
    // ciphertext made for usage 2 does not verify under usage 3.
    let confounder = [0x11u8; 16];
    for key in all_keys() {
        let ct = encrypt(&key, usage(2), &confounder, b"payload").unwrap();
        assert_eq!(
            decrypt(&key, usage(3), &ct).err(),
            Some(Error::IntegrityCheckFailed)
        );
        let mic = get_mic(&key, key.enc_type().checksum_type(), usage(2), b"m").unwrap();
        assert_eq!(
            verify_mic(&key, key.enc_type().checksum_type(), usage(3), b"m", &mic).err(),
            Some(Error::ChecksumVerificationFailed)
        );
    }
}

#[test]
fn reject_wrong_key() {
    // A ciphertext does not verify under a different key of the same type.
    let confounder = [0x22u8; 16];
    let k1 = rfc8009_base_key_128();
    let k2 = random_to_key(EncType::Aes128CtsHmacSha256128, &[0x42; 16]).unwrap();
    let ct = encrypt(&k1, usage(2), &confounder, b"payload").unwrap();
    assert_eq!(
        decrypt(&k2, usage(2), &ct).err(),
        Some(Error::IntegrityCheckFailed)
    );
}

#[test]
fn reject_truncated_ciphertext() {
    // RFC 3961 §5.3 / RFC 8009 §5: a ciphertext is at least the 16-octet
    // confounder block plus h octets of HMAC. Anything shorter is
    // CiphertextTooShort; a valid ciphertext cut by one octet (still long
    // enough) fails integrity.
    let confounder = [0x33u8; 16];
    for key in all_keys() {
        let min = key.enc_type().min_ciphertext_length();
        for len in 0..min {
            assert_eq!(
                decrypt(&key, usage(2), &vec![0u8; len]).err(),
                Some(Error::CiphertextTooShort),
                "length {len} for {:?}",
                key.enc_type()
            );
        }
        let ct = encrypt(&key, usage(2), &confounder, b"some plaintext").unwrap();
        assert_eq!(
            decrypt(&key, usage(2), &ct[..ct.len() - 1]).err(),
            Some(Error::IntegrityCheckFailed)
        );
        // Exactly the minimum length but all zeros: well-formed length,
        // integrity fails.
        assert_eq!(
            decrypt(&key, usage(2), &vec![0u8; min]).err(),
            Some(Error::IntegrityCheckFailed)
        );
    }
}

#[test]
fn reject_unknown_enctype_numbers() {
    // RFC 3961 §8 lists DES (1-3), 3DES (5, 7, 16), RC4 (23, 24) and others;
    // none has a code path here (AGENTS.md §6). Zero and negative numbers are
    // invalid or local-use (RFC 3961 §8).
    for n in [i32::MIN, -1, 0, 1, 2, 3, 5, 7, 16, 21, 23, 24, 65, i32::MAX] {
        assert_eq!(
            EncType::from_number(n),
            Err(Error::UnsupportedEncType),
            "{n}"
        );
    }
    for n in [17, 18, 19, 20] {
        assert_eq!(EncType::from_number(n).unwrap().number(), n);
    }
}

#[test]
fn reject_unknown_checksum_type_numbers() {
    // RFC 3961 §8 checksum types other than 15/16 (RFC 3962 §7) and 19/20
    // (RFC 8009 §7) — CRC32, MD4, MD5, DES-MAC, HMAC-SHA1-DES3 — are refused.
    for n in [
        i32::MIN,
        -138,
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        12,
        13,
        14,
        17,
        18,
        21,
    ] {
        assert_eq!(
            ChecksumType::from_number(n),
            Err(Error::UnsupportedChecksumType),
            "{n}"
        );
    }
    for n in [15, 16, 19, 20] {
        assert_eq!(ChecksumType::from_number(n).unwrap().number(), n);
    }
}

#[test]
fn reject_key_usage_zero() {
    // RFC 3961 §2: "zero is not permitted".
    assert_eq!(KeyUsage::new(0), Err(Error::InvalidKeyUsage));
    assert_eq!(KeyUsage::new(u32::MAX).unwrap().get(), u32::MAX);
}

#[test]
fn reject_bad_checksums() {
    // RFC 3961 §4 verify_mic; RFC 3962 §7 / RFC 8009 §7 checksum lengths.
    for key in all_keys() {
        let ct = key.enc_type().checksum_type();
        let mic = get_mic(&key, ct, usage(2), b"message").unwrap();
        assert_eq!(mic.len(), ct.mic_length());

        // Tampered message.
        assert_eq!(
            verify_mic(&key, ct, usage(2), b"messagf", &mic).err(),
            Some(Error::ChecksumVerificationFailed)
        );
        // Tampered MIC.
        let mut bad = mic.clone();
        bad[0] ^= 0x80;
        assert_eq!(
            verify_mic(&key, ct, usage(2), b"message", &bad).err(),
            Some(Error::ChecksumVerificationFailed)
        );
        // Truncated MIC (a correct prefix) and over-long MIC: wrong length h.
        assert_eq!(
            verify_mic(&key, ct, usage(2), b"message", &mic[..mic.len() - 1]).err(),
            Some(Error::InvalidChecksumLength)
        );
        assert_eq!(
            verify_mic(&key, ct, usage(2), b"message", &[]).err(),
            Some(Error::InvalidChecksumLength)
        );
        let mut long = mic.clone();
        long.push(0);
        assert_eq!(
            verify_mic(&key, ct, usage(2), b"message", &long).err(),
            Some(Error::InvalidChecksumLength)
        );
    }
}

#[test]
fn reject_checksum_type_not_for_key() {
    // RFC 3961 §4 / RFC 3962 §7 / RFC 8009 §6: each checksum type has one
    // associated encryption type.
    let key = rfc8009_base_key_128();
    for ct in [
        ChecksumType::HmacSha196Aes128,
        ChecksumType::HmacSha196Aes256,
        ChecksumType::HmacSha384192Aes256,
    ] {
        assert_eq!(
            get_mic(&key, ct, usage(2), b"m").err(),
            Some(Error::ChecksumTypeNotForKey)
        );
        assert_eq!(
            verify_mic(&key, ct, usage(2), b"m", &[0u8; 16]).err(),
            Some(Error::ChecksumTypeNotForKey)
        );
    }
}

#[test]
fn reject_bad_random_to_key_length() {
    // RFC 3961 §3: random-to-key takes exactly K bits (RFC 3962 §6, RFC 8009
    // §5: K = key size).
    for (enc_type, good) in [
        (EncType::Aes128CtsHmacSha196, 16usize),
        (EncType::Aes256CtsHmacSha196, 32),
        (EncType::Aes128CtsHmacSha256128, 16),
        (EncType::Aes256CtsHmacSha384192, 32),
    ] {
        assert!(random_to_key(enc_type, &vec![0u8; good]).is_ok());
        for bad in [0usize, 1, 15, 17, 24, 31, 33, 64] {
            if bad == good {
                continue;
            }
            assert_eq!(
                random_to_key(enc_type, &vec![0u8; bad]).err(),
                Some(Error::InvalidKeyLength)
            );
        }
    }
}

#[test]
fn s2k_params_parsing_and_limits() {
    // RFC 3962 §4: four octets, big-endian; 00 00 00 00 means 2^32; default
    // 4,096 (RFC 3962) or 32,768 (RFC 8009 §4) when absent.
    assert_eq!(
        iteration_count(EncType::Aes128CtsHmacSha196, None),
        Ok(4096)
    );
    assert_eq!(
        iteration_count(EncType::Aes256CtsHmacSha196, None),
        Ok(4096)
    );
    assert_eq!(
        iteration_count(EncType::Aes128CtsHmacSha256128, None),
        Ok(32768)
    );
    assert_eq!(
        iteration_count(EncType::Aes256CtsHmacSha384192, None),
        Ok(32768)
    );
    assert_eq!(
        iteration_count(EncType::Aes128CtsHmacSha196, Some(&[0, 0, 0x10, 0])),
        Ok(4096)
    );
    assert_eq!(
        iteration_count(EncType::Aes128CtsHmacSha196, Some(&[0, 0, 0, 0])),
        Ok(1u64 << 32)
    );
    for bad in [&[][..], &[0, 0, 1][..], &[0, 0, 0, 1, 0][..]] {
        assert_eq!(
            iteration_count(EncType::Aes128CtsHmacSha196, Some(bad)),
            Err(Error::InvalidS2kParams)
        );
        assert_eq!(
            string_to_key(EncType::Aes128CtsHmacSha196, "p", "s", Some(bad), u32::MAX).err(),
            Some(Error::InvalidS2kParams)
        );
    }
    // RFC 3962 §4/§8: a caller limit refuses a larger (possibly spoofed)
    // count before any work; 2^32 always exceeds a u32 limit.
    assert_eq!(
        string_to_key(
            EncType::Aes128CtsHmacSha196,
            "p",
            "s",
            Some(&[0, 0, 0, 0]),
            u32::MAX
        )
        .err(),
        Some(Error::IterationCountAboveLimit)
    );
    assert_eq!(
        string_to_key(
            EncType::Aes256CtsHmacSha384192,
            "p",
            "s",
            Some(&s2kparams(50_001)),
            50_000
        )
        .err(),
        Some(Error::IterationCountAboveLimit)
    );
    // Absent parameters with a limit below the enctype default are refused.
    assert_eq!(
        string_to_key(EncType::Aes128CtsHmacSha256128, "p", "s", None, 32_767).err(),
        Some(Error::IterationCountAboveLimit)
    );
}

#[test]
fn prf_rfc3962_types_shape() {
    // RFC 3961 §5.3 with the RFC 6113 Appendix A interpretation
    // (aes-ecb(trunc128(sha-1(input)))): a single AES block, 16 octets, for
    // both key sizes; deterministic and input-dependent. No standalone
    // PRF vector exists for 17/18 — the RFC 6113 Appendix A KRB-FX-CF2
    // vectors below exercise this PRF end to end.
    for enc_type in [EncType::Aes128CtsHmacSha196, EncType::Aes256CtsHmacSha196] {
        let key = rfc3962_key(enc_type);
        let a = pseudo_random(&key, b"test").unwrap();
        let b = pseudo_random(&key, b"test").unwrap();
        let c = pseudo_random(&key, b"tesu").unwrap();
        assert_eq!(a.len(), 16);
        assert_eq!(a.as_slice(), b.as_slice());
        assert_ne!(a.as_slice(), c.as_slice());
    }
}

// ---------------------------------------------------------------------------
// RFC 6113 Appendix A — KRB-FX-CF2
// ---------------------------------------------------------------------------

/// The RFC 6113 Appendix A inputs: k1 = string-to-key("key1", "key1",
/// default_parameters), k2 = string-to-key("key2", "key2",
/// default_parameters), both of `enc_type`.
fn rfc6113_inputs(enc_type: EncType) -> (ProtocolKey, ProtocolKey) {
    let default = u32::try_from(iteration_count(enc_type, None).unwrap()).unwrap();
    let k1 = string_to_key(enc_type, "key1", "key1", None, default).unwrap();
    let k2 = string_to_key(enc_type, "key2", "key2", None, default).unwrap();
    (k1, k2)
}

#[test]
fn rfc6113_a_krb_fx_cf2_aes128_cts_hmac_sha1_96() {
    // Source: RFC 6113 Appendix A — KRB-FX-CF2(k1, k2, "a", "b"),
    // "aes 128 (enctype 17): 97df97e4b798b29eb31ed7280287a92a".
    let (k1, k2) = rfc6113_inputs(EncType::Aes128CtsHmacSha196);
    let k3 = krb_fx_cf2(&k1, &k2, b"a", b"b").unwrap();
    assert_eq!(k3.enc_type(), EncType::Aes128CtsHmacSha196);
    assert_eq!(
        k3.octets(),
        hex("97df97e4b798b29eb31ed7280287a92a").as_slice()
    );
}

#[test]
fn rfc6113_a_krb_fx_cf2_aes256_cts_hmac_sha1_96() {
    // Source: RFC 6113 Appendix A — KRB-FX-CF2(k1, k2, "a", "b"),
    // "AES256 (enctype 18): 4d6ca4e629785c1f01baf55e2e548566
    // b9617ae3a96868c337cb93b5e72b1c7b". 32 octets = two PRF+ blocks.
    let (k1, k2) = rfc6113_inputs(EncType::Aes256CtsHmacSha196);
    let k3 = krb_fx_cf2(&k1, &k2, b"a", b"b").unwrap();
    assert_eq!(k3.enc_type(), EncType::Aes256CtsHmacSha196);
    assert_eq!(
        k3.octets(),
        hex("4d6ca4e629785c1f01baf55e2e548566 b9617ae3a96868c337cb93b5e72b1c7b").as_slice()
    );
}

#[test]
fn krb_fx_cf2_rfc8009_types_determinism_only() {
    // RFC 6113 has NO vectors for etypes 19/20, so this is a property test
    // only (not a vector): same inputs give the same key; the result has the
    // enctype and length of k1 (RFC 6113 §5.1); it differs from both inputs;
    // and exchanging the peppers changes it.
    for enc_type in [
        EncType::Aes128CtsHmacSha256128,
        EncType::Aes256CtsHmacSha384192,
    ] {
        let (k1, k2) = rfc6113_inputs(enc_type);
        let a = krb_fx_cf2(&k1, &k2, b"a", b"b").unwrap();
        let b = krb_fx_cf2(&k1, &k2, b"a", b"b").unwrap();
        let swapped = krb_fx_cf2(&k1, &k2, b"b", b"a").unwrap();
        assert_eq!(a.enc_type(), enc_type);
        assert_eq!(a.octets().len(), enc_type.key_length());
        assert_eq!(a.octets(), b.octets());
        assert_ne!(a.octets(), k1.octets());
        assert_ne!(a.octets(), k2.octets());
        assert_ne!(a.octets(), swapped.octets());
    }
}

#[test]
fn krb_fx_cf2_mixed_enctypes_allowed() {
    // RFC 6113 §5.1: "K1 and K2 can be of two different enctypes"; the
    // result has the enctype of k1, and each PRF+ yields as many octets as
    // random-to-key needs for that enctype (here 16 from a 48-octet PRF, and
    // 32 from two 16-octet PRF outputs).
    let k17 = rfc6113_inputs(EncType::Aes128CtsHmacSha196).0;
    let k20 = rfc6113_inputs(EncType::Aes256CtsHmacSha384192).0;

    let r = krb_fx_cf2(&k17, &k20, b"a", b"b").unwrap();
    assert_eq!(r.enc_type(), EncType::Aes128CtsHmacSha196);
    assert_eq!(r.octets().len(), 16);

    let r = krb_fx_cf2(&k20, &k17, b"a", b"b").unwrap();
    assert_eq!(r.enc_type(), EncType::Aes256CtsHmacSha384192);
    assert_eq!(r.octets().len(), 32);
}

#[test]
fn krb_fx_cf2_rejects_identical_peppers() {
    // RFC 6113 §5.1: "The pepper1 and pepper2 MUST be distinct".
    let (k1, k2) = rfc6113_inputs(EncType::Aes128CtsHmacSha196);
    assert_eq!(
        krb_fx_cf2(&k1, &k2, b"a", b"a").err(),
        Some(Error::PeppersNotDistinct)
    );
    assert_eq!(
        krb_fx_cf2(&k1, &k1, b"", b"").err(),
        Some(Error::PeppersNotDistinct)
    );
}

#[test]
fn key_debug_is_redacted() {
    // AGENTS.md §6: secrets never in debug output.
    let key = rfc8009_base_key_128();
    let text = format!("{key:?}");
    assert!(text.contains("redacted"));
    assert!(
        !text.to_lowercase().contains("37"),
        "no key octet in Debug: {text}"
    );
    let kc = derive_key(&key, usage(2), SpecificKeyKind::Kc).unwrap();
    let text = format!("{kc:?}");
    assert!(text.contains("redacted"));
    assert!(
        !text.to_lowercase().contains("b3"),
        "no key octet in Debug: {text}"
    );
}
