//! AES in CBC mode with ciphertext stealing (CTS): the basic encryption and
//! decryption functions E and D of the AES Kerberos encryption types.
//!
//! The AES block cipher itself comes from the approved `aes` crate (docs/CLEAN-ROOM.md
//! §6: we never implement a primitive). This module only composes the
//! Kerberos-specified mode on top of the single-block AES operations, exactly
//! as RFC 3962 §5 describes it:
//!
//! - CBC is used for all but the last two blocks; ciphertext stealing is
//!   always applied to the last two blocks (RFC 3962 §5, following the steps
//!   of RFC 2040 §8 with the errata of RFC 3962 Appendix A). When the length
//!   is a multiple of the block size this equals plain CBC with the last two
//!   ciphertext blocks swapped.
//! - Exactly one block is simply encrypted with AES (ECB) (RFC 3962 §5).
//! - The cipher state carried out is the next-to-last block of the output
//!   (the only block, if there is one block) (RFC 3962 §5). RFC 8009 §5 gives
//!   the same rule for enctypes 19/20.
//!
//! Only the initial cipher state (all bits zero; RFC 3961 §5.3, RFC 8009 §5)
//! is supported: every Kerberos operation in this crate starts from it, and
//! cipher-state chaining is not offered (minimal surface, docs/25 §5). Input
//! shorter than one block is refused: the Kerberos profile always prepends a
//! one-block confounder, so the unspecified-padding case of RFC 3962 §5 never
//! arises and gets no code path.
//!
//! RFC 8009 §1 names its mode "a variation of the CBC-CS3 mode defined in
//! [SP800-38A+], also referred to as ciphertext stealing or CTS mode". The
//! SP 800-38A Addendum is not reachable from an allowed host
//! (docs/questions/Q-010); this composition reproduces every RFC 8009
//! Appendix A "AES Output" vector (one block, one block plus a partial block,
//! two full blocks, two blocks plus a partial block).
//!
//! These are raw building blocks with NO integrity protection, so they are
//! crate-private (minimal surface, docs/25 D104): callers only ever reach
//! them through [`crate::encrypt`] / [`crate::decrypt`] and the key
//! derivation / PRF code. The RFC 3962 Appendix B CTS vectors and the
//! RFC 8009 Appendix A "AES Output" values are checked by the unit tests at
//! the end of this file.

use crate::error::{Error, Result};
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use zeroize::Zeroize;

/// The AES block size (cipher block size c) in octets.
/// Spec: RFC 3962 §6 ("cipher block size 16 octets").
pub(crate) const BLOCK_LENGTH: usize = 16;

type Block = [u8; BLOCK_LENGTH];

/// An AES block cipher instance keyed with a 128- or 256-bit key. The key
/// schedule is zeroized on drop (the `aes` crate's `zeroize` feature).
pub(crate) enum AesCipher {
    Aes128(Aes128),
    Aes256(Aes256),
}

impl AesCipher {
    /// Key the cipher. The key must be 16 or 32 octets.
    /// Spec: RFC 3962 §3, §6 (128- or 256-bit AES key); RFC 8009 §2.
    pub(crate) fn new(key: &[u8]) -> Result<Self> {
        match key.len() {
            16 => Aes128::new_from_slice(key)
                .map(AesCipher::Aes128)
                .map_err(|_| Error::InvalidKeyLength),
            32 => Aes256::new_from_slice(key)
                .map(AesCipher::Aes256)
                .map_err(|_| Error::InvalidKeyLength),
            _ => Err(Error::InvalidKeyLength),
        }
    }

    /// Single-block AES encryption (FIPS 197, via the `aes` crate).
    fn encrypt_block(&self, block: &mut Block) {
        let mut b = aes::Block::from(*block);
        match self {
            AesCipher::Aes128(c) => c.encrypt_block(&mut b),
            AesCipher::Aes256(c) => c.encrypt_block(&mut b),
        }
        block.copy_from_slice(&b);
        b.zeroize();
    }

    /// Single-block AES decryption (FIPS 197, via the `aes` crate).
    fn decrypt_block(&self, block: &mut Block) {
        let mut b = aes::Block::from(*block);
        match self {
            AesCipher::Aes128(c) => c.decrypt_block(&mut b),
            AesCipher::Aes256(c) => c.decrypt_block(&mut b),
        }
        block.copy_from_slice(&b);
        b.zeroize();
    }
}

fn xor_into(dst: &mut Block, src: &Block) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Copy the 16 octets at `data[start..start + 16]` into a block. Callers
/// index only within bounds they have already checked.
fn block_at(data: &[u8], start: usize) -> Block {
    let mut b = [0u8; BLOCK_LENGTH];
    b.copy_from_slice(&data[start..start + BLOCK_LENGTH]);
    b
}

/// Encrypt `input` (at least one block) with AES-CBC-CTS, starting from the
/// initial cipher state (all-zero IV).
///
/// Returns the ciphertext (same length as `input`) and the output cipher
/// state (the next-to-last ciphertext block, or the only block).
/// Errors: [`Error::InvalidInputLength`] if `input` is shorter than one block.
///
/// Spec: RFC 3962 §5; RFC 2040 §8 encryption steps 1-7 with RFC 3962
/// Appendix A errata; vectors in RFC 3962 Appendix B.
pub(crate) fn encrypt_with(
    cipher: &AesCipher,
    input: &[u8],
) -> Result<(Vec<u8>, [u8; BLOCK_LENGTH])> {
    let len = input.len();
    if len < BLOCK_LENGTH {
        return Err(Error::InvalidInputLength);
    }

    // Exactly one block: simply encrypted with AES (ECB).
    // Spec: RFC 3962 §5. Cipher state carried out is that one block.
    if len == BLOCK_LENGTH {
        let mut c = block_at(input, 0);
        cipher.encrypt_block(&mut c);
        return Ok((c.to_vec(), c));
    }

    // n blocks, the last (Pn) of Ln octets with 1 <= Ln <= 16.
    // Spec: RFC 2040 §8 ("Notice that Ln ranges from 1 to BB, inclusive").
    let n = len.div_ceil(BLOCK_LENGTH);
    let ln = len - (n - 1) * BLOCK_LENGTH;
    let mut out = vec![0u8; len];

    // CBC for all blocks before the last two, starting from the initial
    // cipher state (all zero). Spec: RFC 2040 §8 ("behaves like the CBC mode
    // for all but the last two blocks"); RFC 3961 §5.3 / RFC 8009 §5 (initial
    // cipher state all bits zero).
    let mut prev: Block = [0u8; BLOCK_LENGTH]; // Cn-2 once the loop ends (or IV).
    for i in 0..n - 2 {
        let mut x = block_at(input, i * BLOCK_LENGTH);
        xor_into(&mut x, &prev);
        cipher.encrypt_block(&mut x);
        out[i * BLOCK_LENGTH..(i + 1) * BLOCK_LENGTH].copy_from_slice(&x);
        prev = x;
    }

    // Last two portions. Spec: RFC 2040 §8 encryption steps, with RFC 3962
    // Appendix A erratum for step 1 ("For short messages where Cn-2 does not
    // exist, use IV" — `prev` is still the all-zero IV when n == 2).
    let pn1_start = (n - 2) * BLOCK_LENGTH;
    let pn_start = (n - 1) * BLOCK_LENGTH;

    // 1. Exclusive-or Pn-1 with the previous ciphertext block, Cn-2, to
    //    create Xn-1.
    let mut en1 = block_at(input, pn1_start);
    xor_into(&mut en1, &prev);
    // 2. Encrypt Xn-1 to create En-1.
    cipher.encrypt_block(&mut en1);
    // 3. Select the first Ln bytes of En-1 to create Cn.
    out[pn_start..].copy_from_slice(&en1[..ln]);
    // 4. Pad Pn with zeros at the end to create P of length BB.
    let mut p = [0u8; BLOCK_LENGTH];
    p[..ln].copy_from_slice(&input[pn_start..]);
    // 5. Exclusive-or En-1 with P to create Dn.
    let mut dn = en1;
    xor_into(&mut dn, &p);
    // 6. Encrypt Dn to create Cn-1.
    cipher.encrypt_block(&mut dn);
    // 7. The last two parts of the ciphertext are Cn-1 and Cn respectively.
    out[pn1_start..pn_start].copy_from_slice(&dn);

    // Cipher state carried out: the next-to-last block of the output, Cn-1.
    // Spec: RFC 3962 §5; RFC 8009 §5.
    let next_state = dn;

    p.zeroize();
    en1.zeroize();
    Ok((out, next_state))
}

/// Decrypt `input` (at least one block) with AES-CBC-CTS, starting from the
/// initial cipher state (all-zero IV).
///
/// Returns the plaintext (same length as `input`; callers hold it in a
/// zeroizing buffer) and the output cipher state (the next-to-last block of
/// the supplied ciphertext, or the only block).
/// Errors: [`Error::InvalidInputLength`] if `input` is shorter than one block.
///
/// Spec: RFC 3962 §5; RFC 2040 §8 decryption steps 1-7 with RFC 3962
/// Appendix A errata (step 6 XORs with Cn-2, or the IV).
pub(crate) fn decrypt_with(
    cipher: &AesCipher,
    input: &[u8],
) -> Result<(Vec<u8>, [u8; BLOCK_LENGTH])> {
    let len = input.len();
    if len < BLOCK_LENGTH {
        return Err(Error::InvalidInputLength);
    }

    // Exactly one block: AES (ECB) decryption. Cipher state carried out is
    // the one supplied ciphertext block. Spec: RFC 3962 §5.
    if len == BLOCK_LENGTH {
        let c = block_at(input, 0);
        let mut p = c;
        cipher.decrypt_block(&mut p);
        let out = p.to_vec();
        p.zeroize();
        return Ok((out, c));
    }

    let n = len.div_ceil(BLOCK_LENGTH);
    let ln = len - (n - 1) * BLOCK_LENGTH;
    let mut out = vec![0u8; len];

    // CBC decryption for all blocks before the last two, from the all-zero
    // initial cipher state. Spec: RFC 2040 §8; RFC 3961 §5.3; RFC 8009 §5.
    let mut prev: Block = [0u8; BLOCK_LENGTH]; // Cn-2 once the loop ends (or IV).
    for i in 0..n - 2 {
        let c = block_at(input, i * BLOCK_LENGTH);
        let mut p = c;
        cipher.decrypt_block(&mut p);
        xor_into(&mut p, &prev);
        out[i * BLOCK_LENGTH..(i + 1) * BLOCK_LENGTH].copy_from_slice(&p);
        p.zeroize();
        prev = c;
    }

    // Last two portions. Spec: RFC 2040 §8 decryption steps, with RFC 3962
    // Appendix A erratum for step 6.
    let cn1_start = (n - 2) * BLOCK_LENGTH;
    let cn_start = (n - 1) * BLOCK_LENGTH;
    let cn1 = block_at(input, cn1_start);

    // 1. Decrypt Cn-1 to create Dn.
    let mut xn = cn1;
    cipher.decrypt_block(&mut xn);
    // 2. Pad Cn with zeros at the end to create C of length BB.
    let mut c = [0u8; BLOCK_LENGTH];
    c[..ln].copy_from_slice(&input[cn_start..]);
    // 3. Exclusive-or Dn with C to create Xn.
    xor_into(&mut xn, &c);
    // 4. Select the first Ln bytes of Xn to create Pn.
    out[cn_start..].copy_from_slice(&xn[..ln]);
    // 5. Append the tail (BB minus Ln) bytes of Xn to Cn to create En.
    let mut en = c;
    en[ln..].copy_from_slice(&xn[ln..]);
    // 6. Decrypt En and exclusive-or with Cn-2 to create Pn-1. For short
    //    messages where Cn-2 does not exist, use the IV (RFC 3962 App. A).
    cipher.decrypt_block(&mut en);
    xor_into(&mut en, &prev);
    // 7. The last two parts of the plaintext are Pn-1 and Pn respectively.
    out[cn1_start..cn_start].copy_from_slice(&en);

    xn.zeroize();
    en.zeroize();

    // Cipher state carried out: the next-to-last block of the supplied
    // ciphertext. Spec: RFC 3962 §5; RFC 8009 §5.
    Ok((out, cn1))
}

#[cfg(test)]
mod tests {
    //! Vectors for the crate-private CBC-CTS functions. Sources: RFC 3962
    //! Appendix B (CBC with ciphertext stealing, all-zero IV) and RFC 8009
    //! Appendix A (the "AES Output" of every sample encryption). No vector
    //! comes from any other implementation.

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        assert!(s.len().is_multiple_of(2), "odd hex length in test vector");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn cipher(key_hex: &str) -> AesCipher {
        AesCipher::new(&hex(key_hex)).expect("128- or 256-bit key")
    }

    #[test]
    fn short_input_and_bad_key_rejected() {
        // RFC 3962 §5 key sizes are 128/256 bits; inputs below one block have
        // no code path here (see module docs).
        let c = AesCipher::new(&[0u8; 16]).unwrap();
        assert_eq!(encrypt_with(&c, &[0u8; 15]), Err(Error::InvalidInputLength));
        assert_eq!(decrypt_with(&c, &[]), Err(Error::InvalidInputLength));
        assert!(matches!(
            AesCipher::new(&[0u8; 24]),
            Err(Error::InvalidKeyLength)
        ));
    }

    // -- RFC 3962 Appendix B: CBC with ciphertext stealing ------------------

    /// AES 128-bit key of the RFC 3962 Appendix B CTS vectors.
    const CTS_KEY: &str = "63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69";

    /// The plaintext of the RFC 3962 Appendix B CTS vectors; each vector uses
    /// a prefix of it.
    const CTS_INPUT: &str = "49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65
                             20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43
                             68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c 20
                             61 6e 64 20 77 6f 6e 74 6f 6e 20 73 6f 75 70 2e";

    fn check_cts(input_len: usize, output: &str, next_iv: &str) {
        let c = cipher(CTS_KEY);
        let input = hex(CTS_INPUT)[..input_len].to_vec();
        let output = hex(output);
        let next_iv = hex(next_iv);

        let (ct, state) = encrypt_with(&c, &input).unwrap();
        assert_eq!(ct, output, "CTS output");
        assert_eq!(state.as_slice(), next_iv.as_slice(), "next IV (encrypt)");

        // Decryption inverts encryption and carries the next-to-last
        // ciphertext block forward (RFC 3962 §5) — the same block.
        let (pt, state) = decrypt_with(&c, &output).unwrap();
        assert_eq!(pt, input, "CTS decryption");
        assert_eq!(state.as_slice(), next_iv.as_slice(), "next IV (decrypt)");
    }

    #[test]
    fn rfc3962_b_cts_17_octets() {
        // Source: RFC 3962 Appendix B — CTS, 17-octet input.
        check_cts(
            17,
            "c6 35 35 68 f2 bf 8c b4 d8 a5 80 36 2d a7 ff 7f 97",
            "c6 35 35 68 f2 bf 8c b4 d8 a5 80 36 2d a7 ff 7f",
        );
    }

    #[test]
    fn rfc3962_b_cts_31_octets() {
        // Source: RFC 3962 Appendix B — CTS, 31-octet input.
        check_cts(
            31,
            "fc 00 78 3e 0e fd b2 c1 d4 45 d4 c8 ef f7 ed 22
             97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5",
            "fc 00 78 3e 0e fd b2 c1 d4 45 d4 c8 ef f7 ed 22",
        );
    }

    #[test]
    fn rfc3962_b_cts_32_octets() {
        // Source: RFC 3962 Appendix B — CTS, 32-octet input (two full
        // blocks: plain CBC with the last two ciphertext blocks swapped,
        // RFC 3962 §5).
        check_cts(
            32,
            "39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8
             97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84",
            "39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8",
        );
    }

    #[test]
    fn rfc3962_b_cts_47_octets() {
        // Source: RFC 3962 Appendix B — CTS, 47-octet input.
        check_cts(
            47,
            "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84
             b3 ff fd 94 0c 16 a1 8c 1b 55 49 d2 f8 38 02 9e
             39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5",
            "b3 ff fd 94 0c 16 a1 8c 1b 55 49 d2 f8 38 02 9e",
        );
    }

    #[test]
    fn rfc3962_b_cts_48_octets() {
        // Source: RFC 3962 Appendix B — CTS, 48-octet input.
        check_cts(
            48,
            "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84
             9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8
             39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8",
            "9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8",
        );
    }

    #[test]
    fn rfc3962_b_cts_64_octets() {
        // Source: RFC 3962 Appendix B — CTS, 64-octet input.
        check_cts(
            64,
            "97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84
             39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8
             48 07 ef e8 36 ee 89 a5 26 73 0d bc 2f 7b c8 40
             9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8",
            "48 07 ef e8 36 ee 89 a5 26 73 0d bc 2f 7b c8 40",
        );
    }

    // -- RFC 8009 Appendix A: "AES Output" = E(Ke, N | plaintext) ------------
    //
    // Direct evidence for docs/questions/Q-010: the RFC 3962 §5 composition
    // reproduces RFC 8009's CBC-CS3 output in every length class.

    const KE_128: &str = "9B 19 7D D1 E8 C5 60 9D 6E 67 C3 E3 7C 62 C7 2E";
    const KE_256: &str = "56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7
                          A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49";
    const PT_6: &str = "00 01 02 03 04 05";
    const PT_16: &str = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F";
    const PT_21: &str = "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14";

    fn check_aes_output(ke: &str, confounder: &str, plaintext: &str, aes_output: &str) {
        let c = cipher(ke);
        let mut input = hex(confounder);
        input.extend(hex(plaintext));
        let expected = hex(aes_output);
        let (out, _) = encrypt_with(&c, &input).unwrap();
        assert_eq!(out, expected, "AES Output");
        let (back, _) = decrypt_with(&c, &expected).unwrap();
        assert_eq!(back, input, "N | plaintext");
    }

    #[test]
    fn rfc8009_a_aes_output_128_empty() {
        // Source: RFC 8009 Appendix A — aes128-cts-hmac-sha256-128, plaintext
        // (empty): exactly one block.
        check_aes_output(
            KE_128,
            "7E 58 95 EA F2 67 24 35 BA D8 17 F5 45 A3 71 48",
            "",
            "EF 85 FB 89 0B B8 47 2F 4D AB 20 39 4D CA 78 1D",
        );
    }

    #[test]
    fn rfc8009_a_aes_output_128_less_than_block() {
        // Source: RFC 8009 Appendix A — aes128, plaintext length less than
        // block size: one block plus a partial block.
        check_aes_output(
            KE_128,
            "7B CA 28 5E 2F D4 13 0F B5 5B 1A 5C 83 BC 5B 24",
            PT_6,
            "84 D7 F3 07 54 ED 98 7B AB 0B F3 50 6B EB 09 CF B5 54 02 CE F7 E6",
        );
    }

    #[test]
    fn rfc8009_a_aes_output_128_equals_block() {
        // Source: RFC 8009 Appendix A — aes128, plaintext length equals block
        // size: two full blocks.
        check_aes_output(
            KE_128,
            "56 AB 21 71 3F F6 2C 0A 14 57 20 0F 6F A9 94 8F",
            PT_16,
            "35 17 D6 40 F5 0D DC 8A D3 62 87 22 B3 56 9D 2A
             E0 74 93 FA 82 63 25 40 80 EA 65 C1 00 8E 8F C2",
        );
    }

    #[test]
    fn rfc8009_a_aes_output_128_greater_than_block() {
        // Source: RFC 8009 Appendix A — aes128, plaintext length greater than
        // block size: two blocks plus a partial block.
        check_aes_output(
            KE_128,
            "A7 A4 E2 9A 47 28 CE 10 66 4F B6 4E 49 AD 3F AC",
            PT_21,
            "72 0F 73 B1 8D 98 59 CD 6C CB 43 46 11 5C D3 36
             C7 0F 58 ED C0 C4 43 7C 55 73 54 4C 31 C8 13 BC
             E1 E6 D0 72 C1",
        );
    }

    #[test]
    fn rfc8009_a_aes_output_256_empty() {
        // Source: RFC 8009 Appendix A — aes256-cts-hmac-sha384-192, plaintext
        // (empty).
        check_aes_output(
            KE_256,
            "F7 64 E9 FA 15 C2 76 47 8B 2C 7D 0C 4E 5F 58 E4",
            "",
            "41 F5 3F A5 BF E7 02 6D 91 FA F9 BE 95 91 95 A0",
        );
    }

    #[test]
    fn rfc8009_a_aes_output_256_less_than_block() {
        // Source: RFC 8009 Appendix A — aes256, plaintext length less than
        // block size.
        check_aes_output(
            KE_256,
            "B8 0D 32 51 C1 F6 47 14 94 25 6F FE 71 2D 0B 9A",
            PT_6,
            "4E D7 B3 7C 2B CA C8 F7 4F 23 C1 CF 07 E6 2B C7 B7 5F B3 F6 37 B9",
        );
    }

    #[test]
    fn rfc8009_a_aes_output_256_equals_block() {
        // Source: RFC 8009 Appendix A — aes256, plaintext length equals block
        // size.
        check_aes_output(
            KE_256,
            "53 BF 8A 0D 10 52 65 D4 E2 76 42 86 24 CE 5E 63",
            PT_16,
            "BC 47 FF EC 79 98 EB 91 E8 11 5C F8 D1 9D AC 4B
             BB E2 E1 63 E8 7D D3 7F 49 BE CA 92 02 77 64 F6",
        );
    }

    #[test]
    fn rfc8009_a_aes_output_256_greater_than_block() {
        // Source: RFC 8009 Appendix A — aes256, plaintext length greater than
        // block size.
        check_aes_output(
            KE_256,
            "76 3E 65 36 7E 86 4F 02 F5 51 53 C7 E3 B5 8A F1",
            PT_21,
            "40 01 3E 2D F5 8E 87 51 95 7D 28 78 BC D2 D6 FE
             10 1C CF D5 56 CB 1E AE 79 DB 3C 3E E8 64 29 F2
             B2 A6 02 AC 86",
        );
    }
}
