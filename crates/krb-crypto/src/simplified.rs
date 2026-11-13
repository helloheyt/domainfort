//! The RFC 3961 §5 "simplified profile", instantiated with the RFC 3962
//! parameters: aes128-cts-hmac-sha1-96 (17) and aes256-cts-hmac-sha1-96 (18).
//!
//! RFC 3962 §6 parameters:
//! - protocol key format: 128- or 256-bit string;
//! - string-to-key: PBKDF2 (HMAC-SHA1 PRF) + DK, default parameters
//!   00 00 10 00;
//! - key-generation seed length k: key size; random-to-key: identity;
//! - H = SHA-1; HMAC output size h = 12 octets;
//! - message block size m = 1 octet (so the padding is always empty);
//! - E and D: AES in CBC-CTS mode, cipher block size c = 16 octets.
//!
//! Spec: RFC 3961 §5.1 (DR, DK), §5.3 (cryptosystem, PRF), §5.4 (checksum);
//! RFC 3962 §4 (string-to-key), §5 (CTS), §6 (parameters); RFC 6113
//! Appendix A (the AES PRF interpretation).

use crate::cts::{self, AesCipher, BLOCK_LENGTH};
use crate::error::{Error, Result};
use crate::mac::{self, HashAlg};
use crate::nfold::n_fold;
use crate::types::{KeyUsage, SpecificKeyKind, CONFOUNDER_LENGTH};
use zeroize::Zeroizing;

/// HMAC output size h for the SHA-1 types. Spec: RFC 3962 §6.
const H_LENGTH: usize = 12;

/// The well-known constant "kerberos" used by string-to-key.
/// Spec: RFC 3962 §4 ("the 8-octet ASCII string \"kerberos\"").
const KERBEROS_CONSTANT: &[u8] = b"kerberos";

/// The PRF constant. Spec: RFC 3961 §5.3 ("The \"prfconstant\" used in the
/// PRF operation is the three-octet string \"prf\"").
const PRF_CONSTANT: &[u8] = b"prf";

/// DR(Key, Constant) = k-truncate(K1 | K2 | ...), with
/// K1 = E(Key, n-fold(Constant), initial-cipher-state),
/// K(i+1) = E(Key, Ki, initial-cipher-state).
///
/// `k_octets` is the key-generation seed length (16 or 32). The Constant is
/// n-folded to the cipher block size c = 16 octets; a Constant longer than c
/// is refused ("The size of the Constant must not be larger than c").
///
/// Spec: RFC 3961 §5.1. E is AES-CBC-CTS (RFC 3962 §6); on exactly one block
/// it is plain AES (RFC 3962 §5).
fn dr(key: &[u8], constant: &[u8], k_octets: usize) -> Result<Zeroizing<Vec<u8>>> {
    if constant.is_empty() || constant.len() > BLOCK_LENGTH {
        return Err(Error::InvalidInputLength);
    }
    let cipher = AesCipher::new(key)?;
    let mut block = Zeroizing::new(n_fold(constant, BLOCK_LENGTH)?);
    let mut out = Zeroizing::new(Vec::with_capacity(k_octets + BLOCK_LENGTH));
    while out.len() < k_octets {
        let (next, _state) = cts::encrypt_with(&cipher, &block)?;
        let next = Zeroizing::new(next);
        out.extend_from_slice(&next);
        block = next;
    }
    out.truncate(k_octets);
    Ok(out)
}

/// DK(Key, Constant) = random-to-key(DR(Key, Constant)); random-to-key is
/// the identity function for AES. Spec: RFC 3961 §5.1; RFC 3962 §6.
fn dk(key: &[u8], constant: &[u8], k_octets: usize) -> Result<Zeroizing<Vec<u8>>> {
    dr(key, constant, k_octets)
}

/// Derive Kc, Ke or Ki: DK(base-key, usage | 0x99 / 0xAA / 0x55).
/// Spec: RFC 3961 §5.3 (key-derivation function).
pub(crate) fn derive(
    base_key: &[u8],
    usage: KeyUsage,
    kind: SpecificKeyKind,
) -> Result<Zeroizing<Vec<u8>>> {
    dk(base_key, &usage.derivation_constant(kind), base_key.len())
}

/// tkey = random2key(PBKDF2(passphrase, salt, iter_count, keylength)), with
/// the HMAC-SHA1 pseudorandom function. Spec: RFC 3962 §4.
fn pbkdf2_tkey(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length: usize,
) -> Zeroizing<Vec<u8>> {
    let mut tkey = Zeroizing::new(vec![0u8; key_length]);
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(passphrase, salt, iterations, &mut tkey);
    tkey
}

/// key = DK(tkey, "kerberos"). Spec: RFC 3962 §4.
pub(crate) fn string_to_key(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let tkey = pbkdf2_tkey(passphrase, salt, iterations, key_length);
    dk(&tkey, KERBEROS_CONSTANT, key_length)
}

/// Encryption function of the simplified profile, initial cipher state:
///
/// ```text
/// conf = confounder (length c)
/// pad  = empty (m = 1 octet)
/// (C1, newIV) = E(Ke, conf | plaintext | pad, oldstate.ivec)
/// H1 = HMAC(Ki, conf | plaintext | pad)
/// ciphertext = C1 | H1[1..h]
/// ```
///
/// Spec: RFC 3961 §5.3; RFC 3962 §6 (m = 1, h = 12, H = SHA-1).
pub(crate) fn encrypt(
    base_key: &[u8],
    usage: KeyUsage,
    confounder: &[u8; CONFOUNDER_LENGTH],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let ke = derive(base_key, usage, SpecificKeyKind::Ke)?;
    let ki = derive(base_key, usage, SpecificKeyKind::Ki)?;

    // conf | plaintext | pad, with pad empty because m = 1 octet.
    let mut p1 = Zeroizing::new(Vec::with_capacity(CONFOUNDER_LENGTH + plaintext.len()));
    p1.extend_from_slice(confounder);
    p1.extend_from_slice(plaintext);

    let cipher = AesCipher::new(&ke)?;
    let (c1, _new_ivec) = cts::encrypt_with(&cipher, &p1)?;
    let h1 = mac::hmac(HashAlg::Sha1, &ki, &[&p1])?;

    let mut ciphertext = c1;
    ciphertext.extend_from_slice(&h1[..H_LENGTH]);
    Ok(ciphertext)
}

/// Decryption function of the simplified profile, initial cipher state:
///
/// ```text
/// (C1, H1) = ciphertext
/// (P1, newIV) = D(Ke, C1, oldstate.ivec)
/// if (H1 != HMAC(Ki, P1)[1..h]) report error
/// ```
///
/// On success the confounder (the first c octets of P1) is removed: RFC 3961
/// §3 requires that any extra octets of a decryption come after the
/// plaintext, and the pad is empty (m = 1), so the plaintext is P1 without
/// its leading confounder. On failure P1 is discarded (zeroized).
///
/// Spec: RFC 3961 §3 (decrypt), §5.3; RFC 3962 §6.
pub(crate) fn decrypt(base_key: &[u8], usage: KeyUsage, ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < CONFOUNDER_LENGTH + H_LENGTH {
        return Err(Error::CiphertextTooShort);
    }
    let (c1, h1) = ciphertext.split_at(ciphertext.len() - H_LENGTH);

    let ke = derive(base_key, usage, SpecificKeyKind::Ke)?;
    let ki = derive(base_key, usage, SpecificKeyKind::Ki)?;

    let cipher = AesCipher::new(&ke)?;
    let (p1, _new_ivec) = cts::decrypt_with(&cipher, c1)?;
    let p1 = Zeroizing::new(p1);

    if !mac::verify_truncated(HashAlg::Sha1, &ki, &[&p1], h1)? {
        return Err(Error::IntegrityCheckFailed);
    }
    Ok(p1[CONFOUNDER_LENGTH..].to_vec())
}

/// get_mic = HMAC(Kc, message)[1..h]. Spec: RFC 3961 §5.4; RFC 3962 §6.
pub(crate) fn get_mic(base_key: &[u8], usage: KeyUsage, message: &[u8]) -> Result<Vec<u8>> {
    let kc = derive(base_key, usage, SpecificKeyKind::Kc)?;
    let full = mac::hmac(HashAlg::Sha1, &kc, &[message])?;
    Ok(full[..H_LENGTH].to_vec())
}

/// verify_mic = get_mic and compare (constant-time, exact length h).
/// Spec: RFC 3961 §4, §5.4; RFC 3962 §6, §7.
pub(crate) fn verify_mic(
    base_key: &[u8],
    usage: KeyUsage,
    message: &[u8],
    mic: &[u8],
) -> Result<()> {
    if mic.len() != H_LENGTH {
        return Err(Error::InvalidChecksumLength);
    }
    let kc = derive(base_key, usage, SpecificKeyKind::Kc)?;
    if mac::verify_truncated(HashAlg::Sha1, &kc, &[message], mic)? {
        Ok(())
    } else {
        Err(Error::ChecksumVerificationFailed)
    }
}

/// The pseudo-random operation for etypes 17/18:
///
/// ```text
/// tmp1 = H(octet-string)                      (SHA-1, 20 octets)
/// tmp2 = trunc128(tmp1)                       (first 16 octets)
/// PRF  = E(DK(protocol-key, "prf"), tmp2, initial-cipher-state)
/// ```
///
/// RFC 3961 §5.3 gives the template (`tmp1 = H(octet-string)`, `PRF =
/// E(DK(protocol-key, prfconstant), tmp2, initial-cipher-state)`,
/// prfconstant = the three-octet string "prf"). Its truncation step is the
/// ambiguous part for AES; RFC 6113 Appendix A states the interpretation
/// that resolves it: "the AES pseudo-random operation is
/// aes-ecb(trunc128(sha-1(input)))". tmp2 is therefore exactly one AES
/// block, and E on exactly one block is plain AES (RFC 3962 §5). The output
/// is 16 octets. Decision recorded in docs/questions/Q-011 (resolved).
///
/// Spec: RFC 3961 §3 (pseudo-random), §5.3; RFC 3962 §5, §6; RFC 6113 App. A.
pub(crate) fn pseudo_random(base_key: &[u8], octet_string: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use sha1::{Digest, Sha1};

    // prfconstant = "prf" (RFC 3961 §5.3); DK n-folds it to one block.
    let kprf = dk(base_key, PRF_CONSTANT, base_key.len())?;
    // tmp1 = SHA-1(octet-string); tmp2 = its first 128 bits (RFC 6113 App. A).
    let tmp1 = Sha1::digest(octet_string);
    let tmp2 = tmp1.get(..BLOCK_LENGTH).ok_or(Error::InvalidInputLength)?;
    // One-block E with the initial cipher state = AES (RFC 3962 §5).
    let cipher = AesCipher::new(&kprf)?;
    let (out, _state) = cts::encrypt_with(&cipher, tmp2)?;
    Ok(Zeroizing::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Intermediate values of RFC 3962 Appendix B: the PBKDF2 output (tkey)
    // and DK(tkey, "kerberos"). The integration tests check only the final
    // key; these pin down each half separately.

    #[test]
    fn rfc3962_appendix_b_pbkdf2_iter1() {
        // Source: RFC 3962 Appendix B, iteration count = 1, "password",
        // salt "ATHENA.MIT.EDUraeburn".
        let t = pbkdf2_tkey(b"password", b"ATHENA.MIT.EDUraeburn", 1, 32);
        assert_eq!(
            t.as_slice(),
            hex("cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15
                 0a d1 f7 a0 4b b9 f3 a3 33 ec c0 e2 e1 f7 08 37")
        );
        let t = pbkdf2_tkey(b"password", b"ATHENA.MIT.EDUraeburn", 1, 16);
        assert_eq!(
            t.as_slice(),
            hex("cd ed b5 28 1b b2 f8 01 56 5a 11 22 b2 56 35 15")
        );
    }

    #[test]
    fn rfc3962_appendix_b_dk_from_pbkdf2_output() {
        // Source: RFC 3962 Appendix B, iteration count = 2: DK(tkey,
        // "kerberos") of the listed PBKDF2 output equals the listed AES key.
        let tkey128 = hex("01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d");
        assert_eq!(
            dk(&tkey128, KERBEROS_CONSTANT, 16).unwrap().as_slice(),
            hex("c6 51 bf 29 e2 30 0a c2 7f a4 69 d6 93 bd da 13")
        );
        let tkey256 = hex("01 db ee 7f 4a 9e 24 3e 98 8b 62 c7 3c da 93 5d
             a0 53 78 b9 32 44 ec 8f 48 a9 9e 61 ad 79 9d 86");
        assert_eq!(
            dk(&tkey256, KERBEROS_CONSTANT, 32).unwrap().as_slice(),
            hex("a2 e1 6d 16 b3 60 69 c1 35 d5 e9 d2 e2 5f 89 61
                 02 68 56 18 b9 59 14 b4 67 c6 76 22 22 58 24 ff")
        );
    }

    #[test]
    fn dr_rejects_oversized_constant() {
        // RFC 3961 §5.1: "The size of the Constant must not be larger than c".
        assert_eq!(
            dr(&[0u8; 16], &[0u8; 17], 16).err(),
            Some(Error::InvalidInputLength)
        );
    }
}
