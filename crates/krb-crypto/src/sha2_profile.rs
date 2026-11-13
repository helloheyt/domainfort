//! The RFC 8009 profile: aes128-cts-hmac-sha256-128 (19) and
//! aes256-cts-hmac-sha384-192 (20).
//!
//! These types conform to the RFC 3961 framework but NOT to its simplified
//! profile: keys are derived with KDF-HMAC-SHA2 (SP 800-108 counter mode with
//! HMAC, as framed by RFC 8009 §3), and the HMAC is computed over the cipher
//! state concatenated with the AES output (encrypt-then-MAC), so integrity is
//! verified before anything is decrypted.
//!
//! Spec: RFC 8009 §3 (KDF), §4 (string-to-key), §5 (encryption, PRF), §6
//! (checksum).

use crate::cts::{self, AesCipher, BLOCK_LENGTH};
use crate::error::{Error, Result};
use crate::mac::{self, HashAlg};
use crate::types::{EncType, KeyUsage, SpecificKeyKind, CONFOUNDER_LENGTH};
use zeroize::Zeroizing;

/// Per-enctype parameters of RFC 8009.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Params {
    /// HMAC hash. Spec: RFC 8009 §3, §5.
    hash: HashAlg,
    /// Protocol key length (128 or 256 bits) in octets. Spec: RFC 8009 §5.
    key_octets: usize,
    /// Truncated HMAC length h in octets (128 or 192 bits). Spec: RFC 8009 §5.
    h_octets: usize,
    /// Kc and Ki length (128 or 192 bits) in octets. Spec: RFC 8009 §5.
    kc_ki_octets: usize,
    /// PRF output length k (256 or 384 bits) in octets. Spec: RFC 8009 §5.
    prf_octets: usize,
    /// The enctype name prepended to the salt. Spec: RFC 8009 §4.
    name: &'static [u8],
}

impl Params {
    /// Spec: RFC 8009 §3, §4, §5.
    pub(crate) fn for_enc_type(enc_type: EncType) -> Result<Self> {
        match enc_type {
            EncType::Aes128CtsHmacSha256128 => Ok(Params {
                hash: HashAlg::Sha256,
                key_octets: 16,
                h_octets: 16,
                kc_ki_octets: 16,
                prf_octets: 32,
                name: b"aes128-cts-hmac-sha256-128",
            }),
            EncType::Aes256CtsHmacSha384192 => Ok(Params {
                hash: HashAlg::Sha384,
                key_octets: 32,
                h_octets: 24,
                kc_ki_octets: 24,
                prf_octets: 48,
                name: b"aes256-cts-hmac-sha384-192",
            }),
            // The RFC 3962 types are handled by `simplified`; reaching here
            // with one of them is a dispatch error — fail closed.
            EncType::Aes128CtsHmacSha196 | EncType::Aes256CtsHmacSha196 => {
                Err(Error::UnsupportedEncType)
            }
        }
    }
}

/// KDF-HMAC-SHA2(key, label, [context,] k) = k-truncate(K1), with
/// K1 = HMAC-SHA2(key, 0x00000001 | label | 0x00 | [context |] k), where k
/// (in bits) is encoded as four big-endian octets and 0x00000001 is the
/// SP 800-108 iteration counter i.
///
/// `k_octets` is k in octets; it never exceeds the hash output length (k ≤ 256
/// bits for SHA-256, ≤ 384 bits for SHA-384), which RFC 8009 §3 requires.
///
/// Spec: RFC 8009 §3.
fn kdf_hmac_sha2(
    hash: HashAlg,
    key: &[u8],
    label: &[u8],
    context: Option<&[u8]>,
    k_octets: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let k_bits = u32::try_from(k_octets * 8).map_err(|_| Error::InvalidInputLength)?;
    let k_be = k_bits.to_be_bytes();
    let counter: [u8; 4] = 1u32.to_be_bytes();
    let separator: [u8; 1] = [0x00];
    let k1 = match context {
        None => mac::hmac(hash, key, &[&counter, label, &separator, &k_be])?,
        Some(ctx) => mac::hmac(hash, key, &[&counter, label, &separator, ctx, &k_be])?,
    };
    if k_octets > k1.len() {
        return Err(Error::InvalidInputLength);
    }
    // k-truncate: the k leftmost bits (RFC 3961 §5.1; RFC 8009 §3).
    Ok(Zeroizing::new(k1[..k_octets].to_vec()))
}

/// Derive Kc, Ke or Ki: KDF-HMAC-SHA2(base-key, usage | 0x99 / 0xAA / 0x55,
/// k), with k = 128 for all three keys of etype 19, and k = 192 (Kc, Ki) /
/// 256 (Ke) for etype 20. Spec: RFC 8009 §5.
pub(crate) fn derive(
    p: &Params,
    base_key: &[u8],
    usage: KeyUsage,
    kind: SpecificKeyKind,
) -> Result<Zeroizing<Vec<u8>>> {
    let k_octets = match kind {
        SpecificKeyKind::Ke => p.key_octets,
        SpecificKeyKind::Kc | SpecificKeyKind::Ki => p.kc_ki_octets,
    };
    kdf_hmac_sha2(
        p.hash,
        base_key,
        &usage.derivation_constant(kind),
        None,
        k_octets,
    )
}

/// The salt actually fed to PBKDF2: saltp = enctype-name | 0x00 | salt.
/// Spec: RFC 8009 §4.
fn saltp(p: &Params, salt: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(p.name.len() + 1 + salt.len());
    s.extend_from_slice(p.name);
    s.push(0x00);
    s.extend_from_slice(salt);
    s
}

/// tkey = random-to-key(PBKDF2(passphrase, saltp, iter_count, keylength));
/// base-key = random-to-key(KDF-HMAC-SHA2(tkey, "kerberos", keylength)).
/// PBKDF2's PRF is HMAC-SHA-256 (etype 19) or HMAC-SHA-384 (etype 20);
/// random-to-key is the identity. Spec: RFC 8009 §4, §5.
pub(crate) fn string_to_key(
    p: &Params,
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    let saltp = saltp(p, salt);
    let mut tkey = Zeroizing::new(vec![0u8; p.key_octets]);
    match p.hash {
        HashAlg::Sha256 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase, &saltp, iterations, &mut tkey)
        }
        HashAlg::Sha384 => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha384>(passphrase, &saltp, iterations, &mut tkey)
        }
        HashAlg::Sha1 => return Err(Error::UnsupportedEncType),
    }
    // "kerberos" is the octet-string 0x6B65726265726F73 (RFC 8009 §4).
    kdf_hmac_sha2(p.hash, &tkey, b"kerberos", None, p.key_octets)
}

/// Encryption function, initial cipher state (IV all bits zero):
///
/// ```text
/// N = confounder (128 bits)
/// IV = cipher state
/// C = E(Ke, N | plaintext, IV)
/// H = HMAC(Ki, IV | C)
/// ciphertext = C | H[1..h]
/// ```
///
/// Spec: RFC 8009 §5.
pub(crate) fn encrypt(
    p: &Params,
    base_key: &[u8],
    usage: KeyUsage,
    confounder: &[u8; CONFOUNDER_LENGTH],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let ke = derive(p, base_key, usage, SpecificKeyKind::Ke)?;
    let ki = derive(p, base_key, usage, SpecificKeyKind::Ki)?;
    let iv = [0u8; BLOCK_LENGTH]; // initial cipher state (RFC 8009 §5)

    let mut input = Zeroizing::new(Vec::with_capacity(CONFOUNDER_LENGTH + plaintext.len()));
    input.extend_from_slice(confounder);
    input.extend_from_slice(plaintext);

    let cipher = AesCipher::new(&ke)?;
    let (c, _next_state) = cts::encrypt_with(&cipher, &input)?;
    let h = mac::hmac(p.hash, &ki, &[&iv, &c])?;

    let mut ciphertext = c;
    ciphertext.extend_from_slice(&h[..p.h_octets]);
    Ok(ciphertext)
}

/// Decryption function, initial cipher state (IV all bits zero):
///
/// ```text
/// (C, H) = ciphertext          (H is the last h octets)
/// IV = cipher state
/// if H != HMAC(Ki, IV | C)[1..h] then stop, report error
/// (N, P) = D(Ke, C, IV)        (N is the first block)
/// ```
///
/// The HMAC is verified BEFORE any decryption; only P is returned.
/// Spec: RFC 8009 §5.
pub(crate) fn decrypt(
    p: &Params,
    base_key: &[u8],
    usage: KeyUsage,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.len() < CONFOUNDER_LENGTH + p.h_octets {
        return Err(Error::CiphertextTooShort);
    }
    let (c, h) = ciphertext.split_at(ciphertext.len() - p.h_octets);
    let iv = [0u8; BLOCK_LENGTH];

    let ki = derive(p, base_key, usage, SpecificKeyKind::Ki)?;
    if !mac::verify_truncated(p.hash, &ki, &[&iv, c], h)? {
        return Err(Error::IntegrityCheckFailed);
    }

    let ke = derive(p, base_key, usage, SpecificKeyKind::Ke)?;
    let cipher = AesCipher::new(&ke)?;
    let (np, _next_state) = cts::decrypt_with(&cipher, c)?;
    let np = Zeroizing::new(np);
    Ok(np[CONFOUNDER_LENGTH..].to_vec())
}

/// PRF = KDF-HMAC-SHA2(input-key, "prf", octet-string, 256 or 384), where
/// "prf" is the octet-string 0x707266. Spec: RFC 8009 §5.
pub(crate) fn pseudo_random(
    p: &Params,
    base_key: &[u8],
    octet_string: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    kdf_hmac_sha2(p.hash, base_key, b"prf", Some(octet_string), p.prf_octets)
}

/// get_mic = HMAC(Kc, message)[1..h]. Spec: RFC 8009 §6.
pub(crate) fn get_mic(
    p: &Params,
    base_key: &[u8],
    usage: KeyUsage,
    message: &[u8],
) -> Result<Vec<u8>> {
    let kc = derive(p, base_key, usage, SpecificKeyKind::Kc)?;
    let full = mac::hmac(p.hash, &kc, &[message])?;
    Ok(full[..p.h_octets].to_vec())
}

/// verify_mic = get_mic and compare (constant-time, exact length h).
/// Spec: RFC 8009 §6.
pub(crate) fn verify_mic(
    p: &Params,
    base_key: &[u8],
    usage: KeyUsage,
    message: &[u8],
    mic: &[u8],
) -> Result<()> {
    if mic.len() != p.h_octets {
        return Err(Error::InvalidChecksumLength);
    }
    let kc = derive(p, base_key, usage, SpecificKeyKind::Kc)?;
    if mac::verify_truncated(p.hash, &kc, &[message], mic)? {
        Ok(())
    } else {
        Err(Error::ChecksumVerificationFailed)
    }
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

    /// The random 16-octet UTF-8 prefix of the RFC 8009 Appendix A salt.
    const SALT: &str = "10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61
                        41 54 48 45 4E 41 2E 4D 49 54 2E 45 44 55 72 61
                        65 62 75 72 6E";

    #[test]
    fn rfc8009_appendix_a_saltp_128() {
        // Source: RFC 8009 Appendix A, "Saltp for creating 128-bit base-key".
        let p = Params::for_enc_type(EncType::Aes128CtsHmacSha256128).unwrap();
        assert_eq!(
            saltp(&p, &hex(SALT)),
            hex("61 65 73 31 32 38 2D 63 74 73 2D 68 6D 61 63 2D
                 73 68 61 32 35 36 2D 31 32 38 00 10 DF 9D D7 83
                 E5 BC 8A CE A1 73 0E 74 35 5F 61 41 54 48 45 4E
                 41 2E 4D 49 54 2E 45 44 55 72 61 65 62 75 72 6E")
        );
    }

    #[test]
    fn rfc8009_appendix_a_saltp_256() {
        // Source: RFC 8009 Appendix A, "Saltp for creating 256-bit base-key".
        let p = Params::for_enc_type(EncType::Aes256CtsHmacSha384192).unwrap();
        assert_eq!(
            saltp(&p, &hex(SALT)),
            hex("61 65 73 32 35 36 2D 63 74 73 2D 68 6D 61 63 2D
                 73 68 61 33 38 34 2D 31 39 32 00 10 DF 9D D7 83
                 E5 BC 8A CE A1 73 0E 74 35 5F 61 41 54 48 45 4E
                 41 2E 4D 49 54 2E 45 44 55 72 61 65 62 75 72 6E")
        );
    }

    #[test]
    fn rfc8009_appendix_a_prf_input_message() {
        // Source: RFC 8009 Appendix A, PRF "HMAC-SHA-256 input message" —
        // the K1 HMAC input is 00000001 | "prf" | 00 | "test" | 00000100.
        // Checked indirectly: HMAC over that exact message equals the PRF.
        let key = hex("37 05 D9 60 80 C1 77 28 A0 E8 00 EA B6 E0 D2 3C");
        let msg = hex("00 00 00 01 70 72 66 00 74 65 73 74 00 00 01 00");
        let direct = mac::hmac(HashAlg::Sha256, &key, &[&msg]).unwrap();
        let p = Params::for_enc_type(EncType::Aes128CtsHmacSha256128).unwrap();
        let prf = pseudo_random(&p, &key, b"test").unwrap();
        assert_eq!(prf.as_slice(), direct.as_slice());
    }
}
