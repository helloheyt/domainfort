//! The RFC 3961 encryption-mechanism and checksum-mechanism operations for
//! the four AES encryption types, dispatched to the RFC 3962 (simplified
//! profile) or RFC 8009 definitions; plus PRF+ and KRB-FX-CF2, which RFC 6113
//! builds on the RFC 3961 pseudo-random operation.
//!
//! Spec: RFC 3961 §3 (encryption profile), §4 (checksum profile); RFC 3962;
//! RFC 8009; RFC 6113 §5.1.

use crate::error::{Error, Result};
use crate::key::{ProtocolKey, SpecificKey};
use crate::sha2_profile::{self, Params};
use crate::simplified;
use crate::types::{ChecksumType, EncType, KeyUsage, SpecificKeyKind, CONFOUNDER_LENGTH};
use zeroize::Zeroizing;

/// Which family an encryption type belongs to.
enum Family {
    /// RFC 3961 §5 simplified profile with RFC 3962 parameters (17, 18).
    Rfc3962,
    /// RFC 8009 (19, 20).
    Rfc8009(Params),
}

fn family(enc_type: EncType) -> Result<Family> {
    match enc_type {
        EncType::Aes128CtsHmacSha196 | EncType::Aes256CtsHmacSha196 => Ok(Family::Rfc3962),
        EncType::Aes128CtsHmacSha256128 | EncType::Aes256CtsHmacSha384192 => {
            Ok(Family::Rfc8009(Params::for_enc_type(enc_type)?))
        }
    }
}

/// The default string-to-key iteration count when no parameters are given:
/// 4,096 (00 00 10 00) for etypes 17/18, 32,768 for etypes 19/20.
/// Spec: RFC 3962 §4, §6; RFC 8009 §4, §5.
fn default_iteration_count(enc_type: EncType) -> u64 {
    match enc_type {
        EncType::Aes128CtsHmacSha196 | EncType::Aes256CtsHmacSha196 => 4_096,
        EncType::Aes128CtsHmacSha256128 | EncType::Aes256CtsHmacSha384192 => 32_768,
    }
}

/// The PBKDF2 iteration count named by a string-to-key parameter block.
///
/// `s2kparams` is `None` when the parameters are absent (the enctype default
/// applies). When present it must be exactly four octets: an unsigned
/// big-endian iteration count, where 00 00 00 00 means 2^32. The result is a
/// `u64` so that 2^32 is representable; callers can apply a site lower bound
/// with it (RFC 3962 §8).
///
/// Errors: [`Error::InvalidS2kParams`] if present and not four octets.
/// Spec: RFC 3962 §4; RFC 8009 §4.
pub fn iteration_count(enc_type: EncType, s2kparams: Option<&[u8]>) -> Result<u64> {
    match s2kparams {
        None => Ok(default_iteration_count(enc_type)),
        Some(params) => {
            let octets: [u8; 4] = params.try_into().map_err(|_| Error::InvalidS2kParams)?;
            let n = u32::from_be_bytes(octets);
            if n == 0 {
                // "If the value is 00 00 00 00, the number of iterations to be
                // performed is 4,294,967,296 (2**32)." (RFC 3962 §4)
                Ok(1u64 << 32)
            } else {
                Ok(u64::from(n))
            }
        }
    }
}

/// random-to-key: the identity function on a bitstring of exactly the
/// key-generation seed length K (16 or 32 octets).
///
/// Errors: [`Error::InvalidKeyLength`] if `random` is not exactly K octets.
/// Spec: RFC 3961 §3; RFC 3962 §4, §6; RFC 8009 §5.
pub fn random_to_key(enc_type: EncType, random: &[u8]) -> Result<ProtocolKey> {
    ProtocolKey::from_checked(enc_type, random).ok_or(Error::InvalidKeyLength)
}

/// string-to-key(passphrase, salt, params) -> protocol key.
///
/// - Etypes 17/18: key = DK(PBKDF2-HMAC-SHA1(passphrase, salt, iter, keylen),
///   "kerberos") (RFC 3962 §4).
/// - Etypes 19/20: base-key = KDF-HMAC-SHA2(PBKDF2-HMAC-SHA2(passphrase,
///   enctype-name | 0x00 | salt, iter, keylen), "kerberos", keylen)
///   (RFC 8009 §4).
///
/// `passphrase` and `salt` are UTF-8 strings (RFC 3961 §3: strings in other
/// encodings must first be converted to UTF-8). `s2kparams` is the opaque
/// parameter block, `None` when absent (see [`iteration_count`]).
///
/// `max_iterations` is the caller's upper bound on the iteration count: a
/// parameter block naming more iterations is refused with
/// [`Error::IterationCountAboveLimit`] before any work is done. RFC 3962 §4
/// and §8 recommend such a bound against a spoofed parameter (any such limit
/// "SHOULD be no less than 50,000") and leave its value to site policy, so
/// the policy lives with the caller, not in this crate. Because the bound is
/// a `u32`, the 2^32 count of a 00 00 00 00 block is always refused.
///
/// Spec: RFC 3961 §3; RFC 3962 §4, §6, §8; RFC 8009 §4, §5.
pub fn string_to_key(
    enc_type: EncType,
    passphrase: &str,
    salt: &str,
    s2kparams: Option<&[u8]>,
    max_iterations: u32,
) -> Result<ProtocolKey> {
    let count = iteration_count(enc_type, s2kparams)?;
    if count > u64::from(max_iterations) {
        return Err(Error::IterationCountAboveLimit);
    }
    let iterations = u32::try_from(count).map_err(|_| Error::IterationCountAboveLimit)?;
    let octets = match family(enc_type)? {
        Family::Rfc3962 => simplified::string_to_key(
            passphrase.as_bytes(),
            salt.as_bytes(),
            iterations,
            enc_type.key_length(),
        )?,
        Family::Rfc8009(p) => {
            sha2_profile::string_to_key(&p, passphrase.as_bytes(), salt.as_bytes(), iterations)?
        }
    };
    ProtocolKey::from_checked(enc_type, &octets).ok_or(Error::InvalidKeyLength)
}

fn derive_octets(
    key: &ProtocolKey,
    usage: KeyUsage,
    kind: SpecificKeyKind,
) -> Result<Zeroizing<Vec<u8>>> {
    match family(key.enc_type())? {
        Family::Rfc3962 => simplified::derive(key.octets(), usage, kind),
        Family::Rfc8009(p) => sha2_profile::derive(&p, key.octets(), usage, kind),
    }
}

/// key-derivation(protocol-key, usage) -> one specific key (Kc, Ke or Ki).
///
/// - Etypes 17/18: DK(base-key, usage | 0x99 / 0xAA / 0x55) (RFC 3961 §5.3).
/// - Etypes 19/20: KDF-HMAC-SHA2(base-key, usage | 0x99 / 0xAA / 0x55, k)
///   (RFC 8009 §5).
///
/// [`encrypt`], [`decrypt`], [`get_mic`] and [`verify_mic`] derive what they
/// need internally; this function exists for callers that must cache a
/// specific key and for the published key-derivation vectors.
///
/// Spec: RFC 3961 §3 (key-derivation), §5.3; RFC 8009 §5.
pub fn derive_key(
    key: &ProtocolKey,
    usage: KeyUsage,
    kind: SpecificKeyKind,
) -> Result<SpecificKey> {
    let octets = derive_octets(key, usage, kind)?;
    SpecificKey::from_octets(kind, &octets).ok_or(Error::InvalidKeyLength)
}

/// encrypt(key, usage, plaintext) with the initial cipher state, using the
/// caller-supplied confounder.
///
/// This crate never generates randomness: the confounder MUST be a fresh
/// random block from an approved source chosen by the caller (`keyd`)
/// (RFC 3961 §3 "Some random factor such as a confounder should be
/// included"; RFC 8009 §8 on random-number quality).
///
/// Output: etypes 17/18 — C1 | HMAC-SHA1(Ki, conf | plaintext)[1..12]
/// (RFC 3961 §5.3, RFC 3962 §6); etypes 19/20 — C | HMAC(Ki, IV | C)[1..h]
/// (RFC 8009 §5). Every plaintext, including the empty one, is accepted
/// (RFC 3961 §3: no input octet string may result in an error indication).
///
/// Spec: RFC 3961 §3 (encrypt), §5.3; RFC 3962 §5, §6; RFC 8009 §5.
pub fn encrypt(
    key: &ProtocolKey,
    usage: KeyUsage,
    confounder: &[u8; CONFOUNDER_LENGTH],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    match family(key.enc_type())? {
        Family::Rfc3962 => simplified::encrypt(key.octets(), usage, confounder, plaintext),
        Family::Rfc8009(p) => sha2_profile::encrypt(&p, key.octets(), usage, confounder, plaintext),
    }
}

/// decrypt(key, usage, ciphertext) with the initial cipher state.
///
/// Verifies integrity and returns the plaintext without the confounder.
/// Errors (all fail closed, nothing is returned on failure):
/// [`Error::CiphertextTooShort`] if the input is shorter than the confounder
/// plus the truncated HMAC; [`Error::IntegrityCheckFailed`] if the HMAC does
/// not match (tampering, wrong key, or wrong key usage).
///
/// Etypes 19/20 check the HMAC before decrypting (RFC 8009 §5); etypes 17/18
/// decrypt and then check the HMAC over the plaintext, as their definition
/// requires (RFC 3961 §5.3).
///
/// The plaintext is returned in a zeroizing buffer: it often carries keys.
///
/// Spec: RFC 3961 §3 (decrypt), §5.3; RFC 3962 §6; RFC 8009 §5.
pub fn decrypt(
    key: &ProtocolKey,
    usage: KeyUsage,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let plaintext = match family(key.enc_type())? {
        Family::Rfc3962 => simplified::decrypt(key.octets(), usage, ciphertext)?,
        Family::Rfc8009(p) => sha2_profile::decrypt(&p, key.octets(), usage, ciphertext)?,
    };
    Ok(Zeroizing::new(plaintext))
}

/// The checksum type must be the one associated with the key's encryption
/// type. Spec: RFC 3961 §4; RFC 3962 §7; RFC 8009 §6.
fn check_cksumtype(key: &ProtocolKey, cksumtype: ChecksumType) -> Result<()> {
    if cksumtype.enc_type() != key.enc_type() {
        return Err(Error::ChecksumTypeNotForKey);
    }
    Ok(())
}

/// get_mic(key, usage, message) = HMAC(Kc, message)[1..h].
///
/// Errors: [`Error::ChecksumTypeNotForKey`] if `cksumtype` is not the
/// checksum type associated with the key's encryption type.
///
/// Spec: RFC 3961 §4 (get_mic), §5.4; RFC 3962 §6, §7; RFC 8009 §6.
pub fn get_mic(
    key: &ProtocolKey,
    cksumtype: ChecksumType,
    usage: KeyUsage,
    message: &[u8],
) -> Result<Vec<u8>> {
    check_cksumtype(key, cksumtype)?;
    match family(key.enc_type())? {
        Family::Rfc3962 => simplified::get_mic(key.octets(), usage, message),
        Family::Rfc8009(p) => sha2_profile::get_mic(&p, key.octets(), usage, message),
    }
}

/// verify_mic(key, usage, message, mic): get_mic and compare, in constant
/// time, requiring the exact checksum length h.
///
/// Errors: [`Error::ChecksumTypeNotForKey`]; [`Error::InvalidChecksumLength`]
/// if `mic` is not exactly h octets; [`Error::ChecksumVerificationFailed`] if
/// it does not match.
///
/// Spec: RFC 3961 §4 (verify_mic), §5.4; RFC 3962 §6, §7; RFC 8009 §6.
pub fn verify_mic(
    key: &ProtocolKey,
    cksumtype: ChecksumType,
    usage: KeyUsage,
    message: &[u8],
    mic: &[u8],
) -> Result<()> {
    check_cksumtype(key, cksumtype)?;
    match family(key.enc_type())? {
        Family::Rfc3962 => simplified::verify_mic(key.octets(), usage, message, mic),
        Family::Rfc8009(p) => sha2_profile::verify_mic(&p, key.octets(), usage, message, mic),
    }
}

/// pseudo-random(protocol-key, octet-string) -> octet-string.
///
/// - Etypes 17/18: AES(DK(key, "prf"), trunc128(SHA-1(octet-string))), a
///   16-octet output. RFC 3961 §5.3 is the template; RFC 6113 Appendix A
///   states the interpretation of its truncation step for AES
///   ("aes-ecb(trunc128(sha-1(input)))"); docs/questions/Q-011 (resolved).
/// - Etypes 19/20: KDF-HMAC-SHA2(key, "prf", octet-string, 256 or 384), a
///   32- or 48-octet output (RFC 8009 §5).
///
/// The output may be used as key material (RFC 3961 §3), so it is returned
/// in a zeroizing buffer.
///
/// Spec: RFC 3961 §3 (pseudo-random), §5.3; RFC 6113 App. A; RFC 8009 §5.
pub fn pseudo_random(key: &ProtocolKey, octet_string: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    match family(key.enc_type())? {
        Family::Rfc3962 => simplified::pseudo_random(key.octets(), octet_string),
        Family::Rfc8009(p) => sha2_profile::pseudo_random(&p, key.octets(), octet_string),
    }
}

/// PRF+(key, shared-info) := pseudo-random(key, 1 || shared-info) ||
/// pseudo-random(key, 2 || shared-info) || ..., with the counter encoded as
/// a one-octet integer starting at 1, generated until `output_octets` octets
/// are available; unneeded octets are removed from the tail.
///
/// The counter is one octet, so at most 255 pseudo-random outputs can be
/// produced; asking for more is [`Error::InvalidInputLength`] (in this crate
/// the request is at most 32 octets, i.e. at most two invocations).
///
/// Spec: RFC 6113 §5.1.
fn prf_plus(
    key: &ProtocolKey,
    shared_info: &[u8],
    output_octets: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(output_octets + 48));
    let mut input = Zeroizing::new(Vec::with_capacity(1 + shared_info.len()));
    let mut counter: u8 = 1;
    while out.len() < output_octets {
        input.clear();
        input.push(counter);
        input.extend_from_slice(shared_info);
        let block = pseudo_random(key, &input)?;
        if block.is_empty() {
            return Err(Error::InvalidInputLength);
        }
        out.extend_from_slice(&block);
        counter = counter.checked_add(1).ok_or(Error::InvalidInputLength)?;
    }
    out.truncate(output_octets);
    Ok(out)
}

/// KRB-FX-CF2(K1, K2, pepper1, pepper2) := random-to-key(PRF+(K1, pepper1)
/// ^ PRF+(K2, pepper2)).
///
/// - The resulting enctype is the enctype of `k1` ("Unless otherwise
///   specified, the resulting enctype of KRB-FX-CF2 is the enctype of k1").
/// - Each PRF+ produces exactly as many octets as random-to-key needs for the
///   resulting enctype (its key length K), each using the pseudo-random
///   operation of its own input key.
/// - `k1` and `k2` may be of different enctypes: RFC 6113 §5.1 says "K1 and
///   K2 can be of two different enctypes", so a mismatch is NOT rejected.
/// - `pepper1` and `pepper2` must differ ("MUST be distinct"); equal peppers
///   are refused with [`Error::PeppersNotDistinct`] (fail closed).
///
/// Spec: RFC 6113 §5.1; vectors in RFC 6113 Appendix A (etypes 17, 18).
pub fn krb_fx_cf2(
    k1: &ProtocolKey,
    k2: &ProtocolKey,
    pepper1: &[u8],
    pepper2: &[u8],
) -> Result<ProtocolKey> {
    if pepper1 == pepper2 {
        return Err(Error::PeppersNotDistinct);
    }
    let result_enc_type = k1.enc_type();
    let k = result_enc_type.key_length();
    let octet_string_1 = prf_plus(k1, pepper1, k)?;
    let octet_string_2 = prf_plus(k2, pepper2, k)?;
    let mut combined = Zeroizing::new(vec![0u8; k]);
    for ((c, a), b) in combined
        .iter_mut()
        .zip(octet_string_1.iter())
        .zip(octet_string_2.iter())
    {
        *c = a ^ b;
    }
    // random-to-key of the resulting enctype (identity on K octets).
    random_to_key(result_enc_type, &combined)
}
