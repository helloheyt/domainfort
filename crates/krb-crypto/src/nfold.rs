//! n-fold: stretch (or fold) an octet string to n bits so every input bit
//! contributes to every output bit.
//!
//! Spec: RFC 3961 §5.1 — "To n-fold a number X, replicate the input value to
//! a length that is the least common multiple of n and the length of X.
//! Before each repetition, the input is rotated to the right by 13 bit
//! positions. The successive n-bit chunks are added together using
//! 1's-complement addition (that is, with end-around carry) to yield a n-bit
//! result." Octet strings are treated as big-endian numbers (most significant
//! byte first). RFC 3961 Appendix A.1 notes that the first repetition is the
//! input itself ("the initial octets exactly match the input string when the
//! output length is a multiple of the input length"), i.e. repetition i is X
//! rotated right by 13·i bits.
//!
//! In this crate n-fold is only applied to the short well-known constants of
//! RFC 3961 §5.1/§5.3 (5 or 8 octets) to produce one 16-octet AES block. The
//! public function accepts a wider (still bounded) range so the RFC 3961
//! Appendix A.1 vectors can be checked.

use crate::error::{Error, Result};

/// Upper bound, in octets, on both the input and the output of [`n_fold`].
///
/// Resource bound only (docs/CLEAN-ROOM.md: no unbounded work from an input
/// length); it is not a value from the specification. It comfortably covers
/// every RFC 3961 Appendix A.1 vector and every in-crate use.
pub const N_FOLD_MAX_OCTETS: usize = 64;

/// n-fold `input` to `output_octets` octets (n = 8 · `output_octets` bits).
///
/// Both lengths must be in `1..=N_FOLD_MAX_OCTETS`, otherwise
/// [`Error::InvalidInputLength`].
///
/// Spec: RFC 3961 §5.1; vectors in RFC 3961 Appendix A.1.
pub fn n_fold(input: &[u8], output_octets: usize) -> Result<Vec<u8>> {
    if input.is_empty()
        || input.len() > N_FOLD_MAX_OCTETS
        || output_octets == 0
        || output_octets > N_FOLD_MAX_OCTETS
    {
        return Err(Error::InvalidInputLength);
    }

    // Lengths in bits. Both are multiples of 8 and at most 512, so the least
    // common multiple is at most 512 * 512 bits — small and bounded.
    let m_bits = input.len() * 8;
    let n_bits = output_octets * 8;
    let total_bits = lcm(m_bits, n_bits);

    // The replicated string: total_bits / 8 octets. Repetition i (covering
    // bits i·m .. (i+1)·m) is X rotated right by 13·i bits. Spec: RFC 3961
    // §5.1.
    let total_octets = total_bits / 8;
    let mut replicated = vec![0u8; total_octets];
    for q in 0..total_bits {
        let repetition = q / m_bits;
        let p = q % m_bits;
        let rotation = (13 * repetition) % m_bits;
        // Rotating right by r moves the bit at position s to s + r (mod m);
        // so the bit now at p came from (p - r) mod m. Positions count from
        // the most significant bit of the first octet (big-endian).
        let source = (p + m_bits - rotation) % m_bits;
        if bit_at(input, source) {
            replicated[q / 8] |= 0x80 >> (q % 8);
        }
    }

    // Add the successive n-bit chunks with 1's-complement (end-around carry)
    // addition. Spec: RFC 3961 §5.1.
    let mut acc = vec![0u8; output_octets];
    for chunk in replicated.chunks_exact(output_octets) {
        ones_complement_add(&mut acc, chunk);
    }
    Ok(acc)
}

/// The bit at position `pos` of `bytes`, where position 0 is the most
/// significant bit of `bytes[0]` (big-endian bit order, RFC 3961 §5.1).
fn bit_at(bytes: &[u8], pos: usize) -> bool {
    (bytes[pos / 8] >> (7 - (pos % 8))) & 1 == 1
}

/// `acc = acc + addend` in 1's-complement arithmetic of width
/// `acc.len()` octets: a carry out of the most significant bit is added back
/// in at the least significant bit (end-around carry). Both slices are
/// big-endian and of equal length. Spec: RFC 3961 §5.1.
fn ones_complement_add(acc: &mut [u8], addend: &[u8]) {
    let mut carry: u16 = 0;
    for (a, b) in acc.iter_mut().zip(addend.iter()).rev() {
        let sum = u16::from(*a) + u16::from(*b) + carry;
        *a = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
    // End-around carry: feed the carry back into the low end until it is
    // absorbed.
    while carry != 0 {
        for a in acc.iter_mut().rev() {
            let sum = u16::from(*a) + carry;
            *a = (sum & 0xFF) as u8;
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }
    }
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

fn lcm(a: usize, b: usize) -> usize {
    a / gcd(a, b) * b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ones_complement_end_around_carry() {
        // Hand-derived from the RFC 3961 §5.1 definition: in 8-bit 1's
        // complement, 0xFF + 0x01 = 0x100 -> 0x00 with carry 1 -> 0x01.
        let mut acc = [0xFFu8];
        ones_complement_add(&mut acc, &[0x01]);
        assert_eq!(acc, [0x01]);
    }

    #[test]
    fn bounds_rejected() {
        assert_eq!(n_fold(&[], 16), Err(Error::InvalidInputLength));
        assert_eq!(n_fold(&[1], 0), Err(Error::InvalidInputLength));
        assert_eq!(
            n_fold(&[0u8; N_FOLD_MAX_OCTETS + 1], 16),
            Err(Error::InvalidInputLength)
        );
        assert_eq!(
            n_fold(&[1], N_FOLD_MAX_OCTETS + 1),
            Err(Error::InvalidInputLength)
        );
    }
}
