//! The mechanism object identifiers and their octet encoding.
//!
//! The arcs come from [MS-KILE] 1.9.1 (the Kerberos V5 OID) and 3.1.1.7 (the
//! truncated OID KILE also implements). The octets are not written out by
//! hand: they are computed at compile time from the arcs by the rules of RFC
//! 2743 §3.1 element 5 (5a: the first octet is the top-level component times
//! 40 plus the second-level component; 5b: each later component in base 128,
//! most significant bits first, bit 8 set on all but the final octet, minimum
//! number of octets). The tests re-derive the expected octets by hand from the
//! same rules.
//!
//! Spec: RFC 2743 §3.1 element 5; [MS-KILE] v20261110 1.9.1, 3.1.1.7.

/// The Kerberos V5 mechanism OID, 1.2.840.113554.1.2.2 ("iso.member-body.
/// United States.mit.infosys.gssapi.krb5"). The only mechanism this profile
/// accepts or emits.
/// Spec: [MS-KILE] 1.9.1; RFC 4121 §4.1 (MechType "representing Kerberos V5
/// mechanism"); RFC 4752 §3.
pub const KERBEROS_V5_MECHANISM_ARCS: [u32; 7] = [1, 2, 840, 113554, 1, 2, 2];

/// The truncated Kerberos OID, 1.2.840.48018.1.2.2, that KILE also
/// implements. Recognised only so that its refusal is reported distinctly
/// ([`crate::Error::TruncatedKerberosOid`]); never accepted, never emitted.
/// Spec: [MS-KILE] 3.1.1.7; docs/60 §3.4 step 2; Q-1093 item 11.
pub const TRUNCATED_KERBEROS_OID_ARCS: [u32; 7] = [1, 2, 840, 48018, 1, 2, 2];

/// Room for the encoded OIDs above (9 octets each); checked at compile time.
const MAX_OID_OCTETS: usize = 16;

/// Encoded OID contents octets (element 5 of RFC 2743 §3.1).
pub(crate) struct OidOctets {
    octets: [u8; MAX_OID_OCTETS],
    len: usize,
}

impl OidOctets {
    /// The encoded octets.
    pub(crate) const fn as_slice(&self) -> &[u8] {
        self.octets.split_at(self.len).0
    }
}

/// Encode `arcs` by RFC 2743 §3.1 element 5. Evaluated only in `const`
/// items: an arc list it cannot encode stops the build (the asserts are the
/// "const contexts" exception of the no-panic rule, AGENTS.md §6 house style).
///
/// Spec: RFC 2743 §3.1 elements 5a, 5b.
const fn encode_arcs(arcs: &[u32]) -> OidOctets {
    assert!(arcs.len() >= 2, "an OID has at least two components");
    // 5a: "The first octet contains the sum of two values: (1) the top-level
    // object identifier component, multiplied by 40 (decimal), and (2) the
    // second-level object identifier component." A single octet: the sum
    // stays below 128 (bit 8 clear).
    assert!(arcs[0] <= 2 && arcs[1] < 40, "top-level arcs out of range");
    let first = arcs[0] * 40 + arcs[1];
    assert!(
        first < 0x80,
        "5a: the first octet holds both top-level arcs"
    );
    let mut out = [0u8; MAX_OID_OCTETS];
    out[0] = first as u8;
    let mut len = 1;
    let mut i = 2;
    while i < arcs.len() {
        len = push_component(&mut out, len, arcs[i]);
        i += 1;
    }
    OidOctets { octets: out, len }
}

/// Append one component by RFC 2743 §3.1 element 5b: 7 bits per octet, most
/// significant first, bit 8 set on all but the final octet, no leading-zero
/// octets (a zero component is the single octet 0x00).
///
/// Spec: RFC 2743 §3.1 element 5b.
const fn push_component(out: &mut [u8; MAX_OID_OCTETS], mut len: usize, value: u32) -> usize {
    // The number of 7-bit groups in the minimum encoding.
    let mut groups = 1;
    let mut rest = value >> 7;
    while rest != 0 {
        groups += 1;
        rest >>= 7;
    }
    assert!(len + groups <= MAX_OID_OCTETS, "OID longer than the buffer");
    let mut g = 0;
    while g < groups {
        let shift = 7 * (groups - 1 - g);
        let mut octet = ((value >> shift) & 0x7F) as u8;
        if g + 1 < groups {
            octet |= 0x80;
        }
        out[len] = octet;
        len += 1;
        g += 1;
    }
    len
}

/// Element 5 for the Kerberos V5 mechanism ([`KERBEROS_V5_MECHANISM_ARCS`]).
pub(crate) const KERBEROS_V5_MECHANISM_OID: OidOctets = encode_arcs(&KERBEROS_V5_MECHANISM_ARCS);

/// Element 5 for the truncated OID ([`TRUNCATED_KERBEROS_OID_ARCS`]).
pub(crate) const TRUNCATED_KERBEROS_OID: OidOctets = encode_arcs(&TRUNCATED_KERBEROS_OID_ARCS);

/// The contents octets of the Kerberos V5 mechanism OID (element 5 of RFC 2743
/// §3.1), as every token this crate encodes carries them and as every token it
/// decodes must carry them exactly.
/// Spec: RFC 2743 §3.1 element 5; [MS-KILE] 1.9.1.
pub const KERBEROS_V5_MECHANISM_OID_OCTETS: &[u8] = KERBEROS_V5_MECHANISM_OID.as_slice();

/// The contents octets of the truncated Kerberos OID ([MS-KILE] 3.1.1.7) —
/// refused wherever they appear. Spec: RFC 2743 §3.1 element 5.
pub const TRUNCATED_KERBEROS_OID_OCTETS: &[u8] = TRUNCATED_KERBEROS_OID.as_slice();

#[cfg(test)]
mod tests {
    use super::*;

    /// Element 5 holds one octet per 7 bits of each component: the two OIDs
    /// differ only in their fourth arc, so their encodings have the same
    /// length and differ only there. Spec: RFC 2743 §3.1 element 5b.
    #[test]
    fn both_oids_encode_to_nine_octets_and_differ_only_in_the_fourth_arc() {
        assert_eq!(KERBEROS_V5_MECHANISM_OID_OCTETS.len(), 9);
        assert_eq!(TRUNCATED_KERBEROS_OID_OCTETS.len(), 9);
        let differing: Vec<usize> = (0..9)
            .filter(|&i| KERBEROS_V5_MECHANISM_OID_OCTETS[i] != TRUNCATED_KERBEROS_OID_OCTETS[i])
            .collect();
        // Octet 0 is 1.2, octets 1–2 are 840, octets 3–5 are the fourth arc
        // (113554 and 48018 both need three 7-bit groups).
        assert_eq!(differing, vec![3]);
    }

    /// A zero component is the single octet 0x00 (5b: "no octets
    /// representing leading zeros"). Spec: RFC 2743 §3.1 element 5b.
    #[test]
    fn a_zero_component_is_one_zero_octet() {
        const ZERO: OidOctets = encode_arcs(&[1, 2, 0]);
        assert_eq!(ZERO.as_slice(), &[0x2A, 0x00]);
    }
}
