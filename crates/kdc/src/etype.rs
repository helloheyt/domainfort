//! Encryption-type negotiation (main-session decision 6).
//!
//! The acceptable enctypes are the client's request etype list, in the
//! client's preference order, intersected with keyd's configured AES enctypes
//! and with the enctypes of the principal's keys (the client's keys at AS;
//! the service's acceptable enctypes at TGS). An empty intersection is
//! KDC_ERR_ETYPE_NOSUPP. Numbers outside keyd's list — RC4, DES, 3DES, any
//! unassigned value — simply never match: there is no code path that could
//! select them (D125; docs/02 §3).
//!
//! Spec: RFC 4120 3.1.3 ("If there is more than one supported strong
//! encryption type in the etype list, the KDC SHOULD use the first valid
//! strong etype for which an encryption key is available"; "If the server
//! cannot accommodate any encryption type requested by the client, an error
//! message with code KDC_ERR_ETYPE_NOSUPP is returned"; "The KDC will not
//! issue tickets with a weak session key encryption type"), 5.4.1 (etype "in
//! preference order"); main-session decision 6; docs/30 §1; D125.

/// The acceptable enctypes, in the client's preference order, each once.
/// Spec: RFC 4120 3.1.3, 5.4.1; main-session decision 6.
pub(crate) fn negotiate(requested: &[i32], configured: &[i32], principal: &[i32]) -> Vec<i32> {
    let mut chosen: Vec<i32> = Vec::new();
    for etype in requested {
        if configured.contains(etype) && principal.contains(etype) && !chosen.contains(etype) {
            chosen.push(*etype);
        }
    }
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    const AES128: i32 = 17;
    const AES256: i32 = 18;
    // Numbers outside keyd's AES list (krb-crypto implements only 17-20);
    // they are opaque integers here.
    const OTHER_A: i32 = 23;
    const OTHER_B: i32 = 3;

    /// Decision 6: client order, intersected, deduplicated; non-AES numbers
    /// never match.
    #[test]
    fn client_order_intersection() {
        let configured = [AES256, AES128];
        let keys = [AES256, AES128];
        assert_eq!(
            negotiate(&[OTHER_A, AES128, AES256, AES128], &configured, &keys),
            vec![AES128, AES256]
        );
        assert!(negotiate(&[OTHER_A, OTHER_B], &configured, &keys).is_empty());
        assert_eq!(
            negotiate(&[AES128, AES256], &configured, &[AES256]),
            vec![AES256]
        );
        assert!(negotiate(&[AES128], &[AES256], &keys).is_empty());
    }
}
