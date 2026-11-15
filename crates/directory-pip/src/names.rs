//! The krbtgt account's markers (docs/47 §1.4, R47-2).
//!
//! A requested name reaches an object only through the one lookup path,
//! crate::resolve (task PN4; docs/59 §6.1): the per-role search keys this
//! module used to build (`client_search_key` / `service_search_key`, R47-1)
//! are gone — the request's key is `principal_names::key_of_request`, and
//! the phase-1 acceptance is applied there. What stays here is how the
//! krbtgt account is recognised: by its sAMAccountName "krbtgt" and by its
//! objectSid's RID, DOMAIN_USER_RID_KRBTGT.
//!
//! Spec: docs/47 §1.3 step 6, §1.4 (R47-2); docs/59 §6.3 (no more
//! `client_search_key` / `service_search_key`); RFC 4120 §6.2 (names
//! beginning "krbtgt" are reserved for the TGS), §7.3; [MS-SAMR] 2.2.1.14
//! (DOMAIN_USER_RID_KRBTGT), 3.1.1.6 item 14; [MS-DTYP] 2.4.2.4
//! (KRBTGT = S-1-5-21-<domain>-502).

use dtyp::Sid;

/// The krbtgt account's sAMAccountName. Spec: [MS-SAMR] 3.1.1.6 item 14
/// ("sAMAccountName MUST be the value "krbtgt""); RFC 4120 §6.2, §7.3.
pub(crate) const KRBTGT: &str = "krbtgt";

/// DOMAIN_USER_RID_KRBTGT, "User for Key Distribution Center Service".
/// Spec: [MS-SAMR] 2.2.1.14 (0x000001F6); [MS-DTYP] 2.4.2.4
/// (S-1-5-21-<domain>-502).
pub(crate) const DOMAIN_USER_RID_KRBTGT: u32 = 0x0000_01F6;

/// `true` if `sid` is the krbtgt account's: its RID (last sub-authority) is
/// DOMAIN_USER_RID_KRBTGT. Read strictly — any SID ending in 502, whatever
/// its domain prefix (Q-136 item 4) — so the krbtgt account is never handed
/// out as a client or a service (its class is `TicketGrantingService`,
/// which no lookup context admits — crate::principal, crate::resolve).
/// Spec: docs/47 §1.3 step 6, §1.4 (R47-2); [MS-SAMR] 2.2.1.14; [MS-DTYP]
/// 2.4.2.4 ("RID: Indicates a unique object ID within the domain").
pub(crate) fn is_krbtgt_sid(sid: &Sid) -> bool {
    sid.sub_authority().last() == Some(&DOMAIN_USER_RID_KRBTGT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [MS-SAMR] 2.2.1.14: DOMAIN_USER_RID_KRBTGT = 0x1F6 = 502; [MS-DTYP]
    /// 2.4.2.4 example layout S-1-5-21-1-2-3-<RID>.
    #[test]
    fn krbtgt_rid() {
        let nt = dtyp::SECURITY_NT_AUTHORITY;
        assert_eq!(DOMAIN_USER_RID_KRBTGT, 502);
        assert!(is_krbtgt_sid(&Sid::new(nt, &[21, 1, 2, 3, 502]).unwrap()));
        assert!(!is_krbtgt_sid(&Sid::new(nt, &[21, 1, 2, 3, 500]).unwrap()));
        assert!(!is_krbtgt_sid(&Sid::new(nt, &[]).unwrap()));
    }
}
