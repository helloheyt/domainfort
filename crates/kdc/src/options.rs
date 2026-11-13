//! KDC options (RFC 4120 5.4.1) in the phase-1 KDC.
//!
//! Three kinds (main-session decision 9):
//! - **Operation options** — FORWARDED (2), PROXY (4), ALLOW-POSTDATE (5),
//!   POSTDATED (6), ENC-TKT-IN-SKEY (28), RENEW (30), VALIDATE (31) ask for an
//!   operation phase 1 does not implement: the request is refused with
//!   KDC_ERR_BADOPTION ("KDC cannot accommodate requested option", 7.5.9).
//!   ALLOW-POSTDATE asks for the MAY-POSTDATE flag, which RFC 4120 3.1.3 lets
//!   policy withhold; refusing it instead is the main-session decision (a
//!   KDC may refuse an option it recognises — the "KDCs MUST ignore KDC
//!   options that are not recognized" rule of §2 concerns unrecognised ones).
//! - **Flag options** — FORWARDABLE (1), PROXIABLE (3), RENEWABLE (8),
//!   RENEWABLE-OK (27) ask for a ticket flag. RFC 4120 3.1.3: "The flags field
//!   of the new ticket will have the following options set if they have been
//!   requested and if the policy of the local realm allows: FORWARDABLE,
//!   MAY-POSTDATE, POSTDATED, PROXIABLE, RENEWABLE"; §2: "it is not, in
//!   general, possible to determine whether an option was not honored because
//!   it was not understood or because it was rejected through either
//!   configuration or policy", and "clients MUST confirm that the ticket
//!   returned by the KDC meets their needs". So a flag option is honoured
//!   when keyd's TicketPolicy allows the flag (and, at TGS, the TGT carries
//!   it — 5.4.1), and otherwise the flag is simply left off.
//! - **Everything else** — canonicalize (15, "reserved for canonicalize" in
//!   5.4.1), opt-hardware-auth (11), disable-transited-check (26) and every
//!   unassigned bit — is ignored (§2: "KDCs MUST ignore KDC options that are
//!   not recognized"). Phase 1 never canonicalises (main-session decision 4):
//!   the reply names are the request names. disable-transited-check has no
//!   effect in a single realm (the transited field is empty, 3.3.3.2). The
//!   MS-SFU option for S4U2proxy is not recognised by number (MS-SFU is not
//!   pinned or opened in this session); S4U2proxy is refused anyway, because
//!   it needs an additional ticket and additional-tickets are refused.
//!
//! Spec: RFC 4120 §2, 2.3-2.9, 3.1.3, 3.3.3, 5.4.1; main-session decision 9.

use krb_proto::{KdcOptions, TicketFlags};

/// The options that ask for an operation phase 1 does not implement.
/// Spec: RFC 4120 5.4.1; main-session decision 9.
const OPERATION_OPTIONS: KdcOptions = KdcOptions::FORWARDED
    .union(KdcOptions::PROXY)
    .union(KdcOptions::ALLOW_POSTDATE)
    .union(KdcOptions::POSTDATED)
    .union(KdcOptions::ENC_TKT_IN_SKEY)
    .union(KdcOptions::RENEW)
    .union(KdcOptions::VALIDATE);

/// `true` if `options` asks for any operation phase 1 does not implement.
/// Spec: RFC 4120 5.4.1, 7.5.9 (KDC_ERR_BADOPTION); main-session decision 9.
pub(crate) fn asks_unsupported_operation(options: KdcOptions) -> bool {
    options.0.bits() & OPERATION_OPTIONS.0.bits() != 0
}

/// The flag requests of a KDC-REQ, after the operation options were refused.
/// Spec: RFC 4120 5.4.1, 2.3, 2.5, 2.6, 2.9.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlagRequests {
    pub(crate) forwardable: bool,
    pub(crate) proxiable: bool,
    pub(crate) renewable: bool,
    pub(crate) renewable_ok: bool,
}

impl FlagRequests {
    /// Spec: RFC 4120 5.4.1 (bits 1, 3, 8, 27).
    pub(crate) fn of(options: KdcOptions) -> Self {
        FlagRequests {
            forwardable: options.contains(KdcOptions::FORWARDABLE),
            proxiable: options.contains(KdcOptions::PROXIABLE),
            renewable: options.contains(KdcOptions::RENEWABLE),
            renewable_ok: options.contains(KdcOptions::RENEWABLE_OK),
        }
    }
}

/// The FORWARDABLE / PROXIABLE flags to request from keyd: each one only if
/// the client asked for it, keyd's policy allows it, and — for a ticket
/// derived from a TGT — the TGT carries it (RFC 4120 5.4.1: "It may only be
/// set on the initial request, or in a subsequent request if the TGT on which
/// it is based is also forwardable" / "proxiable"). `tgt_flags` is `None` in
/// the AS exchange. RENEWABLE is decided with the times
/// ([`crate::lifetime`]).
///
/// Spec: RFC 4120 2.5, 2.6, 3.1.3, 5.4.1; main-session decision 9.
pub(crate) fn delegation_flags(
    requests: FlagRequests,
    allowed: TicketFlags,
    tgt_flags: Option<TicketFlags>,
) -> TicketFlags {
    let mut flags = TicketFlags::empty();
    for (asked, flag) in [
        (requests.forwardable, TicketFlags::FORWARDABLE),
        (requests.proxiable, TicketFlags::PROXIABLE),
    ] {
        let carried = tgt_flags.is_none_or(|tgt| tgt.contains(flag));
        if asked && allowed.contains(flag) && carried {
            flags.insert(flag);
        }
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb_proto::KerberosFlags;

    fn opt(bit: u32) -> KdcOptions {
        KdcOptions(KerberosFlags::from_bits(0x8000_0000 >> bit))
    }

    /// RFC 4120 5.4.1 bit numbers of the refused operations (decision 9).
    #[test]
    fn operation_options_are_refused() {
        for bit in [2, 4, 5, 6, 28, 30, 31] {
            assert!(asks_unsupported_operation(opt(bit)), "bit {bit}");
        }
        // Flag options, canonicalize (15), opt-hardware-auth (11),
        // disable-transited-check (26), reserved bits: not refused (§2).
        for bit in [0, 1, 3, 7, 8, 9, 10, 11, 12, 14, 15, 16, 25, 26, 27, 29] {
            assert!(!asks_unsupported_operation(opt(bit)), "bit {bit}");
        }
        // Bit 1 is the leading bit after bit 0 (X.680 22.4 via krb-proto).
        assert_eq!(opt(1), KdcOptions::FORWARDABLE);
    }

    /// RFC 4120 3.1.3 / 5.4.1: requested ∧ allowed ∧ (TGT carries it).
    #[test]
    fn delegation_flags_follow_policy_and_tgt() {
        let asked = FlagRequests {
            forwardable: true,
            proxiable: true,
            renewable: false,
            renewable_ok: false,
        };
        let none = TicketFlags::empty();
        let both = TicketFlags::FORWARDABLE.union(TicketFlags::PROXIABLE);
        assert_eq!(delegation_flags(asked, none, None), none);
        assert_eq!(delegation_flags(asked, both, None), both);
        assert_eq!(
            delegation_flags(asked, both, Some(TicketFlags::FORWARDABLE)),
            TicketFlags::FORWARDABLE
        );
        let not_asked = FlagRequests {
            forwardable: false,
            proxiable: false,
            ..asked
        };
        assert_eq!(delegation_flags(not_asked, both, None), none);
    }
}
