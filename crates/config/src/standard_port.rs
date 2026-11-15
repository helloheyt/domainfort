//! The standard ports of the services whose endpoint the zone advertises —
//! one definition (task DN10c; decision A-176 on docs/questions/Q-1016 items
//! 3–4, option (a)).
//!
//! **Class (AGENTS.md §6.1) — the zone advertises an endpoint no process
//! serves.** Each SRV record of the zone names a port (RFC 2782); a client
//! that finds `_kerberos._udp.X` goes to port 88. A listener configured on
//! another port would be advertised on the standard one — a dead end. The
//! port is therefore **one fact, fixed in one place**: this table. The
//! listener rule of the three files whose listeners the zone advertises —
//! the kdc's `listen` (UDP and TCP), ldap-front's `ldap_listen` (StartTLS)
//! and kpasswd-front's `listen` (TCP) — refuses any other port
//! ([`crate::ErrorKind::NonStandardPort`]), and the SRV synthesis (crates/
//! dns-zone `SrvService::port`) reads its ports from here, so the advertised
//! port and the only port a listener may have are the same value by
//! construction. Addresses stay configurable.
//!
//! Not here: LDAPS (`ldaps_listen`) — no SRV record advertises it ([MS-ADTS]
//! §6.3.2.3 lists none for it; docs/questions/Q-1016 item 3 (c)), so its port
//! is not this class's; dnsd's `listen` — see docs/questions/Q-1025.
//!
//! Spec: RFC 4120 §7.2.1, §7.2.2 ("SHOULD listen for them on port 88"),
//! §7.2.3.2 ("the Port number used for "_udp" and "_tcp" SRV records SHOULD be
//! the value assigned to "kerberos" by the Internet Assigned Number
//! Authority: 88 (decimal)"); [MS-ADTS] v20261026 §6.3.2.3 (the SRV fields
//! table: "Set to 389 for LDAP service. … Set to 88 for Kerberos KDC service.
//! Set to 464 for Kerberos Password Change service."); RFC 4511 §5.2 (the
//! IANA-assigned LDAP port, 389); RFC 3244 §2 ("TCP port 464"); docs/54 §3.1;
//! docs/questions/Q-1016 (A-176), Q-1024.

/// A service whose endpoint the zone advertises in an SRV record, by its
/// standard port. The Service labels of the SRV records (crates/dns-zone
/// `SrvService::service_label`) name the same three services.
///
/// Spec: [MS-ADTS] v20261026 §6.3.2.3; RFC 4120 §7.2.3.2; docs/54 §3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StandardPort {
    /// The Kerberos KDC service (`_kerberos`), on UDP and TCP: port 88.
    /// Spec: RFC 4120 §7.2.1, §7.2.2, §7.2.3.2; [MS-ADTS] §6.3.2.3 ("Set to 88
    /// for Kerberos KDC service").
    Kerberos,
    /// The LDAP service (`_ldap`), StartTLS on TCP: port 389.
    /// Spec: [MS-ADTS] §6.3.2.3 ("Set to 389 for LDAP service"); RFC 4511
    /// §5.2; docs/54 §3.1 ("StartTLS only").
    Ldap,
    /// The Kerberos Password Change service (`_kpasswd`), on TCP: port 464.
    /// Spec: [MS-ADTS] §6.3.2.3 ("Set to 464 for Kerberos Password Change
    /// service"); RFC 3244 §2; docs/53 R53-3 (TCP only).
    Kpasswd,
}

impl StandardPort {
    /// Every service of the table.
    pub const ALL: [StandardPort; 3] = [
        StandardPort::Kerberos,
        StandardPort::Ldap,
        StandardPort::Kpasswd,
    ];

    /// The port number — the one copy of it (module documentation).
    /// Spec: RFC 4120 §7.2.3.2 (88); [MS-ADTS] v20261026 §6.3.2.3 (389, 88,
    /// 464).
    #[must_use]
    pub const fn number(self) -> u16 {
        match self {
            StandardPort::Kerberos => 88,
            StandardPort::Ldap => 389,
            StandardPort::Kpasswd => 464,
        }
    }
}
