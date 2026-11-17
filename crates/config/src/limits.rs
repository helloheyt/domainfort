//! Bounds of the format, and the range type of the per-daemon limits.
//!
//! The file and line bounds are the numbers docs/50 §7.1 states. The other
//! format bounds are project choices (docs/CLEAN-ROOM.md requires bounds but does not
//! fix them), listed in docs/questions/Q-230. Every bound is checked before the
//! octets it covers are copied anywhere, so nothing is allocated beyond the
//! input actually present.

/// Largest configuration file: 64 KiB. Spec: docs/50 §7.1 ("file ≤ 64 KiB").
pub const MAX_FILE_OCTETS: usize = 64 * 1024;

/// Longest line, not counting its LF: 1024 octets.
/// Spec: docs/50 §7.1 ("line ≤ 1024").
pub const MAX_LINE_OCTETS: usize = 1024;

/// Most lines in one file: 1024.
///
/// Project choice (docs/CLEAN-ROOM.md bounds; Q-230): the largest key table has
/// fewer than thirty keys, so a file of this many lines is already almost all
/// comments.
pub const MAX_LINES: usize = 1024;

/// Longest key: 48 octets.
///
/// Project choice (Q-230): the longest key of any table is 31 octets
/// (`max_requests_per_tcp_connection`).
pub const MAX_KEY_OCTETS: usize = 48;

/// The separator between a key and its value: exactly one space, `=`, one
/// space. Spec: docs/50 R50-15 ("`key = value`").
pub const SEPARATOR: &str = " = ";

/// Longest value: what a maximal key leaves on a maximal line (973 octets).
///
/// Project choice (Q-230): a value is never longer than the line bound minus
/// the key bound and the separator, so a short key cannot carry a longer value
/// than a long one could.
pub const MAX_VALUE_OCTETS: usize = MAX_LINE_OCTETS - MAX_KEY_OCTETS - SEPARATOR.len();

/// Most items in one list value: 32.
///
/// Project choice (Q-230): listener and network lists of a single DC
/// (OD-2) are short; the line bound caps them further.
pub const MAX_LIST_ITEMS: usize = 32;

/// The documented range of one numeric limit, and its default.
///
/// docs/50 gives each limit as one value ("for example", "project choice").
/// Decision recorded in docs/questions/Q-230 item 4: that value is both the
/// default (when the key is absent) and the ceiling — an operator may tighten
/// a limit, never loosen it — and the floor is 1 unless docs/50 states another
/// constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bound {
    /// Smallest accepted value.
    pub min: u32,
    /// Largest accepted value (the docs/50 value).
    pub max: u32,
    /// The value used when the key is absent.
    pub default: u32,
}

impl Bound {
    /// The range `1 ..= value`, defaulting to `value` (Q-230 item 4).
    pub(crate) const fn up_to(value: u32) -> Bound {
        Bound {
            min: 1,
            max: value,
            default: value,
        }
    }

    /// Whether `value` is inside the range.
    pub(crate) const fn admits(&self, value: u32) -> bool {
        self.min <= value && value <= self.max
    }
}

/// How long a server waits for a frame that has started to arrive on a local
/// socket: 5 s (ceiling and default).
/// Spec: docs/50 §3.6 ("a frame that has started must finish within 5 s").
pub const FRAME_TIMEOUT_SECS: Bound = Bound::up_to(5);

/// The admin plane's ticket-age threshold (`admin_ticket_age_max`): an
/// administrator's ticket whose age (`now − authtime`, the time of the
/// initial authentication) is above it is refused. Required whenever dird's
/// admin channel is configured — no default is ever used (the `default`
/// field below only fills the struct). Range 60 s ..= 3600 s:
/// * the ceiling — docs/51 §5.5 (R51-10, JIT in phase 1: "no admin session;
///   every operation carries its own AP-REQ … dird refuses `ticket_age`
///   above a threshold (project choice ⚠, e.g. minutes)"): one hour bounds
///   how long after an interactive login (authtime does not move when a
///   ticket is renewed, RFC 4120 §5.3) an administrator may still act
///   without authenticating again;
/// * the floor — below a minute an administrator cannot obtain a TGT and a
///   service ticket and send the operation.
///
/// Spec: docs/51 §5.5 (R51-10), §7.4 step 2; docs/questions/Q-385 item 4.
pub const ADMIN_TICKET_AGE_MAX_SECS: Bound = Bound {
    min: 60,
    max: 3600,
    default: 3600,
};

/// The dual-control quorum (`admin_quorum`): the requester plus approvers a
/// dual-controlled operation needs. 2 ..= 3 — no single-administrator mode
/// (P-22 item 3), at most the requester plus the two approvals a request
/// carries (docs/51 §7.2). Required whenever the admin channel is
/// configured (P-22 recommends 2).
/// Spec: docs/51 §5.6 (R51-11), §7.2; P-22 (Q-295); crates/directory-admin
/// `MIN_QUORUM`, `MAX_QUORUM`.
pub const ADMIN_QUORUM: Bound = Bound {
    min: 2,
    max: 3,
    default: 2,
};

/// dird's `dns_record_max_age`: a member host's address registered longer
/// ago is left out of the zone image — 7 days (default and ceiling), at
/// least 1 s. docs/54 §5.2 gives "e.g. 7 days ⚠", read as Q-230 item 4
/// reads every docs value: an operator may tighten it, never loosen it.
/// Spec: docs/54 §4.4, §5.2; docs/questions/Q-614 item 7, Q-230 item 4,
/// Q-1001 item 2.
pub const DNS_RECORD_MAX_AGE_SECS: Bound = Bound::up_to(7 * 24 * 60 * 60);

/// dird's zone time values — the SOA's REFRESH, RETRY, EXPIRE and MINIMUM
/// and the TTLs of the synthesized (`dns_infrastructure_ttl`) and host
/// (`dns_host_ttl`) records — in seconds: 0 ..= 2 147 483 647. A TTL is one
/// of the "positive values of a signed 32 bit number" (RFC 1035 §2.3.4); the
/// zone image refuses a larger TTL or MINIMUM (crates/dns-zone `MAX_TTL`,
/// pinned in crates/directory-daemon), and the SOA's three intervals take the
/// same range so that every time value of the zone has one bound. Required
/// whenever dird's DNS channel is configured — no default is ever used (the
/// `default` field only fills the struct): docs/54 §3.1 names them dird
/// configuration with no value (project choices ⚠).
/// Spec: RFC 1035 §2.3.4, §3.2.1, §3.3.13 ("All times are in units of
/// seconds"); docs/54 §3.1; docs/questions/Q-619 item 5, Q-1001 item 2.
pub const DNS_TIME_SECS: Bound = Bound {
    min: 0,
    max: 2_147_483_647,
    default: 0,
};

/// A client's deadline for an answer on the keyd channel: 2 s.
/// Spec: docs/50 §3.6 ("deadline in the client — keyd: 2 s").
pub const KEYD_DEADLINE_SECS: Bound = Bound::up_to(2);

/// admind's minimum password length (`min_password_length`), in characters:
/// required in admind's file — no default is ever used (the `default` field
/// below only fills the struct). Range 8 ..= 256:
/// * the floor — the owner's minimum, docs/56 §7 P-24 ("8+ characters"; it
///   replaces A-79's temporary floor of 12); an operator may only raise it
///   (PENDING-OWNER P-24). The phase-1 schema has no minPwdLength, so
///   [MS-SAMR] 3.1.1.7.2 item 3.2.1's Effective-MinimumPasswordLength is
///   this setting. Pinned to crate admin-password-policy's
///   `MIN_PASSWORD_CHARS_FLOOR` (provision `configs.rs`; this crate has no
///   dependency);
/// * the ceiling — [MS-SAMR] 3.1.1.7.2 item 2: a password is at most 256
///   characters, so a larger minimum would refuse every password.
///
/// Spec: [MS-SAMR] 3.1.1.7.2 items 2, 3.2.1; docs/51 §11 (the password row);
/// docs/56 §7 (P-24); A-79; docs/questions/Q-298 item 5, Q-401, Q-910 item
/// 2.
pub const MIN_PASSWORD_LENGTH: Bound = Bound {
    min: 8,
    max: 256,
    default: 8,
};
