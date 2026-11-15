//! Every bound of the manifest. Each is checked before the octets it covers
//! are copied anywhere, so nothing is allocated beyond the input actually
//! present (docs/CLEAN-ROOM.md).
//!
//! The line-format bounds are crates/config's (`config::limits`), the
//! bounds of the one line parser both use (A-86 follow-up, task F7); they
//! are re-exported here under the names this crate has always had.

/// Largest manifest: 64 KiB — the configuration-file bound, since the
/// manifest uses the configuration line format.
/// Spec: docs/50 §7.1 ("file ≤ 64 KiB"); `config::limits::MAX_FILE_OCTETS`.
pub const MAX_FILE_OCTETS: usize = config::limits::MAX_FILE_OCTETS;

/// Longest line, not counting its LF: 1024 octets.
/// Spec: docs/50 §7.1 ("line ≤ 1024"); `config::limits::MAX_LINE_OCTETS`.
pub const MAX_LINE_OCTETS: usize = config::limits::MAX_LINE_OCTETS;

/// Most lines: 1024. Project choice (docs/CLEAN-ROOM.md requires a bound;
/// crates/config's, docs/questions/Q-230).
pub const MAX_LINES: usize = config::limits::MAX_LINES;

/// Longest key: 48 octets. Project choice (crates/config's; the longest
/// manifest key, `manifest_version`, has 16).
pub const MAX_KEY_OCTETS: usize = config::limits::MAX_KEY_OCTETS;

/// The separator between a key and its value: one space, `=`, one space.
/// Spec: docs/50 R50-15 ("`key = value`"); `config::limits::SEPARATOR`.
pub const SEPARATOR: &str = config::limits::SEPARATOR;

/// Longest value: what a maximal key leaves on a maximal line (973 octets).
/// Project choice (crates/config's, docs/questions/Q-230).
pub const MAX_VALUE_OCTETS: usize = config::limits::MAX_VALUE_OCTETS;

/// Longest realm, naming-context DNS name and DC host name: 255 octets.
///
/// Project choice, the bound crates/config uses for a DNS host name: the
/// conventional DNS name bound, whose source (RFC 1034) is listed in SOURCES
/// but not pinned — the DNS label syntax is not checked against it
/// (docs/questions/Q-200 item 1; PENDING-OWNER A-55).
pub const MAX_DNS_NAME_OCTETS: usize = 255;

/// Most labels of the naming context: 16.
/// Spec: crates/directory-pip `MAX_NC_LABELS` (16), which dird applies to
/// the same value; crates/config `MAX_NAMING_CONTEXT_LABELS`.
pub const MAX_NC_LABELS: usize = 16;

/// Longest first-administrator sAMAccountName: 20 characters (ASCII, so 20
/// octets). Spec: [MS-SAMR] 3.1.1.6 item 12 ("sAMAccountName MUST contain
/// less than or equal to 20 characters if the object's objectClass is
/// user"); docs/51 §11.
pub const MAX_ACCOUNT_NAME_OCTETS: usize = 20;

/// Fewest first administrators: 2 — provisioning requires at least two
/// tier-0 administrators; there is no "single administrator" mode.
/// Spec: docs/51 §4.3 (R51-4: first administrators ≥ the dual-control
/// quorum); docs/questions/Q-295, PENDING-OWNER P-22 (item 3).
pub const MIN_FIRST_ADMINS: usize = 2;

/// Most first administrators: 8.
///
/// Project choice (docs/CLEAN-ROOM.md bounds): with entries of at most
/// 36 + 1 + 12 + 1 + 20 = 70 octets, eight entries and their separators
/// (8 · 70 + 7 · 2 = 574 octets) stay within [`MAX_VALUE_OCTETS`]; further
/// administrators are created through the admin plane (docs/51 §5.2).
pub const MAX_FIRST_ADMINS: usize = 8;

// The largest first-administrator list always fits one value, so the
// encoder never writes a line the parser refuses.
const _: () = assert!(
    MAX_FIRST_ADMINS * (36 + 1 + 12 + 1 + MAX_ACCOUNT_NAME_OCTETS) + (MAX_FIRST_ADMINS - 1) * 2
        <= MAX_VALUE_OCTETS
);
