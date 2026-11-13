//! Bounds of the format, and the range type of the per-daemon limits.
//!
//! The file and line bounds are the numbers docs/50 §7.1 states. The other
//! format bounds are project choices (AGENTS.md §6 requires bounds but does not
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
/// Project choice (AGENTS.md §6 bounds; Q-230): the largest key table has
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

/// A client's deadline for an answer on the keyd channel: 2 s.
/// Spec: docs/50 §3.6 ("deadline in the client — keyd: 2 s").
pub const KEYD_DEADLINE_SECS: Bound = Bound::up_to(2);
