//! The administrators' channel's fixed identity: magic, version, the
//! per-direction body bounds, the field bounds of `SetPassword`, the closed
//! kind tables and the closed refusal-status table.
//!
//! # Where the numbers come from
//!
//! * **Request direction: 288 KiB.** A forwarded operation is exactly dird's
//!   admin request (`auth` of up to three AP-REQs of 64 KiB, then at most
//!   16 KiB of fields — ipc-dird-admin's bound). `SetPassword` carries the
//!   same `auth` (for dird's `BeginPasswordSet`), one more AP-REQ of the
//!   requester (for dird's `CompletePasswordSet`: keyd's replay cache makes
//!   every AP-REQ single-use, RFC 4120 §3.2.3 — docs/questions/Q-400), the
//!   target and the password: 4 AP-REQs + ~1 KiB. 288 KiB holds both, checked
//!   at compile time below.
//! * **Reply direction: 16 KiB**, as dird's admin channel: the largest reply
//!   is a `Lookup`'s `Found` (a DN of at most 64 components).
//! * **Password: 1024 octets** — keyd's `set_secret` bound
//!   (`ipc_keyd::channel::MAX_SECRET`), to which admind hands it; the
//!   character rules ([MS-SAMR] 3.1.1.7.2) are admind's own check.
//!
//! Spec: docs/51 §7.1 (codec of `crates/ipc`, exact version, closed kinds,
//! no trailing octet, `REFUSED_KIND = 0xFF`), §7.2 (`auth`), §7.6
//! (`SetPassword {target, password: secret bytes<1024>}`); docs/50 §3.3,
//! the channel-magic registry (`admin.sock` / `ipc-admin` / `0x414D` /
//! version 1, A-64); A-59.

use ipc::{Channel, FrameLimit};
use ipc_dird_admin::channel as dird;

/// The channel's magic: the ASCII octets "AM". Registered in docs/50's
/// channel-magic registry for `admin.sock` / `ipc-admin` (A-64; docs/51
/// §7.1, A-72).
/// Spec: docs/50 §3.3, the channel-magic registry; docs/51 §7.1.
pub const ADMIN_MAGIC: u16 = 0x414D;

/// The one version of the channel this build speaks; any other is refused
/// (`Refused::VersionMismatch`), never negotiated.
/// Spec: docs/50 §3.3 ("exact version … no negotiation and no fallback");
/// the channel-magic registry (version 1); D57.
pub const ADMIN_VERSION: u8 = 1;

/// Request body bound: 288 KiB (module documentation). Project choice.
/// Spec: docs/51 §7.5, §7.6; docs/50 §3.3.
pub const MAX_REQUEST_BODY: u32 = 288 * 1024;

/// Reply body bound: 16 KiB. Spec: docs/51 §7.5 (the admin channel's
/// reply bound, which this channel's replies share).
pub const MAX_REPLY_BODY: u32 = 16 * 1024;

/// The request direction's [`FrameLimit`]; a bound outside ipc's range stops
/// the build here (const evaluation), never at run time.
/// Spec: docs/50 §3.3; A-59 (`FrameLimit` range).
pub const REQUEST_LIMIT: FrameLimit = match FrameLimit::new(MAX_REQUEST_BODY) {
    Some(limit) => limit,
    None => panic!("MAX_REQUEST_BODY is outside the ipc FrameLimit range"),
};

/// The reply direction's [`FrameLimit`]. Spec: docs/50 §3.3; A-59.
pub const REPLY_LIMIT: FrameLimit = match FrameLimit::new(MAX_REPLY_BODY) {
    Some(limit) => limit,
    None => panic!("MAX_REPLY_BODY is outside the ipc FrameLimit range"),
};

/// The administrators' channel (`admin.sock`, docs/50 §2.4, §3.1).
/// Spec: docs/51 §7.6.
pub const ADMIN_CHANNEL: Channel =
    Channel::new(ADMIN_MAGIC, ADMIN_VERSION, REQUEST_LIMIT, REPLY_LIMIT);

/// Bound of the password (octets of UTF-8): keyd's `set_secret` bound.
/// Spec: docs/51 §7.6 (`password: secret bytes<1024>`); docs/50 §3.4
/// (`SetSecret … password: secret bytes<1024>`).
pub const MAX_PASSWORD: u32 = 1024;

/// Bound of the completion AP-REQ (octets): 64 KiB, as every AP-REQ of the
/// admin plane (dird hands it to keyd as it is).
/// Spec: docs/51 §7.2; docs/questions/Q-400.
pub const MAX_COMPLETION_AP_REQ: u32 = dird::MAX_AP_REQ;

/// Most key versions a `PasswordChanged` reply reports: one per
/// `set_secret`, two for a computer. Spec: docs/51 §5.2 row 5, §7.6.
pub const MAX_KVNOS: u32 = dird::MAX_KVNOS;

/// Body octets of the largest `SetPassword`: envelope, `auth`, the
/// completion AP-REQ, the target, the password.
const SET_PASSWORD: usize =
    4 + dird::MAX_AUTH + (4 + MAX_COMPLETION_AP_REQ as usize) + 16 + (4 + MAX_PASSWORD as usize);

/// Body octets of the largest forwarded operation: dird's own bound.
const FORWARDED: usize = 4 + dird::MAX_AUTH + dird::MAX_PAYLOAD;

/// Body octets of the largest `PasswordChanged` reply.
const PASSWORD_CHANGED: usize = 4 + (4 + 4 * MAX_KVNOS as usize) + 1;

// The bounds agree with the values they come from and fit the body bounds;
// checked at compile time, never at run time.
const _: () = assert!(MAX_PASSWORD == ipc_keyd::channel::MAX_SECRET);
const _: () = assert!(MAX_COMPLETION_AP_REQ == ipc_keyd::channel::MAX_REQUEST_FIELD);
const _: () = assert!(SET_PASSWORD <= MAX_REQUEST_BODY as usize);
const _: () = assert!(FORWARDED <= MAX_REQUEST_BODY as usize);
const _: () = assert!(dird::MAX_REQUEST_BODY <= MAX_REQUEST_BODY);
const _: () = assert!(dird::MAX_REPLY_BODY <= MAX_REPLY_BODY);
const _: () = assert!(PASSWORD_CHANGED <= MAX_REPLY_BODY as usize);

// ---- kinds -----------------------------------------------------------------

/// Request kinds (administrator → admind). The forwarded operations keep the
/// numbers of dird's admin channel (their layouts are that channel's);
/// `0x06` / `0x07` — dird's `BeginPasswordSet` / `CompletePasswordSet` —
/// are never assigned here (only admind calls them, inside `SetPassword`);
/// `0x0E`–`0x13` stay unused as on dird's channel (the key-operation
/// requests, the keyadm-only forwards and the join token — tasks A10, A12);
/// `SetPassword` is `0x15`. Values are a project choice.
/// Spec: docs/51 §7.3, §7.6; docs/50 §3.3 ("`kind` closed"), §7.5 (`Ping`).
pub mod request_kind {
    use ipc_dird_admin::channel::request_kind as dird;

    /// `CreateUser`. Spec: docs/51 §7.3; §5.2 row 1.
    pub const CREATE_USER: u8 = dird::CREATE_USER;
    /// `CreateComputer`. Spec: docs/51 §7.3; §5.2 row 2.
    pub const CREATE_COMPUTER: u8 = dird::CREATE_COMPUTER;
    /// `CreateGroup`. Spec: docs/51 §7.3; §5.2 row 3.
    pub const CREATE_GROUP: u8 = dird::CREATE_GROUP;
    /// `CreateOu`. Spec: docs/51 §7.3; §5.2 row 4.
    pub const CREATE_OU: u8 = dird::CREATE_OU;
    /// `CreateContainer`. Spec: docs/51 §7.3; §5.2 row 4.
    pub const CREATE_CONTAINER: u8 = dird::CREATE_CONTAINER;
    /// `SetEnabled`. Spec: docs/51 §7.3; §5.2 row 6.
    pub const SET_ENABLED: u8 = dird::SET_ENABLED;
    /// `SetAccountExpires`. Spec: docs/51 §7.3; §5.2 row 7.
    pub const SET_ACCOUNT_EXPIRES: u8 = dird::SET_ACCOUNT_EXPIRES;
    /// `AddMember`. Spec: docs/51 §7.3; §5.2 row 8.
    pub const ADD_MEMBER: u8 = dird::ADD_MEMBER;
    /// `RemoveMember`. Spec: docs/51 §7.3; §5.2 row 8.
    pub const REMOVE_MEMBER: u8 = dird::REMOVE_MEMBER;
    /// `Delete`. Spec: docs/51 §7.3; §5.2 row 9.
    pub const DELETE: u8 = dird::DELETE;
    /// `Lookup`. Spec: docs/51 §7.3; §5.2 row 10.
    pub const LOOKUP: u8 = dird::LOOKUP;
    /// `Ping`: admind's health check, no `auth`. Spec: docs/50 §7.5.
    pub const PING: u8 = dird::PING;
    /// `SetPassword {auth, completion, target, password}`.
    /// Spec: docs/51 §7.6; docs/questions/Q-400.
    pub const SET_PASSWORD: u8 = 0x15;

    /// The forwarded operations: their payload is dird's, read and written
    /// by crate ipc-dird-admin. Spec: docs/51 §7.6 ("the same operations").
    pub const FORWARDED: &[u8] = &[
        CREATE_USER,
        CREATE_COMPUTER,
        CREATE_GROUP,
        CREATE_OU,
        CREATE_CONTAINER,
        SET_ENABLED,
        SET_ACCOUNT_EXPIRES,
        ADD_MEMBER,
        REMOVE_MEMBER,
        DELETE,
        LOOKUP,
    ];

    /// The closed request table. Spec: docs/51 §7.6; docs/50 §3.3.
    pub const ALL: &[u8] = &[
        CREATE_USER,
        CREATE_COMPUTER,
        CREATE_GROUP,
        CREATE_OU,
        CREATE_CONTAINER,
        SET_ENABLED,
        SET_ACCOUNT_EXPIRES,
        ADD_MEMBER,
        REMOVE_MEMBER,
        DELETE,
        LOOKUP,
        PING,
        SET_PASSWORD,
    ];
}

/// Reply kinds (admind → administrator). The replies shared with dird's
/// admin channel keep its numbers and layouts; dird's `PasswordSet`
/// (`0x82`, the answer to `BeginPasswordSet`) never travels here;
/// `PasswordChanged` is `0x87`. [`ipc::REFUSED_KIND`] (`0xFF`) is reserved
/// for the shared transport refusal (A-59).
/// Spec: docs/51 §7.3 (the reply column), §7.6; docs/50 §3.3; A-59.
pub mod reply_kind {
    use ipc_dird_admin::channel::reply_kind as dird;

    /// `Created { guid, sid? }`. Spec: docs/51 §7.3 (create rows).
    pub const CREATED: u8 = dird::CREATED;
    /// `Done`: the `()` of docs/51 §7.3.
    pub const DONE: u8 = dird::DONE;
    /// `Found { guid, dn, class, sid? }`. Spec: docs/51 §7.3 (`Lookup`).
    pub const FOUND: u8 = dird::FOUND;
    /// `Refused { status }`: the operation was refused or failed, with this
    /// channel's status table ([`super::RefusalStatus`]).
    pub const REFUSED: u8 = dird::REFUSED;
    /// `Pong`: the reply to `Ping`. Spec: docs/50 §7.5.
    pub const PONG: u8 = dird::PONG;
    /// `PasswordChanged { kvnos, completion_recorded }`: every `set_secret`
    /// of a `SetPassword` succeeded. Spec: docs/51 §7.6.
    pub const PASSWORD_CHANGED: u8 = 0x87;

    /// The closed reply table (without the reserved `REFUSED_KIND`).
    /// Spec: docs/51 §7.6; docs/50 §3.3; A-59.
    pub const ALL: &[u8] = &[CREATED, DONE, FOUND, REFUSED, PONG, PASSWORD_CHANGED];
}

/// Whether `kinds` lists no value twice. Compile-time helper.
const fn all_distinct(kinds: &[u8]) -> bool {
    let mut i = 0;
    while i < kinds.len() {
        let mut j = i + 1;
        while j < kinds.len() {
            if kinds[i] == kinds[j] {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

/// Whether `kind` is in `kinds`. Compile-time helper.
const fn contains(kinds: &[u8], kind: u8) -> bool {
    let mut i = 0;
    while i < kinds.len() {
        if kinds[i] == kind {
            return true;
        }
        i += 1;
    }
    false
}

// No kind equals the reserved `REFUSED_KIND` (A-59); each table is a set;
// dird's password-set kinds are not on this channel; `SetPassword` and
// `PasswordChanged` are not dird's kinds.
const _: () = assert!(ipc::kinds_exclude_refused(request_kind::ALL));
const _: () = assert!(ipc::kinds_exclude_refused(reply_kind::ALL));
const _: () = assert!(all_distinct(request_kind::ALL));
const _: () = assert!(all_distinct(reply_kind::ALL));
const _: () = assert!(!contains(
    request_kind::ALL,
    dird::request_kind::BEGIN_PASSWORD_SET
));
const _: () = assert!(!contains(
    request_kind::ALL,
    dird::request_kind::COMPLETE_PASSWORD_SET
));
const _: () = assert!(!contains(
    dird::request_kind::ALL,
    request_kind::SET_PASSWORD
));
const _: () = assert!(!contains(reply_kind::ALL, dird::reply_kind::PASSWORD_SET));
const _: () = assert!(!contains(
    dird::reply_kind::ALL,
    reply_kind::PASSWORD_CHANGED
));

// ---- the refusal-status table ----------------------------------------------

/// What the administrator is told about a refused or failed operation (the
/// reason is in the audit trail only). The first six are dird's statuses by
/// name (ipc-dird-admin `RefusalStatus`), passed on for forwarded operations
/// and for `SetPassword`'s dird steps; the last two exist only here, so that
/// "not done" is never said of something that may have been done (A-88,
/// A-90).
/// Spec: A-26 (uniform `Denied`); A-55 (`NotFound` for absent and
/// invisible); A-56 (`Unavailable`); A-88, A-90 (a key-state call's outcome
/// unknown is reported as such, "check before retrying"); docs/51 §9 (the
/// password-set row: "between the two `set_secret` of a computer: new
/// PrincipalLongterm, old Service … repeat `SetPassword`").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalStatus {
    /// Not permitted.
    Denied,
    /// Dual control applies and the approvals do not reach the quorum.
    ApprovalRequired,
    /// The object does not exist or the requester cannot read it.
    NotFound,
    /// A request value breaks a rule (a password breaking admind's rules
    /// included).
    Invalid,
    /// The directory holds a conflicting value or state.
    Conflict,
    /// The operation was not carried out (keyd, dird or auditd unreachable,
    /// busy or refusing before acting); nothing was changed by it.
    Unavailable,
    /// The operation may have been carried out in part or in whole — a
    /// request was handed to keyd (or dird) and no usable answer came back.
    /// Check (keyd's and dird's audit records) before retrying.
    OutcomeUnknown,
    /// A `SetPassword` of a computer was carried out in part: its
    /// `PrincipalLongterm` key set holds the new password, its `Service`
    /// key set does not. Repeat the `SetPassword`.
    Incomplete,
}

impl RefusalStatus {
    /// The wire code. Spec: docs/50 §3.3 ("enum = `u8` from a closed table").
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            RefusalStatus::Denied => 0x01,
            RefusalStatus::ApprovalRequired => 0x02,
            RefusalStatus::NotFound => 0x03,
            RefusalStatus::Invalid => 0x04,
            RefusalStatus::Conflict => 0x05,
            RefusalStatus::Unavailable => 0x06,
            RefusalStatus::OutcomeUnknown => 0x07,
            RefusalStatus::Incomplete => 0x08,
        }
    }

    /// Code → status (closed table).
    #[must_use]
    pub const fn from_code(code: u8) -> Option<RefusalStatus> {
        match code {
            0x01 => Some(RefusalStatus::Denied),
            0x02 => Some(RefusalStatus::ApprovalRequired),
            0x03 => Some(RefusalStatus::NotFound),
            0x04 => Some(RefusalStatus::Invalid),
            0x05 => Some(RefusalStatus::Conflict),
            0x06 => Some(RefusalStatus::Unavailable),
            0x07 => Some(RefusalStatus::OutcomeUnknown),
            0x08 => Some(RefusalStatus::Incomplete),
            _ => None,
        }
    }

    /// dird's status, by name (the same code).
    /// Spec: crate ipc-dird-admin `RefusalStatus`.
    #[must_use]
    pub const fn from_dird(status: ipc_dird_admin::RefusalStatus) -> RefusalStatus {
        match status {
            ipc_dird_admin::RefusalStatus::Denied => RefusalStatus::Denied,
            ipc_dird_admin::RefusalStatus::ApprovalRequired => RefusalStatus::ApprovalRequired,
            ipc_dird_admin::RefusalStatus::NotFound => RefusalStatus::NotFound,
            ipc_dird_admin::RefusalStatus::Invalid => RefusalStatus::Invalid,
            ipc_dird_admin::RefusalStatus::Conflict => RefusalStatus::Conflict,
            ipc_dird_admin::RefusalStatus::Unavailable => RefusalStatus::Unavailable,
        }
    }
}

// dird's six statuses keep their codes here.
const _: () = assert!(
    RefusalStatus::from_dird(ipc_dird_admin::RefusalStatus::Denied).code()
        == ipc_dird_admin::RefusalStatus::Denied.code()
);
const _: () = assert!(
    RefusalStatus::from_dird(ipc_dird_admin::RefusalStatus::Unavailable).code()
        == ipc_dird_admin::RefusalStatus::Unavailable.code()
);
