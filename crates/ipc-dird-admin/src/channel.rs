//! The admin channel's fixed identity: magic, version, the per-direction
//! body bounds, the per-field bounds, the closed kind tables and the closed
//! code tables.
//!
//! # Where the numbers come from
//!
//! * **Request direction: 256 KiB.** Every operation carries the
//!   authentication field `auth := requester ‖ approvals` — up to three raw
//!   AP-REQs of at most 64 KiB each (`ipc_keyd::MAX_REQUEST_FIELD`, because
//!   dird hands them to keyd exactly as they arrived) — and a payload of at
//!   most 16 KiB (names ≤ 3 KiB per docs/46 §5.4, as docs/51 §7.5 states).
//!   docs/51 §7.5: "request ≤ 256 KiB (three AP-REQs of 64 KiB + payload
//!   ≤ 16 KiB …); const assert against `ipc_keyd::MAX_REQUEST_FIELD`".
//! * **Reply direction: 16 KiB.** The largest reply is a `BeginPasswordSet`
//!   answer (two key targets with their bindings and the salt) or a `Lookup`
//!   answer (a DN of at most 64 components) — both under 10 KiB, checked at
//!   compile time below. docs/51 §7.5: "reply ≤ 16 KiB".
//! * **Field bounds** are octet bounds that only bound allocation; the write
//!   PEP (crates/directory-admin) applies the semantic rules (characters,
//!   forms, lengths in characters) and records a refusal in the audit trail.
//!   Each bound is at least the PEP's own maximum for that field, so a value
//!   the PEP could accept always fits (crates/directory-daemon pins this at
//!   compile time — it links both crates; this crate links no PEP).
//!
//! Spec: docs/51 §7.1 (the codec of `crates/ipc`, magic `0x4441`, exact
//! version, closed kinds, no trailing octet, `REFUSED_KIND = 0xFF`), §7.2
//! (`auth`), §7.3 (the operations), §7.5 (the bounds); docs/50 §3.3, the
//! channel-magic registry (A-64); A-59.

use ipc::{Channel, FrameLimit};

/// The channel's magic: the ASCII octets "DA". Registered in docs/50's
/// channel-magic registry for `dird-admin.sock` / `ipc-dird-admin` before
/// this crate was built (A-64; docs/51 §7.1, A-72).
/// Spec: docs/50 §3.3, the channel-magic registry; docs/51 §7.1.
pub const ADMIN_MAGIC: u16 = 0x4441;

/// The one version of the channel this build speaks; any other is refused
/// (`Refused::VersionMismatch`), never negotiated.
/// Spec: docs/50 §3.3 ("exact version … no negotiation and no fallback");
/// docs/51 §7.1; the channel-magic registry (version 1); D57.
pub const ADMIN_VERSION: u8 = 1;

/// Request body bound: 256 KiB. Spec: docs/51 §7.5.
pub const MAX_REQUEST_BODY: u32 = 256 * 1024;

/// Reply body bound: 16 KiB. Spec: docs/51 §7.5.
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

/// The admin channel (`dird-admin.sock`, docs/50 §3.1; docs/51 §7.1).
/// Spec: docs/51 §7.1.
pub const ADMIN_CHANNEL: Channel =
    Channel::new(ADMIN_MAGIC, ADMIN_VERSION, REQUEST_LIMIT, REPLY_LIMIT);

// ---- field bounds ----------------------------------------------------------

/// Bound of one raw AP-REQ (the requester's or an approver's): 64 KiB, the
/// keyd channel's per-field request bound, because dird forwards it to keyd
/// `open_and_verify_service_ticket` exactly as received.
/// Spec: docs/51 §7.2 (`requester: bytes<64 KiB>`; "64 KiB =
/// `ipc_keyd::MAX_REQUEST_FIELD`, because dird passes them to keyd as they
/// are").
pub const MAX_AP_REQ: u32 = 64 * 1024;

/// Most approvals one request carries. Spec: docs/51 §7.2 (`approvals:
/// seq<bytes<64 KiB>, 2>`).
pub const MAX_APPROVALS: u32 = 2;

/// Bound of the payload after `auth`: 16 KiB. Spec: docs/51 §7.5 ("payload
/// ≤ 16 KiB: names ≤ 3 KiB according to docs/46 §5.4").
pub const MAX_PAYLOAD: usize = 16 * 1024;

/// Bound of a sAMAccountName, a computer name or an OU / container RDN value
/// (octets): 256 — the largest name the PEP accepts is a group's
/// sAMAccountName of 256 characters ([MS-SAMR] 3.1.1.6 item 13; names are
/// printable ASCII, P-6).
/// Spec: docs/46 §5.4; docs/51 §11; crates/directory-admin
/// `MAX_GROUP_SAM_CHARS`.
pub const MAX_NAME: u32 = 256;

/// Bound of a userPrincipalName or servicePrincipalName (octets): 1024.
/// Spec: docs/46 §5.4 (UPN / SPN 1..1024); crates/directory-admin
/// `MAX_PRINCIPAL_NAME_CHARS`.
pub const MAX_PRINCIPAL_NAME: u32 = 1024;

/// Bound of a dNSHostName (octets): 2048.
/// Spec: docs/46 §5.4 (dNSHostName 0..2048); crates/directory-admin
/// `MAX_DNS_HOST_NAME_CHARS`.
pub const MAX_DNS_HOST_NAME: u32 = 2048;

/// Bound of a description (octets of UTF-8): 3072 — 1024 UTF-16 units
/// (docs/46 §5.4) take at most three UTF-8 octets each (a unit of the Basic
/// Multilingual Plane), or four octets per surrogate pair of two units.
/// Spec: docs/46 §5.4; crates/directory-admin `MAX_DESCRIPTION_UNITS`.
pub const MAX_DESCRIPTION: u32 = 3 * 1024;

/// Bound of one DN component `att=value` (octets): 128 — an RDN value is at
/// most 64 characters (cn / ou, docs/46 §5.4; a dc label is shorter) behind
/// a two-letter attribute and `=`.
/// Spec: docs/46 §5.4; docs/49 §7 (R49-11); docs/questions/Q-358 item 5.
pub const MAX_DN_COMPONENT: u32 = 128;

/// Most components of a DN: directory-pip's `MAX_DN_DEPTH` (64; pinned in
/// crates/directory-daemon, which links both).
/// Spec: docs/47 §8.2; crates/directory-pip `MAX_DN_DEPTH`.
pub const MAX_DN_COMPONENTS: u32 = 64;

/// Most key versions a `CompletePasswordSet` reports: one per `set_secret`
/// (two for a computer). Spec: docs/51 §5.2 row 5, §7.3; crate ipc-audit
/// `MAX_REPORTED_KVNOS`.
pub const MAX_KVNOS: u32 = 2;

/// Bound of a SID packet: 1 + 1 + 6 + 15 × 4 = 68 octets.
/// Spec: [MS-DTYP] 2.4.2.2 (at most 15 sub-authorities).
pub const MAX_SID: u32 = 68;

/// Bound of a realm (octets): 255, a DNS name in upper case.
/// Spec: docs/47 §3.3 item 3 (the realm is the domain's DNS name in upper
/// case); crates/provision-manifest `MAX_DNS_NAME_OCTETS`.
pub const MAX_REALM: u32 = 255;

/// Bound of a binding's `PrincipalName` DER: 4 KiB — at most two components
/// (`NT-PRINCIPAL [sam]` or `NT-SRV-HST [service, host]`), the host a
/// dNSHostName of at most 2048 octets.
/// Spec: docs/47 §9.1 (the bindings); RFC 4120 §5.2.2, §6.2.1.
pub const MAX_BINDING_NAME: u32 = 4 * 1024;

/// Most key targets of a `BeginPasswordSet` reply: one for a user, two for
/// a computer with its SPN. Spec: docs/51 §7.3 ("handles (1 or 2)").
pub const MAX_KEY_TARGETS: u32 = 2;

/// Bound of the salt (octets): the keyd channel's `set_secret` salt bound,
/// since admind passes it to keyd as is.
/// Spec: docs/51 §7.3 (salt from `account_salt`); docs/50 §3.4.
pub const MAX_SALT: u32 = 1024;

/// Bound of a class's lDAPDisplayName (octets): 64.
/// Spec: docs/46 §4 (the ten phase-1 classes; the longest name is
/// `organizationalUnit`).
pub const MAX_CLASS_NAME: u32 = 64;

/// Octets of a key-operation request's digest: a SHA-256 output.
/// Spec: docs/51 §5.6 ("the operation digest"); FIPS 180-4 (SHA-256, as
/// computed by the approved RustCrypto `sha2` in dird); docs/questions/
/// Q-420.
pub const DIGEST_LEN: usize = 32;

/// Most entries one `PendingDestruction` page carries. Project choice: a
/// page stays far under the 16 KiB reply bound (checked below).
/// Spec: docs/51 §6, §7.5; docs/questions/Q-422.
pub const MAX_DESTRUCTION_ENTRIES: u32 = 256;

/// Body octets of the `auth` field at its largest.
pub const MAX_AUTH: usize =
    4 + MAX_AP_REQ as usize + 4 + MAX_APPROVALS as usize * (4 + MAX_AP_REQ as usize);

/// The envelope: magic, version, kind.
const ENVELOPE: usize = 4;

/// Payload octets of the largest request of each shape (module notes).
const CREATE_USER: usize = 16
    + (4 + MAX_NAME as usize)
    + (1 + 4 + MAX_PRINCIPAL_NAME as usize)
    + (1 + 4 + MAX_DESCRIPTION as usize);
const CREATE_COMPUTER: usize = 16
    + (4 + MAX_NAME as usize)
    + (4 + MAX_DNS_HOST_NAME as usize)
    + (1 + 4 + MAX_PRINCIPAL_NAME as usize);
const LOOKUP_DN: usize = 1 + 4 + MAX_DN_COMPONENTS as usize * (4 + MAX_DN_COMPONENT as usize);
const LOOKUP_SPN: usize = 1 + 4 + MAX_PRINCIPAL_NAME as usize;

/// Body octets of the largest reply of each shape.
const KEY_TARGET: usize = 16 + 1 + (4 + MAX_REALM as usize) + (4 + MAX_BINDING_NAME as usize);
const PASSWORD_SET: usize =
    ENVELOPE + 1 + 4 + MAX_KEY_TARGETS as usize * KEY_TARGET + (4 + MAX_SALT as usize);
const FOUND: usize = ENVELOPE
    + 16
    + (4 + MAX_DN_COMPONENTS as usize * (4 + MAX_DN_COMPONENT as usize))
    + (4 + MAX_CLASS_NAME as usize)
    + (1 + 4 + MAX_SID as usize);

/// The largest `KeyOperation`: tag, key-reference tag, objectGUID, kvno.
const KEY_OPERATION_SIZE: usize = 1 + 1 + 16 + 4;
/// Payload octets of the largest `Approve` after `auth`.
const APPROVE_SIZE: usize = 8 + KEY_OPERATION_SIZE;
/// Body octets of the largest key-request replies.
const KEY_REQUEST_SIZE: usize = ENVELOPE + 8 + DIGEST_LEN + KEY_OPERATION_SIZE + 1 + 1;
const APPROVED_SIZE: usize =
    ENVELOPE + 8 + DIGEST_LEN + KEY_OPERATION_SIZE + 16 + 16 + 4 + MAX_APPROVALS as usize * 16;
const PENDING_DESTRUCTION_SIZE: usize =
    ENVELOPE + 4 + MAX_DESTRUCTION_ENTRIES as usize * (16 + 1) + (1 + 16);

// The bounds agree with the values they are derived from and fit the body
// bounds; checked at compile time, never at run time.
const _: () = assert!(APPROVE_SIZE <= MAX_PAYLOAD);
const _: () = assert!(KEY_REQUEST_SIZE <= MAX_REPLY_BODY as usize);
const _: () = assert!(APPROVED_SIZE <= MAX_REPLY_BODY as usize);
const _: () = assert!(PENDING_DESTRUCTION_SIZE <= MAX_REPLY_BODY as usize);
const _: () = assert!(MAX_AP_REQ == ipc_keyd::channel::MAX_REQUEST_FIELD);
const _: () = assert!(MAX_SALT <= ipc_keyd::channel::MAX_SALT);
const _: () = assert!(MAX_REALM <= ipc_keyd::channel::MAX_REQUEST_FIELD);
const _: () = assert!(MAX_BINDING_NAME <= ipc_keyd::channel::MAX_REQUEST_FIELD);
const _: () = assert!(CREATE_USER <= MAX_PAYLOAD);
const _: () = assert!(CREATE_COMPUTER <= MAX_PAYLOAD);
const _: () = assert!(LOOKUP_DN <= MAX_PAYLOAD);
const _: () = assert!(LOOKUP_SPN <= MAX_PAYLOAD);
const _: () = assert!(ENVELOPE + MAX_AUTH + MAX_PAYLOAD <= MAX_REQUEST_BODY as usize);
const _: () = assert!(PASSWORD_SET <= MAX_REPLY_BODY as usize);
const _: () = assert!(FOUND <= MAX_REPLY_BODY as usize);

// ---- kinds -----------------------------------------------------------------

/// Request kinds (admind → dird): the closed operation set of docs/51 §7.3,
/// numbered in the table's order, and `Ping`. The key-operation rows of that
/// table (task A10) take `0x0E`–`0x12` in the same order —
/// `RequestKeyOperation`, `Approve`, `FetchApproved`, `Complete`,
/// `ListPendingDestruction`; `0x13` (the table's `IssueJoinToken`, task A12
/// — deferred, A-78) stays unused. Values are a project choice.
/// Spec: docs/51 §7.3; docs/50 §3.3 ("`kind` closed"), §7.5 (`Ping`);
/// docs/questions/Q-389 item 1 (A-91), Q-422.
pub mod request_kind {
    /// `CreateUser`. Spec: docs/51 §7.3; §5.2 row 1.
    pub const CREATE_USER: u8 = 0x01;
    /// `CreateComputer`. Spec: docs/51 §7.3; §5.2 row 2.
    pub const CREATE_COMPUTER: u8 = 0x02;
    /// `CreateGroup`. Spec: docs/51 §7.3; §5.2 row 3.
    pub const CREATE_GROUP: u8 = 0x03;
    /// `CreateOu`. Spec: docs/51 §7.3; §5.2 row 4.
    pub const CREATE_OU: u8 = 0x04;
    /// `CreateContainer`. Spec: docs/51 §7.3; §5.2 row 4.
    pub const CREATE_CONTAINER: u8 = 0x05;
    /// `BeginPasswordSet`. Spec: docs/51 §7.3; §5.2 row 5.
    pub const BEGIN_PASSWORD_SET: u8 = 0x06;
    /// `CompletePasswordSet`. Spec: docs/51 §7.3.
    pub const COMPLETE_PASSWORD_SET: u8 = 0x07;
    /// `SetEnabled`. Spec: docs/51 §7.3; §5.2 row 6.
    pub const SET_ENABLED: u8 = 0x08;
    /// `SetAccountExpires`. Spec: docs/51 §7.3; §5.2 row 7.
    pub const SET_ACCOUNT_EXPIRES: u8 = 0x09;
    /// `AddMember`. Spec: docs/51 §7.3; §5.2 row 8.
    pub const ADD_MEMBER: u8 = 0x0A;
    /// `RemoveMember`. Spec: docs/51 §7.3; §5.2 row 8.
    pub const REMOVE_MEMBER: u8 = 0x0B;
    /// `Delete`. Spec: docs/51 §7.3; §5.2 row 9.
    pub const DELETE: u8 = 0x0C;
    /// `Lookup`. Spec: docs/51 §7.3; §5.2 row 10.
    pub const LOOKUP: u8 = 0x0D;
    /// `RequestKeyOperation {operation}`: a requester opens a pending
    /// key-operation request. Spec: docs/51 §5.2 row 11, §5.6, §6, §7.3.
    pub const REQUEST_KEY_OPERATION: u8 = 0x0E;
    /// `Approve {id, operation}`: an approver approves the exact operation
    /// of a pending request. Spec: docs/51 §5.6, §6, §7.3.
    pub const APPROVE: u8 = 0x0F;
    /// `FetchApproved {id}` — keyadm's, forwarded by admind only from
    /// `keyadm_uid`; no `auth`. Spec: docs/51 §6, §7.3.
    pub const FETCH_APPROVED: u8 = 0x10;
    /// `Complete {id, outcome}` — keyadm's; no `auth`. Spec: docs/51 §6,
    /// §7.3.
    pub const COMPLETE: u8 = 0x11;
    /// `ListPendingDestruction {cursor}` — keyadm's; no `auth`.
    /// Spec: docs/51 §6, §7.3, §9.
    pub const LIST_PENDING_DESTRUCTION: u8 = 0x12;
    /// `Ping`: the health check, no `auth`. Spec: docs/51 §7.3; docs/50 §7.5.
    pub const PING: u8 = 0x14;

    /// The requests keyadm sends (through admind, which forwards them only
    /// when its peer's uid is `keyadm_uid`): they carry no `auth` — keyadm
    /// has no Kerberos client (docs/51 §6). Spec: docs/51 §6, §7.3;
    /// docs/questions/Q-422.
    pub const KEYADM: &[u8] = &[FETCH_APPROVED, COMPLETE, LIST_PENDING_DESTRUCTION];

    /// The closed request table. Spec: docs/51 §7.3; docs/50 §3.3.
    pub const ALL: &[u8] = &[
        CREATE_USER,
        CREATE_COMPUTER,
        CREATE_GROUP,
        CREATE_OU,
        CREATE_CONTAINER,
        BEGIN_PASSWORD_SET,
        COMPLETE_PASSWORD_SET,
        SET_ENABLED,
        SET_ACCOUNT_EXPIRES,
        ADD_MEMBER,
        REMOVE_MEMBER,
        DELETE,
        LOOKUP,
        REQUEST_KEY_OPERATION,
        APPROVE,
        FETCH_APPROVED,
        COMPLETE,
        LIST_PENDING_DESTRUCTION,
        PING,
    ];
}

/// Reply kinds (dird → admind). [`ipc::REFUSED_KIND`] (`0xFF`) is reserved
/// for the shared transport refusal (A-59). Values are a project choice.
/// Spec: docs/51 §7.3 (the reply column); docs/50 §3.3; A-59.
pub mod reply_kind {
    /// `Created { guid, sid? }`. Spec: docs/51 §7.3 (create rows).
    pub const CREATED: u8 = 0x81;
    /// `PasswordSet { kind, keys, salt }`. Spec: docs/51 §7.3
    /// (`BeginPasswordSet`).
    pub const PASSWORD_SET: u8 = 0x82;
    /// `Done`: the `()` of docs/51 §7.3.
    pub const DONE: u8 = 0x83;
    /// `Found { guid, dn, class, sid? }`. Spec: docs/51 §7.3 (`Lookup`).
    pub const FOUND: u8 = 0x84;
    /// `Refused { status }`: the operation was refused or failed; the reason
    /// is in the audit trail only (A-26; docs/11 §1b).
    pub const REFUSED: u8 = 0x85;
    /// `Pong`: the reply to `Ping`. Spec: docs/50 §7.5.
    pub const PONG: u8 = 0x86;
    /// `KeyRequest { id, digest, operation, approvals, quorum }`: the
    /// pending request as dird holds it, shown back to the requester and to
    /// every approver. (`0x87` is admin.sock's `PasswordChanged`, never
    /// dird's — the two channels share their common reply numbers.)
    /// Spec: docs/51 §5.6, §7.3 (`id / state`); docs/questions/Q-422.
    pub const KEY_REQUEST: u8 = 0x88;
    /// `Approved { id, digest, operation, principal, requester, approvers }`:
    /// the answer to `FetchApproved`. Spec: docs/51 §6, §7.3.
    pub const APPROVED: u8 = 0x89;
    /// `PendingDestruction { entries, next }`: one page of the tombstones of
    /// user / computer objects. Spec: docs/51 §6, §7.3, §9; A-18.
    pub const PENDING_DESTRUCTION: u8 = 0x8A;

    /// The closed reply table (without the reserved `REFUSED_KIND`).
    /// Spec: docs/51 §7.3; docs/50 §3.3; A-59.
    pub const ALL: &[u8] = &[
        CREATED,
        PASSWORD_SET,
        DONE,
        FOUND,
        REFUSED,
        PONG,
        KEY_REQUEST,
        APPROVED,
        PENDING_DESTRUCTION,
    ];
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

// No kind equals the reserved `REFUSED_KIND` (A-59), and each table is a set.
const _: () = assert!(ipc::kinds_exclude_refused(request_kind::ALL));
const _: () = assert!(ipc::kinds_exclude_refused(reply_kind::ALL));
const _: () = assert!(all_distinct(request_kind::ALL));
const _: () = assert!(all_distinct(reply_kind::ALL));

// ---- closed value tables ---------------------------------------------------

/// Wire codes of the closed value tables (project choices; one octet each,
/// docs/50 §3.3: "enum = `u8` from a closed table").
pub mod codes {
    /// `CompletePasswordSet.outcome`: every `set_secret` succeeded.
    /// Spec: docs/51 §7.3 (`outcome`).
    pub const OUTCOME_COMPLETED: u8 = 0x01;
    /// `CompletePasswordSet.outcome`: a `set_secret` failed.
    pub const OUTCOME_FAILED: u8 = 0x02;

    /// `SetAccountExpires.value`: "never". Spec: docs/51 §5.2 row 7
    /// (`never | filetime`).
    pub const EXPIRES_NEVER: u8 = 0x01;
    /// `SetAccountExpires.value`: a FILETIME follows.
    pub const EXPIRES_AT: u8 = 0x02;

    /// `Lookup.key`: a sAMAccountName follows. Spec: docs/51 §5.2 row 10
    /// (`sam | spn | dn`).
    pub const LOOKUP_SAM: u8 = 0x01;
    /// `Lookup.key`: a servicePrincipalName follows.
    pub const LOOKUP_SPN: u8 = 0x02;
    /// `Lookup.key`: a DN as RDN components follows (leaf first,
    /// docs/questions/Q-358 item 5).
    pub const LOOKUP_DN: u8 = 0x03;

    /// `PasswordSet.kind`: a user account. Spec: docs/51 §7.3 (`kind`
    /// (User/Computer)).
    pub const KIND_USER: u8 = 0x01;
    /// `PasswordSet.kind`: a computer account.
    pub const KIND_COMPUTER: u8 = 0x02;

    /// A key target's purpose: `PrincipalLongterm`. Only the two purposes a
    /// password set fills are expressible — never `Krbtgt` (docs/47 §9.1;
    /// R47-12: `set_secret` for user / computer only).
    pub const PURPOSE_PRINCIPAL_LONGTERM: u8 = 0x01;
    /// A key target's purpose: `Service` (a computer's SPN key set).
    pub const PURPOSE_SERVICE: u8 = 0x02;

    /// `KeyOperation`: `rotate_krbtgt` (no field; dird names the krbtgt key
    /// set). Spec: docs/51 §6; docs/10 §7.
    pub const KEY_OP_ROTATE_KRBTGT: u8 = 0x01;
    /// `KeyOperation`: `rotate_key` of a service object's randomized
    /// `Service` key set; its objectGUID follows. Spec: docs/51 §6; docs/10
    /// §7, §5ב.
    pub const KEY_OP_ROTATE_KEY: u8 = 0x02;
    /// `KeyOperation`: `retire_kvno`; a key reference and the kvno follow.
    /// Spec: docs/51 §6; docs/10 §7; docs/33 §5.
    pub const KEY_OP_RETIRE_KVNO: u8 = 0x03;

    /// `KeyRef`: the krbtgt key set (dird names it). Spec: docs/51 §6.
    pub const KEY_REF_KRBTGT: u8 = 0x01;
    /// `KeyRef`: a service object's `Service` key set; its objectGUID
    /// follows. Spec: docs/51 §6.
    pub const KEY_REF_SERVICE: u8 = 0x02;

    /// `Complete.outcome`: keyd performed the operation; an optional kvno
    /// (the new one, for a rotation) follows. Spec: docs/51 §6 (`Complete
    /// {id, outcome, kvno}`); A-88, A-90.
    pub const KEY_OUTCOME_PERFORMED: u8 = 0x01;
    /// `Complete.outcome`: keyd answered with a refusal (nothing stored,
    /// docs/10 §9).
    pub const KEY_OUTCOME_REFUSED: u8 = 0x02;
    /// `Complete.outcome`: not performed — never sent, or refused by keyd's
    /// transport before keyd ran it (A-88).
    pub const KEY_OUTCOME_NOT_PERFORMED: u8 = 0x03;
    /// `Complete.outcome`: sent, and no usable answer came back (A-90).
    pub const KEY_OUTCOME_UNKNOWN: u8 = 0x04;
}

/// What the client is told about a refused or failed operation (the reason
/// is in the audit event only). Mirrors crate directory-admin's
/// `RefusalStatus` by name (crates/directory-daemon maps one to the other;
/// this crate links no PEP).
/// Spec: A-26 (uniform `Denied`); A-55 (no existence oracle: `NotFound` for
/// an absent object and for one the requester cannot read); A-56
/// (`Unavailable`); docs/11 §1b.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalStatus {
    /// Not permitted (unauthenticated, not allowed, an unacceptable approval,
    /// a protected target, the self-lockout guard).
    Denied,
    /// Dual control applies and the approvals do not reach the quorum.
    ApprovalRequired,
    /// The object does not exist or the requester cannot read it.
    NotFound,
    /// A request value breaks a rule.
    Invalid,
    /// The directory holds a conflicting value or state.
    Conflict,
    /// The operation could not be carried out now (keyd, auditd, the store);
    /// nothing was committed.
    Unavailable,
}

impl RefusalStatus {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            RefusalStatus::Denied => 0x01,
            RefusalStatus::ApprovalRequired => 0x02,
            RefusalStatus::NotFound => 0x03,
            RefusalStatus::Invalid => 0x04,
            RefusalStatus::Conflict => 0x05,
            RefusalStatus::Unavailable => 0x06,
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
            _ => None,
        }
    }
}
