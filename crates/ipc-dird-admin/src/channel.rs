//! The admin channel's fixed identity: magic, version, the per-direction
//! body bounds, the per-field bounds, the closed kind tables and the closed
//! code tables.
//!
//! # Where the numbers come from
//!
//! * **Request direction: 256 KiB.** Every operation carries the
//!   authentication field `auth := requester ‖ approvals` — the requester's
//!   raw AP-REQ of at most 64 KiB (`ipc_keyd::MAX_REQUEST_FIELD`, because
//!   dird hands it to keyd exactly as it arrived) and the **retired**
//!   approvals sequence, always empty (docs/questions/Q-882, A-148: every
//!   approval is a step on a pending request held in dird — `Approve` —
//!   never an AP-REQ inside another request) — and a payload of at most
//!   16 KiB (names ≤ 3 KiB per docs/46 §5.4, as docs/51 §7.5 states).
//!   docs/51 §7.5: "request ≤ 256 KiB (… payload ≤ 16 KiB …); const assert
//!   against `ipc_keyd::MAX_REQUEST_FIELD`". The 256 KiB bound is kept
//!   (it now holds one AP-REQ, not three).
//! * **Reply direction: 64 KiB.** The largest reply is a `ShowRequest`
//!   answer (`RequestShown`): the pending request's operation as dird holds
//!   it (≤ 16 KiB of fields) and the facts dird resolved for the objects it
//!   names (two DNs of at most 64 components each, ≈ 8.4 KiB each) — about
//!   34 KiB, checked at compile time below. docs/51 §7.5 set "reply ≤
//!   16 KiB" before the request queue existed; raised to 64 KiB by task
//!   D2-c (docs/questions/Q-936; project choice).
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

/// Reply body bound: 64 KiB (module notes: a `RequestShown` reaches about
/// 34 KiB). Project choice.
/// Spec: docs/51 §7.5 (16 KiB before the request queue); docs/questions/
/// Q-936 (raised for `ShowRequest`, Q-882).
pub const MAX_REPLY_BODY: u32 = 64 * 1024;

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

/// Bound of one raw AP-REQ (the requester's): 64 KiB, the keyd channel's
/// per-field request bound, because dird forwards it to keyd
/// `open_and_verify_service_ticket` exactly as received.
/// Spec: docs/51 §7.2 (`requester: bytes<64 KiB>`; "64 KiB =
/// `ipc_keyd::MAX_REQUEST_FIELD`, because dird passes them to keyd as they
/// are").
pub const MAX_AP_REQ: u32 = 64 * 1024;

/// The bound of `auth`'s **retired** approvals sequence: zero. The sequence
/// keeps its place on the wire (its count, always 0 — so every other field
/// of every kind keeps its layout), and a sequence with any element is
/// refused by the codec (`ipc::Error::CountOverBound`): the in-request
/// approvals form of dual control has no code path (docs/CLEAN-ROOM.md "insecure
/// options have no code path"; docs/52 C14 — one mechanism). Every approval
/// is an `Approve` of a pending request dird holds.
/// Spec: docs/questions/Q-882 item 6 (A-148: "remove `auth.approvals` from
/// the wire"); docs/research/r5-b-cli.md §7.1-§7.2; docs/questions/Q-935.
pub const RETIRED_APPROVALS: u32 = 0;

/// Bound of a pending request's `reason_ref` (octets): 64 — "printable
/// ASCII ≤ 64, a change identifier" (the PEP checks the characters).
/// Spec: docs/questions/Q-882 item 4; docs/research/r5-b-cli.md §7.2.
pub const MAX_REASON_REF: u32 = 64;

/// Most pending requests one `ListRequests` answer carries: dird's whole
/// table (crate directory-admin `MAX_PENDING_REQUESTS`, pinned in
/// crates/directory-daemon, which links both).
/// Spec: docs/research/r5-a-admin-model.md §11 MA5 (`ListRequests`);
/// docs/questions/Q-937.
pub const MAX_LISTED_REQUESTS: u32 = 32;

/// Most approvers a `ShowRequest` answer names: the quorum's largest number
/// of approvers besides the requester (crate directory-admin `MAX_QUORUM`
/// − 1, pinned in crates/directory-daemon).
/// Spec: docs/51 §5.6 (P-22 — the requester plus one other); docs/questions/
/// Q-882 item 1 (`Show {id}` ⇒ "… the approvals").
pub const MAX_SHOWN_APPROVERS: u32 = 2;

/// Most facts a `ShowRequest` answer carries: one per object the pending
/// operation names — at most two (a membership change names the group and
/// the member; a create of a security principal reads its parent and the
/// naming-context root).
/// Spec: docs/questions/Q-882 item 1 ("facts dird resolved for every GUID
/// in the operation"), Q-887 item 3 (the same structure).
pub const MAX_FACTS: u32 = 2;

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

/// Octets of an operation digest: a SHA-256 output (crate::digest).
/// Spec: docs/52 §5 item 1; FIPS 180-4 (SHA-256, as computed by the
/// approved RustCrypto `sha2`); docs/questions/Q-882 item 1.
pub const DIGEST_LEN: usize = 32;

/// Most tier-map changes one `ChangePolicy` request carries: four — every
/// change is named in the request's audit events, which keep at most
/// `ipc_audit::MAX_TARGET_NAMES` (4) names (pinned in crates/directory-daemon,
/// which links both). A larger edit is several requests, each activated by
/// root before the next (one pending change at a time). Project choice
/// (task A16; docs/questions/Q-592).
/// Spec: docs/51 §5.7 item 1 ("names only as `AuditText`"), §5.10.
pub const MAX_POLICY_CHANGES: u32 = 4;

/// Most RDN components of a tier-map subtree DN in a `ChangePolicy`
/// request: 16 — so that four changes fit the 16 KiB payload bound
/// (checked below). The policy file itself admits 64 (crate policy-store);
/// a deeper subtree is edited offline (`provision policy`). Project choice
/// (task A16; docs/questions/Q-592).
/// Spec: docs/51 §7.5 ("payload ≤ 16 KiB").
pub const MAX_POLICY_DN_COMPONENTS: u32 = 16;

/// Bound of an effect plan's canonical encoding (octets): 24 KiB — so that
/// a `RequestShown` carrying the plan of the request beside its operation
/// and its facts stays within the 64 KiB reply bound (checked below). An
/// effect closure that does not fit is not performed (`PlanTooLarge`, fail
/// closed). Project choice (task MA2; docs/questions/Q-981).
/// Spec: docs/research/r5-a-admin-model.md §3.3; docs/51 §7.5 (reply bound,
/// as raised by Q-936).
pub const MAX_PLAN: usize = 24 * 1024;

/// Most principals one effect plan names (and most SIDs one of its sets
/// holds). Project choice (task MA2; docs/questions/Q-981).
/// Spec: docs/research/r5-a-admin-model.md §3.3; docs/CLEAN-ROOM.md (bounded).
pub const MAX_PLAN_PRINCIPALS: u32 = 256;

/// Most effects one plan holds (each groups the principals that share one
/// change). Project choice (task MA2; docs/questions/Q-981).
/// Spec: docs/research/r5-a-admin-model.md §3.3.
pub const MAX_PLAN_EFFECTS: u32 = 64;

/// Body octets of the `auth` field at its largest: the requester's AP-REQ
/// and the (always empty) retired approvals count.
pub const MAX_AUTH: usize = 4 + MAX_AP_REQ as usize + 4;

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
/// Payload octets of an `Approve` / `Reject` after `auth`: id and digest.
const APPROVE_SIZE: usize = 8 + DIGEST_LEN;
/// Body octets of a `PendingRequest` reply.
const PENDING_REQUEST_SIZE: usize = ENVELOPE + 8 + DIGEST_LEN + 1 + 1 + 1 + 8;
/// One `RequestSummary` of a `RequestList`.
const REQUEST_SUMMARY_SIZE: usize = 8 + DIGEST_LEN + 1 + 1 + (4 + MAX_SID as usize) + 1 + 1 + 8;
/// Body octets of the largest `RequestList`.
const REQUEST_LIST_SIZE: usize = ENVELOPE + 4 + MAX_LISTED_REQUESTS as usize * REQUEST_SUMMARY_SIZE;
/// One `Fact` of a `RequestShown`: GUID, DN, class, SID, tier.
const FACT_SIZE: usize = 16
    + (4 + MAX_DN_COMPONENTS as usize * (4 + MAX_DN_COMPONENT as usize))
    + (4 + MAX_CLASS_NAME as usize)
    + (1 + 4 + MAX_SID as usize)
    + 1;
/// Body octets of the largest `RequestShown`: the header, the requester and
/// approvers, the reason, the operation (its kind and at most the payload
/// bound of fields) and the facts.
const REQUEST_SHOWN_SIZE: usize = ENVELOPE
    + 8
    + DIGEST_LEN
    + 1
    + (4 + MAX_SID as usize)
    + (4 + MAX_SHOWN_APPROVERS as usize * (4 + MAX_SID as usize))
    + 1
    + 8
    + (1 + 4 + MAX_REASON_REF as usize)
    + (1 + MAX_PAYLOAD)
    + (4 + MAX_FACTS as usize * FACT_SIZE)
    + (1 + 4 + MAX_PLAN);
/// Body octets of a `Plan` reply: the plan and its digest (task MA2).
const PLAN_SIZE: usize = ENVELOPE + (4 + MAX_PLAN) + DIGEST_LEN;
/// Payload octets of the largest `Propose` of a `Commit` after `auth`: the
/// reason, the `Commit` kind, the plan digest, the inner kind and the
/// largest planned operation (a `ChangePolicy`).
const PROPOSE_COMMIT_SIZE: usize =
    (1 + 4 + MAX_REASON_REF as usize) + 1 + DIGEST_LEN + 1 + CHANGE_POLICY_SIZE;
/// Payload octets of the largest `Propose` after `auth`: the reason and the
/// largest proposable operation (a `ChangePolicy`, bounded below; a
/// `CreateUser`).
const PROPOSE_SIZE: usize = (1 + 4 + MAX_REASON_REF as usize) + 1 + CHANGE_POLICY_SIZE;
const PROPOSE_CREATE_SIZE: usize = (1 + 4 + MAX_REASON_REF as usize) + 1 + CREATE_USER;

/// The largest tier-map change: its tag, then a SID and a tier, or a DN of
/// [`MAX_POLICY_DN_COMPONENTS`] components and a tier (task A16).
const POLICY_SUBTREE_CHANGE: usize =
    1 + 4 + MAX_POLICY_DN_COMPONENTS as usize * (4 + MAX_DN_COMPONENT as usize) + 1;
const POLICY_PRINCIPAL_CHANGE: usize = 1 + 4 + MAX_SID as usize + 1;
/// Payload octets of the largest `ChangePolicy` after `auth`.
const CHANGE_POLICY_SIZE: usize = 4 + MAX_POLICY_CHANGES as usize * POLICY_SUBTREE_CHANGE;
/// Body octets of the `PolicyNext` reply: the version written.
const POLICY_NEXT_SIZE: usize = ENVELOPE + 8;

// The bounds agree with the values they are derived from and fit the body
// bounds; checked at compile time, never at run time.
const _: () = assert!(APPROVE_SIZE <= MAX_PAYLOAD);
const _: () = assert!(KEY_OPERATION_SIZE <= MAX_PAYLOAD);
const _: () = assert!(PROPOSE_SIZE <= MAX_PAYLOAD);
const _: () = assert!(PROPOSE_CREATE_SIZE <= MAX_PAYLOAD);
const _: () = assert!(PENDING_REQUEST_SIZE <= MAX_REPLY_BODY as usize);
const _: () = assert!(REQUEST_LIST_SIZE <= MAX_REPLY_BODY as usize);
const _: () = assert!(REQUEST_SHOWN_SIZE <= MAX_REPLY_BODY as usize);
const _: () = assert!(PLAN_SIZE <= MAX_REPLY_BODY as usize);
const _: () = assert!(PROPOSE_COMMIT_SIZE <= MAX_PAYLOAD);
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
const _: () = assert!(POLICY_PRINCIPAL_CHANGE <= POLICY_SUBTREE_CHANGE);
const _: () = assert!(CHANGE_POLICY_SIZE <= MAX_PAYLOAD);
const _: () = assert!(POLICY_NEXT_SIZE <= MAX_REPLY_BODY as usize);
const _: () = assert!(MAX_POLICY_DN_COMPONENTS <= MAX_DN_COMPONENTS);

// ---- kinds -----------------------------------------------------------------

/// Request kinds (admind → dird): the closed operation set of docs/51 §7.3,
/// numbered in the table's order, and `Ping`. The key-operation rows of that
/// table (task A10) took `0x0E`–`0x12` in the same order —
/// `RequestKeyOperation`, `Approve`, and keyadm's `FetchApproved`,
/// `Complete`, `ListPendingDestruction`. **`0x10`, `0x11`, `0x12` are
/// retired by A-102 and never reused** (docs/52 §4.6, §4.8;
/// docs/questions/Q-460). **`0x0E` (`RequestKeyOperation`) and `0x0F` (the
/// key-only `Approve {id, operation}`) are retired by task D2-c and never
/// reused** (docs/questions/Q-882, A-148: one dual-control mechanism — a
/// key operation is proposed with `Propose` like every other dual-controlled
/// operation, and approved with the one `Approve {id, digest}`). `0x13` (the
/// table's `IssueJoinToken`, task A12 — deferred, A-78) stays unused; `0x15`
/// is admin.sock's `SetPassword`. The request queue (task D2-c,
/// docs/questions/Q-882, docs/research/r5-a-admin-model.md §11 MA5) is
/// appended from `0x17`. Values are a project choice.
/// Spec: docs/51 §7.3; docs/50 §3.3 ("`kind` closed"), §7.5 (`Ping`);
/// docs/questions/Q-389 item 1 (A-91), Q-422, Q-460 (A-102), Q-882, Q-935.
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
    // 0x0E (`RequestKeyOperation`) and 0x0F (`Approve {id, operation}`):
    // retired by task D2-c, never reused (docs/questions/Q-882, Q-935).
    // 0x10 (`FetchApproved`), 0x11 (`Complete`), 0x12
    // (`ListPendingDestruction`): retired by A-102, never reused (docs/52
    // §4.6; docs/questions/Q-460).
    /// `Ping`: the health check, no `auth`. Spec: docs/51 §7.3; docs/50 §7.5.
    pub const PING: u8 = 0x14;
    /// `ChangePolicy {changes}` (appended by task A16): a tier-map edit
    /// under mandatory dual control — executed by its requester once a
    /// pending request for exactly these changes is approved (Q-882) —
    /// which dird writes as `policy.next` (version + 1) for root to
    /// activate. `0x15` is admin.sock's `SetPassword` (the two channels
    /// share the forwarded kinds' numbers), so this kind is `0x16`.
    /// Spec: docs/51 §5.2 row 13, §5.6, §5.10 (R51-21); A-80;
    /// docs/questions/Q-592, Q-882.
    pub const CHANGE_POLICY: u8 = 0x16;
    /// `Propose {reason_ref?, operation}`: the requester opens a pending
    /// request for one dual-controlled operation — dird holds its exact
    /// fields and its operation digest (task D2-c).
    /// Spec: docs/questions/Q-882 item 1 (`Propose`); docs/research/
    /// r5-b-cli.md §7.2.
    pub const PROPOSE: u8 = 0x17;
    /// `Approve {id, digest}`: an approver approves the pending request
    /// `id`, naming the operation digest it was shown.
    /// Spec: docs/questions/Q-882 item 1 (`Approve {id, digest}`); docs/51
    /// §5.6.
    pub const APPROVE: u8 = 0x18;
    /// `Reject {id, digest}`: an eligible approver ends a pending request.
    /// Spec: docs/research/r5-a-admin-model.md §5, §11 MA5 (`Reject`).
    pub const REJECT: u8 = 0x19;
    /// `Withdraw {id}`: the requester ends its own pending request.
    /// Spec: docs/questions/Q-882 item 1 (`Withdraw {id}`); r5-a §11 MA5.
    pub const WITHDRAW: u8 = 0x1A;
    /// `ListRequests {scope}`: the caller's own pending requests, or those
    /// awaiting its approval.
    /// Spec: docs/questions/Q-882 item 1 (`List {mine | awaiting_me}`);
    /// r5-a §5, §11 MA5 (`ListRequests`).
    pub const LIST_REQUESTS: u8 = 0x1B;
    /// `ShowRequest {id}`: the pending request as dird holds it — its
    /// operation from dird's own fields, never from requester text — and
    /// the facts dird resolved.
    /// Spec: docs/questions/Q-882 item 1 (`Show {id}`); r5-a §5, §11 MA5;
    /// docs/research/r5-b-cli.md §7.4.
    pub const SHOW_REQUEST: u8 = 0x1C;
    /// The kind of a **proposed key operation** — `RotateKrbtgt`,
    /// `RotateKey`, `RetireKvno` (docs/51 §6) — inside a `Propose` only:
    /// it names the operation in the digest (crate::digest) and in a
    /// `RequestShown`. Never a request of its own: not in [`ALL`], so a
    /// frame of this kind is refused like an unknown kind (a key operation
    /// is executed by keyadm in keyd, from the decision dird registers —
    /// A-102).
    /// Spec: docs/51 §6; docs/questions/Q-882 item 2; docs/52 §4.3.
    pub const KEY_OPERATION: u8 = 0x1D;
    /// `PlanOperation {operation}` (appended by task MA2): the requester
    /// asks dird for the **effect plan** of one of [`PLANNED`] — the same
    /// checks as its execution, committing nothing; answered `Plan {plan,
    /// digest}` (crate::plan).
    /// Spec: docs/research/r5-a-admin-model.md §3.3 (`PlanOperation {op,
    /// fields} → EffectPlan`), §11 MA2; docs/questions/Q-874 item 1, Q-980.
    pub const PLAN_OPERATION: u8 = 0x1E;
    /// `Commit {plan, operation}` (appended by task MA2): one of [`PLANNED`]
    /// with the digest of the plan it commits to — the only form in which a
    /// planned operation executes, and the form in which it is proposed. Its
    /// operation digest covers the plan digest, so the requester's AP-REQ
    /// and every approver's `Approve` bind the effect closure; dird
    /// recomputes the plan at the execution and refuses any difference
    /// (`PlanChanged`). A `Commit` of a key operation is valid only inside a
    /// `Propose` (keyadm executes key operations, A-102).
    /// Spec: docs/research/r5-a-admin-model.md §3.3 (`Commit {plan_id}` with
    /// `OperationDigest = H(op ‖ fields ‖ plan.digest)`); docs/questions/
    /// Q-874 items 1-2, Q-980.
    pub const COMMIT: u8 = 0x1F;

    /// The operations that **require an effect plan** (task MA2;
    /// docs/questions/Q-982): every operation whose effect reaches beyond
    /// its direct target — membership changes (transitive), an account's
    /// enable / expiry / delete and password set (its tickets; a delete's
    /// memberships and key sets), the policy change (everyone whose tier
    /// changes) and the key operations. None of these kinds is a request of
    /// its own any more (they are not in [`ALL`]): each travels only inside
    /// `PlanOperation` and `Commit` — so a planned operation has no frame
    /// that executes it without a plan.
    /// Spec: docs/research/r5-a-admin-model.md §3.3, §8.2 ("hidden
    /// effects"); docs/questions/Q-982.
    pub const PLANNED: &[u8] = &[
        BEGIN_PASSWORD_SET,
        SET_ENABLED,
        SET_ACCOUNT_EXPIRES,
        ADD_MEMBER,
        REMOVE_MEMBER,
        DELETE,
        CHANGE_POLICY,
        KEY_OPERATION,
    ];

    /// The kinds retired by A-102 (keyadm's `FetchApproved`, `Complete`,
    /// `ListPendingDestruction`) and by task D2-c (`RequestKeyOperation`,
    /// the key-only `Approve`) — kept only so that tests can show the closed
    /// table refuses them; never in [`ALL`], never reused.
    /// Spec: docs/52 §4.6; docs/questions/Q-460 (A-102), Q-882, Q-935.
    pub const RETIRED: &[u8] = &[0x0E, 0x0F, 0x10, 0x11, 0x12];

    /// The operations a `Propose` may carry: the dual-controlled ones
    /// (docs/51 §5.6, P-22 — the writes whose rule can require an approver,
    /// the policy change and the key operations). `Lookup` and
    /// `CompletePasswordSet` never need an approver and are not proposable;
    /// neither is any request-queue kind.
    /// Spec: docs/51 §5.2, §5.6, §6; docs/questions/Q-882 item 1 ("every
    /// dual-controlled operation, by P-22's list").
    ///
    /// Since task MA2 a planned operation is proposed only as a `Commit` of
    /// it (the plan it commits to is what the approvers approve): the
    /// [`PLANNED`] kinds are proposable only inside [`COMMIT`].
    pub const PROPOSABLE: &[u8] = &[
        CREATE_USER,
        CREATE_COMPUTER,
        CREATE_GROUP,
        CREATE_OU,
        CREATE_CONTAINER,
        COMMIT,
    ];

    /// The kinds of the operation a pending request is for, as a
    /// `RequestList` entry names it: a proposable create, or the planned
    /// operation inside a `Commit` (task MA2).
    /// Spec: docs/research/r5-a-admin-model.md §11 MA5; docs/questions/Q-980.
    pub const REQUEST_OPERATIONS: &[u8] = &[
        CREATE_USER,
        CREATE_COMPUTER,
        CREATE_GROUP,
        CREATE_OU,
        CREATE_CONTAINER,
        BEGIN_PASSWORD_SET,
        SET_ENABLED,
        SET_ACCOUNT_EXPIRES,
        ADD_MEMBER,
        REMOVE_MEMBER,
        DELETE,
        CHANGE_POLICY,
        KEY_OPERATION,
    ];

    /// The closed request table. Spec: docs/51 §7.3; docs/50 §3.3. The
    /// [`PLANNED`] kinds left it with task MA2 (they travel only inside
    /// `PlanOperation` / `Commit`); their numbers keep their meaning there.
    pub const ALL: &[u8] = &[
        CREATE_USER,
        CREATE_COMPUTER,
        CREATE_GROUP,
        CREATE_OU,
        CREATE_CONTAINER,
        COMPLETE_PASSWORD_SET,
        LOOKUP,
        PING,
        PROPOSE,
        APPROVE,
        REJECT,
        WITHDRAW,
        LIST_REQUESTS,
        SHOW_REQUEST,
        PLAN_OPERATION,
        COMMIT,
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
    /// `Done`: the `()` of docs/51 §7.3 (and of `Reject` / `Withdraw`).
    pub const DONE: u8 = 0x83;
    /// `Found { guid, dn, class, sid? }`. Spec: docs/51 §7.3 (`Lookup`).
    pub const FOUND: u8 = 0x84;
    /// `Refused { status }`: the operation was refused or failed; the reason
    /// is in the audit trail only (A-26; docs/11 §1b).
    pub const REFUSED: u8 = 0x85;
    /// `Pong`: the reply to `Ping`. Spec: docs/50 §7.5.
    pub const PONG: u8 = 0x86;
    // 0x87 is admin.sock's `PasswordChanged`, never dird's (the two channels
    // share their common reply numbers). 0x88 (`KeyRequest`): retired by
    // task D2-c with its requests, never reused (docs/questions/Q-882).
    // 0x89 (`Approved`) and 0x8A (`PendingDestruction`): keyadm's replies,
    // retired by A-102, never reused (docs/52 §4.6; docs/questions/Q-460).
    /// `PolicyNext { version }` (appended by task A16): the answer to a
    /// `ChangePolicy` dird wrote as `policy.next` — the version root's
    /// activation will install.
    /// Spec: docs/51 §5.10; docs/questions/Q-592.
    pub const POLICY_NEXT: u8 = 0x8B;
    /// `PendingRequest { id, digest, state, approvals, quorum, expires }`:
    /// the answer to `Propose` and `Approve` (task D2-c).
    /// Spec: docs/questions/Q-882 item 1 (`{id, digest, quorum, expires}`).
    pub const PENDING_REQUEST: u8 = 0x8C;
    /// `RequestList { entries }`: the answer to `ListRequests`.
    /// Spec: r5-a §11 MA5; docs/questions/Q-882 item 1.
    pub const REQUEST_LIST: u8 = 0x8D;
    /// `RequestShown { … }`: the answer to `ShowRequest`.
    /// Spec: docs/questions/Q-882 item 1, Q-887 item 3; r5-b §7.4.
    pub const REQUEST_SHOWN: u8 = 0x8E;
    /// `Plan { plan, digest }`: the answer to `PlanOperation` — the effect
    /// plan's canonical encoding and its digest (task MA2).
    /// Spec: docs/research/r5-a-admin-model.md §3.3; docs/questions/Q-874
    /// item 1, Q-980.
    pub const PLAN: u8 = 0x8F;

    /// The reply kinds retired by A-102 and by task D2-c; never in [`ALL`],
    /// never reused.
    /// Spec: docs/52 §4.6; docs/questions/Q-460 (A-102), Q-882, Q-935.
    pub const RETIRED: &[u8] = &[0x88, 0x89, 0x8A];

    /// The closed reply table (without the reserved `REFUSED_KIND`).
    /// Spec: docs/51 §7.3; docs/50 §3.3; A-59.
    pub const ALL: &[u8] = &[
        CREATED,
        PASSWORD_SET,
        DONE,
        FOUND,
        REFUSED,
        PONG,
        POLICY_NEXT,
        PENDING_REQUEST,
        REQUEST_LIST,
        REQUEST_SHOWN,
        PLAN,
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

/// Whether no value of `a` is in `b`. Compile-time helper.
const fn disjoint(a: &[u8], b: &[u8]) -> bool {
    let mut i = 0;
    while i < a.len() {
        let mut j = 0;
        while j < b.len() {
            if a[i] == b[j] {
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
const _: () = assert!(all_distinct(request_kind::PROPOSABLE));
const _: () = assert!(disjoint(request_kind::ALL, request_kind::RETIRED));
const _: () = assert!(disjoint(reply_kind::ALL, reply_kind::RETIRED));
// The inner kind of a proposed key operation is never a request of its own.
const _: () = assert!(disjoint(request_kind::ALL, &[request_kind::KEY_OPERATION]));
// No planned operation is a request of its own (task MA2): it travels only
// inside `PlanOperation` / `Commit`.
const _: () = assert!(disjoint(request_kind::ALL, request_kind::PLANNED));
const _: () = assert!(disjoint(request_kind::PROPOSABLE, request_kind::PLANNED));
const _: () = assert!(all_distinct(request_kind::PLANNED));
const _: () = assert!(all_distinct(request_kind::REQUEST_OPERATIONS));
// No request-queue kind, read or audit-only step is proposable (no
// `Propose` inside a `Propose`).
const _: () = assert!(disjoint(
    request_kind::PROPOSABLE,
    &[
        request_kind::PROPOSE,
        request_kind::APPROVE,
        request_kind::REJECT,
        request_kind::WITHDRAW,
        request_kind::LIST_REQUESTS,
        request_kind::SHOW_REQUEST,
        request_kind::LOOKUP,
        request_kind::COMPLETE_PASSWORD_SET,
        request_kind::PING,
        request_kind::PLAN_OPERATION,
    ]
));

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
    /// §7, §5b.
    pub const KEY_OP_ROTATE_KEY: u8 = 0x02;
    /// `KeyOperation`: `retire_kvno`; a key reference and the kvno follow.
    /// Spec: docs/51 §6; docs/10 §7; docs/33 §5.
    pub const KEY_OP_RETIRE_KVNO: u8 = 0x03;

    /// `KeyRef`: the krbtgt key set (dird names it). Spec: docs/51 §6.
    pub const KEY_REF_KRBTGT: u8 = 0x01;
    /// `KeyRef`: a service object's `Service` key set; its objectGUID
    /// follows. Spec: docs/51 §6.
    pub const KEY_REF_SERVICE: u8 = 0x02;

    /// `PolicyChange`: add `SID → tier` (a SID and a tier follow). The
    /// four changes are the tier-map edit's vocabulary (crate policy-store
    /// `TierChange`, the vocabulary of `provision policy`). Task A16.
    /// Spec: docs/51 §5.10 ("add / remove rows of the map").
    pub const POLICY_ADD_PRINCIPAL: u8 = 0x01;
    /// `PolicyChange`: remove the row of a SID (the SID follows).
    pub const POLICY_REMOVE_PRINCIPAL: u8 = 0x02;
    /// `PolicyChange`: add `subtree → tier` (a DN and a tier follow).
    pub const POLICY_ADD_SUBTREE: u8 = 0x03;
    /// `PolicyChange`: remove the row of a subtree (the DN follows).
    pub const POLICY_REMOVE_SUBTREE: u8 = 0x04;

    /// A tier-map row's tier: `Tier0` — the policy file's own tier codes
    /// (crate policy-store `codes::tier`, format 1's), without `Untiered`,
    /// which is never a map row and so has no code here (unrepresentable).
    /// Spec: crate policy-store (`tier := 0 Tier0 | 1 Tier1 | 2 Tier2`); A-36.
    pub const TIER_0: u8 = 0x00;
    /// A tier-map row's tier: `Tier1`.
    pub const TIER_1: u8 = 0x01;
    /// A tier-map row's tier: `Tier2`.
    pub const TIER_2: u8 = 0x02;
    /// A fact's tier (`RequestShown`): no explicit classification — Tier0
    /// for writes by A-36's default, but no tier-map entry or structural
    /// rule names it (P-22: such a write needs no approver). The three tier
    /// codes above are the explicit tiers. Task D2-c.
    /// Spec: docs/47 §6.3; A-36; P-22; docs/questions/Q-887 item 2 ("tier").
    pub const FACT_UNCLASSIFIED: u8 = 0x03;

    /// A pending request's state: awaiting approvals. Task D2-c.
    /// Spec: docs/questions/Q-882 item 1; docs/questions/Q-937.
    pub const REQUEST_PENDING: u8 = 0x01;
    /// A pending request's state: the quorum is reached — a directory or
    /// policy operation may now be executed by its requester; a key
    /// operation's decision is registered in keyd for keyadm (A-102).
    /// Spec: docs/questions/Q-882 item 2; docs/questions/Q-937.
    pub const REQUEST_APPROVED: u8 = 0x02;

    /// `ListRequests.scope`: the caller's own pending requests.
    /// Spec: docs/questions/Q-882 item 1 (`List {mine | awaiting_me}`).
    pub const LIST_MINE: u8 = 0x01;
    /// `ListRequests.scope`: the pending requests the caller may approve and
    /// has not approved.
    pub const LIST_AWAITING_ME: u8 = 0x02;

    /// An effect plan's principal: a user (task MA2, crate::plan).
    /// Spec: docs/research/r5-a-admin-model.md §3.3; docs/46 §4.
    pub const PLAN_KIND_USER: u8 = 0x01;
    /// An effect plan's principal: a computer.
    pub const PLAN_KIND_COMPUTER: u8 = 0x02;
    /// An effect plan's principal: a group.
    pub const PLAN_KIND_GROUP: u8 = 0x03;

    /// Effect tag: `MembershipDelta` (task MA2, crate::plan).
    /// Spec: docs/research/r5-a-admin-model.md §3.3 (`Effect`).
    pub const EFFECT_MEMBERSHIP_DELTA: u8 = 0x01;
    /// Effect tag: `TierDelta`.
    pub const EFFECT_TIER_DELTA: u8 = 0x02;
    /// Effect tag: `PolicyReference`.
    pub const EFFECT_POLICY_REFERENCE: u8 = 0x03;
    /// Effect tag: `TicketsRevoked`.
    pub const EFFECT_TICKETS_REVOKED: u8 = 0x04;
    /// Effect tag: `ProtectedDataLoss`.
    pub const EFFECT_PROTECTED_DATA_LOSS: u8 = 0x05;
    /// Effect tag: `KeyDestruction`.
    pub const EFFECT_KEY_DESTRUCTION: u8 = 0x06;

    /// `PolicyReference`: a tier-map row names the group (its tier
    /// follows). Spec: docs/47 §6.3; A-36.
    pub const REFERENCE_TIER_MAP: u8 = 0x01;
    /// `PolicyReference`: a policy principal (the bootstrap group).
    /// Spec: A-39 / A-44.
    pub const REFERENCE_POLICY_PRINCIPAL: u8 = 0x02;

    /// `TicketsRevoked`: a password set (`revoked_before`, A-162).
    pub const REVOKED_BY_PASSWORD_SET: u8 = 0x01;
    /// `TicketsRevoked`: the account becomes unusable (D53).
    pub const REVOKED_ACCOUNT_UNUSABLE: u8 = 0x02;
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
