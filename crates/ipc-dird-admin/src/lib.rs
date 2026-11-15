#![forbid(unsafe_code)]
//! `ipc-dird-admin`: the admind ↔ dird admin channel (`dird-admin.sock`) —
//! its message set, the typed requests and replies, dird's decoding and
//! reply encoding, and admind's synchronous client (docs/51 §7, R51-15,
//! §12 task A8; decisions A-72, A-73).
//!
//! The write PEP (crates/directory-admin), keyd's ticket verification and
//! the audit gate run in dird (crates/directory-daemon); this crate links
//! none of them — no dirstore, redb, directory-pip, directory-admin, keyd or
//! krb-crypto (checked by `tests/no_store_dependency.rs`), so admind links
//! only the codec and the client.
//!
//! # Layers
//!
//! | layer | module | what it checks |
//! |---|---|---|
//! | channel | [`channel`] | magic `0x4441`, exact version 1, per-direction / per-field bounds, closed kind and code tables (no kind equals `ipc::REFUSED_KIND`) |
//! | wire | [`wire`] | fixed-order fields through `ipc` (lengths, markers, closed tables, no trailing octet) |
//! | typed | [`typed`] | UTF-8 text, GUIDs, SIDs (dtyp), realms / salts / binding names (krb-proto); one spelling per value |
//! | server | [`server`] | [`decode_request`] (or how to refuse), [`encode_reply`] |
//! | digest | [`digest`] | [`operation_digest`]: the application data an admin AP-REQ is bound to (R2, docs/52 §5) |
//! | plan | [`plan`] | [`EffectPlan`]: the effect plan's canonical encoding and [`plan_digest`] (task MA2) |
//! | client | [`client`] | [`AdminClient`]: dird-uid check before sending, deadline, idle check, no resend, strict replies |
//! | socket | `unix` | [`UnixConnector`]: blocking Unix stream, peer uid via rustix (Linux; elsewhere fail closed) |
//!
//! # Wire layout (magic `0x4441` "DA", version 1)
//!
//! Every frame: `length:u32 ‖ magic:u16 ‖ version:u8 ‖ kind:u8 ‖ payload`
//! (docs/50 §3.3). Every operation's payload starts with
//! `auth := requester: bytes<64 KiB> ‖ approvals: seq<_, 0>` — the
//! requester's raw AP-REQ, and the count of the **retired** in-request
//! approvals, always 0 (a non-empty sequence is refused: docs/questions/
//! Q-882 item 6, A-148 — every approval is an `Approve` of a pending request
//! dird holds); there is no field in which admind could claim a name, SID,
//! tier or "approved" (docs/51 §7.2; A-70).
//!
//! **Every AP-REQ is bound to its operation (R2; docs/52 §5; A-102):** the
//! Authenticator's `cksum` (RFC 4120 §5.5.1, key usage 10) is the session
//! key's MIC over the [`operation_digest`] of the request it accompanies —
//! SHA-256 over a fixed label, this channel's magic, version and kind, and
//! the payload after `auth` (for `CompletePasswordSet`, its `target` only).
//! dird has keyd verify it; an AP-REQ attached to another operation is
//! refused.
//!
//! Since task MA2 the rows `0x06`, `0x08`–`0x0C` and `0x16` (and `0x1D`)
//! are **planned operations**: valid only as the operation inside
//! `PlanOperation` (`0x1E`) and `Commit` (`0x1F`), never as frames of their
//! own (docs/questions/Q-980, Q-982).
//!
//! | dir | kind | message | payload after `auth` | reply |
//! |---|---|---|---|---|
//! | → | `0x01` | `CreateUser` | `parent:[16] ‖ sam:bytes<256> ‖ upn:Option<bytes<1024>> ‖ description:Option<bytes<3072>>` | `Created` |
//! | → | `0x02` | `CreateComputer` | `parent ‖ name:bytes<256> ‖ dns_host_name:bytes<2048> ‖ spn:Option<bytes<1024>>` | `Created` |
//! | → | `0x03` | `CreateGroup` | `parent ‖ sam:bytes<256> ‖ group_type:Option<u32>` | `Created` |
//! | → | `0x04` | `CreateOu` | `parent ‖ name:bytes<256>` | `Created` |
//! | → | `0x05` | `CreateContainer` | `parent ‖ name:bytes<256>` | `Created` |
//! | → | `0x06` | `BeginPasswordSet` | `target:[16]` | `PasswordSet` |
//! | → | `0x07` | `CompletePasswordSet` | `target ‖ outcome:u8{1 Completed, 2 Failed} ‖ kvnos:seq<u32,2>` | `Done` |
//! | → | `0x08` | `SetEnabled` | `target ‖ enabled:bool` | `Done` |
//! | → | `0x09` | `SetAccountExpires` | `target ‖ (u8 1 Never \| u8 2 At ‖ filetime:u64)` | `Done` |
//! | → | `0x0A` | `AddMember` | `group:[16] ‖ member:[16]` | `Done` |
//! | → | `0x0B` | `RemoveMember` | `group ‖ member` | `Done` |
//! | → | `0x0C` | `Delete` | `target` | `Done` |
//! | → | `0x0D` | `Lookup` | `u8 1 ‖ sam:bytes<256> \| u8 2 ‖ spn:bytes<1024> \| u8 3 ‖ dn:seq<bytes<128>,64>` | `Found` |
//! | → | `0x0E`, `0x0F` | (retired by task D2-c: `RequestKeyOperation`, the key-only `Approve {id, operation}` — Q-882) | — | — |
//! | → | `0x10`–`0x12` | (retired by A-102: keyadm's `FetchApproved`, `Complete`, `ListPendingDestruction`) | — | — |
//! | → | `0x14` | `Ping` | (no `auth`, empty) | `Pong` |
//! | → | `0x16` | `ChangePolicy` (task A16) | `changes:seq<PolicyChange, 4>` | `PolicyNext` |
//! | → | `0x17` | `Propose` (D2-c) | `reason_ref:Option<bytes<64>> ‖ operation:ProposedOperation` | `PendingRequest` |
//! | → | `0x18` | `Approve` (D2-c) | `id:u64 ‖ digest:[32]` | `PendingRequest` |
//! | → | `0x19` | `Reject` (D2-c) | `id:u64 ‖ digest:[32]` | `Done` |
//! | → | `0x1A` | `Withdraw` (D2-c) | `id:u64` | `Done` |
//! | → | `0x1B` | `ListRequests` (D2-c) | `scope:u8{1 Mine, 2 AwaitingMe}` | `RequestList` |
//! | → | `0x1C` | `ShowRequest` (D2-c) | `id:u64` | `RequestShown` |
//! | → | `0x1E` | `PlanOperation` (MA2) | `operation:PlannedOperation` | `Plan` |
//! | → | `0x1F` | `Commit` (MA2) | `plan:[32] ‖ operation:PlannedOperation` (never a key operation at top level) | the planned operation's reply |
//! | ← | `0x81` | `Created` | `guid:[16] ‖ sid:Option<bytes<68>>` | — |
//! | ← | `0x82` | `PasswordSet` | `kind:u8{1 User, 2 Computer} ‖ keys:seq<(principal:[16] ‖ purpose:u8{1 Longterm, 2 Service} ‖ realm:bytes<255> ‖ name:bytes<4096> DER), 2> ‖ salt:bytes<1024>` | — |
//! | ← | `0x83` | `Done` | — | — |
//! | ← | `0x84` | `Found` | `guid:[16] ‖ dn:seq<bytes<128>,64> ‖ class:bytes<64> ‖ sid:Option<bytes<68>>` | — |
//! | ← | `0x85` | `Refused` | `status:u8{1 Denied, 2 ApprovalRequired, 3 NotFound, 4 Invalid, 5 Conflict, 6 Unavailable}` | — |
//! | ← | `0x86` | `Pong` | — | — |
//! | ← | `0x88` | (retired by task D2-c: `KeyRequest`) | — | — |
//! | ← | `0x89`, `0x8A` | (retired by A-102: `Approved`, `PendingDestruction`) | — | — |
//! | ← | `0x8B` | `PolicyNext` (task A16) | `version:u64` | — |
//! | ← | `0x8C` | `PendingRequest` (D2-c) | `id:u64 ‖ digest:[32] ‖ state:u8{1 Pending, 2 Approved} ‖ approvals:u8 ‖ quorum:u8 ‖ expires:u64` | — |
//! | ← | `0x8D` | `RequestList` (D2-c) | `entries:seq<(id ‖ digest ‖ state ‖ operation:u8 ‖ requester:bytes<68> ‖ approvals:u8 ‖ quorum:u8 ‖ expires:u64), 32>` | — |
//! | ← | `0x8E` | `RequestShown` (D2-c) | `id ‖ digest ‖ state ‖ requester:bytes<68> ‖ approvers:seq<bytes<68>,2> ‖ quorum:u8 ‖ expires:u64 ‖ reason_ref:Option<bytes<64>> ‖ operation:ProposedOperation ‖ facts:seq<Fact,2> ‖ plan:Option<bytes<24 KiB>>` (`plan` appended by MA2) | — |
//! | ← | `0x8F` | `Plan` (MA2) | `plan:bytes<24 KiB> ‖ digest:[32]` | — |
//! | ← | `0xFF` | shared `Refused` (A-59) | `code` | — |
//!
//! `ProposedOperation := kind:u8 ‖ fields`, the kind one of
//! `request_kind::PROPOSABLE` — the creates, and `0x1F Commit` of a planned
//! operation. `PlannedOperation := kind:u8 ‖ fields`, the kind one of
//! `request_kind::PLANNED` — `BeginPasswordSet`, `SetEnabled`,
//! `SetAccountExpires`, `AddMember`, `RemoveMember`, `Delete`,
//! `ChangePolicy`, and `0x1D KeyOperation`. **Since task MA2 none of these
//! is a request of its own** (docs/research/r5-a-admin-model.md §3.3;
//! docs/questions/Q-980, Q-982): each is planned (`PlanOperation` → `Plan`)
//! and executed or proposed only as a `Commit {plan, operation}`, whose
//! operation digest covers the plan digest — the effect closure the
//! requester's AP-REQ and the approvers' `Approve` bind; dird recomputes the
//! plan at the execution and refuses any difference (`PlanChanged`, wire
//! `Conflict`).
//! `Fact := guid:[16] ‖ dn:seq<bytes<128>,64> ‖ class:bytes<64> ‖
//! sid:Option<bytes<68>> ‖ tier:u8{0 Tier0, 1 Tier1, 2 Tier2,
//! 3 Unclassified}`. `expires` is in seconds since 1970-01-01T00:00:00Z.
//! `KeyOperation := u8 1 RotateKrbtgt | u8 2 RotateKey ‖ service:[16] |
//! u8 3 RetireKvno ‖ KeyRef ‖ kvno:u32`; `KeyRef := u8 1 Krbtgt | u8 2
//! Service ‖ principal:[16]` (task A10, docs/questions/Q-422). keyadm's
//! three requests (`0x10`–`0x12`, the only ones without `auth`) and their
//! replies (`0x89`, `0x8A`) were **retired by A-102** and are never reused
//! (docs/52 §4.6, §4.8; docs/questions/Q-460): when an `Approve` completes
//! the quorum of a key-operation request, dird registers the decision in
//! keyd itself (Role::Ldap), and keyadm executes it in keyd by the request's
//! id.
//!
//! **One dual-control mechanism (task D2-c; docs/questions/Q-882, A-148).**
//! Every dual-controlled operation goes through a pending request dird
//! holds: `Propose` (the requester's AP-REQ bound to the `Propose`) ⇒ dird
//! holds the exact operation and its operation digest; `Approve {id,
//! digest}` (each approver's AP-REQ bound to the `Approve`); at the quorum a
//! directory or policy operation becomes executable by its requester — the
//! same operation sent again, with a fresh AP-REQ, which dird matches to the
//! approved request by its digest, re-evaluating the requester, every
//! approver and the objects it names against the current state (class C43)
//! — and a key operation's decision is registered in keyd. `Reject`,
//! `Withdraw`, `ListRequests`, `ShowRequest` complete the queue (r5-a MA5).
//! The in-request approvals and the key-only `RequestKeyOperation` /
//! `Approve` have no code path. `PolicyChange := u8 1
//! AddPrincipal ‖ sid:bytes<68> ‖ tier:u8 | u8 2 RemovePrincipal ‖ sid | u8 3
//! AddSubtree ‖ dn:seq<bytes<128>,16> ‖ tier | u8 4 RemoveSubtree ‖ dn`,
//! `tier := 0 Tier0 | 1 Tier1 | 2 Tier2` — the tier-map edit's vocabulary
//! (task A16, docs/51 §5.10; the `auth` of a `ChangePolicy` carries the
//! requester and the approvers, every AP-REQ bound to the request's digest
//! like any other operation's). Kind `0x13` (the join token of docs/51 §7.3, task A12) is unused. Reply
//! `0x87` is admin.sock's `PasswordChanged`, never dird's. Request body
//! ≤ 256 KiB, reply body ≤ 64 KiB ([`channel`]).
//!
//! # Security
//!
//! `#![forbid(unsafe_code)]`; no `unwrap`, `expect` or `panic!` outside
//! tests and const evaluation. Every bound is a named constant; nothing is
//! allocated from a peer-supplied length beyond its bound. No error and no
//! `Debug` output carries frame octets or AP-REQ octets (docs/50 §8.2).
//!
//! # Provenance
//!
//! Written only from this project's decided design, opened in-session:
//! docs/CLEAN-ROOM.md, docs/CLEAN-ROOM.md, docs/51 (§5, §7, §9, §12), docs/50 (§2.4,
//! §3.1-§3.7, §7.5, §8, §9, the channel-magic registry), docs/10 (§2, §5b,
//! §7a), docs/questions Q-230, Q-270, Q-290, Q-292, Q-340, Q-341, Q-350,
//! Q-351, Q-355..Q-358 and PENDING-OWNER (A-26, A-55, A-56, A-59, A-63,
//! A-64, A-70, A-72, A-73, A-85, A-87, A-89); the public API of this
//! project's crates ipc, dtyp, keyd-types, krb-proto, ipc-keyd (and
//! ipc-directory / ipc-ldap as the pattern); and the docs.rs API pages of
//! rustix 1.1.6 and zeroize 1.9.1 (P-2). No other implementation,
//! management plane, serializer or RPC framework was consulted or recalled
//! (docs/CLEAN-ROOM.md). The operation digest (R2) is written from RFC 4120 §4,
//! §5.5.1, §7.5.1 (pinned copy, SHA-256 verified), docs/52 §3.2, §5 and
//! docs/questions/Q-463 (A-102), calling the approved `sha2` through the
//! one-shot `Digest::digest` this project's crates already use.
//!
//! Spec: docs/51 §7.1-§7.5, R51-15; docs/50 R50-3, R50-4, R50-7, §3, §7.5;
//! A-59; A-63; A-70; A-72; A-73.

pub mod channel;
pub mod client;
pub mod digest;
pub mod plan;
pub mod server;
pub mod typed;
#[cfg(unix)]
mod unix;
pub mod wire;

pub use channel::{
    RefusalStatus, ADMIN_CHANNEL, ADMIN_MAGIC, ADMIN_VERSION, MAX_REPLY_BODY, MAX_REQUEST_BODY,
    REPLY_LIMIT, REQUEST_LIMIT,
};
pub use client::{
    answers, AdminClient, ClientConfigError, Connection, Connector, TransportError, Unserved,
    DEFAULT_DEADLINE,
};
pub use digest::{operation_digest, wire_operation_digest, DigestError, OPERATION_DIGEST_LABEL};
pub use plan::{
    plan_digest, Effect, EffectPlan, PlanError, PlanPrincipal, PlanPrincipalKind, PlanTier,
    PolicyReferenceKind, RevocationKind, PLAN_DIGEST_LABEL, PLAN_LAYOUT,
};
pub use server::{decode_request, encode_refusal, encode_reply, EncodeError, Rejection};
pub use typed::{
    AccountExpires, AccountKind, Auth, ConversionError, Fact, FactTier, Found, KeyOperation,
    KeyRef, KeyTarget, ListScope, LookupKey, Operation, PasswordSet, PasswordSetOutcome,
    PendingRequestState, PolicyChange, PolicyTier, Reply, Request, RequestShown, RequestState,
    RequestSummary, ACCOUNT_EXPIRES_NEVER,
};
#[cfg(unix)]
pub use unix::{UnixConnection, UnixConnector};
pub use wire::{
    AdminReply, AdminRequest, WireAuth, WireFact, WireKeyOperation, WireKeyRef, WireKeyTarget,
    WireLookupKey, WireOperation, WirePendingRequest, WirePolicyChange, WireRequestShown,
    WireRequestSummary,
};
