//! The keyd channel's fixed identity: magic, version, the per-direction body
//! bounds, the per-field bounds, and the closed kind tables.
//!
//! Spec: docs/50 §3.3 ("`magic` per channel" — a project choice; "exact
//! version, no negotiation"; "a bound per channel and per direction"; the
//! proposed bounds "keyd request ≤ 80 KiB … reply ≤ 320 KiB"), §3.4 (one
//! request kind and one reply kind per operation); A-59 (`REFUSED_KIND`
//! reserved on every channel).

use ipc::{Channel, FrameLimit};

/// The keyd channel's magic: the ASCII octets "KD". Project choice — any
/// value distinct from the other channels' (docs/50 §3.3: "a different
/// constant for each channel").
/// Spec: docs/50 §3.3.
pub const KEYD_MAGIC: u16 = 0x4B44;

/// The one version of the keyd channel this build speaks. A peer with any
/// other version is refused (`Refused::VersionMismatch`), never negotiated.
/// Spec: docs/50 §3.3 ("exact version … no negotiation and no fallback"),
/// §12; D57.
pub const KEYD_VERSION: u8 = 1;

/// Request body bound: 80 KiB for the KDC-request part of a request, plus
/// room for the two attested name resolutions an `issue_as_rep` can carry
/// (task PN11) — 149 KiB in all (derived below: [`MAX_KDC_PART_BODY`] +
/// 2 × [`LARGEST_RESOLUTION`] + one octet, rounded up to whole KiB; checked
/// at compile time). Every byte or DER field of a keyd request is part of
/// one KDC request (at most `kdc::MAX_REQUEST_LEN` = 64 KiB) or a small
/// structure the KDC builds (a KRB-ERROR, PA-DATA) — except a resolution's
/// canonical names, which come from dird's store, not from the request, so
/// the 80 KiB of docs/50 §3.3 no longer bound them.
///
/// Task PN11b re-derived it from task PN11b's layout (docs/questions/
/// Q-1081): the largest request is still an armored change-password
/// `issue_as_rep` — its KDC part, the client's resolution, the server's
/// variant octet and the service's resolution (the octet replaces PN11's
/// option marker; the two handles and the template's client principal that
/// left the request only shrink the KDC part) — so the bound is unchanged;
/// a TGT's request (one resolution, the octet, a 17-octet handle) and
/// `issue_tgs_rep` (one resolution, no handle) are smaller.
/// Spec: docs/50 §3.3 ("keyd request ≤ 80 KiB"; "⚠ to be estimated" — see
/// docs/questions/Q-245 item 6 for the armored TGS case); docs/59 §7.5
/// ("size bounds"); docs/questions/Q-1062 (the bound as built), Q-1081.
pub const MAX_REQUEST_BODY: u32 = 149 * 1024;

/// The KDC-request part of a request body: docs/50 §3.3's 80 KiB (every
/// field a substring of one KDC request or a small structure the KDC
/// builds). Spec: docs/50 §3.3.
pub const MAX_KDC_PART_BODY: u32 = 80 * 1024;

/// Reply body bound: 320 KiB (krb-proto bounds every encoding at 256 KiB).
/// Spec: docs/50 §3.3 ("reply ≤ 320 KiB").
pub const MAX_REPLY_BODY: u32 = 320 * 1024;

/// The request direction's [`FrameLimit`]. A bound outside ipc's range would
/// stop the build here (const evaluation), never at run time.
/// Spec: docs/50 §3.3; A-59 (`FrameLimit` range).
pub const REQUEST_LIMIT: FrameLimit = match FrameLimit::new(MAX_REQUEST_BODY) {
    Some(limit) => limit,
    None => panic!("MAX_REQUEST_BODY is outside the ipc FrameLimit range"),
};

/// The reply direction's [`FrameLimit`].
/// Spec: docs/50 §3.3; A-59.
pub const REPLY_LIMIT: FrameLimit = match FrameLimit::new(MAX_REPLY_BODY) {
    Some(limit) => limit,
    None => panic!("MAX_REPLY_BODY is outside the ipc FrameLimit range"),
};

/// The keyd channel (`keyd.sock`, docs/50 §3.1).
/// Spec: docs/50 §3.3, §3.4.
pub const KEYD_CHANNEL: Channel =
    Channel::new(KEYD_MAGIC, KEYD_VERSION, REQUEST_LIMIT, REPLY_LIMIT);

// ---- field bounds ----------------------------------------------------------

/// Bound of every byte-string and DER field of a request: 64 KiB, the KDC's
/// own request bound (`kdc::MAX_REQUEST_LEN`), of which each such field is a
/// part.
/// Spec: docs/50 §3.3 (bound rationale: "every keyd request field is a
/// substring of one KDC request ≤ `MAX_REQUEST_LEN`").
pub const MAX_REQUEST_FIELD: u32 = 64 * 1024;

/// Bound of every byte-string and DER field of a reply: 256 KiB, krb-proto's
/// bound on any one encoding (`krb_proto::limits::MAX_MESSAGE_LEN`).
/// Spec: docs/50 §3.3 ("krb-proto bounds encodings at 256 KiB").
pub const MAX_REPLY_FIELD: u32 = 256 * 1024;

/// Bound of a password (`set_secret`) or a candidate (`verify_secret`).
/// Spec: docs/50 §3.4 (`password: secret bytes<1024>`, `candidate: secret
/// bytes<1024>`).
pub const MAX_SECRET: u32 = 1024;

/// Bound of the salt of `set_secret`. docs/50 §3.4 names the field without a
/// bound; project choice, equal to the password bound (docs/questions/Q-245
/// item 7).
/// Spec: docs/50 §3.4 (`salt: bytes`).
pub const MAX_SALT: u32 = 1024;

/// Bound of the PA-DATA sequence of `seal_fast_error`: krb-proto's own bound
/// on a padata sequence (`krb_proto::limits::MAX_PADATA`), so the codec never
/// refuses what keyd itself must judge (keyd's allowlist, docs/10 §5a).
/// Spec: docs/50 §3.4 (`padata: seq<DER>`); docs/10 §5a.
pub const MAX_SEAL_PADATA: u32 = 32;

/// Bound of the enctype list of `describe_config`: the four encryption types
/// krb-crypto implements (keyd refuses a list with a duplicate).
/// Spec: docs/10 §1 (EncType list); docs/50 §3.4 (`DescribeConfig`).
pub const MAX_ENCTYPES: u32 = 4;

/// Bound of the key-target list of `grant_set_secret`: keyd-types'
/// `MAX_GRANT_TARGETS` (a computer's two key sets). The codec refuses a
/// longer list; keyd judges the shape of a shorter one (and records why it
/// refuses it), as the dird-admin codec leaves semantic checks to its PEP
/// (docs/questions/Q-389 item 3).
/// Spec: docs/51 §5.2 row 5, §7.3; docs/questions/Q-450 item 9.
pub const MAX_GRANT_TARGETS: u32 = 2;

/// Bound of the approvers of `register_decision`: keyd-types'
/// `MAX_DECISION_APPROVERS` (the requester and at most two approvals). The
/// codec refuses a longer list; keyd judges distinctness and the minimum.
/// Spec: docs/52 §4.2 (A-102); docs/51 §7.2.
pub const MAX_DECISION_APPROVERS: u32 = 3;

/// Bound of the entries of one `list_destroy_decisions` page: keyd-types'
/// `MAX_DESTROY_DECISION_PAGE`.
/// Spec: docs/52 §4.6 (A-102); docs/50 §3.3 (bounded replies).
pub const MAX_DESTROY_PAGE: u32 = 64;

/// The exact length of the attestation key on the wire (`install_attestation_key`,
/// task PN9): 32 octets — crate name-attestation's `ATTESTATION_KEY_LEN`
/// (the SHA-256 output size L, FIPS 180-4 §1, as name-attestation records).
/// This crate links no crypto code (D182; A-63, A-173), so the value is
/// restated here and pinned against name-attestation's at compile time in
/// crate ipc-keyd-server, which links both (a different value does not
/// build there). Every other length is refused: fewer octets `Truncated`,
/// more `LengthOverBound` — both `Malformed`.
/// Spec: docs/59 §7.4; docs/questions/Q-1011 item 2 (A-173), Q-1033
/// (A-177); docs/50 §3.3 (bounded fields).
pub const ATTESTATION_KEY_OCTETS: usize = 32;

/// [`ATTESTATION_KEY_OCTETS`] as the `u32` field bound of the ipc layer.
/// Spec: docs/50 §3.3 (`bytes<max>` = `u32` length ≤ max + octets).
pub const ATTESTATION_KEY_FIELD: u32 = ATTESTATION_KEY_OCTETS as u32;

/// The bounds of an attested name resolution on this channel (task PN11):
/// a realm (`MAX_RESOLUTION_REALM`), a `PrincipalName` DER
/// (`MAX_RESOLUTION_NAME`) and the whole resolution's body
/// (`LARGEST_RESOLUTION`) — defined once in crate keyd-types beside the
/// bounds of `NameResolution` they are derived from, and used by this
/// channel and the dird-kdc channel (crate ipc-directory, task PN10) alike:
/// one resolution, one bound on both of its channels (A-190 on
/// docs/questions/Q-1062 item 1).
/// Spec: docs/59 §7.1, §7.5 ("size bounds"); crates/keyd-types
/// `name_resolution.rs`; docs/CLEAN-ROOM.md.
pub use keyd_types::{LARGEST_RESOLUTION, MAX_RESOLUTION_NAME, MAX_RESOLUTION_REALM};

// The bounds agree with the values they are derived from; checked at compile
// time, never at run time. Task K3 (docs/questions/Q-620 item 4): the bound
// of a password on this channel is the bound of RFC 3244's `newpasswd`, so a
// kpasswd password and a `set_secret` password share one limit.
const _: () = assert!(krb_proto::limits::MAX_NEWPASSWD_LEN == MAX_SECRET as usize);
const _: () = assert!(MAX_REQUEST_FIELD as usize == kdc::MAX_REQUEST_LEN);
const _: () = assert!(MAX_REPLY_FIELD as usize == krb_proto::limits::MAX_MESSAGE_LEN);
const _: () = assert!(MAX_SEAL_PADATA as usize == krb_proto::limits::MAX_PADATA);
const _: () = assert!(MAX_GRANT_TARGETS as usize == keyd_types::MAX_GRANT_TARGETS);
const _: () = assert!(MAX_DECISION_APPROVERS as usize == keyd_types::MAX_DECISION_APPROVERS);
const _: () = assert!(MAX_DESTROY_PAGE as usize == keyd_types::MAX_DESTROY_DECISION_PAGE);
const _: () = assert!(MAX_REQUEST_FIELD < MAX_REQUEST_BODY);
const _: () = assert!(MAX_REPLY_FIELD < MAX_REPLY_BODY);
const _: () = assert!(ATTESTATION_KEY_FIELD as usize == ATTESTATION_KEY_OCTETS);
const _: () = assert!(ATTESTATION_KEY_FIELD < MAX_REQUEST_FIELD);
// Task PN11: a resolution's realm bound is keyd-types' (the derivation and
// its own compile-time checks are keyd-types', A-190); the request body
// holds the KDC-request part and two resolutions (the AS client's and the
// change-password service's) with one octet — since task PN11b the server's
// variant code (Q-1081).
const _: () = assert!(MAX_RESOLUTION_REALM as usize == keyd_types::sealed_store::MAX_NAME_OCTETS);
const _: () = assert!(MAX_RESOLUTION_NAME < MAX_REQUEST_FIELD);
// (`<` here: the KDC part, two resolutions and the server's one variant octet.)
const _: () =
    assert!(MAX_KDC_PART_BODY as usize + 2 * LARGEST_RESOLUTION < MAX_REQUEST_BODY as usize);
const _: () = assert!(
    (MAX_REQUEST_BODY as usize) < MAX_KDC_PART_BODY as usize + 2 * LARGEST_RESOLUTION + 1 + 1024
);

// ---- kinds -----------------------------------------------------------------

/// Request kinds: one per keyd operation that crosses the process boundary
/// (docs/50 §3.4). Values are a project choice.
/// Spec: docs/50 §3.3 ("`kind` closed"), §3.4.
pub mod request_kind {
    /// `verify_preauth` (Kdc). Spec: docs/10 §4.
    pub const VERIFY_PREAUTH: u8 = 0x01;
    /// `issue_as_rep` (Kdc). Spec: docs/10 §4.
    pub const ISSUE_AS_REP: u8 = 0x02;
    /// `open_fast_armor` (Kdc). Spec: docs/10 §5a.
    pub const OPEN_FAST_ARMOR: u8 = 0x03;
    /// `open_and_verify_tgt` (Kdc). Spec: docs/10 §5.
    pub const OPEN_AND_VERIFY_TGT: u8 = 0x04;
    /// `issue_tgs_rep` (Kdc). Spec: docs/10 §5.
    pub const ISSUE_TGS_REP: u8 = 0x05;
    /// `seal_fast_error` (Kdc). Spec: docs/10 §5a.
    pub const SEAL_FAST_ERROR: u8 = 0x06;
    /// `open_and_verify_service_ticket` (Ldap) — the unbound verification
    /// only since Q-523. Spec: docs/10 §5b.
    pub const OPEN_AND_VERIFY_SERVICE_TICKET: u8 = 0x07;
    /// `set_secret` (Directory). Spec: docs/10 §6.
    pub const SET_SECRET: u8 = 0x08;
    /// `verify_secret` — **no role** holds it since A-102 (docs/52 R4); the
    /// kind stays so that keyd records a refused call. Spec: docs/10 §6.
    pub const VERIFY_SECRET: u8 = 0x09;
    /// `create_key` (Admin). Spec: docs/10 §7.
    pub const CREATE_KEY: u8 = 0x0A;
    /// `rotate_key(decision)` (Admin). Spec: docs/10 §7; docs/52 §4.6.
    pub const ROTATE_KEY: u8 = 0x0B;
    /// `rotate_krbtgt(decision)` (Admin). Spec: docs/10 §7; docs/52 §4.6.
    pub const ROTATE_KRBTGT: u8 = 0x0C;
    /// `retire_kvno(decision)` (Admin). Spec: docs/10 §7; docs/52 §4.6.
    pub const RETIRE_KVNO: u8 = 0x0D;
    /// `destroy_key_set(decision)` (Admin). Spec: docs/10 §7; docs/52 §4.6.
    pub const DESTROY_KEY_SET: u8 = 0x0E;
    /// `describe_config` (Kdc, Ldap). Spec: docs/10 §7a.
    pub const DESCRIBE_CONFIG: u8 = 0x0F;
    /// `ping` (every role). Spec: docs/10 §7a.
    pub const PING: u8 = 0x10;
    /// `grant_set_secret` (Admin, provisioning only since A-102). Appended
    /// by task A15a.
    /// Spec: docs/51 §5.8 option (b); docs/questions/Q-450 item 9.
    pub const GRANT_SET_SECRET: u8 = 0x11;
    /// `register_decision` (Ldap). Appended by A-102.
    /// Spec: docs/52 §4.2, §4.6.
    pub const REGISTER_DECISION: u8 = 0x12;
    /// `seal_ceremony` (Admin). Appended by A-102.
    /// Spec: docs/52 §4.4, §4.6.
    pub const SEAL_CEREMONY: u8 = 0x13;
    /// `list_destroy_decisions` (Admin). Appended by A-102.
    /// Spec: docs/52 §4.3, §4.6.
    pub const LIST_DESTROY_DECISIONS: u8 = 0x14;
    /// `verify_operation_ticket` (Ldap): the operation-bound service-ticket
    /// verification, which keeps no service context. Appended by Q-523.
    /// Spec: docs/10 §5b; docs/52 §3.4, §5; docs/questions/Q-523.
    pub const VERIFY_OPERATION_TICKET: u8 = 0x15;
    /// `open_change_password_request` (Ldap): an RFC 3244 request's AP-REQ
    /// and KRB-PRIV, opened and judged inside keyd. Appended by task K4.
    /// Spec: docs/53 §5.5; docs/10 §5c; RFC 3244 §2.
    pub const OPEN_CHANGE_PASSWORD_REQUEST: u8 = 0x16;
    /// `complete_change_password` (Ldap): install the context's password on
    /// dird's decision and seal the success reply — a state call. Appended
    /// by task K4.
    /// Spec: docs/53 §5.5; docs/10 §5c; docs/52 §3.10 (c) (R9).
    pub const COMPLETE_CHANGE_PASSWORD: u8 = 0x17;
    /// `seal_change_password_error` (Ldap): seal a non-zero result code.
    /// Appended by task K4.
    /// Spec: docs/53 §5.5, §5.7; docs/10 §5c.
    pub const SEAL_CHANGE_PASSWORD_ERROR: u8 = 0x18;
    /// `revoke_decision(id)` (Ldap): take back a key-operation decision dird
    /// registered. Appended by task F3.
    /// Spec: docs/52 §4.2, §4.6; docs/questions/Q-937 item 6, Q-976.
    pub const REVOKE_DECISION: u8 = 0x19;
    /// `install_attestation_key(key)` (Admin, provisioning only): hand keyd
    /// the attestation key of dird's name resolutions — a state call.
    /// Appended by task PN9.
    /// Spec: docs/59 §7.4, §7.5; docs/questions/Q-1011 items 2, 8, Q-1033.
    pub const INSTALL_ATTESTATION_KEY: u8 = 0x1A;

    /// The closed request table. Spec: docs/50 §3.3, §3.4.
    pub const ALL: &[u8] = &[
        VERIFY_PREAUTH,
        ISSUE_AS_REP,
        OPEN_FAST_ARMOR,
        OPEN_AND_VERIFY_TGT,
        ISSUE_TGS_REP,
        SEAL_FAST_ERROR,
        OPEN_AND_VERIFY_SERVICE_TICKET,
        SET_SECRET,
        VERIFY_SECRET,
        CREATE_KEY,
        ROTATE_KEY,
        ROTATE_KRBTGT,
        RETIRE_KVNO,
        DESTROY_KEY_SET,
        DESCRIBE_CONFIG,
        PING,
        GRANT_SET_SECRET,
        REGISTER_DECISION,
        SEAL_CEREMONY,
        LIST_DESTROY_DECISIONS,
        VERIFY_OPERATION_TICKET,
        OPEN_CHANGE_PASSWORD_REQUEST,
        COMPLETE_CHANGE_PASSWORD,
        SEAL_CHANGE_PASSWORD_ERROR,
        REVOKE_DECISION,
        INSTALL_ATTESTATION_KEY,
    ];
}

/// Reply kinds: the success reply of each operation is its request kind with
/// the top bit set; the three failure replies carry keyd's three error types.
/// Values are a project choice; [`ipc::REFUSED_KIND`] (`0xFF`) is reserved
/// for the shared transport refusal (A-59).
/// Spec: docs/50 §3.3 (errors row), §3.4 ("each row = a request `kind` + a
/// reply `kind`"); A-59.
pub mod reply_kind {
    use super::request_kind as rq;

    /// Success reply of an operation: its request kind with the top bit set.
    const fn ok(request: u8) -> u8 {
        0x80 | request
    }

    /// `AuthnProof`. Spec: docs/10 §4.
    pub const VERIFY_PREAUTH: u8 = ok(rq::VERIFY_PREAUTH);
    /// `AsRepParts`. Spec: docs/10 §4.
    pub const ISSUE_AS_REP: u8 = ok(rq::ISSUE_AS_REP);
    /// `FastArmor`. Spec: docs/10 §5a.
    pub const OPEN_FAST_ARMOR: u8 = ok(rq::OPEN_FAST_ARMOR);
    /// `TgtContext`. Spec: docs/10 §5.
    pub const OPEN_AND_VERIFY_TGT: u8 = ok(rq::OPEN_AND_VERIFY_TGT);
    /// `TgsRepParts`. Spec: docs/10 §5.
    pub const ISSUE_TGS_REP: u8 = ok(rq::ISSUE_TGS_REP);
    /// The sealed `EncryptedData`. Spec: docs/10 §5a.
    pub const SEAL_FAST_ERROR: u8 = ok(rq::SEAL_FAST_ERROR);
    /// `ServiceContext` (with its one-time context id). Spec: docs/10 §5b.
    pub const OPEN_AND_VERIFY_SERVICE_TICKET: u8 = ok(rq::OPEN_AND_VERIFY_SERVICE_TICKET);
    /// The installed `Kvno`. Spec: docs/10 §6.
    pub const SET_SECRET: u8 = ok(rq::SET_SECRET);
    /// `()`. Spec: docs/10 §6.
    pub const VERIFY_SECRET: u8 = ok(rq::VERIFY_SECRET);
    /// The new `Kvno`. Spec: docs/10 §7.
    pub const CREATE_KEY: u8 = ok(rq::CREATE_KEY);
    /// The new `Kvno`. Spec: docs/10 §7.
    pub const ROTATE_KEY: u8 = ok(rq::ROTATE_KEY);
    /// The new `Kvno`. Spec: docs/10 §7.
    pub const ROTATE_KRBTGT: u8 = ok(rq::ROTATE_KRBTGT);
    /// `()`. Spec: docs/10 §7.
    pub const RETIRE_KVNO: u8 = ok(rq::RETIRE_KVNO);
    /// `()`. Spec: docs/10 §7.
    pub const DESTROY_KEY_SET: u8 = ok(rq::DESTROY_KEY_SET);
    /// `ConfigDescription`. Spec: docs/10 §7a.
    pub const DESCRIBE_CONFIG: u8 = ok(rq::DESCRIBE_CONFIG);
    /// `()`. Spec: docs/10 §7a.
    pub const PING: u8 = ok(rq::PING);
    /// `()`: the grant is registered. Spec: docs/51 §5.8 option (b);
    /// docs/questions/Q-450 item 9.
    pub const GRANT_SET_SECRET: u8 = ok(rq::GRANT_SET_SECRET);
    /// `()`: the decision is registered. Spec: docs/52 §4.2.
    pub const REGISTER_DECISION: u8 = ok(rq::REGISTER_DECISION);
    /// `()`: the ceremony is sealed. Spec: docs/52 §4.4.
    pub const SEAL_CEREMONY: u8 = ok(rq::SEAL_CEREMONY);
    /// One page of pending destroy decisions. Spec: docs/52 §4.6.
    pub const LIST_DESTROY_DECISIONS: u8 = ok(rq::LIST_DESTROY_DECISIONS);
    /// `OperationTicket` (no context id). Spec: docs/10 §5b;
    /// docs/questions/Q-523.
    pub const VERIFY_OPERATION_TICKET: u8 = ok(rq::VERIFY_OPERATION_TICKET);
    /// `ChangePasswordContext` (a request-context id and a verdict).
    /// Spec: docs/53 §5.5; docs/10 §5c.
    pub const OPEN_CHANGE_PASSWORD_REQUEST: u8 = ok(rq::OPEN_CHANGE_PASSWORD_REQUEST);
    /// `SealedReply` (the success reply). Spec: docs/53 §5.5.
    pub const COMPLETE_CHANGE_PASSWORD: u8 = ok(rq::COMPLETE_CHANGE_PASSWORD);
    /// `SealedReply` (an error reply). Spec: docs/53 §5.5.
    pub const SEAL_CHANGE_PASSWORD_ERROR: u8 = ok(rq::SEAL_CHANGE_PASSWORD_ERROR);
    /// `()`: the decision is revoked (task F3). Spec: docs/52 §4.2;
    /// docs/questions/Q-976.
    pub const REVOKE_DECISION: u8 = ok(rq::REVOKE_DECISION);
    /// `()`: the attestation key is installed (task PN9). Spec: docs/59
    /// §7.4, §7.5.
    pub const INSTALL_ATTESTATION_KEY: u8 = ok(rq::INSTALL_ATTESTATION_KEY);
    /// A refusal of an authentication step: `keyd_types::AuthnError`.
    /// Spec: docs/10 §9; A-26; A-56.
    pub const AUTHN_FAILURE: u8 = 0xF1;
    /// A refusal of an issuance step: `keyd_types::IssueError`.
    /// Spec: docs/10 §9; A-56.
    pub const ISSUE_FAILURE: u8 = 0xF2;
    /// A refusal of any other operation: `keyd_types::Error`.
    /// Spec: docs/10 §9.
    pub const FAILURE: u8 = 0xF3;

    /// The closed reply table (without the reserved `REFUSED_KIND`).
    /// Spec: docs/50 §3.3, §3.4; A-59.
    pub const ALL: &[u8] = &[
        VERIFY_PREAUTH,
        ISSUE_AS_REP,
        OPEN_FAST_ARMOR,
        OPEN_AND_VERIFY_TGT,
        ISSUE_TGS_REP,
        SEAL_FAST_ERROR,
        OPEN_AND_VERIFY_SERVICE_TICKET,
        SET_SECRET,
        VERIFY_SECRET,
        CREATE_KEY,
        ROTATE_KEY,
        ROTATE_KRBTGT,
        RETIRE_KVNO,
        DESTROY_KEY_SET,
        DESCRIBE_CONFIG,
        PING,
        GRANT_SET_SECRET,
        REGISTER_DECISION,
        SEAL_CEREMONY,
        LIST_DESTROY_DECISIONS,
        VERIFY_OPERATION_TICKET,
        OPEN_CHANGE_PASSWORD_REQUEST,
        COMPLETE_CHANGE_PASSWORD,
        SEAL_CHANGE_PASSWORD_ERROR,
        REVOKE_DECISION,
        INSTALL_ATTESTATION_KEY,
        AUTHN_FAILURE,
        ISSUE_FAILURE,
        FAILURE,
    ];
}

/// Whether `kinds` lists no value twice (a closed table maps each kind to one
/// message). Compile-time helper.
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
// Evaluated at compile time: a table that breaks either rule does not build.
const _: () = assert!(ipc::kinds_exclude_refused(request_kind::ALL));
const _: () = assert!(ipc::kinds_exclude_refused(reply_kind::ALL));
const _: () = assert!(all_distinct(request_kind::ALL));
const _: () = assert!(all_distinct(reply_kind::ALL));
