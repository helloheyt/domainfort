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

/// Request body bound: 80 KiB. Every byte or DER field of a keyd request is
/// part of one KDC request (at most `kdc::MAX_REQUEST_LEN` = 64 KiB) or a
/// small structure the KDC builds (a KRB-ERROR, PA-DATA).
/// Spec: docs/50 §3.3 ("keyd request ≤ 80 KiB"; "⚠ to be estimated" — see
/// docs/questions/Q-245 item 6 for the armored TGS case).
pub const MAX_REQUEST_BODY: u32 = 80 * 1024;

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
/// refuses what keyd itself must judge (keyd's allowlist, docs/10 §5א).
/// Spec: docs/50 §3.4 (`padata: seq<DER>`); docs/10 §5א.
pub const MAX_SEAL_PADATA: u32 = 32;

/// Bound of the enctype list of `describe_config`: the four encryption types
/// krb-crypto implements (keyd refuses a list with a duplicate).
/// Spec: docs/10 §1 (EncType list); docs/50 §3.4 (`DescribeConfig`).
pub const MAX_ENCTYPES: u32 = 4;

// The bounds agree with the values they are derived from; checked at compile
// time, never at run time.
const _: () = assert!(MAX_REQUEST_FIELD as usize == kdc::MAX_REQUEST_LEN);
const _: () = assert!(MAX_REPLY_FIELD as usize == krb_proto::limits::MAX_MESSAGE_LEN);
const _: () = assert!(MAX_SEAL_PADATA as usize == krb_proto::limits::MAX_PADATA);
const _: () = assert!(MAX_REQUEST_FIELD < MAX_REQUEST_BODY);
const _: () = assert!(MAX_REPLY_FIELD < MAX_REPLY_BODY);

// ---- kinds -----------------------------------------------------------------

/// Request kinds: one per keyd operation that crosses the process boundary
/// (docs/50 §3.4). Values are a project choice.
/// Spec: docs/50 §3.3 ("`kind` closed"), §3.4.
pub mod request_kind {
    /// `verify_preauth` (Kdc). Spec: docs/10 §4.
    pub const VERIFY_PREAUTH: u8 = 0x01;
    /// `issue_as_rep` (Kdc). Spec: docs/10 §4.
    pub const ISSUE_AS_REP: u8 = 0x02;
    /// `open_fast_armor` (Kdc). Spec: docs/10 §5א.
    pub const OPEN_FAST_ARMOR: u8 = 0x03;
    /// `open_and_verify_tgt` (Kdc). Spec: docs/10 §5.
    pub const OPEN_AND_VERIFY_TGT: u8 = 0x04;
    /// `issue_tgs_rep` (Kdc). Spec: docs/10 §5.
    pub const ISSUE_TGS_REP: u8 = 0x05;
    /// `seal_fast_error` (Kdc). Spec: docs/10 §5א.
    pub const SEAL_FAST_ERROR: u8 = 0x06;
    /// `open_and_verify_service_ticket` (Ldap). Spec: docs/10 §5ב.
    pub const OPEN_AND_VERIFY_SERVICE_TICKET: u8 = 0x07;
    /// `set_secret` (Directory). Spec: docs/10 §6.
    pub const SET_SECRET: u8 = 0x08;
    /// `verify_secret` (Directory). Spec: docs/10 §6.
    pub const VERIFY_SECRET: u8 = 0x09;
    /// `create_key` (Admin). Spec: docs/10 §7.
    pub const CREATE_KEY: u8 = 0x0A;
    /// `rotate_key` (Admin). Spec: docs/10 §7.
    pub const ROTATE_KEY: u8 = 0x0B;
    /// `rotate_krbtgt` (Admin). Spec: docs/10 §7.
    pub const ROTATE_KRBTGT: u8 = 0x0C;
    /// `retire_kvno` (Admin). Spec: docs/10 §7.
    pub const RETIRE_KVNO: u8 = 0x0D;
    /// `destroy_key_set` (Admin). Spec: docs/10 §7.
    pub const DESTROY_KEY_SET: u8 = 0x0E;
    /// `describe_config` (Kdc, Ldap). Spec: docs/10 §7א.
    pub const DESCRIBE_CONFIG: u8 = 0x0F;
    /// `ping` (every role). Spec: docs/10 §7א.
    pub const PING: u8 = 0x10;

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
    /// `FastArmor`. Spec: docs/10 §5א.
    pub const OPEN_FAST_ARMOR: u8 = ok(rq::OPEN_FAST_ARMOR);
    /// `TgtContext`. Spec: docs/10 §5.
    pub const OPEN_AND_VERIFY_TGT: u8 = ok(rq::OPEN_AND_VERIFY_TGT);
    /// `TgsRepParts`. Spec: docs/10 §5.
    pub const ISSUE_TGS_REP: u8 = ok(rq::ISSUE_TGS_REP);
    /// The sealed `EncryptedData`. Spec: docs/10 §5א.
    pub const SEAL_FAST_ERROR: u8 = ok(rq::SEAL_FAST_ERROR);
    /// `ServiceContext`. Spec: docs/10 §5ב.
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
    /// `ConfigDescription`. Spec: docs/10 §7א.
    pub const DESCRIBE_CONFIG: u8 = ok(rq::DESCRIBE_CONFIG);
    /// `()`. Spec: docs/10 §7א.
    pub const PING: u8 = ok(rq::PING);
    /// A refusal of an authentication step: `keyd::AuthnError`.
    /// Spec: docs/10 §9; A-26; A-56.
    pub const AUTHN_FAILURE: u8 = 0xF1;
    /// A refusal of an issuance step: `keyd::IssueError`.
    /// Spec: docs/10 §9; A-56.
    pub const ISSUE_FAILURE: u8 = 0xF2;
    /// A refusal of any other operation: `keyd::Error`.
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
