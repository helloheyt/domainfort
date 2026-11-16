//! The directory-view channel's fixed identity: magic, version, the
//! per-direction body bounds, the per-field bounds, the closed kind tables
//! and the closed code tables of its enumerations.
//!
//! Spec: docs/50 §3.3 ("`magic` per channel" — a project choice registered
//! in docs/50's channel-magic registry, A-64; "exact version, no
//! negotiation"; "a bound per channel and per direction"; "enum = `u8` from a
//! closed table"), §3.4 (the dird-kdc rows); A-59 (`REFUSED_KIND` reserved on
//! every channel).

use ipc::{Channel, FrameLimit};
use kdc::{AccountKind, AccountSourceError, ArmorPolicy};
use keyd_types::KeyPurpose;
use pdp::{PipError, Tier};

/// The directory-view channel's magic: the ASCII octets "DR". Project choice
/// — distinct from every other channel's (docs/50 §3.3: "a different
/// constant for each channel"); registered in docs/50's channel-magic
/// registry (A-64).
/// Spec: docs/50 §3.3; A-64.
pub const DIRECTORY_MAGIC: u16 = 0x4452;

/// The one version of the channel this build speaks; any other is refused
/// (`Refused::VersionMismatch`), never negotiated.
/// Spec: docs/50 §3.3 ("exact version … no negotiation and no fallback"),
/// §12; D57.
pub const DIRECTORY_VERSION: u8 = 1;

/// Request body bound: 80 KiB. docs/50 §3.3 proposes 16 KiB ("⚠ to be
/// estimated"); the estimate made here (docs/questions/Q-270 item 4): a
/// `Client` / `Service` request carries a realm and a name that are two
/// disjoint parts of one KDC request (at most `kdc::MAX_REQUEST_LEN` =
/// 64 KiB together), and a `TierOf` request carries up to
/// [`MAX_GROUPS`] SIDs (about 72 KiB) — both are checked below at compile
/// time.
/// Spec: docs/50 §3.3; Q-270 item 4.
pub const MAX_REQUEST_BODY: u32 = 80 * 1024;

/// Reply body bound: 128 KiB. docs/50 §3.3 proposes 64 KiB ("⚠ to be
/// estimated"); a client record with [`MAX_GROUPS`] group SIDs and
/// [`MAX_ENCTYPES`] ETYPE-INFO2 entries needs about 90 KiB, and its attested
/// name resolution (task PN10) at most about 35 KiB more — still within the
/// bound (checked below at compile time; docs/questions/Q-270 item 4,
/// Q-1046).
/// Spec: docs/50 §3.3; Q-270 item 4; docs/59 §7.5.
pub const MAX_REPLY_BODY: u32 = 128 * 1024;

/// The request direction's [`FrameLimit`]; a bound outside ipc's range stops
/// the build here (const evaluation), never at run time.
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

/// The directory-view channel (`dird-kdc.sock`, docs/50 §3.1).
/// Spec: docs/50 §3.3, §3.4.
pub const DIRECTORY_CHANNEL: Channel = Channel::new(
    DIRECTORY_MAGIC,
    DIRECTORY_VERSION,
    REQUEST_LIMIT,
    REPLY_LIMIT,
);

// ---- field bounds ----------------------------------------------------------

/// Bound of a realm (KerberosString octets) on the wire: the KDC's own
/// request bound, of which the realm is a part.
/// Spec: docs/50 §3.4 (`Client | realm, name: DER`); crates/kdc
/// `MAX_REQUEST_LEN`.
pub const MAX_REALM: u32 = 64 * 1024;

/// Bound of a `PrincipalName` DER on the wire: the KDC's own request bound.
/// Spec: docs/50 §3.4; crates/kdc `MAX_REQUEST_LEN`.
pub const MAX_NAME: u32 = 64 * 1024;

/// Bound of one SID packet: revision, count, authority and at most 15
/// sub-authorities = 8 + 4 × 15 octets.
/// Spec: [MS-DTYP] 2.4.2.2 ("maximum number of elements allowed is 15");
/// crates/dtyp `SID_MAX_SUB_AUTHORITIES`.
pub const MAX_SID: u32 = 8 + 4 * 15;

/// Most group SIDs in one record or one `TierOf` request: the bound of the
/// directory's group expansion (directory-pip `MAX_EXPANDED_GROUPS`; pinned
/// to it at compile time in crates/ipc-directory-server, which links both).
/// Spec: docs/47 §5.3 (R47-8: bounded closure); docs/50 §3.4.
pub const MAX_GROUPS: u32 = 1024;

/// Most encryption types of a record (and ETYPE-INFO2 entries of a client
/// record): the four AES types keyd's configuration may list (keyd-types
/// `EncTypeId`, closed table).
/// Spec: docs/47 §7.3 (R47-10: keyd's configured list); docs/10 §1.
pub const MAX_ENCTYPES: u32 = 4;

/// Bound of a salt (KerberosString octets). The [MS-KILE] 3.1.1.2 salt of a
/// directory account is the realm (a configuration value, at most 973
/// octets — crates/config) and the account name (sAMAccountName, at most 256
/// characters — ad-schema) put together, twice the realm for a computer;
/// 4096 octets leave room. Project choice.
/// Spec: docs/47 §3.3 (R47-4); [MS-KILE] 3.1.1.2; docs/questions/Q-270
/// item 4.
pub const MAX_SALT: u32 = 4096;

/// Bound of the s2kparams of an ETYPE-INFO2 entry: keyd's configuration
/// holds them as exactly four octets (keyd-types `KeydConfig::s2k_params:
/// Option<[u8; 4]>`).
/// Spec: docs/47 §7.3 (R47-10); RFC 3962 §4.
pub const MAX_S2KPARAMS: u32 = 4;

/// Most labels of the naming context in `DescribeDomain`
/// (directory-pip `MAX_NC_LABELS`).
/// Spec: A-53; crates/directory-pip naming.rs.
pub const MAX_NC_LABELS: u32 = 16;

/// Bound of one naming-context label: "dc=<label>" is under 255 characters
/// ([MS-ADTS] 3.1.1.5.1.2 as read in A-30), so a label is shorter still.
/// Spec: [MS-ADTS] 3.1.1.5.1.2; A-30; A-53.
pub const MAX_NC_LABEL: u32 = 255;

/// The bounds of an attested name resolution on this channel (task PN10):
/// a realm (`MAX_RESOLUTION_REALM`), a `PrincipalName` DER
/// (`MAX_RESOLUTION_NAME`) and the whole resolution's body
/// (`LARGEST_RESOLUTION`) — defined once in crate keyd-types beside the
/// bounds of `NameResolution` they are derived from, and used by this
/// channel and the keyd channel (crate ipc-keyd) alike: one resolution, one
/// bound on both of its channels (A-190 on docs/questions/Q-1062 item 1).
/// Spec: docs/59 §7.1, §7.5 ("size bounds"); crates/keyd-types
/// `name_resolution.rs`; AGENTS.md §6.
pub use keyd_types::{LARGEST_RESOLUTION, MAX_RESOLUTION_NAME, MAX_RESOLUTION_REALM};

// The bounds agree with the values they are derived from and fit the body
// bounds; checked at compile time, never at run time.
const _: () = assert!(MAX_REALM as usize == kdc::MAX_REQUEST_LEN);
const _: () = assert!(MAX_NAME as usize == kdc::MAX_REQUEST_LEN);
const _: () = assert!(MAX_SID as usize == 8 + 4 * dtyp::SID_MAX_SUB_AUTHORITIES);
// A resolution's realm bound is keyd-types' (task PN10; the derivation and
// its own compile-time checks are keyd-types', A-190).
const _: () = assert!(MAX_RESOLUTION_REALM as usize == keyd_types::sealed_store::MAX_NAME_OCTETS);

/// Body octets of the largest `Client` / `Service` request a KDC request can
/// produce: envelope, view id, two length prefixes, and the realm and name,
/// which share one KDC request (docs/questions/Q-270 item 4).
const LARGEST_NAME_REQUEST: usize = 4 + 8 + 4 + 4 + kdc::MAX_REQUEST_LEN;
/// Body octets of the largest `TierOf` request.
const LARGEST_TIER_REQUEST: usize =
    4 + 8 + (4 + MAX_SID as usize) + 4 + MAX_GROUPS as usize * (4 + MAX_SID as usize);
/// Body octets of one ETYPE-INFO2 entry at its bounds.
const LARGEST_ETYPE_ENTRY: usize =
    4 + (1 + 4 + MAX_SALT as usize) + (1 + 4 + MAX_S2KPARAMS as usize);
/// Body octets of the largest client record reply (no key handle of its
/// own since task PN10c — the resolution names the key set).
const LARGEST_CLIENT_REPLY: usize = 4
    + 1
    + (4 + MAX_SID as usize)
    + 4
    + MAX_GROUPS as usize * (4 + MAX_SID as usize)
    + 1
    + 2
    + 2 * (1 + 7)
    + 4
    + MAX_ENCTYPES as usize * LARGEST_ETYPE_ENTRY
    + 2
    + LARGEST_RESOLUTION;
/// Body octets of the largest service record reply (task PN10: it carries
/// a resolution too; task PN10c: and no key handle of its own).
const LARGEST_SERVICE_REPLY: usize =
    4 + 1 + 2 + 2 * (1 + 7) + 4 + 4 * MAX_ENCTYPES as usize + LARGEST_RESOLUTION;
/// Body octets of the largest group-expansion reply.
const LARGEST_GROUPS_REPLY: usize = 4 + 4 + MAX_GROUPS as usize * (4 + MAX_SID as usize);
const _: () = assert!(LARGEST_NAME_REQUEST <= MAX_REQUEST_BODY as usize);
const _: () = assert!(LARGEST_TIER_REQUEST <= MAX_REQUEST_BODY as usize);
const _: () = assert!(LARGEST_CLIENT_REPLY <= MAX_REPLY_BODY as usize);
const _: () = assert!(LARGEST_SERVICE_REPLY <= MAX_REPLY_BODY as usize);
const _: () = assert!(LARGEST_GROUPS_REPLY <= MAX_REPLY_BODY as usize);

// ---- kinds -----------------------------------------------------------------

/// Request kinds (docs/50 §3.4 rows, plus `Ping` — §7.5: "health check: op
/// `Ping` on every channel"). Values are a project choice.
/// Spec: docs/50 §3.3 ("`kind` closed"), §3.4, §7.5.
pub mod request_kind {
    /// `BeginView`: pin one snapshot to this connection. Spec: docs/50 §3.4.
    pub const BEGIN_VIEW: u8 = 0x01;
    /// `Client`: `AccountSource::client`. Spec: docs/50 §3.4.
    pub const CLIENT: u8 = 0x02;
    /// `Service`: `AccountSource::service`. Spec: docs/50 §3.4.
    pub const SERVICE: u8 = 0x03;
    /// `ExpandGroups`: `Pip::expand_groups`. Spec: docs/50 §3.4.
    pub const EXPAND_GROUPS: u8 = 0x04;
    /// `TierOf`: `Pip::tier_of`. Spec: docs/50 §3.4.
    pub const TIER_OF: u8 = 0x05;
    /// `EndView`: release the snapshot. Spec: docs/50 §3.4.
    pub const END_VIEW: u8 = 0x06;
    /// `DescribeDomain`: realm, naming context, krbtgt handle, policy
    /// version. Spec: docs/50 §3.4, §7.5.
    pub const DESCRIBE_DOMAIN: u8 = 0x07;
    /// `Ping`: health check. Spec: docs/50 §7.5.
    pub const PING: u8 = 0x08;

    /// The closed request table. Spec: docs/50 §3.3, §3.4.
    pub const ALL: &[u8] = &[
        BEGIN_VIEW,
        CLIENT,
        SERVICE,
        EXPAND_GROUPS,
        TIER_OF,
        END_VIEW,
        DESCRIBE_DOMAIN,
        PING,
    ];
}

/// Reply kinds: the success reply of each request is its kind with the top
/// bit set; three failure replies carry the view's own answers that are not
/// records (`AccountSourceError`, `PipError`) and the view protocol's
/// refusals. [`ipc::REFUSED_KIND`] (`0xFF`) is reserved for the shared
/// transport refusal (A-59). Values are a project choice.
/// Spec: docs/50 §3.3 (errors row), §3.4; A-59.
pub mod reply_kind {
    use super::request_kind as rq;

    /// Success reply of a request: its kind with the top bit set.
    const fn ok(request: u8) -> u8 {
        0x80 | request
    }

    /// `ViewBegun { view, policy_version }`. Spec: docs/50 §3.4.
    pub const VIEW_BEGUN: u8 = ok(rq::BEGIN_VIEW);
    /// `Option<ClientAccount>`. Spec: docs/50 §3.4.
    pub const CLIENT: u8 = ok(rq::CLIENT);
    /// `Option<ServiceAccount>`. Spec: docs/50 §3.4.
    pub const SERVICE: u8 = ok(rq::SERVICE);
    /// `seq<Sid>`. Spec: docs/50 §3.4.
    pub const GROUPS: u8 = ok(rq::EXPAND_GROUPS);
    /// `Tier`. Spec: docs/50 §3.4.
    pub const TIER: u8 = ok(rq::TIER_OF);
    /// `()`. Spec: docs/50 §3.4.
    pub const VIEW_ENDED: u8 = ok(rq::END_VIEW);
    /// The domain description. Spec: docs/50 §3.4.
    pub const DOMAIN: u8 = ok(rq::DESCRIBE_DOMAIN);
    /// `()`. Spec: docs/50 §7.5.
    pub const PONG: u8 = ok(rq::PING);
    /// The view answered a `Client` / `Service` query with an
    /// `AccountSourceError`. Spec: crates/kdc accounts.rs.
    pub const ACCOUNT_FAILURE: u8 = 0xF1;
    /// The view answered an `ExpandGroups` / `TierOf` query with a
    /// `PipError`. Spec: crates/pdp pip.rs.
    pub const PIP_FAILURE: u8 = 0xF2;
    /// The view protocol refused the request (no such view, one already
    /// open, the bound reached, expired, no snapshot). Spec: docs/50 §3.4.
    pub const VIEW_FAILURE: u8 = 0xF3;

    /// The closed reply table (without the reserved `REFUSED_KIND`).
    /// Spec: docs/50 §3.3, §3.4; A-59.
    pub const ALL: &[u8] = &[
        VIEW_BEGUN,
        CLIENT,
        SERVICE,
        GROUPS,
        TIER,
        VIEW_ENDED,
        DOMAIN,
        PONG,
        ACCOUNT_FAILURE,
        PIP_FAILURE,
        VIEW_FAILURE,
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
// Evaluated at compile time: a table that breaks either rule does not build.
const _: () = assert!(ipc::kinds_exclude_refused(request_kind::ALL));
const _: () = assert!(ipc::kinds_exclude_refused(reply_kind::ALL));
const _: () = assert!(all_distinct(request_kind::ALL));
const _: () = assert!(all_distinct(reply_kind::ALL));

// ---- closed code tables ----------------------------------------------------

/// Why the view protocol refused a request (reply kind
/// [`reply_kind::VIEW_FAILURE`]). The kdc's client reports every one as
/// "not served" (`AccountSourceError::Unavailable`, `PipError::Unavailable`).
/// Spec: docs/50 §3.4 ("one view open per connection, expires after ≤ 5 s").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewFailure {
    /// No view with this id is open on this connection.
    UnknownView,
    /// `BeginView` while a view is already open on this connection.
    ViewOpen,
    /// The bound on concurrently open views is reached.
    ViewLimit,
    /// The view outlived the view lifetime and was released.
    Expired,
    /// The store could not hand out a snapshot.
    Snapshot,
}

/// Wire codes, project choices (closed tables). Spec: docs/50 §3.3.
pub mod codes {
    use super::ViewFailure;
    use super::{AccountKind, AccountSourceError, ArmorPolicy, KeyPurpose, PipError, Tier};

    /// `Tier` → code. Spec: crates/pdp model.rs (`Tier`).
    #[must_use]
    pub const fn tier(tier: Tier) -> u8 {
        match tier {
            Tier::Tier0 => 0x00,
            Tier::Tier1 => 0x01,
            Tier::Tier2 => 0x02,
            Tier::Untiered => 0x03,
        }
    }

    /// Code → `Tier`. Spec: crates/pdp model.rs.
    #[must_use]
    pub const fn tier_from(code: u8) -> Option<Tier> {
        match code {
            0x00 => Some(Tier::Tier0),
            0x01 => Some(Tier::Tier1),
            0x02 => Some(Tier::Tier2),
            0x03 => Some(Tier::Untiered),
            _ => None,
        }
    }

    /// `AccountKind` → code. Spec: crates/kdc accounts.rs; docs/48 §3.1.
    #[must_use]
    pub const fn account_kind(kind: AccountKind) -> u8 {
        match kind {
            AccountKind::User => 0x01,
            AccountKind::Computer => 0x02,
        }
    }

    /// Code → `AccountKind`.
    #[must_use]
    pub const fn account_kind_from(code: u8) -> Option<AccountKind> {
        match code {
            0x01 => Some(AccountKind::User),
            0x02 => Some(AccountKind::Computer),
            _ => None,
        }
    }

    /// `ArmorPolicy` → code. Spec: crates/kdc accounts.rs; docs/48 §7.2.
    #[must_use]
    pub const fn armor_policy(policy: ArmorPolicy) -> u8 {
        match policy {
            ArmorPolicy::Required => 0x01,
            ArmorPolicy::BootstrapAllowed => 0x02,
        }
    }

    /// Code → `ArmorPolicy`.
    #[must_use]
    pub const fn armor_policy_from(code: u8) -> Option<ArmorPolicy> {
        match code {
            0x01 => Some(ArmorPolicy::Required),
            0x02 => Some(ArmorPolicy::BootstrapAllowed),
            _ => None,
        }
    }

    /// `KeyPurpose` → code (the codes of the keyd channel, crates/ipc-keyd).
    /// Spec: docs/50 §3.3 ("`KeyHandle` = 16 octets `PrincipalId` + `u8`
    /// purpose").
    #[must_use]
    pub const fn key_purpose(purpose: KeyPurpose) -> u8 {
        match purpose {
            KeyPurpose::PrincipalLongterm => 0x01,
            KeyPurpose::Krbtgt => 0x02,
            KeyPurpose::Service => 0x03,
            // R2 (docs/52 §5 item 3): the admin service's key set — the KDC
            // seals its tickets there.
            KeyPurpose::AdminService => 0x04,
            // Task K3 (docs/53 §5.2): the change-password service's key set,
            // appended (docs/50 §3.3).
            KeyPurpose::ChangePasswordService => 0x05,
        }
    }

    /// Code → `KeyPurpose`.
    #[must_use]
    pub const fn key_purpose_from(code: u8) -> Option<KeyPurpose> {
        match code {
            0x01 => Some(KeyPurpose::PrincipalLongterm),
            0x02 => Some(KeyPurpose::Krbtgt),
            0x03 => Some(KeyPurpose::Service),
            0x04 => Some(KeyPurpose::AdminService),
            0x05 => Some(KeyPurpose::ChangePasswordService),
            _ => None,
        }
    }

    /// `AccountSourceError` → code. Spec: crates/kdc accounts.rs.
    #[must_use]
    pub const fn account_error(error: AccountSourceError) -> u8 {
        match error {
            AccountSourceError::Failed => 0x01,
            AccountSourceError::Unavailable => 0x02,
        }
    }

    /// Code → `AccountSourceError`.
    #[must_use]
    pub const fn account_error_from(code: u8) -> Option<AccountSourceError> {
        match code {
            0x01 => Some(AccountSourceError::Failed),
            0x02 => Some(AccountSourceError::Unavailable),
            _ => None,
        }
    }

    /// `PipError` → code. Spec: crates/pdp pip.rs.
    #[must_use]
    pub const fn pip_error(error: PipError) -> u8 {
        match error {
            PipError::NotFound => 0x01,
            PipError::Unavailable => 0x02,
        }
    }

    /// Code → `PipError`.
    #[must_use]
    pub const fn pip_error_from(code: u8) -> Option<PipError> {
        match code {
            0x01 => Some(PipError::NotFound),
            0x02 => Some(PipError::Unavailable),
            _ => None,
        }
    }

    /// `ViewFailure` → code. Spec: docs/50 §3.4.
    #[must_use]
    pub const fn view_failure(failure: ViewFailure) -> u8 {
        match failure {
            ViewFailure::UnknownView => 0x01,
            ViewFailure::ViewOpen => 0x02,
            ViewFailure::ViewLimit => 0x03,
            ViewFailure::Expired => 0x04,
            ViewFailure::Snapshot => 0x05,
        }
    }

    /// Code → `ViewFailure`.
    #[must_use]
    pub const fn view_failure_from(code: u8) -> Option<ViewFailure> {
        match code {
            0x01 => Some(ViewFailure::UnknownView),
            0x02 => Some(ViewFailure::ViewOpen),
            0x03 => Some(ViewFailure::ViewLimit),
            0x04 => Some(ViewFailure::Expired),
            0x05 => Some(ViewFailure::Snapshot),
            _ => None,
        }
    }
}
