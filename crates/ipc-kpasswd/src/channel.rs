//! The dird-kpasswd channel's fixed identity: magic, version, the
//! per-direction body bounds, the per-field bounds, the closed kind tables,
//! the closed code tables and the identifier octets the Kerberos message
//! fields must start with.
//!
//! # Where the numbers come from
//!
//! * **The forwarded request.** An RFC 3244 request message is at most what
//!   its 16-bit `message length` field counts, 65,535 octets "including this
//!   field", of which 6 are the header (`message length`, `protocol version
//!   number`, `AP_REQ length`) — so the AP-REQ and the KRB-PRIV together are
//!   at most [`MAX_REQUEST_MESSAGES`] = 65,529 octets, and each, the other
//!   being non-empty, at most [`MAX_REQUEST_FIELD`] = 65,528 (RFC 3244 §2;
//!   docs/53 §5.1). kpasswd-front, which links parse-kpasswd as well, pins
//!   these numbers to parse-kpasswd's `MAX_MESSAGE_LEN` and
//!   `MESSAGE_HEADER_LEN` at compile time (this crate links no Kerberos
//!   crate — the crate documentation says why).
//! * **Request direction: 64 KiB + 64.** docs/53 §5.9: "request ≤ 64 KiB +
//!   header (both fields together ≤ one message)". The largest request is a
//!   `ChangePassword`: the envelope (4), two length prefixes (8), the two
//!   messages (65,529) and two addresses (2 × 17) — 65,575 octets.
//! * **Reply direction: 8 KiB** — docs/53 §5.9's "reply ≤ 8 KiB ⚠". The
//!   largest reply is a `Sealed`: an AP-REP (an EncAPRepPart of ctime, cusec
//!   and a sequence number, encrypted) and a KRB-PRIV whose user-data is a
//!   2-octet result code (RFC 3244 §2; docs/53 §5.5) — a few hundred octets.
//!   ⚠ Project bound, to be confirmed against keyd's real replies in task
//!   K10 (docs/questions/Q-955 item 3).
//!
//! Spec: docs/53 §4.3, §5.1, §5.9; docs/50 §3.3, the channel-magic registry
//! (A-64: `dird-kpasswd.sock | ipc-kpasswd | 0x4B50 ("KP") | 1`); RFC 3244
//! §2; A-59.

use core::time::Duration;
use ipc::{Channel, FrameLimit};

/// The channel's magic: the ASCII octets "KP". Registered in docs/50's
/// channel-magic registry before this crate was built (A-64; A-117,
/// docs/53 K0) — distinct from every other channel's magic.
/// Spec: docs/50 §3.3, the channel-magic registry; docs/53 R53-4.
pub const KPASSWD_MAGIC: u16 = 0x4B50;

/// The one version of the channel this build speaks; any other is refused
/// (`Refused::VersionMismatch`), never negotiated.
/// Spec: docs/50 §3.3 ("exact version … no negotiation and no fallback");
/// the registry row (version 1); D57.
pub const KPASSWD_VERSION: u8 = 1;

/// Most octets of an RFC 3244 message: the 16-bit `message length` field.
/// Spec: RFC 3244 §2 ("message length field: contains the number of bytes in
/// the message including this field"); docs/53 §5.1, §5.9.
pub const MAX_RFC3244_MESSAGE: u32 = 65_535;

/// Octets of the fixed RFC 3244 header: `message length`, `protocol version
/// number`, `AP_REQ length` — 16 bits each.
/// Spec: RFC 3244 §2 (request message diagram).
pub const RFC3244_HEADER: u32 = 6;

/// Most octets of the AP-REQ and the KRB-PRIV of one request together.
/// Spec: RFC 3244 §2; docs/53 §5.9 ("both fields together ≤ one message").
pub const MAX_REQUEST_MESSAGES: u32 = MAX_RFC3244_MESSAGE - RFC3244_HEADER;

/// Most octets of either message of a request: the other is non-empty
/// (docs/53 §5.1: `AP_REQ length` ≥ 1; the KRB-PRIV ≥ 1).
/// Spec: RFC 3244 §2; docs/53 §5.1.
pub const MAX_REQUEST_FIELD: u32 = MAX_REQUEST_MESSAGES - 1;

/// Request body bound: 64 KiB + 64 (module documentation).
/// Spec: docs/53 §5.9.
pub const MAX_REQUEST_BODY: u32 = 64 * 1024 + 64;

/// Reply body bound: 8 KiB (module documentation).
/// Spec: docs/53 §5.9 ("reply ≤ 8 KiB ⚠").
pub const MAX_REPLY_BODY: u32 = 8 * 1024;

/// Most octets of the AP-REP and the KRB-PRIV of one sealed reply together:
/// what the reply bound leaves after the envelope (4) and two length
/// prefixes (8), rounded down to a multiple of 16.
/// Spec: docs/53 §5.5 (`SealedReply { ap_rep, krb_priv }`), §5.9.
pub const MAX_SEALED_MESSAGES: u32 = MAX_REPLY_BODY - 16;

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

/// The kpasswd-front ↔ dird channel (`dird-kpasswd.sock`, docs/53 §4.3).
/// Spec: docs/53 §4.3; docs/50 §3.3.
pub const KPASSWD_CHANNEL: Channel =
    Channel::new(KPASSWD_MAGIC, KPASSWD_VERSION, REQUEST_LIMIT, REPLY_LIMIT);

/// Most connections the front opens to dird at once; the front answers
/// HARDERROR beyond it, and dird may refuse more (its kpasswd thread has a
/// bounded queue and one request in flight — docs/53 §5.6 step 1). Project
/// choice (docs/questions/Q-955 item 3).
/// Spec: docs/53 §5.6, §8 ("DoS on keyd / dird" row).
pub const MAX_FRONT_CONNECTIONS: usize = 8;

/// The default deadline of one call of the front's client: 25 s. One change
/// makes, in dird, three keyd calls (`open_change_password_request`,
/// `register_decision`, `complete_change_password` — docs/53 §5.6 steps 2, 5,
/// 6) at keyd's 2 s client deadline (docs/50 §3.6) and waits for auditd's
/// acknowledgement of the decision before the commit (step 5; the audit
/// client's 5 s exchange bound) — 11 s; doubled for one request queued ahead
/// of it in dird's bounded kpasswd queue, rounded up. ⚠ Project choice,
/// pinned against dird's real path when it is built (docs/questions/Q-955
/// item 3); the front's configuration may only lower it.
/// Spec: docs/53 §5.6; docs/50 §3.6.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(25);

/// The envelope: magic, version, kind.
const ENVELOPE: u32 = 4;
/// Octets of the largest address field: family + an IPv6 address.
const LARGEST_ADDRESS: u32 = 1 + 16;
/// Body octets of the largest `ChangePassword`.
const LARGEST_CHANGE_PASSWORD: u32 = ENVELOPE + 4 + 4 + MAX_REQUEST_MESSAGES + 2 * LARGEST_ADDRESS;
/// Body octets of the largest `Sealed`.
const LARGEST_SEALED: u32 = ENVELOPE + 4 + 4 + MAX_SEALED_MESSAGES;

// The bounds fit the body bounds; checked at compile time, never at run time.
const _: () = assert!(LARGEST_CHANGE_PASSWORD <= MAX_REQUEST_BODY);
const _: () = assert!(LARGEST_SEALED <= MAX_REPLY_BODY);
const _: () = assert!(MAX_SEALED_MESSAGES + RFC3244_HEADER <= MAX_RFC3244_MESSAGE);

// ---- identifier octets -------------------------------------------------------

/// The one identifier octet of a constructed encoding of an
/// `[APPLICATION n]` tag, `n` ≤ 30: bits 8–7 = `01` (application class,
/// X.690 Table 1), bit 6 = 1 (constructed — the RFC 4120 module is
/// `DEFINITIONS EXPLICIT TAGS`, and an explicitly tagged value is encoded
/// constructed, X.690 8.14.3), bits 5–1 = the tag number (X.690 8.1.2.2).
/// Spec: ITU-T X.690 (02/2021) 8.1.2.2, 8.1.2.5, Table 1, 8.14.3; RFC 4120
/// Appendix A ("DEFINITIONS EXPLICIT TAGS").
const fn application_identifier(tag: u8) -> u8 {
    assert!(
        tag <= 30,
        "a tag number above 30 has a multi-octet identifier"
    );
    0b0100_0000 | 0b0010_0000 | tag
}

/// The identifier octet every AP-REQ starts with: `[APPLICATION 14]`.
/// Spec: RFC 4120 §5.5.1 (`AP-REQ ::= [APPLICATION 14]`), §5.10; X.690
/// 8.1.2.2.
pub const AP_REQ_IDENTIFIER: u8 = application_identifier(14);

/// The identifier octet every AP-REP starts with: `[APPLICATION 15]`.
/// Spec: RFC 4120 §5.5.2, §5.10; X.690 8.1.2.2.
pub const AP_REP_IDENTIFIER: u8 = application_identifier(15);

/// The identifier octet every KRB-PRIV starts with: `[APPLICATION 21]`. The
/// KRB-PRIV's fields are `pvno`, `msg-type` and `enc-part` only — the
/// EncKrbPrivPart, whose `user-data` holds the change-password request (and
/// so the new password), is inside `enc-part` (RFC 4120 §5.7.1).
/// Spec: RFC 4120 §5.7.1, §5.10; X.690 8.1.2.2.
pub const KRB_PRIV_IDENTIFIER: u8 = application_identifier(21);

/// The identifier octet of the cleartext EncKrbPrivPart: `[APPLICATION 28]`
/// — what a KRB-PRIV field of this channel can never start with (the
/// constant exists so the tests can show it is refused).
/// Spec: RFC 4120 §5.7.1, §5.10; X.690 8.1.2.2.
pub const ENC_KRB_PRIV_PART_IDENTIFIER: u8 = application_identifier(28);

// The values the derivation gives, as the lab observed them on the wire
// (docs/research/r3-e §3.2: the AP-REQ's first octet 0x6e, the KRB-PRIV's
// 0x75, a KRB-ERROR's 0x7e). Checked at compile time.
const _: () = assert!(AP_REQ_IDENTIFIER == 0x6E);
const _: () = assert!(KRB_PRIV_IDENTIFIER == 0x75);
const _: () = assert!(application_identifier(30) == 0x7E);
const _: () = assert!(ENC_KRB_PRIV_PART_IDENTIFIER != KRB_PRIV_IDENTIFIER);

// ---- kinds -------------------------------------------------------------------

/// Request kinds (kpasswd-front → dird). Values are a project choice.
/// Spec: docs/53 §4.3; docs/50 §3.3 ("`kind` closed"), §7.5 (`Ping` on every
/// channel).
pub mod request_kind {
    /// `Ping`: peer verification on every new connection and health check;
    /// the reply names the zone dird assigned (R14, the R9b pattern).
    /// Spec: docs/53 §5.6 step 1; docs/50 §3.7.
    pub const PING: u8 = 0x01;
    /// `ChangePassword { ap_req, krb_priv, peer, local }`: one RFC 3244
    /// request's two messages as received, and the connection's two
    /// addresses as the front's kernel reported them.
    /// Spec: docs/53 §4.3 ("an opaque request: ap_req, krb_priv, the peer's
    /// address, the local address"), §5.5.
    pub const CHANGE_PASSWORD: u8 = 0x02;

    /// The closed request table. Spec: docs/50 §3.3.
    pub const ALL: &[u8] = &[PING, CHANGE_PASSWORD];
}

/// Reply kinds (dird → kpasswd-front). [`ipc::REFUSED_KIND`] (`0xFF`) is
/// reserved for the shared transport refusal (A-59). Values are a project
/// choice.
/// Spec: docs/53 §5.5–§5.7; docs/50 §3.3; A-59.
pub mod reply_kind {
    /// `Pong { zone }`: the reply to `Ping`. Spec: docs/53 §5.6 step 1.
    pub const PONG: u8 = 0x81;
    /// `Sealed { ap_rep, krb_priv }`: keyd's sealed reply — AP-REP and a
    /// KRB-PRIV under the Authenticator's subkey — which the front frames
    /// as the RFC 3244 reply.
    /// Spec: docs/53 §5.5 (`SealedReply`), §5.7; RFC 3244 §2.
    pub const SEALED: u8 = 0x82;
    /// `Unsealed { code }`: no context to seal in — the front answers with
    /// its KRB-ERROR carrying `code`.
    /// Spec: docs/53 §5.7 (the KRB-ERROR rows dird decides).
    pub const UNSEALED: u8 = 0x83;

    /// The closed reply table (without the reserved `REFUSED_KIND`).
    /// Spec: docs/50 §3.3; A-59.
    pub const ALL: &[u8] = &[PONG, SEALED, UNSEALED];
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

// No kind equals the reserved `REFUSED_KIND` (A-59) and each table is a set.
// Evaluated at compile time: a table that breaks either rule does not build.
const _: () = assert!(ipc::kinds_exclude_refused(request_kind::ALL));
const _: () = assert!(ipc::kinds_exclude_refused(reply_kind::ALL));
const _: () = assert!(all_distinct(request_kind::ALL));
const _: () = assert!(all_distinct(reply_kind::ALL));

// ---- closed value tables -----------------------------------------------------

/// Wire codes of the closed value tables (one octet each, docs/50 §3.3:
/// "enum = `u8` from a closed table").
pub mod codes {
    /// `Pong.zone`: the internal front (the only zone of phase 1).
    /// Spec: docs/53 §3.3, §5.6 step 1 (`FrontZone::Internal` the only
    /// value); A-114.
    pub const ZONE_INTERNAL: u8 = 0x01;

    /// An address field: an IPv4 address (4 octets) follows — the family
    /// numbering of keyd's `HostAddr` on keyd.sock, to which dird hands the
    /// address on (crates/ipc-keyd).
    /// Spec: RFC 4120 §7.1 (IPv4, type 2); docs/53 §5.5 (`peer`, `local`).
    pub const FAMILY_IPV4: u8 = 0x01;
    /// An address field: an IPv6 address (16 octets) follows; never an
    /// IPv4-mapped one (the IPv4 form is the only spelling of those).
    /// Spec: RFC 4120 §7.1 ("IPv4-mapped IPv6 addresses MUST be represented
    /// as addresses of type 2"); docs/53 §5.4 item 3.
    pub const FAMILY_IPV6: u8 = 0x02;

    /// `Unsealed.code`: KRB5_KPASSWD_HARDERROR — dird, keyd or the audit
    /// trail not available, dird busy, an unknown outcome.
    /// Spec: RFC 3244 §2 (code 2); docs/53 §5.7.
    pub const UNSEALED_HARDERROR: u8 = 2;
    /// `Unsealed.code`: KRB5_KPASSWD_AUTHERROR — keyd's uniform `Denied`
    /// before or in the cryptographic chain (A-26), an undecodable AP-REQ or
    /// KRB-PRIV included (A-126 on docs/questions/Q-660 item 3).
    /// Spec: RFC 3244 §2 (code 3); docs/53 §5.7.
    pub const UNSEALED_AUTHERROR: u8 = 3;
}
