//! The ldap-front ↔ dird channel's fixed identity: magic, version, the
//! per-direction body bounds, the per-field and per-reply bounds, the closed
//! kind tables and the closed code tables.
//!
//! # Where the numbers come from
//!
//! * **Request direction.** The largest frame is a `Message`: the canonical
//!   LDAPMessage is bounded by parse-ldap's post-authentication message bound
//!   `MAX_AUTH_MESSAGE_OCTETS` (1 MiB, the larger of the two
//!   authentication-state bounds — docs/49 §2.4); the engine applies the
//!   session's own bound again when it decodes (crates/ldap engine.rs step
//!   2). docs/50 §3.3: "dird-ldap request ≤ `MAX_AUTH_MESSAGE_OCTETS` (1 MiB)
//!   + header".
//! * **Reply direction.** One search may send SearchResultEntry messages
//!   totalling at most the engine's `MAX_RESPONSE_OCTETS` (8 MiB, crates/ldap
//!   search/limits.rs), and the octet budget is the only bound on a single
//!   entry — so one entry can be up to 8 MiB (a memberOf of 4,096 DNs of up to
//!   2,048 octets each alone approaches it). ipc's ceiling on any frame body
//!   is also 8 MiB (`ipc::MAX_BODY_CEILING`), which leaves no room for the
//!   envelope around an 8 MiB entry. A response therefore travels in **parts**
//!   of at most [`MAX_RESPONSE_PART`] (1 MiB); every part but the last of a
//!   response is exactly that long (one encoding per response), so a response
//!   takes at most 8 frames. docs/50 §3.3 proposed "a frame per LDAP response
//!   ≤ 2 MiB, ⚠ to be estimated": the estimate is 8 MiB, hence the parts
//!   (docs/questions/Q-280 item 2).
//! * **Per reply.** At most [`MAX_RESPONSES`] responses (the engine's page
//!   bound of 1,000 entries, the SearchResultDone, and a Notice of
//!   Disconnection), at most [`MAX_REPLY_OCTETS`] octets in all (the entries'
//!   8 MiB plus [`RESULT_RESERVE`] for the LDAPResult-bearing messages, whose
//!   matchedDN and diagnosticMessage are always empty — R49-13). The client
//!   enforces both; crates/ipc-ldap-server pins them to the engine's
//!   constants at compile time (this crate links no engine).
//!
//! Spec: docs/50 §3.3 ("`magic` per channel" — a project choice registered in
//! docs/50's channel-magic registry, A-64; "exact version, no negotiation";
//! "a bound per channel and per direction"; "enum = `u8` from a closed
//! table"), §4.2 (the channel's messages); docs/49 §2.4; A-59
//! (`REFUSED_KIND` reserved on every channel).

use ipc::{Channel, FrameLimit};
use parse_ldap::{AuthState, MAX_AUTH_MESSAGE_OCTETS, MAX_PREAUTH_MESSAGE_OCTETS};

/// The channel's magic: the ASCII octets "LD". Project choice — distinct
/// from every other channel's (docs/50 §3.3: "a different constant for each
/// channel"); registered in docs/50's channel-magic registry (A-64).
/// Spec: docs/50 §3.3; A-64.
pub const LDAP_MAGIC: u16 = 0x4C44;

/// The one version of the channel this build speaks; any other is refused
/// (`Refused::VersionMismatch`), never negotiated.
/// Spec: docs/50 §3.3 ("exact version … no negotiation and no fallback"),
/// §12; D57.
pub const LDAP_VERSION: u8 = 1;

/// Most octets of the canonical LDAPMessage of one `Message`: parse-ldap's
/// post-authentication bound, 1 MiB.
/// Spec: docs/50 §3.3; docs/49 §2.4 (`MAX_AUTH_PDU`); crates/parse-ldap
/// limits.rs.
pub const MAX_CANONICAL_MESSAGE: u32 = 1024 * 1024;

/// Most octets of one response part: 1 MiB. Project choice (module
/// documentation): an 8 MiB entry takes 8 parts.
/// Spec: docs/50 §3.3; docs/questions/Q-280 item 2.
pub const MAX_RESPONSE_PART: u32 = 1024 * 1024;

/// Most octets of one reassembled LDAP response: 8 MiB — the engine's
/// `MAX_RESPONSE_OCTETS` (pinned in crates/ipc-ldap-server, which links
/// both).
/// Spec: docs/50 §3.3; docs/49 §6.1 item 7; crates/ldap search/limits.rs.
pub const MAX_RESPONSE_MESSAGE: usize = 8 * 1024 * 1024;

/// Most responses in the reply to one `Message`: the engine's 1,000-entry
/// page bound, plus the SearchResultDone, plus one Notice of Disconnection
/// (pinned to `ldap::MAX_PAGE_SIZE` in crates/ipc-ldap-server).
/// Spec: docs/49 §6.1 item 7; crates/ldap search/limits.rs `MAX_PAGE_SIZE`.
pub const MAX_RESPONSES: usize = 1_002;

/// Octets allowed beyond the entries in the reply to one `Message`, for the
/// LDAPResult-bearing responses (SearchResultDone, BindResponse,
/// ExtendedResponse, a Notice of Disconnection — each a few dozen octets,
/// with empty matchedDN and diagnosticMessage, R49-13): 64 KiB. Project
/// choice, generous.
/// Spec: docs/49 §9 (R49-13); docs/questions/Q-280 item 2.
pub const RESULT_RESERVE: usize = 64 * 1024;

/// Most octets of all responses in the reply to one `Message`.
/// Spec: module documentation.
pub const MAX_REPLY_OCTETS: usize = MAX_RESPONSE_MESSAGE + RESULT_RESERVE;

/// Request body bound: the largest `Message` (envelope 4, length 4, the
/// canonical message, two booleans) rounded up: [`MAX_CANONICAL_MESSAGE`] +
/// 16.
/// Spec: docs/50 §3.3 ("≤ `MAX_AUTH_MESSAGE_OCTETS` (1 MiB) + header").
pub const MAX_REQUEST_BODY: u32 = MAX_CANONICAL_MESSAGE + 16;

/// Reply body bound: the largest `Response` (envelope 4, length 4, one
/// part, one boolean) rounded up: [`MAX_RESPONSE_PART`] + 16.
/// Spec: docs/50 §3.3; module documentation.
pub const MAX_REPLY_BODY: u32 = MAX_RESPONSE_PART + 16;

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

/// The ldap-front ↔ dird channel (`dird-ldap.sock`, docs/50 §3.1).
/// Spec: docs/50 §3.3, §4.2.
pub const LDAP_CHANNEL: Channel =
    Channel::new(LDAP_MAGIC, LDAP_VERSION, REQUEST_LIMIT, REPLY_LIMIT);

/// Body octets of the largest `Message`.
const LARGEST_MESSAGE: usize = 4 + 4 + MAX_CANONICAL_MESSAGE as usize + 1 + 1;
/// Body octets of the largest `Open` (an IPv6 peer).
const LARGEST_OPEN: usize = 4 + 1 + 1 + 16;
/// Body octets of the largest `Response`.
const LARGEST_RESPONSE: usize = 4 + 4 + MAX_RESPONSE_PART as usize + 1;

// The bounds agree with the values they are derived from and fit the body
// bounds; checked at compile time, never at run time.
const _: () = assert!(MAX_CANONICAL_MESSAGE as usize == MAX_AUTH_MESSAGE_OCTETS);
const _: () = assert!(MAX_PREAUTH_MESSAGE_OCTETS <= MAX_AUTH_MESSAGE_OCTETS);
const _: () = assert!(AuthState::Authenticated.max_message_octets() == MAX_AUTH_MESSAGE_OCTETS);
const _: () = assert!(LARGEST_MESSAGE <= MAX_REQUEST_BODY as usize);
const _: () = assert!(LARGEST_OPEN <= MAX_REQUEST_BODY as usize);
const _: () = assert!(LARGEST_RESPONSE <= MAX_REPLY_BODY as usize);
const _: () = assert!(MAX_RESPONSE_PART as usize <= MAX_RESPONSE_MESSAGE);
const _: () = assert!(MAX_RESPONSE_MESSAGE <= MAX_REPLY_OCTETS);

// ---- kinds -----------------------------------------------------------------

/// Request kinds (front → dird): docs/50 §4.2's `Open`, `Message`, the
/// TLS report and the end of the session, plus `Ping` (§7.5: "health check:
/// op `Ping` on every channel"; §7.5 step 5: ldap-front makes "a test
/// connection to dird"). Values are a project choice.
/// Spec: docs/50 §3.3 ("`kind` closed"), §4.2, §4.3, §7.5.
pub mod request_kind {
    /// `Open { listener, peer_addr }`: the first message of a session.
    /// Spec: docs/50 §4.2.
    pub const OPEN: u8 = 0x01;
    /// `Message { canonical, tls_established, input_pending }`.
    /// Spec: docs/50 §4.2; docs/49 R49-16.
    pub const MESSAGE: u8 = 0x02;
    /// `TlsEstablished`: the TLS layer the last `StartTls` asked for is up,
    /// with the docs/50 R50-11 parameters. Spec: docs/50 §4.3 step 4.
    pub const TLS_ESTABLISHED: u8 = 0x03;
    /// `Close`: the client connection ended; no reply.
    /// Spec: docs/50 §4.2 (dird destroys the session at close).
    pub const CLOSE: u8 = 0x04;
    /// `Ping`: health check, only as the first message of a connection.
    /// Spec: docs/50 §7.5.
    pub const PING: u8 = 0x05;

    /// The closed request table. Spec: docs/50 §3.3, §4.2.
    pub const ALL: &[u8] = &[OPEN, MESSAGE, TLS_ESTABLISHED, CLOSE, PING];
}

/// Reply kinds (dird → front). [`ipc::REFUSED_KIND`] (`0xFF`) is reserved
/// for the shared transport refusal (A-59). Values are a project choice.
/// Spec: docs/50 §3.3 (errors row), §4.2 ("`Response(bytes)` for every
/// response of `Outcome.responses`, then `Done { action, framing }`"); A-59.
pub mod reply_kind {
    /// `Opened { framing }`: the session exists. Spec: docs/50 §4.2.
    pub const OPENED: u8 = 0x81;
    /// `Response { part, more }`: one part of one canonical response.
    /// Spec: docs/50 §4.2; crate::channel module documentation.
    pub const RESPONSE: u8 = 0x82;
    /// `Done { action, framing }`: the end of the reply to a `Message`.
    /// Spec: docs/50 §4.2.
    pub const DONE: u8 = 0x83;
    /// `TlsAccepted { framing }`: the reply to `TlsEstablished`.
    /// Spec: docs/50 §4.3.
    pub const TLS_ACCEPTED: u8 = 0x84;
    /// `Pong`: the reply to `Ping`. Spec: docs/50 §7.5.
    pub const PONG: u8 = 0x85;

    /// The closed reply table (without the reserved `REFUSED_KIND`).
    /// Spec: docs/50 §3.3, §4.2; A-59.
    pub const ALL: &[u8] = &[OPENED, RESPONSE, DONE, TLS_ACCEPTED, PONG];
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

// ---- closed value tables ---------------------------------------------------

/// Which listener accepted the client connection. Mirrors the engine's
/// `ldap::Listener` by name (crates/ipc-ldap-server maps one to the other);
/// this crate links no engine.
/// Spec: docs/50 §4.2 (`Open { listener: Ldap|Ldaps, … }`); docs/49 §4.1;
/// [MS-ADTS] 5.1.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Listener {
    /// Cleartext LDAP (389); TLS only after a successful StartTLS.
    /// Spec: RFC 4511 §4.14; RFC 4513 §3.
    Ldap,
    /// LDAP over TLS from the first octet (636). The front opens the dird
    /// connection only after the LDAPS handshake completed with the docs/50
    /// R50-11 parameters (docs/50 §4.3 step 6).
    Ldaps,
}

/// What the front does with the client connection after sending the
/// responses. Mirrors the engine's `ldap::ConnectionAction` by name.
/// Spec: docs/50 §4.2 (`Done { action: Continue|StartTls|Close, … }`);
/// docs/49 §11.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionAction {
    /// Keep reading requests.
    Continue,
    /// Write the responses in cleartext, require and discard an empty
    /// cleartext buffer, then negotiate TLS as the server; report
    /// `TlsEstablished` when it is up (docs/50 §4.3 steps 3-4).
    StartTls,
    /// Write the responses, then close the client connection.
    Close,
}

/// Wire codes, project choices (closed tables). Spec: docs/50 §3.3.
pub mod codes {
    use super::{AuthState, ConnectionAction, Listener};

    /// `Listener` → code. Spec: docs/50 §4.2.
    #[must_use]
    pub const fn listener(listener: Listener) -> u8 {
        match listener {
            Listener::Ldap => 0x01,
            Listener::Ldaps => 0x02,
        }
    }

    /// Code → `Listener`.
    #[must_use]
    pub const fn listener_from(code: u8) -> Option<Listener> {
        match code {
            0x01 => Some(Listener::Ldap),
            0x02 => Some(Listener::Ldaps),
            _ => None,
        }
    }

    /// `ConnectionAction` → code. Spec: docs/50 §4.2.
    #[must_use]
    pub const fn action(action: ConnectionAction) -> u8 {
        match action {
            ConnectionAction::Continue => 0x01,
            ConnectionAction::StartTls => 0x02,
            ConnectionAction::Close => 0x03,
        }
    }

    /// Code → `ConnectionAction`.
    #[must_use]
    pub const fn action_from(code: u8) -> Option<ConnectionAction> {
        match code {
            0x01 => Some(ConnectionAction::Continue),
            0x02 => Some(ConnectionAction::StartTls),
            0x03 => Some(ConnectionAction::Close),
            _ => None,
        }
    }

    /// The framing state (parse-ldap `AuthState`) → code.
    /// Spec: docs/50 §4.2 ("`framing: AuthState`"); docs/49 §2.4.
    #[must_use]
    pub const fn framing(state: AuthState) -> u8 {
        match state {
            AuthState::Unauthenticated => 0x01,
            AuthState::Authenticated => 0x02,
        }
    }

    /// Code → framing state.
    #[must_use]
    pub const fn framing_from(code: u8) -> Option<AuthState> {
        match code {
            0x01 => Some(AuthState::Unauthenticated),
            0x02 => Some(AuthState::Authenticated),
            _ => None,
        }
    }

    /// The address family of a peer address: IPv4.
    pub const FAMILY_V4: u8 = 0x04;
    /// The address family of a peer address: IPv6.
    pub const FAMILY_V6: u8 = 0x06;
}
