#![forbid(unsafe_code)]
//! `kdc`: the phase-1 native Key Distribution Center — AS and TGS — as a
//! library.
//!
//! # What it is
//!
//! [`Kdc::handle`] turns one request (an AS-REQ or TGS-REQ as it arrived)
//! into one reply: an AS-REP, a TGS-REP, a terse KRB-ERROR, or nothing (UDP
//! silence, RFC 4120 5.1.4). No sockets, no daemon, no threads, no clock:
//! the caller supplies the transport kind, the source zone and `now`
//! (main-session decision 1). TCP record framing and the UDP rules are pure,
//! bounded helpers ([`tcp_decode_frame`], [`tcp_encode_frame`],
//! [`Kdc::reject_frame`], the KRB_ERR_RESPONSE_TOO_BIG rule; module
//! [`transport`]).
//!
//! The KDC holds no secret (docs/30 §1): every key operation is a call to
//! keyd through [`KeyCustody`] — `verify_preauth`, `issue_as_rep`,
//! `open_and_verify_tgt`, `issue_tgs_rep`, `open_fast_armor`,
//! `seal_fast_error` (docs/10 §4-§5א). Every AS and TGS step is a PDP
//! decision (`Action::KdcAs` / `KdcTgs`, docs/11; module [`gate`]).
//! Principals come from a KDC-owned [`AccountSource`] trait (main-session
//! decision 3), passed with each request alongside the [`PolicyInputs`] so
//! both come from one directory view (docs/47 R47-14).
//!
//! # Profile (decisions of the main session, docs/02 §3, docs/30)
//!
//! - **Names:** exact match only — realm octets and name-string components,
//!   name-type not significant (RFC 4120 6.2); no case folding, aliases,
//!   enterprise names, referrals or canonicalisation; ASCII only; one realm.
//! - **FAST is mandatory (RFC 6113; D126, docs/48, P-10 interim):** every
//!   AS and TGS exchange is armored — the AS with an FX_FAST_ARMOR_AP_REQUEST
//!   armor whose ticket is a computer account's TGT (D126, re-evaluated at
//!   use, D53), the TGS with the implicit armor of its PA-TGS-REQ. Only the
//!   inner request is processed; refusals after the armor opened are
//!   armored (PA-FX-ERROR sealed by keyd); every FAST key stays in keyd
//!   (A-33). Enforced in two layers (docs/48 §7.2): this KDC's gate before
//!   keyd — an unarmored AS for an account that may not bootstrap gets a
//!   KDC_ERR_PREAUTH_REQUIRED advertising only PA-FX-FAST and PA-FX-COOKIE,
//!   an unarmored TGS gets KDC_ERR_POLICY — and the PDP, which sees
//!   `armored` truthfully (`pdp::mandatory_fast_rules`). The single
//!   exception (docs/48 §7.3): a computer account ([`AccountKind::Computer`]
//!   with [`ArmorPolicy::BootstrapAllowed`]) may get its TGT unarmored with
//!   PA-ENC-TIMESTAMP.
//! - **Pre-authentication is mandatory:** inside FAST, the encrypted
//!   challenge (RFC 6113 5.4.6) verified inside keyd, the reply key always
//!   strengthened; unarmored (the bootstrap only), PA-ENC-TIMESTAMP verified
//!   inside keyd. KDC_ERR_PREAUTH_REQUIRED always advertises PA-FX-FAST and
//!   carries the PA-FX-COOKIE (RFC 6113 5.2, 5.4.2), PA-ETYPE-INFO2 where a
//!   key is offered (never PA-ETYPE-INFO or PA-PW-SALT).
//! - **AES only:** the client's etype list in its order ∩ keyd's AES types ∩
//!   the principal's keys; there is no code path for RC4 / DES / 3DES (D125).
//! - **Re-evaluation at TGS (D53):** the client account is read again; a
//!   disabled, locked, expired or deleted account is refused, and the
//!   RFC 4120 3.3.3.1 hot-list ([`AccountState::revoked_before`]) revokes
//!   TGTs authenticated before a cut-off.
//! - **KDC options:** flag options are honoured only when keyd's
//!   TicketPolicy allows the flag; operation options phase 1 lacks
//!   (forwarded, proxy, allow-postdate, postdated, enc-tkt-in-skey, renew,
//!   validate) are KDC_ERR_BADOPTION; unrecognised options are ignored
//!   (RFC 4120 §2). See [`options`].
//! - **KRB-ERROR:** never e-text, never internal detail; stime from `now`.
//! - **Bounds:** [`MAX_REQUEST_LEN`]; the retransmit cache (RFC 4120 3.1.2)
//!   is bounded in entries and octets.
//! - **Audit:** exactly one [`AuditEvent`] per request, with the FAST armor
//!   principal (R48-11); no key, plaintext or ticket octets.
//!
//! # Not implemented in phase 1 (no code path)
//!
//! PKINIT, anonymous FAST armor (RFC 6112 not pinned), FAST options
//! (hide-client-names is refused as an unsupported critical option), any
//! FAST factor other than encrypted challenge (PA-ENC-TIMESTAMP inside FAST
//! is ignored), multi-round-trip pre-authentication, an explicit armor in a
//! TGS request, PAC (phase 2, D124), S4U / constrained delegation,
//! user-to-user, renewal, validation, forwarded / proxy tickets,
//! postdating, cross-realm referrals, ticket addresses, authorization data,
//! name canonicalisation (RFC 6806), kpasswd.
//!
//! # Follow-ups
//!
//! - The directory-backed [`AccountSource`] is the `directory-pip` crate
//!   (docs/47 R47-11); the in-memory [`InMemoryAccounts`] serves tests and
//!   fuzzing.
//! - The keyd IPC client (D34) implementing [`KeyCustody`].
//! - Which group SID the deployment's `pdp::mandatory_fast_rules` names as
//!   the bootstrap set (Q-130, with P-10).
//!
//! # Residuals (documented, not hidden)
//!
//! - **User enumeration:** an unknown client gets
//!   KDC_ERR_C_PRINCIPAL_UNKNOWN and a known one KDC_ERR_PREAUTH_REQUIRED
//!   (RFC 4120 3.1.3); account state (revoked) is likewise visible before
//!   pre-authentication — by design, so that a locked account is never a
//!   password oracle. No anti-enumeration scheme is invented
//!   (main-session decision 5).
//! - **TGS failure codes (A-26, docs/questions/Q-071):** every failure keyd
//!   decides before the TGT and authenticator decrypted and the req-body
//!   checksum verified is one code, KRB_AP_ERR_BAD_INTEGRITY — including a
//!   forged request for an expired TGT. Only a holder of the TGT session key
//!   learns KRB_AP_ERR_TKT_EXPIRED, KRB_AP_ERR_TKT_NYV, KRB_AP_ERR_SKEW or
//!   KRB_AP_ERR_REPEAT. An out-of-skew PA-ENC-TIMESTAMP stays
//!   KDC_ERR_PREAUTH_FAILED (RFC 4120 names no other code for it).
//! - **Error codes for phase-1 refusals** (cross-realm, AS for a non-TGS
//!   service, TGS for a TGT, addresses) are this crate's choices among the
//!   RFC 4120 7.5.9 codes (docs/questions/Q-070, accepted as A-27).
//! - **Retransmit cache:** a full cache stores nothing more; an identical
//!   TGS-REQ retransmitted then is refused by keyd's replay cache (fail
//!   closed). An identical request within the window (keyd's clock skew)
//!   gets the earlier reply even if the account was disabled or the policy
//!   changed in between (no new ticket or session key is issued).
//! - **No PAC:** a TGT names its client only by name; a reassigned name
//!   inherits older TGTs unless the operator sets the account's
//!   `revoked_before` (RFC 4120 3.3.3.1).
//! - **`now` is trusted:** the caller's clock decides every time check
//!   (RFC 4120 §1.6 / §10: clock synchronisation must itself be secured).
//! - **FAST interpretations awaiting the lab** (docs/questions/Q-120..Q-126,
//!   Q-145, Q-150): among them the single PA-ETYPE-INFO2 entry of an armored
//!   PREAUTH_REQUIRED (the key keyd will use, Q-123), the fixed
//!   content-free PA-FX-COOKIE (Q-126: "expected", not MUST, to change per
//!   message), and the codes of refusals RFC 6113 leaves open (Q-125). A
//!   client that reads them otherwise is refused, never accepted wrongly.
//! - **Account kind is visible before pre-authentication:** the
//!   KDC_ERR_PREAUTH_REQUIRED of an unarmored AS offers PA-ENC-TIMESTAMP to a
//!   computer account that may bootstrap and not to anyone else (docs/48
//!   §7.3) — part of the user-enumeration residual above.
//! - **An armored error lost over UDP:** an armored KRB-ERROR too large for
//!   UDP is replaced by KRB_ERR_RESPONSE_TOO_BIG after keyd consumed the
//!   conversation's token; the client's identical retry over TCP then meets
//!   keyd's replay cache (KRB_AP_ERR_REPEAT, unarmored) and must build a
//!   fresh armor — which the native client does for every request (docs/48
//!   §3.3). Successful replies are kept in the retransmit cache.
//!
//! # Provenance
//!
//! Written only from the allowed sources, opened in-session (AGENTS.md
//! §1-3): RFC 4120 (pinned copy, sha256 368d3cd1…f75b) §2, 2.1-2.9, 3.1,
//! 3.1.2-3.1.6, 3.2.3, 3.3, 3.3.1-3.3.3.2, 5.1.1-5.1.5, 5.2.1-5.2.3, 5.2.7,
//! 5.2.7.1-5.2.7.5, 5.2.8, 5.3, 5.4.1, 5.4.2, 5.9, 5.9.1, 5.10, 6.1, 6.2,
//! 7.2, 7.2.1, 7.2.2, 7.3, 7.5.1, 7.5.2, 7.5.7, 7.5.8, 7.5.9, 8.2; RFC 6113
//! (pinned copy, sha256 69c49f1a…d278c) §2.2, 2.4, 5.2, 5.4, 5.4.1, 5.4.1.1,
//! 5.4.2, 5.4.3, 5.4.4, 5.4.5, 5.4.6, 6.1, 6.2, 7.1, 7.2, 7.3; this project's
//! docs/02 §3, docs/10 (§5א included), docs/11, docs/25 §3-§5, docs/30
//! §1-§3, §7, docs/45 §10, docs/48 (decided A-33),
//! docs/questions/PENDING-OWNER.md (A-17, A-19, A-22, A-23, A-24..A-27,
//! A-32, A-33, A-39, A-42, A-43, P-10), docs/questions/Q-120..Q-127, Q-130,
//! Q-145, Q-150; and the source and documentation of this project's own
//! crates keyd, pdp, krb-proto and dtyp. No other implementation was
//! consulted or recalled.
//!
//! Spec: RFC 4120 §3.1, §3.3, §7.2; RFC 6113 §5.4; docs/30; docs/48;
//! main-session decisions 1-15.

mod accounts;
mod as_exchange;
pub mod audit;
mod config;
mod custody;
mod etype;
mod fast;
pub mod gate;
#[allow(clippy::module_inception)]
mod kdc;
mod krb_error;
mod lifetime;
mod names;
pub mod options;
mod retransmit;
mod tgs_exchange;
mod time;
pub mod transport;

pub use accounts::{
    AccountKind, AccountSource, AccountSourceError, AccountState, ArmorPolicy, ClientAccount,
    DuplicatePrincipal, InMemoryAccounts, NamedPrincipal, ServiceAccount,
};
pub use audit::{ArmorAudit, AuditEvent, AuditOutcome, AuditReason, AuditSink, Exchange};
pub use config::{
    ConfigError, KdcConfig, DEFAULT_RETRANSMIT_CAPACITY, DEFAULT_RETRANSMIT_MAX_OCTETS,
    DEFAULT_UDP_MAX_REPLY_LEN, MAX_REQUEST_LEN, MAX_RETRANSMIT_CAPACITY, MAX_RETRANSMIT_OCTETS,
};
pub use custody::{KeyCustody, LocalKeyd};
pub use gate::{PolicyInputs, RateLimiter};
pub use kdc::Kdc;
pub use transport::{
    tcp_decode_frame, tcp_encode_frame, FramingError, KdcReply, Peer, TcpFrame, Transport,
    TCP_LENGTH_PREFIX_LEN,
};
