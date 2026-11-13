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
//! `open_and_verify_tgt`, `issue_tgs_rep` (docs/10 §4-§5). Every AS and TGS
//! step is a PDP decision (`Action::KdcAs` / `KdcTgs`, docs/11; module
//! [`gate`]). Principals come from a KDC-owned [`AccountSource`] trait
//! (main-session decision 3).
//!
//! # Profile (decisions of the main session, docs/02 §3, docs/30)
//!
//! - **Names:** exact match only — realm octets and name-string components,
//!   name-type not significant (RFC 4120 6.2); no case folding, aliases,
//!   enterprise names, referrals or canonicalisation; ASCII only; one realm.
//! - **Pre-authentication is mandatory:** PA-ENC-TIMESTAMP verified inside
//!   keyd; KDC_ERR_PREAUTH_REQUIRED carries METHOD-DATA with PA-ENC-TIMESTAMP
//!   and PA-ETYPE-INFO2 (never PA-ETYPE-INFO or PA-PW-SALT).
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
//! - **Audit:** exactly one [`AuditEvent`] per request; no key, plaintext or
//!   ticket octets.
//!
//! # Not implemented in phase 1 (no code path)
//!
//! FAST (RFC 6113, the D126 follow-up — the PDP sees `armored = false`),
//! PKINIT, PAC (phase 2, D124), S4U / constrained delegation, user-to-user,
//! renewal, validation, forwarded / proxy tickets, postdating, cross-realm
//! referrals, ticket addresses, authorization data, name canonicalisation
//! (RFC 6806), kpasswd.
//!
//! # Follow-ups
//!
//! - A directory-backed [`AccountSource`] (dirstore + the AD schema subset);
//!   the in-memory [`InMemoryAccounts`] serves tests and fuzzing.
//! - The keyd IPC client (D34) implementing [`KeyCustody`].
//! - FAST armoring and its PDP requirement (D126).
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
//!
//! # Provenance
//!
//! Written only from the allowed sources, opened in-session (AGENTS.md
//! §1-3): RFC 4120 (pinned copy, sha256 368d3cd1…f75b) §2, 2.1-2.9, 3.1,
//! 3.1.2-3.1.6, 3.2.3, 3.3, 3.3.1-3.3.3.2, 5.1.1-5.1.5, 5.2.1-5.2.3, 5.2.7,
//! 5.2.7.1-5.2.7.5, 5.2.8, 5.3, 5.4.1, 5.4.2, 5.9, 5.9.1, 5.10, 6.1, 6.2,
//! 7.2, 7.2.1, 7.2.2, 7.3, 7.5.1, 7.5.2, 7.5.7, 7.5.8, 7.5.9, 8.2; this
//! project's docs/02 §3, docs/10, docs/11, docs/25 §3-§5, docs/30 §1-§3, §7,
//! docs/45 §10, docs/questions/PENDING-OWNER.md (A-17, A-19, A-22, A-23); and
//! the source and documentation of this project's own crates keyd, pdp,
//! krb-proto and dtyp. No other implementation was consulted or recalled.
//!
//! Spec: RFC 4120 §3.1, §3.3, §7.2; docs/30; main-session decisions 1-15.

mod accounts;
mod as_exchange;
pub mod audit;
mod config;
mod custody;
mod etype;
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
    AccountSource, AccountSourceError, AccountState, ClientAccount, DuplicatePrincipal,
    InMemoryAccounts, NamedPrincipal, ServiceAccount,
};
pub use audit::{AuditEvent, AuditOutcome, AuditReason, AuditSink, Exchange};
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
