//! The ids of the one-time tokens that bind issuance to a completed
//! authentication: the AuthnProof exchange id (AS), the TGS context id, the
//! FAST armor id of an opened AS armor (docs/48 §2.3), and the
//! service-context id of a verified service ticket (docs/49 §3.3, A-46).
//!
//! Each token is 128 random bits from keyd's entropy source, bound to the
//! calling process and to the principal, short-lived, and consumed on first
//! presentation; the bounded token tables that hold them stay in keyd. Only
//! the ids cross keyd's interface, so they live in this crypto-free crate
//! (moved unchanged from keyd: D182; decision A-63).
//!
//! Spec: docs/10 §8 (state machines; tokens short-lived, single-use,
//! caller-bound), D36; docs/25 §2 principle 3 (per-session access); docs/48
//! §2.3 (armor id), §9.1 I4; docs/49 §3.3 (service ctx id).

use core::fmt;

/// Length of a token id in octets (128 bits).
pub const TOKEN_ID_LENGTH: usize = 16;

/// The AS exchange token returned by `verify_preauth` inside an
/// [`crate::AuthnProof`]. Not secret by itself: it is useless to any caller
/// other than the one it was issued to. Spec: docs/10 §4 (`exchange_id`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExchangeId([u8; TOKEN_ID_LENGTH]);

/// The TGS context token returned by `open_and_verify_tgt`.
/// Spec: docs/10 §5 (`ctx_id`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CtxId([u8; TOKEN_ID_LENGTH]);

/// The FAST armor token returned by `open_fast_armor`: it names the armor
/// key and the inner-request facts keyd holds for one armored AS
/// conversation. Not secret by itself (useless to any other caller); the
/// armor key it names never leaves keyd.
/// Spec: docs/48 §2.3 (`armor_id: ArmorId`), §9.1 I4.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArmorId([u8; TOKEN_ID_LENGTH]);

/// The service-context token returned by `open_and_verify_service_ticket`:
/// it names the session key (and authenticator subkey) of one verified
/// unbound AP-REQ, which keyd holds for the later GSS steps (task L6b:
/// `seal_ap_rep`; phase 2: wrap / unwrap). An operation-bound verification
/// (`verify_operation_ticket`) has none (docs/questions/Q-523). Not secret by itself (useless to any other
/// caller); the keys it names never leave keyd.
/// Spec: docs/49 §3.3 (`ServiceContext { ctx_id, … }`); docs/questions/Q-165
/// item 2 (decided A-46).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceCtxId([u8; TOKEN_ID_LENGTH]);

/// The request-context token returned by `open_change_password_request`
/// (task K3): it names the session key, the Authenticator's subkey and —
/// for an acceptable request — the new password that keyd holds for one
/// RFC 3244 request until `complete_change_password` or
/// `seal_change_password_error` consumes it. Not secret by itself (useless
/// to any other caller); what it names never leaves keyd.
/// Spec: docs/53 §5.5 (`ctx_id: ChangePasswordCtxId // one-time,
/// caller-bound, ≤ token_lifetime_secs`); docs/10 §8.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChangePasswordCtxId([u8; TOKEN_ID_LENGTH]);

macro_rules! token_id {
    ($ty:ident) => {
        impl $ty {
            /// Rebuild a token id received back from the caller (e.g. by the
            /// IPC layer). Spec: docs/10 §8.
            pub const fn from_bytes(bytes: [u8; TOKEN_ID_LENGTH]) -> Self {
                $ty(bytes)
            }

            /// The token octets.
            pub const fn as_bytes(&self) -> &[u8; TOKEN_ID_LENGTH] {
                &self.0
            }
        }

        impl fmt::Debug for $ty {
            /// Only a short prefix, enough to correlate in tests.
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    concat!(stringify!($ty), "({:02x}{:02x}..)"),
                    self.0[0], self.0[1]
                )
            }
        }
    };
}

token_id!(ExchangeId);
token_id!(CtxId);
token_id!(ArmorId);
token_id!(ServiceCtxId);
token_id!(ChangePasswordCtxId);
