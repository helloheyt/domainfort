//! The body of the `ipc_kpasswd_reply` fuzz target — the front's side: an
//! arbitrary reply body through `ipc::decode_reply` (bound, magic, exact
//! version, the shared `Refused` ahead of the closed reply table, fields,
//! field domains, no trailing octet) — what the front's `KpasswdClient`
//! does with dird's octets (docs/50 §3.3: "replies are decoded with the same
//! strictness").
//!
//! Properties (docs/CLEAN-ROOM.md; docs/50 §3.3, §9; docs/53 §5.9): never a
//! panic, bounded allocation; whatever decodes re-encodes to exactly the
//! input; a decoded `Sealed` keeps its domains (an AP-REP starting
//! `[APPLICATION 15]`, a KRB-PRIV starting `[APPLICATION 21]`, the two
//! together ≤ `MAX_SEALED_MESSAGES`); a decoded `Unsealed` is HARDERROR or
//! AUTHERROR only (docs/53 §5.7; RFC 3244 §2: never SUCCESS).
//!
//! Shared by the fuzz target (`fuzz/fuzz_targets/ipc_kpasswd_reply.rs`) and
//! by `tests/fuzz_bodies.rs` (see the request body's note).

use ipc::{decode_reply, encode_reply, Reply};
use ipc_kpasswd::channel::{AP_REP_IDENTIFIER, KRB_PRIV_IDENTIFIER};
use ipc_kpasswd::{KpasswdReply, KPASSWD_CHANNEL, MAX_SEALED_MESSAGES};

/// Run the target's checks over `data`.
pub fn run(data: &[u8]) {
    if let Ok(reply) = decode_reply::<KpasswdReply>(KPASSWD_CHANNEL, data) {
        let again = encode_reply(KPASSWD_CHANNEL, &reply).expect("a decoded reply re-encodes");
        assert_eq!(again.body(), data, "canonical wire round trip");
        match &reply {
            Reply::Message(KpasswdReply::Sealed(sealed)) => {
                assert_eq!(sealed.ap_rep().as_bytes().first(), Some(&AP_REP_IDENTIFIER));
                assert_eq!(
                    sealed.krb_priv().as_bytes().first(),
                    Some(&KRB_PRIV_IDENTIFIER)
                );
                let total = sealed.ap_rep().len() + sealed.krb_priv().len();
                assert!(total <= MAX_SEALED_MESSAGES as usize);
            }
            Reply::Message(KpasswdReply::Unsealed(code)) => {
                assert!(matches!(code.value(), 2 | 3));
            }
            Reply::Message(KpasswdReply::Pong { .. }) | Reply::Refused(_) => {}
        }
    }
}
