//! The body of the `ipc_kpasswd_request` fuzz target — dird's side: an
//! arbitrary request body through `ipc::decode_body` (bound, magic, exact
//! version, closed kind table, fields, field domains, no trailing octet),
//! through `ipc_kpasswd::decode_request` (the entry point dird's dispatcher
//! takes), and through the dispatcher itself with a host that answers.
//!
//! Properties (docs/CLEAN-ROOM.md; docs/50 §3.3, §9; docs/53 §5.9): arbitrary
//! bytes → decoder, never a panic, bounded allocation; whatever decodes
//! re-encodes to exactly the input ("a single encoding per value"); a decoded
//! `ChangePassword` keeps its domains — an AP-REQ starting `[APPLICATION 14]`,
//! a KRB-PRIV starting `[APPLICATION 21]` (never the cleartext EncKrbPrivPart
//! `[APPLICATION 28]` — docs/53 R53-4), the two together ≤ one RFC 3244
//! message, canonical addresses (RFC 4120 §7.1); a rejection maps to the
//! refusal table, the same from both entry points; the host is reached only
//! by a request that decodes.
//!
//! Shared by the fuzz target (`fuzz/fuzz_targets/ipc_kpasswd_request.rs`)
//! and by `tests/fuzz_bodies.rs`, which runs it over hand-made inputs so the
//! body compiles and holds in every `cargo test` (the fuzz workspace itself
//! is built only after PENDING-OWNER P-1).

use ipc::{decode_body, encode_frame, Direction};
use ipc_kpasswd::channel::{AP_REQ_IDENTIFIER, KRB_PRIV_IDENTIFIER};
use ipc_kpasswd::{
    decode_request, ChangePasswordRequest, FrontZone, HostUnserved, KpasswdAnswer,
    KpasswdConnection, KpasswdHost, KpasswdRequest, Rejection, UnsealedCode, KPASSWD_CHANNEL,
    MAX_REQUEST_MESSAGES,
};

/// A host that counts its calls and answers HARDERROR.
struct Counting(u32);

impl KpasswdHost for Counting {
    fn change_password(
        &mut self,
        _zone: FrontZone,
        _request: &ChangePasswordRequest,
    ) -> Result<KpasswdAnswer, HostUnserved> {
        self.0 += 1;
        Ok(KpasswdAnswer::Unsealed(UnsealedCode::HardError))
    }
}

/// Run the target's checks over `data`.
pub fn run(data: &[u8]) {
    let decoded = decode_body::<KpasswdRequest>(KPASSWD_CHANNEL, Direction::Request, data);
    match &decoded {
        Ok(request) => {
            let again = encode_frame(KPASSWD_CHANNEL, Direction::Request, request)
                .expect("a decoded request re-encodes");
            assert_eq!(again.body(), data, "canonical wire round trip");
            if let KpasswdRequest::ChangePassword(change) = request {
                assert_eq!(change.ap_req().as_bytes().first(), Some(&AP_REQ_IDENTIFIER));
                assert_eq!(
                    change.krb_priv().as_bytes().first(),
                    Some(&KRB_PRIV_IDENTIFIER)
                );
                let total = change.ap_req().len() + change.krb_priv().len();
                assert!(total <= MAX_REQUEST_MESSAGES as usize);
                for address in [change.peer().address(), change.local().address()] {
                    assert_eq!(address, address.to_canonical());
                }
            }
        }
        Err(error) => {
            // Either a shared refusal or a close; never anything else.
            let _ = error.refusal();
        }
    }
    // dird's entry point over the same octets agrees.
    match (decode_request(data), &decoded) {
        (Ok(a), Ok(b)) => assert_eq!(&a, b),
        (Err(Rejection::Close), Err(error)) => assert_eq!(error.refusal(), None),
        (Err(Rejection::Refuse(refused)), Err(error)) => {
            assert_eq!(error.refusal(), Some(refused));
        }
        _ => panic!("the two entry points disagree"),
    }
    // The dispatcher reaches the host only for a decoded change request.
    let mut host = Counting(0);
    let mut connection = KpasswdConnection::new(0, FrontZone::Internal);
    let _ = connection.handle(data, &mut host);
    let expected = u32::from(matches!(decoded, Ok(KpasswdRequest::ChangePassword(_))));
    assert_eq!(host.0, expected);
}
