//! dird's dispatch skeleton: the zone from the front's peer uid, the
//! replies, one change per connection, the refusals, and nothing malformed
//! reaching the host.
//!
//! Sources: docs/53 §3.3 (`FrontZone::Internal` the only value), §5.6 step 1
//! (the front's uid only; full queue ⇒ `Busy`), §5.7; docs/50 R50-3 (uid 0
//! never mapped), §3.3 (the refusal table); A-114; A-59; RFC 3244 §2 (one
//! request, one reply). The host is a test double that records its calls.

mod common;

use common::*;
use ipc::{decode_reply, Refused, Reply};
use ipc_kpasswd::{
    ChangePasswordRequest, Dispatch, FrontZone, HostUnserved, KpasswdAnswer, KpasswdConnection,
    KpasswdFronts, KpasswdHost, KpasswdReply, KpasswdRequest, UnsealedCode, KPASSWD_CHANNEL,
};

/// A host that answers with a fixed result and records what it was asked.
struct Host {
    answer: Result<KpasswdAnswer, HostUnserved>,
    calls: Vec<(FrontZone, ChangePasswordRequest)>,
}

impl Host {
    fn new(answer: Result<KpasswdAnswer, HostUnserved>) -> Host {
        Host {
            answer,
            calls: Vec::new(),
        }
    }
}

impl KpasswdHost for Host {
    fn change_password(
        &mut self,
        zone: FrontZone,
        request: &ChangePasswordRequest,
    ) -> Result<KpasswdAnswer, HostUnserved> {
        self.calls.push((zone, request.clone()));
        self.answer.clone()
    }
}

fn reply_of(dispatch: &Dispatch) -> Reply<KpasswdReply> {
    let frame = dispatch.frame().expect("a frame");
    decode_reply::<KpasswdReply>(KPASSWD_CHANNEL, frame.body()).expect("decodes")
}

/// docs/50 R50-3 ("uid 0 is never mapped"), §3.2; docs/53 §5.6 step 1 ("the
/// peer on dird-kpasswd.sock = the front's uid only"); A-114 (the internal
/// zone the only value).
#[test]
fn the_zone_comes_from_the_front_uid_only() {
    let fronts = KpasswdFronts::new(4644);
    assert_eq!(fronts.zone_of(4644), Some(FrontZone::Internal));
    assert_eq!(fronts.zone_of(4645), None);
    assert_eq!(fronts.zone_of(0), None);
    assert_eq!(KpasswdFronts::new(0).zone_of(0), None);
}

/// docs/53 §5.6 step 1 (`Ping` → the connection's zone); docs/50 §7.5: a
/// `Ping` is answered with `Pong { Internal }` and the connection stays
/// open; the host is not asked.
#[test]
fn ping_names_the_connection_zone() {
    let mut host = Host::new(Err(HostUnserved::Unavailable));
    let mut connection = KpasswdConnection::new(7, FrontZone::Internal);
    let dispatch = connection.handle(&request_body(&KpasswdRequest::Ping), &mut host);
    assert!(!dispatch.closes());
    assert_eq!(
        reply_of(&dispatch),
        Reply::Message(KpasswdReply::Pong {
            zone: FrontZone::Internal
        })
    );
    assert!(host.calls.is_empty());
    assert!(!connection.is_closed());
    assert_eq!(connection.id(), 7);
}

/// docs/53 §5.5 (`SealedReply`), §5.7; RFC 3244 §2 (one request, one
/// reply): the host receives the request exactly as sent, with the
/// connection's zone; its sealed answer is relayed, and the connection then
/// closes — a second request on it is not processed.
#[test]
fn a_change_reaches_the_host_once_and_closes_the_connection() {
    let mut host = Host::new(Ok(KpasswdAnswer::Sealed(sealed())));
    let mut connection = KpasswdConnection::new(1, FrontZone::Internal);
    let body = request_body(&KpasswdRequest::ChangePassword(request()));
    let dispatch = connection.handle(&body, &mut host);
    assert!(dispatch.closes());
    assert_eq!(
        reply_of(&dispatch),
        Reply::Message(KpasswdReply::Sealed(sealed()))
    );
    assert_eq!(host.calls, vec![(FrontZone::Internal, request())]);
    assert!(connection.is_closed());
    assert!(matches!(
        connection.handle(&body, &mut host),
        Dispatch::Close
    ));
    assert_eq!(host.calls.len(), 1);
}

/// docs/53 §5.7 (no context to seal in ⇒ the front's KRB-ERROR with
/// AUTHERROR or HARDERROR).
#[test]
fn an_unsealed_answer_is_relayed() {
    for code in [UnsealedCode::AuthError, UnsealedCode::HardError] {
        let mut host = Host::new(Ok(KpasswdAnswer::Unsealed(code)));
        let mut connection = KpasswdConnection::new(1, FrontZone::Internal);
        let dispatch = connection.handle(
            &request_body(&KpasswdRequest::ChangePassword(request())),
            &mut host,
        );
        assert!(dispatch.closes());
        assert_eq!(
            reply_of(&dispatch),
            Reply::Message(KpasswdReply::Unsealed(code))
        );
    }
}

/// docs/53 §5.6 step 1 ("full ⇒ `Busy` ⇒ the front answers HARDERROR");
/// docs/50 §3.6, §3.7 (`Busy`, `Unavailable` + close).
#[test]
fn host_refusals_are_shared_refusals_and_close() {
    for (unserved, refused) in [
        (HostUnserved::Busy, Refused::Busy),
        (HostUnserved::Unavailable, Refused::Unavailable),
    ] {
        let mut host = Host::new(Err(unserved));
        let mut connection = KpasswdConnection::new(1, FrontZone::Internal);
        let dispatch = connection.handle(
            &request_body(&KpasswdRequest::ChangePassword(request())),
            &mut host,
        );
        assert!(dispatch.closes());
        assert_eq!(reply_of(&dispatch), Reply::Refused(refused));
        assert!(connection.is_closed());
    }
}

/// docs/50 §3.3 (malformed ⇒ `Refused{Malformed}` + close; unknown kind ⇒
/// close without a reply; version ⇒ `Refused{VersionMismatch}`): nothing
/// malformed reaches the host — a KRB-PRIV that is an EncKrbPrivPart (RFC
/// 4120 §5.7.1, §5.10) included.
#[test]
fn nothing_malformed_reaches_the_host() {
    let good = request_body(&KpasswdRequest::ChangePassword(request()));
    let mut cleartext = good.clone();
    cleartext[52] = ENC_KRB_PRIV_PART;
    let mut unknown = good.clone();
    unknown[3] = 0x09;
    let mut version = good.clone();
    version[2] = 9;
    for (body, expected) in [
        (cleartext, Some(Refused::Malformed)),
        (good[..good.len() - 2].to_vec(), Some(Refused::Malformed)),
        (version, Some(Refused::VersionMismatch)),
        (unknown, None),
    ] {
        let mut host = Host::new(Ok(KpasswdAnswer::Sealed(sealed())));
        let mut connection = KpasswdConnection::new(1, FrontZone::Internal);
        let dispatch = connection.handle(&body, &mut host);
        assert!(dispatch.closes());
        match expected {
            Some(refused) => assert_eq!(reply_of(&dispatch), Reply::Refused(refused)),
            None => assert!(dispatch.frame().is_none()),
        }
        assert!(host.calls.is_empty());
        assert!(connection.is_closed());
    }
}
