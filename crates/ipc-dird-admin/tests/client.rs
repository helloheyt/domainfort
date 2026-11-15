//! Tier 1: admind's client rules over a scripted connection (docs/51 §7.1:
//! "the client verifies before sending that the server's uid = dird's
//! uid", precedent A-63; docs/50 R50-7, §3.6, §3.7; A-87: idle check before
//! reuse, never a resend).
//!
//! The scripted connection records every frame sent and answers from a
//! queue of reply bodies built with this crate's own encoder. Test data
//! only; no vector from any other implementation.

use core::time::Duration;
use ipc::{FrameLimit, Refused};
use ipc_dird_admin::{
    encode_refusal, encode_reply, AdminClient, Auth, ClientConfigError, Connection, Connector,
    LookupKey, Operation, RefusalStatus, Reply, Request, TransportError, Unserved,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use zeroize::Zeroizing;

const DIRD_UID: u32 = 802;

#[derive(Default)]
struct Script {
    /// Reply bodies, in order.
    replies: VecDeque<Vec<u8>>,
    /// Frames sent, per connection opened.
    sent: Vec<Vec<Vec<u8>>>,
    /// The uid the next connection reports.
    uid: u32,
    /// Whether the held connection fails its idle check.
    stale: bool,
}

struct ScriptConnector(Rc<RefCell<Script>>);

struct ScriptConnection {
    script: Rc<RefCell<Script>>,
    index: usize,
    uid: u32,
}

impl Connector for ScriptConnector {
    type Connection = ScriptConnection;
    fn connect(&mut self) -> Result<ScriptConnection, TransportError> {
        let mut s = self.0.borrow_mut();
        s.sent.push(Vec::new());
        s.stale = false;
        Ok(ScriptConnection {
            script: Rc::clone(&self.0),
            index: s.sent.len() - 1,
            uid: s.uid,
        })
    }
}

impl Connection for ScriptConnection {
    fn peer_uid(&self) -> Result<u32, TransportError> {
        Ok(self.uid)
    }
    fn exchange(
        &mut self,
        frame: &[u8],
        _reply_limit: FrameLimit,
        _deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        let mut s = self.script.borrow_mut();
        s.sent[self.index].push(frame.to_vec());
        s.replies
            .pop_front()
            .map(Zeroizing::new)
            .ok_or(TransportError::Closed)
    }
    fn check_idle(&mut self) -> Result<(), TransportError> {
        if self.script.borrow().stale {
            Err(TransportError::Closed)
        } else {
            Ok(())
        }
    }
}

fn client(script: &Rc<RefCell<Script>>) -> AdminClient<ScriptConnector> {
    AdminClient::new(
        ScriptConnector(Rc::clone(script)),
        DIRD_UID,
        Duration::from_secs(5),
    )
    .unwrap()
}

fn lookup() -> Request {
    Request::Operation {
        auth: Auth::of(vec![1, 2, 3]),
        operation: Operation::Lookup(LookupKey::SamAccountName("carol".into())),
    }
}

fn body(reply: &Reply) -> Vec<u8> {
    encode_reply(reply).unwrap().body().to_vec()
}

/// docs/50 §3.2: a root server uid is never accepted.
#[test]
fn root_server_uid_is_refused() {
    let script = Rc::new(RefCell::new(Script::default()));
    assert_eq!(
        AdminClient::new(ScriptConnector(script), 0, Duration::from_secs(1)).err(),
        Some(ClientConfigError::RootServerUid)
    );
}

/// docs/51 §7.1; A-63: a peer that is not dird receives nothing.
#[test]
fn nothing_is_sent_to_a_peer_that_is_not_dird() {
    let script = Rc::new(RefCell::new(Script {
        uid: 4242,
        ..Script::default()
    }));
    let mut c = client(&script);
    assert_eq!(c.call(&lookup()), Err(Unserved::PeerMismatch));
    assert!(script.borrow().sent.iter().all(Vec::is_empty));
    assert!(!c.is_connected());
}

/// docs/51 §7.3: dird's own answer — a refusal included — is the result;
/// the connection is kept for the next call (one request in flight).
#[test]
fn dirds_answers_pass_through() {
    let script = Rc::new(RefCell::new(Script {
        uid: DIRD_UID,
        ..Script::default()
    }));
    script
        .borrow_mut()
        .replies
        .push_back(body(&Reply::Refused(RefusalStatus::NotFound)));
    script.borrow_mut().replies.push_back(body(&Reply::Pong));
    let mut c = client(&script);
    assert_eq!(
        c.call(&lookup()),
        Ok(Reply::Refused(RefusalStatus::NotFound))
    );
    assert!(c.is_connected());
    assert_eq!(c.ping(), Ok(()));
    assert_eq!(script.borrow().sent.len(), 1, "one connection for both");
}

/// docs/50 §3.7 (R50-8): the shared refusal and a reply that answers
/// another request are not served; the connection is dropped.
#[test]
fn shared_refusal_and_mismatched_reply() {
    let script = Rc::new(RefCell::new(Script {
        uid: DIRD_UID,
        ..Script::default()
    }));
    script
        .borrow_mut()
        .replies
        .push_back(encode_refusal(Refused::Busy).unwrap().body().to_vec());
    script.borrow_mut().replies.push_back(body(&Reply::Pong));
    script.borrow_mut().replies.push_back(body(&Reply::Done));
    let mut c = client(&script);
    assert_eq!(c.call(&lookup()), Err(Unserved::Refused(Refused::Busy)));
    assert!(!c.is_connected());
    assert!(matches!(
        c.call(&lookup()),
        Err(Unserved::UnexpectedReply(_))
    ));
    assert!(matches!(c.ping(), Err(Unserved::UnexpectedReply(_))));
}

/// docs/questions/Q-312 (A-82), A-87: a held connection that fails its idle
/// check is replaced before the request is sent; a request that failed after
/// it was written is not sent again.
#[test]
fn idle_check_and_no_resend() {
    let script = Rc::new(RefCell::new(Script {
        uid: DIRD_UID,
        ..Script::default()
    }));
    script.borrow_mut().replies.push_back(body(&Reply::Pong));
    script.borrow_mut().replies.push_back(body(&Reply::Pong));
    let mut c = client(&script);
    c.ping().unwrap();
    script.borrow_mut().stale = true;
    c.ping().unwrap();
    {
        let s = script.borrow();
        assert_eq!(s.sent.len(), 2);
        assert_eq!(s.sent[0].len(), 1);
        assert_eq!(s.sent[1].len(), 1);
    }
    // No reply queued: the exchange fails after the write; one frame only.
    assert_eq!(
        c.call(&lookup()),
        Err(Unserved::Transport(TransportError::Closed))
    );
    assert_eq!(script.borrow().sent[1].len(), 2);
}
