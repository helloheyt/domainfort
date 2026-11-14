//! Tier 1: the kdc's client of the directory-view channel over a scripted
//! in-process connection — the server-uid check before anything is sent,
//! the policy-version check of `BeginView`, the mapping of every way dird
//! may not serve a call to `Unavailable` (never `Failed`), the view's own
//! answers passed through unchanged, and the `Pip` methods the KDC does not
//! need answered locally.
//!
//! Sources: docs/50 R50-2 (policy version per view), R50-3 (the client
//! verifies the server's uid), R50-7, R50-8 (§3.7: not served ⇒
//! `Unavailable`), §3.4 (the `Pip` subset; "the other `Pip` methods … return
//! `PipError` locally without asking"), §3.6 (deadline); docs/47 §8.2; D40;
//! A-56; docs/questions/Q-466 (task R9: the client exists only with dird's
//! domain pinned — `DirectoryClient::connect`). Every value is hand-made
//! (tests/common).

mod common;

use common::*;
use core::time::Duration;
use ipc::{decode_body, encode_refused, Direction, FrameLimit, Refused};
use ipc_directory::typed::{Query, Request};
use ipc_directory::wire::{DirectoryReply, DirectoryRequest};
use ipc_directory::{
    ClientConfigError, ConnectError, Connection, Connector, DirectoryClient, TransportError,
    UnavailableDirectory, Unserved, ViewFailure, DIRECTORY_CHANNEL,
};
use kdc::{AccountSource, AccountSourceError};
use pdp::{Dn, Pip, PipError, PolicyVersion, Resource, Tier};
use std::cell::RefCell;
use std::collections::{BTreeSet, VecDeque};
use std::rc::Rc;
use zeroize::Zeroizing;

const DIRD_UID: u32 = 61002;
const VERSION: PolicyVersion = PolicyVersion(7);

/// What the scripted dird answers and what it received.
#[derive(Default)]
struct Script {
    uid: u32,
    replies: VecDeque<Result<Vec<u8>, TransportError>>,
    received: Vec<Request>,
    connects: usize,
}

#[derive(Clone)]
struct ScriptConnector(Rc<RefCell<Script>>);

struct ScriptConnection(Rc<RefCell<Script>>);

impl Connector for ScriptConnector {
    type Connection = ScriptConnection;
    fn connect(&mut self) -> Result<ScriptConnection, TransportError> {
        self.0.borrow_mut().connects += 1;
        Ok(ScriptConnection(Rc::clone(&self.0)))
    }
}

impl Connection for ScriptConnection {
    fn peer_uid(&self) -> Result<u32, TransportError> {
        Ok(self.0.borrow().uid)
    }

    fn exchange(
        &mut self,
        frame: &[u8],
        _reply_limit: FrameLimit,
        _deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        let wire: DirectoryRequest =
            decode_body(DIRECTORY_CHANNEL, Direction::Request, &frame[4..]).unwrap();
        let mut script = self.0.borrow_mut();
        script.received.push(Request::from_wire(&wire).unwrap());
        script
            .replies
            .pop_front()
            .unwrap_or(Err(TransportError::Closed))
            .map(Zeroizing::new)
    }

    /// The scripted connection lives as long as the script: always usable
    /// (the check has no default since task R9).
    fn check_idle(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

/// A client connected to the scripted dird (its start-time
/// `DescribeDomain` answered with [`domain`], task R9); the script's record
/// starts after it.
fn setup(uid: u32) -> (Rc<RefCell<Script>>, DirectoryClient<ScriptConnector>) {
    let script = Rc::new(RefCell::new(Script {
        uid,
        ..Script::default()
    }));
    push(&script, &DirectoryReply::from_domain(&domain()));
    let client = DirectoryClient::connect(
        ScriptConnector(Rc::clone(&script)),
        DIRD_UID,
        Duration::from_secs(2),
        VERSION,
    )
    .unwrap();
    assert_eq!(client.domain(), &domain());
    {
        let mut script = script.borrow_mut();
        assert_eq!(script.received, [Request::DescribeDomain]);
        script.received.clear();
        script.connects = 0;
    }
    (script, client)
}

fn push(script: &Rc<RefCell<Script>>, reply: &DirectoryReply) {
    script.borrow_mut().replies.push_back(Ok(reply_body(reply)));
}

fn push_refused(script: &Rc<RefCell<Script>>, refused: Refused) {
    let frame = encode_refused(DIRECTORY_CHANNEL, refused).unwrap();
    script
        .borrow_mut()
        .replies
        .push_back(Ok(frame.body().to_vec()));
}

fn begun(view: u64, version: u64) -> DirectoryReply {
    DirectoryReply::ViewBegun {
        view,
        policy_version: version,
    }
}

fn alice() -> krb_proto::PrincipalName {
    name(1, &["alice"])
}

/// docs/50 §3.2 ("uid 0 is never mapped"), Q-245 item 5 (the same rule for
/// the server identity).
#[test]
fn a_root_server_uid_is_refused() {
    let script = Rc::new(RefCell::new(Script::default()));
    assert_eq!(
        DirectoryClient::connect(ScriptConnector(script), 0, Duration::from_secs(2), VERSION).err(),
        Some(ConnectError::Config(ClientConfigError::RootServerUid))
    );
}

/// docs/50 R50-3; Q-466 (task R9): a peer that is not dird's uid receives
/// nothing — there is no client at all.
#[test]
fn a_wrong_peer_uid_receives_nothing() {
    let script = Rc::new(RefCell::new(Script {
        uid: DIRD_UID + 1,
        ..Script::default()
    }));
    assert_eq!(
        DirectoryClient::connect(
            ScriptConnector(Rc::clone(&script)),
            DIRD_UID,
            Duration::from_secs(2),
            VERSION
        )
        .err(),
        Some(ConnectError::Unserved(Unserved::PeerMismatch))
    );
    assert!(script.borrow().received.is_empty());
}

/// docs/50 R50-2, §3.4, §7.5 step 4; Q-466 (task R9): a dird whose
/// start-time `DescribeDomain` names another policy version gives no client
/// (`PolicyVersionMismatch`: the kdc does not start); only `DescribeDomain`
/// was sent.
#[test]
fn a_dird_of_another_policy_version_gives_no_client() {
    let script = Rc::new(RefCell::new(Script {
        uid: DIRD_UID,
        ..Script::default()
    }));
    let mut other = domain();
    other.policy_version = PolicyVersion(8);
    push(&script, &DirectoryReply::from_domain(&other));
    assert_eq!(
        DirectoryClient::connect(
            ScriptConnector(Rc::clone(&script)),
            DIRD_UID,
            Duration::from_secs(2),
            VERSION
        )
        .err(),
        Some(ConnectError::Unserved(Unserved::PolicyVersionMismatch {
            dird: PolicyVersion(8)
        }))
    );
    assert_eq!(script.borrow().received, [Request::DescribeDomain]);
}

/// docs/50 R50-2, §3.4: a view carries the request's queries with its id,
/// answers pass through unchanged (records, `Failed`, `NotFound`), and
/// dropping the view sends `EndView`.
#[test]
fn a_view_carries_queries_and_passes_answers_through() {
    let (script, mut client) = setup(DIRD_UID);
    push(&script, &begun(41, 7));
    push(
        &script,
        &DirectoryReply::from_client(&Ok(Some(client_account()))),
    );
    push(&script, &DirectoryReply::from_service(&Ok(None)));
    push(
        &script,
        &DirectoryReply::from_client(&Err(AccountSourceError::Failed)),
    );
    let groups: BTreeSet<_> = [sid(513), sid(1030)].into_iter().collect();
    push(&script, &DirectoryReply::from_groups(&Ok(groups.clone())));
    push(&script, &DirectoryReply::from_tier(&Ok(Tier::Tier1)));
    push(
        &script,
        &DirectoryReply::from_groups(&Err(PipError::NotFound)),
    );
    push(&script, &DirectoryReply::ViewEnded);
    {
        let view = client.begin_view().unwrap();
        assert_eq!(view.id(), 41);
        assert_eq!(view.client(&realm(), &alice()), Ok(Some(client_account())));
        assert_eq!(view.service(&realm(), &alice()), Ok(None));
        // The directory's own "cannot tell" stays Failed (KRB_ERR_GENERIC),
        // exactly as the in-process view answers it.
        assert_eq!(
            view.client(&realm(), &alice()),
            Err(AccountSourceError::Failed)
        );
        assert_eq!(view.expand_groups(&sid(1010)), Ok(groups.clone()));
        assert_eq!(view.tier_of(&sid(1010), &groups), Ok(Tier::Tier1));
        assert_eq!(view.expand_groups(&sid(1)), Err(PipError::NotFound));
        assert!(view.is_open());
    }
    let received = script.borrow().received.clone();
    assert_eq!(received.len(), 8);
    assert_eq!(received[0], Request::BeginView);
    assert_eq!(
        received[1],
        Request::Query {
            view: 41,
            query: Query::Client {
                realm: realm(),
                name: alice()
            }
        }
    );
    assert!(received[1..7]
        .iter()
        .all(|r| matches!(r, Request::Query { view: 41, .. })));
    assert_eq!(received[7], Request::EndView { view: 41 });
    assert!(client.is_connected());
}

/// docs/50 R50-2, §3.4 ("if the `policy_version` dird returned ≠ the version
/// of the kdc's `PolicySnapshot` ⇒ the request fails closed and the kdc
/// reloads"): the view is refused and the connection dropped (dird releases
/// the view); after the kdc reloads, the next view is accepted.
#[test]
fn a_different_policy_version_refuses_the_view() {
    let (script, mut client) = setup(DIRD_UID);
    push(&script, &begun(1, 8));
    assert_eq!(
        client.begin_view().err(),
        Some(Unserved::PolicyVersionMismatch {
            dird: PolicyVersion(8)
        })
    );
    assert!(!client.is_connected());
    client.set_policy_version(PolicyVersion(8));
    // The new connection describes the domain first (task R9) — now of the
    // version the kdc reloaded.
    let mut reloaded = domain();
    reloaded.policy_version = PolicyVersion(8);
    push(&script, &DirectoryReply::from_domain(&reloaded));
    push(&script, &begun(2, 8));
    push(&script, &DirectoryReply::ViewEnded);
    client.begin_view().unwrap().end().unwrap();
    assert_eq!(script.borrow().connects, 1);
}

/// docs/50 R50-8, §3.6, §3.7; A-56: every way dird may not serve a query —
/// each shared refusal, each transport failure, a view-protocol refusal, an
/// answer to another request — is `Unavailable` for the account source
/// (never `Failed`, never "no such principal") and for the PIP; the view is
/// then broken and later queries are `Unavailable` without being sent.
#[test]
fn not_served_is_unavailable_never_failed() {
    type Failure = Box<dyn Fn(&Rc<RefCell<Script>>)>;
    let failures: Vec<Failure> = vec![
        Box::new(|s| push_refused(s, Refused::Busy)),
        Box::new(|s| push_refused(s, Refused::Unavailable)),
        Box::new(|s| push_refused(s, Refused::Malformed)),
        Box::new(|s| push_refused(s, Refused::VersionMismatch)),
        Box::new(|s| {
            s.borrow_mut()
                .replies
                .push_back(Err(TransportError::DeadlineExceeded))
        }),
        Box::new(|s| {
            s.borrow_mut()
                .replies
                .push_back(Err(TransportError::Closed))
        }),
        Box::new(|s| {
            s.borrow_mut()
                .replies
                .push_back(Err(TransportError::Framing))
        }),
        Box::new(|s| s.borrow_mut().replies.push_back(Err(TransportError::Io))),
        Box::new(|s| push(s, &DirectoryReply::ViewFailure(ViewFailure::Expired))),
        Box::new(|s| push(s, &DirectoryReply::ViewFailure(ViewFailure::UnknownView))),
        Box::new(|s| push(s, &DirectoryReply::Pong)),
        Box::new(|s| {
            s.borrow_mut()
                .replies
                .push_back(Ok(vec![0x44, 0x52, 1, 0x82, 2]))
        }),
    ];
    for (n, fail) in failures.iter().enumerate() {
        for method in 0..4 {
            let (script, mut client) = setup(DIRD_UID);
            push(&script, &begun(5, 7));
            fail(&script);
            let view = client.begin_view().unwrap();
            match method {
                0 => assert_eq!(
                    view.client(&realm(), &alice()),
                    Err(AccountSourceError::Unavailable),
                    "case {n}"
                ),
                1 => assert_eq!(
                    view.service(&realm(), &alice()),
                    Err(AccountSourceError::Unavailable),
                    "case {n}"
                ),
                2 => assert_eq!(
                    view.expand_groups(&sid(1010)),
                    Err(PipError::Unavailable),
                    "case {n}"
                ),
                _ => assert_eq!(
                    view.tier_of(&sid(1010), &BTreeSet::new()),
                    Err(PipError::Unavailable),
                    "case {n}"
                ),
            }
            assert!(!view.is_open(), "case {n}");
            let sent = script.borrow().received.len();
            assert_eq!(
                view.client(&realm(), &alice()),
                Err(AccountSourceError::Unavailable)
            );
            drop(view);
            // Nothing more was sent: neither the query nor an EndView.
            assert_eq!(script.borrow().received.len(), sent, "case {n}");
        }
    }
}

/// docs/50 R50-8, §3.7: `BeginView` not served — dird down, Busy, the view
/// bound reached — is an error the kdc answers through
/// `UnavailableDirectory`, whose every answer is `Unavailable`.
#[test]
fn no_view_means_the_unavailable_directory() {
    let (script, mut client) = setup(DIRD_UID);
    assert_eq!(
        client.begin_view().err(),
        Some(Unserved::Transport(TransportError::Closed))
    );
    // Each later call opens a new connection, which describes the domain
    // first (task R9).
    push(&script, &DirectoryReply::from_domain(&domain()));
    push_refused(&script, Refused::Busy);
    assert_eq!(
        client.begin_view().err(),
        Some(Unserved::Refused(Refused::Busy))
    );
    push(&script, &DirectoryReply::from_domain(&domain()));
    push(
        &script,
        &DirectoryReply::ViewFailure(ViewFailure::ViewLimit),
    );
    assert_eq!(
        client.begin_view().err(),
        Some(Unserved::View(ViewFailure::ViewLimit))
    );
    let none = UnavailableDirectory;
    assert_eq!(
        none.client(&realm(), &alice()),
        Err(AccountSourceError::Unavailable)
    );
    assert_eq!(
        none.service(&realm(), &alice()),
        Err(AccountSourceError::Unavailable)
    );
    assert_eq!(none.expand_groups(&sid(1)), Err(PipError::Unavailable));
    assert_eq!(
        none.tier_of(&sid(1), &BTreeSet::new()),
        Err(PipError::Unavailable)
    );
    assert_eq!(
        none.object_tier(&Resource::RootDse),
        Err(PipError::Unavailable)
    );
}

/// docs/50 §3.4 ("the remaining `Pip` methods — the adapter on the kdc side
/// returns `PipError` locally without asking ⇒ Deny"); docs/47 §8.2; D40.
#[test]
fn pip_methods_the_kdc_does_not_need_are_answered_locally() {
    let (script, mut client) = setup(DIRD_UID);
    push(&script, &begun(3, 7));
    push(&script, &DirectoryReply::ViewEnded);
    let view = client.begin_view().unwrap();
    let dn = Dn::new(vec![String::from("dc=example")]);
    let attr = pdp::AttrId(dtyp::Guid {
        data1: 1,
        data2: 2,
        data3: 3,
        data4: [4; 8],
    });
    assert_eq!(
        view.object_tier(&Resource::RootDse),
        Err(PipError::Unavailable)
    );
    assert_eq!(
        view.security_descriptor(&dn).err(),
        Some(PipError::Unavailable)
    );
    assert_eq!(view.attr_class(&attr).err(), Some(PipError::Unavailable));
    assert_eq!(view.object_classes(&dn).err(), Some(PipError::Unavailable));
    assert_eq!(view.object_sid(&dn), Err(PipError::Unavailable));
    assert_eq!(view.property_set(&attr), Err(PipError::Unavailable));
    // None of them was sent; the view is still usable.
    assert_eq!(script.borrow().received.len(), 1);
    assert!(view.is_open());
    view.end().unwrap();
}

/// docs/50 §3.4, §7.5 (`DescribeDomain` → `KdcConfig::new(realm, krbtgt)`),
/// §7.5 (`Ping`).
#[test]
fn describe_domain_and_ping() {
    let (script, mut client) = setup(DIRD_UID);
    push(&script, &DirectoryReply::from_domain(&domain()));
    push(&script, &DirectoryReply::Pong);
    push(&script, &DirectoryReply::Pong);
    assert_eq!(client.describe_domain(), Ok(domain()));
    assert_eq!(client.ping(), Ok(()));
    assert!(matches!(
        client.describe_domain(),
        Err(Unserved::UnexpectedReply(_))
    ));
    assert!(!client.is_connected());
}
