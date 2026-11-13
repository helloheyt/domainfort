//! Tier 1 (docs/50 §9: in-process): dird's dispatcher over a temporary
//! dirstore built with the phase-1 schema and the directory-pip fixtures
//! (crates/directory-pip/tests/common, reused through `#[path]`), reached by
//! the kdc's real client (`ipc_directory::DirectoryClient` / `RemoteView`)
//! through an in-process loopback connection.
//!
//! * every `AccountSource` and `Pip` answer through the remote view equals
//!   the direct `DirectoryView`'s, for every account of the standard
//!   directory, unknown and malformed names, and a tier map;
//! * view pinning — a write committed after `BeginView` is invisible to the
//!   view until a new one is taken;
//! * the view lifetime, the bound on open views, one view per connection,
//!   release at disconnect;
//! * the refusal dispositions; `DescribeDomain`; start-up refusals.
//!
//! Sources: docs/50 R50-2, §3.3, §3.4, §7.5, §9; docs/47 §1.4 (R47-2), §8;
//! docs/11 §6 (snapshot semantics); D39; A-53; A-59. Every value is
//! hand-made (the fixtures' own data).

#[path = "../../directory-pip/tests/common/mod.rs"]
mod common;

use common::*;
use core::time::Duration;
use directory_pip::TierMap;
use ipc::{decode_reply, encode_frame, Direction, FrameLimit, Refused, Reply};
use ipc_directory::typed::{Query, Request};
use ipc_directory::wire::DirectoryReply;
use ipc_directory::{
    Connection, Connector, DirectoryClient, TransportError, Unserved, ViewFailure,
    DIRECTORY_CHANNEL,
};
use ipc_directory_server::{DirectoryServer, Dispatch, StartError, ViewLimits};
use kdc::AccountSource;
use krb_proto::constants::{KRB_NT_PRINCIPAL, KRB_NT_SRV_HST};
use pdp::{Pip, PolicyVersion, Tier};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::Instant;
use zeroize::Zeroizing;

const DIRD_UID: u32 = 61002;
const VERSION: PolicyVersion = PolicyVersion(3);
const LIMITS: ViewLimits = ViewLimits {
    max_views: 4,
    lifetime: Duration::from_secs(5),
};

/// The kdc's connector, connected in-process to `server`: each connection
/// gets a fresh id, and dropping it releases its view (as a closed socket
/// does in dird).
struct Loopback<'s, 'a> {
    server: &'s RefCell<DirectoryServer<'a>>,
    next: Rc<Cell<u64>>,
}

struct LoopConnection<'s, 'a> {
    server: &'s RefCell<DirectoryServer<'a>>,
    id: u64,
}

impl<'s, 'a> Connector for Loopback<'s, 'a> {
    type Connection = LoopConnection<'s, 'a>;
    fn connect(&mut self) -> Result<LoopConnection<'s, 'a>, TransportError> {
        self.next.set(self.next.get() + 1);
        Ok(LoopConnection {
            server: self.server,
            id: self.next.get(),
        })
    }
}

impl Connection for LoopConnection<'_, '_> {
    fn peer_uid(&self) -> Result<u32, TransportError> {
        Ok(DIRD_UID)
    }

    fn exchange(
        &mut self,
        frame: &[u8],
        _reply_limit: FrameLimit,
        _deadline: Duration,
    ) -> Result<Zeroizing<Vec<u8>>, TransportError> {
        match self
            .server
            .borrow_mut()
            .handle(self.id, &frame[4..], Instant::now())
        {
            Dispatch::Reply(frame) | Dispatch::ReplyAndClose(frame) => {
                Ok(Zeroizing::new(frame.body().to_vec()))
            }
            Dispatch::Close => Err(TransportError::Closed),
        }
    }
}

impl Drop for LoopConnection<'_, '_> {
    fn drop(&mut self) {
        self.server.borrow_mut().release(self.id);
    }
}

fn client<'s, 'a>(server: &'s RefCell<DirectoryServer<'a>>) -> DirectoryClient<Loopback<'s, 'a>> {
    DirectoryClient::new(
        Loopback {
            server,
            next: Rc::new(Cell::new(0)),
        },
        DIRD_UID,
        Duration::from_secs(2),
        VERSION,
    )
    .unwrap()
}

/// A tier map with a subject entry and a subtree entry (A-36).
fn tiers() -> TierMap {
    let principals: BTreeMap<_, _> = [(sid_of(TIER0), Tier::Tier0), (sid_of(STAFF), Tier::Tier2)]
        .into_iter()
        .collect();
    TierMap::new(principals, Vec::new()).unwrap()
}

/// A request body.
fn body(request: &Request) -> Vec<u8> {
    encode_frame(
        DIRECTORY_CHANNEL,
        Direction::Request,
        &request.to_wire().unwrap(),
    )
    .unwrap()
    .body()
    .to_vec()
}

/// The reply of a `Reply` dispatch.
fn reply_of(dispatch: Dispatch) -> DirectoryReply {
    match dispatch {
        Dispatch::Reply(frame) => {
            match decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, frame.body()).unwrap() {
                Reply::Message(reply) => reply,
                Reply::Refused(refused) => panic!("refused {refused:?}"),
            }
        }
        other => panic!("expected a reply, got {other:?}"),
    }
}

/// The refusal of a `ReplyAndClose` dispatch.
fn refusal_of(dispatch: Dispatch) -> Refused {
    match dispatch {
        Dispatch::ReplyAndClose(frame) => {
            match decode_reply::<DirectoryReply>(DIRECTORY_CHANNEL, frame.body()).unwrap() {
                Reply::Refused(refused) => refused,
                Reply::Message(message) => panic!("expected a refusal, got {message:?}"),
            }
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// docs/50 R50-2, §3.4; docs/47 §8.1, §8.2: every `AccountSource` and `Pip`
/// method the kdc asks, through the remote view, equals the direct
/// `DirectoryView` over the same store and tier map — records, `None`,
/// `PipError` and all.
#[test]
fn every_answer_through_the_remote_view_equals_the_direct_view() {
    let d = Dir::standard("ids_equal");
    let tiers = tiers();
    let server =
        RefCell::new(DirectoryServer::new(&d.ctx, &d.store, &tiers, VERSION, LIMITS).unwrap());
    let mut kdc_side = client(&server);
    let remote = kdc_side.begin_view().unwrap();
    let direct = d.view_with(&tiers);

    let other_realm = krb_proto::Realm::new("OTHER.TEST").unwrap();
    let clients = [
        name(KRB_NT_PRINCIPAL, &["alice"]),
        name(KRB_NT_PRINCIPAL, &["bob"]),
        name(KRB_NT_PRINCIPAL, &["rootadmin"]),
        name(KRB_NT_PRINCIPAL, &["ws01$"]),
        name(KRB_NT_PRINCIPAL, &["dc01$"]),
        name(KRB_NT_PRINCIPAL, &["krbtgt"]),
        name(KRB_NT_PRINCIPAL, &["ALICE"]),
        name(KRB_NT_PRINCIPAL, &["nobody"]),
        name(KRB_NT_PRINCIPAL, &["staff"]),
        name(KRB_NT_PRINCIPAL, &["alice", "extra"]),
    ];
    let mut found = 0;
    for client_name in &clients {
        let expected = direct.client(&realm(), client_name);
        found += usize::from(matches!(expected, Ok(Some(_))));
        assert_eq!(
            remote.client(&realm(), client_name),
            expected,
            "{client_name:?}"
        );
        assert_eq!(
            remote.client(&other_realm, client_name),
            direct.client(&other_realm, client_name)
        );
    }
    assert_eq!(found, 5, "alice, bob, rootadmin, ws01$, dc01$");

    let services = [
        name(KRB_NT_SRV_HST, &["host", "ws01.example.test"]),
        name(KRB_NT_SRV_HST, &["ldap", "dc01.example.test"]),
        name(KRB_NT_SRV_HST, &["host", "nowhere.example.test"]),
        name(KRB_NT_SRV_HST, &["host/ws01.example.test"]),
        name(KRB_NT_PRINCIPAL, &["krbtgt", REALM]),
    ];
    let mut found = 0;
    for service_name in &services {
        let expected = direct.service(&realm(), service_name);
        found += usize::from(matches!(expected, Ok(Some(_))));
        assert_eq!(
            remote.service(&realm(), service_name),
            expected,
            "{service_name:?}"
        );
    }
    assert_eq!(found, 2, "ws01 and dc01");

    let subjects = [
        ALICE, BOB, ROOTADMIN, WS01, DC01, STAFF, ALLSTAFF, MAIL, HIDDEN, TIER0, KRBTGT,
    ];
    for id in subjects {
        let sid = sid_of(id);
        let groups = direct.expand_groups(&sid);
        assert_eq!(remote.expand_groups(&sid), groups, "expand {id}");
        let set = groups.unwrap_or_default();
        assert_eq!(
            remote.tier_of(&sid, &set),
            direct.tier_of(&sid, &set),
            "tier {id}"
        );
        assert_eq!(
            remote.tier_of(&sid, &BTreeSet::new()),
            direct.tier_of(&sid, &BTreeSet::new())
        );
    }
    let stranger = account_sid(4242);
    assert_eq!(
        remote.expand_groups(&stranger),
        direct.expand_groups(&stranger)
    );
    assert!(remote.expand_groups(&stranger).is_err());
    assert_eq!(
        remote.tier_of(&stranger, &[sid_of(TIER0)].into_iter().collect()),
        Ok(Tier::Tier0)
    );
    assert!(remote.is_open());
    remote.end().unwrap();
    assert_eq!(server.borrow().open_views(), 0);
}

/// docs/50 §3.4 ("each connection pins one snapshot"); docs/32 §6 (D39):
/// a write committed after `BeginView` is not visible through that view; a
/// new view sees it.
#[test]
fn a_view_is_pinned_to_its_snapshot() {
    let d = Dir::standard("ids_pinned");
    let tiers = TierMap::empty();
    let server =
        RefCell::new(DirectoryServer::new(&d.ctx, &d.store, &tiers, VERSION, LIMITS).unwrap());
    let mut kdc_side = client(&server);
    let alice = name(KRB_NT_PRINCIPAL, &["alice"]);
    let bob = name(KRB_NT_PRINCIPAL, &["bob"]);
    {
        let view = kdc_side.begin_view().unwrap();
        let before = view.client(&realm(), &alice).unwrap().unwrap();
        assert!(before.state.enabled);
        // Disable alice and delete bob, committed after BeginView.
        d.set(
            ALICE,
            "userAccountControl",
            vec![bits(
                uac::ADS_UF_NORMAL_ACCOUNT | uac::ADS_UF_ACCOUNT_DISABLE,
            )],
        );
        let mut txn = d.store.begin_write().unwrap();
        txn.delete_object(guid(BOB), &d.origin()).unwrap();
        txn.commit().unwrap();
        assert_eq!(view.client(&realm(), &alice).unwrap().unwrap(), before);
        assert!(view.client(&realm(), &bob).unwrap().is_some());
        // The direct view taken now sees the writes.
        let fresh = d.view();
        assert!(
            !fresh
                .client(&realm(), &alice)
                .unwrap()
                .unwrap()
                .state
                .enabled
        );
        assert!(fresh.client(&realm(), &bob).unwrap().is_none());
    }
    let view = kdc_side.begin_view().unwrap();
    assert!(
        !view
            .client(&realm(), &alice)
            .unwrap()
            .unwrap()
            .state
            .enabled
    );
    assert!(view.client(&realm(), &bob).unwrap().is_none());
}

/// docs/50 §3.4 ("one view open per connection, expires after ≤ 5 s"):
/// the lifetime on the server's monotonic clock, the sweep, one view per
/// connection, ids checked, release at disconnect, and the bound on open
/// views.
#[test]
fn views_have_a_lifetime_a_bound_and_one_per_connection() {
    let d = Dir::standard("ids_limits");
    let tiers = TierMap::empty();
    let limits = ViewLimits {
        max_views: 2,
        lifetime: Duration::from_secs(5),
    };
    let mut server = DirectoryServer::new(&d.ctx, &d.store, &tiers, VERSION, limits).unwrap();
    let t0 = Instant::now();
    let begin = body(&Request::BeginView);
    let ping = |view| {
        body(&Request::Query {
            view,
            query: Query::ExpandGroups { sid: sid_of(ALICE) },
        })
    };

    // Connection 1: a view; a second BeginView on it is refused.
    let DirectoryReply::ViewBegun {
        view: v1,
        policy_version,
    } = reply_of(server.handle(1, &begin, t0))
    else {
        panic!("view")
    };
    assert_eq!(policy_version, VERSION.0);
    assert_eq!(
        reply_of(server.handle(1, &begin, t0)),
        DirectoryReply::ViewFailure(ViewFailure::ViewOpen)
    );
    // A query with another id, or on a connection with no view.
    assert_eq!(
        reply_of(server.handle(1, &ping(v1 + 100), t0)),
        DirectoryReply::ViewFailure(ViewFailure::UnknownView)
    );
    assert_eq!(
        reply_of(server.handle(9, &ping(v1), t0)),
        DirectoryReply::ViewFailure(ViewFailure::UnknownView)
    );
    // Connection 2 takes the second slot; connection 3 meets the bound.
    let DirectoryReply::ViewBegun { view: v2, .. } = reply_of(server.handle(2, &begin, t0)) else {
        panic!("view")
    };
    assert_ne!(v1, v2);
    assert_eq!(
        reply_of(server.handle(3, &begin, t0)),
        DirectoryReply::ViewFailure(ViewFailure::ViewLimit)
    );
    // Connection 2 disconnects: its slot frees.
    assert!(server.release(2));
    let DirectoryReply::ViewBegun { view: v3, .. } = reply_of(server.handle(3, &begin, t0)) else {
        panic!("view")
    };
    assert_eq!(server.open_views(), 2);
    // Just inside the lifetime: answered. At the lifetime: Expired.
    let inside = t0 + Duration::from_millis(4999);
    assert!(matches!(
        reply_of(server.handle(1, &ping(v1), inside)),
        DirectoryReply::Groups(_)
    ));
    let at = t0 + Duration::from_secs(5);
    assert_eq!(
        reply_of(server.handle(1, &ping(v1), at)),
        DirectoryReply::ViewFailure(ViewFailure::Expired)
    );
    // The sweep at `at` released connection 3's view as well.
    assert_eq!(server.open_views(), 0);
    assert_eq!(
        reply_of(server.handle(3, &ping(v3), at)),
        DirectoryReply::ViewFailure(ViewFailure::UnknownView)
    );
    // EndView with the right id releases; with a wrong id it is refused.
    let DirectoryReply::ViewBegun { view: v4, .. } = reply_of(server.handle(1, &begin, at)) else {
        panic!("view")
    };
    assert_eq!(
        reply_of(server.handle(1, &body(&Request::EndView { view: v4 + 1 }), at)),
        DirectoryReply::ViewFailure(ViewFailure::UnknownView)
    );
    assert_eq!(
        reply_of(server.handle(1, &body(&Request::EndView { view: v4 }), at)),
        DirectoryReply::ViewEnded
    );
    assert_eq!(server.open_views(), 0);
    // `expire` alone releases an old view.
    let _ = reply_of(server.handle(5, &begin, at));
    assert_eq!(server.expire(at + Duration::from_secs(5)), 1);
}

/// docs/50 §3.3; A-59: bad magic or unknown kind ⇒ close without a reply;
/// wrong version ⇒ `VersionMismatch` + close; a malformed payload (also a
/// SID the strict decoder refuses) ⇒ `Malformed` + close.
#[test]
fn refusal_dispositions_follow_the_table() {
    let d = Dir::standard("ids_refusals");
    let tiers = TierMap::empty();
    let mut server = DirectoryServer::new(&d.ctx, &d.store, &tiers, VERSION, LIMITS).unwrap();
    let now = Instant::now();
    let good = body(&Request::Ping);
    assert_eq!(reply_of(server.handle(1, &good, now)), DirectoryReply::Pong);

    let mut magic = good.clone();
    magic[0] ^= 0xFF;
    assert!(matches!(server.handle(1, &magic, now), Dispatch::Close));
    let mut kind = good.clone();
    kind[3] = 0x7F;
    assert!(matches!(server.handle(1, &kind, now), Dispatch::Close));
    let mut version = good.clone();
    version[2] = 2;
    assert_eq!(
        refusal_of(server.handle(1, &version, now)),
        Refused::VersionMismatch
    );
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        refusal_of(server.handle(1, &trailing, now)),
        Refused::Malformed
    );
    let mut bad_sid = body(&Request::Query {
        view: 1,
        query: Query::ExpandGroups { sid: sid_of(ALICE) },
    });
    let revision_at = bad_sid.len() - 28;
    bad_sid[revision_at] = 2;
    assert_eq!(
        refusal_of(server.handle(1, &bad_sid, now)),
        Refused::Malformed
    );
    assert!(matches!(server.handle(1, &[], now), Dispatch::Close));
}

/// docs/50 §3.4, §7.5 step 4; docs/47 §1.4 (R47-2); A-53: `DescribeDomain`
/// answers the realm, the naming context, the krbtgt handle (domain SID ‖
/// 502) and the policy version.
#[test]
fn describe_domain_answers_the_krbtgt_handle_and_the_policy_version() {
    let d = Dir::standard("ids_domain");
    let tiers = TierMap::empty();
    let server =
        RefCell::new(DirectoryServer::new(&d.ctx, &d.store, &tiers, VERSION, LIMITS).unwrap());
    let mut kdc_side = client(&server);
    let domain = kdc_side.describe_domain().unwrap();
    assert_eq!(domain.realm, realm());
    assert_eq!(domain.naming_context, ["example", "test"]);
    assert_eq!(
        domain.krbtgt,
        d.view().krbtgt_handle(&domain_sid()).unwrap()
    );
    assert_eq!(domain.policy_version, VERSION);
    assert_eq!(kdc_side.ping(), Ok(()));
}

/// docs/50 §7.5 (no start on a start-up failure); docs/47 R47-2: no server
/// over a directory without its root or its krbtgt account, nor with limits
/// of zero.
#[test]
fn the_server_refuses_to_start_without_a_domain() {
    let empty = Dir::new("ids_empty");
    let tiers = TierMap::empty();
    assert_eq!(
        DirectoryServer::new(&empty.ctx, &empty.store, &tiers, VERSION, LIMITS).err(),
        Some(StartError::NamingContextRoot)
    );
    let no_krbtgt = Dir::new("ids_no_krbtgt");
    let objects: Vec<_> = no_krbtgt
        .standard_objects()
        .into_iter()
        .filter(|o| o.guid != guid(KRBTGT))
        .collect();
    no_krbtgt.create_all(objects);
    assert_eq!(
        DirectoryServer::new(&no_krbtgt.ctx, &no_krbtgt.store, &tiers, VERSION, LIMITS).err(),
        Some(StartError::Krbtgt)
    );
    let d = Dir::standard("ids_zero");
    for limits in [
        ViewLimits {
            max_views: 0,
            lifetime: Duration::from_secs(5),
        },
        ViewLimits {
            max_views: 1,
            lifetime: Duration::ZERO,
        },
    ] {
        assert_eq!(
            DirectoryServer::new(&d.ctx, &d.store, &tiers, VERSION, limits).err(),
            Some(StartError::Limits)
        );
    }
}

/// docs/50 R50-2: a view of another policy version is refused by the kdc's
/// client (fail closed, the kdc reloads), and dird releases it when the
/// client drops the connection.
#[test]
fn the_kdc_refuses_a_view_of_another_policy_version() {
    let d = Dir::standard("ids_version");
    let tiers = TierMap::empty();
    let server = RefCell::new(
        DirectoryServer::new(&d.ctx, &d.store, &tiers, PolicyVersion(4), LIMITS).unwrap(),
    );
    let mut kdc_side = client(&server);
    assert_eq!(
        kdc_side.begin_view().err(),
        Some(Unserved::PolicyVersionMismatch {
            dird: PolicyVersion(4)
        })
    );
    assert_eq!(server.borrow().open_views(), 0);
}
