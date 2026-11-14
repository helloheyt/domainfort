//! Tier 1 (docs/50 §9: in-process): dird's dispatcher over a temporary
//! dirstore built with the phase-1 schema and the directory-pip fixtures
//! (crates/directory-pip/tests/common, reused through `#[path]`), reached by
//! the front's real state machine (`ipc_ldap::FrontChannel`) — every reply
//! compared octet for octet with calling `ldap::Engine::handle` directly on
//! a second session with the same inputs.
//!
//! * the anonymous rootDSE; the bind refusals; an anonymous directory search
//!   over LDAPS under an internal anonymous grant (the bound-identity seam
//!   of the engine is crate-internal, `Session::bound_for_test`, so it is not
//!   reachable here — docs/questions/Q-280 item 9); StartTLS sequencing;
//! * the channel's order: Open first, `TlsEstablished` only after
//!   `Done { StartTls }`, a front report the channel never accepted refused
//!   before the engine;
//! * host refusals (`Busy`, `Unavailable`); a response split into parts and
//!   reassembled; an outcome over the reply bounds refused;
//! * exactly one audit event per engine call, equal to the direct call's.
//!
//! Sources: docs/50 R50-10, §3.3, §4.2, §4.3, §9; docs/49 R49-14, R49-15,
//! R49-16, §4.3, §4.4, §5.2, §6; RFC 4511 §4.2, §4.5.1, §4.14.1 (requests
//! built by hand from the ASN.1 of App. B); RFC 4513 §3.1.1, §5.1; [MS-ADTS]
//! 5.1.3.2 (LC, RP); [MS-DTYP] 2.4.2.4 (S-1-5-7), 2.4.4.2, 2.4.6; A-47,
//! A-48, A-51, A-59; Q-190, Q-200. Every value is hand-made (the fixtures'
//! own data).

#[path = "../../directory-pip/tests/common/mod.rs"]
mod common;

use common::*;
use core::net::{IpAddr, Ipv4Addr};
use directory_pip::TierMap;
use dtyp::{AccessMask, Ace, Acl, Control, MaskSidAce, SecurityDescriptor, Sid, ACL_REVISION_DS};
use ipc::{decode_body, encode_frame, Direction, EncodedFrame, Refused};
use ipc_ldap::{
    ChannelFailure, ConnectionAction as WireAction, Exchange, FrontChannel, LdapReply, LdapRequest,
    Listener as WireListener, MessageRequest, Progress, TransportFacts, LDAP_CHANNEL,
    MAX_RESPONSES, MAX_RESPONSE_PART,
};
use ipc_ldap_server::{Dispatch, LdapConnection, RequestHost, Unserved};
use krb_proto::KerberosTime;
use ldap::{
    AuditEvent, AuditOperation, ConnectionAction, DirectoryInputs, Engine, EngineConfig, Listener,
    Outcome, RateLimiter, RequestInputs, RootDseConfig, SearchClock, Session, TransportReport,
};
use parse_ldap::{
    encode_message, AuthState, AuthenticationChoice, BindRequest, DerefAliases, ExtendedRequest,
    Filter, LdapMessage, MessageId, ProtocolOp, SaslCredentials, Scope, SearchRequest,
    START_TLS_OID,
};
use pdp::access_check::rights::{RIGHT_DS_LIST_CONTENTS, RIGHT_DS_READ_PROPERTY};
use pdp::{
    Action, ActionMatch, AnonymousGrant, AuthMatch, ContextMatch, Effect, IpScope, Match,
    PolicySnapshot, PolicyVersion, ResourceMatch, RlKey, Rule, RuleId, SubjectMatch, SubtreeBase,
    TransportSec,
};
use std::cell::RefCell;
use zeroize::Zeroizing;

const CONNECTION: u64 = 41;
const NC_DN: &str = "dc=example,dc=test";

// ---- the directory, the policy, the engine --------------------------------

/// ANONYMOUS, S-1-5-7 ([MS-DTYP] 2.4.2.4): the anonymous requester's
/// principal (Q-190 item 10).
fn anonymous() -> Sid {
    Sid::new(dtyp::SECURITY_NT_AUTHORITY, &[7]).unwrap()
}

/// A descriptor whose DACL grants ANONYMOUS list and read ([MS-DTYP] 2.4.6:
/// SR, DP, GD; 2.4.4.2 ACCESS_ALLOWED_ACE; [MS-ADTS] 5.1.3.2 LC, RP).
fn anonymous_readable() -> Vec<u8> {
    SecurityDescriptor {
        sbz1: 0,
        control: Control(Control::SELF_RELATIVE | Control::DACL_PRESENT | Control::GROUP_DEFAULTED),
        owner_sid: Some(Sid::new(dtyp::SECURITY_NT_AUTHORITY, &[18]).unwrap()),
        group_sid: None,
        sacl: None,
        dacl: Some(Acl {
            acl_revision: ACL_REVISION_DS,
            aces: vec![Ace::AccessAllowed(MaskSidAce {
                ace_flags: 0,
                mask: AccessMask(RIGHT_DS_LIST_CONTENTS | RIGHT_DS_READ_PROPERTY),
                sid: anonymous(),
            })],
        }),
    }
    .encode()
    .unwrap()
}

/// The standard directory of the fixtures, with the domain root, ou=Staff,
/// alice and bob readable and listable by ANONYMOUS (every other object
/// keeps the fixtures' descriptor without a DACL: denied, docs/11 §5).
fn directory(test: &str) -> Dir {
    let d = Dir::standard(test);
    for id in [ROOT, STAFF_OU, ALICE, BOB] {
        d.set(id, "nTSecurityDescriptor", vec![anonymous_readable()]);
    }
    d
}

/// The policy: the rootDSE for internal anonymous readers with no transport
/// minimum (docs/49 §4.3 row 1, §5.2; Q-170), and the NC subtree for
/// internal anonymous readers over TLS (A-51; Q-200 item 5: the grant covers
/// the NC root), each with its Allow rule (docs/11 §3).
fn policy() -> PolicySnapshot {
    let nc = || ResourceMatch::DirSubtree {
        base: SubtreeBase::new(naming_context().dn().clone()).unwrap(),
    };
    let read_list = || ActionMatch::AnyOf(vec![Action::DirRead, Action::DirList]);
    let allow = |id, action, resource| Rule {
        id: RuleId(id),
        effect: Effect::Allow,
        when: Match {
            action,
            resource,
            subject: SubjectMatch::Any,
            context: ContextMatch::ANY,
            auth: AuthMatch::ANY,
        },
        obligations: vec![],
    };
    PolicySnapshot::new(
        PolicyVersion(1),
        vec![
            allow(
                1,
                ActionMatch::Exact(Action::DirRead),
                ResourceMatch::RootDse,
            ),
            allow(2, read_list(), nc()),
        ],
        vec![
            AnonymousGrant::new(
                ActionMatch::Exact(Action::DirRead),
                ResourceMatch::RootDse,
                TransportSec::NONE,
                IpScope::Internal,
            )
            .unwrap(),
            AnonymousGrant::new(
                read_list(),
                nc(),
                TransportSec {
                    encrypted: true,
                    sealed: false,
                    channel_bound: false,
                },
                IpScope::Internal,
            )
            .unwrap(),
        ],
    )
}

fn engine() -> Engine {
    Engine::new(EngineConfig {
        root_dse: RootDseConfig {
            naming_context: naming_context(),
            dns_host_name: "dc1.example.test".to_owned(),
        },
    })
    .unwrap()
}

struct AdmitAll;

impl RateLimiter for AdmitAll {
    fn admit(&mut self, _key: &RlKey, _now: &KerberosTime) -> bool {
        true
    }
}

/// The fixtures' fixed "now" as the search clock.
struct FixedClock;

impl SearchClock for FixedClock {
    fn now(&self) -> KerberosTime {
        now()
    }
}

/// Build one request's inputs over a fresh view of `d` and run `f` with
/// them — the same for the dispatcher's host and the direct call.
fn with_inputs<R>(
    d: &Dir,
    tiers: &TierMap,
    policy: &PolicySnapshot,
    transport: TransportReport,
    f: impl FnOnce(RequestInputs<'_>) -> R,
) -> R {
    let view = d.ctx.view(&d.store, tiers).unwrap();
    let mut rate = AdmitAll;
    f(RequestInputs {
        snapshot: policy,
        pip: &view,
        accounts: &view,
        rate: &mut rate,
        now: now(),
        transport,
        directory: Some(DirectoryInputs {
            view: directory_pip::PepView::new(&view),
            clock: &FixedClock,
        }),
    })
}

/// 10.0.0.0/8 is internal (the test's own zone table).
fn zone_of(peer: IpAddr) -> IpScope {
    match peer {
        IpAddr::V4(v4) if v4.octets()[0] == 10 => IpScope::Internal,
        _ => IpScope::External,
    }
}

/// The dispatcher's host: inputs as [`with_inputs`], every event kept.
struct Host<'a> {
    d: &'a Dir,
    tiers: &'a TierMap,
    policy: &'a PolicySnapshot,
    events: Vec<AuditEvent>,
    refuse: Option<Unserved>,
    replace: Option<Vec<Vec<u8>>>,
}

impl<'a> Host<'a> {
    fn new(d: &'a Dir, tiers: &'a TierMap, policy: &'a PolicySnapshot) -> Host<'a> {
        Host {
            d,
            tiers,
            policy,
            events: Vec::new(),
            refuse: None,
            replace: None,
        }
    }
}

impl RequestHost for Host<'_> {
    fn zone(&self, peer: IpAddr) -> IpScope {
        zone_of(peer)
    }

    fn serve(
        &mut self,
        transport: TransportReport,
        run: &mut dyn FnMut(RequestInputs<'_>) -> Outcome,
    ) -> Result<Outcome, Unserved> {
        if let Some(refused) = self.refuse {
            return Err(refused);
        }
        let mut outcome = with_inputs(self.d, self.tiers, self.policy, transport, |inputs| {
            run(inputs)
        });
        self.events.push(outcome.audit.clone());
        if let Some(replacement) = self.replace.take() {
            outcome.responses = replacement;
        }
        Ok(outcome)
    }
}

/// The engine called directly on its own session (the reference path).
struct Direct<'a> {
    d: &'a Dir,
    tiers: &'a TierMap,
    policy: &'a PolicySnapshot,
    engine: Engine,
    session: Session,
    src_net: IpScope,
}

impl Direct<'_> {
    fn send(&mut self, message: &[u8], tls: bool) -> Outcome {
        let transport = TransportReport {
            src_net: self.src_net,
            tls_established: tls,
            input_pending: false,
        };
        let (engine, session) = (&self.engine, &mut self.session);
        with_inputs(self.d, self.tiers, self.policy, transport, |inputs| {
            engine.handle(session, message, inputs)
        })
    }
}

/// The channel path: the front's state machine, the dispatcher and the host.
struct Channel<'a> {
    engine: Engine,
    connection: LdapConnection,
    front: FrontChannel,
    host: Host<'a>,
}

impl<'a> Channel<'a> {
    fn new(d: &'a Dir, tiers: &'a TierMap, policy: &'a PolicySnapshot) -> Channel<'a> {
        Channel {
            engine: engine(),
            connection: LdapConnection::new(CONNECTION),
            front: FrontChannel::new(),
            host: Host::new(d, tiers, policy),
        }
    }

    /// Hand a request body to the dispatcher.
    fn dispatch(&mut self, frame: &EncodedFrame) -> Dispatch {
        self.connection
            .handle(&self.engine, frame.body(), &mut self.host)
    }

    /// Hand a request to the dispatcher and feed every reply frame to the
    /// front; the last progress (or the front's failure), and whether the
    /// connection closes.
    fn exchange(&mut self, frame: &EncodedFrame) -> (Result<Progress, ChannelFailure>, bool) {
        let dispatch = self.dispatch(frame);
        let mut last = Err(ChannelFailure::UnexpectedReply);
        for reply in dispatch.frames() {
            last = self.front.accept_reply(reply.body());
            if last.is_err() {
                break;
            }
        }
        (last, dispatch.closes())
    }

    fn open(&mut self, listener: WireListener) {
        let frame = self
            .front
            .encode_open(listener, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
            .unwrap();
        let (progress, closes) = self.exchange(&frame);
        assert_eq!(
            progress.unwrap(),
            Progress::Opened {
                framing: AuthState::Unauthenticated
            }
        );
        assert!(!closes);
    }

    fn send(&mut self, message: &[u8], tls: bool) -> (Exchange, bool) {
        let frame = self
            .front
            .encode_message(
                message,
                TransportFacts {
                    tls_established: tls,
                    input_pending: false,
                },
            )
            .unwrap();
        match self.exchange(&frame) {
            (Ok(Progress::Done(exchange)), closes) => (exchange, closes),
            other => panic!("no reply: {other:?}"),
        }
    }
}

fn wire_action(action: ConnectionAction) -> WireAction {
    match action {
        ConnectionAction::Continue => WireAction::Continue,
        ConnectionAction::StartTls => WireAction::StartTls,
        ConnectionAction::Close => WireAction::Close,
    }
}

/// Compare a channel exchange with the direct outcome: the same response
/// octets, the same action, the session's framing state, and the host's
/// last event equal to the direct event.
fn assert_same(exchange: &Exchange, closes: bool, outcome: &Outcome, host: &Host<'_>) {
    assert_eq!(exchange.responses, outcome.responses, "response octets");
    assert_eq!(exchange.action, wire_action(outcome.action));
    assert_eq!(closes, outcome.action == ConnectionAction::Close);
    assert_eq!(host.events.last(), Some(&outcome.audit), "audit event");
}

// ---- requests (RFC 4511 App. B, by hand) -----------------------------------

fn id(n: u32) -> MessageId {
    MessageId::new(n).unwrap()
}

fn encoded(n: u32, protocol_op: ProtocolOp) -> Vec<u8> {
    encode_message(&LdapMessage {
        message_id: id(n),
        protocol_op,
        controls: None,
    })
    .unwrap()
}

fn search(n: u32, base: &str, scope: Scope, attributes: &[&str]) -> Vec<u8> {
    encoded(
        n,
        ProtocolOp::SearchRequest(SearchRequest {
            base_object: base.to_owned(),
            scope,
            deref_aliases: DerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::Present("objectClass".to_owned()),
            attributes: attributes.iter().map(|a| (*a).to_owned()).collect(),
        }),
    )
}

fn root_dse(n: u32) -> Vec<u8> {
    search(n, "", Scope::BaseObject, &[])
}

fn bind(n: u32, version: u8, name: &str, authentication: AuthenticationChoice) -> Vec<u8> {
    encoded(
        n,
        ProtocolOp::BindRequest(BindRequest {
            version,
            name: name.to_owned(),
            authentication,
        }),
    )
}

fn start_tls(n: u32) -> Vec<u8> {
    encoded(
        n,
        ProtocolOp::ExtendedRequest(ExtendedRequest {
            request_name: START_TLS_OID.to_owned(),
            request_value: None,
        }),
    )
}

fn request_frame(request: &LdapRequest) -> EncodedFrame {
    encode_frame(LDAP_CHANNEL, Direction::Request, request).unwrap()
}

fn raw_message(octets: &[u8], tls: bool) -> EncodedFrame {
    request_frame(&LdapRequest::Message(MessageRequest {
        canonical: Zeroizing::new(octets.to_vec()),
        transport: TransportFacts {
            tls_established: tls,
            input_pending: false,
        },
    }))
}

/// The shared refusal a dispatch carries, if it is exactly one.
fn refusal(dispatch: &Dispatch) -> Option<Refused> {
    match dispatch.frames() {
        [frame] => match ipc::decode_reply::<LdapReply>(LDAP_CHANNEL, frame.body()).ok()? {
            ipc::Reply::Refused(refused) => Some(refused),
            ipc::Reply::Message(_) => None,
        },
        _ => None,
    }
}

// ---- tests -----------------------------------------------------------------

/// docs/49 §5.2 (R49-10), §4.3 row 1; docs/50 §4.2; R49-14: the anonymous
/// rootDSE read in cleartext from the internal network — the channel's reply
/// is octet for octet the engine's, with one equal audit event.
#[test]
fn the_anonymous_root_dse_is_byte_equal() {
    let d = directory("ldap-rootdse");
    let (tiers, policy) = (TierMap::empty(), policy());
    let mut channel = Channel::new(&d, &tiers, &policy);
    let mut direct = Direct {
        d: &d,
        tiers: &tiers,
        policy: &policy,
        engine: engine(),
        session: Session::new(CONNECTION, Listener::Ldap),
        src_net: IpScope::Internal,
    };
    channel.open(WireListener::Ldap);
    let message = root_dse(1);
    let (exchange, closes) = channel.send(&message, false);
    let outcome = direct.send(&message, false);
    assert_eq!(outcome.responses.len(), 2, "the entry and the done");
    assert_same(&exchange, closes, &outcome, &channel.host);
    assert_eq!(exchange.framing, AuthState::Unauthenticated);
    assert_eq!(channel.host.events.len(), 1);
    assert_eq!(channel.host.events[0].connection_id, CONNECTION);
}

/// docs/49 §3.1 (R49-4); RFC 4513 §5.1.2; RFC 4511 §4.2; Q-190 item 3
/// (A-54): every bind refusal through the channel equals the engine's —
/// simple bind with a password (7, before any lookup), an unauthenticated
/// simple bind (53), the anonymous simple bind, SASL GSSAPI without TLS
/// (13), another mechanism (7), version 2 (2).
#[test]
fn the_bind_refusals_are_byte_equal() {
    let d = directory("ldap-binds");
    let (tiers, policy) = (TierMap::empty(), policy());
    let mut channel = Channel::new(&d, &tiers, &policy);
    let mut direct = Direct {
        d: &d,
        tiers: &tiers,
        policy: &policy,
        engine: engine(),
        session: Session::new(CONNECTION, Listener::Ldap),
        src_net: IpScope::Internal,
    };
    channel.open(WireListener::Ldap);
    let sasl = |mechanism: &str| {
        AuthenticationChoice::Sasl(SaslCredentials {
            mechanism: mechanism.to_owned(),
            credentials: None,
        })
    };
    let binds = [
        bind(
            1,
            3,
            "cn=alice",
            AuthenticationChoice::Simple {
                password_empty: false,
            },
        ),
        bind(
            2,
            3,
            "cn=alice",
            AuthenticationChoice::Simple {
                password_empty: true,
            },
        ),
        bind(
            3,
            3,
            "",
            AuthenticationChoice::Simple {
                password_empty: true,
            },
        ),
        bind(4, 3, "", sasl("GSSAPI")),
        bind(5, 3, "", sasl("PLAIN")),
        bind(
            6,
            2,
            "",
            AuthenticationChoice::Simple {
                password_empty: true,
            },
        ),
    ];
    for message in &binds {
        let (exchange, closes) = channel.send(message, false);
        let outcome = direct.send(message, false);
        assert_eq!(outcome.responses.len(), 1);
        assert_same(&exchange, closes, &outcome, &channel.host);
    }
    assert_eq!(channel.host.events.len(), binds.len());
}

/// docs/49 §6 (R49-9), §4.3 row 2; A-51; Q-200 item 5: an anonymous
/// subtree search of the NC over LDAPS from the internal network, under the
/// internal anonymous grant — the entries and the done equal the engine's.
#[test]
fn an_anonymous_directory_search_is_byte_equal() {
    let d = directory("ldap-search");
    let (tiers, policy) = (TierMap::empty(), policy());
    let mut channel = Channel::new(&d, &tiers, &policy);
    let mut direct = Direct {
        d: &d,
        tiers: &tiers,
        policy: &policy,
        engine: engine(),
        session: Session::new(CONNECTION, Listener::Ldaps),
        src_net: IpScope::Internal,
    };
    channel.open(WireListener::Ldaps);
    let message = search(7, NC_DN, Scope::WholeSubtree, &["cn", "ou", "objectClass"]);
    let (exchange, closes) = channel.send(&message, true);
    let outcome = direct.send(&message, true);
    assert!(
        outcome.responses.len() >= 4,
        "the root, ou=Staff, alice and bob at least, then the done: {}",
        outcome.responses.len()
    );
    assert_same(&exchange, closes, &outcome, &channel.host);
    assert_eq!(
        channel.host.events[0]
            .search
            .as_ref()
            .map(|s| s.entries_returned),
        Some(u32::try_from(outcome.responses.len() - 1).unwrap())
    );
}

/// docs/50 §4.3; RFC 4511 §4.14.1, §4.14.2; docs/49 §4.4: StartTLS in
/// cleartext → `Done { StartTls }`; `TlsEstablished` → `TlsAccepted`; the
/// next message over TLS is answered exactly as the engine answers a
/// session that went through StartTLS. `TlsEstablished` itself is no engine
/// call (no audit event).
#[test]
fn start_tls_sequencing_is_byte_equal() {
    let d = directory("ldap-starttls");
    let (tiers, policy) = (TierMap::empty(), policy());
    let mut channel = Channel::new(&d, &tiers, &policy);
    let mut direct = Direct {
        d: &d,
        tiers: &tiers,
        policy: &policy,
        engine: engine(),
        session: Session::new(CONNECTION, Listener::Ldap),
        src_net: IpScope::Internal,
    };
    channel.open(WireListener::Ldap);
    let message = start_tls(1);
    let (exchange, closes) = channel.send(&message, false);
    let outcome = direct.send(&message, false);
    assert_eq!(outcome.action, ConnectionAction::StartTls);
    assert_same(&exchange, closes, &outcome, &channel.host);

    let frame = channel.front.encode_tls_established().unwrap();
    let (progress, closes) = channel.exchange(&frame);
    assert_eq!(
        progress.unwrap(),
        Progress::TlsAccepted {
            framing: AuthState::Unauthenticated
        }
    );
    assert!(!closes);
    assert_eq!(channel.host.events.len(), 1);

    let message = root_dse(2);
    let (exchange, closes) = channel.send(&message, true);
    let outcome = direct.send(&message, true);
    assert_same(&exchange, closes, &outcome, &channel.host);
    assert_eq!(channel.host.events.len(), 2);
    assert_eq!(
        channel.host.events[1].transport,
        ldap::AuditTransport::StartTls
    );
}

/// docs/50 §4.3 (the TLS order); docs/49 §4.4; crates/ldap session.rs:
/// TLS comes up only through LDAPS or a successful StartTLS. `TlsEstablished`
/// before StartTLS, on LDAPS, or twice is refused (`Malformed`, close); a
/// message claiming TLS the channel never accepted is refused before the
/// engine (no event); a cleartext message after StartTLS reaches the engine,
/// which closes the session unparsed — as the direct engine does.
#[test]
fn tls_reports_follow_the_session_rules() {
    let d = directory("ldap-tlsorder");
    let (tiers, policy) = (TierMap::empty(), policy());

    // TlsEstablished before any StartTLS.
    let mut channel = Channel::new(&d, &tiers, &policy);
    channel.open(WireListener::Ldap);
    let dispatch = channel.dispatch(&request_frame(&LdapRequest::TlsEstablished));
    assert_eq!(refusal(&dispatch), Some(Refused::Malformed));
    assert!(dispatch.closes());
    assert!(channel.connection.is_closed());
    assert!(matches!(
        channel.dispatch(&raw_message(&root_dse(1), false)),
        Dispatch::Close
    ));

    // TlsEstablished on LDAPS.
    let mut channel = Channel::new(&d, &tiers, &policy);
    channel.open(WireListener::Ldaps);
    let dispatch = channel.dispatch(&request_frame(&LdapRequest::TlsEstablished));
    assert_eq!(refusal(&dispatch), Some(Refused::Malformed));

    // A cleartext session claiming TLS.
    let mut channel = Channel::new(&d, &tiers, &policy);
    channel.open(WireListener::Ldap);
    let dispatch = channel.dispatch(&raw_message(&root_dse(1), true));
    assert_eq!(refusal(&dispatch), Some(Refused::Malformed));
    assert!(channel.host.events.is_empty(), "the engine was not called");

    // An LDAPS session claiming cleartext.
    let mut channel = Channel::new(&d, &tiers, &policy);
    channel.open(WireListener::Ldaps);
    let dispatch = channel.dispatch(&raw_message(&root_dse(1), false));
    assert_eq!(refusal(&dispatch), Some(Refused::Malformed));

    // After StartTLS: a message claiming TLS before TlsEstablished.
    let mut channel = Channel::new(&d, &tiers, &policy);
    channel.open(WireListener::Ldap);
    let _ = channel.send(&start_tls(1), false);
    let dispatch = channel.dispatch(&raw_message(&root_dse(2), true));
    assert_eq!(refusal(&dispatch), Some(Refused::Malformed));
    assert_eq!(channel.host.events.len(), 1, "only the StartTLS");

    // After StartTLS: a cleartext message reaches the engine and closes.
    let mut channel = Channel::new(&d, &tiers, &policy);
    let mut direct = Direct {
        d: &d,
        tiers: &tiers,
        policy: &policy,
        engine: engine(),
        session: Session::new(CONNECTION, Listener::Ldap),
        src_net: IpScope::Internal,
    };
    channel.open(WireListener::Ldap);
    let _ = channel.send(&start_tls(1), false);
    let _ = direct.send(&start_tls(1), false);
    let dispatch = channel.dispatch(&raw_message(&root_dse(2), false));
    let outcome = direct.send(&root_dse(2), false);
    assert!(outcome.responses.is_empty());
    assert_eq!(outcome.action, ConnectionAction::Close);
    assert!(dispatch.closes());
    let mut front_view = FrontChannel::new();
    // Read the dispatcher's reply as a front that sent a message would.
    front_view
        .encode_open(WireListener::Ldap, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
        .unwrap();
    front_view
        .accept_reply(
            encode_frame(
                LDAP_CHANNEL,
                Direction::Reply,
                &LdapReply::Opened {
                    framing: AuthState::Unauthenticated,
                },
            )
            .unwrap()
            .body(),
        )
        .unwrap();
    front_view
        .encode_message(&root_dse(2), TransportFacts::default())
        .unwrap();
    let mut last = None;
    for frame in dispatch.frames() {
        last = Some(front_view.accept_reply(frame.body()).unwrap());
    }
    match last {
        Some(Progress::Done(exchange)) => {
            assert!(exchange.responses.is_empty());
            assert_eq!(exchange.action, WireAction::Close);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(channel.host.events.last(), Some(&outcome.audit));
    assert_eq!(outcome.audit.operation, AuditOperation::NotDecoded);
}

/// docs/50 §3.3, §4.2, §7.5: the channel's order — `Ping` only before
/// `Open` (and the connection stays before `Open`); `Message` before `Open`,
/// `Open` twice and `Ping` after `Open` are refused (`Malformed`, close);
/// `Close` ends the session without a reply; a closed connection answers
/// nothing; a body with a wrong magic closes without a reply, one with a
/// wrong version is refused `VersionMismatch`.
#[test]
fn the_channel_order() {
    let d = directory("ldap-order");
    let (tiers, policy) = (TierMap::empty(), policy());
    let open = request_frame(&LdapRequest::Open {
        listener: WireListener::Ldap,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
    });

    let mut channel = Channel::new(&d, &tiers, &policy);
    let dispatch = channel.dispatch(&raw_message(&root_dse(1), false));
    assert_eq!(refusal(&dispatch), Some(Refused::Malformed));

    let mut channel = Channel::new(&d, &tiers, &policy);
    let pong = channel.dispatch(&request_frame(&LdapRequest::Ping));
    assert!(!pong.closes());
    assert_eq!(
        ipc::decode_reply::<LdapReply>(LDAP_CHANNEL, pong.frames()[0].body()).unwrap(),
        ipc::Reply::Message(LdapReply::Pong)
    );
    let opened = channel.dispatch(&open);
    assert!(!opened.closes());
    assert!(channel.connection.is_open());
    let again = channel.dispatch(&open);
    assert_eq!(refusal(&again), Some(Refused::Malformed));

    let mut channel = Channel::new(&d, &tiers, &policy);
    let _ = channel.dispatch(&open);
    let ping = channel.dispatch(&request_frame(&LdapRequest::Ping));
    assert_eq!(refusal(&ping), Some(Refused::Malformed));

    let mut channel = Channel::new(&d, &tiers, &policy);
    let _ = channel.dispatch(&open);
    let close = channel.dispatch(&request_frame(&LdapRequest::Close));
    assert!(matches!(close, Dispatch::Close));
    assert!(matches!(channel.dispatch(&open), Dispatch::Close));
    assert!(channel.host.events.is_empty());

    let mut channel = Channel::new(&d, &tiers, &policy);
    let mut wrong_magic = open.body().to_vec();
    wrong_magic[0] ^= 0xFF;
    assert!(matches!(
        channel
            .connection
            .handle(&channel.engine, &wrong_magic, &mut channel.host),
        Dispatch::Close
    ));
    let mut channel = Channel::new(&d, &tiers, &policy);
    let mut wrong_version = open.body().to_vec();
    wrong_version[2] = 9;
    let dispatch = channel
        .connection
        .handle(&channel.engine, &wrong_version, &mut channel.host);
    assert_eq!(refusal(&dispatch), Some(Refused::VersionMismatch));
    // The request body the dispatcher refused still decodes as a request
    // with the right version (the refusal is the version's).
    assert!(decode_body::<LdapRequest>(LDAP_CHANNEL, Direction::Request, open.body()).is_ok());
}

/// docs/50 R50-7 ("queue full ⇒ `Busy`"), §3.7, §8.1 (A-57): a host that
/// cannot serve answers the shared refusal and the connection closes; the
/// front reads it as a failure.
#[test]
fn host_refusals_close_the_connection() {
    let d = directory("ldap-refusals");
    let (tiers, policy) = (TierMap::empty(), policy());
    for (unserved, refused) in [
        (Unserved::Busy, Refused::Busy),
        (Unserved::Unavailable, Refused::Unavailable),
    ] {
        let mut channel = Channel::new(&d, &tiers, &policy);
        channel.open(WireListener::Ldap);
        channel.host.refuse = Some(unserved);
        let frame = channel
            .front
            .encode_message(&root_dse(1), TransportFacts::default())
            .unwrap();
        let (progress, closes) = channel.exchange(&frame);
        assert_eq!(progress.err(), Some(ChannelFailure::Refused(refused)));
        assert!(closes);
        assert!(channel.connection.is_closed());
    }
}

/// crates/ipc-ldap channel documentation (parts; per-reply bounds): a
/// response longer than one part is split and reassembled exactly; an
/// outcome over the reply bounds is not sent (`Unavailable`, close).
#[test]
fn large_responses_travel_in_parts_and_bounds_hold() {
    let d = directory("ldap-parts");
    let (tiers, policy) = (TierMap::empty(), policy());
    let part = MAX_RESPONSE_PART as usize;
    let big: Vec<u8> = (0..3 * part + 5).map(|i| (i % 253) as u8).collect();

    let mut channel = Channel::new(&d, &tiers, &policy);
    channel.open(WireListener::Ldap);
    channel.host.replace = Some(vec![big.clone(), vec![0x30, 0x00]]);
    let frame = channel
        .front
        .encode_message(&root_dse(1), TransportFacts::default())
        .unwrap();
    let dispatch = channel.dispatch(&frame);
    assert_eq!(dispatch.frames().len(), 4 + 1 + 1, "4 parts, 1 part, done");
    let mut last = None;
    for reply in dispatch.frames() {
        last = Some(channel.front.accept_reply(reply.body()).unwrap());
    }
    match last {
        Some(Progress::Done(exchange)) => {
            assert_eq!(exchange.responses, vec![big, vec![0x30, 0x00]]);
        }
        other => panic!("{other:?}"),
    }

    let mut channel = Channel::new(&d, &tiers, &policy);
    channel.open(WireListener::Ldap);
    channel.host.replace = Some(vec![vec![0x30, 0x00]; MAX_RESPONSES + 1]);
    let dispatch = channel.dispatch(&raw_message(&root_dse(1), false));
    assert_eq!(refusal(&dispatch), Some(Refused::Unavailable));
    assert!(dispatch.closes());

    let mut channel = Channel::new(&d, &tiers, &policy);
    channel.open(WireListener::Ldap);
    channel.host.replace = Some(vec![Vec::new()]);
    let dispatch = channel.dispatch(&raw_message(&root_dse(1), false));
    assert_eq!(refusal(&dispatch), Some(Refused::Unavailable));
}

/// docs/50 R50-10 (one Unix connection per client connection, 1:1): two
/// connections keep separate sessions — StartTLS on one leaves the other in
/// cleartext.
#[test]
fn one_session_per_connection() {
    let d = directory("ldap-sessions");
    let (tiers, policy) = (TierMap::empty(), policy());
    let engine = engine();
    let host = RefCell::new(Host::new(&d, &tiers, &policy));
    let mut first = LdapConnection::new(1);
    let mut second = LdapConnection::new(2);
    let open = request_frame(&LdapRequest::Open {
        listener: WireListener::Ldap,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
    });
    let _ = first.handle(&engine, open.body(), &mut *host.borrow_mut());
    let _ = second.handle(&engine, open.body(), &mut *host.borrow_mut());
    let started = first.handle(
        &engine,
        raw_message(&start_tls(1), false).body(),
        &mut *host.borrow_mut(),
    );
    assert!(!started.closes());
    let cleartext = second.handle(
        &engine,
        raw_message(&root_dse(1), false).body(),
        &mut *host.borrow_mut(),
    );
    assert!(!cleartext.closes(), "the second session is still cleartext");
    let events = &host.borrow().events;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].connection_id, 1);
    assert_eq!(events[1].connection_id, 2);
    assert_eq!(events[1].transport, ldap::AuditTransport::Ldap);
}
