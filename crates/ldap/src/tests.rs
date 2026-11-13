//! Unit tests for the paths only a bound identity reaches.
//!
//! In L4 nothing outside this crate can bind (task L7 builds the GSSAPI
//! bind), so a bound session is built here with the test-only constructor
//! `Session::bound_for_test`, and the per-request re-check is driven through
//! `Engine::handle` exactly as for an anonymous session. The account source
//! is kdc's `InMemoryAccounts` (the in-memory equivalent of the
//! directory-pip view, docs/47 §10.1).
//!
//! Sources (each test names its own): [MS-ADTS] v20261026 5.1.1.6; RFC 4511
//! §4.4.1, §4.3; RFC 4513 §4; RFC 4120 3.3.3.1; docs/49 §3.2, §4.3, §4.4
//! (R49-15), §9; Q-169 item 5; A-47; X.690 (02/2021) 8.1.2.2, 8.14.4; RFC
//! 4511 App. B. Every value is hand-made.

use std::collections::BTreeSet;

use dtyp::{SecurityDescriptor, Sid, SECURITY_NT_AUTHORITY};
use kdc::{
    AccountKind, AccountState, ArmorPolicy, ClientAccount, InMemoryAccounts, NamedPrincipal,
};
use keyd_types::{KeyHandle, KeyPurpose, PrincipalId as KeydPrincipalId};
use krb_proto::KerberosTime;
use parse_ldap::{
    decode_message, encode_message, AuthState, AuthenticationChoice, BindRequest, DecodeOptions,
    DerefAliases, Direction, Filter, LdapMessage, LdapResult, MessageId, Profile, ProtocolOp,
    ResultCode, Scope, SearchRequest, UnsupportedOp, MAX_AUTH_MESSAGE_OCTETS,
    NOTICE_OF_DISCONNECTION_OID,
};
use pdp::{
    Action, ActionMatch, AttrClass, AttrId, AuthMatch, ContextMatch, Dn, Effect, IpScope, Match,
    ObjClassChain, Pip, PipError, PolicySnapshot, PolicyVersion, PrincipalId, PropertySet,
    ReasonCode, Resource, ResourceMatch, RlKey, Rule, RuleId, SubjectMatch, Tier, TransportSec,
};

use crate::respond::{self, ResponseKind};
use crate::session::BoundIdentity;
use crate::{
    AuditReason, ConnectionAction, Engine, EngineConfig, Listener, Outcome, RateLimiter,
    RequestInputs, RootDseConfig, Session, TransportReport,
};

// ---------------------------------------------------------------- fixture --

const REALM: &str = "EXAMPLE.ORG";

fn time(h: u8) -> KerberosTime {
    KerberosTime::new(2026, 11, 13, h, 0, 0).expect("valid time")
}

/// authtime 08:00, endtime 18:00, now 10:00.
fn authtime() -> KerberosTime {
    time(8)
}
fn endtime() -> KerberosTime {
    time(18)
}
fn now() -> KerberosTime {
    time(10)
}

fn alice_sid() -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 1105]).expect("valid SID")
}

fn alice() -> NamedPrincipal {
    NamedPrincipal::from_text(REALM, 1, &["alice"]).expect("valid name")
}

fn alice_account() -> ClientAccount {
    ClientAccount {
        key: KeyHandle::new(
            KeydPrincipalId::from_bytes([5; 16]),
            KeyPurpose::PrincipalLongterm,
        ),
        sid: alice_sid(),
        groups: BTreeSet::new(),
        tier: Tier::Tier2,
        state: AccountState::ACTIVE,
        etype_info: Vec::new(),
        kind: AccountKind::User,
        armor_policy: ArmorPolicy::Required,
    }
}

fn accounts_with_alice() -> InMemoryAccounts {
    let mut accounts = InMemoryAccounts::new();
    let p = alice();
    accounts
        .insert_client(&p.realm, &p.name, alice_account())
        .expect("one alice");
    accounts
}

fn identity(channel_bound: bool) -> BoundIdentity {
    BoundIdentity {
        principal: alice(),
        sid: alice_sid(),
        authtime: authtime(),
        endtime: endtime(),
        channel_bound,
    }
}

fn bound_session() -> Session {
    Session::bound_for_test(3, Listener::Ldaps, identity(true))
}

/// A PIP whose `tier_of` answers `tier`; nothing else is asked for the
/// rootDSE (no layer 5).
struct TierPip(Tier);

impl Pip for TierPip {
    fn expand_groups(&self, _p: &PrincipalId) -> Result<BTreeSet<PrincipalId>, PipError> {
        Err(PipError::NotFound)
    }
    fn tier_of(&self, _p: &PrincipalId, _g: &BTreeSet<PrincipalId>) -> Result<Tier, PipError> {
        Ok(self.0)
    }
    fn object_tier(&self, _r: &Resource) -> Result<Tier, PipError> {
        Err(PipError::NotFound)
    }
    fn security_descriptor(&self, _dn: &Dn) -> Result<SecurityDescriptor, PipError> {
        Err(PipError::NotFound)
    }
    fn attr_class(&self, _a: &AttrId) -> Result<AttrClass, PipError> {
        Err(PipError::NotFound)
    }
    fn object_classes(&self, _dn: &Dn) -> Result<ObjClassChain, PipError> {
        Err(PipError::NotFound)
    }
    fn object_sid(&self, _dn: &Dn) -> Result<Option<Sid>, PipError> {
        Err(PipError::NotFound)
    }
    fn property_set(&self, _a: &AttrId) -> Result<Option<PropertySet>, PipError> {
        Err(PipError::NotFound)
    }
}

struct AdmitAll;

impl RateLimiter for AdmitAll {
    fn admit(&mut self, _key: &RlKey, _now: &KerberosTime) -> bool {
        true
    }
}

/// An Allow rule for DirRead on the rootDSE; no anonymous grant (an
/// authenticated read needs none — docs/11 §4).
fn allow_policy() -> PolicySnapshot {
    PolicySnapshot::new(
        PolicyVersion(1),
        vec![Rule {
            id: RuleId(1),
            effect: Effect::Allow,
            when: Match {
                action: ActionMatch::Exact(Action::DirRead),
                resource: ResourceMatch::RootDse,
                subject: SubjectMatch::Any,
                context: ContextMatch::ANY,
                auth: AuthMatch::ANY,
            },
            obligations: vec![],
        }],
        vec![],
    )
}

fn engine() -> Engine {
    Engine::new(EngineConfig {
        root_dse: RootDseConfig {
            naming_context: directory_pip::NamingContext::new(&["example", "org"])
                .expect("naming context"),
            dns_host_name: "dc1.example.org".to_owned(),
        },
    })
    .expect("valid configuration")
}

fn tls_report() -> TransportReport {
    TransportReport {
        src_net: IpScope::Internal,
        tls_established: true,
        input_pending: false,
    }
}

fn id(n: u32) -> MessageId {
    MessageId::new(n).expect("valid MessageID")
}

fn root_dse_search(n: u32) -> LdapMessage {
    LdapMessage {
        message_id: id(n),
        protocol_op: ProtocolOp::SearchRequest(SearchRequest {
            base_object: String::new(),
            scope: Scope::BaseObject,
            deref_aliases: DerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::Present("objectClass".to_owned()),
            attributes: vec![],
        }),
        controls: None,
    }
}

fn send(
    session: &mut Session,
    accounts: &InMemoryAccounts,
    policy: &PolicySnapshot,
    msg: &LdapMessage,
    at: KerberosTime,
) -> Outcome {
    let pip = TierPip(Tier::Tier2);
    let mut rate = AdmitAll;
    let octets = encode_message(msg).expect("canonical");
    engine().handle(
        session,
        &octets,
        RequestInputs {
            snapshot: policy,
            pip: &pip,
            accounts,
            rate: &mut rate,
            now: at,
            transport: tls_report(),
            directory: None,
        },
    )
}

fn decode(octets: &[u8]) -> LdapMessage {
    decode_message(
        octets,
        &DecodeOptions {
            direction: Direction::Response,
            profile: Profile::Canonical,
            max_message_octets: MAX_AUTH_MESSAGE_OCTETS,
        },
    )
    .expect("canonical response")
}

/// RFC 4511 §4.4.1 + [MS-ADTS] 5.1.1.6: the request is not executed; the one
/// response is the Notice of Disconnection; the session closes and is no
/// longer bound.
fn assert_disconnected(outcome: &Outcome, session: &Session, reason: AuditReason) {
    assert_eq!(outcome.responses.len(), 1);
    let notice = decode(&outcome.responses[0]);
    assert_eq!(notice.message_id.get(), 0);
    match notice.protocol_op {
        ProtocolOp::ExtendedResponse(e) => {
            assert_eq!(e.result.result_code, ResultCode::StrongerAuthRequired);
            assert_eq!(
                e.response_name.as_deref(),
                Some(NOTICE_OF_DISCONNECTION_OID)
            );
        }
        other => panic!("not a notice: {other:?}"),
    }
    assert_eq!(outcome.action, ConnectionAction::Close);
    assert_eq!(outcome.audit.reason, reason);
    assert_eq!(outcome.audit.principal, Some(alice_sid()));
    assert_eq!(outcome.audit.notice, Some(ResultCode::StrongerAuthRequired));
    assert_eq!(outcome.audit.result_code, None);
    assert!(session.is_closed());
    assert_eq!(session.auth_state(), AuthState::Unauthenticated);
}

// ------------------------------------------------------------------ tests --

/// docs/49 §3.2 / §4.4 (the subject from the fresh record), §5.2 (an
/// authenticated read needs `{encrypted}`); A-47 (TLS + keyd-verified
/// channel binding → `{encrypted, sealed, channel_bound}`): a valid bound
/// identity over TLS reads the rootDSE.
#[test]
fn a_bound_identity_over_tls_reads_the_root_dse() {
    let accounts = accounts_with_alice();
    let mut session = bound_session();
    assert_eq!(session.auth_state(), AuthState::Authenticated);
    let outcome = send(
        &mut session,
        &accounts,
        &allow_policy(),
        &root_dse_search(1),
        now(),
    );
    assert_eq!(outcome.responses.len(), 2);
    assert_eq!(outcome.audit.reason, AuditReason::RootDseReturned);
    assert_eq!(outcome.audit.principal, Some(alice_sid()));
    assert_eq!(
        outcome.audit.transport_sec,
        TransportSec {
            encrypted: true,
            sealed: true,
            channel_bound: true
        }
    );
    assert_eq!(outcome.action, ConnectionAction::Continue);
}

/// A-47 / docs/49 §4.3: without keyd's channel-binding verification only
/// `encrypted` is reported.
#[test]
fn without_a_verified_channel_binding_only_encrypted_is_reported() {
    let accounts = accounts_with_alice();
    let mut session = Session::bound_for_test(3, Listener::Ldaps, identity(false));
    let outcome = send(
        &mut session,
        &accounts,
        &allow_policy(),
        &root_dse_search(1),
        now(),
    );
    assert_eq!(
        outcome.audit.transport_sec,
        TransportSec {
            encrypted: true,
            sealed: false,
            channel_bound: false
        }
    );
}

/// docs/49 §9: an authenticated read the policy does not grant (no Allow
/// rule — docs/11 §4 deny by default) is insufficientAccessRights.
#[test]
fn a_bound_identity_without_a_grant_is_insufficient_access_rights() {
    let accounts = accounts_with_alice();
    let mut session = bound_session();
    let no_rules = PolicySnapshot::new(PolicyVersion(2), vec![], vec![]);
    let outcome = send(
        &mut session,
        &accounts,
        &no_rules,
        &root_dse_search(1),
        now(),
    );
    assert_eq!(outcome.responses.len(), 1);
    match decode(&outcome.responses[0]).protocol_op {
        ProtocolOp::SearchResultDone(r) => {
            assert_eq!(r.result_code, ResultCode::InsufficientAccessRights)
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert_eq!(
        outcome.audit.reason,
        AuditReason::PolicyDenied(ReasonCode::NoGrant)
    );
}

/// R49-15 / docs/49 §4.4: a disabled account (authorization re-derived per
/// request) → Notice of Disconnection, strongerAuthRequired (Q-169 item 5).
#[test]
fn a_disabled_account_is_disconnected() {
    let mut accounts = accounts_with_alice();
    let p = alice();
    accounts
        .client_mut(&p.realm, &p.name)
        .expect("alice")
        .state
        .enabled = false;
    let mut session = bound_session();
    let outcome = send(
        &mut session,
        &accounts,
        &allow_policy(),
        &root_dse_search(1),
        now(),
    );
    assert_disconnected(&outcome, &session, AuditReason::IdentityRevoked);
}

/// RFC 4120 3.3.3.1 (the hot-list) via docs/49 §3.2: `revoked_before` after
/// the identity's authtime (a password reset) → Notice of Disconnection.
#[test]
fn a_revocation_after_authtime_is_disconnected() {
    let mut accounts = accounts_with_alice();
    let p = alice();
    accounts
        .client_mut(&p.realm, &p.name)
        .expect("alice")
        .state
        .revoked_before = Some(time(9));
    let mut session = bound_session();
    let outcome = send(
        &mut session,
        &accounts,
        &allow_policy(),
        &root_dse_search(1),
        now(),
    );
    assert_disconnected(&outcome, &session, AuditReason::IdentityRevoked);
}

/// docs/49 §3.2: a revocation instant at or before authtime does not revoke.
#[test]
fn a_revocation_before_authtime_does_not_disconnect() {
    let mut accounts = accounts_with_alice();
    let p = alice();
    accounts
        .client_mut(&p.realm, &p.name)
        .expect("alice")
        .state
        .revoked_before = Some(authtime());
    let mut session = bound_session();
    let outcome = send(
        &mut session,
        &accounts,
        &allow_policy(),
        &root_dse_search(1),
        now(),
    );
    assert_eq!(outcome.audit.reason, AuditReason::RootDseReturned);
}

/// docs/49 §4.4: an account that is gone, or whose name now carries another
/// SID, no longer backs the identity.
#[test]
fn a_removed_or_replaced_account_is_disconnected() {
    let p = alice();
    let mut removed = accounts_with_alice();
    removed.remove_client(&p.realm, &p.name);
    let mut session = bound_session();
    let outcome = send(
        &mut session,
        &removed,
        &allow_policy(),
        &root_dse_search(1),
        now(),
    );
    assert_disconnected(&outcome, &session, AuditReason::IdentityRevoked);

    let mut replaced = accounts_with_alice();
    replaced.client_mut(&p.realm, &p.name).expect("alice").sid =
        Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 1200]).expect("valid SID");
    let mut session = bound_session();
    let outcome = send(
        &mut session,
        &replaced,
        &allow_policy(),
        &root_dse_search(1),
        now(),
    );
    assert_disconnected(&outcome, &session, AuditReason::IdentityRevoked);
}

/// AGENTS.md §6 (fail closed): an account source that cannot answer ends the
/// session like a revocation.
#[test]
fn an_unavailable_account_source_is_disconnected() {
    let mut accounts = accounts_with_alice();
    accounts.set_unavailable(true);
    let mut session = bound_session();
    let outcome = send(
        &mut session,
        &accounts,
        &allow_policy(),
        &root_dse_search(1),
        now(),
    );
    assert_disconnected(&outcome, &session, AuditReason::AccountSourceFailure);
}

/// [MS-ADTS] 5.1.1.6: "When a DC receives a new LDAP request on an existing
/// connection that has an associated expiry time, where the current time
/// exceeds the expiry time, the DC MUST NOT execute the LDAP request ...
/// MUST disconnect the connection and send a Notice of Disconnection" —
/// for every request, Abandon and Bind included; at the expiry time itself
/// the request still runs.
#[test]
fn an_expired_identity_is_disconnected_on_any_request() {
    let accounts = accounts_with_alice();
    let after = KerberosTime::new(2026, 11, 13, 18, 0, 1).expect("valid time");
    let abandon = LdapMessage {
        message_id: id(2),
        protocol_op: ProtocolOp::AbandonRequest(id(1)),
        controls: None,
    };
    let rebind = LdapMessage {
        message_id: id(3),
        protocol_op: ProtocolOp::BindRequest(BindRequest {
            version: 3,
            name: String::new(),
            authentication: AuthenticationChoice::Simple {
                password_empty: true,
            },
        }),
        controls: None,
    };
    let delete = LdapMessage {
        message_id: id(4),
        protocol_op: ProtocolOp::Unsupported {
            op_tag: UnsupportedOp::DelRequest,
        },
        controls: None,
    };
    for msg in [root_dse_search(1), abandon, rebind, delete] {
        let mut session = bound_session();
        let outcome = send(&mut session, &accounts, &allow_policy(), &msg, after);
        assert_disconnected(&outcome, &session, AuditReason::IdentityExpired);
    }
    let mut session = bound_session();
    let at_expiry = send(
        &mut session,
        &accounts,
        &allow_policy(),
        &root_dse_search(1),
        endtime(),
    );
    assert_eq!(at_expiry.audit.reason, AuditReason::RootDseReturned);
}

/// RFC 4511 §4.4.1 ("this notification is not a response to an Unbind") and
/// §4.3: an Unbind closes a bound session without a notice, even when the
/// identity has expired.
#[test]
fn unbind_of_a_bound_session_closes_without_a_notice() {
    let accounts = accounts_with_alice();
    let mut session = bound_session();
    let unbind = LdapMessage {
        message_id: id(5),
        protocol_op: ProtocolOp::UnbindRequest,
        controls: None,
    };
    let outcome = send(&mut session, &accounts, &allow_policy(), &unbind, time(19));
    assert!(outcome.responses.is_empty());
    assert_eq!(outcome.action, ConnectionAction::Close);
    assert_eq!(outcome.audit.reason, AuditReason::Unbind);
    assert_eq!(outcome.audit.principal, Some(alice_sid()));
    assert!(outcome.audit.transport_sec.channel_bound);
}

/// docs/49 §10.1 (`principal`) and RFC 4511 §4.1.1: undecodable input on a
/// bound session is a Notice of Disconnection (protocolError), recorded
/// against the bound principal; the account source is not consulted for it.
#[test]
fn malformed_input_on_a_bound_session_is_recorded_against_the_principal() {
    let mut accounts = accounts_with_alice();
    accounts.set_unavailable(true);
    let mut session = bound_session();
    let pip = TierPip(Tier::Tier2);
    let mut rate = AdmitAll;
    let outcome = engine().handle(
        &mut session,
        &[0x30, 0x02, 0x02],
        RequestInputs {
            snapshot: &allow_policy(),
            pip: &pip,
            accounts: &accounts,
            rate: &mut rate,
            now: now(),
            transport: tls_report(),
            directory: None,
        },
    );
    assert_eq!(outcome.audit.notice, Some(ResultCode::ProtocolError));
    assert!(matches!(outcome.audit.reason, AuditReason::Malformed(_)));
    assert_eq!(outcome.audit.principal, Some(alice_sid()));
    assert_eq!(outcome.action, ConnectionAction::Close);
}

/// RFC 4513 §4: "Upon receipt of a Bind request, the server immediately
/// moves the session to an anonymous authorization state" — an anonymous
/// bind on a bound session leaves it anonymous (and with the smaller bound,
/// docs/49 §2.4).
#[test]
fn a_bind_moves_a_bound_session_to_anonymous() {
    let accounts = accounts_with_alice();
    let mut session = bound_session();
    let rebind = LdapMessage {
        message_id: id(6),
        protocol_op: ProtocolOp::BindRequest(BindRequest {
            version: 3,
            name: String::new(),
            authentication: AuthenticationChoice::Simple {
                password_empty: true,
            },
        }),
        controls: None,
    };
    let outcome = send(&mut session, &accounts, &allow_policy(), &rebind, now());
    assert_eq!(outcome.audit.reason, AuditReason::AnonymousBind);
    assert_eq!(outcome.audit.principal, None);
    assert_eq!(session.auth_state(), AuthState::Unauthenticated);
    assert!(!session.is_closed());
}

/// RFC 4511 App. B (ModifyResponse ::= [APPLICATION 7] LDAPResult, …) and
/// X.690 8.1.2.2 / 8.14.4; docs/questions/Q-190 item 1 (A-54): the five
/// refusal responses are parse-ldap's typed `UnsupportedResponse`, which
/// decodes back to itself and differs from a SearchResultDone only in the
/// protocolOp identifier octet (`[APPLICATION n]`, constructed).
#[test]
fn unsupported_responses_carry_the_matching_application_tag() {
    for (op, tag) in [
        (UnsupportedOp::ModifyRequest, 7u8),
        (UnsupportedOp::AddRequest, 9),
        (UnsupportedOp::DelRequest, 11),
        (UnsupportedOp::ModifyDnRequest, 13),
        (UnsupportedOp::CompareRequest, 15),
    ] {
        for n in [1u32, 127, 128, 65_535, 2_147_483_647] {
            let octets = respond::result(
                id(n),
                ResponseKind::NotSupported(op),
                ResultCode::UnwillingToPerform,
            )
            .expect("encodes");
            assert_eq!(
                decode(&octets).protocol_op,
                ProtocolOp::UnsupportedResponse {
                    op,
                    result: LdapResult::new(ResultCode::UnwillingToPerform),
                }
            );
            let done = encode_message(&LdapMessage {
                message_id: id(n),
                protocol_op: ProtocolOp::SearchResultDone(LdapResult::new(
                    ResultCode::UnwillingToPerform,
                )),
                controls: None,
            })
            .expect("encodes");
            assert_eq!(octets.len(), done.len());
            let differing: Vec<usize> = (0..octets.len())
                .filter(|&i| octets[i] != done[i])
                .collect();
            assert_eq!(differing.len(), 1);
            let at = differing[0];
            assert_eq!(done[at], 0x65);
            assert_eq!(octets[at], 0x60 | tag);
        }
    }
}
