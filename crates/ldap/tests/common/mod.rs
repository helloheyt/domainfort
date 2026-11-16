//! Shared fixtures for the engine's integration tests.
//!
//! The tests drive [`ldap::Engine::handle`] exactly as the front would: each
//! request is built as a typed `parse_ldap::LdapMessage`, encoded with
//! parse-ldap's canonical encoder (the form the front hands over, docs/49
//! R49-16), and passed with the per-request inputs. Responses are decoded
//! back with parse-ldap in the response direction under the canonical
//! profile, which also checks that every engine output is canonical.
//!
//! The policy is the phase-1 rootDSE policy of docs/49 §5.2 / Q-170: one
//! anonymous-allowlist entry for `DirRead` on the rootDSE from the internal
//! network (A-51), plus one Allow rule for the same. The PIP and the
//! ticket-subject lookup are minimal in-memory stand-ins.
//!
//! Every value here is constructed by hand for these tests from the ASN.1 of
//! RFC 4511 App. B and the decided design docs/49. No vector or fixture comes
//! from any other implementation.
#![allow(dead_code)] // each test binary uses a different subset

use std::cell::Cell;
use std::collections::BTreeSet;

use directory_pip::{NamingContext, TicketSubject, TicketSubjectError, TicketSubjects};
use dtyp::{SecurityDescriptor, Sid};
use krb_proto::{KerberosTime, PrincipalName, Realm};
use ldap::{
    Engine, EngineConfig, Listener, Outcome, RateLimiter, RequestInputs, RootDseConfig, Session,
    TransportReport,
};
use parse_ldap::{
    decode_message, encode_message, AuthenticationChoice, BindRequest, Control, DecodeOptions,
    DerefAliases, Direction, ExtendedRequest, Filter, LdapMessage, LdapResult, MessageId, Profile,
    ProtocolOp, ResultCode, SaslCredentials, Scope, SearchRequest, UnsupportedOp,
    MAX_AUTH_MESSAGE_OCTETS, START_TLS_OID,
};
use pdp::{
    Action, ActionMatch, AnonymousGrant, AttrClass, AttrId, AuthMatch, ContextMatch, Dn, Effect,
    IpScope, Match, ObjClassChain, Obligation, Pip, PipError, PolicySnapshot, PolicyVersion,
    PrincipalId, PropertySet, Resource, ResourceMatch, RlKey, Rule, RuleId, SubjectMatch, Tier,
    TransportSec,
};

// ---------------------------------------------------------------------------
// Configuration and time.
// ---------------------------------------------------------------------------

/// The domain NC DN the rootDSE reports (a hand-made example): the RFC 4514
/// encoding of the naming context `dc=example,dc=org` (A-53; the attribute
/// written as the lDAPDisplayName "dc").
pub const NAMING_CONTEXT: &str = "dc=example,dc=org";
/// The DC's DNS name (a hand-made example).
pub const DNS_HOST_NAME: &str = "dc1.example.org";

/// The naming context example.org ([MS-ADTS] 3.1.1.1.5: "dc=n1,dc=n2").
pub fn naming_context() -> NamingContext {
    NamingContext::new(&["example", "org"]).expect("naming context")
}

pub fn engine() -> Engine {
    Engine::new(EngineConfig {
        root_dse: RootDseConfig {
            naming_context: naming_context(),
            dns_host_name: DNS_HOST_NAME.to_owned(),
        },
    })
    .expect("valid configuration")
}

pub fn now() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 10, 0, 0).expect("valid time")
}

// ---------------------------------------------------------------------------
// The PIP, account source and rate limiter stand-ins.
// ---------------------------------------------------------------------------

/// A PIP that answers only `tier_of` (the rootDSE has no layer 5, and a read
/// asks no object tier — pdp `decide`). Every other lookup is `NotFound`.
pub struct TestPip {
    pub tier: Result<Tier, PipError>,
    pub tier_calls: Cell<u32>,
}

impl TestPip {
    pub fn untiered() -> TestPip {
        TestPip {
            tier: Ok(Tier::Untiered),
            tier_calls: Cell::new(0),
        }
    }
}

impl Pip for TestPip {
    fn expand_groups(&self, _p: &PrincipalId) -> Result<BTreeSet<PrincipalId>, PipError> {
        Err(PipError::NotFound)
    }
    fn tier_of(&self, _p: &PrincipalId, _g: &BTreeSet<PrincipalId>) -> Result<Tier, PipError> {
        self.tier_calls.set(self.tier_calls.get() + 1);
        self.tier
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

/// A ticket-subject lookup (directory-pip `TicketSubjects` — what the
/// engine's inputs carry since task PN10b) with no accounts that counts
/// every lookup — the tests use it to show that no bind path looks a name
/// up (P-14; docs/49 §3.1: refused "before any lookup of the name").
#[derive(Default)]
pub struct CountingSubjects {
    pub calls: Cell<u32>,
}

impl TicketSubjects for CountingSubjects {
    fn ticket_subject(
        &self,
        _realm: &Realm,
        _name: &PrincipalName,
    ) -> Result<Option<TicketSubject>, TicketSubjectError> {
        self.calls.set(self.calls.get() + 1);
        Ok(None)
    }
}

/// A rate limiter that admits or refuses everything and counts calls.
pub struct TestRate {
    pub admit: bool,
    pub calls: u32,
}

impl RateLimiter for TestRate {
    fn admit(&mut self, _key: &RlKey, _now: &KerberosTime) -> bool {
        self.calls += 1;
        self.admit
    }
}

// ---------------------------------------------------------------------------
// Policy.
// ---------------------------------------------------------------------------

/// The rootDSE anonymous-allowlist entry for `src_net` with transport
/// minimum `min` (docs/49 §5.2; Q-170 "AnonymousGrant::new(Exact(DirRead),
/// RootDse, <min>, Internal)").
pub fn root_dse_grant(src_net: IpScope, min: TransportSec) -> AnonymousGrant {
    AnonymousGrant::new(
        ActionMatch::Exact(Action::DirRead),
        ResourceMatch::RootDse,
        min,
        src_net,
    )
    .expect("a bounded grant")
}

/// An Allow rule for `DirRead` on the rootDSE, with `obligations`.
pub fn root_dse_allow(obligations: Vec<Obligation>) -> Rule {
    Rule {
        id: RuleId(1),
        effect: Effect::Allow,
        when: Match {
            action: ActionMatch::Exact(Action::DirRead),
            resource: ResourceMatch::RootDse,
            subject: SubjectMatch::Any,
            context: ContextMatch::ANY,
            auth: AuthMatch::ANY,
        },
        obligations,
    }
}

/// The phase-1 rootDSE policy: internal anonymous reads with no transport
/// minimum (docs/49 §4.3 row 1, §5.2), and the Allow rule.
pub fn root_dse_policy() -> PolicySnapshot {
    PolicySnapshot::new(
        PolicyVersion(1),
        vec![root_dse_allow(vec![])],
        vec![root_dse_grant(IpScope::Internal, TransportSec::NONE)],
    )
}

// ---------------------------------------------------------------------------
// Transport reports.
// ---------------------------------------------------------------------------

pub fn report(src_net: IpScope, tls_established: bool) -> TransportReport {
    TransportReport {
        src_net,
        tls_established,
        input_pending: false,
    }
}

pub fn cleartext() -> TransportReport {
    report(IpScope::Internal, false)
}

pub fn tls() -> TransportReport {
    report(IpScope::Internal, true)
}

// ---------------------------------------------------------------------------
// The harness: one connection.
// ---------------------------------------------------------------------------

pub struct Harness {
    pub engine: Engine,
    pub session: Session,
    pub snapshot: PolicySnapshot,
    pub pip: TestPip,
    pub subjects: CountingSubjects,
    pub rate: TestRate,
}

impl Harness {
    pub fn new(listener: Listener) -> Harness {
        Harness {
            engine: engine(),
            session: Session::new(7, listener),
            snapshot: root_dse_policy(),
            pip: TestPip::untiered(),
            subjects: CountingSubjects::default(),
            rate: TestRate {
                admit: true,
                calls: 0,
            },
        }
    }

    /// Hand raw octets to the engine.
    pub fn send_octets(&mut self, octets: &[u8], transport: TransportReport) -> Outcome {
        let inputs = RequestInputs {
            snapshot: &self.snapshot,
            pip: &self.pip,
            subjects: &self.subjects,
            rate: &mut self.rate,
            now: now(),
            transport,
            directory: None,
        };
        self.engine.handle(&mut self.session, octets, inputs)
    }

    /// Encode `message` canonically (as the front does) and hand it over.
    pub fn send(&mut self, message: &LdapMessage, transport: TransportReport) -> Outcome {
        let octets = encode_message(message).expect("canonical encoding");
        self.send_octets(&octets, transport)
    }
}

// ---------------------------------------------------------------------------
// Requests (RFC 4511 App. B, built by hand).
// ---------------------------------------------------------------------------

pub fn id(n: u32) -> MessageId {
    MessageId::new(n).expect("valid MessageID")
}

pub fn message(n: u32, protocol_op: ProtocolOp) -> LdapMessage {
    LdapMessage {
        message_id: id(n),
        protocol_op,
        controls: None,
    }
}

pub fn bind(n: u32, version: u8, name: &str, authentication: AuthenticationChoice) -> LdapMessage {
    message(
        n,
        ProtocolOp::BindRequest(BindRequest {
            version,
            name: name.to_owned(),
            authentication,
        }),
    )
}

pub fn simple_bind(n: u32, name: &str, password_empty: bool) -> LdapMessage {
    bind(n, 3, name, AuthenticationChoice::Simple { password_empty })
}

pub fn sasl_bind(n: u32, mechanism: &str, credentials: Option<Vec<u8>>) -> LdapMessage {
    bind(
        n,
        3,
        "",
        AuthenticationChoice::Sasl(SaslCredentials {
            mechanism: mechanism.to_owned(),
            credentials,
        }),
    )
}

/// `(objectClass=*)`. Spec: RFC 4512 §5.1 (the rootDSE filter).
pub fn object_class_present() -> Filter {
    Filter::Present("objectClass".to_owned())
}

pub fn search(
    n: u32,
    base: &str,
    scope: Scope,
    filter: Filter,
    attributes: &[&str],
) -> LdapMessage {
    message(
        n,
        ProtocolOp::SearchRequest(SearchRequest {
            base_object: base.to_owned(),
            scope,
            deref_aliases: DerefAliases::NeverDerefAliases,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter,
            attributes: attributes.iter().map(|a| (*a).to_owned()).collect(),
        }),
    )
}

pub fn root_dse_search(n: u32, attributes: &[&str]) -> LdapMessage {
    search(n, "", Scope::BaseObject, object_class_present(), attributes)
}

pub fn extended(n: u32, name: &str, value: Option<Vec<u8>>) -> LdapMessage {
    message(
        n,
        ProtocolOp::ExtendedRequest(ExtendedRequest {
            request_name: name.to_owned(),
            request_value: value,
        }),
    )
}

pub fn start_tls(n: u32) -> LdapMessage {
    extended(n, START_TLS_OID, None)
}

pub fn unbind(n: u32) -> LdapMessage {
    message(n, ProtocolOp::UnbindRequest)
}

pub fn abandon(n: u32, target: u32) -> LdapMessage {
    message(n, ProtocolOp::AbandonRequest(id(target)))
}

pub fn unsupported(n: u32, op_tag: UnsupportedOp) -> LdapMessage {
    message(n, ProtocolOp::Unsupported { op_tag })
}

pub fn with_controls(mut msg: LdapMessage, controls: Vec<Control>) -> LdapMessage {
    msg.controls = Some(controls);
    msg
}

pub fn control(oid: &str, criticality: bool) -> Control {
    Control {
        control_type: oid.to_owned(),
        criticality,
        control_value: None,
    }
}

// ---------------------------------------------------------------------------
// Responses.
// ---------------------------------------------------------------------------

fn response_options() -> DecodeOptions {
    DecodeOptions {
        direction: Direction::Response,
        profile: Profile::Canonical,
        max_message_octets: MAX_AUTH_MESSAGE_OCTETS,
    }
}

/// Decode one response; it must be canonical, and every LDAPResult in it
/// must have empty matchedDN and diagnosticMessage (R49-13).
pub fn decode(octets: &[u8]) -> LdapMessage {
    let msg = decode_message(octets, &response_options()).expect("canonical response");
    if let Some(result) = result_of(&msg) {
        assert!(result.matched_dn.is_empty(), "matchedDN must be empty");
        assert!(
            result.diagnostic_message.is_empty(),
            "diagnosticMessage must be empty"
        );
    }
    msg
}

pub fn result_of(msg: &LdapMessage) -> Option<&LdapResult> {
    match &msg.protocol_op {
        ProtocolOp::BindResponse(b) => Some(&b.result),
        ProtocolOp::SearchResultDone(r) => Some(r),
        ProtocolOp::ExtendedResponse(e) => Some(&e.result),
        _ => None,
    }
}

/// The single response of an outcome, decoded.
pub fn only_response(outcome: &Outcome) -> LdapMessage {
    assert_eq!(outcome.responses.len(), 1, "exactly one response");
    decode(&outcome.responses[0])
}

/// The result code of the single response.
pub fn only_code(outcome: &Outcome) -> ResultCode {
    let msg = only_response(outcome);
    result_of(&msg).expect("an LDAPResult").result_code
}

/// Decode a ModifyResponse / AddResponse / DelResponse / ModifyDNResponse /
/// CompareResponse: check the protocolOp identifier is `[APPLICATION n]`
/// constructed (X.690 8.1.2.2: class bits `01`, bit 6 = 1), then decode it —
/// parse-ldap's typed `UnsupportedResponse` (Q-190 item 1, A-54) — and
/// return it with its LDAPResult presented as a SearchResultDone, the
/// response it is identical to apart from the tag (RFC 4511 App. B: all are
/// `[APPLICATION n] LDAPResult`; X.690 8.14.4 b)).
pub fn decode_ldap_result_response(octets: &[u8], tag_number: u8) -> LdapMessage {
    // A canonical response this small has the short-form outer length and a
    // short messageID: 30 L 02 n <n octets> <op identifier>.
    assert_eq!(octets[0], 0x30);
    assert!(octets[1] < 0x80);
    assert_eq!(octets[2], 0x02);
    let at = 4 + usize::from(octets[3]);
    assert_eq!(octets[at], 0x60 | tag_number, "response tag");
    let msg = decode(octets);
    match msg.protocol_op {
        ProtocolOp::UnsupportedResponse { op, result } => {
            assert_eq!(op.response_tag_number(), tag_number);
            assert!(result.matched_dn.is_empty(), "matchedDN must be empty");
            assert!(result.diagnostic_message.is_empty());
            LdapMessage {
                message_id: msg.message_id,
                protocol_op: ProtocolOp::SearchResultDone(result),
                controls: msg.controls,
            }
        }
        other => panic!("not a typed unsupported-operation response: {other:?}"),
    }
}

/// `true` if `needle` occurs in `haystack`.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
