//! The rootDSE (docs/49 §5.2, R49-10) and the other searches of L4.
//!
//! Sources (each test names its own): [MS-ADTS] v20261026 3.1.1.3.1.3.6,
//! 3.1.1.3.2 (the attribute table and .3, .4, .13, .16, .23, .33); RFC 4511
//! §4.5.1.6, §4.5.1.8, §4.5.2; RFC 4512 §2.5, §5.1, §5.1.3, §5.1.7; RFC 4517
//! §3.3.16; docs/49 §2.3 E14, §4.3, §5.2, §6.5, §9; docs/15 §6; Q-169;
//! Q-170; A-51. Hand-made requests and policy.

mod common;

use common::*;
use ldap::{AuditReason, AuditScope, AuditTarget, ConnectionAction, Listener};
use parse_ldap::{
    AttributeValueAssertion, Filter, LdapMessage, ProtocolOp, ResultCode, Scope, SearchResultEntry,
    START_TLS_OID,
};
use pdp::{
    Constraint, IpScope, Obligation, PipError, PolicySnapshot, PolicyVersion, ReasonCode,
    TransportSec,
};

/// The entry and the done code of a rootDSE outcome (two responses).
fn entry_and_done(outcome: &ldap::Outcome, msg: &LdapMessage) -> SearchResultEntry {
    assert_eq!(outcome.responses.len(), 2, "entry + done");
    let first = decode(&outcome.responses[0]);
    let second = decode(&outcome.responses[1]);
    assert_eq!(first.message_id, msg.message_id);
    assert_eq!(second.message_id, msg.message_id);
    match second.protocol_op {
        ProtocolOp::SearchResultDone(r) => assert_eq!(r.result_code, ResultCode::Success),
        other => panic!("not a SearchResultDone: {other:?}"),
    }
    match first.protocol_op {
        ProtocolOp::SearchResultEntry(e) => e,
        other => panic!("not a SearchResultEntry: {other:?}"),
    }
}

/// A SearchResultDone-only outcome's code.
fn done_code(outcome: &ldap::Outcome) -> ResultCode {
    match only_response(outcome).protocol_op {
        ProtocolOp::SearchResultDone(r) => r.result_code,
        other => panic!("not a SearchResultDone: {other:?}"),
    }
}

fn names(entry: &SearchResultEntry) -> Vec<&str> {
    entry.attributes.iter().map(|a| a.r#type.as_str()).collect()
}

fn values<'e>(entry: &'e SearchResultEntry, name: &str) -> &'e [Vec<u8>] {
    &entry
        .attributes
        .iter()
        .find(|a| a.r#type == name)
        .expect("attribute present")
        .vals
}

/// The non-operational phase-1 attributes, in the engine's order.
/// Spec: [MS-ADTS] 3.1.1.3.2 ("Operational?" = N); docs/49 §5.2.
const DEFAULT_SET: [&str; 5] = [
    "namingContexts",
    "defaultNamingContext",
    "rootDomainNamingContext",
    "dNSHostName",
    "supportedLDAPVersion",
];

/// docs/49 §5.2 + Q-170 / A-51: an anonymous request from the internal
/// network, under the rootDSE allowlist entry, gets the entry — in cleartext
/// (docs/49 §4.3 row 1) and over TLS. The empty list asks for every
/// non-operational attribute (RFC 4511 §4.5.1.8; [MS-ADTS] 3.1.1.3.2); the
/// entry is named by the empty DN (RFC 4512 §5.1).
#[test]
fn anonymous_internal_request_under_the_grant_gets_the_entry() {
    for (listener, transport) in [(Listener::Ldap, cleartext()), (Listener::Ldaps, tls())] {
        let mut h = Harness::new(listener);
        let msg = root_dse_search(1, &[]);
        let outcome = h.send(&msg, transport);
        assert_eq!(outcome.action, ConnectionAction::Continue);
        let entry = entry_and_done(&outcome, &msg);
        assert_eq!(entry.object_name, "");
        assert_eq!(names(&entry), DEFAULT_SET);
        for nc in [
            "namingContexts",
            "defaultNamingContext",
            "rootDomainNamingContext",
        ] {
            assert_eq!(values(&entry, nc), [NAMING_CONTEXT.as_bytes().to_vec()]);
        }
        assert_eq!(
            values(&entry, "dNSHostName"),
            [DNS_HOST_NAME.as_bytes().to_vec()]
        );
        // Integer "3" only — no LDAPv2. Spec: [MS-ADTS] 3.1.1.3.2.23;
        // RFC 4517 §3.3.16.
        assert_eq!(values(&entry, "supportedLDAPVersion"), [b"3".to_vec()]);

        assert_eq!(outcome.audit.reason, AuditReason::RootDseReturned);
        assert_eq!(outcome.audit.target, Some(AuditTarget::RootDse));
        assert_eq!(outcome.audit.principal, None);
        let search = outcome.audit.search.expect("search facts");
        assert_eq!(search.scope, AuditScope::BaseObject);
        assert_eq!(search.entries_returned, 1);
        assert_eq!(outcome.audit.result_code, Some(ResultCode::Success));
        // The PDP was consulted with the PIP's tier of the anonymous
        // principal (Q-170 item 5).
        assert!(h.pip.tier_calls.get() >= 1);
        assert_eq!(h.rate.calls, 1, "RateLimit obligation honoured");
    }
}

/// [MS-ADTS] 3.1.1.3.2: supportedExtension is operational ("returns the
/// attribute only when it is explicitly requested"); its value is the
/// StartTLS OID ([MS-ADTS] 3.1.1.3.2.33, 3.1.1.3.4.2). RFC 4512 §2.5: names
/// are case-insensitive. RFC 4511 §4.5.1.8: each attribute at most once.
#[test]
fn attributes_requested_by_name_case_insensitively_once() {
    let mut h = Harness::new(Listener::Ldap);
    let msg = root_dse_search(
        2,
        &["SUPPORTEDEXTENSION", "dnshostname", "supportedExtension"],
    );
    let entry = entry_and_done(&h.send(&msg, cleartext()), &msg);
    assert_eq!(names(&entry), ["dNSHostName", "supportedExtension"]);
    assert_eq!(
        values(&entry, "supportedExtension"),
        [START_TLS_OID.as_bytes().to_vec()]
    );
}

/// RFC 4511 §4.5.1.8: "*" asks for all user attributes "in addition to other
/// listed (operational) attributes"; "1.1" alone asks for none, and is
/// ignored beside other selectors; an unrecognised description is ignored.
#[test]
fn special_selectors() {
    let cases: [(&[&str], Vec<&str>); 5] = [
        (&["*"], DEFAULT_SET.to_vec()),
        (&["*", "supportedExtension"], {
            let mut all = DEFAULT_SET.to_vec();
            all.push("supportedExtension");
            all
        }),
        (&["1.1"], vec![]),
        (&["1.1", "namingContexts"], vec!["namingContexts"]),
        (&["noSuchAttribute", "currentTime"], vec![]),
    ];
    for (selection, expected) in cases {
        let mut h = Harness::new(Listener::Ldap);
        let msg = root_dse_search(3, selection);
        let entry = entry_and_done(&h.send(&msg, cleartext()), &msg);
        assert_eq!(names(&entry), expected, "{selection:?}");
    }
}

/// [MS-ADTS] 3.1.1.3.1.3.6: rootDSE attributes "MUST be specified by their
/// LDAP display name" — a numeric OID is "the same as specifying a
/// nonexistent attribute"; RFC 4512 §2.5: a description with an unrecognised
/// option is unrecognised.
#[test]
fn numeric_oids_and_options_select_nothing() {
    let mut h = Harness::new(Listener::Ldap);
    let msg = root_dse_search(4, &["1.3.6.1.4.1.1466.101.120.5", "namingContexts;binary"]);
    let entry = entry_and_done(&h.send(&msg, cleartext()), &msg);
    assert!(entry.attributes.is_empty());
}

/// RFC 4511 §4.5.1.6: typesOnly returns the descriptions without values.
#[test]
fn types_only_returns_no_values() {
    let mut h = Harness::new(Listener::Ldap);
    let mut msg = root_dse_search(5, &[]);
    if let ProtocolOp::SearchRequest(s) = &mut msg.protocol_op {
        s.types_only = true;
    }
    let entry = entry_and_done(&h.send(&msg, cleartext()), &msg);
    assert_eq!(names(&entry), DEFAULT_SET);
    assert!(entry.attributes.iter().all(|a| a.vals.is_empty()));
}

/// [MS-ADTS] 3.1.1.3.1.3.6: "When performing a search against the rootDSE,
/// the server will ignore the contents of the search filter" (docs/49
/// §5.2): any filter gives the same entry.
#[test]
fn the_filter_of_a_root_dse_search_is_ignored() {
    let filters = [
        object_class_present(),
        Filter::EqualityMatch(AttributeValueAssertion {
            attribute_desc: "objectClass".to_owned(),
            assertion_value: b"nothing-has-this".to_vec(),
        }),
        Filter::Not(Box::new(object_class_present())),
    ];
    for filter in filters {
        let mut h = Harness::new(Listener::Ldap);
        let msg = search(6, "", Scope::BaseObject, filter, &[]);
        let entry = entry_and_done(&h.send(&msg, cleartext()), &msg);
        assert_eq!(names(&entry), DEFAULT_SET);
    }
}

/// docs/49 §6.5 ("Secret and nTSecurityDescriptor never"; §8.2 names
/// unicodePwd and ntPwdHistory as Secret) and §5.2 (the minimal set):
/// asking for Secret or descriptor attributes by name returns
/// nothing but the phase-1 set; no value carries anything but configuration.
#[test]
fn no_secret_or_descriptor_attribute_is_ever_returned() {
    let mut h = Harness::new(Listener::Ldaps);
    let msg = root_dse_search(
        7,
        &["unicodePwd", "ntPwdHistory", "nTSecurityDescriptor", "*"],
    );
    let entry = entry_and_done(&h.send(&msg, tls()), &msg);
    assert_eq!(names(&entry), DEFAULT_SET);
}

/// Q-169 item 3 / docs/49 §9 (PDP `Unauthenticated` → operationsError) and
/// docs/15 §6 / A-51 (anonymous: internal network only): an anonymous
/// request from outside is denied with no entry.
#[test]
fn anonymous_external_request_is_denied_with_operations_error() {
    let mut h = Harness::new(Listener::Ldaps);
    let outcome = h.send(&root_dse_search(8, &[]), report(IpScope::External, true));
    assert_eq!(done_code(&outcome), ResultCode::OperationsError);
    assert_eq!(
        outcome.audit.reason,
        AuditReason::PolicyDenied(ReasonCode::Unauthenticated)
    );
    assert_eq!(
        outcome.audit.search.expect("search facts").entries_returned,
        0
    );
    assert_eq!(outcome.action, ConnectionAction::Continue);
}

/// Deny by default (docs/11 §4): with no allowlist entry the anonymous read
/// is `Unauthenticated` → operationsError; with the entry but no Allow rule
/// it is `NoGrant` → insufficientAccessRights (docs/49 §9).
#[test]
fn without_grant_or_rule_the_root_dse_is_denied() {
    let mut no_grant = Harness::new(Listener::Ldap);
    no_grant.snapshot = PolicySnapshot::new(PolicyVersion(2), vec![root_dse_allow(vec![])], vec![]);
    let outcome = no_grant.send(&root_dse_search(9, &[]), cleartext());
    assert_eq!(done_code(&outcome), ResultCode::OperationsError);

    let mut no_rule = Harness::new(Listener::Ldap);
    no_rule.snapshot = PolicySnapshot::new(
        PolicyVersion(3),
        vec![],
        vec![root_dse_grant(IpScope::Internal, TransportSec::NONE)],
    );
    let outcome = no_rule.send(&root_dse_search(9, &[]), cleartext());
    assert_eq!(done_code(&outcome), ResultCode::InsufficientAccessRights);
    assert_eq!(
        outcome.audit.reason,
        AuditReason::PolicyDenied(ReasonCode::NoGrant)
    );
}

/// docs/49 §9 (`WeakTransport`, no encryption → confidentialityRequired) and
/// RFC 4513 §6.1: a grant whose minimum is `{encrypted}` refuses a
/// cleartext read and admits it over TLS (after StartTLS).
#[test]
fn a_grant_requiring_encryption_refuses_cleartext() {
    let encrypted = TransportSec {
        encrypted: true,
        sealed: false,
        channel_bound: false,
    };
    let mut h = Harness::new(Listener::Ldap);
    h.snapshot = PolicySnapshot::new(
        PolicyVersion(4),
        vec![root_dse_allow(vec![])],
        vec![root_dse_grant(IpScope::Internal, encrypted)],
    );
    let outcome = h.send(&root_dse_search(10, &[]), cleartext());
    assert_eq!(done_code(&outcome), ResultCode::ConfidentialityRequired);

    h.send(&start_tls(11), cleartext());
    let over_tls = h.send(&root_dse_search(12, &[]), tls());
    assert_eq!(over_tls.responses.len(), 2);
}

/// docs/11 §2, §8 (the PEP honours RateLimit); docs/49 §10.2: a refused
/// rate-limit admission sends no entry (busy — Q-190 item 4).
#[test]
fn a_refused_rate_limit_sends_no_entry() {
    let mut h = Harness::new(Listener::Ldap);
    h.rate.admit = false;
    let outcome = h.send(&root_dse_search(13, &[]), cleartext());
    assert_eq!(done_code(&outcome), ResultCode::Busy);
    assert_eq!(outcome.audit.reason, AuditReason::RateLimited);
}

/// docs/11 §8 (Constrain: a page-size cap); docs/49 §6.1 item 7 (server limit
/// → adminLimitExceeded): a cap of zero admits no entry; a cap of one admits
/// the rootDSE.
#[test]
fn a_page_size_obligation_is_honoured() {
    let mut zero = Harness::new(Listener::Ldap);
    zero.snapshot = PolicySnapshot::new(
        PolicyVersion(5),
        vec![root_dse_allow(vec![Obligation::Constrain(
            Constraint::MaxPageSize(0),
        )])],
        vec![root_dse_grant(IpScope::Internal, TransportSec::NONE)],
    );
    let outcome = zero.send(&root_dse_search(14, &[]), cleartext());
    assert_eq!(done_code(&outcome), ResultCode::AdminLimitExceeded);

    let mut one = Harness::new(Listener::Ldap);
    one.snapshot = PolicySnapshot::new(
        PolicyVersion(6),
        vec![root_dse_allow(vec![Obligation::Constrain(
            Constraint::MaxPageSize(1),
        )])],
        vec![root_dse_grant(IpScope::Internal, TransportSec::NONE)],
    );
    assert_eq!(
        one.send(&root_dse_search(15, &[]), cleartext())
            .responses
            .len(),
        2
    );
}

/// D40 / Q-170 item 5 (fail closed): when the PIP cannot give the anonymous
/// principal's tier, the read is refused with other (80) (docs/49 §9).
#[test]
fn a_pip_failure_is_other() {
    let mut h = Harness::new(Listener::Ldap);
    h.pip.tier = Err(PipError::Unavailable);
    let outcome = h.send(&root_dse_search(16, &[]), cleartext());
    assert_eq!(done_code(&outcome), ResultCode::Other);
    assert_eq!(outcome.audit.reason, AuditReason::SubjectUnavailable);
}

/// docs/49 §5.2 ("scope other than base on '' → unwillingToPerform"); RFC
/// 4512 §5.1 ("The root DSE SHALL NOT be included if the client performs a
/// subtree search starting from the root").
#[test]
fn the_empty_base_with_another_scope_is_unwilling_to_perform() {
    for scope in [Scope::SingleLevel, Scope::WholeSubtree] {
        let mut h = Harness::new(Listener::Ldap);
        let outcome = h.send(
            &search(17, "", scope, object_class_present(), &[]),
            cleartext(),
        );
        assert_eq!(done_code(&outcome), ResultCode::UnwillingToPerform);
        assert_eq!(outcome.audit.reason, AuditReason::RootDseScopeNotBase);
    }
}

/// docs/49 §12: directory search is task L8; every search of a non-empty base
/// is unwillingToPerform in L4, and the PDP is not consulted.
#[test]
fn every_other_search_is_unwilling_to_perform() {
    for scope in [Scope::BaseObject, Scope::SingleLevel, Scope::WholeSubtree] {
        let mut h = Harness::new(Listener::Ldaps);
        let outcome = h.send(
            &search(18, NAMING_CONTEXT, scope, object_class_present(), &[]),
            tls(),
        );
        assert_eq!(done_code(&outcome), ResultCode::UnwillingToPerform);
        assert_eq!(outcome.audit.reason, AuditReason::SearchNotImplemented);
        assert_eq!(outcome.audit.target, None);
        assert_eq!(h.pip.tier_calls.get(), 0);
    }
}

/// docs/49 §2.3 E14: an unrecognised scope gets the operation's response with
/// protocolError (not a disconnection).
#[test]
fn an_unrecognized_scope_is_protocol_error() {
    let mut h = Harness::new(Listener::Ldap);
    let outcome = h.send(
        &search(19, "", Scope::Unrecognized(7), object_class_present(), &[]),
        cleartext(),
    );
    assert_eq!(done_code(&outcome), ResultCode::ProtocolError);
    assert_eq!(outcome.action, ConnectionAction::Continue);
    assert_eq!(
        outcome.audit.search.expect("search facts").scope,
        AuditScope::Unrecognized
    );
}
