//! Task P12 scenario 3 (docs/50 §9 tier 2 across all daemons): LDAP
//! through the whole chain — a rustls / plain TCP client → **ldap-front** →
//! `dird-ldap.sock` → **dird** (the LDAP engine, the PEP) → `audit.sock` →
//! **auditd** — with keyd and the kdc running beside them.
//!
//! * the anonymous rootDSE and an anonymous search of the directory over
//!   **LDAPS** and over **StartTLS**: the responses are octet for octet the
//!   engine's, called in-process over an identical directory with the same
//!   policy file and time (docs/50 §9); dird's events of each operation are
//!   in auditd's verified log;
//! * cleartext octets injected after the StartTLS response ⇒ no LDAP answer,
//!   the connection closes (docs/50 §4.3 step 3); cleartext behind the
//!   StartTLS request in the same write ⇒ operationsError, closed (§4.3
//!   steps 1-2; RFC 4511 §4.14.1);
//! * a password bind over TLS ⇒ refused authMethodNotSupported (A-71;
//!   AGENTS.md §6: cleartext simple bind has no code path).
//!
//! The TLS client is rustls itself with ldap-front's test trust model
//! (tests/support/tls.rs; A-71, Q-285 item 1).
//!
//! Sources: docs/50 R50-10, R50-11, §4.2, §4.3, §8.1, §9; docs/49 R49-14,
//! R49-15, R49-16, §5.2; RFC 4511 §4.2, §4.5.1, §4.14.1, §4.14.2, §5.2;
//! RFC 4513 §3.1.1; A-51, A-52, A-70, A-71. Every value is made here.

#[path = "../../kdc/tests/common/mod.rs"]
mod common;
mod support;

use common::now;
use ipc_audit::{EventBody, LdapOperation, LdapTransport};
use ldap_front::relay::{take_message, WireBuffer};
use parse_ldap::{AuthState, ProtocolOp, ResultCode};
use std::io::{Read, Write};
use support::ldap_client::*;
use support::*;

/// The engine's answer to `message` for `session` (tests/support
/// ldap_client.rs `direct`).
fn reference(
    h: &Harness,
    session: &mut ldap::Session,
    message: &[u8],
    tls: bool,
    input_pending: bool,
) -> Vec<Vec<u8>> {
    direct(
        &h.local.store,
        &h.policy,
        now(),
        session,
        message,
        tls,
        input_pending,
    )
    .responses
}

/// The responses of a search: every message up to and including the
/// SearchResultDone (RFC 4511 §4.5.2).
fn search_responses<R: Read>(reader: &mut LdapReader, stream: &mut R) -> Vec<Vec<u8>> {
    let mut responses = Vec::new();
    loop {
        let response = reader.next(stream).expect("a search response");
        let done = matches!(
            decoded(&response).protocol_op,
            ProtocolOp::SearchResultDone(_)
        );
        responses.push(response);
        if done {
            return responses;
        }
    }
}

/// How many of dird's LDAP events in `events` are `operation`.
fn count(events: &[EventBody], operation: LdapOperation) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, EventBody::Ldap(e) if e.operation == operation))
        .count()
}

/// The anonymous directory search's answer: only a SearchResultDone, not a
/// success — no entry of the directory reaches an anonymous client (crates/
/// ldap: "directory search, anonymous … before the base is looked at";
/// A-55).
fn assert_anonymous_search_refused(responses: &[Vec<u8>]) {
    assert_eq!(responses.len(), 1, "no SearchResultEntry for anonymous");
    assert_ne!(result_code(&responses[0]), ResultCode::Success);
}

/// docs/50 R50-10, §4.2, §4.3 step 6; docs/49 §5.2, R49-14; RFC 4511
/// §4.5.1: over LDAPS (a TLS session from the first octet) the anonymous
/// rootDSE and an anonymous search of dc=example,dc=org are answered octet
/// for octet as the engine answers them; dird's events of both searches,
/// over LDAPS, are in auditd's verified log.
#[test]
fn root_dse_and_anonymous_search_over_ldaps() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        let mut session = ldap::Session::new(1, ldap::Listener::Ldaps);
        let mut stream = tls_over(tcp(h.front().ldaps), &h.tls_client).unwrap();
        let mut reader = LdapReader::default();

        stream.write_all(&root_dse(1)).unwrap();
        let answer = search_responses(&mut reader, &mut stream);
        assert_eq!(answer.len(), 2, "the rootDSE entry and its done");
        assert_eq!(result_code(&answer[1]), ResultCode::Success);
        assert_eq!(
            answer,
            reference(&h, &mut session, &root_dse(1), true, false)
        );

        stream.write_all(&directory_search(2)).unwrap();
        let answer = search_responses(&mut reader, &mut stream);
        assert_eq!(
            answer,
            reference(&h, &mut session, &directory_search(2), true, false)
        );
        assert_anonymous_search_refused(&answer);
        drop(stream);

        // dird's events reach auditd's log (persisted) — waited for before
        // dird stops (tests/support harness.rs `wait_until_persisted`, Q-313).
        assert!(h.wait_until_persisted(|e| count(e, LdapOperation::Search) >= 2));
        h.stop_all();
        let searches: Vec<_> = h
            .ldap_events()
            .into_iter()
            .filter(|e| e.operation == LdapOperation::Search)
            .collect();
        assert_eq!(searches.len(), 2, "dird audited both searches");
        assert!(searches.iter().all(|e| e.transport == LdapTransport::Ldaps));
        assert_eq!(searches[0].result_code, Some(0), "the rootDSE: success");
    });
}

/// docs/50 §4.3 (the hand-over order); RFC 4511 §4.14.1-§4.14.2; RFC 4513
/// §3.1.1: StartTLS on the cleartext listener — the StartTLS response is
/// the engine's, the TLS handshake follows on the same connection, and the
/// anonymous rootDSE and directory search over it are the engine's for a
/// session after StartTLS; dird audited the StartTLS and both searches as
/// StartTLS-carried.
#[test]
fn root_dse_and_anonymous_search_over_start_tls() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        let mut session = ldap::Session::new(1, ldap::Listener::Ldap);
        let mut plain = tcp(h.front().ldap);
        plain.write_all(&start_tls(1)).unwrap();
        let mut reader = LdapReader::default();
        let started = reader.next(&mut plain).unwrap();
        assert!(reader.is_empty());
        assert_eq!(result_code(&started), ResultCode::Success);
        assert_eq!(
            vec![started],
            reference(&h, &mut session, &start_tls(1), false, false)
        );

        let mut stream = tls_over(plain, &h.tls_client).unwrap();
        stream.write_all(&root_dse(2)).unwrap();
        let answer = search_responses(&mut reader, &mut stream);
        assert_eq!(result_code(answer.last().unwrap()), ResultCode::Success);
        assert_eq!(
            answer,
            reference(&h, &mut session, &root_dse(2), true, false)
        );

        stream.write_all(&directory_search(3)).unwrap();
        let answer = search_responses(&mut reader, &mut stream);
        assert_eq!(
            answer,
            reference(&h, &mut session, &directory_search(3), true, false)
        );
        assert_anonymous_search_refused(&answer);
        drop(stream);

        assert!(h.wait_until_persisted(|e| {
            count(e, LdapOperation::StartTls) >= 1 && count(e, LdapOperation::Search) >= 2
        }));
        h.stop_all();
        let events = h.ldap_events();
        assert!(events
            .iter()
            .any(|e| e.operation == LdapOperation::StartTls && e.result_code == Some(0)));
        let searches: Vec<_> = events
            .iter()
            .filter(|e| e.operation == LdapOperation::Search)
            .collect();
        assert_eq!(searches.len(), 2);
        assert!(searches
            .iter()
            .all(|e| e.transport == LdapTransport::StartTls));
    });
}

/// docs/50 §4.3 step 3 ("a cleartext octet injected after the response is
/// parsed as TLS and fails ⇒ close"): after a successful StartTLS response
/// the client sends a cleartext rootDSE instead of a ClientHello — no LDAP
/// answer comes back (at most a TLS alert record, RFC 8446 §5.1:
/// ContentType alert = 21) and the connection closes. And docs/50 §4.3
/// steps 1-2, RFC 4511 §4.14.1, docs/49 §4.4 (R49-15): StartTLS with a
/// cleartext rootDSE behind it in the same write ⇒ the engine's
/// operationsError, then closed, the injected search unanswered.
#[test]
fn cleartext_injected_around_start_tls_closes_the_connection() {
    within(TEST_BOUND, || {
        let Some(h) = Harness::start() else {
            return;
        };
        // After the response.
        let mut plain = tcp(h.front().ldap);
        plain.write_all(&start_tls(1)).unwrap();
        let mut reader = LdapReader::default();
        let started = reader.next(&mut plain).unwrap();
        assert_eq!(result_code(&started), ResultCode::Success);
        plain.write_all(&root_dse(2)).unwrap();
        let mut received = Vec::new();
        // Bounded by the stream's read timeout (tests/support ldap_client).
        let end = plain.read_to_end(&mut received);
        assert!(end.is_ok(), "closed by the front, not timed out: {end:?}");
        if let Some(&first) = received.first() {
            assert_eq!(first, 21, "only a TLS alert may come back");
        }

        // Behind the request, in the same write.
        let mut plain = tcp(h.front().ldap);
        let mut both = start_tls(1);
        both.extend_from_slice(&root_dse(2));
        plain.write_all(&both).unwrap();
        let mut reader = LdapReader::default();
        let refused = reader.next(&mut plain).unwrap();
        assert_eq!(result_code(&refused), ResultCode::OperationsError);
        let mut session = ldap::Session::new(1, ldap::Listener::Ldap);
        assert_eq!(
            vec![refused],
            reference(&h, &mut session, &start_tls(1), false, true)
        );
        assert!(reader.is_empty());
        assert_eq!(closed(&mut plain), Ok(()));
    });
}

/// RFC 4511 §4.2 (a simple bind with a password); A-71; AGENTS.md §6
/// (cleartext simple bind has no code path; crates/ldap: "simple bind with
/// a password | authMethodNotSupported (7), before any lookup, never
/// keyd"): over LDAPS and over StartTLS the bind is refused with 7, octet
/// for octet the engine's answer to the canonical message the front relays
/// (the password replaced by the decoder's placeholder, A-52); dird audited
/// both refusals.
#[test]
fn a_password_bind_over_tls_is_refused() {
    within(TEST_BOUND, || {
        let Some(mut h) = Harness::start() else {
            return;
        };
        let mut wire = WireBuffer::new();
        wire.extend(&password_bind()).unwrap();
        let canonical = take_message(&mut wire, AuthState::Unauthenticated)
            .unwrap()
            .unwrap()
            .canonical;

        // LDAPS.
        let mut stream = tls_over(tcp(h.front().ldaps), &h.tls_client).unwrap();
        stream.write_all(&password_bind()).unwrap();
        let mut reader = LdapReader::default();
        let response = reader.next(&mut stream).unwrap();
        assert!(matches!(
            decoded(&response).protocol_op,
            ProtocolOp::BindResponse(_)
        ));
        assert_eq!(result_code(&response), ResultCode::AuthMethodNotSupported);
        let mut session = ldap::Session::new(1, ldap::Listener::Ldaps);
        assert_eq!(
            vec![response],
            reference(&h, &mut session, &canonical, true, false)
        );
        drop(stream);

        // StartTLS.
        let mut plain = tcp(h.front().ldap);
        plain.write_all(&start_tls(2)).unwrap();
        let mut reader = LdapReader::default();
        assert_eq!(
            result_code(&reader.next(&mut plain).unwrap()),
            ResultCode::Success
        );
        let mut stream = tls_over(plain, &h.tls_client).unwrap();
        stream.write_all(&password_bind()).unwrap();
        let response = reader.next(&mut stream).unwrap();
        assert_eq!(result_code(&response), ResultCode::AuthMethodNotSupported);
        drop(stream);

        assert!(h.wait_until_persisted(|e| count(e, LdapOperation::Bind) >= 2));
        h.stop_all();
        let binds: Vec<_> = h
            .ldap_events()
            .into_iter()
            .filter(|e| e.operation == LdapOperation::Bind)
            .collect();
        assert_eq!(binds.len(), 2, "dird audited both refusals");
        assert!(binds.iter().all(|e| e.result_code == Some(7)));
    });
}
