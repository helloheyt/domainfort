//! `open_and_verify_service_ticket` (task L6a): RFC 4120 §3.2.3 run inside
//! keyd under the LDAP service key, for Role::Ldap only, returning only
//! non-secret facts.
//!
//! The tests play three parts: the KDC (keyd's own AS and TGS issue the
//! service ticket for the LDAP service principal), the Kerberos client
//! (building the AP-REQ with krb-crypto from the RFC 4120 §5.5.1 text, key
//! usage 11 of §7.5.1), and — to exercise A-19 and the ticket checks — a
//! compromised KDC that seals tickets of its own under a key it knows.
//! Every value is constructed by hand for these tests; no vector comes from
//! any other implementation.
//!
//! Sources: RFC 4120 §2.2, §3.2.3, §3.3.3.2, §5.3, §5.5.1, §7.5.1, §7.5.5;
//! [MS-KILE] 3.4.5; docs/10 §2, §5ב, §9, §12; docs/49 §3.3;
//! docs/questions/Q-165 (A-46), Q-180; A-19 (Q-040); A-26 (Q-071).

mod common;

use common::*;
use keyd::{AuditOutcome, AuditReason, AuthnError, KeyHandle, KeyPurpose, Kvno, PrincipalId};
use krb_crypto::{ChecksumType, EncType, ProtocolKey};
use krb_proto::constants::{DOMAIN_X500_COMPRESS, KRB_NT_SRV_INST};
use krb_proto::{
    ApOptions, ApReq, Authenticator, AuthorizationData, AuthorizationElement, Checksum,
    EncTgsRepPart, EncTicketPart, EncryptedData, EncryptionKey, HostAddress, HostAddresses,
    KerberosTime, KeyValue, Microseconds, PrincipalName, Realm, Ticket, TicketFlags,
    TransitedEncoding,
};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// The KDC side: keyd's own AS and TGS issue alice's LDAP service ticket.
// ---------------------------------------------------------------------------

/// A service ticket keyd issued, and what the client learned with it.
struct Issued {
    ticket: Ticket,
    /// The service session key (from EncTGSRepPart, RFC 4120 5.4.2).
    session: ProtocolKey,
    session_octets: Vec<u8>,
    authtime: KerberosTime,
    flags: TicketFlags,
    endtime: KerberosTime,
}

/// A fixture with the LDAP service key set (created by `create_key`, A-46).
fn fixture() -> Fixture {
    let mut f = Fixture::new();
    add_ldap_service(&mut f);
    f
}

/// RFC 4120 §3.3: a TGS exchange through keyd for `sname`, sealed under the
/// service key `service`. `cusec` keeps each TGS authenticator distinct.
fn issue(
    f: &mut Fixture,
    tgt: &Tgt,
    service: &KeyHandle,
    sname: PrincipalName,
    cusec: u32,
    endtime: KerberosTime,
) -> Issued {
    let nonce = 0x4C00_0000 + cusec;
    let (_, body) = tgs_req_body(nonce, sname.clone());
    let auth = authenticator(&tgt.session, &AuthenticatorSpec::new(now(), cusec, &body));
    let ctx = f
        .keyd
        .open_and_verify_tgt(
            &KDC,
            &KRBTGT,
            &ap_req(&tgt.parts.ticket, auth),
            &body,
            None,
            &now(),
        )
        .unwrap();
    let template = keyd::TgsTicketTemplate {
        sname,
        endtime,
        ..tgs_template(nonce)
    };
    let rep = f
        .keyd
        .issue_tgs_rep(&KDC, service, &ctx.ctx_id, &template, &now())
        .unwrap();
    let part = EncTgsRepPart::decode(&open(&tgt.session, 8, &rep.enc_part)).unwrap();
    f.keyd.audit_sink_mut().records.clear();
    Issued {
        ticket: rep.ticket,
        session: key_from(&part.0.key),
        session_octets: part.0.key.keyvalue.as_bytes().to_vec(),
        authtime: part.0.authtime,
        flags: part.0.flags,
        endtime: part.0.endtime,
    }
}

/// Alice's LDAP service ticket, valid until 17:00.
fn ldap_ticket(f: &mut Fixture, tgt: &Tgt, cusec: u32) -> Issued {
    issue(
        f,
        tgt,
        &LDAP_SERVICE,
        ldap_service_name(),
        cusec,
        kt("20261113170000Z"),
    )
}

// ---------------------------------------------------------------------------
// The client side: the application AP-REQ (RFC 4120 §3.2.2, §5.5.1).
// ---------------------------------------------------------------------------

/// An application authenticator: encrypted in the ticket session key with
/// key usage 11 ("in normal application exchanges", RFC 4120 5.5.1).
struct ApAuth {
    crealm: Realm,
    cname: PrincipalName,
    ctime: KerberosTime,
    cusec: u32,
    subkey: Option<EncryptionKey>,
    cksum: Option<Checksum>,
    authorization_data: Option<AuthorizationData>,
    usage: u32,
}

impl ApAuth {
    fn new(ctime: KerberosTime, cusec: u32) -> Self {
        ApAuth {
            crealm: realm(),
            cname: alice_name(),
            ctime,
            cusec,
            subkey: None,
            cksum: None,
            authorization_data: None,
            usage: 11,
        }
    }
}

fn seal_authenticator(session: &ProtocolKey, spec: &ApAuth) -> EncryptedData {
    let plain = Authenticator {
        crealm: spec.crealm.clone(),
        cname: spec.cname.clone(),
        cksum: spec.cksum.clone(),
        cusec: Microseconds::new(spec.cusec).unwrap(),
        ctime: spec.ctime,
        subkey: spec.subkey.clone(),
        seq_number: None,
        authorization_data: spec.authorization_data.clone(),
    }
    .encode()
    .unwrap();
    EncryptedData {
        etype: session.enc_type().number(),
        kvno: None,
        cipher: krb_crypto::encrypt(session, usage(spec.usage), &[0x77; 16], &plain).unwrap(),
    }
}

/// The DER of a KRB_AP_REQ (RFC 4120 5.5.1).
fn octets(ticket: &Ticket, authenticator: EncryptedData, ap_options: ApOptions) -> Vec<u8> {
    ApReq {
        ap_options,
        ticket: ticket.clone(),
        authenticator,
    }
    .encode()
    .unwrap()
}

/// A fresh AP-REQ for `issued` at `when`.
fn ap_octets(issued: &Issued, when: KerberosTime, cusec: u32) -> Vec<u8> {
    octets(
        &issued.ticket,
        seal_authenticator(&issued.session, &ApAuth::new(when, cusec)),
        ApOptions::empty(),
    )
}

// ---------------------------------------------------------------------------
// The compromised-KDC side: tickets sealed under a known service key.
// ---------------------------------------------------------------------------

const FORGED_SESSION: [u8; 32] = [0x2A; 32];

fn forged_session_key() -> ProtocolKey {
    krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &FORGED_SESSION).unwrap()
}

/// An EncTicketPart as keyd's TGS would build it for alice (RFC 4120 5.3):
/// empty transited (local authentication, 3.3.3.2), no addresses, no
/// authorization-data.
fn ticket_part() -> EncTicketPart {
    EncTicketPart {
        flags: TicketFlags::PRE_AUTHENT,
        key: EncryptionKey {
            keytype: 18,
            keyvalue: KeyValue::from_slice(&FORGED_SESSION),
        },
        crealm: realm(),
        cname: alice_name(),
        transited: TransitedEncoding {
            tr_type: DOMAIN_X500_COMPRESS,
            contents: Vec::new(),
        },
        authtime: now(),
        starttime: Some(now()),
        endtime: kt("20261113170000Z"),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    }
}

/// A ticket for `sname` with `part` sealed under `key` (usage 2, RFC 4120
/// 5.3).
fn seal_ticket(
    key: &ProtocolKey,
    sname: PrincipalName,
    part: &EncTicketPart,
    kvno: Option<u32>,
) -> Ticket {
    let plain: Zeroizing<Vec<u8>> = part.encode().unwrap();
    Ticket {
        realm: realm(),
        sname,
        enc_part: EncryptedData {
            etype: key.enc_type().number(),
            kvno,
            cipher: krb_crypto::encrypt(key, usage(2), &[0x88; 16], &plain).unwrap(),
        },
    }
}

/// An AP-REQ around a forged ticket, with a valid authenticator under the
/// forged session key.
fn forged_octets(ticket: &Ticket, cusec: u32) -> Vec<u8> {
    octets(
        ticket,
        seal_authenticator(&forged_session_key(), &ApAuth::new(now(), cusec)),
        ApOptions::empty(),
    )
}

// ---------------------------------------------------------------------------
// Helpers on the verification side.
// ---------------------------------------------------------------------------

fn verify(
    f: &mut Fixture,
    ap: &[u8],
    when: KerberosTime,
) -> Result<keyd::ServiceContext, AuthnError> {
    f.keyd
        .open_and_verify_service_ticket(&LDAP, &LDAP_SERVICE, ap, &when)
}

fn last_reason(f: &Fixture) -> AuditReason {
    f.records().last().unwrap().reason
}

fn live_contexts(f: &Fixture) -> String {
    let text = format!("{:?}", f.keyd);
    let start = text.find("live_service_contexts: ").unwrap();
    text[start..]
        .trim_start_matches("live_service_contexts: ")
        .chars()
        .take_while(char::is_ascii_digit)
        .collect()
}

/// Decimal and hex renderings of the first octets of `secret`, as they would
/// appear if a byte slice leaked into Debug output.
fn renderings(secret: &[u8]) -> Vec<String> {
    let h = &secret[..4];
    vec![
        format!("{}, {}, {}, {}", h[0], h[1], h[2], h[3]),
        format!("{:02x}{:02x}{:02x}{:02x}", h[0], h[1], h[2], h[3]),
        format!("{:02X}{:02X}{:02X}{:02X}", h[0], h[1], h[2], h[3]),
    ]
}

// ---------------------------------------------------------------------------
// The round trip.
// ---------------------------------------------------------------------------

/// The full round trip: keyd's TGS issues alice's ticket for the LDAP
/// service principal; the client sends a KRB_AP_REQ; keyd verifies it under
/// the LDAP service key and returns only the ticket's non-secret facts and
/// a one-time context id. One audit record, with the kvno used.
/// Source: RFC 4120 §3.2.3 ("If all these checks succeed without an error,
/// the server is assured that the client possesses the credentials of the
/// principal named in the ticket"); docs/49 §3.3; A-46.
#[test]
fn round_trip_returns_only_ticket_facts() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);

    let ctx = verify(&mut f, &ap_octets(&issued, now(), 500), now()).unwrap();
    assert_eq!(ctx.crealm, realm());
    assert_eq!(ctx.cname, alice_name());
    assert_eq!(ctx.authtime, issued.authtime);
    assert_eq!(ctx.authtime, tgt.rep.0.authtime);
    assert_eq!(ctx.endtime, issued.endtime);
    assert_eq!(ctx.flags, issued.flags);
    assert!(ctx.flags.contains(TicketFlags::PRE_AUTHENT));
    assert!(!ctx.subkey_present);

    let records = f.records();
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r.op, keyd::Operation::OpenAndVerifyServiceTicket);
    assert_eq!(r.caller_role, keyd::Role::Ldap);
    assert_eq!(r.caller_uid, LDAP.uid);
    assert_eq!(r.principal, Some(LDAP_SERVICE_ID));
    assert_eq!(r.purpose, Some(KeyPurpose::Service));
    assert_eq!(r.kvno, Some(Kvno::INITIAL));
    assert_eq!(r.result, AuditOutcome::Success);
    // The session key is held in keyd's service-context table.
    assert_eq!(live_contexts(&f), "1");
}

/// A subkey in the authenticator is reported only as present; the subkey
/// itself stays in keyd. Source: RFC 4120 §3.2.3 ("If a subkey is present,
/// the server either saves it for later use ..."), §5.5.1; A-46.
#[test]
fn subkey_is_reported_only_as_present() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    let subkey = [0x5B; 32];
    let mut spec = ApAuth::new(now(), 501);
    spec.subkey = Some(EncryptionKey {
        keytype: 18,
        keyvalue: KeyValue::from_slice(&subkey),
    });
    let ap = octets(
        &issued.ticket,
        seal_authenticator(&issued.session, &spec),
        ApOptions::empty(),
    );
    let ctx = verify(&mut f, &ap, now()).unwrap();
    assert!(ctx.subkey_present);
    let text = format!("{ctx:?} {:?}", f.records());
    for r in renderings(&subkey)
        .into_iter()
        .chain(renderings(&issued.session_octets))
    {
        assert!(!text.contains(&r), "key material in output: {r}");
    }

    // A subkey of an enctype that is not configured is refused (I5).
    let mut spec = ApAuth::new(now(), 502);
    spec.subkey = Some(EncryptionKey {
        keytype: 17,
        keyvalue: KeyValue::from_slice(&[0x5C; 16]),
    });
    let ap = octets(
        &issued.ticket,
        seal_authenticator(&issued.session, &spec),
        ApOptions::empty(),
    );
    assert_eq!(verify(&mut f, &ap, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::UnsupportedEncType);
}

/// The ticket is decrypted under the key version its kvno names — after a
/// rotation, the previous version still opens an older ticket; without a
/// kvno, current then previous are tried; once the old version is retired
/// the ticket is refused. Source: RFC 4120 §3.2.3 ("decrypted using the
/// version of the server's key specified by the ticket";
/// KRB_AP_ERR_BADKEYVER); [MS-KILE] 3.4.5 (retry with older versions of the
/// server key); docs/10 §1, §7.
#[test]
fn ticket_opens_under_current_or_previous_kvno() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    assert_eq!(issued.ticket.enc_part.kvno, Some(1));
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, &LDAP_SERVICE, &now()),
        Ok(Kvno::new(2))
    );

    assert!(verify(&mut f, &ap_octets(&issued, now(), 510), now()).is_ok());
    assert_eq!(f.records().last().unwrap().kvno, Some(Kvno::new(1)));

    // The kvno is outside the encryption: strip it, keyd tries both.
    let mut no_kvno = issued.ticket.clone();
    no_kvno.enc_part.kvno = None;
    let ap = octets(
        &no_kvno,
        seal_authenticator(&issued.session, &ApAuth::new(now(), 511)),
        ApOptions::empty(),
    );
    assert!(verify(&mut f, &ap, now()).is_ok());
    assert_eq!(f.records().last().unwrap().kvno, Some(Kvno::new(1)));

    // A ticket issued after the rotation is sealed under kvno 2.
    let fresh = ldap_ticket(&mut f, &tgt, 2);
    assert_eq!(fresh.ticket.enc_part.kvno, Some(2));
    assert!(verify(&mut f, &ap_octets(&fresh, now(), 512), now()).is_ok());

    f.keyd
        .retire_kvno(&ADMIN, &LDAP_SERVICE, Kvno::new(1), &now())
        .unwrap();
    assert_eq!(
        verify(&mut f, &ap_octets(&issued, now(), 513), now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::KvnoMismatch);
}

// ---------------------------------------------------------------------------
// Refusals before any key is used.
// ---------------------------------------------------------------------------

/// A-19: a ticket naming another service is never opened under the LDAP
/// key — refused before any key is used (no kvno in audit), whether it is a
/// genuine ticket for another service, alice's TGT, or a ticket a
/// compromised KDC sealed under the LDAP key while naming another service.
/// And the LDAP ticket is not opened under another service's key set.
/// Source: A-19 (docs/questions/Q-040); docs/questions/Q-165 item 6 (A-46);
/// docs/49 §3.3; RFC 4120 §5.3 (sname in the clear part), §6.2.
#[test]
fn ticket_for_another_sname_is_denied_before_decryption() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let host = issue(
        &mut f,
        &tgt,
        &SERVICE,
        service_name(),
        1,
        kt("20261113170000Z"),
    );
    let ldap = ldap_ticket(&mut f, &tgt, 2);

    let cases = [
        // A genuine ticket for host/files.example.org.
        ap_octets(&host, now(), 520),
        // Alice's TGT (krbtgt/EXAMPLE.ORG).
        octets(
            &tgt.parts.ticket,
            seal_authenticator(&tgt.session, &ApAuth::new(now(), 521)),
            ApOptions::empty(),
        ),
        // Compromised KDC: names host/files, sealed under the LDAP key.
        forged_octets(
            &seal_ticket(&ldap_service_key(), service_name(), &ticket_part(), Some(1)),
            522,
        ),
    ];
    for ap in &cases {
        assert_eq!(verify(&mut f, ap, now()), Err(AuthnError::Denied));
        let last = f.records().last().unwrap();
        assert_eq!(last.reason, AuditReason::NameBindingMismatch);
        assert_eq!(last.kvno, None, "no key was used");
    }

    // The LDAP ticket under the host service's key set (Role::Ldap may hold
    // any Service handle — docs/questions/Q-180 item 6 — but the binding
    // still refuses).
    let ap = ap_octets(&ldap, now(), 523);
    assert_eq!(
        f.keyd
            .open_and_verify_service_ticket(&LDAP, &SERVICE, &ap, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameBindingMismatch);
    // Not consumed by the refusals: the genuine ticket verifies.
    assert!(verify(&mut f, &ap, now()).is_ok());
}

/// A ticket of another realm is refused (no cross-realm; srealm selects the
/// server key). Source: RFC 4120 §3.2.3 (srealm, KRB_AP_ERR_NOKEY), §5.3
/// (realm).
#[test]
fn ticket_of_another_realm_is_denied() {
    let mut f = fixture();
    let mut ticket = seal_ticket(
        &ldap_service_key(),
        ldap_service_name(),
        &ticket_part(),
        Some(1),
    );
    ticket.realm = Realm::new("OTHER.ORG").unwrap();
    assert_eq!(
        verify(&mut f, &forged_octets(&ticket, 530), now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::WrongRealm);
}

/// Not a KRB_AP_REQ, not DER, trailing data, or user-to-user: refused
/// uniformly. Source: RFC 4120 §3.2.3 (KRB_AP_ERR_MSG_TYPE; USE-SESSION-KEY
/// "indicates ... user-to-user authentication"), §3.7, §5.5.1.
#[test]
fn malformed_or_user_to_user_requests_are_denied() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    let good = ap_octets(&issued, now(), 540);

    let mut trailing = good.clone();
    trailing.push(0x00);
    let not_ap_req = fast_krb_error(25).encode().unwrap();
    for bad in [vec![], vec![0x30, 0x00], trailing, not_ap_req] {
        assert_eq!(verify(&mut f, &bad, now()), Err(AuthnError::Denied));
        assert_eq!(last_reason(&f), AuditReason::MalformedInput);
    }

    let u2u = octets(
        &issued.ticket,
        seal_authenticator(&issued.session, &ApAuth::new(now(), 541)),
        ApOptions::USE_SESSION_KEY,
    );
    assert_eq!(verify(&mut f, &u2u, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::UnsupportedApOption);

    assert!(verify(&mut f, &good, now()).is_ok());
}

// ---------------------------------------------------------------------------
// Authorization (I2, I3) and unknown handles.
// ---------------------------------------------------------------------------

/// Only Role::Ldap may verify a service ticket; a refusal by role is
/// decided first and leaves the AP-REQ unused. Source: docs/10 §2, §12 I2;
/// docs/questions/Q-165 item 3 (A-46).
#[test]
fn wrong_role_is_denied() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    let ap = ap_octets(&issued, now(), 550);
    for caller in [KDC, DIRECTORY, ADMIN] {
        assert_eq!(
            f.keyd
                .open_and_verify_service_ticket(&caller, &LDAP_SERVICE, &ap, &now()),
            Err(AuthnError::Denied)
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.reason, AuditReason::RoleNotPermitted);
        assert_eq!(last.caller_role, caller.role);
    }
    assert!(verify(&mut f, &ap, now()).is_ok());
}

/// Role::Ldap opens only Service-purpose handles: a Krbtgt or a
/// PrincipalLongterm handle is refused before anything else. Source:
/// docs/10 §2, §12 I3; docs/questions/Q-165 item 3 ("only handles of type
/// `Service`").
#[test]
fn krbtgt_and_principal_handles_are_denied() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    let ap = ap_octets(&issued, now(), 560);
    // Alice's TGT under the krbtgt handle: still refused (purpose).
    let tgt_ap = octets(
        &tgt.parts.ticket,
        seal_authenticator(&tgt.session, &ApAuth::new(now(), 561)),
        ApOptions::empty(),
    );
    for (handle, request) in [(KRBTGT, &tgt_ap), (KRBTGT, &ap), (ALICE, &ap)] {
        assert_eq!(
            f.keyd
                .open_and_verify_service_ticket(&LDAP, &handle, request, &now()),
            Err(AuthnError::Denied)
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.reason, AuditReason::PurposeMismatch);
        assert_eq!(last.purpose, Some(handle.purpose));
    }
    assert!(verify(&mut f, &ap, now()).is_ok());
}

/// An unknown Service handle is the uniform `Denied`. Source: docs/10 §9
/// (`Denied` does not distinguish non-existence), §12 I6.
#[test]
fn unknown_handle_is_denied() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    let ap = ap_octets(&issued, now(), 570);
    let stranger = KeyHandle::new(PrincipalId::from_bytes([0xEE; 16]), KeyPurpose::Service);
    assert_eq!(
        f.keyd
            .open_and_verify_service_ticket(&LDAP, &stranger, &ap, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::KeyNotFound);
    assert!(verify(&mut f, &ap, now()).is_ok());
}

// ---------------------------------------------------------------------------
// The cryptographic chain.
// ---------------------------------------------------------------------------

/// A ticket sealed under another key (here the host service's, as a
/// compromised KDC might) fails its integrity check under the LDAP key —
/// with or without a kvno. Source: RFC 4120 §3.2.3
/// (KRB_AP_ERR_BAD_INTEGRITY: "chances are good that different keys were
/// used to encrypt and decrypt").
#[test]
fn ticket_under_a_wrong_service_key_is_denied() {
    let mut f = fixture();
    for (cusec, kvno) in [(580, Some(1)), (581, None)] {
        let ticket = seal_ticket(&service_key(), ldap_service_name(), &ticket_part(), kvno);
        assert_eq!(
            verify(&mut f, &forged_octets(&ticket, cusec), now()),
            Err(AuthnError::Denied)
        );
        assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);
    }
    // Control: the same ticket under the right key verifies.
    let ticket = seal_ticket(
        &ldap_service_key(),
        ldap_service_name(),
        &ticket_part(),
        Some(1),
    );
    assert!(verify(&mut f, &forged_octets(&ticket, 582), now()).is_ok());
}

/// A modified authenticator fails its integrity check — and stays `Denied`
/// even when it is also skewed (no class before the chain completes). An
/// authenticator sealed with the PA-TGS-REQ key usage 7 is refused: the
/// application usage is 11. Source: RFC 4120 §3.2.3 (BAD_INTEGRITY), §5.5.1
/// ("a key usage value of 11 in normal application exchanges, or 7 when used
/// as the PA-TGS-REQ"), §7.5.1; A-26.
#[test]
fn tampered_or_mis_keyed_authenticator_is_denied() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    for (when, cusec) in [(now(), 590), (at(-900), 591)] {
        let mut auth = seal_authenticator(&issued.session, &ApAuth::new(when, cusec));
        let last = auth.cipher.len() - 1;
        auth.cipher[last] ^= 0x01;
        let ap = octets(&issued.ticket, auth, ApOptions::empty());
        assert_eq!(verify(&mut f, &ap, now()), Err(AuthnError::Denied));
        assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);
    }
    let mut spec = ApAuth::new(now(), 592);
    spec.usage = 7;
    let ap = octets(
        &issued.ticket,
        seal_authenticator(&issued.session, &spec),
        ApOptions::empty(),
    );
    assert_eq!(verify(&mut f, &ap, now()), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);
}

/// The authenticator must name the ticket's client, carry no
/// authorization-data, and — in task L6a — no application-data checksum.
/// Source: RFC 4120 §3.2.3 (KRB_AP_ERR_BADMATCH), §5.5.1 (cksum,
/// authorization-data); docs/questions/Q-180 item 3.
#[test]
fn authenticator_contents_are_checked() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);

    let mut bob = ApAuth::new(now(), 600);
    bob.cname = bob_name();
    let mut cksum = ApAuth::new(now(), 601);
    cksum.cksum = Some(Checksum {
        cksumtype: ChecksumType::HmacSha196Aes256.number(),
        checksum: krb_crypto::get_mic(
            &issued.session,
            ChecksumType::HmacSha196Aes256,
            usage(10),
            b"application data",
        )
        .unwrap(),
    });
    let mut ad = ApAuth::new(now(), 602);
    ad.authorization_data = Some(AuthorizationData(vec![AuthorizationElement {
        ad_type: 1,
        ad_data: vec![0x30, 0x00],
    }]));
    for (spec, reason) in [
        (bob, AuditReason::NameMismatch),
        (cksum, AuditReason::ApChecksumUnsupported),
        (ad, AuditReason::UnsupportedContent),
    ] {
        let ap = octets(
            &issued.ticket,
            seal_authenticator(&issued.session, &spec),
            ApOptions::empty(),
        );
        assert_eq!(verify(&mut f, &ap, now()), Err(AuthnError::Denied));
        assert_eq!(last_reason(&f), reason);
    }
}

// ---------------------------------------------------------------------------
// Ticket contents.
// ---------------------------------------------------------------------------

/// The INVALID flag is refused (uniform `Denied`, as in keyd's TGS path).
/// The same ticket without the flag verifies. Source: RFC 4120 §2.2
/// ("Application servers MUST reject tickets that have this flag set"),
/// §3.2.3; docs/questions/Q-180 item 2.
#[test]
fn invalid_flag_is_denied() {
    let mut f = fixture();
    let mut part = ticket_part();
    part.flags.insert(TicketFlags::INVALID);
    let ticket = seal_ticket(&ldap_service_key(), ldap_service_name(), &part, Some(1));
    assert_eq!(
        verify(&mut f, &forged_octets(&ticket, 610), now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TicketInvalidFlag);

    let ticket = seal_ticket(
        &ldap_service_key(),
        ldap_service_name(),
        &ticket_part(),
        Some(1),
    );
    let ctx = verify(&mut f, &forged_octets(&ticket, 611), now()).unwrap();
    assert!(!ctx.flags.contains(TicketFlags::INVALID));
}

/// Ticket contents keyd cannot check or enforce are refused: addresses,
/// authorization-data ("restrictions"), a non-empty transited field or an
/// encoding other than DOMAIN-X500-COMPRESS, a client of another realm.
/// Source: RFC 4120 §3.2.3 (addresses), §3.3.3.2 (local authentication:
/// empty transited), §5.3 (authorization-data, transited-policy-checked:
/// "if unable to do so, it must reject the authentication"), §7.5.3,
/// §7.5.4, §7.5.5.
#[test]
fn ticket_contents_keyd_cannot_enforce_are_denied() {
    let mut f = fixture();
    let mut addresses = ticket_part();
    addresses.caddr = Some(HostAddresses(vec![HostAddress {
        addr_type: 2,
        address: vec![192, 0, 2, 7],
    }]));
    let mut authorization = ticket_part();
    authorization.authorization_data = Some(AuthorizationData(vec![AuthorizationElement {
        ad_type: 1,
        ad_data: vec![0x30, 0x00],
    }]));
    let mut transited = ticket_part();
    transited.transited.contents = b"OTHER.ORG".to_vec();
    let mut encoding = ticket_part();
    encoding.transited.tr_type = 2;
    let mut foreign = ticket_part();
    foreign.crealm = Realm::new("OTHER.ORG").unwrap();
    for (cusec, (part, reason)) in [
        (addresses, AuditReason::UnsupportedContent),
        (authorization, AuditReason::UnsupportedContent),
        (transited, AuditReason::TransitedNotLocal),
        (encoding, AuditReason::TransitedNotLocal),
        (foreign, AuditReason::WrongRealm),
    ]
    .into_iter()
    .enumerate()
    {
        let ticket = seal_ticket(&ldap_service_key(), ldap_service_name(), &part, Some(1));
        let mut spec = ApAuth::new(now(), 620 + cusec as u32);
        spec.crealm = part.crealm.clone();
        let ap = octets(
            &ticket,
            seal_authenticator(&forged_session_key(), &spec),
            ApOptions::empty(),
        );
        assert_eq!(verify(&mut f, &ap, now()), Err(AuthnError::Denied));
        assert_eq!(last_reason(&f), reason);
    }
}

// ---------------------------------------------------------------------------
// The classes, only after the chain (A-26).
// ---------------------------------------------------------------------------

/// A skewed authenticator is `Skew` — only after the chain — and never
/// enters the replay cache. Source: RFC 4120 §3.2.3 (KRB_AP_ERR_SKEW);
/// A-26 (docs/questions/Q-071).
#[test]
fn skew_is_reported_after_the_chain() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    let skewed = ap_octets(&issued, at(-900), 630);
    assert_eq!(verify(&mut f, &skewed, now()), Err(AuthnError::Skew));
    assert_eq!(last_reason(&f), AuditReason::ClockSkew);
    // Refused for skew, it was not recorded: it is Skew again, not Replay.
    assert_eq!(verify(&mut f, &skewed, now()), Err(AuthnError::Skew));
    // Within the skew it passes.
    assert!(verify(&mut f, &ap_octets(&issued, at(-299), 631), now()).is_ok());
}

/// A replayed authenticator is `Replay` — and the replay cache is shared:
/// a second LDAP process sees the same entry. The rejection is per server:
/// the client's TGS authenticator with the same time and microseconds does
/// not collide. Source: RFC 4120 §3.2.3 ("the server MUST utilize a replay
/// cache"; "restricted to authenticators from the same principal to the
/// same server"; "If multiple servers ... share a service principal ...
/// they MUST share this replay cache"); docs/49 §3.3.
#[test]
fn replay_is_reported_after_the_chain() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    // The TGS-REQ authenticator used (now, cusec 1).
    let issued = ldap_ticket(&mut f, &tgt, 1);
    // The AP-REQ authenticator uses the same (now, cusec 1): other server.
    let ap = ap_octets(&issued, now(), 1);
    assert!(verify(&mut f, &ap, now()).is_ok());
    assert_eq!(verify(&mut f, &ap, now()), Err(AuthnError::Replay));
    assert_eq!(last_reason(&f), AuditReason::Replay);
    assert_eq!(
        f.keyd
            .open_and_verify_service_ticket(&LDAP_OTHER, &LDAP_SERVICE, &ap, &now()),
        Err(AuthnError::Replay)
    );
    // A tampered copy is Denied, not Replay: the class needs the chain.
    let mut tampered = ApReq::decode(&ap).unwrap();
    let last = tampered.authenticator.cipher.len() - 1;
    tampered.authenticator.cipher[last] ^= 0x80;
    assert_eq!(
        verify(&mut f, &tampered.encode().unwrap(), now()),
        Err(AuthnError::Denied)
    );
}

/// An expired ticket is `TicketExpired` only once the chain completed; with
/// a broken authenticator it is `Denied`. Source: RFC 4120 §3.2.3
/// (KRB_AP_ERR_TKT_EXPIRED: "the current time is later than end time by
/// more than the allowable clock skew"); A-26.
#[test]
fn expired_ticket_is_reported_only_after_the_chain() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = issue(
        &mut f,
        &tgt,
        &LDAP_SERVICE,
        ldap_service_name(),
        1,
        kt("20261113110000Z"),
    );
    // 11:05:00 is within the skew of the endtime; 11:05:01 is not.
    assert!(verify(&mut f, &ap_octets(&issued, at(3900), 640), at(3900)).is_ok());
    let late = at(3901);
    assert_eq!(
        verify(&mut f, &ap_octets(&issued, late, 641), late),
        Err(AuthnError::TicketExpired)
    );
    assert_eq!(last_reason(&f), AuditReason::TicketExpired);
    // Expired AND under the wrong session key: Denied.
    let ap = octets(
        &issued.ticket,
        seal_authenticator(&forged_session_key(), &ApAuth::new(late, 642)),
        ApOptions::empty(),
    );
    assert_eq!(verify(&mut f, &ap, late), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::IntegrityFailure);
}

/// A ticket whose starttime is beyond the skew in the future is
/// `TicketNotYetValid` only once the chain completed. Source: RFC 4120
/// §3.2.3 (KRB_AP_ERR_TKT_NYV: "If the starttime is later than the current
/// time by more than the allowable clock skew"); A-26.
#[test]
fn not_yet_valid_ticket_is_reported_only_after_the_chain() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    // The ticket starts at 10:00:00; at 09:55:00 it is within the skew.
    assert!(verify(&mut f, &ap_octets(&issued, at(-300), 650), at(-300)).is_ok());
    let early = at(-301);
    assert_eq!(
        verify(&mut f, &ap_octets(&issued, early, 651), early),
        Err(AuthnError::TicketNotYetValid)
    );
    assert_eq!(last_reason(&f), AuditReason::TicketNotYetValid);
    let ap = octets(
        &issued.ticket,
        seal_authenticator(&forged_session_key(), &ApAuth::new(early, 652)),
        ApOptions::empty(),
    );
    assert_eq!(verify(&mut f, &ap, early), Err(AuthnError::Denied));
}

// ---------------------------------------------------------------------------
// A-46: the LDAP service key is one keyd drew.
// ---------------------------------------------------------------------------

/// A password-derived Service key never authenticates a Bind: after the
/// Directory role overwrites the LDAP key set with a password (kvno 2), a
/// ticket sealed under that version is refused while the keyd-drawn kvno 1
/// still verifies; a Service key set that was password-derived from the
/// start is refused outright. Source: docs/questions/Q-165 item 4 (A-46:
/// "created in `create_key` — the key never has to leave"); docs/10 §6;
/// docs/questions/Q-180 item 4.
#[test]
fn password_derived_service_key_never_verifies() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let before = ldap_ticket(&mut f, &tgt, 1);
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &LDAP_SERVICE,
            &bound(ldap_service_name()),
            Zeroizing::new("known outside keyd".to_owned()),
            "EXAMPLE.ORGldapdc01.example.org",
            &now(),
        ),
        Ok(Kvno::new(2))
    );
    let after = ldap_ticket(&mut f, &tgt, 2);
    assert_eq!(after.ticket.enc_part.kvno, Some(2));
    assert_eq!(
        verify(&mut f, &ap_octets(&after, now(), 660), now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::KvnoMismatch);
    assert!(verify(&mut f, &ap_octets(&before, now(), 661), now()).is_ok());

    // A Service key set created by set_secret.
    let dc02 = KeyHandle::new(PrincipalId::from_bytes([0x2D; 16]), KeyPurpose::Service);
    let dc02_name = PrincipalName {
        name_type: KRB_NT_SRV_INST,
        name_string: vec![kstr("ldap"), kstr("dc02.example.org")],
    };
    f.keyd
        .set_secret(
            &DIRECTORY,
            &dc02,
            &bound(dc02_name.clone()),
            Zeroizing::new("another known password".to_owned()),
            "EXAMPLE.ORGldapdc02.example.org",
            &now(),
        )
        .unwrap();
    let issued = issue(&mut f, &tgt, &dc02, dc02_name, 3, kt("20261113170000Z"));
    assert_eq!(
        f.keyd.open_and_verify_service_ticket(
            &LDAP,
            &dc02,
            &ap_octets(&issued, now(), 662),
            &now()
        ),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::ServiceKeyNotRandom);
    assert_eq!(f.records().last().unwrap().kvno, None, "no key was used");
}

// ---------------------------------------------------------------------------
// The service-context table and secrets.
// ---------------------------------------------------------------------------

/// The service-context table is bounded and fails closed when full of live
/// entries; expired entries make room. Source: docs/10 §8, D36; AGENTS.md §6
/// (bounded, fail closed).
#[test]
fn service_context_table_is_bounded() {
    let mut config = config();
    config.max_service_contexts = 1;
    let mut f = Fixture::with_config(config);
    add_ldap_service(&mut f);
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    assert!(verify(&mut f, &ap_octets(&issued, now(), 670), now()).is_ok());
    assert_eq!(
        verify(&mut f, &ap_octets(&issued, now(), 671), now()),
        Err(AuthnError::Denied)
    );
    let last = f.records().last().unwrap();
    assert_eq!(last.reason, AuditReason::TokenTableFull);
    assert_eq!(last.result, AuditOutcome::Unavailable);
    // After the 30-second token lifetime the first entry has expired.
    let later = at(31);
    assert!(verify(&mut f, &ap_octets(&issued, later, 672), later).is_ok());
}

/// Destroying the service key set discards the contexts opened under it
/// (their session keys zeroized), and the handle is unknown afterwards.
/// Source: docs/questions/Q-115 (A-35: destroy_key_set); docs/49 §3.3.
#[test]
fn destroying_the_service_key_set_discards_its_contexts() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    assert!(verify(&mut f, &ap_octets(&issued, now(), 680), now()).is_ok());
    assert_eq!(live_contexts(&f), "1");
    // Destroying another Service key set leaves it alone.
    f.keyd.destroy_key_set(&ADMIN, &SERVICE, &now()).unwrap();
    assert_eq!(live_contexts(&f), "1");
    f.keyd
        .destroy_key_set(&ADMIN, &LDAP_SERVICE, &now())
        .unwrap();
    assert_eq!(live_contexts(&f), "0");
    assert_eq!(
        verify(&mut f, &ap_octets(&issued, now(), 681), now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::KeyNotFound);
}

/// Nothing keyd returns or audits holds the LDAP service key, the service
/// session key or a subkey — in any rendering; Debug is redacted. Source:
/// docs/10 §12 I1, I8; AGENTS.md §6 (secrets never in logs or debug
/// output).
#[test]
fn no_key_octets_in_outputs_or_audit() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    let subkey = [0x6D; 32];
    let mut spec = ApAuth::new(now(), 690);
    spec.subkey = Some(EncryptionKey {
        keytype: 18,
        keyvalue: KeyValue::from_slice(&subkey),
    });
    let ap = octets(
        &issued.ticket,
        seal_authenticator(&issued.session, &spec),
        ApOptions::empty(),
    );
    let ctx = verify(&mut f, &ap, now()).unwrap();
    // A refused attempt too (replay).
    let _ = verify(&mut f, &ap, now());

    let text = format!("{ctx:?} {:?} {:?} {:?}", ctx.ctx_id, f.records(), f.keyd);
    for secret in [
        &LDAP_SERVICE_KEY[..],
        &issued.session_octets[..],
        &subkey[..],
        tgt.rep.0.key.keyvalue.as_bytes(),
    ] {
        for r in renderings(secret) {
            assert!(!text.contains(&r), "key material in output: {r}");
        }
    }
    // The context id prints only a short prefix.
    let id = format!("{:?}", ctx.ctx_id);
    assert!(id.starts_with("ServiceCtxId(") && id.ends_with("..)"));
}
