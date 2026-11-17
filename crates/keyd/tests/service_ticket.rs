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
//! [MS-KILE] 3.4.5; docs/10 §2, §5b, §9, §12; docs/49 §3.3;
//! docs/questions/Q-165 (A-46), Q-180; A-19 (Q-040); A-26 (Q-071).

mod common;

use common::*;
use keyd::{
    AuditOutcome, AuditReason, AuthnError, DecidedOperation, KeyHandle, KeyPurpose, Kvno,
    PrincipalId,
};
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
        .issue_tgs(&KDC, service, &ctx.ctx_id, &template, &now())
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
        .open_and_verify_service_ticket(&LDAP, &LDAP_SERVICE.principal, ap, &when)
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
    // A-102: the rotation runs on a decision dird registered.
    let rotation = f
        .decide(
            DecidedOperation::RotateKey {
                handle: LDAP_SERVICE,
            },
            &now(),
        )
        .unwrap();
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, rotation, &now()),
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

    let retirement = f
        .decide(
            DecidedOperation::RetireKvno {
                handle: LDAP_SERVICE,
                kvno: Kvno::new(1),
            },
            &now(),
        )
        .unwrap();
    f.keyd.retire_kvno(&ADMIN, retirement, &now()).unwrap();
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
            .open_and_verify_service_ticket(&LDAP, &SERVICE.principal, &ap, &now()),
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
                .open_and_verify_service_ticket(&caller, &LDAP_SERVICE.principal, &ap, &now()),
            Err(AuthnError::Denied)
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.reason, AuditReason::RoleNotPermitted);
        assert_eq!(last.caller_role, caller.role);
    }
    assert!(verify(&mut f, &ap, now()).is_ok());
}

/// Role::Ldap opens only Service-purpose key sets, and the purpose is never
/// the caller's to name (R2: the binding's, `AppBinding::key_purpose`):
/// naming the krbtgt's or alice's principal looks up *their* `Service` key
/// set — which does not exist — so neither alice's TGT nor her LDAP ticket
/// is opened under the krbtgt or a long-term key. Source: docs/10 §2, §12
/// I3; docs/questions/Q-165 item 3 ("only handles of type `Service`");
/// docs/52 §5 item 3.
#[test]
fn krbtgt_and_principal_keys_are_never_opened() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    let ap = ap_octets(&issued, now(), 560);
    let tgt_ap = octets(
        &tgt.parts.ticket,
        seal_authenticator(&tgt.session, &ApAuth::new(now(), 561)),
        ApOptions::empty(),
    );
    for (handle, request) in [(KRBTGT, &tgt_ap), (KRBTGT, &ap), (ALICE, &ap)] {
        assert_eq!(
            f.keyd
                .open_and_verify_service_ticket(&LDAP, &handle.principal, request, &now()),
            Err(AuthnError::Denied)
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.reason, AuditReason::KeyNotFound);
        assert_eq!(last.purpose, Some(KeyPurpose::Service));
        assert_eq!(last.kvno, None, "no key was used");
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
    // (The purpose is the binding's, R2: only the principal is named.)
    assert_eq!(
        f.keyd
            .open_and_verify_service_ticket(&LDAP, &stranger.principal, &ap, &now()),
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
/// authorization-data, and — on an unbound verification (task L6a; R2) —
/// no application-data checksum.
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
            .open_and_verify_service_ticket(&LDAP_OTHER, &LDAP_SERVICE.principal, &ap, &now()),
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
    f.grant(
        &LDAP_SERVICE,
        &bound(ldap_service_name()),
        "EXAMPLE.ORGldapdc01.example.org",
        &now(),
    )
    .unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &LDAP_SERVICE,
            &bound(ldap_service_name()),
            Zeroizing::new("Zinnia-Basil-26-Clover".to_owned()),
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
    f.grant(
        &dc02,
        &bound(dc02_name.clone()),
        "EXAMPLE.ORGldapdc02.example.org",
        &now(),
    )
    .unwrap();
    f.keyd
        .set_secret(
            &DIRECTORY,
            &dc02,
            &bound(dc02_name.clone()),
            Zeroizing::new("Dahlia-Egret-49-Fennel".to_owned()),
            "EXAMPLE.ORGldapdc02.example.org",
            &now(),
        )
        .unwrap();
    let issued = issue(&mut f, &tgt, &dc02, dc02_name, 3, kt("20261113170000Z"));
    assert_eq!(
        f.keyd.open_and_verify_service_ticket(
            &LDAP,
            &dc02.principal,
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
/// entries; expired entries make room. Source: docs/10 §8, D36; docs/CLEAN-ROOM.md
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
/// Source: docs/questions/Q-115 (A-35: destroy_key_set); docs/49 §3.3;
/// docs/52 §4.2 (A-102: by decision, per principal).
#[test]
fn destroying_the_service_key_set_discards_its_contexts() {
    let mut f = fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = ldap_ticket(&mut f, &tgt, 1);
    assert!(verify(&mut f, &ap_octets(&issued, now(), 680), now()).is_ok());
    assert_eq!(live_contexts(&f), "1");
    // Destroying another principal's key sets leaves it alone.
    let other = f
        .decide(
            DecidedOperation::DestroyKeySet {
                principal: SERVICE_ID,
            },
            &now(),
        )
        .unwrap();
    f.keyd.destroy_key_set(&ADMIN, other, &now()).unwrap();
    assert_eq!(live_contexts(&f), "1");
    let destroy = f
        .decide(
            DecidedOperation::DestroyKeySet {
                principal: LDAP_SERVICE.principal,
            },
            &now(),
        )
        .unwrap();
    f.keyd.destroy_key_set(&ADMIN, destroy, &now()).unwrap();
    assert_eq!(live_contexts(&f), "0");
    assert_eq!(
        verify(&mut f, &ap_octets(&issued, now(), 681), now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::KeyNotFound);
}

/// Nothing keyd returns or audits holds the LDAP service key, the service
/// session key or a subkey — in any rendering; Debug is redacted. Source:
/// docs/10 §12 I1, I8; docs/CLEAN-ROOM.md (secrets never in logs or debug
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

// ---------------------------------------------------------------------------
// R2 (docs/52 §3.2, §5; docs/questions/Q-463, A-102): the admin service's
// key set opens a ticket only bound to an operation digest — the
// Authenticator's `cksum`, key usage 10, keyed with the ticket session key,
// of the session key's required checksum type (RFC 4120 §4, 5.5.1, 7.5.1
// item 10; RFC 3961 §3, §4). The digests are made-up 32-octet values: keyd
// never interprets them.
// ---------------------------------------------------------------------------

/// The operation an admin AP-REQ is made for, and another one.
const DIGEST_A: [u8; 32] = [0xA0; 32];
const DIGEST_B: [u8; 32] = [0xB0; 32];

fn digest(octets: [u8; 32]) -> keyd::OperationDigest {
    keyd::OperationDigest::new(octets)
}

/// A fixture with the LDAP and the admin service key sets.
fn admin_fixture() -> Fixture {
    let mut f = fixture();
    add_admin_service(&mut f);
    f
}

/// Alice's admin service ticket, issued by keyd's own TGS under the
/// AdminService key set (the KDC seals it there, R2).
fn admin_ticket(f: &mut Fixture, tgt: &Tgt, cusec: u32) -> Issued {
    issue(
        f,
        tgt,
        &ADMIN_SERVICE,
        admin_service_name(),
        cusec,
        kt("20261113170000Z"),
    )
}

/// The client's `cksum` over `message` (RFC 4120 5.5.1): the session key's
/// required checksum type and key usage 10 — or what the test changes.
fn cksum_over(
    key: &ProtocolKey,
    cksumtype: ChecksumType,
    usage_number: u32,
    message: &[u8],
) -> Checksum {
    Checksum {
        cksumtype: cksumtype.number(),
        checksum: krb_crypto::get_mic(key, cksumtype, usage(usage_number), message).unwrap(),
    }
}

/// An AP-REQ of `issued` bound to `bound` (key usage 10, the session key's
/// checksum type), at `now()` with `cusec`.
fn bound_octets(issued: &Issued, bound: &[u8; 32], cusec: u32) -> Vec<u8> {
    let mut spec = ApAuth::new(now(), cusec);
    spec.cksum = Some(cksum_over(
        &issued.session,
        issued.session.enc_type().checksum_type(),
        10,
        bound,
    ));
    octets(
        &issued.ticket,
        seal_authenticator(&issued.session, &spec),
        ApOptions::empty(),
    )
}

fn verify_bound(
    f: &mut Fixture,
    ap: &[u8],
    bound: [u8; 32],
) -> Result<keyd::OperationTicket, AuthnError> {
    f.keyd
        .verify_operation_ticket(&LDAP, &ADMIN_SERVICE_ID, &digest(bound), ap, &now())
}

/// The right digest ⇒ verified under the AdminService key set; the answer
/// names the verified digest; one success record with purpose AdminService
/// and operation `VerifyOperationTicket` — and **no service context** is
/// left in keyd (Q-523: the answer has no context id, and keyd's table of
/// live contexts stays empty). The unbound LDAP verification still keeps
/// its context and answers its id. Source: RFC 4120 §5.5.1 ("a checksum of
/// the application data that accompanies the KRB_AP_REQ, computed using a
/// key usage value of 10"), §7.5.1 item 10, §3.2.3 (a subkey is saved "for
/// later use" — the admin channel has none); RFC 3961 §4 (verify_mic);
/// docs/52 §3.4 (C4), §5 items 2-3; docs/questions/Q-523.
#[test]
fn right_operation_digest_verifies_the_admin_ticket_and_keeps_no_context() {
    let mut f = admin_fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = admin_ticket(&mut f, &tgt, 1);
    let ticket = verify_bound(&mut f, &bound_octets(&issued, &DIGEST_A, 700), DIGEST_A).unwrap();
    assert_eq!(ticket.cname, alice_name());
    assert_eq!(ticket.crealm, realm());
    assert_eq!(ticket.authtime, issued.authtime);
    assert_eq!(ticket.operation, digest(DIGEST_A));
    assert_eq!(
        live_contexts(&f),
        "0",
        "an operation-bound verification keeps no context"
    );
    let records = f.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].op, keyd::Operation::VerifyOperationTicket);
    assert_eq!(records[0].result, AuditOutcome::Success);
    assert_eq!(records[0].principal, Some(ADMIN_SERVICE_ID));
    assert_eq!(records[0].purpose, Some(KeyPurpose::AdminService));

    let ldap = ldap_ticket(&mut f, &tgt, 2);
    let ctx = verify(&mut f, &ap_octets(&ldap, now(), 701), now()).unwrap();
    assert_eq!(ctx.cname, alice_name());
    assert_eq!(
        live_contexts(&f),
        "1",
        "the unbound verification keeps its context"
    );
    let last = f.records().last().unwrap();
    assert_eq!(last.op, keyd::Operation::OpenAndVerifyServiceTicket);
    assert_eq!(last.purpose, Some(KeyPurpose::Service));
}

/// Q-523 at the table's bound: with room for ONE service context, any
/// number of operation-bound verifications succeed and take no room — the
/// next unbound verification still gets the one slot, and only a second
/// unbound one meets the full table (`TokenTableFull`). So an admin request
/// flood cannot fill the table the LDAP front's GSS verifications need
/// (docs/questions/Q-387 item 4). Source: docs/10 §8, D36; docs/52 §3.4
/// (C4); docs/questions/Q-387 item 4, Q-493 item 3, Q-523.
#[test]
fn operation_bound_verifications_never_fill_the_context_table() {
    let mut config = config();
    config.max_service_contexts = 1;
    let mut f = Fixture::with_config(config);
    add_ldap_service(&mut f);
    add_admin_service(&mut f);
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let admin = admin_ticket(&mut f, &tgt, 1);
    for cusec in 740..745 {
        let ticket = verify_bound(&mut f, &bound_octets(&admin, &DIGEST_A, cusec), DIGEST_A);
        assert_eq!(ticket.map(|t| t.operation), Ok(digest(DIGEST_A)), "{cusec}");
    }
    assert_eq!(live_contexts(&f), "0");
    let ldap = ldap_ticket(&mut f, &tgt, 2);
    assert!(verify(&mut f, &ap_octets(&ldap, now(), 746), now()).is_ok());
    assert_eq!(live_contexts(&f), "1");
    assert_eq!(
        verify(&mut f, &ap_octets(&ldap, now(), 747), now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::TokenTableFull);
    // A full table does not stop an operation-bound verification: it needs
    // no slot.
    assert!(verify_bound(&mut f, &bound_octets(&admin, &DIGEST_A, 748), DIGEST_A).is_ok());
}

/// The Q-292 attack at keyd: an admin's AP-REQ made for operation A,
/// presented for operation B, is the uniform `Denied` with its own reason —
/// before the replay cache and with no service context, so it stays usable
/// for the operation it was made for (and only once). Source: docs/52 §3.2
/// (C2), §5 item 3; RFC 4120 §3.2.3 (replay cache after authentication);
/// A-26.
#[test]
fn wrong_operation_digest_is_denied_uniformly() {
    let mut f = admin_fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = admin_ticket(&mut f, &tgt, 1);
    let ap = bound_octets(&issued, &DIGEST_A, 710);
    assert_eq!(verify_bound(&mut f, &ap, DIGEST_B), Err(AuthnError::Denied));
    let last = f.records().last().unwrap();
    assert_eq!(last.reason, AuditReason::OperationDigestMismatch);
    assert_eq!(last.result, AuditOutcome::Denied);
    assert_eq!(live_contexts(&f), "0");
    // Not consumed: the operation it was made for verifies, once.
    assert!(verify_bound(&mut f, &ap, DIGEST_A).is_ok());
    assert_eq!(verify_bound(&mut f, &ap, DIGEST_A), Err(AuthnError::Replay));
    // A mismatch is `Denied` even when the authenticator is also skewed:
    // the class needs the whole chain (A-26).
    let mut skewed = ApAuth::new(at(3600), 711);
    skewed.cksum = Some(cksum_over(
        &issued.session,
        ChecksumType::HmacSha196Aes256,
        10,
        &DIGEST_A,
    ));
    let ap = octets(
        &issued.ticket,
        seal_authenticator(&issued.session, &skewed),
        ApOptions::empty(),
    );
    assert_eq!(verify_bound(&mut f, &ap, DIGEST_B), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::OperationDigestMismatch);
}

/// Attack test (R7, `ChainVerified`; A-26 with R2): an EXPIRED admin ticket
/// presented with an AP-REQ bound to ANOTHER operation is the uniform
/// `Denied` (`OperationDigestMismatch`), never `TicketExpired` — the
/// operation binding is a step of the cryptographic chain, and a class is
/// built only from the chain's proof. Bound to its own operation, the same
/// AP-REQ is `TicketExpired` (only a holder of the session key gets there),
/// and neither presentation leaves a replay entry (the class comes before
/// the replay cache). Source: RFC 4120 §3.2.3 (KRB_AP_ERR_TKT_EXPIRED;
/// replay cache), §5.5.1, §7.5.1 item 10; A-26 (docs/questions/Q-071);
/// docs/52 §3.6 (a), §5.
#[test]
fn an_expired_admin_ticket_bound_elsewhere_learns_no_class() {
    let mut f = admin_fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    // The ticket ends at 17:00:00; 17:05:01 is past it by more than the
    // skew (300 s).
    let issued = admin_ticket(&mut f, &tgt, 1);
    let late = at(7 * 3600 + 301);
    let mut spec = ApAuth::new(late, 760);
    spec.cksum = Some(cksum_over(
        &issued.session,
        issued.session.enc_type().checksum_type(),
        10,
        &DIGEST_A,
    ));
    let ap = octets(
        &issued.ticket,
        seal_authenticator(&issued.session, &spec),
        ApOptions::empty(),
    );
    let verify_at = |f: &mut Fixture, bound: [u8; 32]| {
        f.keyd
            .verify_operation_ticket(&LDAP, &ADMIN_SERVICE_ID, &digest(bound), &ap, &late)
    };
    assert_eq!(verify_at(&mut f, DIGEST_B), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::OperationDigestMismatch);
    assert_eq!(verify_at(&mut f, DIGEST_A), Err(AuthnError::TicketExpired));
    assert_eq!(last_reason(&f), AuditReason::TicketExpired);
    // Again: refused for its age, never as a replay (no entry was made).
    assert_eq!(verify_at(&mut f, DIGEST_A), Err(AuthnError::TicketExpired));
    assert_eq!(live_contexts(&f), "0");
}

/// An admin AP-REQ without a `cksum` cannot be used at all; a `cksum` that
/// is not exactly the session key's MIC with key usage 10 is refused: the
/// wrong checksum type (another enctype's, RFC 3961 §3 / RFC 3962 §7), the
/// TGS usage 6, the KRB-SAFE-style application usage 1025, keyed with the
/// authenticator subkey instead of the session key (RFC 4120 §7.5.1 item
/// 10: "keyed with the application session key"), or truncated. Source: RFC
/// 4120 §4, §5.5.1, §7.5.1; RFC 3961 §3, §4; docs/52 §5 item 3.
#[test]
fn missing_or_malformed_cksum_is_denied() {
    let mut f = admin_fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let issued = admin_ticket(&mut f, &tgt, 1);

    let ap = ap_octets(&issued, now(), 720);
    assert_eq!(verify_bound(&mut f, &ap, DIGEST_A), Err(AuthnError::Denied));
    assert_eq!(last_reason(&f), AuditReason::OperationDigestMissing);

    let subkey_octets = [0x5D; 32];
    let subkey = krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &subkey_octets).unwrap();
    let aes128 = krb_crypto::random_to_key(EncType::Aes128CtsHmacSha196, &[0x12; 16]).unwrap();
    let mut truncated = cksum_over(
        &issued.session,
        ChecksumType::HmacSha196Aes256,
        10,
        &DIGEST_A,
    );
    truncated.checksum.pop();
    let cases = [
        cksum_over(&aes128, ChecksumType::HmacSha196Aes128, 10, &DIGEST_A),
        cksum_over(
            &issued.session,
            ChecksumType::HmacSha196Aes256,
            6,
            &DIGEST_A,
        ),
        cksum_over(
            &issued.session,
            ChecksumType::HmacSha196Aes256,
            1025,
            &DIGEST_A,
        ),
        cksum_over(&subkey, ChecksumType::HmacSha196Aes256, 10, &DIGEST_A),
        truncated,
    ];
    for (i, cksum) in cases.into_iter().enumerate() {
        let mut spec = ApAuth::new(now(), 721 + u32::try_from(i).unwrap());
        spec.subkey = Some(EncryptionKey {
            keytype: 18,
            keyvalue: KeyValue::from_slice(&subkey_octets),
        });
        spec.cksum = Some(cksum);
        let ap = octets(
            &issued.ticket,
            seal_authenticator(&issued.session, &spec),
            ApOptions::empty(),
        );
        assert_eq!(
            verify_bound(&mut f, &ap, DIGEST_A),
            Err(AuthnError::Denied),
            "case {i}"
        );
        assert_eq!(
            last_reason(&f),
            AuditReason::OperationDigestMismatch,
            "case {i}"
        );
    }
    assert_eq!(live_contexts(&f), "0");
}

/// The binding names the key set's purpose (R2): an LDAP-purpose key set is
/// never opened with an operation digest (its principal names no
/// AdminService key set), the admin service key set is never opened unbound
/// (its principal names no Service key set), and an admin AP-REQ handed to
/// the LDAP key unbound fails the A-19 binding before any key is used.
/// Source: docs/52 §3.2 ("keyd will verify a ticket of this profile only
/// with `OperationDigest`"), §5 item 3; docs/questions/Q-463 item 4; A-19.
#[test]
fn binding_and_purpose_cannot_be_mixed() {
    let mut f = admin_fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let admin = admin_ticket(&mut f, &tgt, 1);
    let ldap = ldap_ticket(&mut f, &tgt, 2);

    // An LDAP-purpose key with a digest: the LDAP ticket, even carrying a
    // valid usage-10 cksum over the digest.
    let ldap_bound = bound_octets(&ldap, &DIGEST_A, 730);
    assert_eq!(
        f.keyd.verify_operation_ticket(
            &LDAP,
            &LDAP_SERVICE_ID,
            &digest(DIGEST_A),
            &ldap_bound,
            &now()
        ),
        Err(AuthnError::Denied)
    );
    let last = f.records().last().unwrap();
    assert_eq!(last.reason, AuditReason::KeyNotFound);
    assert_eq!(last.purpose, Some(KeyPurpose::AdminService));
    assert_eq!(last.kvno, None, "no key was used");

    // The admin service key unbound: a correctly bound admin AP-REQ, and one
    // without a cksum.
    for ap in [
        bound_octets(&admin, &DIGEST_A, 731),
        ap_octets(&admin, now(), 732),
    ] {
        assert_eq!(
            f.keyd
                .open_and_verify_service_ticket(&LDAP, &ADMIN_SERVICE_ID, &ap, &now()),
            Err(AuthnError::Denied)
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.reason, AuditReason::KeyNotFound);
        assert_eq!(last.purpose, Some(KeyPurpose::Service));
    }

    // An admin AP-REQ handed to the LDAP key set unbound: the binding check.
    assert_eq!(
        verify(&mut f, &bound_octets(&admin, &DIGEST_A, 733), now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::NameBindingMismatch);
    assert_eq!(f.records().last().unwrap().kvno, None);

    // None of these consumed anything: both verify as made.
    assert!(verify_bound(&mut f, &bound_octets(&admin, &DIGEST_A, 731), DIGEST_A).is_ok());
    assert!(verify(&mut f, &ap_octets(&ldap, now(), 734), now()).is_ok());
}

/// The admin service key set is keyd's alone: no `set_secret`, grant or
/// set-secret decision may name it, no destroy decision touches it, and it
/// is bound only to the admin service's name (and that name to it only).
/// Source: docs/52 §5 item 3 (R2: the purpose); docs/questions/Q-180 item 4
/// (A-50: a password-derived service key must never verify); A-19; RFC 4120
/// 6.2, 7.3 (the reserved-name rule shape).
#[test]
fn admin_service_key_is_never_password_derived_or_misbound() {
    let mut f = admin_fixture();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ADMIN_SERVICE,
            &bound(admin_service_name()),
            Zeroizing::new("Zinnia-Basil-26-Clover".to_owned()),
            "EXAMPLE.ORGadminddc01.example.org",
            &now(),
        ),
        Err(keyd::Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::PurposeMismatch);
    // A set-secret decision naming it is refused at registration.
    assert!(f
        .decide(
            DecidedOperation::SetSecret {
                kind: keyd::AccountKind::User,
                targets: vec![keyd::SetSecretTarget {
                    handle: ADMIN_SERVICE,
                    binding: bound(admin_service_name()),
                    salt: String::from("EXAMPLE.ORGadminddc01.example.org"),
                }],
            },
            &now(),
        )
        .is_err());
    assert_eq!(last_reason(&f), AuditReason::DecisionInvalid);

    // The name rule, both ways (create_key — the ceremony, before the seal).
    let other = PrincipalId::from_bytes([0xAE; 16]);
    f.entropy.push(&[0x01; 32]);
    assert_eq!(
        f.keyd.create_key(
            &ADMIN,
            &KeyHandle::new(other, KeyPurpose::AdminService),
            &bound(ldap_service_name()),
            &now()
        ),
        Err(keyd::Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::InvalidNameBinding);
    assert_eq!(
        f.keyd.create_key(
            &ADMIN,
            &KeyHandle::new(other, KeyPurpose::Service),
            &bound(admin_service_name()),
            &now()
        ),
        Err(keyd::Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::InvalidNameBinding);

    // A destroy decision for its principal is not even registered — the
    // principal has no PrincipalLongterm or Service key set, the only ones a
    // destruction touches (R6b: KeyNotFound) — and the key set stays.
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    assert_eq!(
        f.decide(
            DecidedOperation::DestroyKeySet {
                principal: ADMIN_SERVICE_ID,
            },
            &now(),
        ),
        Err(keyd::Error::Denied)
    );
    assert_eq!(last_reason(&f), AuditReason::KeyNotFound);
    let issued = admin_ticket(&mut f, &tgt, 1);
    assert!(verify_bound(&mut f, &bound_octets(&issued, &DIGEST_A, 740), DIGEST_A).is_ok());
}

/// The admin service key rotates like any service key (a decision dird
/// registered), and a ticket under the previous version still verifies
/// bound. Source: docs/51 §6; docs/10 §1, §7; [MS-KILE] 3.4.5.
#[test]
fn admin_service_key_rotates_on_a_decision() {
    let mut f = admin_fixture();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let before = admin_ticket(&mut f, &tgt, 1);
    let rotation = f
        .decide(
            DecidedOperation::RotateKey {
                handle: ADMIN_SERVICE,
            },
            &now(),
        )
        .unwrap();
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, rotation, &now()),
        Ok(Kvno::new(2))
    );
    assert!(verify_bound(&mut f, &bound_octets(&before, &DIGEST_A, 750), DIGEST_A).is_ok());
    let after = admin_ticket(&mut f, &tgt, 2);
    assert_eq!(after.ticket.enc_part.kvno, Some(2));
    assert!(verify_bound(&mut f, &bound_octets(&after, &DIGEST_B, 751), DIGEST_B).is_ok());
}
