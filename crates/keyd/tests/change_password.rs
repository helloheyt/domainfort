//! The RFC 3244 change-password operations of keyd (task K3):
//! `open_change_password_request`, `complete_change_password`,
//! `seal_change_password_error` — Role::Ldap (dird) only.
//!
//! The tests play three parts: the KDC (most tests seal the
//! `kadmin/changepw` ticket themselves under the change-password service key
//! they scripted into `create_key`, so that a test can make a ticket keyd
//! would never issue; the last section — task K3b — has keyd's armored AS
//! issue it, under the service's profile), the Kerberos client (the AP-REQ
//! with a subkey and a
//! sequence number, the KRB-PRIV under the subkey with key usage 13, and the
//! opening of keyd's AP-REP — usage 12 under the session key — and reply
//! KRB-PRIV), and dird (the `ChangePassword` decision, then the completion or
//! the error seal). The cryptography itself (krb-crypto) is verified against
//! the RFC 3962 / RFC 8009 vectors in its own tests; no RFC gives an example
//! of an RFC 3244 exchange, so these are the round trips and attack cases
//! docs/53 §10 asks for. Every value is made up for these tests (addresses
//! from the RFC 5737 documentation range); no vector comes from any other
//! implementation.
//!
//! Sources: RFC 3244 §2 (pinned, read in full); RFC 4120 §2.1, §3.1.3,
//! §3.1.5, §3.2.3, §3.2.4, §3.2.5, §3.5.1, §3.5.2, §5.3, §5.5.1, §5.5.2,
//! §5.7.1, §7.1, §7.5.1, §8.2 (pinned); RFC 6113 §5.4, §5.4.3, §5.4.6
//! (pinned); RFC 3962 §7; RFC 8009 §7; [MS-SAMR] 3.1.1.7.2 (as applied by
//! crate admin-password-policy); docs/53 §2.4, §4.3-§4.5, §5.2-§5.8, §6, §8,
//! §10; docs/questions/Q-601, Q-603, Q-604, Q-605, Q-620, Q-662, Q-915.

mod common;

use common::*;
use keyd::{
    AsRepParts, AsServer, AsTicketTemplate, AuditOutcome, AuditReason, AuthnError, AuthnProof,
    ChangePasswordContext, ChangePasswordCtxId, ChangePasswordVerdict, ConfigError,
    DecidedOperation, EncTypeId, Error, FastArmor, HostAddr, InMemoryKeyStore, IssueError,
    KeyHandle, KeyPurpose, Keyd, KeydConfig, Kvno, Operation, SealedReply, SetSecretTarget,
    ADDRESS_TYPE_DIRECTIONAL, CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS,
};
use krb_crypto::{EncType, ProtocolKey};
use krb_proto::constants::{DOMAIN_X500_COMPRESS, PA_ENCRYPTED_CHALLENGE};
use krb_proto::{
    ApOptions, ApReq, Authenticator, ChangePasswdData, Checksum, EncApRepPart, EncAsRepPart,
    EncKrbPrivPart, EncTicketPart, EncryptedData, EncryptionKey, FastOptions, HostAddress,
    KerberosTime, KeyValue, KrbFastReq, KrbFastResponse, KrbPriv, Microseconds, NewPasswd,
    NonZeroResultCode, PaData, PaEncTsEnc, PrincipalName, ResultCode, Ticket, TicketFlags,
    TransitedEncoding, UserData,
};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Fixture.
// ---------------------------------------------------------------------------

/// The four AES encryption types keyd's profile has (RFC 3962 §7; RFC 8009
/// §7), all configured, so each round trip can use its own.
const ENCTYPES: [EncType; 4] = [
    EncType::Aes256CtsHmacSha196,
    EncType::Aes128CtsHmacSha196,
    EncType::Aes256CtsHmacSha384192,
    EncType::Aes128CtsHmacSha256128,
];

const SESSION_KEY: [u8; 32] = [0x5A; 32];
const SUBKEY: [u8; 32] = [0x6B; 32];
const OTHER_SUBKEY: [u8; 32] = [0x7C; 32];
/// The client's initial sequence number (RFC 4120 5.5.1: "SHOULD be random").
const SEQ: u32 = 0x8A21_3C47;

/// The connection as the front's kernel reported it (RFC 5737 TEST-NET-1).
fn peer() -> HostAddr {
    HostAddr::ipv4([192, 0, 2, 10])
}
fn local() -> HostAddr {
    HostAddr::ipv4([192, 0, 2, 1])
}

/// keyd with every AES enctype configured and the change-password service
/// key set drawn by `create_key` (docs/53 §5.2).
fn fixture() -> Fixture {
    let mut c = config();
    c.enctypes = vec![
        EncTypeId::Aes256CtsHmacSha196,
        EncTypeId::Aes128CtsHmacSha196,
        EncTypeId::Aes256CtsHmacSha384192,
        EncTypeId::Aes128CtsHmacSha256128,
    ];
    let mut f = Fixture::with_config(c);
    add_change_password_service(&mut f);
    f
}

fn key(enctype: EncType, bytes: &[u8; 32]) -> ProtocolKey {
    krb_crypto::random_to_key(enctype, &bytes[..enctype.key_length()]).unwrap()
}

// ---------------------------------------------------------------------------
// The KDC side: a `kadmin/changepw` ticket (the AS issuance is task K5).
// ---------------------------------------------------------------------------

/// A ticket and what the client learned with it.
struct Issued {
    enctype: EncType,
    ticket: Ticket,
    session: ProtocolKey,
}

/// alice's `kadmin/changepw` ticket of `enctype` with `flags` — INITIAL
/// unless a test says otherwise (RFC 4120 2.1) — sealed under `service_key`
/// (usage 2) for `sname`.
fn issue_with(
    enctype: EncType,
    flags: TicketFlags,
    sname: PrincipalName,
    service_key: &ProtocolKey,
) -> Issued {
    let session = key(enctype, &SESSION_KEY);
    let part = EncTicketPart {
        flags,
        key: EncryptionKey {
            keytype: enctype.number(),
            keyvalue: KeyValue::from_slice(session.octets()),
        },
        crealm: realm(),
        cname: alice_name(),
        transited: TransitedEncoding {
            tr_type: DOMAIN_X500_COMPRESS,
            contents: Vec::new(),
        },
        authtime: now(),
        starttime: None,
        endtime: at(300),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let plain: Zeroizing<Vec<u8>> = part.encode().unwrap();
    let ticket = Ticket {
        realm: realm(),
        sname,
        enc_part: EncryptedData {
            etype: service_key.enc_type().number(),
            kvno: Some(1),
            cipher: krb_crypto::encrypt(service_key, usage(2), &[0x31; 16], &plain).unwrap(),
        },
    };
    Issued {
        enctype,
        ticket,
        session,
    }
}

fn initial() -> TicketFlags {
    TicketFlags::INITIAL.union(TicketFlags::PRE_AUTHENT)
}

fn issue(enctype: EncType) -> Issued {
    issue_with(
        enctype,
        initial(),
        change_password_service_name(),
        &change_password_service_key(enctype),
    )
}

// ---------------------------------------------------------------------------
// The client side: the RFC 3244 request (AP-REQ ‖ KRB-PRIV).
// ---------------------------------------------------------------------------

/// What the client puts in a request; the defaults are a valid request.
struct Spec {
    cusec: u32,
    subkey: Option<[u8; 32]>,
    seq: Option<u32>,
    cksum: Option<Checksum>,
    /// The key octets the KRB-PRIV is sealed under: the subkey's unless set.
    priv_key: Option<[u8; 32]>,
    priv_seq: Option<u32>,
    timestamp: Option<KerberosTime>,
    s_address: HostAddress,
    /// The ChangePasswdData DER (the KRB-PRIV user-data).
    user_data: Vec<u8>,
}

/// The DER of a change request for `password` (RFC 3244 §2; krb-proto's
/// only constructor builds the change form).
fn change(password: &str) -> Vec<u8> {
    ChangePasswdData::change(NewPasswd::from_slice(password.as_bytes()))
        .encode()
        .unwrap()
        .to_vec()
}

/// A DER element with a short-form length (this project's test helper rule,
/// crates/krb-proto/tests/common `tlv`, X.690 8.1.3: lengths below 128 take
/// one octet).
fn tlv(identifier: u8, contents: &[u8]) -> Vec<u8> {
    assert!(contents.len() < 0x80);
    let mut out = vec![identifier, contents.len() as u8];
    out.extend_from_slice(contents);
    out
}

/// The DER of a **set** request (RFC 3244 §2; [MS-KILE] 3.1.5.12):
/// `SEQUENCE { newpasswd [0] OCTET STRING, targname [1] PrincipalName }`,
/// explicit tags (docs/questions/Q-620 item 1).
fn set_request(password: &str, targname: &PrincipalName) -> Vec<u8> {
    let newpasswd = tlv(0xA0, &tlv(0x04, password.as_bytes()));
    let target = tlv(0xA1, &targname.encode().unwrap());
    let mut body = newpasswd;
    body.extend_from_slice(&target);
    tlv(0x30, &body)
}

fn directional(value: [u8; 4]) -> HostAddress {
    HostAddress {
        addr_type: ADDRESS_TYPE_DIRECTIONAL,
        address: value.to_vec(),
    }
}

impl Spec {
    fn new(cusec: u32, password: &str) -> Spec {
        Spec {
            cusec,
            subkey: Some(SUBKEY),
            seq: Some(SEQ),
            cksum: None,
            priv_key: None,
            priv_seq: Some(SEQ),
            timestamp: Some(now()),
            s_address: directional([0, 0, 0, 0]),
            user_data: change(password),
        }
    }
}

/// The request's two fields: the AP-REQ (Authenticator under the session
/// key, usage 11, RFC 4120 5.5.1) and the KRB-PRIV (EncKrbPrivPart under the
/// subkey, usage 13, RFC 4120 5.7.1; RFC 3244 §2).
fn request(issued: &Issued, spec: &Spec) -> (Vec<u8>, Vec<u8>) {
    let enctype = issued.enctype;
    let authenticator = Authenticator {
        crealm: realm(),
        cname: alice_name(),
        cksum: spec.cksum.clone(),
        cusec: Microseconds::new(spec.cusec).unwrap(),
        ctime: now(),
        subkey: spec.subkey.map(|bytes| EncryptionKey {
            keytype: enctype.number(),
            keyvalue: KeyValue::from_slice(&bytes[..enctype.key_length()]),
        }),
        seq_number: spec.seq,
        authorization_data: None,
    }
    .encode()
    .unwrap();
    let ap_req = ApReq {
        ap_options: ApOptions::empty(),
        ticket: issued.ticket.clone(),
        authenticator: EncryptedData {
            etype: enctype.number(),
            kvno: None,
            cipher: krb_crypto::encrypt(&issued.session, usage(11), &[0x42; 16], &authenticator)
                .unwrap(),
        },
    }
    .encode()
    .unwrap();
    let priv_key = key(enctype, &spec.priv_key.unwrap_or(SUBKEY));
    let part = EncKrbPrivPart {
        user_data: UserData::from_slice(&spec.user_data),
        timestamp: spec.timestamp,
        usec: Some(Microseconds::new(spec.cusec).unwrap()),
        seq_number: spec.priv_seq,
        s_address: spec.s_address.clone(),
        r_address: None,
    }
    .encode()
    .unwrap();
    let krb_priv = KrbPriv {
        enc_part: EncryptedData {
            etype: priv_key.enc_type().number(),
            kvno: None,
            cipher: krb_crypto::encrypt(&priv_key, usage(13), &[0x43; 16], &part).unwrap(),
        },
    }
    .encode()
    .unwrap();
    (ap_req, krb_priv)
}

/// dird's call: open the request.
fn open_request(
    f: &mut Fixture,
    issued: &Issued,
    spec: &Spec,
) -> Result<ChangePasswordContext, AuthnError> {
    let (ap_req, krb_priv) = request(issued, spec);
    f.keyd.open_change_password_request(
        &LDAP,
        &CHANGE_PASSWORD_SERVICE_ID,
        &ap_req,
        &krb_priv,
        &peer(),
        &local(),
        &now(),
    )
}

/// The `ChangePassword` decision dird registers for alice's own change
/// (docs/53 §5.6 step 5; Q-662).
fn decide_alice(f: &mut Fixture) {
    f.decide(
        DecidedOperation::ChangePassword {
            target: SetSecretTarget {
                handle: ALICE,
                binding: alice_binding(),
                salt: ALICE_SALT.to_owned(),
            },
        },
        &now(),
    )
    .unwrap();
}

/// The client opens keyd's reply (RFC 4120 3.2.5: the AP-REP under the
/// session key with the Authenticator's ctime / cusec; RFC 3244 §2: the
/// KRB-PRIV under the subkey) and returns the result code and the reply's
/// `s-address`.
fn read_reply(issued: &Issued, reply: &SealedReply, cusec: u32) -> (ResultCode, HostAddress) {
    let rep = EncApRepPart::decode(&open(&issued.session, 12, &reply.ap_rep.enc_part)).unwrap();
    assert_eq!(rep.ctime, now(), "RFC 4120 3.2.4: the client's ctime");
    assert_eq!(rep.cusec.get(), cusec, "RFC 4120 3.2.4: the client's cusec");
    assert_eq!(
        rep.subkey, None,
        "the client's subkey stays the KRB-PRIV key"
    );
    let seq = rep.seq_number.expect("a random sequence number");
    assert_ne!(seq, 0);
    let subkey = key(issued.enctype, &SUBKEY);
    let part = EncKrbPrivPart::decode(&open(&subkey, 13, &reply.krb_priv.enc_part)).unwrap();
    assert_eq!(
        part.seq_number,
        Some(seq),
        "Q-604 item 2: the AP-REP's number"
    );
    assert_eq!(part.timestamp, Some(now()));
    assert_eq!(part.r_address, None);
    // RFC 3244 §2: exactly the 2-octet code — no result string (Q-604 item 5).
    assert_eq!(part.user_data.as_bytes().len(), 2);
    (
        ResultCode::from_result_data(part.user_data.as_bytes()).unwrap(),
        part.s_address,
    )
}

fn last(f: &Fixture) -> &keyd::AuditRecord {
    f.records().last().unwrap()
}

// ---------------------------------------------------------------------------
// The round trip.
// ---------------------------------------------------------------------------

/// docs/53 §10 item 2 (the cryptographic round trip, for every AES enctype —
/// RFC 3962 §7, RFC 8009 §7): alice changes her password through keyd. The
/// request opens with verdict `Acceptable`; dird registers its decision;
/// the completion installs the new password (kvno + 1, through the install
/// path of `set_secret`) and seals the success reply, which the client
/// opens: AP-REP with her ctime / cusec, KRB-PRIV with result 0 and the
/// directional address 1 (RFC 4120 7.1). Afterwards the AS accepts the new
/// password and refuses the old one. Sources: RFC 3244 §2; RFC 4120 3.2.4,
/// 3.2.5, 5.5.2, 5.7.1, 7.1, 7.5.1 items 12, 13.
#[test]
fn a_change_round_trips_for_every_aes_enctype() {
    let mut f = fixture();
    let mut old = ALICE_PASSWORD.to_owned();
    for (i, enctype) in ENCTYPES.into_iter().enumerate() {
        let new = format!("Garland-Owl-24-Fir#{i}");
        let issued = issue(enctype);
        let cusec = 1_000 + i as u32;
        let ctx = open_request(&mut f, &issued, &Spec::new(cusec, &new)).unwrap();
        assert_eq!(
            ctx.verdict,
            ChangePasswordVerdict::Acceptable,
            "{enctype:?}"
        );
        assert_eq!(ctx.cname, alice_name());
        assert_eq!(ctx.crealm, realm());
        assert!(ctx.flags.contains(TicketFlags::INITIAL));
        let open_record = last(&f);
        assert_eq!(open_record.op, Operation::OpenChangePasswordRequest);
        assert_eq!(open_record.result, AuditOutcome::Success);
        assert_eq!(open_record.reason, AuditReason::None);
        assert_eq!(open_record.purpose, Some(KeyPurpose::ChangePasswordService));

        decide_alice(&mut f);
        let reply = f
            .keyd
            .complete_change_password(&LDAP, &ctx.ctx_id, &ALICE, &now())
            .unwrap();
        let record = last(&f);
        assert_eq!(record.op, Operation::CompleteChangePassword);
        assert_eq!(record.result, AuditOutcome::Success);
        assert_eq!(record.principal, Some(ALICE_ID));
        assert!(record.decision.is_some());
        assert_eq!(record.kvno, Some(Kvno::new(2 + i as u32)));

        let (code, s_address) = read_reply(&issued, &reply, cusec);
        assert_eq!(code, ResultCode::Success);
        assert_eq!(s_address, directional([0, 0, 0, 1]));
        assert!(f.password_works(&ALICE, &new, ALICE_SALT), "{enctype:?}");
        assert!(!f.password_works(&ALICE, &old, ALICE_SALT), "{enctype:?}");
        old = new;
    }
}

/// RFC 4120 3.5.2 ("the recipient verifies that the operating system's
/// report of the sender's address matches"), 7.1; Q-603 item 8; Q-604 item
/// 2: a request whose `s-address` is the peer's own address is accepted, and
/// the reply carries the connection's local address; an IPv4-mapped peer
/// address is matched as type 2.
#[test]
fn a_peer_address_is_matched_and_the_reply_carries_the_local_address() {
    let mut f = fixture();
    let issued = issue(EncType::Aes256CtsHmacSha196);
    let mut spec = Spec::new(2_001, "Rhubarb-Sequoia-68-Tapir");
    spec.s_address = peer().host_address();
    let ctx = open_request(&mut f, &issued, &spec).unwrap();
    decide_alice(&mut f);
    let reply = f
        .keyd
        .complete_change_password(&LDAP, &ctx.ctx_id, &ALICE, &now())
        .unwrap();
    let (code, s_address) = read_reply(&issued, &reply, 2_001);
    assert_eq!(code, ResultCode::Success);
    assert_eq!(s_address, local().host_address());

    // The same peer reported as an IPv4-mapped IPv6 address.
    let mut mapped = [0u8; 16];
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12..].copy_from_slice(&[192, 0, 2, 10]);
    let mut spec = Spec::new(2_002, "Urchin-Violet-84-Yucca");
    spec.s_address = peer().host_address();
    let (ap_req, krb_priv) = request(&issued, &spec);
    assert!(f
        .keyd
        .open_change_password_request(
            &LDAP,
            &CHANGE_PASSWORD_SERVICE_ID,
            &ap_req,
            &krb_priv,
            &HostAddr::ipv6(mapped),
            &local(),
            &now(),
        )
        .is_ok());
}

// ---------------------------------------------------------------------------
// The decision binding (docs/53 R53-8, §5.5; Q-662).
// ---------------------------------------------------------------------------

/// docs/53 §5.5: without a decision the completion is refused (`NoGrant`,
/// nothing installed), and the context stays for the error reply; with a
/// decision whose target is another principal it is refused too
/// (`GrantMismatch`) — keyd binds the target to the ticket's client — and
/// the decision is consumed. Nothing of alice's or bob's changes.
#[test]
fn the_completion_needs_the_clients_own_decision() {
    let mut f = fixture();
    let issued = issue(EncType::Aes256CtsHmacSha196);
    let ctx = open_request(&mut f, &issued, &Spec::new(3_001, "Quill-Marsh-31-Pebble")).unwrap();

    // No decision at all.
    assert_eq!(
        f.keyd
            .complete_change_password(&LDAP, &ctx.ctx_id, &ALICE, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::NoGrant);

    // A decision for bob's key set, presented with bob as the target.
    f.decide(
        DecidedOperation::ChangePassword {
            target: SetSecretTarget {
                handle: BOB,
                binding: bob_binding(),
                salt: BOB_SALT.to_owned(),
            },
        },
        &now(),
    )
    .unwrap();
    assert_eq!(
        f.keyd
            .complete_change_password(&LDAP, &ctx.ctx_id, &BOB, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::GrantMismatch);

    // A decision for alice's key set naming bob's binding.
    f.decide(
        DecidedOperation::ChangePassword {
            target: SetSecretTarget {
                handle: ALICE,
                binding: bob_binding(),
                salt: ALICE_SALT.to_owned(),
            },
        },
        &now(),
    )
    .unwrap();
    assert_eq!(
        f.keyd
            .complete_change_password(&LDAP, &ctx.ctx_id, &ALICE, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::GrantMismatch);

    // An admin-plane `SetSecret` decision for alice is not for this executor.
    f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
        .unwrap();
    assert_eq!(
        f.keyd
            .complete_change_password(&LDAP, &ctx.ctx_id, &ALICE, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::NoGrant);

    // Nothing changed; the context still takes its (one) error reply.
    assert!(f.password_works(&ALICE, ALICE_PASSWORD, ALICE_SALT));
    assert!(f.password_works(&BOB, BOB_PASSWORD, BOB_SALT));
    let reply = f
        .keyd
        .seal_change_password_error(&LDAP, &ctx.ctx_id, NonZeroResultCode::HardError, &now())
        .unwrap();
    assert_eq!(
        read_reply(&issued, &reply, 3_001).0,
        ResultCode::Failure(NonZeroResultCode::HardError)
    );
    assert_eq!(last(&f).reason, AuditReason::KpasswdHardError);
}

/// Q-662 (the class "a one-time authorization meant for one executor
/// redeemable by another"): a `ChangePassword` decision dird registers for
/// alice's own change cannot be redeemed by admind's `set_secret` — even
/// with exactly its binding and salt and while it is live — so admind alone
/// still cannot set a secret of its choosing (docs/53 R53-8). The decision
/// stays for keyd's completion.
#[test]
fn admind_cannot_redeem_a_change_password_decision() {
    let mut f = fixture();
    let issued = issue(EncType::Aes128CtsHmacSha196);
    let ctx = open_request(&mut f, &issued, &Spec::new(4_001, "Lichen-Sparrow-75-Haze")).unwrap();
    decide_alice(&mut f);
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            Zeroizing::new("Koala-Lotus-92-Mango".to_owned()),
            ALICE_SALT,
            &now(),
        ),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::NoGrant);
    assert!(f.password_works(&ALICE, ALICE_PASSWORD, ALICE_SALT));
    f.keyd
        .complete_change_password(&LDAP, &ctx.ctx_id, &ALICE, &now())
        .unwrap();
    assert!(f.password_works(&ALICE, "Lichen-Sparrow-75-Haze", ALICE_SALT));
    assert!(!f.password_works(&ALICE, "Koala-Lotus-92-Mango", ALICE_SALT));
}

// ---------------------------------------------------------------------------
// Verdicts.
// ---------------------------------------------------------------------------

/// RFC 3244 §2 ("replying with status 0x0007 if it is not set and should
/// be"); RFC 4120 2.1; docs/53 R53-9: a ticket without INITIAL opens with
/// verdict `InitialFlagNeeded`; the completion is refused even with a
/// decision; the only error reply that may be sealed carries code 7.
#[test]
fn a_ticket_without_initial_is_result_7() {
    let mut f = fixture();
    let issued = issue_with(
        EncType::Aes256CtsHmacSha196,
        TicketFlags::PRE_AUTHENT,
        change_password_service_name(),
        &change_password_service_key(EncType::Aes256CtsHmacSha196),
    );
    let ctx = open_request(&mut f, &issued, &Spec::new(5_001, "Mortar-Cypress-19-Wisp")).unwrap();
    assert_eq!(ctx.verdict, ChangePasswordVerdict::InitialFlagNeeded);
    assert_eq!(last(&f).result, AuditOutcome::Success);
    assert_eq!(last(&f).reason, AuditReason::KpasswdInitialFlagNeeded);
    decide_alice(&mut f);
    assert_eq!(
        f.keyd
            .complete_change_password(&LDAP, &ctx.ctx_id, &ALICE, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::ChangePasswordNotAcceptable);
    assert!(f.password_works(&ALICE, ALICE_PASSWORD, ALICE_SALT));
    for wrong in [
        NonZeroResultCode::AccessDenied,
        NonZeroResultCode::SoftError,
        NonZeroResultCode::HardError,
    ] {
        assert_eq!(
            f.keyd
                .seal_change_password_error(&LDAP, &ctx.ctx_id, wrong, &now()),
            Err(Error::Denied)
        );
        assert_eq!(last(&f).reason, AuditReason::ResultCodeNotPermitted);
    }
    let reply = f
        .keyd
        .seal_change_password_error(
            &LDAP,
            &ctx.ctx_id,
            NonZeroResultCode::InitialFlagNeeded,
            &now(),
        )
        .unwrap();
    assert_eq!(
        read_reply(&issued, &reply, 5_001).0,
        ResultCode::Failure(NonZeroResultCode::InitialFlagNeeded)
    );
}

/// [MS-SAMR] 3.1.1.7.2 items 2, 3.2.1, 3.2.2 and docs/56 §7 P-24 (keyd's
/// one policy, docs/53 §6); RFC 3244 §2; Q-603 item 7; A-121: a new
/// password that breaks any one rule — too short, the account name (both
/// cases), the realm's name, a missing character class, a sequence (`Abc`,
/// `123`), a repeat (`111`), a weak word (`admin`), over 256 UTF-16 units,
/// or not UTF-8 — opens with verdict `PasswordRefused` — before dird writes
/// anything — and its reply is SOFTERROR with **no** result string; the
/// audit record says which code, never which rule. Test data made up.
#[test]
fn a_policy_violating_password_is_softerror_without_a_reason() {
    let mut f = fixture();
    let issued = issue(EncType::Aes256CtsHmacSha196);
    let too_long = format!("Tq7#{}", "p-".repeat(127));
    let mut cases: Vec<Vec<u8>> = vec![
        change("short"),
        change("Tq7#Lm2"),
        change("Tq7#alice!w"),
        change("Tq7#ALICE!w"),
        change("Tq7#Example!"),
        change("tq7#lm2!xw"),
        change("Tq7#Abc!w"),
        change("Tq7#123!w"),
        change("Tq7#111!w"),
        change("Tq7#admin!w"),
        change(&too_long),
    ];
    // Not UTF-8 (RFC 3961 §3: no conversion of an unknown encoding).
    cases.push(
        ChangePasswdData::change(NewPasswd::from_slice(&[0xC3, 0x28, 0x61, 0x62, 0x63, 0x64]))
            .encode()
            .unwrap()
            .to_vec(),
    );
    for (i, user_data) in cases.into_iter().enumerate() {
        let cusec = 6_000 + i as u32;
        let mut spec = Spec::new(cusec, "unused");
        spec.user_data = user_data;
        let ctx = open_request(&mut f, &issued, &spec).unwrap();
        assert_eq!(ctx.verdict, ChangePasswordVerdict::PasswordRefused, "{i}");
        assert_eq!(last(&f).reason, AuditReason::KpasswdSoftError);
        let reply = f
            .keyd
            .seal_change_password_error(&LDAP, &ctx.ctx_id, NonZeroResultCode::SoftError, &now())
            .unwrap();
        assert_eq!(
            read_reply(&issued, &reply, cusec).0,
            ResultCode::Failure(NonZeroResultCode::SoftError)
        );
    }
    assert!(f.password_works(&ALICE, ALICE_PASSWORD, ALICE_SALT));
}

/// docs/53 R53-1, §5.4 item 4; [MS-KILE] 3.1.5.12; Q-600 item 2; Q-620
/// item 3: a set request (targname present — even naming the client
/// herself) opens with verdict `SetNotSupported`; it never reaches the
/// install — the completion is refused with a live decision — and its only
/// error reply is ACCESSDENIED. A malformed ChangePasswdData opens with
/// verdict `Malformed` (Q-620 item 5).
#[test]
fn the_set_form_never_reaches_the_install() {
    let mut f = fixture();
    let issued = issue(EncType::Aes256CtsHmacSha196);
    for (i, target) in [alice_name(), bob_name()].into_iter().enumerate() {
        let cusec = 7_000 + i as u32;
        let mut spec = Spec::new(cusec, "unused");
        spec.user_data = set_request("a phrase set for", &target);
        let ctx = open_request(&mut f, &issued, &spec).unwrap();
        assert_eq!(ctx.verdict, ChangePasswordVerdict::SetNotSupported);
        assert_eq!(last(&f).reason, AuditReason::KpasswdAccessDenied);
        decide_alice(&mut f);
        assert_eq!(
            f.keyd
                .complete_change_password(&LDAP, &ctx.ctx_id, &ALICE, &now()),
            Err(Error::Denied)
        );
        assert_eq!(last(&f).reason, AuditReason::ChangePasswordNotAcceptable);
        let reply = f
            .keyd
            .seal_change_password_error(&LDAP, &ctx.ctx_id, NonZeroResultCode::AccessDenied, &now())
            .unwrap();
        assert_eq!(
            read_reply(&issued, &reply, cusec).0,
            ResultCode::Failure(NonZeroResultCode::AccessDenied)
        );
    }
    assert!(f.password_works(&ALICE, ALICE_PASSWORD, ALICE_SALT));
    assert!(!f.password_works(&ALICE, "a phrase set for", ALICE_SALT));
    assert!(f.password_works(&BOB, BOB_PASSWORD, BOB_SALT));

    let mut spec = Spec::new(7_100, "unused");
    spec.user_data = vec![0x30, 0x00];
    let ctx = open_request(&mut f, &issued, &spec).unwrap();
    assert_eq!(ctx.verdict, ChangePasswordVerdict::Malformed);
    assert_eq!(last(&f).reason, AuditReason::KpasswdMalformed);
}

// ---------------------------------------------------------------------------
// Attacks on the request (docs/53 §2.4, §8).
// ---------------------------------------------------------------------------

/// The request's AP-REQ and KRB-PRIV rules, each the uniform `Denied` with
/// its audit reason and no context: no subkey and no sequence number (RFC
/// 3244 §2); a `cksum` (Q-603 item 4); the KRB-PRIV under the session key or
/// under another subkey (RFC 3244 §2; RFC 4120 3.5.2 BAD_INTEGRITY); a
/// KRB-PRIV sequence number missing or different (BADORDER); a stale
/// timestamp (SKEW); a foreign or reflected `s-address` (BADADDR); an
/// undecodable AP-REQ or KRB-PRIV (Q-660: uniform before the chain).
#[test]
fn malformed_and_unbound_requests_are_denied() {
    let mut f = fixture();
    let issued = issue(EncType::Aes256CtsHmacSha196);
    let mut cusec = 8_000;
    let mut next = || {
        cusec += 1;
        cusec
    };
    type Tweak = Box<dyn Fn(&mut Spec)>;
    let cases: Vec<(Tweak, AuditReason)> = vec![
        (Box::new(|s| s.subkey = None), AuditReason::SubkeyMissing),
        (
            Box::new(|s| s.seq = None),
            AuditReason::SequenceNumberMissing,
        ),
        (
            Box::new(|s| {
                s.cksum = Some(Checksum {
                    cksumtype: 16,
                    checksum: vec![0; 12],
                })
            }),
            AuditReason::ApChecksumUnsupported,
        ),
        (
            Box::new(|s| s.priv_key = Some(SESSION_KEY)),
            AuditReason::IntegrityFailure,
        ),
        (
            Box::new(|s| s.priv_key = Some(OTHER_SUBKEY)),
            AuditReason::IntegrityFailure,
        ),
        (
            Box::new(|s| s.priv_seq = None),
            AuditReason::KrbPrivSequenceMismatch,
        ),
        (
            Box::new(|s| s.priv_seq = Some(SEQ.wrapping_add(1))),
            AuditReason::KrbPrivSequenceMismatch,
        ),
        (
            Box::new(|s| s.timestamp = Some(at(-3_600))),
            AuditReason::KrbPrivTimestampSkew,
        ),
        (
            Box::new(|s| s.s_address = HostAddr::ipv4([192, 0, 2, 99]).host_address()),
            AuditReason::KrbPrivAddressMismatch,
        ),
        (
            Box::new(|s| s.s_address = directional([0, 0, 0, 1])),
            AuditReason::KrbPrivAddressMismatch,
        ),
    ];
    for (tweak, reason) in cases {
        let mut spec = Spec::new(next(), "Mortar-Cypress-19-Wisp");
        tweak(&mut spec);
        assert_eq!(
            open_request(&mut f, &issued, &spec).map(|c| c.verdict),
            Err(AuthnError::Denied),
            "{reason:?}"
        );
        assert_eq!(last(&f).reason, reason);
        assert_eq!(last(&f).result, AuditOutcome::Denied);
    }
    // Undecodable fields.
    let (ap_req, krb_priv) = request(&issued, &Spec::new(next(), "Mortar-Cypress-19-Wisp"));
    for (a, p) in [
        (&[0x30, 0x00][..], &krb_priv[..]),
        (&ap_req[..], &[0x30, 0x00][..]),
    ] {
        assert_eq!(
            f.keyd
                .open_change_password_request(
                    &LDAP,
                    &CHANGE_PASSWORD_SERVICE_ID,
                    a,
                    p,
                    &peer(),
                    &local(),
                    &now(),
                )
                .map(|c| c.verdict),
            Err(AuthnError::Denied)
        );
        assert_eq!(last(&f).reason, AuditReason::MalformedInput);
    }
}

/// RFC 4120 3.2.3 (the replay cache, shared — "they MUST share this replay
/// cache"); docs/53 §5.8: the same AP-REQ presented twice is refused as
/// `Replay` (the chain completed, so the class is reported, A-26), with a
/// different KRB-PRIV too.
#[test]
fn a_replayed_request_is_refused() {
    let mut f = fixture();
    let issued = issue(EncType::Aes256CtsHmacSha196);
    let spec = Spec::new(9_001, "Mortar-Cypress-19-Wisp");
    let (ap_req, krb_priv) = request(&issued, &spec);
    let open = |f: &mut Fixture, krb_priv: &[u8]| {
        f.keyd.open_change_password_request(
            &LDAP,
            &CHANGE_PASSWORD_SERVICE_ID,
            &ap_req,
            krb_priv,
            &peer(),
            &local(),
            &now(),
        )
    };
    assert!(open(&mut f, &krb_priv).is_ok());
    assert_eq!(
        open(&mut f, &krb_priv).map(|c| c.verdict),
        Err(AuthnError::Replay)
    );
    assert_eq!(last(&f).reason, AuditReason::Replay);
    let (_, other_priv) = request(&issued, &Spec::new(9_001, "Pumice-Kestrel-53-Fig"));
    assert_eq!(
        open(&mut f, &other_priv).map(|c| c.verdict),
        Err(AuthnError::Replay)
    );
}

/// docs/53 §4.5, §5.3, §8 (cross-service / confused deputy; R2's pattern):
/// the change-password service key set is opened by
/// `open_change_password_request` only — the two other service-ticket
/// verifications name other purposes of the principal (no such key set),
/// the KDC's issuance and every secret operation refuse its purpose, its
/// rotation is only a decision's (task F3, A-126: the decision is accepted;
/// the rotation itself — `the_change_password_key_rotates_through_a_decision_only`
/// — runs only on it) — and that operation opens no other key
/// set: a ticket for another service under the request's principal fails the
/// A-19 binding, and the other services' principals have no
/// ChangePasswordService key set.
#[test]
fn the_change_password_key_is_opened_by_its_operation_only() {
    let mut f = fixture();
    add_ldap_service(&mut f);
    let issued = issue(EncType::Aes256CtsHmacSha196);
    let (ap_req, _) = request(&issued, &Spec::new(10_001, "Mortar-Cypress-19-Wisp"));

    assert_eq!(
        f.keyd
            .open_and_verify_service_ticket(&LDAP, &CHANGE_PASSWORD_SERVICE_ID, &ap_req, &now())
            .map(|_| ()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::KeyNotFound);
    assert_eq!(
        f.keyd
            .verify_operation_ticket(
                &LDAP,
                &CHANGE_PASSWORD_SERVICE_ID,
                &keyd::OperationDigest::new([0x11; 32]),
                &ap_req,
                &now(),
            )
            .map(|_| ()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::KeyNotFound);
    assert!(f
        .keyd
        .issue_tgs_rep(
            &KDC,
            &CHANGE_PASSWORD_SERVICE,
            &keyd::CtxId::from_bytes([1; 16]),
            &tgs_template(1),
            &now(),
        )
        .is_err());
    assert_eq!(last(&f).reason, AuditReason::PurposeMismatch);
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &CHANGE_PASSWORD_SERVICE,
            &bound(change_password_service_name()),
            Zeroizing::new("Nutmeg-Olive-13-Panda".to_owned()),
            "salt",
            &now(),
        ),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::PurposeMismatch);
    // Task F3 (A-126, Q-660 item 11): a rotation of it can be decided — a
    // dird decision, the one way `rotate_key` runs; a password set of it
    // still cannot (the set-secret family's purposes).
    assert!(f
        .decide(
            DecidedOperation::RotateKey {
                handle: CHANGE_PASSWORD_SERVICE
            },
            &now()
        )
        .is_ok());
    assert_eq!(
        f.decide(
            DecidedOperation::ChangePassword {
                target: SetSecretTarget {
                    handle: CHANGE_PASSWORD_SERVICE,
                    binding: bound(change_password_service_name()),
                    salt: String::from("salt"),
                },
            },
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::DecisionInvalid);

    // An LDAP service ticket presented to the change-password operation:
    // under the LDAP principal there is no change-password key set; under
    // the change-password principal the A-19 binding refuses the sname.
    let ldap = issue_with(
        EncType::Aes256CtsHmacSha196,
        initial(),
        ldap_service_name(),
        &ldap_service_key(),
    );
    let (ldap_ap_req, ldap_priv) = request(&ldap, &Spec::new(10_002, "Mortar-Cypress-19-Wisp"));
    for (principal, reason) in [
        (LDAP_SERVICE_ID, AuditReason::KeyNotFound),
        (CHANGE_PASSWORD_SERVICE_ID, AuditReason::NameBindingMismatch),
    ] {
        assert_eq!(
            f.keyd
                .open_change_password_request(
                    &LDAP,
                    &principal,
                    &ldap_ap_req,
                    &ldap_priv,
                    &peer(),
                    &local(),
                    &now(),
                )
                .map(|c| c.verdict),
            Err(AuthnError::Denied)
        );
        assert_eq!(last(&f).reason, reason);
    }
    // A key set under any other name cannot take the change-password
    // purpose, nor another purpose the change-password name (A-19,
    // docs/53 §5.2).
    let other = KeyHandle::new(
        keyd::PrincipalId::from_bytes([0x3E; 16]),
        KeyPurpose::ChangePasswordService,
    );
    assert_eq!(
        f.keyd
            .create_key(&ADMIN, &other, &bound(ldap_service_name()), &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::InvalidNameBinding);
    let service = KeyHandle::new(
        keyd::PrincipalId::from_bytes([0x3F; 16]),
        KeyPurpose::Service,
    );
    assert_eq!(
        f.keyd.create_key(
            &ADMIN,
            &service,
            &bound(change_password_service_name()),
            &now()
        ),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::InvalidNameBinding);
}

/// Only Role::Ldap holds the three operations (docs/53 R53-7; docs/10 §2):
/// the KDC, the directory and the admin roles are refused, one record each.
#[test]
fn only_ldap_runs_the_change_password_operations() {
    let mut f = fixture();
    let issued = issue(EncType::Aes256CtsHmacSha196);
    let (ap_req, krb_priv) = request(&issued, &Spec::new(11_001, "Mortar-Cypress-19-Wisp"));
    for caller in [KDC, DIRECTORY, ADMIN] {
        assert_eq!(
            f.keyd
                .open_change_password_request(
                    &caller,
                    &CHANGE_PASSWORD_SERVICE_ID,
                    &ap_req,
                    &krb_priv,
                    &peer(),
                    &local(),
                    &now(),
                )
                .map(|c| c.verdict),
            Err(AuthnError::Denied)
        );
        assert_eq!(last(&f).reason, AuditReason::RoleNotPermitted);
    }
    // The request is still fresh for dird (refused calls record nothing in
    // the replay cache).
    let ctx = f
        .keyd
        .open_change_password_request(
            &LDAP,
            &CHANGE_PASSWORD_SERVICE_ID,
            &ap_req,
            &krb_priv,
            &peer(),
            &local(),
            &now(),
        )
        .unwrap();
    for caller in [KDC, DIRECTORY, ADMIN] {
        assert!(f
            .keyd
            .complete_change_password(&caller, &ctx.ctx_id, &ALICE, &now())
            .is_err());
        assert_eq!(last(&f).reason, AuditReason::RoleNotPermitted);
        assert!(f
            .keyd
            .seal_change_password_error(&caller, &ctx.ctx_id, NonZeroResultCode::HardError, &now())
            .is_err());
        assert_eq!(last(&f).reason, AuditReason::RoleNotPermitted);
    }
    // Another Ldap uid: the context is bound to its caller (and goes).
    assert!(f
        .keyd
        .seal_change_password_error(
            &LDAP_OTHER,
            &ctx.ctx_id,
            NonZeroResultCode::HardError,
            &now()
        )
        .is_err());
    assert_eq!(last(&f).reason, AuditReason::TokenCallerMismatch);
}

// ---------------------------------------------------------------------------
// Exactly one reply per context (docs/53 §5.5).
// ---------------------------------------------------------------------------

/// docs/53 §5.5 ("exactly one reply per context; success only after the
/// install"): after the error seal, neither a completion nor a second seal
/// is possible; after the completion, no error seal; a context also expires
/// (`token_lifetime_secs`) — and with it the password.
#[test]
fn each_context_takes_exactly_one_reply() {
    let mut f = fixture();
    let issued = issue(EncType::Aes256CtsHmacSha196);

    let ctx = open_request(&mut f, &issued, &Spec::new(12_001, "Basalt-Magpie-97-Rue")).unwrap();
    f.keyd
        .seal_change_password_error(&LDAP, &ctx.ctx_id, NonZeroResultCode::AuthError, &now())
        .unwrap();
    decide_alice(&mut f);
    assert_eq!(
        f.keyd
            .complete_change_password(&LDAP, &ctx.ctx_id, &ALICE, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::TokenUnknown);
    assert_eq!(
        f.keyd
            .seal_change_password_error(&LDAP, &ctx.ctx_id, NonZeroResultCode::AuthError, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::TokenUnknown);
    assert!(f.password_works(&ALICE, ALICE_PASSWORD, ALICE_SALT));

    let ctx = open_request(&mut f, &issued, &Spec::new(12_002, "Fable-Crane-41-Moth")).unwrap();
    f.keyd
        .complete_change_password(&LDAP, &ctx.ctx_id, &ALICE, &now())
        .unwrap();
    assert_eq!(
        f.keyd
            .seal_change_password_error(&LDAP, &ctx.ctx_id, NonZeroResultCode::HardError, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::TokenUnknown);
    decide_alice(&mut f);
    assert_eq!(
        f.keyd
            .complete_change_password(&LDAP, &ctx.ctx_id, &ALICE, &now()),
        Err(Error::Denied)
    );
    assert!(f.password_works(&ALICE, "Fable-Crane-41-Moth", ALICE_SALT));

    // Expiry: the context lives `token_lifetime_secs` (30 s by default); the
    // decision (registered later, live 30 s) is still live when it is
    // presented.
    let ctx = open_request(&mut f, &issued, &Spec::new(12_003, "Tallow-Bison-86-Sage")).unwrap();
    f.decide(
        DecidedOperation::ChangePassword {
            target: SetSecretTarget {
                handle: ALICE,
                binding: alice_binding(),
                salt: ALICE_SALT.to_owned(),
            },
        },
        &at(10),
    )
    .unwrap();
    assert_eq!(
        f.keyd
            .complete_change_password(&LDAP, &ctx.ctx_id, &ALICE, &at(31)),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::TokenExpired);
    assert!(f.password_works(&ALICE, "Fable-Crane-41-Moth", ALICE_SALT));
}

/// docs/53 §5.5 (`max_change_password_contexts`); docs/CLEAN-ROOM.md (bounded):
/// a full context table refuses a new request (`Unavailable`), never
/// evicting a live one.
#[test]
fn the_context_table_is_bounded() {
    let mut c = config();
    c.max_change_password_contexts = 1;
    let mut f = Fixture::with_config(c);
    add_change_password_service(&mut f);
    let issued = issue(EncType::Aes256CtsHmacSha196);
    let first = open_request(
        &mut f,
        &issued,
        &Spec::new(13_001, "Mortar-Cypress-19-Wisp"),
    )
    .unwrap();
    assert_eq!(
        open_request(
            &mut f,
            &issued,
            &Spec::new(13_002, "Mortar-Cypress-19-Wisp")
        )
        .map(|c| c.verdict),
        Err(AuthnError::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::TokenTableFull);
    assert_eq!(last(&f).result, AuditOutcome::Unavailable);
    // The live one still completes.
    decide_alice(&mut f);
    assert!(f
        .keyd
        .complete_change_password(&LDAP, &first.ctx_id, &ALICE, &now())
        .is_ok());
}

// ---------------------------------------------------------------------------
// One password policy, on every path (docs/53 §6; Q-605).
// ---------------------------------------------------------------------------

/// docs/53 §6.1 (R53-10; Q-605 item 1); docs/56 §7 P-24: the policy is
/// enforced in keyd's install path — so admind's `set_secret` on a live
/// decision is refused a password breaking any one of the owner's rules
/// (too short, the account name, the realm's name, a missing class, a
/// sequence, a repeat, a weak word), the decision is consumed and nothing
/// is installed; the floor is the configured `min_password_chars` (8 by
/// default, P-24) — exactly 8 passes — and a larger one applies. Test data
/// made up.
#[test]
fn set_secret_obeys_the_same_policy() {
    let mut f = Fixture::new();
    for weak in [
        "Tq7#Lm2",
        "Tq7#Alice!",
        "Tq7#example!",
        "TQ7#LM2!X",
        "Tq7#cba!w",
        "Tq7#987!w",
        "Tq7#zZz!w",
        "Tq7#Admin!",
        "Tq7#Root!w",
        "Tq7#KRBTGT!",
    ] {
        f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
            .unwrap();
        assert_eq!(
            f.keyd.set_secret(
                &DIRECTORY,
                &ALICE,
                &alice_binding(),
                Zeroizing::new(weak.to_owned()),
                ALICE_SALT,
                &now(),
            ),
            Err(Error::Denied),
            "{weak}"
        );
        assert_eq!(last(&f).reason, AuditReason::PasswordPolicyRefused);
        assert!(f.keyd.secret_decision(&ALICE).is_none());
    }
    assert!(f.password_works(&ALICE, ALICE_PASSWORD, ALICE_SALT));
    f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
        .unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            Zeroizing::new("Tq7#Lm2!".to_owned()),
            ALICE_SALT,
            &now(),
        ),
        Ok(Kvno::new(2))
    );

    // (16: the fixture's own passwords still pass.)
    let mut c = config();
    c.min_password_chars = 16;
    let mut f = Fixture::with_config(c);
    f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
        .unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            Zeroizing::new("Hollow-Ibis-79S".to_owned()),
            ALICE_SALT,
            &now(),
        ),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::PasswordPolicyRefused);
    f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
        .unwrap();
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            Zeroizing::new("Hollow-Ibis-79Sx".to_owned()),
            ALICE_SALT,
            &now(),
        ),
        Ok(Kvno::new(2))
    );
}

// ---------------------------------------------------------------------------
// The new password never leaves keyd (docs/53 §8, §9; docs/CLEAN-ROOM.md).
// ---------------------------------------------------------------------------

/// docs/53 §9 ("never: the password, the KRB-PRIV / AP-REQ octets, the
/// subkey or the session key"); docs/10 I1, I7, I8: across an open, a
/// completion and an error seal, no audit record, no `Debug` of keyd, of a
/// context or of a reply carries the new password, the subkey or the session
/// key.
#[test]
fn the_new_password_is_never_in_debug_or_audit() {
    let mut f = fixture();
    let issued = issue(EncType::Aes256CtsHmacSha196);
    let secret = "Zephyr-Quartz-Lantern-88";
    let ctx = open_request(&mut f, &issued, &Spec::new(14_001, secret)).unwrap();
    let ctx_debug = format!("{ctx:?}");
    decide_alice(&mut f);
    let reply = f
        .keyd
        .complete_change_password(&LDAP, &ctx.ctx_id, &ALICE, &now())
        .unwrap();
    let refused = open_request(&mut f, &issued, &Spec::new(14_002, "short")).unwrap();
    let refused_reply = f
        .keyd
        .seal_change_password_error(&LDAP, &refused.ctx_id, NonZeroResultCode::SoftError, &now())
        .unwrap();
    let mut texts = vec![
        ctx_debug,
        format!("{reply:?}"),
        format!("{refused_reply:?}"),
        format!("{:?}", f.keyd),
    ];
    texts.extend(f.records().iter().map(|r| format!("{r:?}")));
    for text in &texts {
        assert!(!text.contains(secret), "{text}");
        assert!(!text.contains("Zephyr"), "{text}");
        for bytes in [&SUBKEY, &SESSION_KEY] {
            let hex: String = bytes[..4].iter().map(|b| format!("{b:02x}")).collect();
            assert!(!text.contains(&hex), "{text}");
            assert!(!text.contains(&format!("{}, {}, {}", bytes[0], bytes[1], bytes[2])));
        }
    }
    assert!(f.password_works(&ALICE, secret, ALICE_SALT));
}

/// A ChangePasswordCtxId that keyd never issued is refused by both
/// consuming operations (docs/10 §8: tokens are keyd's, single-use).
#[test]
fn an_unknown_context_is_refused() {
    let mut f = fixture();
    decide_alice(&mut f);
    let unknown = ChangePasswordCtxId::from_bytes([0x5E; 16]);
    assert_eq!(
        f.keyd
            .complete_change_password(&LDAP, &unknown, &ALICE, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::TokenUnknown);
    assert_eq!(
        f.keyd
            .seal_change_password_error(&LDAP, &unknown, NonZeroResultCode::HardError, &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::TokenUnknown);
    assert!(f.password_works(&ALICE, ALICE_PASSWORD, ALICE_SALT));
}

// ---------------------------------------------------------------------------
// Task K3b: keyd's AS issues the ticket — armored only, under the profile.
//
// The test is the KDC (opening the armor, verifying the encrypted challenge,
// asking keyd to issue) and the client (the armor AP-REQ, the encrypted
// challenge, opening the armored reply). The derivations follow RFC 6113
// 5.4.1.1 (the armor key), 5.4.6 (the challenge key, usage 54) and 5.4.3
// (the strengthened reply key); no RFC gives a vector for them (the
// cryptography is krb-crypto's, verified against RFC 3962 / RFC 8009).
// Sources: docs/53 §5.2; docs/questions/Q-915 (A-151); A-142; RFC 4120 2.1,
// 3.1.3, 3.1.5, 5.3, §8.2; RFC 3244 §2.
// ---------------------------------------------------------------------------

/// The subkey of the computer's armor AP-REQ (RFC 6113 5.4.1.1: "MUST be
/// present"), made up for these tests.
const ARMOR_SUBKEY: [u8; 32] = [0x2D; 32];
/// The nonce of alice's inner AS request (RFC 4120 5.4.1), made up.
const AS_NONCE: u32 = 0x4B33_0001;

/// keyd (aes256 only, `config` otherwise) with the change-password service
/// key set, the computer account and its TGT — the armor ticket (D126,
/// docs/48 §3.1) — audit cleared.
fn as_fixture_with(config: KeydConfig) -> (Fixture, Tgt) {
    let mut f = Fixture::with_config(config);
    add_change_password_service(&mut f);
    add_computer(&mut f);
    let tgt = obtain_computer_tgt(&mut f, now(), kt("20261113180000Z"));
    f.keyd.audit_sink_mut().records.clear();
    (f, tgt)
}

fn as_fixture() -> (Fixture, Tgt) {
    as_fixture_with(config())
}

/// One armored conversation: keyd opened the armor of alice's inner AS
/// request for `kadmin/changepw`; `armor_key` is the client's own
/// derivation of the armor key.
struct Conversation {
    armor: FastArmor,
    armor_key: ProtocolKey,
}

/// Open a conversation (the armor authenticator made unique by `cusec`):
/// the inner request names alice and `kadmin/changepw`; the req-checksum
/// covers the outer body's octets (RFC 6113 5.4.2).
fn open_conversation(f: &mut Fixture, tgt: &Tgt, cusec: u32) -> Conversation {
    let ap = ap_req(
        &tgt.parts.ticket,
        armor_authenticator(
            &tgt.session,
            &ArmorAuthSpec::new(now(), cusec, ARMOR_SUBKEY),
        ),
    );
    let armor_key = client_armor_key(&ARMOR_SUBKEY, &tgt.session);
    let (mut inner_body, _) = as_req_body(AS_NONCE);
    inner_body.sname = Some(change_password_service_name());
    let inner = KrbFastReq {
        fast_options: FastOptions::empty(),
        padata: Vec::new(),
        req_body: inner_body,
    };
    let (_, outer) = as_req_body(AS_NONCE);
    let req = armored_req(&ap, &armor_key, &outer, &inner);
    let armor = f
        .keyd
        .open_fast_armor(&KDC, &KRBTGT, &req, &outer, &now())
        .unwrap();
    Conversation { armor, armor_key }
}

/// alice's encrypted challenge in this conversation: PA-ENC-TS-ENC under
/// KRB-FX-CF2(armor_key, long-term key, "clientchallengearmor",
/// "challengelongterm"), key usage 54 (RFC 6113 5.4.6).
fn encrypted_challenge(c: &Conversation) -> PaData {
    let key = krb_crypto::krb_fx_cf2(
        &c.armor_key,
        &alice_key(),
        b"clientchallengearmor",
        b"challengelongterm",
    )
    .unwrap();
    let plain = PaEncTsEnc {
        patimestamp: now(),
        pausec: None,
    }
    .encode()
    .unwrap();
    let cipher = krb_crypto::encrypt(&key, usage(54), &[0x29; 16], &plain).unwrap();
    PaData {
        padata_type: PA_ENCRYPTED_CHALLENGE,
        padata_value: EncryptedData {
            etype: key.enc_type().number(),
            kvno: None,
            cipher,
        }
        .encode()
        .unwrap(),
    }
}

/// keyd verifies alice's encrypted challenge under the conversation's armor.
fn armored_proof(f: &mut Fixture, c: &Conversation) -> AuthnProof {
    f.keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &encrypted_challenge(c),
            Some(c.armor.armor_id),
            &now(),
        )
        .unwrap()
}

/// The template the KDC sends for alice's change-password ticket ending at
/// `endtime` (docs/53 §5.2: no flag, no starttime, no renew-till).
fn change_password_template(endtime: KerberosTime) -> AsTicketTemplate {
    AsTicketTemplate {
        client: ALICE_ID,
        crealm: realm(),
        cname: alice_name(),
        sname: change_password_service_name(),
        starttime: None,
        endtime,
        renew_till: None,
        flags: TicketFlags::empty(),
        session_enctype: EncTypeId::Aes256CtsHmacSha196,
        nonce: AS_NONCE,
    }
}

/// keyd issues for `server` with `template`, under the conversation's armor.
fn issue_armored(
    f: &mut Fixture,
    c: &Conversation,
    proof: &AuthnProof,
    server: &KeyHandle,
    template: &AsTicketTemplate,
) -> Result<AsRepParts, IssueError> {
    f.keyd.issue_as_rep(
        &KDC,
        &ALICE,
        server,
        proof,
        Some(c.armor.armor_id),
        template,
        &now(),
    )
}

/// A fresh conversation, alice's proof in it, and keyd's answer for
/// `server` and `template`.
fn try_issue(
    f: &mut Fixture,
    tgt: &Tgt,
    cusec: u32,
    server: &KeyHandle,
    template: &AsTicketTemplate,
) -> Result<AsRepParts, IssueError> {
    let c = open_conversation(f, tgt, cusec);
    let proof = armored_proof(f, &c);
    issue_armored(f, &c, &proof, server, template)
}

/// The client opens the armored reply: the KrbFastResponse under the armor
/// key (usage 52), the strengthen key, the reply key KRB-FX-CF2(strengthen
/// key, alice's key, "strengthenkey", "replykey"), the EncASRepPart (usage
/// 3). RFC 6113 5.4.3; RFC 4120 5.4.2.
fn open_armored_reply(c: &Conversation, parts: &AsRepParts) -> EncAsRepPart {
    let fast_rep = parts.fast_rep.as_ref().expect("an armored reply");
    let response = KrbFastResponse::decode(&open(&c.armor_key, 52, fast_rep)).unwrap();
    assert_eq!(response.nonce, AS_NONCE);
    let strengthen = key_from(response.strengthen_key.as_ref().expect("strengthen-key"));
    let reply_key =
        krb_crypto::krb_fx_cf2(&strengthen, &alice_key(), b"strengthenkey", b"replykey").unwrap();
    EncAsRepPart::decode(&open(&reply_key, 3, &parts.enc_part)).unwrap()
}

/// alice's change-password ticket as keyd issues it, opened by her.
fn issue_change_password_ticket(f: &mut Fixture, tgt: &Tgt, cusec: u32) -> Issued {
    let c = open_conversation(f, tgt, cusec);
    let proof = armored_proof(f, &c);
    let parts = issue_armored(
        f,
        &c,
        &proof,
        &CHANGE_PASSWORD_SERVICE,
        &change_password_template(at(300)),
    )
    .unwrap();
    let rep = open_armored_reply(&c, &parts);
    Issued {
        enctype: EncType::Aes256CtsHmacSha196,
        ticket: parts.ticket,
        session: key_from(&rep.0.key),
    }
}

/// The full keyd round trip (docs/53 §5.2; Q-915 items 1, 3, 4; RFC 4120
/// 2.1 — INITIAL "issued using the AS protocol"; 3.1.3 — the ticket sealed
/// with "the encryption key extracted from the server principal's record",
/// the server principal's maximum lifetime; 3.1.5 — the client checks sname
/// / srealm and the nonce; 5.3 — usage 2; RFC 6113 5.4.3, 5.4.6; RFC 3244
/// §2): keyd issues alice's armored AS for `kadmin/changepw` under the
/// change-password service's key set — the ticket opens under that key
/// (never krbtgt) with exactly INITIAL | PRE-AUTHENT, authtime now, no
/// starttime, endtime now + 300 s, no renew-till; her armored reply carries
/// the same facts and session key; keyd's record names the
/// ChangePasswordService key set as the server. Then the ticket is what
/// `open_change_password_request` accepts: a change request through it opens
/// with verdict `Acceptable` and INITIAL (RFC 3244 §2 — "checks whether the
/// initial flag is required").
#[test]
fn the_as_issues_the_change_password_ticket_under_its_profile() {
    let (mut f, tgt) = as_fixture();
    let c = open_conversation(&mut f, &tgt, 1);
    let proof = armored_proof(&mut f, &c);
    let parts = issue_armored(
        &mut f,
        &c,
        &proof,
        &CHANGE_PASSWORD_SERVICE,
        &change_password_template(at(CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS.into())),
    )
    .unwrap();
    let record = last(&f);
    assert_eq!(record.op, Operation::IssueAsRep);
    assert_eq!(record.result, AuditOutcome::Success);
    let server = record.secondary.expect("the server key set");
    assert_eq!(server.principal, CHANGE_PASSWORD_SERVICE_ID);
    assert_eq!(server.purpose, KeyPurpose::ChangePasswordService);

    let profile = TicketFlags::INITIAL.union(TicketFlags::PRE_AUTHENT);
    assert_eq!(parts.ticket.realm, realm());
    assert_eq!(parts.ticket.sname, change_password_service_name());
    assert_eq!(parts.ticket.enc_part.etype, 18);
    assert_eq!(parts.ticket.enc_part.kvno, Some(1));
    let service_key = change_password_service_key(EncType::Aes256CtsHmacSha196);
    let ticket = EncTicketPart::decode(&open(&service_key, 2, &parts.ticket.enc_part)).unwrap();
    assert_eq!(ticket.flags, profile);
    assert_eq!(ticket.crealm, realm());
    assert_eq!(ticket.cname, alice_name());
    assert_eq!(ticket.authtime, now());
    assert_eq!(ticket.starttime, None);
    assert_eq!(ticket.endtime, at(300));
    assert_eq!(ticket.renew_till, None);
    assert_eq!(ticket.caddr, None);
    assert_eq!(ticket.authorization_data, None);
    assert!(krb_crypto::decrypt(&krbtgt_key(), usage(2), &parts.ticket.enc_part.cipher).is_err());

    let rep = open_armored_reply(&c, &parts);
    assert_eq!(rep.0.flags, profile);
    assert_eq!(rep.0.srealm, realm());
    assert_eq!(rep.0.sname, change_password_service_name());
    assert_eq!(rep.0.nonce, AS_NONCE);
    assert_eq!(rep.0.endtime, at(300));
    assert_eq!(rep.0.renew_till, None);
    assert_eq!(rep.0.key.keyvalue, ticket.key.keyvalue);

    // The ticket opens a change request (task K3's operation).
    let issued = Issued {
        enctype: EncType::Aes256CtsHmacSha196,
        ticket: parts.ticket.clone(),
        session: key_from(&rep.0.key),
    };
    let ctx = open_request(&mut f, &issued, &Spec::new(15_001, "Garland-Owl-24-Fir")).unwrap();
    assert_eq!(ctx.verdict, ChangePasswordVerdict::Acceptable);
    assert_eq!(ctx.cname, alice_name());
    assert_eq!(ctx.endtime, at(300));
    assert!(ctx.flags.contains(TicketFlags::INITIAL));
}

/// A-142 at keyd's layer (docs/53 §5.2 "second layer"; Q-915 items 1, 3;
/// docs/52 C24 — a lax option the client chooses): an unarmored issuance for
/// the change-password service is not representable — keyd's unarmored
/// server slot takes the krbtgt key set only, so the change-password key set
/// there is `Denied` (`PurposeMismatch`) before the proof is touched; the
/// same holds for an armored proof presented without its armor. The same
/// proofs still issue what their slot allows (an unarmored TGT; the armored
/// change-password ticket with the armor). The classification has no value
/// for an unarmored change-password server.
#[test]
fn an_unarmored_change_password_issuance_is_refused() {
    let (mut f, tgt) = as_fixture();
    assert_eq!(AsServer::of(KeyPurpose::ChangePasswordService, false), None);
    assert_eq!(
        AsServer::of(KeyPurpose::ChangePasswordService, true),
        Some(AsServer::ChangePasswordService)
    );

    // An unarmored (PA-ENC-TIMESTAMP) proof.
    let proof = f
        .keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), now()),
            None,
            &now(),
        )
        .unwrap();
    assert_eq!(
        f.keyd
            .issue_as_rep(
                &KDC,
                &ALICE,
                &CHANGE_PASSWORD_SERVICE,
                &proof,
                None,
                &change_password_template(at(300)),
                &now(),
            )
            .map(|_| ()),
        Err(IssueError::Denied)
    );
    assert_eq!(last(&f).result, AuditOutcome::Denied);
    assert_eq!(last(&f).reason, AuditReason::PurposeMismatch);
    let tgt_parts = f
        .keyd
        .issue_as_rep(&KDC, &ALICE, &KRBTGT, &proof, None, &as_template(), &now())
        .unwrap();
    assert_eq!(tgt_parts.ticket.sname, krbtgt_name());

    // An armored proof, the armor withheld.
    let c = open_conversation(&mut f, &tgt, 2);
    let proof = armored_proof(&mut f, &c);
    assert_eq!(
        f.keyd
            .issue_as_rep(
                &KDC,
                &ALICE,
                &CHANGE_PASSWORD_SERVICE,
                &proof,
                None,
                &change_password_template(at(300)),
                &now(),
            )
            .map(|_| ()),
        Err(IssueError::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::PurposeMismatch);
    assert!(issue_armored(
        &mut f,
        &c,
        &proof,
        &CHANGE_PASSWORD_SERVICE,
        &change_password_template(at(300)),
    )
    .is_ok());
}

/// keyd enforces the profile whatever the KDC asks (docs/53 §5.2: "lifetime
/// ≤ 300 s, no renewable, forwardable, proxiable, postdated"; Q-915 item 4;
/// RFC 4120 3.1.3 — the server principal's maximum lifetime, flags only "if
/// the policy of the local realm allows", 5.3 — starttime absent ⇒
/// authtime): under a realm policy that allows forwardable, proxiable and
/// renewable tickets and a one-minute minimum, a change-password template
/// ending beyond authtime + 300 s, asking any flag, carrying a starttime or
/// a renew-till is refused (`BadTemplate`) — never issued longer or with
/// the flag; a template naming another service with the change-password key
/// set, or `kadmin/changepw` with the krbtgt key set, is refused
/// (`TemplateNames`). Templates within the profile — 120 s and 300 s — are
/// issued, ending where asked.
#[test]
fn keyd_enforces_the_profile_whatever_the_kdc_asks() {
    let mut generous = config();
    generous.ticket_policy.allowed_flags = generous
        .ticket_policy
        .allowed_flags
        .union(TicketFlags::FORWARDABLE)
        .union(TicketFlags::PROXIABLE);
    generous.ticket_policy.min_lifetime_secs = 60;
    let (mut f, tgt) = as_fixture_with(generous);

    let base = change_password_template(at(300));
    let with = |change: &dyn Fn(&mut AsTicketTemplate)| {
        let mut template = base.clone();
        change(&mut template);
        template
    };
    let cases: Vec<(&str, KeyHandle, AsTicketTemplate, AuditReason)> = vec![
        (
            "301 s",
            CHANGE_PASSWORD_SERVICE,
            change_password_template(at(301)),
            AuditReason::TemplateTimes,
        ),
        (
            "one hour",
            CHANGE_PASSWORD_SERVICE,
            change_password_template(at(3_600)),
            AuditReason::TemplateTimes,
        ),
        (
            "forwardable",
            CHANGE_PASSWORD_SERVICE,
            with(&|t| t.flags = TicketFlags::FORWARDABLE),
            AuditReason::TemplateFlags,
        ),
        (
            "proxiable",
            CHANGE_PASSWORD_SERVICE,
            with(&|t| t.flags = TicketFlags::PROXIABLE),
            AuditReason::TemplateFlags,
        ),
        (
            "renewable",
            CHANGE_PASSWORD_SERVICE,
            with(&|t| {
                t.flags = TicketFlags::RENEWABLE;
                t.renew_till = Some(at(600));
            }),
            AuditReason::TemplateFlags,
        ),
        (
            "initial asked",
            CHANGE_PASSWORD_SERVICE,
            with(&|t| t.flags = TicketFlags::INITIAL),
            AuditReason::TemplateFlags,
        ),
        (
            "renew-till",
            CHANGE_PASSWORD_SERVICE,
            with(&|t| t.renew_till = Some(at(300))),
            AuditReason::TemplateTimes,
        ),
        (
            "starttime",
            CHANGE_PASSWORD_SERVICE,
            with(&|t| t.starttime = Some(now())),
            AuditReason::TemplateTimes,
        ),
        (
            "TGS name",
            CHANGE_PASSWORD_SERVICE,
            with(&|t| t.sname = krbtgt_name()),
            AuditReason::TemplateNames,
        ),
        (
            "another service",
            CHANGE_PASSWORD_SERVICE,
            with(&|t| t.sname = service_name()),
            AuditReason::TemplateNames,
        ),
        (
            "kadmin/changepw under krbtgt",
            KRBTGT,
            base.clone(),
            AuditReason::TemplateNames,
        ),
    ];
    for (i, (what, server, template, reason)) in cases.into_iter().enumerate() {
        let cusec = 100 + i as u32;
        assert_eq!(
            try_issue(&mut f, &tgt, cusec, &server, &template).map(|_| ()),
            Err(IssueError::BadTemplate),
            "{what}"
        );
        assert_eq!(last(&f).result, AuditOutcome::BadTemplate, "{what}");
        assert_eq!(last(&f).reason, reason, "{what}");
    }

    let service_key = change_password_service_key(EncType::Aes256CtsHmacSha196);
    for (cusec, end) in [(200, at(120)), (201, at(300))] {
        let parts = try_issue(
            &mut f,
            &tgt,
            cusec,
            &CHANGE_PASSWORD_SERVICE,
            &change_password_template(end),
        )
        .unwrap();
        let ticket = EncTicketPart::decode(&open(&service_key, 2, &parts.ticket.enc_part)).unwrap();
        assert_eq!(ticket.endtime, end);
        assert_eq!(
            ticket.flags,
            TicketFlags::INITIAL.union(TicketFlags::PRE_AUTHENT)
        );
    }
}

/// The change-password ticket is not a TGT (RFC 4120 3.3.2: the TGS takes a
/// ticket "for the TGS"; 5.3: a ticket is sealed in "the server's secret
/// key"; docs/53 §5.2): presented to `open_and_verify_tgt` as issued it is
/// `NotLocalTgt`; with its sname rewritten to `krbtgt/REALM` it does not
/// open under the krbtgt key (`IntegrityFailure`); the change-password key
/// set is never the key of a TGT step (`PurposeMismatch`); and as the armor
/// of a FAST conversation it is `NotLocalTgt` too.
#[test]
fn the_change_password_ticket_is_no_tgt() {
    let (mut f, tgt) = as_fixture();
    let issued = issue_change_password_ticket(&mut f, &tgt, 1);
    let (_, body) = tgs_req_body(0x5151_0001, service_name());
    let tgs_ap_req = |ticket: &Ticket, cusec: u32| {
        ap_req(
            ticket,
            authenticator(
                &issued.session,
                &AuthenticatorSpec::new(now(), cusec, &body),
            ),
        )
    };

    let opened = f.keyd.open_and_verify_tgt(
        &KDC,
        &KRBTGT,
        &tgs_ap_req(&issued.ticket, 11),
        &body,
        None,
        &now(),
    );
    assert_eq!(opened.map(|_| ()), Err(AuthnError::Denied));
    assert_eq!(last(&f).reason, AuditReason::NotLocalTgt);

    let mut renamed = issued.ticket.clone();
    renamed.sname = krbtgt_name();
    let opened = f.keyd.open_and_verify_tgt(
        &KDC,
        &KRBTGT,
        &tgs_ap_req(&renamed, 12),
        &body,
        None,
        &now(),
    );
    assert_eq!(opened.map(|_| ()), Err(AuthnError::Denied));
    assert_eq!(last(&f).reason, AuditReason::IntegrityFailure);

    let opened = f.keyd.open_and_verify_tgt(
        &KDC,
        &CHANGE_PASSWORD_SERVICE,
        &tgs_ap_req(&issued.ticket, 13),
        &body,
        None,
        &now(),
    );
    assert_eq!(opened.map(|_| ()), Err(AuthnError::Denied));
    assert_eq!(last(&f).reason, AuditReason::PurposeMismatch);

    // As a FAST armor (RFC 6113 5.4.1.1: the armor ticket is a TGT).
    let armor_ap = ap_req(
        &issued.ticket,
        armor_authenticator(
            &issued.session,
            &ArmorAuthSpec {
                crealm: realm(),
                cname: alice_name(),
                ..ArmorAuthSpec::new(now(), 14, ARMOR_SUBKEY)
            },
        ),
    );
    let armor_key = client_armor_key(&ARMOR_SUBKEY, &issued.session);
    let (_, outer) = as_req_body(AS_NONCE);
    let req = armored_req(&armor_ap, &armor_key, &outer, &fast_req(AS_NONCE));
    assert_eq!(
        f.keyd
            .open_fast_armor(&KDC, &KRBTGT, &req, &outer, &now())
            .map(|_| ()),
        Err(AuthnError::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::NotLocalTgt);
}

/// Q-915 item 5 (RFC 4120 3.1.3: below the site minimum a ticket is
/// KDC_ERR_NEVER_VALID; §8.2: the default minimum, 5 minutes, equals the
/// change-password maximum): keyd refuses to start with a realm minimum
/// ticket lifetime above 300 s — every change-password AS would fail — and
/// starts with exactly 300 s.
#[test]
fn keyd_refuses_to_start_with_a_minimum_above_the_change_password_maximum() {
    let start = |minimum: u32| {
        let mut c = config();
        c.ticket_policy.min_lifetime_secs = minimum;
        Keyd::with_entropy(
            c,
            InMemoryKeyStore::new_insecure_development_allowing_krbtgt(8),
            CollectingAudit::default(),
            TestEntropy::default(),
            &keyd_started(),
        )
        .map(|_| ())
    };
    assert_eq!(
        start(CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS + 1),
        Err(ConfigError::ChangePasswordTicketLifetime)
    );
    assert_eq!(start(3_600), Err(ConfigError::ChangePasswordTicketLifetime));
    assert_eq!(start(CHANGE_PASSWORD_TICKET_MAX_LIFETIME_SECS), Ok(()));
}

// ---------------------------------------------------------------------------
// Task F3: rotating the change-password service's key set through a decision
// (owner decision A-126 on docs/questions/Q-660 item 11; Q-978). Sources:
// docs/10 §1 ("keyd holds current + previous; sealing always under the
// current kvno"), §5b step 5 (a ticket is opened under the version its kvno
// names), §6a, §7 (`rotate_key`: "the current goes down to previous";
// `retire_kvno`); RFC 4120 3.1.3 (the ticket sealed with "the encryption
// key extracted from the server principal's record"); docs/52 §4.2. The
// rotated key's octets are made up for this test.
// ---------------------------------------------------------------------------

/// The change-password service key the rotation draws (scripted entropy).
const ROTATED_CHANGE_PASSWORD_KEY: [u8; 32] = [0xE7; 32];

/// A-126 / Q-978: the change-password service's key set rotates **only**
/// through a decision dird registered for a dual-controlled key request —
/// without one `rotate_key` is refused (`NoDecision`) and nothing changes;
/// with one only Role::Admin runs it (Ldap, Directory and the KDC are
/// refused at the capability table, the decision unconsumed). The rotation
/// draws a new key under kvno 2; the AS then seals new change-password
/// tickets under kvno 2 and the new key; a ticket issued before (kvno 1)
/// still opens a change request — the previous version is retained (docs/10
/// §1) — until kvno 1 is retired, also through a decision.
#[test]
fn the_change_password_key_rotates_through_a_decision_only() {
    let (mut f, tgt) = as_fixture();
    let old = issue_change_password_ticket(&mut f, &tgt, 31);
    assert_eq!(old.ticket.enc_part.kvno, Some(1));

    // No decision: refused at the authorization step, nothing rotated.
    assert_eq!(
        f.keyd.rotate_key(&ADMIN, next_decision_id(), &now()),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::NoDecision);
    let unchanged = issue_change_password_ticket(&mut f, &tgt, 32);
    assert_eq!(unchanged.ticket.enc_part.kvno, Some(1));

    // dird's decision for the approved request (the dual-control pair).
    let id = f
        .decide(
            DecidedOperation::RotateKey {
                handle: CHANGE_PASSWORD_SERVICE,
            },
            &now(),
        )
        .unwrap();
    for caller in [LDAP, DIRECTORY, KDC] {
        assert_eq!(f.keyd.rotate_key(&caller, id, &now()), Err(Error::Denied));
        assert_eq!(last(&f).reason, AuditReason::RoleNotPermitted);
    }
    f.entropy.push(&ROTATED_CHANGE_PASSWORD_KEY);
    assert_eq!(f.keyd.rotate_key(&ADMIN, id, &now()), Ok(Kvno::new(2)));
    let rotated = last(&f);
    assert_eq!(rotated.op, Operation::RotateKey);
    assert_eq!(rotated.result, AuditOutcome::Success);
    assert_eq!(rotated.principal, Some(CHANGE_PASSWORD_SERVICE_ID));
    assert_eq!(rotated.purpose, Some(KeyPurpose::ChangePasswordService));
    assert_eq!(rotated.kvno, Some(Kvno::new(2)));
    assert_eq!(rotated.decision, Some(id));
    assert_eq!(rotated.approvers, Some([APPROVER_1, APPROVER_2]));

    // New tickets: kvno 2, under the new key only.
    let new = issue_change_password_ticket(&mut f, &tgt, 33);
    assert_eq!(new.ticket.enc_part.kvno, Some(2));
    let new_key = key(EncType::Aes256CtsHmacSha196, &ROTATED_CHANGE_PASSWORD_KEY);
    assert!(krb_crypto::decrypt(&new_key, usage(2), &new.ticket.enc_part.cipher).is_ok());
    let old_key = change_password_service_key(EncType::Aes256CtsHmacSha196);
    assert!(krb_crypto::decrypt(&old_key, usage(2), &new.ticket.enc_part.cipher).is_err());

    // Both open a change request: the old one under the retained kvno 1.
    for (issued, cusec, password) in [
        (&new, 15_301, "Copper-Wren-58-Ash"),
        (&old, 15_302, "Velvet-Kite-31-Elm"),
    ] {
        let ctx = open_request(&mut f, issued, &Spec::new(cusec, password)).unwrap();
        assert_eq!(ctx.verdict, ChangePasswordVerdict::Acceptable);
    }

    // Retiring kvno 1 (a decision too): the old ticket no longer opens.
    let retire = f
        .decide(
            DecidedOperation::RetireKvno {
                handle: CHANGE_PASSWORD_SERVICE,
                kvno: Kvno::new(1),
            },
            &now(),
        )
        .unwrap();
    assert_eq!(f.keyd.retire_kvno(&ADMIN, retire, &now()), Ok(()));
    assert_eq!(
        open_request(&mut f, &old, &Spec::new(15_303, "Marble-Fox-47-Oak")).map(|_| ()),
        Err(AuthnError::Denied)
    );
    let ctx = open_request(&mut f, &new, &Spec::new(15_304, "Marble-Fox-47-Oak")).unwrap();
    assert_eq!(ctx.verdict, ChangePasswordVerdict::Acceptable);
}
