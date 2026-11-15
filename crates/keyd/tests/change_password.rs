//! The RFC 3244 change-password operations of keyd (task K3):
//! `open_change_password_request`, `complete_change_password`,
//! `seal_change_password_error` — Role::Ldap (dird) only.
//!
//! The tests play three parts: the KDC (the AS issuance of a
//! `kadmin/changepw` ticket is task K5, so the tests seal the ticket
//! themselves under the change-password service key they scripted into
//! `create_key`), the Kerberos client (the AP-REQ with a subkey and a
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
//! Sources: RFC 3244 §2 (pinned, read in full); RFC 4120 §2.1, §3.2.3,
//! §3.2.4, §3.2.5, §3.5.1, §3.5.2, §5.5.1, §5.5.2, §5.7.1, §7.1, §7.5.1
//! (pinned); RFC 3962 §7; RFC 8009 §7; [MS-SAMR] 3.1.1.7.2 (as applied by
//! crate admin-password-policy); docs/53 §2.4, §4.3-§4.5, §5.3-§5.8, §6, §8,
//! §10; docs/questions/Q-601, Q-603, Q-604, Q-605, Q-620, Q-662.

mod common;

use common::*;
use keyd::{
    AuditOutcome, AuditReason, AuthnError, ChangePasswordContext, ChangePasswordCtxId,
    ChangePasswordVerdict, DecidedOperation, EncTypeId, Error, HostAddr, KeyHandle, KeyPurpose,
    Kvno, Operation, SealedReply, SetSecretTarget, ADDRESS_TYPE_DIRECTIONAL,
};
use krb_crypto::{EncType, ProtocolKey};
use krb_proto::constants::DOMAIN_X500_COMPRESS;
use krb_proto::{
    ApOptions, ApReq, Authenticator, ChangePasswdData, Checksum, EncApRepPart, EncKrbPrivPart,
    EncTicketPart, EncryptedData, EncryptionKey, HostAddress, KerberosTime, KeyValue, KrbPriv,
    Microseconds, NewPasswd, NonZeroResultCode, PrincipalName, ResultCode, Ticket, TicketFlags,
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
        let new = format!("her new passphrase {i}");
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
    let mut spec = Spec::new(2_001, "an address-bound phrase");
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
    let mut spec = Spec::new(2_002, "another bound phrase");
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
    let ctx = open_request(&mut f, &issued, &Spec::new(3_001, "a phrase of hers")).unwrap();

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
    let ctx = open_request(&mut f, &issued, &Spec::new(4_001, "her chosen phrase")).unwrap();
    decide_alice(&mut f);
    assert_eq!(
        f.keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            Zeroizing::new("an admind-chosen phrase".to_owned()),
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
    assert!(f.password_works(&ALICE, "her chosen phrase", ALICE_SALT));
    assert!(!f.password_works(&ALICE, "an admind-chosen phrase", ALICE_SALT));
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
    let ctx = open_request(&mut f, &issued, &Spec::new(5_001, "a long enough phrase")).unwrap();
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

/// [MS-SAMR] 3.1.1.7.2 items 2, 3.2.1, 3.2.2 (keyd's one policy, docs/53
/// §6); RFC 3244 §2; Q-603 item 7: a new password that is too short, that
/// contains the account name, that is over 256 UTF-16 units, or that is not
/// UTF-8 opens with verdict `PasswordRefused` — before dird writes anything
/// — and its reply is SOFTERROR with **no** result string; the audit record
/// says which code, never which rule.
#[test]
fn a_policy_violating_password_is_softerror_without_a_reason() {
    let mut f = fixture();
    let issued = issue(EncType::Aes256CtsHmacSha196);
    let too_long = "p".repeat(257);
    let mut cases: Vec<Vec<u8>> = vec![
        change("short"),
        change("xx-alice-xx-yy-zz"),
        change("xx-ALICE-xx-yy-zz"),
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
        let mut spec = Spec::new(next(), "a long enough phrase");
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
    let (ap_req, krb_priv) = request(&issued, &Spec::new(next(), "a long enough phrase"));
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
    let spec = Spec::new(9_001, "a long enough phrase");
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
    let (_, other_priv) = request(&issued, &Spec::new(9_001, "another phrase entirely"));
    assert_eq!(
        open(&mut f, &other_priv).map(|c| c.verdict),
        Err(AuthnError::Replay)
    );
}

/// docs/53 §4.5, §5.3, §8 (cross-service / confused deputy; R2's pattern):
/// the change-password service key set is opened by
/// `open_change_password_request` only — the two other service-ticket
/// verifications name other purposes of the principal (no such key set),
/// the KDC's issuance and every secret operation refuse its purpose, no
/// rotation can be decided for it — and that operation opens no other key
/// set: a ticket for another service under the request's principal fails the
/// A-19 binding, and the other services' principals have no
/// ChangePasswordService key set.
#[test]
fn the_change_password_key_is_opened_by_its_operation_only() {
    let mut f = fixture();
    add_ldap_service(&mut f);
    let issued = issue(EncType::Aes256CtsHmacSha196);
    let (ap_req, _) = request(&issued, &Spec::new(10_001, "a long enough phrase"));

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
            Zeroizing::new("a chosen service phrase".to_owned()),
            "salt",
            &now(),
        ),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::PurposeMismatch);
    assert_eq!(
        f.decide(
            DecidedOperation::RotateKey {
                handle: CHANGE_PASSWORD_SERVICE
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
    let (ldap_ap_req, ldap_priv) = request(&ldap, &Spec::new(10_002, "a long enough phrase"));
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
    let (ap_req, krb_priv) = request(&issued, &Spec::new(11_001, "a long enough phrase"));
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

    let ctx = open_request(&mut f, &issued, &Spec::new(12_001, "first of the phrases")).unwrap();
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

    let ctx = open_request(&mut f, &issued, &Spec::new(12_002, "second of the phrases")).unwrap();
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
    assert!(f.password_works(&ALICE, "second of the phrases", ALICE_SALT));

    // Expiry: the context lives `token_lifetime_secs` (30 s by default); the
    // decision (registered later, live 30 s) is still live when it is
    // presented.
    let ctx = open_request(&mut f, &issued, &Spec::new(12_003, "third of the phrases")).unwrap();
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
    assert!(f.password_works(&ALICE, "second of the phrases", ALICE_SALT));
}

/// docs/53 §5.5 (`max_change_password_contexts`); AGENTS.md §6 (bounded):
/// a full context table refuses a new request (`Unavailable`), never
/// evicting a live one.
#[test]
fn the_context_table_is_bounded() {
    let mut c = config();
    c.max_change_password_contexts = 1;
    let mut f = Fixture::with_config(c);
    add_change_password_service(&mut f);
    let issued = issue(EncType::Aes256CtsHmacSha196);
    let first = open_request(&mut f, &issued, &Spec::new(13_001, "a long enough phrase")).unwrap();
    assert_eq!(
        open_request(&mut f, &issued, &Spec::new(13_002, "a long enough phrase"))
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

/// docs/53 §6.1 (R53-10; Q-605 item 1): the policy is enforced in keyd's
/// install path — so admind's `set_secret` on a live decision is refused a
/// short password or one containing the account name, the decision is
/// consumed and nothing is installed; the floor is the configured
/// `min_password_chars` (12 by default, P-24), and a larger one applies.
#[test]
fn set_secret_obeys_the_same_policy() {
    let mut f = Fixture::new();
    for weak in ["short-1", "my-alice-phrase-x", "elevenchars"] {
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
            Zeroizing::new("twelve chars".to_owned()),
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
            Zeroizing::new("fifteen-chars-x".to_owned()),
            ALICE_SALT,
            &now(),
        ),
        Err(Error::Denied)
    );
    assert_eq!(last(&f).reason, AuditReason::PasswordPolicyRefused);
}

// ---------------------------------------------------------------------------
// The new password never leaves keyd (docs/53 §8, §9; AGENTS.md §6).
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
