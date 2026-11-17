//! Invariants I1 (no long-term key bytes out), I6 (uniform errors,
//! constant-time comparison facilities), I7 (plaintext taken in zeroizing
//! containers) and I8 (every operation audited, no secret in audit), plus
//! redacted Debug output. Source: docs/10 §9, §10, §12; docs/09 א.1, א.5;
//! docs/52 §4 (A-102: the decision operations); AGENTS.md §6. All values
//! are constructed for these tests.

mod common;

use common::*;
use keyd::{
    AccountKind, ArmorId, AsRepParts, AsServerKeySet, AsTicketTemplate, AttestedNameResolution,
    AuditOutcome, AuthnError, AuthnProof, CallerId, CtxId, DecidedOperation, DecisionId,
    DestructionPage, Error, IssueError, KeyHandle, Kvno, Operation, PrincipalBinding, PrincipalId,
    ServiceContext, SetSecretTarget, TgsFastRequest, TgsRepParts, TgsTicketTemplate, TgtContext,
};
use krb_proto::{ApReq, KerberosTime, PaData};
use zeroize::Zeroizing;

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

/// I1 at the type level: every public operation's signature, pinned. None
/// returns key material: only kvnos, unit, one-time tokens with non-secret
/// facts, and sealed EncryptedData. Changing any return type breaks this
/// test and forces a review. There is no read-key operation in any role.
/// Source: docs/10 §12 I1 ("checking the output types"), §7; docs/09 א.5
/// (export_key / get_key / read_secret / generic crypto absent).
#[test]
// The pinned fn-pointer types are long by nature; aliases would hide them.
#[allow(clippy::type_complexity)]
fn operation_signatures_return_no_key_material() {
    type K = TestKeyd;
    // docs/48 §2.3 (task T2): both AS operations take the FAST armor id —
    // a one-time token, not key material — and AsRepParts gains only the
    // sealed `fast_rep`.
    let _: fn(
        &mut K,
        &CallerId,
        &KeyHandle,
        &PaData,
        Option<ArmorId>,
        &KerberosTime,
    ) -> Result<AuthnProof, AuthnError> = K::verify_preauth;
    // Task PN11b (docs/questions/Q-1067): the client and the
    // change-password server reach keyd only as their resolutions; the
    // krbtgt of a TGT keeps its handle (`AsServerKeySet::LocalTgt`).
    let _: fn(
        &mut K,
        &CallerId,
        &AttestedNameResolution,
        AsServerKeySet<'_>,
        &AuthnProof,
        Option<ArmorId>,
        &AsTicketTemplate,
        &KerberosTime,
    ) -> Result<AsRepParts, IssueError> = K::issue_as_rep;
    // docs/48 §2.3 (task T3): the TGS opening takes the FAST part of an
    // armored request (request data, no key) and TgtContext gains only the
    // decrypted KrbFastReq; TgsRepParts gains only the sealed `fast_rep`.
    let _: fn(
        &mut K,
        &CallerId,
        &KeyHandle,
        &ApReq,
        &[u8],
        Option<TgsFastRequest<'_>>,
        &KerberosTime,
    ) -> Result<TgtContext, AuthnError> = K::open_and_verify_tgt;
    let _: fn(
        &mut K,
        &CallerId,
        &AttestedNameResolution,
        &CtxId,
        &TgsTicketTemplate,
        &KerberosTime,
    ) -> Result<TgsRepParts, IssueError> = K::issue_tgs_rep;
    let _: fn(
        &mut K,
        &CallerId,
        &KeyHandle,
        &PrincipalBinding,
        &KerberosTime,
    ) -> Result<Kvno, Error> = K::create_key;
    // A-102 (docs/52 §4.2): the Admin operations that run a decision take
    // only its id — never a handle, kvno or approval.
    let _: fn(&mut K, &CallerId, DecisionId, &KerberosTime) -> Result<Kvno, Error> = K::rotate_key;
    let _: fn(&mut K, &CallerId, DecisionId, &KerberosTime) -> Result<Kvno, Error> =
        K::rotate_krbtgt;
    let _: fn(&mut K, &CallerId, DecisionId, &KerberosTime) -> Result<(), Error> = K::retire_kvno;
    // A-35 (docs/questions/Q-115): destroy_key_set returns nothing.
    let _: fn(&mut K, &CallerId, DecisionId, &KerberosTime) -> Result<(), Error> =
        K::destroy_key_set;
    // A-102: registering a decision, sealing the ceremony and listing the
    // pending destructions return nothing secret (unit, or ids).
    let _: fn(
        &mut K,
        &CallerId,
        DecisionId,
        &DecidedOperation,
        &[PrincipalId],
        u32,
        &KerberosTime,
    ) -> Result<(), Error> = K::register_decision;
    let _: fn(&mut K, &CallerId, &KerberosTime) -> Result<(), Error> = K::seal_ceremony;
    let _: fn(
        &mut K,
        &CallerId,
        Option<DecisionId>,
        &KerberosTime,
    ) -> Result<DestructionPage, Error> = K::list_destroy_decisions;
    let _: fn(
        &mut K,
        &CallerId,
        AccountKind,
        &[SetSecretTarget],
        u32,
        &KerberosTime,
    ) -> Result<(), Error> = K::grant_set_secret;
    // I7: plaintext enters as Zeroizing<String> BY VALUE — keyd owns it and
    // it is wiped when the call returns (docs/10 §12 I7). A-35: keyd chooses
    // the kvno and returns it (not secret).
    let _: fn(
        &mut K,
        &CallerId,
        &KeyHandle,
        &PrincipalBinding,
        Zeroizing<String>,
        &str,
        &KerberosTime,
    ) -> Result<Kvno, Error> = K::set_secret;
    let _: fn(
        &mut K,
        &CallerId,
        &KeyHandle,
        Zeroizing<String>,
        &KerberosTime,
    ) -> Result<(), Error> = K::verify_secret;
    // docs/49 §3.3, A-46 (task L6a): the service AP-REQ goes in as octets;
    // out come non-secret facts and a one-time token — no key, no session
    // key. R2: the service key set is named by its principal; its purpose
    // is the operation's binding's. Q-523: the operation-bound verification
    // returns facts only — no context token either.
    let _: fn(
        &mut K,
        &CallerId,
        &keyd::PrincipalId,
        &[u8],
        &KerberosTime,
    ) -> Result<ServiceContext, AuthnError> = K::open_and_verify_service_ticket;
    let _: fn(
        &mut K,
        &CallerId,
        &keyd::PrincipalId,
        &keyd::OperationDigest,
        &[u8],
        &KerberosTime,
    ) -> Result<keyd::OperationTicket, AuthnError> = K::verify_operation_ticket;
}

/// I1 at the value level: nothing keyd returns contains a long-term key or
/// the session key in the clear. Source: docs/10 §12 I1; docs/09 א.4.
#[test]
fn returned_values_contain_no_key_octets() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let ctx = open_tgt(&mut f, &tgt, 60, 60);
    let tgs = f
        .keyd
        .issue_tgs(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(60), &now())
        .unwrap();
    let service_session = krb_proto::EncTgsRepPart::decode(&open(&tgt.session, 8, &tgs.enc_part))
        .unwrap()
        .0
        .key;

    let alice = alice_key();
    let secrets: Vec<&[u8]> = vec![
        &KRBTGT_KEY,
        &SERVICE_KEY,
        alice.octets(),
        tgt.rep.0.key.keyvalue.as_bytes(),
        service_session.keyvalue.as_bytes(),
    ];
    let mut outputs: Vec<Vec<u8>> = vec![
        tgt.parts.ticket.encode().unwrap(),
        tgt.parts.enc_part.encode().unwrap(),
        tgs.ticket.encode().unwrap(),
        tgs.enc_part.encode().unwrap(),
    ];
    outputs.push(format!("{ctx:?}").into_bytes());
    for out in &outputs {
        for secret in &secrets {
            assert!(!contains_bytes(out, secret));
        }
    }
}

/// I8: every operation — success or failure, any role — emits exactly one
/// audit record naming the operation and the caller. Source: docs/10 §3
/// ("every call is recorded"), §10, §12 I8.
#[test]
fn every_operation_emits_exactly_one_audit_record() {
    let mut f = Fixture::new();
    let n = now();
    let mut expected: Vec<(Operation, u32, bool)> = Vec::new();
    let mut check = |f: &Fixture, op: Operation, caller: &CallerId, ok: bool| {
        expected.push((op, caller.uid, ok));
        assert_eq!(f.records().len(), expected.len(), "after {op:?}");
        let last = f.records().last().unwrap();
        assert_eq!(last.op, op);
        assert_eq!(last.caller_uid, caller.uid);
        assert_eq!(last.result == AuditOutcome::Success, ok, "{op:?}");
    };

    let pa = pa_enc_timestamp(&alice_key(), Some(1), n);
    let proof = f.keyd.verify_preauth(&KDC, &ALICE, &pa, None, &n).unwrap();
    check(&f, Operation::VerifyPreauth, &KDC, true);
    let _ = f.keyd.verify_preauth(&DIRECTORY, &ALICE, &pa, None, &n);
    check(&f, Operation::VerifyPreauth, &DIRECTORY, false);
    let parts = f
        .keyd
        .issue_as(&KDC, &ALICE, &KRBTGT, &proof, None, &as_template(), &n)
        .unwrap();
    check(&f, Operation::IssueAsRep, &KDC, true);
    let _ = f
        .keyd
        .issue_as(&KDC, &ALICE, &KRBTGT, &proof, None, &as_template(), &n);
    check(&f, Operation::IssueAsRep, &KDC, false);

    let rep = krb_proto::EncAsRepPart::decode(&open(&alice_key(), 3, &parts.enc_part)).unwrap();
    let session = key_from(&rep.0.key);
    let (_, body) = tgs_req_body(70, service_name());
    let req = ap_req(
        &parts.ticket,
        authenticator(&session, &AuthenticatorSpec::new(n, 70, &body)),
    );
    let ctx = f
        .keyd
        .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, None, &n)
        .unwrap();
    check(&f, Operation::OpenAndVerifyTgt, &KDC, true);
    let _ = f
        .keyd
        .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, None, &n);
    check(&f, Operation::OpenAndVerifyTgt, &KDC, false);
    f.keyd
        .issue_tgs(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(70), &n)
        .unwrap();
    check(&f, Operation::IssueTgsRep, &KDC, true);
    let _ = f
        .keyd
        .issue_tgs(&ADMIN, &SERVICE, &ctx.ctx_id, &tgs_template(70), &n);
    check(&f, Operation::IssueTgsRep, &ADMIN, false);

    // The ceremony's grant (task A15a; Admin before the seal, A-102): one
    // record either way.
    let _ = f.grant_as(&DIRECTORY, &ALICE, &alice_binding(), ALICE_SALT, &n);
    check(&f, Operation::GrantSetSecret, &DIRECTORY, false);
    let dave = KeyHandle::new(
        PrincipalId::from_bytes([0xDA; 16]),
        keyd::KeyPurpose::PrincipalLongterm,
    );
    f.grant_as(&ADMIN, &dave, &alice_binding(), "EXAMPLE.ORGdave", &n)
        .unwrap();
    check(&f, Operation::GrantSetSecret, &ADMIN, true);
    // A decision (A-102): one record either way.
    f.grant(&ALICE, &alice_binding(), ALICE_SALT, &n).unwrap();
    check(&f, Operation::RegisterDecision, &LDAP, true);
    let refused = DecidedOperation::DestroyKeySet {
        principal: ALICE_ID,
    };
    let _ = f
        .keyd
        .register_decision(&ADMIN, next_decision_id(), &refused, &[], 60, &n);
    check(&f, Operation::RegisterDecision, &ADMIN, false);
    f.keyd
        .set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            z("Hazel-Tundra-82-Lynx"),
            ALICE_SALT,
            &n,
        )
        .unwrap();
    check(&f, Operation::SetSecret, &DIRECTORY, true);
    // No role holds verify_secret (A-102, docs/52 R4): one record, refused.
    let _ = f
        .keyd
        .verify_secret(&DIRECTORY, &ALICE, z("Hazel-Tundra-82-Lynx"), &n);
    check(&f, Operation::VerifySecret, &DIRECTORY, false);

    let h = KeyHandle::new(
        PrincipalId::from_bytes([0x77; 16]),
        keyd::KeyPurpose::Service,
    );
    let h_binding = bound(krb_proto::PrincipalName {
        name_type: krb_proto::constants::KRB_NT_PRINCIPAL,
        name_string: vec![kstr("svc-77")],
    });
    f.keyd.create_key(&ADMIN, &h, &h_binding, &n).unwrap();
    check(&f, Operation::CreateKey, &ADMIN, true);
    // A-102: each Admin key operation runs a decision (its registration is
    // one record, the execution another).
    let rotation = f
        .decide(DecidedOperation::RotateKey { handle: h }, &n)
        .unwrap();
    check(&f, Operation::RegisterDecision, &LDAP, true);
    f.keyd.rotate_key(&ADMIN, rotation, &n).unwrap();
    check(&f, Operation::RotateKey, &ADMIN, true);
    let retirement = f
        .decide(
            DecidedOperation::RetireKvno {
                handle: h,
                kvno: Kvno::new(1),
            },
            &n,
        )
        .unwrap();
    check(&f, Operation::RegisterDecision, &LDAP, true);
    f.keyd.retire_kvno(&ADMIN, retirement, &n).unwrap();
    check(&f, Operation::RetireKvno, &ADMIN, true);
    let krbtgt_rotation = f
        .decide(DecidedOperation::RotateKrbtgt { krbtgt: KRBTGT }, &n)
        .unwrap();
    check(&f, Operation::RegisterDecision, &LDAP, true);
    let _ = f.keyd.rotate_krbtgt(&KDC, krbtgt_rotation, &n);
    check(&f, Operation::RotateKrbtgt, &KDC, false);
    f.keyd.rotate_krbtgt(&ADMIN, krbtgt_rotation, &n).unwrap();
    check(&f, Operation::RotateKrbtgt, &ADMIN, true);
    // destroy_key_set (A-35, docs/questions/Q-115): one record either way.
    let destroy = f
        .decide(
            DecidedOperation::DestroyKeySet {
                principal: h.principal,
            },
            &n,
        )
        .unwrap();
    check(&f, Operation::RegisterDecision, &LDAP, true);
    let _ = f.keyd.destroy_key_set(&DIRECTORY, destroy, &n);
    check(&f, Operation::DestroyKeySet, &DIRECTORY, false);
    f.keyd.list_destroy_decisions(&ADMIN, None, &n).unwrap();
    check(&f, Operation::ListDestroyDecisions, &ADMIN, true);
    let _ = f.keyd.list_destroy_decisions(&KDC, None, &n);
    check(&f, Operation::ListDestroyDecisions, &KDC, false);
    f.keyd.destroy_key_set(&ADMIN, destroy, &n).unwrap();
    check(&f, Operation::DestroyKeySet, &ADMIN, true);
    let _ = f
        .keyd
        .destroy_key_set(&ADMIN, DecisionId::new(0xDEAD_0003), &n);
    check(&f, Operation::DestroyKeySet, &ADMIN, false);
    // The attestation key's install (task PN9; docs/59 §7.5; Q-1033): one
    // record either way (before the seal: it exists only in the ceremony).
    let attestation_key =
        || keyd::AttestationKey::from_bytes(&[0x6E; keyd::ATTESTATION_KEY_LEN]).unwrap();
    let _ = f.keyd.install_attestation_key(&KDC, attestation_key(), &n);
    check(&f, Operation::InstallAttestationKey, &KDC, false);
    // The fixture's ceremony installed the key (task PN11): a second
    // install is refused — still one record.
    let _ = f
        .keyd
        .install_attestation_key(&ADMIN, attestation_key(), &n);
    check(&f, Operation::InstallAttestationKey, &ADMIN, false);
    // The seal (A-102, docs/52 R3): one record either way.
    let _ = f.keyd.seal_ceremony(&DIRECTORY, &n);
    check(&f, Operation::SealCeremony, &DIRECTORY, false);
    f.keyd.seal_ceremony(&ADMIN, &n).unwrap();
    check(&f, Operation::SealCeremony, &ADMIN, true);
    // The revocation (task F3, docs/questions/Q-976): one record either way.
    let revocable = f
        .decide(DecidedOperation::RotateKey { handle: h }, &n)
        .unwrap();
    check(&f, Operation::RegisterDecision, &LDAP, true);
    let _ = f.keyd.revoke_decision(&ADMIN, revocable, &n);
    check(&f, Operation::RevokeDecision, &ADMIN, false);
    f.keyd.revoke_decision(&LDAP, revocable, &n).unwrap();
    check(&f, Operation::RevokeDecision, &LDAP, true);

    // FAST (docs/48 §2.4: one record per call, success or failure). The
    // successful paths are audited in tests/fast_armor.rs.
    let armored = krb_proto::KrbFastArmoredReq {
        armor: None,
        req_checksum: krb_proto::Checksum {
            cksumtype: 16,
            checksum: vec![0; 12],
        },
        enc_fast_req: krb_proto::EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![0; 48],
        },
    };
    let _ = f
        .keyd
        .open_fast_armor(&KDC, &KRBTGT, &armored, &[0x30, 0x00], &n);
    check(&f, Operation::OpenFastArmor, &KDC, false);
    let _ = f.keyd.seal_fast_error(
        &KDC,
        &keyd::FastConversation::As(keyd::ArmorId::from_bytes([6; 16])),
        &fast_krb_error(25),
        &[],
        &n,
    );
    check(&f, Operation::SealFastError, &KDC, false);

    // Service-ticket verification (docs/49 §3.3, A-46): one record either
    // way. The successful path is audited in tests/service_ticket.rs.
    let _ = f
        .keyd
        .open_and_verify_service_ticket(&LDAP, &SERVICE.principal, &[0x30, 0x00], &n);
    check(&f, Operation::OpenAndVerifyServiceTicket, &LDAP, false);
    let _ = f
        .keyd
        .open_and_verify_service_ticket(&KDC, &SERVICE.principal, &[0x30, 0x00], &n);
    check(&f, Operation::OpenAndVerifyServiceTicket, &KDC, false);
    let _ = f.keyd.verify_operation_ticket(
        &LDAP,
        &SERVICE.principal,
        &keyd::OperationDigest::new([0x0D; 32]),
        &[0x30, 0x00],
        &n,
    );
    check(&f, Operation::VerifyOperationTicket, &LDAP, false);

    // The change-password operations (task K3): one record either way. The
    // successful paths are audited in tests/change_password.rs.
    let peer = keyd::HostAddr::ipv4([192, 0, 2, 10]);
    let local = keyd::HostAddr::ipv4([192, 0, 2, 1]);
    let _ = f.keyd.open_change_password_request(
        &LDAP,
        &SERVICE.principal,
        &[0x30, 0x00],
        &[0x30, 0x00],
        &peer,
        &local,
        &n,
    );
    check(&f, Operation::OpenChangePasswordRequest, &LDAP, false);
    let unknown = keyd::ChangePasswordCtxId::from_bytes([9; 16]);
    let _ = f.keyd.complete_change_password(&LDAP, &unknown, &ALICE, &n);
    check(&f, Operation::CompleteChangePassword, &LDAP, false);
    let _ = f.keyd.seal_change_password_error(
        &DIRECTORY,
        &unknown,
        krb_proto::NonZeroResultCode::HardError,
        &n,
    );
    check(&f, Operation::SealChangePasswordError, &DIRECTORY, false);

    // Daemon support (docs/50 §3.4): one record either way.
    f.keyd.describe_config(&KDC, &n).unwrap();
    check(&f, Operation::DescribeConfig, &KDC, true);
    let _ = f.keyd.describe_config(&ADMIN, &n);
    check(&f, Operation::DescribeConfig, &ADMIN, false);
    f.keyd.ping(&DIRECTORY, &n).unwrap();
    check(&f, Operation::Ping, &DIRECTORY, true);

    // Every operation was exercised.
    for op in Operation::ALL {
        assert!(expected.iter().any(|(o, _, _)| *o == op), "{op:?}");
    }
}

/// Decimal and hex renderings of the first octets of `secret`, as they would
/// appear if a byte slice leaked into Debug output.
fn renderings(secret: &[u8]) -> Vec<String> {
    let head = &secret[..4];
    vec![
        format!("{}, {}, {}, {}", head[0], head[1], head[2], head[3]),
        format!(
            "{:02x}{:02x}{:02x}{:02x}",
            head[0], head[1], head[2], head[3]
        ),
        format!(
            "{:02X}{:02X}{:02X}{:02X}",
            head[0], head[1], head[2], head[3]
        ),
    ]
}

/// I8: audit records carry no secret — no password text, no key octets (in
/// any rendering), no session key — across a full set of operations.
/// Source: docs/10 §10 ("without any secret"), §12 I8; AGENTS.md §6.
#[test]
fn audit_records_contain_no_secret_bytes() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let ctx = open_tgt(&mut f, &tgt, 80, 80);
    let tgs = f
        .keyd
        .issue_tgs(&KDC, &SERVICE, &ctx.ctx_id, &tgs_template(80), &now())
        .unwrap();
    let service_session = krb_proto::EncTgsRepPart::decode(&open(&tgt.session, 8, &tgs.enc_part))
        .unwrap()
        .0
        .key;
    f.grant(&BOB, &bob_binding(), BOB_SALT, &now()).unwrap();
    f.keyd
        .set_secret(
            &DIRECTORY,
            &BOB,
            &bob_binding(),
            z("Indigo-Parrot-59-Gale"),
            BOB_SALT,
            &now(),
        )
        .unwrap();
    let _ = f
        .keyd
        .verify_secret(&DIRECTORY, &BOB, z("Amber-Falcon-36-Reed"), &now());
    let _ = f.keyd.verify_preauth(
        &KDC,
        &ALICE,
        &pa_enc_timestamp(
            &password_key(krb_crypto::EncType::Aes256CtsHmacSha196, "bad", ALICE_SALT),
            Some(1),
            now(),
        ),
        None,
        &now(),
    );

    let text = format!("{:?}", f.records());
    assert!(!f.records().is_empty());
    for password in [
        ALICE_PASSWORD,
        BOB_PASSWORD,
        "Indigo-Parrot-59-Gale",
        "Amber-Falcon-36-Reed",
    ] {
        assert!(
            !text.contains(password),
            "password text in audit: {password}"
        );
    }
    let alice = alice_key();
    for secret in [
        &KRBTGT_KEY[..],
        &SERVICE_KEY[..],
        alice.octets(),
        tgt.rep.0.key.keyvalue.as_bytes(),
        service_session.keyvalue.as_bytes(),
    ] {
        for r in renderings(secret) {
            assert!(!text.contains(&r), "key material in audit: {r}");
        }
    }
}

/// Debug output of keyd's public values is redacted: no key octets, no
/// session keys. Source: docs/09 א.7 ("no Debug on key types"); AGENTS.md §6.
#[test]
fn debug_output_is_redacted() {
    let mut f = Fixture::new();
    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let ctx = open_tgt(&mut f, &tgt, 90, 90);
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
    let text = format!("{:?} {:?} {:?}", f.keyd, ctx, proof);
    let alice = alice_key();
    for secret in [
        &KRBTGT_KEY[..],
        &SERVICE_KEY[..],
        alice.octets(),
        tgt.rep.0.key.keyvalue.as_bytes(),
    ] {
        for r in renderings(secret) {
            assert!(!text.contains(&r), "key material in Debug: {r}");
        }
    }
    let store = keyd::InMemoryKeyStore::new_insecure_development_allowing_krbtgt(4);
    let store_text = format!("{store:?}");
    assert!(store_text.contains("insecure_development_krbtgt"));
}

/// I6 (as amended by A-26): every failure decided before the cryptographic
/// chain completes is the same uniform value, whatever the cause (wrong
/// password, unknown principal, wrong role — and a wrong password with a
/// skewed timestamp, which never decrypts); only a key holder, past the
/// decryption, learns the skew class. Errors render without detail. Source:
/// docs/10 §9 (AuthnError { Denied } "does not distinguish"), §12 I6;
/// docs/questions/Q-071 (A-26).
#[test]
fn errors_are_uniform() {
    let mut f = Fixture::new();
    let n = now();
    let wrong_pw = password_key(krb_crypto::EncType::Aes256CtsHmacSha196, "x", ALICE_SALT);
    let stranger = KeyHandle::new(
        PrincipalId::from_bytes([0xEE; 16]),
        keyd::KeyPurpose::PrincipalLongterm,
    );
    let failures = [
        f.keyd.verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&wrong_pw, Some(1), n),
            None,
            &n,
        ),
        f.keyd.verify_preauth(
            &KDC,
            &stranger,
            &pa_enc_timestamp(&alice_key(), Some(1), n),
            None,
            &n,
        ),
        f.keyd.verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&wrong_pw, Some(1), at(-900)),
            None,
            &n,
        ),
        f.keyd.verify_preauth(
            &ADMIN,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), n),
            None,
            &n,
        ),
    ];
    for r in &failures {
        assert_eq!(r, &Err(AuthnError::Denied));
    }
    let reasons: std::collections::HashSet<_> = f.records().iter().map(|r| r.reason).collect();
    assert_eq!(reasons.len(), 3, "distinct reasons only in audit");
    // Past the decryption (the right key), the skew is a class (A-26).
    assert_eq!(
        f.keyd.verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), at(-900)),
            None,
            &n
        ),
        Err(AuthnError::Skew)
    );

    assert_eq!(AuthnError::Denied.to_string(), "denied");
    assert_eq!(AuthnError::Skew.to_string(), "clock skew too great");
    assert_eq!(IssueError::Denied.to_string(), "denied");
    assert_eq!(IssueError::BadTemplate.to_string(), "bad ticket template");
    assert_eq!(Error::Denied.to_string(), "denied");
    assert_eq!(Error::Unavailable.to_string(), "unavailable");
    assert_eq!(Error::RateLimited.to_string(), "rate limited");
}
