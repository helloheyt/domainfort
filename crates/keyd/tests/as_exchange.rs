//! The AS exchange through keyd: verify_preauth -> issue_as_rep, with the
//! test acting as the client (RFC 4120 §3.1, §5.2.7.2, §5.3, §5.4.2, key
//! usages 1/2/3 of §7.5.1), the negative cases of invariants I4 and I5
//! (docs/10 §12), and the principal-name binding (docs/questions/Q-040,
//! A-19; RFC 4120 §6.2). All values are constructed for these tests.

mod common;

use common::*;
use keyd::{
    AuditOutcome, AuditReason, AuthnError, AuthnProof, ExchangeId, IssueError, KeyHandle,
    KeyPurpose, PrincipalId,
};
use krb_crypto::EncType;
use krb_proto::constants::{KRB_NT_ENTERPRISE, KRB_NT_PRINCIPAL, KRB_NT_SRV_INST, KRB_NT_UNKNOWN};
use krb_proto::{EncAsRepPart, EncTicketPart, EncryptedData, PaData, PrincipalName, TicketFlags};
use zeroize::Zeroizing;

/// A change applied to a valid template to make it invalid.
type AsMutation = Box<dyn Fn(&mut keyd::AsTicketTemplate)>;

/// Full AS round trip. Source: RFC 4120 3.1.3 (KDC builds the ticket and
/// the reply), 3.1.5 (client checks nonce, sname, srealm), 5.2.7.2 (usage
/// 1), 5.3 (ticket enc-part, usage 2), 5.4.2 (enc-part usage 3, client kvno
/// included), 2.1 (INITIAL / PRE-AUTHENT), 7.3 (TGS name); docs/10 §4.
#[test]
fn as_round_trip() {
    let mut f = Fixture::new();
    let n = now();
    let mut template = as_template();
    template.flags = TicketFlags::RENEWABLE;
    template.renew_till = Some(kt("20261115100000Z"));

    let proof = f
        .keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), n),
            None,
            &n,
        )
        .unwrap();
    assert_eq!(proof.client, ALICE_ID);
    assert_eq!(proof.authtime, n);
    let parts = f
        .keyd
        .issue_as_rep(&KDC, &ALICE, &KRBTGT, &proof, None, &template, &n)
        .unwrap();

    // Client side: the enc-part opens with the client key, usage 3.
    assert_eq!(parts.enc_part.etype, 18);
    assert_eq!(parts.enc_part.kvno, Some(1), "RFC 4120 5.4.2: client kvno");
    let rep = EncAsRepPart::decode(&open(&alice_key(), 3, &parts.enc_part))
        .unwrap()
        .0;
    assert_eq!(rep.nonce, template.nonce, "RFC 4120 3.1.5 nonce");
    assert_eq!(rep.sname, krbtgt_name());
    assert_eq!(rep.srealm, realm());
    assert_eq!(rep.authtime, n);
    assert_eq!(rep.endtime, template.endtime);
    assert_eq!(rep.renew_till, template.renew_till);
    assert!(rep.flags.contains(TicketFlags::INITIAL));
    assert!(rep.flags.contains(TicketFlags::PRE_AUTHENT));
    assert!(rep.flags.contains(TicketFlags::RENEWABLE));
    assert_eq!(rep.key.keytype, 18);
    assert_eq!(rep.key.keyvalue.len(), 32);
    assert!(rep.caddr.is_none());

    // The ticket opens with the krbtgt key (known to the test only because
    // its entropy was scripted), usage 2.
    assert_eq!(parts.ticket.realm, realm());
    assert_eq!(parts.ticket.sname, krbtgt_name());
    assert_eq!(parts.ticket.enc_part.kvno, Some(1));
    let etp = EncTicketPart::decode(&open(&krbtgt_key(), 2, &parts.ticket.enc_part)).unwrap();
    assert_eq!(etp.key, rep.key, "same session key in ticket and reply");
    assert_eq!(etp.cname, alice_name());
    assert_eq!(etp.crealm, realm());
    assert_eq!(etp.authtime, n);
    assert_eq!(etp.flags, rep.flags);
    assert!(etp.transited.contents.is_empty(), "RFC 4120 3.3.3.2 local");
    assert!(etp.caddr.is_none(), "addressless ticket");
    assert!(etp.authorization_data.is_none(), "no PAC in phase 1");

    // The session key never appears in the clear in what keyd returned.
    let session = rep.key.keyvalue.as_bytes();
    assert!(!contains_bytes(&parts.ticket.enc_part.cipher, session));
    assert!(!contains_bytes(&parts.enc_part.cipher, session));
}

/// Two AS exchanges draw different session keys. Source: RFC 4120 3.1.3
/// ("it should be impossible to guess the next session key").
#[test]
fn session_keys_are_fresh() {
    let mut f = Fixture::new();
    let a = obtain_tgt(&mut f, now(), &as_template());
    let b = obtain_tgt(&mut f, now(), &as_template());
    assert_ne!(a.rep.0.key, b.rep.0.key);
}

/// Wrong password: the PA-ENC-TIMESTAMP does not decrypt. Source: RFC 4120
/// 3.1.3 (KDC_ERR_PREAUTH_FAILED); uniform AuthnError::Denied (docs/10 §9).
#[test]
fn preauth_wrong_password_denied() {
    let mut f = Fixture::new();
    let wrong = password_key(EncType::Aes256CtsHmacSha196, "not the password", ALICE_SALT);
    let r = f.keyd.verify_preauth(
        &KDC,
        &ALICE,
        &pa_enc_timestamp(&wrong, Some(1), now()),
        None,
        &now(),
    );
    assert_eq!(r, Err(AuthnError::Denied));
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::IntegrityFailure
    );
}

/// Unknown principal: same uniform error. Source: docs/10 §9.
#[test]
fn preauth_unknown_principal_denied() {
    let mut f = Fixture::new();
    let stranger = keyd::KeyHandle::new(
        keyd::PrincipalId::from_bytes([0xEE; 16]),
        keyd::KeyPurpose::PrincipalLongterm,
    );
    let r = f.keyd.verify_preauth(
        &KDC,
        &stranger,
        &pa_enc_timestamp(&alice_key(), None, now()),
        None,
        &now(),
    );
    assert_eq!(r, Err(AuthnError::Denied));
}

/// Clock skew: patimestamp more than the skew window (300 s, RFC 4120 §8.2)
/// from now is refused as the `Skew` class — reported only because the
/// timestamp decrypted under the client key (A-26); exactly at the window it
/// is accepted. A wrong password with a skewed timestamp never decrypts and
/// stays the uniform `Denied` (no password oracle). Source: RFC 4120 5.2.7.2,
/// 3.2.3 (KRB_AP_ERR_SKEW); docs/questions/Q-071 (A-26).
#[test]
fn preauth_clock_skew() {
    let mut f = Fixture::new();
    for (offset, ok) in [(-301, false), (301, false), (-300, true), (300, true)] {
        let r = f.keyd.verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), at(offset)),
            None,
            &now(),
        );
        assert_eq!(r.is_ok(), ok, "offset {offset}");
        if !ok {
            assert_eq!(r, Err(AuthnError::Skew), "offset {offset}");
            assert_eq!(f.records().last().unwrap().reason, AuditReason::ClockSkew);
        }
    }
    let wrong = password_key(EncType::Aes256CtsHmacSha196, "not the password", ALICE_SALT);
    let r = f.keyd.verify_preauth(
        &KDC,
        &ALICE,
        &pa_enc_timestamp(&wrong, Some(1), at(-900)),
        None,
        &now(),
    );
    assert_eq!(r, Err(AuthnError::Denied));
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::IntegrityFailure
    );
}

/// I5: an RC4 (etype 23) or unconfigured AES (etype 17) PA-ENC-TIMESTAMP is
/// refused before any decryption. Source: docs/10 §12 I5; AGENTS.md §6 (no
/// RC4 code path); krb-crypto has no type for 23 at all.
#[test]
fn preauth_rejects_weak_and_unconfigured_etypes() {
    let mut f = Fixture::new();
    assert!(EncType::from_number(23).is_err());
    for etype in [23, 17, 1, 3] {
        let enc = EncryptedData {
            etype,
            kvno: Some(1),
            cipher: vec![0x55; 64],
        };
        let padata = PaData {
            padata_type: 2,
            padata_value: enc.encode().unwrap(),
        };
        assert_eq!(
            f.keyd.verify_preauth(&KDC, &ALICE, &padata, None, &now()),
            Err(AuthnError::Denied),
            "etype {etype}"
        );
        assert_eq!(
            f.records().last().unwrap().reason,
            AuditReason::UnsupportedEncType
        );
    }
}

/// Only PA-ENC-TIMESTAMP (padata-type 2) is accepted. Source: RFC 4120
/// 5.2.7, 7.5.2 (PA-PW-SALT = 3 has no code path).
#[test]
fn preauth_rejects_other_padata_types() {
    let mut f = Fixture::new();
    let mut padata = pa_enc_timestamp(&alice_key(), Some(1), now());
    padata.padata_type = 3;
    assert_eq!(
        f.keyd.verify_preauth(&KDC, &ALICE, &padata, None, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::UnsupportedPadataType
    );
}

/// After a password change the superseded key never pre-authenticates,
/// with or without a kvno. Source: RFC 4120 5.2.9 (kvno), 3.1.3; docs/10 §6.
#[test]
fn preauth_superseded_password_denied() {
    let mut f = Fixture::new();
    f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
        .unwrap();
    f.keyd
        .set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            Zeroizing::new("a new password".to_owned()),
            ALICE_SALT,
            &now(),
        )
        .unwrap();
    for kvno in [Some(1), None, Some(2)] {
        let r = f.keyd.verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), kvno, now()),
            None,
            &now(),
        );
        assert_eq!(r, Err(AuthnError::Denied), "kvno {kvno:?}");
    }
    let new_key = password_key(EncType::Aes256CtsHmacSha196, "a new password", ALICE_SALT);
    assert!(f
        .keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&new_key, Some(2), now()),
            None,
            &now()
        )
        .is_ok());
}

fn proof(f: &mut Fixture) -> AuthnProof {
    f.keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), now()),
            None,
            &now(),
        )
        .unwrap()
}

/// I4: issuance without a proof from verify_preauth is refused. Source:
/// docs/10 §8 ("without a valid proof issue_as_rep refuses"), §12 I4.
#[test]
fn issue_without_proof_denied() {
    let mut f = Fixture::new();
    let forged = AuthnProof {
        exchange_id: ExchangeId::from_bytes([0x42; 16]),
        client: ALICE_ID,
        authtime: now(),
    };
    assert_eq!(
        f.keyd
            .issue_as_rep(&KDC, &ALICE, &KRBTGT, &forged, None, &as_template(), &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::TokenUnknown
    );
}

/// I4: a proof is single-use. Source: docs/10 §8, D36.
#[test]
fn proof_is_single_use() {
    let mut f = Fixture::new();
    let p = proof(&mut f);
    assert!(f
        .keyd
        .issue_as_rep(&KDC, &ALICE, &KRBTGT, &p, None, &as_template(), &now())
        .is_ok());
    assert_eq!(
        f.keyd
            .issue_as_rep(&KDC, &ALICE, &KRBTGT, &p, None, &as_template(), &now()),
        Err(IssueError::Denied)
    );
}

/// I4: a proof expires after the token lifetime (30 s default). Source:
/// docs/10 D36 ("short-lived (seconds)").
#[test]
fn expired_proof_denied() {
    let mut f = Fixture::new();
    let p = proof(&mut f);
    assert_eq!(
        f.keyd
            .issue_as_rep(&KDC, &ALICE, &KRBTGT, &p, None, &as_template(), &at(31)),
        Err(IssueError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::TokenExpired
    );
    // Within the lifetime it works.
    let p = proof(&mut f);
    assert!(f
        .keyd
        .issue_as_rep(&KDC, &ALICE, &KRBTGT, &p, None, &as_template(), &at(30))
        .is_ok());
}

/// I4: a proof is bound to the caller that obtained it; presenting it from
/// another caller is refused and destroys it. Source: docs/10 §8
/// ("caller-bound"), §12 I4.
#[test]
fn proof_bound_to_caller() {
    let mut f = Fixture::new();
    let p = proof(&mut f);
    assert_eq!(
        f.keyd.issue_as_rep(
            &KDC_OTHER,
            &ALICE,
            &KRBTGT,
            &p,
            None,
            &as_template(),
            &now()
        ),
        Err(IssueError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::TokenCallerMismatch
    );
    assert_eq!(
        f.keyd
            .issue_as_rep(&KDC, &ALICE, &KRBTGT, &p, None, &as_template(), &now()),
        Err(IssueError::Denied)
    );
}

/// I4: a proof is bound to the pre-authenticated client: it cannot issue a
/// ticket for another client handle, nor with a template naming another
/// client. Source: docs/10 §4 step 1 ("proof valid and bound to client").
#[test]
fn proof_bound_to_client() {
    let mut f = Fixture::new();
    let p = proof(&mut f);
    let mut t = as_template();
    t.client = BOB_ID;
    assert_eq!(
        f.keyd
            .issue_as_rep(&KDC, &BOB, &KRBTGT, &p, None, &t, &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::TokenPrincipalMismatch
    );

    let p = proof(&mut f);
    assert_eq!(
        f.keyd
            .issue_as_rep(&KDC, &ALICE, &KRBTGT, &p, None, &t, &now()),
        Err(IssueError::Denied)
    );

    let mut p = proof(&mut f);
    p.client = BOB_ID;
    assert_eq!(
        f.keyd
            .issue_as_rep(&KDC, &ALICE, &KRBTGT, &p, None, &as_template(), &now()),
        Err(IssueError::Denied)
    );
}

/// Flags outside the default allowed mask are a BadTemplate. Source:
/// docs/30 §2.6 (dangerous options reduced by default); RFC 4120 5.3 bits;
/// docs/10 §4 step 2 ("flags without a forbidden flag").
#[test]
fn forbidden_flags_bad_template() {
    let mut f = Fixture::new();
    for flag in [
        TicketFlags::FORWARDABLE,
        TicketFlags::FORWARDED,
        TicketFlags::PROXIABLE,
        TicketFlags::PROXY,
        TicketFlags::MAY_POSTDATE,
        TicketFlags::POSTDATED,
        TicketFlags::INVALID,
        TicketFlags::OK_AS_DELEGATE,
        TicketFlags::HW_AUTHENT,
    ] {
        let p = proof(&mut f);
        let mut t = as_template();
        t.flags = flag;
        assert_eq!(
            f.keyd
                .issue_as_rep(&KDC, &ALICE, &KRBTGT, &p, None, &t, &now()),
            Err(IssueError::BadTemplate),
            "{flag:?}"
        );
        let last = f.records().last().unwrap();
        assert_eq!(last.result, AuditOutcome::BadTemplate);
        assert_eq!(last.reason, AuditReason::TemplateFlags);
    }
}

/// I5: the session-key enctype must be configured. Source: docs/10 §4 step
/// 2 ("enctype supported"), §12 I5.
#[test]
fn unconfigured_session_enctype_bad_template() {
    let mut f = Fixture::new();
    for enctype in [
        keyd::EncTypeId::Aes128CtsHmacSha196,
        keyd::EncTypeId::Aes128CtsHmacSha256128,
        keyd::EncTypeId::Aes256CtsHmacSha384192,
    ] {
        let p = proof(&mut f);
        let mut t = as_template();
        t.session_enctype = enctype;
        assert_eq!(
            f.keyd
                .issue_as_rep(&KDC, &ALICE, &KRBTGT, &p, None, &t, &now()),
            Err(IssueError::BadTemplate)
        );
        assert_eq!(
            f.records().last().unwrap().reason,
            AuditReason::TemplateEncType
        );
    }
}

/// Times outside policy are a BadTemplate. Source: RFC 4120 3.1.3
/// (KDC_ERR_NEVER_VALID, KDC_ERR_CANNOT_POSTDATE), 5.3 (renew-till only
/// with RENEWABLE), §8.2 (1-day max lifetime, 5-minute min, 1-week renew).
#[test]
fn template_times_bad_template() {
    let mut f = Fixture::new();
    let cases: Vec<AsMutation> = vec![
        Box::new(|t| t.endtime = kt("20261114100001Z")), // > 1 day
        Box::new(|t| t.endtime = kt("20261113100200Z")), // < 5 minutes
        Box::new(|t| t.endtime = kt("20261113095959Z")), // in the past
        Box::new(|t| t.starttime = Some(kt("20261113110000Z"))), // postdated
        Box::new(|t| t.starttime = Some(kt("20261113090000Z"))), // backdated
        Box::new(|t| t.flags = TicketFlags::RENEWABLE),  // no renew-till
        Box::new(|t| t.renew_till = Some(kt("20261114100000Z"))), // not renewable
        Box::new(|t| {
            t.flags = TicketFlags::RENEWABLE;
            t.renew_till = Some(kt("20261121100001Z")); // > 1 week
        }),
        Box::new(|t| {
            t.flags = TicketFlags::RENEWABLE;
            t.renew_till = Some(kt("20261113170000Z")); // before endtime
        }),
    ];
    for (i, mutate) in cases.iter().enumerate() {
        let p = proof(&mut f);
        let mut t = as_template();
        mutate(&mut t);
        assert_eq!(
            f.keyd
                .issue_as_rep(&KDC, &ALICE, &KRBTGT, &p, None, &t, &now()),
            Err(IssueError::BadTemplate),
            "case {i}"
        );
    }
}

/// The ticket is sealed under krbtgt, so it must be this realm's TGT for a
/// client of this realm. Source: RFC 4120 7.3 (TGS name), 5.3 (realm);
/// docs/10 §4 ("keyd builds a correct structure").
#[test]
fn template_names_bad_template() {
    let mut f = Fixture::new();
    let cases: Vec<AsMutation> = vec![
        Box::new(|t| t.sname = service_name()),
        Box::new(|t| t.crealm = kstr("OTHER.ORG")),
        Box::new(|t| {
            t.sname = krb_proto::PrincipalName {
                name_type: 2,
                name_string: vec![kstr("krbtgt"), kstr("OTHER.ORG")],
            }
        }),
    ];
    for (i, mutate) in cases.iter().enumerate() {
        let p = proof(&mut f);
        let mut t = as_template();
        mutate(&mut t);
        assert_eq!(
            f.keyd
                .issue_as_rep(&KDC, &ALICE, &KRBTGT, &p, None, &t, &now()),
            Err(IssueError::BadTemplate),
            "case {i}"
        );
        assert_eq!(
            f.records().last().unwrap().reason,
            AuditReason::TemplateNames
        );
    }
}

/// A password change between verify_preauth and issue_as_rep invalidates
/// the exchange (the proof's key version is no longer current). Source:
/// docs/10 §1 (sealing always with the current kvno).
#[test]
fn key_change_between_steps_denied() {
    let mut f = Fixture::new();
    let p = proof(&mut f);
    f.grant(&ALICE, &alice_binding(), ALICE_SALT, &now())
        .unwrap();
    f.keyd
        .set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            Zeroizing::new("changed".to_owned()),
            ALICE_SALT,
            &now(),
        )
        .unwrap();
    assert_eq!(
        f.keyd
            .issue_as_rep(&KDC, &ALICE, &KRBTGT, &p, None, &as_template(), &now()),
        Err(IssueError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::KvnoMismatch
    );
}

/// Bounded proof table: when full of live proofs, new ones are refused
/// (fail closed) and room returns as proofs expire. Source: docs/10 D36;
/// AGENTS.md §6 (bounded).
#[test]
fn proof_table_is_bounded() {
    let mut c = config();
    c.max_authn_proofs = 2;
    let mut f = Fixture::with_config(c);
    let pa = pa_enc_timestamp(&alice_key(), Some(1), now());
    assert!(f
        .keyd
        .verify_preauth(&KDC, &ALICE, &pa, None, &now())
        .is_ok());
    assert!(f
        .keyd
        .verify_preauth(&KDC, &ALICE, &pa, None, &now())
        .is_ok());
    assert_eq!(
        f.keyd.verify_preauth(&KDC, &ALICE, &pa, None, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::TokenTableFull
    );
    let pa_later = pa_enc_timestamp(&alice_key(), Some(1), at(31));
    assert!(f
        .keyd
        .verify_preauth(&KDC, &ALICE, &pa_later, None, &at(31))
        .is_ok());
}

/// Name binding (Q-040, A-19): a valid proof for alice cannot produce a TGT
/// naming anyone else — the client key set is bound to alice. Callers see
/// only the uniform Denied. Source: docs/questions/Q-040 (A-19); docs/25
/// §3.2 (keyd is a PEP bounding a compromised KDC); RFC 4120 5.3 (cname),
/// 6.1 / 6.2 (names compared as given; no case folding in keyd).
#[test]
fn as_cname_must_match_client_binding() {
    let mut f = Fixture::new();
    let names = [
        bob_name(),
        // Case differs.
        PrincipalName {
            name_type: KRB_NT_PRINCIPAL,
            name_string: vec![kstr("Alice")],
        },
        // An extra component.
        PrincipalName {
            name_type: KRB_NT_PRINCIPAL,
            name_string: vec![kstr("alice"), kstr("admin")],
        },
    ];
    for cname in names {
        let p = proof(&mut f);
        let mut t = as_template();
        t.cname = cname.clone();
        assert_eq!(
            f.keyd
                .issue_as_rep(&KDC, &ALICE, &KRBTGT, &p, None, &t, &now()),
            Err(IssueError::Denied),
            "{cname:?}"
        );
        assert_eq!(
            f.records().last().unwrap().reason,
            AuditReason::NameBindingMismatch
        );
    }
}

/// RFC 4120 6.2: "Principal names that differ only in the name-type identify
/// the same principal" — a cname equal to alice's binding except for the
/// name-type is accepted, and the ticket carries the name as given.
#[test]
fn as_cname_name_type_is_not_significant() {
    let mut f = Fixture::new();
    for name_type in [KRB_NT_UNKNOWN, KRB_NT_ENTERPRISE, KRB_NT_SRV_INST] {
        let mut t = as_template();
        t.cname.name_type = name_type;
        let tgt = obtain_tgt(&mut f, now(), &t);
        let etp =
            EncTicketPart::decode(&open(&krbtgt_key(), 2, &tgt.parts.ticket.enc_part)).unwrap();
        assert_eq!(etp.cname, t.cname);
    }
}

/// Name binding (Q-040, A-19): a krbtgt key set bound to another TGS name
/// (an inter-realm style krbtgt/OTHER.ORG) can neither seal nor open this
/// realm's TGTs. Source: RFC 4120 7.3 (TGS name), 6.2; Q-040 (A-19).
#[test]
fn krbtgt_bound_to_wrong_name_denied() {
    let mut f = Fixture::new();
    let other_krbtgt = KeyHandle::new(PrincipalId::from_bytes([0x7C; 16]), KeyPurpose::Krbtgt);
    let wrong = bound(PrincipalName {
        name_type: KRB_NT_SRV_INST,
        name_string: vec![kstr("krbtgt"), kstr("OTHER.ORG")],
    });
    f.keyd
        .create_key(&ADMIN, &other_krbtgt, &wrong, &now())
        .unwrap();
    let p = proof(&mut f);
    assert_eq!(
        f.keyd.issue_as_rep(
            &KDC,
            &ALICE,
            &other_krbtgt,
            &p,
            None,
            &as_template(),
            &now()
        ),
        Err(IssueError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::NameBindingMismatch
    );

    let tgt = obtain_tgt(&mut f, now(), &as_template());
    let (_, body) = tgs_req_body(1, service_name());
    let req = ap_req(
        &tgt.parts.ticket,
        authenticator(&tgt.session, &AuthenticatorSpec::new(now(), 1, &body)),
    );
    assert_eq!(
        f.keyd
            .open_and_verify_tgt(&KDC, &other_krbtgt, &req, &body, None, &now()),
        Err(AuthnError::Denied)
    );
    assert_eq!(
        f.records().last().unwrap().reason,
        AuditReason::NameBindingMismatch
    );
    // The correctly bound krbtgt still opens it: the binding check precedes
    // the replay cache, so the authenticator was not consumed.
    assert!(f
        .keyd
        .open_and_verify_tgt(&KDC, &KRBTGT, &req, &body, None, &now())
        .is_ok());
}
