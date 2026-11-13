//! The account source over the directory: names, salt, state,
//! revoked_before.
//!
//! Sources (named per test): docs/47 §1.3 (R47-1), §1.4 (R47-2), §2.3
//! (R47-3), §3.3 (R47-4), §4 (R47-5, R47-6, R47-7), §7.3 (R47-10);
//! [MS-KILE] 3.1.1.2, 4.4; [MS-ADTS] 2.2.16; [MS-SAMR] 2.2.1.14, 2.2.6.1,
//! 3.1.1.6, 3.1.1.8.1; RFC 4120 3.3.3.1, 6.2. Test data: tests/common.

mod common;

use common::*;
use directory_pip::{account_salt, AccountKind, DirectoryContext, ViewError};
use kdc::{AccountSource, AccountSourceError};
use keyd::{KeyHandle, KeyPurpose, PrincipalId};
use krb_proto::constants::{KRB_NT_ENTERPRISE, KRB_NT_PRINCIPAL, KRB_NT_SRV_HST, KRB_NT_SRV_INST};
use krb_proto::KerberosString;

fn client(
    view: &impl AccountSource,
    parts: &[&str],
) -> Result<Option<kdc::ClientAccount>, AccountSourceError> {
    view.client(&realm(), &name(KRB_NT_PRINCIPAL, parts))
}

fn service(
    view: &impl AccountSource,
    parts: &[&str],
) -> Result<Option<kdc::ServiceAccount>, AccountSourceError> {
    view.service(&realm(), &name(KRB_NT_SRV_HST, parts))
}

fn key_of(id: u32, purpose: KeyPurpose) -> KeyHandle {
    KeyHandle::new(PrincipalId::from_bytes(guid(id).to_packet()), purpose)
}

/// docs/47 §1.3 AS steps 1-8 (R47-1), §2.3 (R47-3: KeyHandle = (objectGUID,
/// PrincipalLongterm)), §7.3 (R47-10: one ETYPE-INFO2 entry per keyd
/// enctype, in keyd's order, s2kparams = keyd's).
#[test]
fn exact_sam_account_name_hit() {
    let d = Dir::standard("exact-hit");
    let view = d.view();
    let alice = client(&view, &["alice"]).unwrap().expect("alice");
    assert_eq!(alice.key, key_of(ALICE, KeyPurpose::PrincipalLongterm));
    assert_eq!(alice.sid, sid_of(ALICE));
    let etypes: Vec<i32> = alice.etype_info.iter().map(|e| e.etype).collect();
    assert_eq!(etypes, vec![18, 17]);
    for entry in &alice.etype_info {
        assert_eq!(entry.salt.as_ref().unwrap().as_str(), "EXAMPLE.TESTalice");
        assert_eq!(entry.s2kparams, None);
    }
    // The name-type is not significant (RFC 4120 §6.2).
    let other_type = view
        .client(&realm(), &name(KRB_NT_ENTERPRISE, &["alice"]))
        .unwrap();
    assert_eq!(other_type, Some(alice));
}

/// docs/47 §1.3 AS step 4 (A-27): the unique index folds A–Z (Q-080), the
/// final comparison is octet for octet — a case-differing name is refused.
#[test]
fn case_differing_name_is_refused_at_the_byte_compare() {
    let d = Dir::standard("case");
    let view = d.view();
    for spelled in ["Alice", "ALICE", "aLiCe"] {
        assert_eq!(client(&view, &[spelled]), Ok(None), "{spelled}");
    }
}

/// docs/47 §1.3 "What is refused in phase 1": no UPN, no "$" retry, no
/// enterprise interpretation, no multi-component cname, no other realm.
#[test]
fn no_fallbacks() {
    let d = Dir::standard("no-fallbacks");
    let view = d.view();
    // alice's userPrincipalName is alice@example.test: never used.
    assert_eq!(client(&view, &["alice@example.test"]), Ok(None));
    assert_eq!(
        view.client(&realm(), &name(KRB_NT_ENTERPRISE, &["alice@example.test"])),
        Ok(None)
    );
    assert_eq!(client(&view, &["alice", "example.test"]), Ok(None));
    // No "$" retry for a computer.
    assert_eq!(client(&view, &["ws01"]), Ok(None));
    assert!(client(&view, &["ws01$"]).unwrap().is_some());
    // Realm: octet for octet (RFC 4120 §6.1).
    for other in ["example.test", "OTHER.TEST"] {
        let r = krb_proto::Realm::new(other).unwrap();
        assert_eq!(
            view.client(&r, &name(KRB_NT_PRINCIPAL, &["alice"])),
            Ok(None)
        );
        assert_eq!(
            view.service(&r, &name(KRB_NT_SRV_HST, &["host", "ws01.example.test"])),
            Ok(None)
        );
    }
    // A name longer than any stored sAMAccountName cannot match.
    let long = "a".repeat(300);
    assert_eq!(client(&view, &[long.as_str()]), Ok(None));
}

/// docs/47 §1.3 AS step 5: only user and computer objects are clients.
#[test]
fn groups_are_not_clients() {
    let d = Dir::standard("group-not-client");
    let view = d.view();
    assert_eq!(client(&view, &["staff"]), Ok(None));
    assert_eq!(client(&view, &["mail"]), Ok(None));
}

/// docs/47 §1.4 (R47-2): the krbtgt account is never a client or a service
/// — refused by name ("krbtgt", RFC 4120 §6.2) and by RID (502, [MS-SAMR]
/// 2.2.1.14); its key handle is [`DirectoryView::krbtgt_handle`].
#[test]
fn krbtgt_is_never_returned() {
    let d = Dir::standard("krbtgt");
    let view = d.view();
    assert_eq!(client(&view, &["krbtgt"]), Ok(None));
    assert_eq!(
        view.service(&realm(), &name(KRB_NT_SRV_INST, &["krbtgt", REALM])),
        Ok(None)
    );
    assert_eq!(
        view.krbtgt_handle(&domain_sid()),
        Ok(key_of(KRBTGT, KeyPurpose::Krbtgt))
    );
}

/// docs/47 §1.3 step 6: the RID check stands alone — an RID-502 account
/// under another sAMAccountName (breaking [MS-SAMR] 3.1.1.6 item 14) is
/// still never a client, and is not accepted as the krbtgt account.
#[test]
fn rid_502_is_refused_whatever_its_name() {
    let d = Dir::new("rid-502");
    let mut objects = d.standard_objects();
    objects.retain(|o| o.guid != guid(KRBTGT));
    objects.push(d.user(
        KRBTGT,
        USERS_CN,
        "kdcsvc",
        &[
            ("userAccountControl", vec![bits(uac::ADS_UF_NORMAL_ACCOUNT)]),
            ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
        ],
    ));
    d.create_all(objects);
    let view = d.view();
    assert_eq!(client(&view, &["kdcsvc"]), Ok(None));
    assert_eq!(view.krbtgt_handle(&domain_sid()), Err(AccountSourceError));
}

/// docs/47 §1.3 TGS (R47-1), §2.3 (KeyHandle = (objectGUID, Service)),
/// §7.3 (enctypes = keyd's): an exact servicePrincipalName match on a
/// computer.
#[test]
fn spn_lookup_on_computers() {
    let d = Dir::standard("spn");
    let view = d.view();
    let ws01 = service(&view, &["host", "ws01.example.test"])
        .unwrap()
        .expect("ws01");
    assert_eq!(ws01.key, key_of(WS01, KeyPurpose::Service));
    assert_eq!(ws01.enctypes, vec![18, 17]);
    assert!(ws01.state.usable_at(&now()));
    // Exact: no case folding (A-27), no single component, no extra
    // component, no joined component (Q-070 item 12).
    for parts in [
        &["HOST", "ws01.example.test"][..],
        &["host", "WS01.example.test"],
        &["host", "ws01"],
        &["ws01$"],
        &["host/ws01.example.test"],
        &["host", "ws01.example.test", "x"],
        &["cifs", "ws01.example.test"],
    ] {
        assert_eq!(service(&view, parts), Ok(None), "{parts:?}");
    }
    // A DC computer serves its SPN too.
    assert!(service(&view, &["ldap", "dc01.example.test"])
        .unwrap()
        .is_some());
}

/// docs/47 §1.3 TGS step 4, R47-13: an SPN can only be held by a computer
/// (the schema refuses it on a user), so a user is never a service.
#[test]
fn spn_cannot_be_held_by_a_user() {
    let d = Dir::standard("spn-user");
    let obj = d.user(
        50,
        STAFF_OU,
        "websvc",
        &[(
            "servicePrincipalName",
            vec![b"http/web.example.test".to_vec()],
        )],
    );
    let mut txn = d.store.begin_write().unwrap();
    let result = txn.create_object(obj, &d.origin());
    assert!(matches!(
        result,
        Err(dirstore::Error::Rejected(
            dirstore::Violation::AttributeNotAllowed(_)
        ))
    ));
    drop(txn);
    let view = d.view();
    assert_eq!(service(&view, &["http", "web.example.test"]), Ok(None));
    assert_eq!(service(&view, &["alice", "x"]), Ok(None));
}

/// [MS-KILE] 3.1.1.2 (R47-4), worked by hand:
/// - user: "< DNS of the realm, converted to uppercase> | <user name>" =
///   "EXAMPLE.TEST" | "alice" = "EXAMPLE.TESTalice";
/// - computer: "EXAMPLE.TEST" | "host" | lower("ws01$" without "$") = "ws01"
///   | "." | lower("EXAMPLE.TEST") = "example.test" =
///   "EXAMPLE.TESThostws01.example.test";
/// - [MS-KILE] 4.4 printed salt: realm DOMAIN.COM, computer "client" →
///   "DOMAIN.COMhostclient.domain.com".
///
/// The account source advertises exactly what the shared function returns.
#[test]
fn salt_values() {
    let r = realm();
    assert_eq!(
        account_salt(&r, AccountKind::User, "alice")
            .unwrap()
            .as_str(),
        "EXAMPLE.TESTalice"
    );
    assert_eq!(
        account_salt(&r, AccountKind::Computer, "ws01$")
            .unwrap()
            .as_str(),
        "EXAMPLE.TESThostws01.example.test"
    );
    let kile = krb_proto::Realm::new("DOMAIN.COM").unwrap();
    assert_eq!(
        account_salt(&kile, AccountKind::Computer, "CLIENT$")
            .unwrap()
            .as_str(),
        "DOMAIN.COMhostclient.domain.com"
    );
    let d = Dir::standard("salt");
    let view = d.view();
    let ws01 = client(&view, &["ws01$"]).unwrap().unwrap();
    let expected = KerberosString::new("EXAMPLE.TESThostws01.example.test").unwrap();
    assert!(ws01
        .etype_info
        .iter()
        .all(|e| e.salt.as_ref() == Some(&expected)));
}

/// docs/47 §3.3 item 3: the realm must be the domain's DNS name in upper
/// case — a realm with a lower-case letter is refused at setup.
#[test]
fn realm_must_be_upper_case() {
    let p1 = ad_schema::phase1().unwrap();
    let lower = keyd::KeydConfig::new(krb_proto::Realm::new("Example.test").unwrap());
    assert!(matches!(
        DirectoryContext::new(p1, &lower),
        Err(ViewError::RealmNotUppercase)
    ));
}

/// The account state of user `sam`, created with `extra` (an empty value
/// list leaves the attribute out).
fn state_of(
    test: &str,
    extra: &[(&str, Vec<Vec<u8>>)],
) -> Result<Option<kdc::AccountState>, AccountSourceError> {
    let d = Dir::standard(test);
    d.create_all(vec![d.user(60, STAFF_OU, "carol", extra)]);
    let view = d.view();
    client(&view, &["carol"]).map(|c| c.map(|c| c.state))
}

fn normal() -> Vec<Vec<u8>> {
    vec![bits(uac::ADS_UF_NORMAL_ACCOUNT)]
}

/// docs/47 §4.1 (R47-5a): N, password set → enabled, never expires,
/// locked = false (R47-6), revoked_before set (R47-7).
#[test]
fn normal_account_state() {
    let s = state_of(
        "state-normal",
        &[
            ("userAccountControl", normal()),
            ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
        ],
    )
    .unwrap()
    .unwrap();
    assert!(s.enabled);
    assert!(!s.locked);
    assert_eq!(s.expires, None);
    assert!(s.usable_at(&now()));
    assert!(s.revoked_before.is_some());
}

/// [MS-ADTS] 2.2.16 D ("not enabled for authentication"); [MS-KILE] 3.3.1.1
/// Disabled; docs/47 §4.1.
#[test]
fn disabled_account() {
    let s = state_of(
        "state-disabled",
        &[
            (
                "userAccountControl",
                vec![bits(
                    uac::ADS_UF_NORMAL_ACCOUNT | uac::ADS_UF_ACCOUNT_DISABLE,
                )],
            ),
            ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
        ],
    )
    .unwrap()
    .unwrap();
    assert!(!s.enabled);
    assert!(!s.usable_at(&now()));
}

/// docs/47 §4.2 (R47-5b); [MS-SAMR] 2.2.6.1 ("the time at which an account
/// is no longer permitted to log on"), 3.1.1.8.1 (0x7FFFFFFF FFFFFFFF
/// default); Q-113 / A-37 (0 = expired).
#[test]
fn account_expires() {
    let base = |v: Option<i64>| {
        let mut e = vec![
            ("userAccountControl", normal()),
            ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
        ];
        if let Some(v) = v {
            e.push(("accountExpires", vec![int64(v)]));
        }
        e
    };
    // Past (2026-01-01): expired.
    let s = state_of("expires-past", &base(Some(EXPIRES_2026)))
        .unwrap()
        .unwrap();
    assert_eq!(s.expires, Some(kt(2026, 1, 1, 0, 0, 0)));
    assert!(!s.usable_at(&now()));
    // Future (2027-01-01): usable now, expiry carried.
    let s = state_of("expires-future", &base(Some(EXPIRES_2027)))
        .unwrap()
        .unwrap();
    assert_eq!(s.expires, Some(kt(2027, 1, 1, 0, 0, 0)));
    assert!(s.usable_at(&now()));
    // 0 = 1601-01-01T00:00:00Z: expired (the literal reading).
    let s = state_of("expires-zero", &base(Some(0))).unwrap().unwrap();
    assert_eq!(s.expires, Some(kt(1601, 1, 1, 0, 0, 0)));
    assert!(!s.usable_at(&now()));
    // 0x7FFFFFFF FFFFFFFF and absent: never.
    let s = state_of("expires-never", &base(Some(i64::MAX)))
        .unwrap()
        .unwrap();
    assert_eq!(s.expires, None);
    let s = state_of("expires-absent", &base(None)).unwrap().unwrap();
    assert_eq!(s.expires, None);
    // Beyond 9999-12-31 (but not "never"): an error, not "never".
    assert_eq!(
        state_of("expires-beyond", &base(Some(i64::MAX - 1))),
        Err(AccountSourceError)
    );
}

/// docs/47 §4.3 (R47-5c); [MS-ADTS] 3.1.1.4.5.17 (PE when pwdLastSet = 0 or
/// null and none of SR / DP / WT / ST / ID); [MS-SAMR] 3.1.5.14.4.
#[test]
fn pwd_last_set_zero_or_absent() {
    for (test, pwd) in [("pwd-zero", vec![int64(0)]), ("pwd-absent", vec![])] {
        let s = state_of(
            test,
            &[("userAccountControl", normal()), ("pwdLastSet", pwd)],
        )
        .unwrap()
        .unwrap();
        assert!(!s.enabled, "{test}");
    }
    // DP exempts it ([MS-SAMR] 3.1.5.14.4 item 1).
    let s = state_of(
        "pwd-zero-dp",
        &[
            (
                "userAccountControl",
                vec![bits(
                    uac::ADS_UF_NORMAL_ACCOUNT | uac::ADS_UF_DONT_EXPIRE_PASSWD,
                )],
            ),
            ("pwdLastSet", vec![int64(0)]),
        ],
    )
    .unwrap()
    .unwrap();
    assert!(s.enabled);
    // Computers are exempt: dc01$ has no pwdLastSet.
    let d = Dir::standard("pwd-computer");
    let view = d.view();
    assert!(client(&view, &["dc01$"]).unwrap().unwrap().state.enabled);
}

/// docs/47 §4.3: SR ⇒ STATUS_SMARTCARD_LOGON_REQUIRED for a password logon
/// ([MS-KILE] 3.3.5.6.3); no PKINIT in phase 1 ⇒ not usable.
#[test]
fn smart_card_required() {
    let s = state_of(
        "state-sr",
        &[
            (
                "userAccountControl",
                vec![bits(
                    uac::ADS_UF_NORMAL_ACCOUNT | uac::ADS_UF_SMARTCARD_REQUIRED,
                )],
            ),
            ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
        ],
    )
    .unwrap()
    .unwrap();
    assert!(!s.enabled);
}

/// [MS-KILE] 3.3.1.1 ("Expired ... use the userAccountControl attribute PE
/// flag"), 3.3.5.6.3 ("If Expired is TRUE ... KDC_ERR_CLIENT_REVOKED").
#[test]
fn password_expired_bit() {
    let s = state_of(
        "state-pe",
        &[
            (
                "userAccountControl",
                vec![bits(
                    uac::ADS_UF_NORMAL_ACCOUNT | uac::ADS_UF_PASSWORD_EXPIRED,
                )],
            ),
            ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
        ],
    )
    .unwrap()
    .unwrap();
    assert!(!s.enabled);
}

/// docs/47 §4.1 (R47-5a): userAccountControl absent ⇒ not enabled (fail
/// closed); a kind that contradicts the class ⇒ error ([MS-SAMR] 3.1.1.6
/// items 20, 23, 24).
#[test]
fn missing_or_inconsistent_user_account_control() {
    let s = state_of("uac-absent", &[("pwdLastSet", vec![int64(PWD_LAST_SET)])])
        .unwrap()
        .unwrap();
    assert!(!s.enabled);
    for (test, bits_value) in [
        ("uac-user-wt", uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT),
        ("uac-user-st", uac::ADS_UF_SERVER_TRUST_ACCOUNT),
        ("uac-user-none", uac::ADS_UF_DONT_EXPIRE_PASSWD),
    ] {
        assert_eq!(
            state_of(
                test,
                &[
                    ("userAccountControl", vec![bits(bits_value)]),
                    ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
                ]
            ),
            Err(AccountSourceError),
            "{test}"
        );
    }
}

/// docs/47 §4.5 (R47-7): revoked_before = max(whenCreated + 1 s,
/// ceil_s(pwdLastSet)), pwdLastSet absent / 0 not counted.
/// - whenCreated = 2026-11-01T00:00:00Z, pwdLastSet = 2026-11-05T12:00:00.5Z
///   → ceil = 12:00:01, the later → 2026-11-05T12:00:01Z;
/// - pwdLastSet 0 (DP account) → whenCreated + 1 s = 2026-11-01T00:00:01Z;
/// - pwdLastSet earlier than whenCreated → whenCreated + 1 s.
///
/// RFC 4120 3.3.3.1: a TGT whose authtime is in the range is rejected.
#[test]
fn revoked_before_derivation() {
    let d = Dir::standard("revoked-before");
    let dp = vec![bits(
        uac::ADS_UF_NORMAL_ACCOUNT | uac::ADS_UF_DONT_EXPIRE_PASSWD,
    )];
    d.create_all(vec![
        d.user(
            61,
            STAFF_OU,
            "zero",
            &[
                ("userAccountControl", dp.clone()),
                ("pwdLastSet", vec![int64(0)]),
            ],
        ),
        // pwdLastSet 2026-01-01 (EXPIRES_2026 as a FILETIME) < whenCreated.
        d.user(
            62,
            STAFF_OU,
            "older",
            &[
                ("userAccountControl", dp),
                ("pwdLastSet", vec![int64(EXPIRES_2026)]),
            ],
        ),
    ]);
    let view = d.view();
    let alice = client(&view, &["alice"]).unwrap().unwrap().state;
    assert_eq!(alice.revoked_before, Some(kt(2026, 11, 5, 12, 0, 1)));
    assert!(alice.revokes(&kt(2026, 11, 5, 12, 0, 0)));
    assert!(!alice.revokes(&kt(2026, 11, 5, 12, 0, 1)));
    let zero = client(&view, &["zero"]).unwrap().unwrap().state;
    assert_eq!(zero.revoked_before, Some(kt(2026, 11, 1, 0, 0, 1)));
    let older = client(&view, &["older"]).unwrap().unwrap().state;
    assert_eq!(older.revoked_before, Some(kt(2026, 11, 1, 0, 0, 1)));
}

/// docs/47 §4.5: whenCreated is set by the system on create; an account
/// without it cannot be told apart from a former holder of its name — an
/// error (fail closed).
#[test]
fn missing_when_created_is_an_error() {
    assert_eq!(
        state_of(
            "no-when-created",
            &[
                ("userAccountControl", normal()),
                ("pwdLastSet", vec![int64(PWD_LAST_SET)]),
                ("whenCreated", vec![]),
            ]
        ),
        Err(AccountSourceError)
    );
}
