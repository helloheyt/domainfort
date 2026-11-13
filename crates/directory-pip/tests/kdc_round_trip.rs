//! A full AS → TGS round trip through `kdc::Kdc::handle` against the
//! directory-backed account source, with the SAME per-request view handed
//! to the KDC as its account source and as the PIP (docs/47 §8.1, R47-11,
//! R47-14).
//!
//! Keys come from a development keyd set up the way docs/47 §9 describes:
//! the krbtgt key set `(objectGUID(krbtgt), Krbtgt)` from `create_key` with
//! binding krbtgt/REALM (R47-2, R47-12); alice's `(objectGUID, Principal-
//! Longterm)` and ws01's `(objectGUID, Service)` from `set_secret` with the
//! salt of [`directory_pip::account_salt`] (R47-4, R47-12). The test plays
//! the Kerberos client with krb-crypto (a dev-dependency only, main-session
//! decision 2): it derives its key from the password and the advertised
//! ETYPE-INFO2 salt (RFC 4120 §3.1.3), builds PA-ENC-TIMESTAMP (5.2.7.2, key
//! usage 1) and the TGS authenticator (5.5.1, usages 6 and 7), and opens
//! the replies (usages 3 and 8) and the service ticket (usage 2) — the
//! service key derived from the machine password and the [MS-KILE] 3.1.1.2
//! computer salt.
//!
//! Sources: RFC 4120 §3.1.3, 3.3.3.1, 5.2.7.2, 5.2.7.5, 5.4.1, 5.4.2, 5.5.1,
//! 7.5.1; docs/47 §1.3, §1.4, §3.3, §4.5, §8.1, §9; [MS-KILE] 3.1.1.2. All
//! values hand-made (tests/common).

mod common;

use common::*;
use directory_pip::{account_salt, AccountKind, DirectoryView, TierMap};
use kdc::{
    AccountSource, AuditEvent, Kdc, KdcConfig, KdcReply, LocalKeyd, Peer, PolicyInputs,
    RateLimiter, Transport,
};
use keyd::{AuditRecord, CallerId, InMemoryKeyStore, Keyd, OsEntropy, PrincipalBinding, Role};
use krb_crypto::{EncType, KeyUsage, ProtocolKey};
use krb_proto::constants::{
    KDC_ERR_CLIENT_REVOKED, KDC_ERR_C_PRINCIPAL_UNKNOWN, KDC_ERR_PREAUTH_REQUIRED,
    KDC_ERR_S_PRINCIPAL_UNKNOWN, KDC_ERR_TGT_REVOKED, KRB_NT_PRINCIPAL, KRB_NT_SRV_HST,
    KRB_NT_SRV_INST, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, PA_TGS_REQ,
};
use krb_proto::{
    ApOptions, ApReq, AsRep, AsReq, Authenticator, Checksum, EncAsRepPart, EncTgsRepPart,
    EncTicketPart, EncryptedData, EncryptionKey, EtypeInfo2, KdcOptions, KdcReq, KdcReqBody,
    KerberosTime, KrbError, MethodData, Microseconds, PaData, PaEncTsEnc, PrincipalName, TgsRep,
    TgsReq, Ticket,
};
use pdp::{
    ActionClass, ActionMatch, AuthMatch, ContextMatch, Effect, IpScope, Match, PolicySnapshot,
    PolicyVersion, ResourceMatch, RlKey, Rule, RuleId, SubjectMatch, Tier,
};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// The KDC.
// ---------------------------------------------------------------------------

struct NoKeydAudit;
impl keyd::AuditSink for NoKeydAudit {
    fn record(&mut self, _record: &AuditRecord) {}
}

#[derive(Default)]
struct KdcAudit {
    events: Vec<AuditEvent>,
}
impl kdc::AuditSink for KdcAudit {
    fn record(&mut self, event: &AuditEvent) {
        self.events.push(event.clone());
    }
}

struct AdmitAll;
impl RateLimiter for AdmitAll {
    fn admit(&mut self, _key: &RlKey, _now: &KerberosTime) -> bool {
        true
    }
}

const ADMIN: CallerId = CallerId {
    uid: 300,
    role: Role::Admin,
};
const DIRECTORY: CallerId = CallerId {
    uid: 200,
    role: Role::Directory,
};
const KDC_CALLER: CallerId = CallerId {
    uid: 100,
    role: Role::Kdc,
};

type TestKdc = Kdc<LocalKeyd<InMemoryKeyStore, NoKeydAudit, OsEntropy>, KdcAudit, AdmitAll>;

fn alice_name() -> PrincipalName {
    name(KRB_NT_PRINCIPAL, &["alice"])
}

fn krbtgt_name() -> PrincipalName {
    name(KRB_NT_SRV_INST, &["krbtgt", REALM])
}

fn service_name() -> PrincipalName {
    name(KRB_NT_SRV_HST, &["host", "ws01.example.test"])
}

/// docs/11 §3: one Allow rule for every Kerberos action and subject.
fn policy() -> PolicySnapshot {
    PolicySnapshot::new(
        PolicyVersion(1),
        vec![Rule {
            id: RuleId(1),
            effect: Effect::Allow,
            when: Match {
                action: ActionMatch::Class(ActionClass::Kerberos),
                resource: ResourceMatch::Any,
                subject: SubjectMatch::Any,
                context: ContextMatch::ANY,
                auth: AuthMatch::ANY,
            },
            obligations: Vec::new(),
        }],
        Vec::new(),
    )
}

/// The KDC over the standard directory, with keyd holding the krbtgt key,
/// alice's password key and ws01's service key (docs/47 §9.1 table).
fn kdc_for(d: &Dir) -> TestKdc {
    let view = d.view();
    // R47-2: KdcConfig.krbtgt from the directory (domainSID ‖ 502).
    let krbtgt = view.krbtgt_handle(&domain_sid()).unwrap();
    let alice = view.client(&realm(), &alice_name()).unwrap().unwrap();
    let ws01 = view.service(&realm(), &service_name()).unwrap().unwrap();
    drop(view);
    let n = now();
    let mut keyd = Keyd::new(
        keyd_config(),
        InMemoryKeyStore::new_insecure_development_allowing_krbtgt(16),
        NoKeydAudit,
    )
    .unwrap();
    keyd.create_key(
        &ADMIN,
        &krbtgt,
        &PrincipalBinding::new(realm(), krbtgt_name()),
        &n,
    )
    .unwrap();
    let alice_salt = account_salt(&realm(), AccountKind::User, "alice").unwrap();
    keyd.set_secret(
        &DIRECTORY,
        &alice.key,
        &PrincipalBinding::new(realm(), alice_name()),
        String::from(ALICE_PASSWORD).into(),
        alice_salt.as_str(),
        &n,
    )
    .unwrap();
    let ws01_salt = account_salt(&realm(), AccountKind::Computer, "ws01$").unwrap();
    keyd.set_secret(
        &DIRECTORY,
        &ws01.key,
        &PrincipalBinding::new(realm(), service_name()),
        String::from(WS01_PASSWORD).into(),
        ws01_salt.as_str(),
        &n,
    )
    .unwrap();
    Kdc::new(
        KdcConfig::new(realm(), krbtgt),
        LocalKeyd::new(keyd, KDC_CALLER).unwrap(),
        KdcAudit::default(),
        AdmitAll,
    )
    .unwrap()
}

/// One request: a fresh view (one snapshot) is both the account source and
/// the PIP (docs/47 §8.1, R47-14).
fn send(
    d: &Dir,
    kdc: &mut TestKdc,
    tiers: &TierMap,
    request: &[u8],
    when: KerberosTime,
) -> KdcReply {
    let view: DirectoryView<'_> = d.view_with(tiers);
    let snapshot = policy();
    let inputs = PolicyInputs {
        snapshot: &snapshot,
        pip: &view,
    };
    kdc.handle(
        request,
        Peer {
            transport: Transport::Tcp,
            src_net: IpScope::Internal,
        },
        when,
        &inputs,
        &view,
    )
}

fn sent(reply: KdcReply) -> Vec<u8> {
    match reply {
        KdcReply::Send(bytes) => bytes,
        other => panic!("expected Send, got {other:?}"),
    }
}

fn error_of(reply: KdcReply) -> KrbError {
    KrbError::decode(&sent(reply)).expect("a KRB-ERROR")
}

// ---------------------------------------------------------------------------
// The client (RFC 4120 §3.1.1, §3.3.1, 5.2.7.2, 5.5.1).
// ---------------------------------------------------------------------------

const AES256: i32 = 18;
const AES128: i32 = 17;

fn usage(n: u32) -> KeyUsage {
    KeyUsage::new(n).unwrap()
}

fn enc_type(number: i32) -> EncType {
    EncType::from_number(number).unwrap()
}

/// string-to-key (RFC 3961 §3, RFC 3962 §4), default iterations.
fn password_key(etype: i32, password: &str, salt: &str) -> ProtocolKey {
    krb_crypto::string_to_key(enc_type(etype), password, salt, None, 50_000).unwrap()
}

fn key_from(ek: &EncryptionKey) -> ProtocolKey {
    krb_crypto::random_to_key(enc_type(ek.keytype), ek.keyvalue.as_bytes()).unwrap()
}

fn open(key: &ProtocolKey, usage_number: u32, enc: &EncryptedData) -> Vec<u8> {
    krb_crypto::decrypt(key, usage(usage_number), &enc.cipher)
        .unwrap()
        .to_vec()
}

/// PA-ENC-TIMESTAMP (RFC 4120 5.2.7.2): key usage 1.
fn pa_enc_timestamp(key: &ProtocolKey, ts: KerberosTime) -> PaData {
    let plain = PaEncTsEnc {
        patimestamp: ts,
        pausec: Some(Microseconds::new(1234).unwrap()),
    }
    .encode()
    .unwrap();
    let cipher = krb_crypto::encrypt(key, usage(1), &[0x31; 16], &plain).unwrap();
    PaData {
        padata_type: PA_ENC_TIMESTAMP,
        padata_value: EncryptedData {
            etype: key.enc_type().number(),
            kvno: Some(1),
            cipher,
        }
        .encode()
        .unwrap(),
    }
}

/// An AS-REQ for a TGT (RFC 4120 5.4.1) until 18:00.
fn as_req(cname: PrincipalName, padata: Option<Vec<PaData>>) -> Vec<u8> {
    AsReq(KdcReq {
        padata,
        req_body: KdcReqBody {
            kdc_options: KdcOptions::empty(),
            cname: Some(cname),
            realm: realm(),
            sname: Some(krbtgt_name()),
            from: None,
            till: kt(2026, 11, 13, 18, 0, 0),
            rtime: None,
            nonce: 0x0D1_4747,
            etype: vec![AES256, AES128],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    })
    .encode()
    .unwrap()
}

/// alice's TGT: PREAUTH_REQUIRED → ETYPE-INFO2 salt → key → AS-REP.
struct Tgt {
    ticket: Ticket,
    session: ProtocolKey,
    salt: String,
}

fn obtain_tgt(d: &Dir, kdc: &mut TestKdc, tiers: &TierMap) -> Tgt {
    // RFC 4120 3.1.3: PREAUTH_REQUIRED carries PA-ETYPE-INFO2.
    let error = error_of(send(d, kdc, tiers, &as_req(alice_name(), None), now()));
    assert_eq!(error.error_code, KDC_ERR_PREAUTH_REQUIRED);
    let methods = MethodData::decode(error.e_data.as_deref().unwrap()).unwrap();
    let info = methods
        .0
        .iter()
        .find(|p| p.padata_type == PA_ETYPE_INFO2)
        .unwrap();
    let entries = EtypeInfo2::decode(&info.padata_value).unwrap();
    let first = &entries.0[0];
    assert_eq!(first.etype, AES256);
    let salt = first.salt.as_ref().unwrap().as_str().to_owned();
    // The client derives its key from the password and the advertised salt.
    let key = password_key(first.etype, ALICE_PASSWORD, &salt);
    let request = as_req(alice_name(), Some(vec![pa_enc_timestamp(&key, now())]));
    let bytes = sent(send(d, kdc, tiers, &request, now()));
    let rep = AsRep::decode(&bytes).expect("an AS-REP");
    assert_eq!(rep.0.cname, alice_name());
    let part = EncAsRepPart::decode(&open(&key, 3, &rep.0.enc_part)).unwrap();
    assert_eq!(part.0.sname, krbtgt_name());
    Tgt {
        ticket: rep.0.ticket,
        session: key_from(&part.0.key),
        salt,
    }
}

/// A TGS-REQ for `sname` at `ctime` (RFC 4120 5.4.1, 5.5.1): the
/// authenticator's checksum covers the KDC-REQ-BODY octets (usage 6), the
/// authenticator is sealed with the TGT session key (usage 7).
fn tgs_req(tgt: &Tgt, sname: PrincipalName, ctime: KerberosTime) -> Vec<u8> {
    let body = KdcReqBody {
        kdc_options: KdcOptions::empty(),
        cname: None,
        realm: realm(),
        sname: Some(sname),
        from: None,
        till: kt(2026, 11, 13, 17, 0, 0),
        rtime: None,
        nonce: 0x0D1_4748,
        etype: vec![AES256, AES128],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let body_bytes = body.encode().unwrap();
    let cksumtype = tgt.session.enc_type().checksum_type();
    let authenticator = Authenticator {
        crealm: realm(),
        cname: alice_name(),
        cksum: Some(Checksum {
            cksumtype: cksumtype.number(),
            checksum: krb_crypto::get_mic(&tgt.session, cksumtype, usage(6), &body_bytes).unwrap(),
        }),
        cusec: Microseconds::new(7).unwrap(),
        ctime,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    }
    .encode()
    .unwrap();
    let ap_req = ApReq {
        ap_options: ApOptions::empty(),
        ticket: tgt.ticket.clone(),
        authenticator: EncryptedData {
            etype: tgt.session.enc_type().number(),
            kvno: None,
            cipher: krb_crypto::encrypt(&tgt.session, usage(7), &[0x47; 16], &authenticator)
                .unwrap(),
        },
    };
    TgsReq(KdcReq {
        padata: Some(vec![PaData {
            padata_type: PA_TGS_REQ,
            padata_value: ap_req.encode().unwrap(),
        }]),
        req_body: body,
    })
    .encode()
    .unwrap()
}

/// `now` + `secs` (under an hour).
fn at(secs: u32) -> KerberosTime {
    let minute = u8::try_from(secs / 60).unwrap();
    let second = u8::try_from(secs % 60).unwrap();
    kt(2026, 11, 13, 10, minute, second)
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// docs/47 §8.1 / R47-14 end to end: AS (PREAUTH_REQUIRED with the [MS-KILE]
/// 3.1.1.2 user salt, then a TGT) and TGS (a service ticket for the
/// computer's SPN). The service ticket opens under the key a host derives
/// from its machine password and the computer salt (docs/47 §3.3 item 2),
/// and names alice. The PDP accepted a Subject whose tier came from the same
/// view (P3), here with alice's nested group mapped to Tier1.
#[test]
fn as_then_tgs_round_trip() {
    let d = Dir::standard("round-trip");
    let mut kdc = kdc_for(&d);
    let tiers = TierMap::new(
        BTreeMap::from([(sid_of(ALLSTAFF), Tier::Tier1)]),
        Vec::new(),
    )
    .unwrap();
    let tgt = obtain_tgt(&d, &mut kdc, &tiers);
    assert_eq!(tgt.salt, "EXAMPLE.TESTalice");

    let bytes = sent(send(
        &d,
        &mut kdc,
        &tiers,
        &tgs_req(&tgt, service_name(), now()),
        now(),
    ));
    let rep = TgsRep::decode(&bytes).expect("a TGS-REP");
    assert_eq!(rep.0.crealm, realm());
    assert_eq!(rep.0.cname, alice_name());
    let part = EncTgsRepPart::decode(&open(&tgt.session, 8, &rep.0.enc_part)).unwrap();
    assert_eq!(part.0.sname, service_name());
    assert_eq!(part.0.srealm, realm());
    // The host's own key: machine password + [MS-KILE] 3.1.1.2 computer salt
    // "EXAMPLE.TESThostws01.example.test".
    let host_key = password_key(
        rep.0.ticket.enc_part.etype,
        WS01_PASSWORD,
        "EXAMPLE.TESThostws01.example.test",
    );
    let ticket = EncTicketPart::decode(&open(&host_key, 2, &rep.0.ticket.enc_part)).unwrap();
    assert_eq!(ticket.cname, alice_name());
    assert_eq!(ticket.crealm, realm());
    assert_eq!(ticket.key.keyvalue, part.0.key.keyvalue);
    // One audit event per request (PREAUTH_REQUIRED, AS-REP, TGS-REP).
    assert_eq!(kdc.audit_sink().events.len(), 3);
}

/// docs/47 §4.5 (R47-7) end to end: a password set after the TGT's authtime
/// moves revoked_before past it, and the next TGS refuses the TGT
/// (RFC 4120 3.3.3.1 → KDC_ERR_TGT_REVOKED). The new value is read from the
/// next request's snapshot.
#[test]
fn password_reset_revokes_older_tgts() {
    let d = Dir::standard("tgt-revoked");
    let mut kdc = kdc_for(&d);
    let tiers = TierMap::empty();
    let tgt = obtain_tgt(&d, &mut kdc, &tiers);
    // pwdLastSet = now + 30 s (FILETIME derived in tests/common).
    d.set(ALICE, "pwdLastSet", vec![int64(NOW_PLUS_30_FILETIME)]);
    let error = error_of(send(
        &d,
        &mut kdc,
        &tiers,
        &tgs_req(&tgt, service_name(), at(60)),
        at(60),
    ));
    assert_eq!(error.error_code, KDC_ERR_TGT_REVOKED);
}

/// docs/47 §4.1 end to end: disabling the account (userAccountControl D)
/// after the TGT was issued refuses the next TGS (re-evaluation at use,
/// D53 → KDC_ERR_CLIENT_REVOKED).
#[test]
fn disabling_the_account_refuses_the_next_tgs() {
    let d = Dir::standard("disabled-after-tgt");
    let mut kdc = kdc_for(&d);
    let tiers = TierMap::empty();
    let tgt = obtain_tgt(&d, &mut kdc, &tiers);
    d.set(
        ALICE,
        "userAccountControl",
        vec![bits(
            uac::ADS_UF_NORMAL_ACCOUNT | uac::ADS_UF_ACCOUNT_DISABLE,
        )],
    );
    let error = error_of(send(
        &d,
        &mut kdc,
        &tiers,
        &tgs_req(&tgt, service_name(), at(1)),
        at(1),
    ));
    assert_eq!(error.error_code, KDC_ERR_CLIENT_REVOKED);
}

/// docs/47 §1.3 through the KDC: a case-differing or UPN-form cname is an
/// unknown client; a service name that only differs in case, or names the
/// computer by its sAMAccountName, is an unknown server.
#[test]
fn exact_names_through_the_kdc() {
    let d = Dir::standard("names-kdc");
    let mut kdc = kdc_for(&d);
    let tiers = TierMap::empty();
    for cname in [
        name(KRB_NT_PRINCIPAL, &["Alice"]),
        name(KRB_NT_PRINCIPAL, &["alice@example.test"]),
        name(KRB_NT_PRINCIPAL, &["krbtgt"]),
    ] {
        let error = error_of(send(&d, &mut kdc, &tiers, &as_req(cname, None), now()));
        assert_eq!(error.error_code, KDC_ERR_C_PRINCIPAL_UNKNOWN);
    }
    let tgt = obtain_tgt(&d, &mut kdc, &tiers);
    for (i, sname) in [
        name(KRB_NT_SRV_HST, &["HOST", "ws01.example.test"]),
        name(KRB_NT_PRINCIPAL, &["ws01$"]),
    ]
    .into_iter()
    .enumerate()
    {
        let when = at(u32::try_from(i + 1).unwrap());
        let error = error_of(send(
            &d,
            &mut kdc,
            &tiers,
            &tgs_req(&tgt, sname, when),
            when,
        ));
        assert_eq!(error.error_code, KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }
}

/// The view keeps answering the account source and the PIP alike for the
/// same request: the KDC's Subject tier equals `Pip::tier_of` (P3).
#[test]
fn account_tier_equals_pip_tier() {
    use pdp::Pip;
    let d = Dir::standard("p3");
    let tiers = TierMap::new(
        BTreeMap::from([
            (sid_of(STAFF), Tier::Tier2),
            (sid_of(ALLSTAFF), Tier::Tier1),
        ]),
        Vec::new(),
    )
    .unwrap();
    let view = d.view_with(&tiers);
    let alice = view.client(&realm(), &alice_name()).unwrap().unwrap();
    assert_eq!(view.tier_of(&alice.sid, &alice.groups), Ok(alice.tier));
    assert_eq!(alice.tier, Tier::Tier1);
}
