//! Full AS → TGS round trips through `kdc::Kdc::handle` against the
//! directory-backed account source, with the SAME per-request view handed
//! to the KDC as its account source and as the PIP (docs/47 §8.1, R47-11,
//! R47-14) — FAST-armored, as the KDC requires (docs/48, P-10 interim).
//!
//! Keys come from a development keyd set up the way docs/47 §9 describes:
//! the krbtgt key set `(objectGUID(krbtgt), Krbtgt)` from `create_key` with
//! binding krbtgt/REALM (R47-2, R47-12); alice's `(objectGUID, Principal-
//! Longterm)` and ws01's `(objectGUID, Service)` and `(objectGUID,
//! PrincipalLongterm)` from `set_secret` with the salt of
//! [`directory_pip::account_salt`] (R47-4, R47-12; docs/47 §9.1: a computer
//! has both, same password and salt).
//!
//! The flow (docs/48 §9.2): ws01$, a computer account (objectClass computer
//! → may bootstrap, docs/48 §7.2-§7.3), gets its TGT with an unarmored
//! PA-ENC-TIMESTAMP AS; that TGT armors alice's AS (FX_FAST_ARMOR_AP_REQUEST,
//! RFC 6113 5.4.1.1), pre-authenticated with the encrypted challenge (5.4.6);
//! alice's TGT then obtains a service ticket in an armored TGS (implicit
//! armor, 5.4.2).
//!
//! The test plays the Kerberos client with krb-crypto (a dev-dependency
//! only, main-session decision 2), from RFC 4120 and RFC 6113 only: it
//! derives keys from the passwords and the advertised ETYPE-INFO2 salts
//! (RFC 4120 §3.1.3), builds PA-ENC-TIMESTAMP (5.2.7.2, usage 1), the armor
//! AP-REQ (authenticator usage 11 — docs/questions/Q-120 — with a subkey),
//! the armor key KRB-FX-CF2(subkey, ticket session key, "subkeyarmor",
//! "ticketarmor"), the req-checksum (usage 50) and enc-fast-req (usage 51),
//! the encrypted challenge (usage 54), the TGS authenticator (5.5.1, usages
//! 6 and 7) with its subkey, and opens the replies through the
//! KrbFastResponse (usage 52): strengthened reply key KRB-FX-CF2(strengthen
//! key, reply key, "strengthenkey", "replykey") (5.4.3), usages 3 and 9
//! (docs/questions/Q-121), KrbFastFinished (usage 53, over the Ticket DER —
//! Q-122), and the service ticket (usage 2) — the service key derived from
//! the machine password and the [MS-KILE] 3.1.1.2 computer salt.
//!
//! Sources: RFC 4120 §3.1.3, 3.3.3.1, 5.2.7.2, 5.2.7.5, 5.4.1, 5.4.2, 5.5.1,
//! 7.5.1; RFC 6113 5.2, 5.4.1.1-5.4.6; docs/47 §1.3, §1.4, §3.3, §4.5, §8.1,
//! §9; docs/48 §3.1, §7, §9.2; [MS-KILE] 3.1.1.2. All values hand-made
//! (tests/common).

mod common;

use common::*;
use directory_pip::{account_salt, AccountKind, DirectoryView, TierMap};
use kdc::{
    AccountSource, AuditEvent, Kdc, KdcConfig, KdcReply, Peer, PolicyInputs, RateLimiter, Transport,
};
use keyd::{
    AuditRecord, CallerId, DecidedOperation, DecisionId, InMemoryKeyStore, Keyd, LocalKeyd,
    OsEntropy, PrincipalBinding, Role, SetSecretTarget, MAX_SET_SECRET_GRANT_SECS,
};
use krb_crypto::{EncType, KeyUsage, ProtocolKey};
use krb_proto::constants::{
    FX_FAST_ARMOR_AP_REQUEST, KDC_ERR_CLIENT_REVOKED, KDC_ERR_C_PRINCIPAL_UNKNOWN, KDC_ERR_POLICY,
    KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_S_PRINCIPAL_UNKNOWN, KDC_ERR_TGT_REVOKED, KRB_NT_PRINCIPAL,
    KRB_NT_SRV_HST, KRB_NT_SRV_INST, PA_ENCRYPTED_CHALLENGE, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2,
    PA_FX_COOKIE, PA_FX_ERROR, PA_FX_FAST, PA_TGS_REQ,
};
use krb_proto::{
    ApOptions, ApReq, AsRep, AsReq, Authenticator, Checksum, EncAsRepPart, EncTgsRepPart,
    EncTicketPart, EncryptedData, EncryptionKey, EtypeInfo2, FastOptions, KdcOptions, KdcRep,
    KdcReq, KdcReqBody, KerberosTime, KeyValue, KrbError, KrbFastArmor, KrbFastArmoredReq,
    KrbFastReq, KrbFastResponse, MethodData, Microseconds, PaData, PaEncTsEnc, PaFxFastReply,
    PaFxFastRequest, PrincipalName, TgsRep, TgsReq, Ticket,
};
use pdp::{
    ActionClass, ActionMatch, AuthMatch, ContextMatch, Effect, IpScope, Match, PolicySnapshot,
    PolicyVersion, ResourceMatch, RlKey, Rule, RuleId, SubjectMatch, Tier,
};
use std::cell::Cell;
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
/// dird's role in keyd, which registers the set_secret grant after its PDP
/// (task A15a; docs/51 §5.8 option (b)).
const LDAP: CallerId = CallerId {
    uid: 400,
    role: Role::Ldap,
};
const KDC_CALLER: CallerId = CallerId {
    uid: 100,
    role: Role::Kdc,
};

/// A group of the test directory holding ws01$: the bootstrap set named in
/// `pdp::mandatory_fast_rules` (Q-130: a deployment datum).
const WORKSTATIONS: u32 = 35;

type TestKdc = Kdc<LocalKeyd<InMemoryKeyStore, NoKeydAudit, OsEntropy>, KdcAudit, AdmitAll>;

fn alice_name() -> PrincipalName {
    name(KRB_NT_PRINCIPAL, &["alice"])
}

fn ws01_name() -> PrincipalName {
    name(KRB_NT_PRINCIPAL, &["ws01$"])
}

fn krbtgt_name() -> PrincipalName {
    name(KRB_NT_SRV_INST, &["krbtgt", REALM])
}

fn service_name() -> PrincipalName {
    name(KRB_NT_SRV_HST, &["host", "ws01.example.test"])
}

/// docs/11 §3: one Allow rule for every Kerberos action and subject.
fn allow_all() -> Rule {
    Rule {
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
    }
}

fn policy() -> PolicySnapshot {
    PolicySnapshot::new(PolicyVersion(1), vec![allow_all()], Vec::new())
}

/// P-10 interim: `pdp::mandatory_fast_rules` for the workstations group,
/// plus the broad grant (docs/48 §7.2: the explicit Deny wins over it).
fn mandatory_fast_policy() -> PolicySnapshot {
    let mut rules = pdp::mandatory_fast_rules(sid_of(WORKSTATIONS), RuleId(100)).unwrap();
    rules.push(allow_all());
    PolicySnapshot::new(PolicyVersion(2), rules, Vec::new())
}

/// The KDC over the standard directory, with keyd holding the krbtgt key,
/// alice's password key and ws01's client and service keys (docs/47 §9.1
/// table).
fn kdc_for(d: &Dir) -> TestKdc {
    let view = d.view();
    // R47-2: KdcConfig.krbtgt from the directory (domainSID ‖ 502).
    let krbtgt = view.krbtgt_handle(&domain_sid()).unwrap();
    let alice = view.client(&realm(), &alice_name()).unwrap().unwrap();
    let ws01_client = view.client(&realm(), &ws01_name()).unwrap().unwrap();
    let ws01 = view.service(&realm(), &service_name()).unwrap().unwrap();
    drop(view);
    let n = now();
    // keyd started the day before: its startup hold-down (RFC 4120 3.2.3;
    // docs/50 R50-6) is long over.
    let started = kt(2026, 11, 12, 10, 0, 0);
    let mut keyd = Keyd::new(
        keyd_config(),
        InMemoryKeyStore::new_insecure_development_allowing_krbtgt(16),
        NoKeydAudit,
        &started,
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
    let ws01_salt = account_salt(&realm(), AccountKind::Computer, "ws01$").unwrap();
    // The set-secret decisions dird registers after its PDP (task A15a;
    // A-102: binding and salt bound, N4).
    keyd.register_decision(
        &LDAP,
        DecisionId::new(1),
        &DecidedOperation::SetSecret {
            kind: keyd::AccountKind::User,
            targets: vec![SetSecretTarget {
                handle: alice.key,
                binding: PrincipalBinding::new(realm(), alice_name()),
                salt: alice_salt.as_str().to_owned(),
            }],
        },
        &[],
        MAX_SET_SECRET_GRANT_SECS,
        &n,
    )
    .unwrap();
    keyd.register_decision(
        &LDAP,
        DecisionId::new(2),
        &DecidedOperation::SetSecret {
            kind: keyd::AccountKind::Computer,
            targets: vec![
                SetSecretTarget {
                    handle: ws01_client.key,
                    binding: PrincipalBinding::new(realm(), ws01_name()),
                    salt: ws01_salt.as_str().to_owned(),
                },
                SetSecretTarget {
                    handle: ws01.key,
                    binding: PrincipalBinding::new(realm(), service_name()),
                    salt: ws01_salt.as_str().to_owned(),
                },
            ],
        },
        &[],
        MAX_SET_SECRET_GRANT_SECS,
        &n,
    )
    .unwrap();
    keyd.set_secret(
        &DIRECTORY,
        &alice.key,
        &PrincipalBinding::new(realm(), alice_name()),
        String::from(ALICE_PASSWORD).into(),
        alice_salt.as_str(),
        &n,
    )
    .unwrap();
    for (handle, binding) in [(ws01.key, service_name()), (ws01_client.key, ws01_name())] {
        keyd.set_secret(
            &DIRECTORY,
            &handle,
            &PrincipalBinding::new(realm(), binding),
            String::from(WS01_PASSWORD).into(),
            ws01_salt.as_str(),
            &n,
        )
        .unwrap();
    }
    Kdc::new(
        KdcConfig::new(realm(), krbtgt),
        LocalKeyd::new(keyd, KDC_CALLER).unwrap(),
        KdcAudit::default(),
        AdmitAll,
    )
    .unwrap()
}

/// One request under `policy`: a fresh view (one snapshot) is both the
/// account source and the PIP (docs/47 §8.1, R47-14).
fn send_with(
    d: &Dir,
    kdc: &mut TestKdc,
    tiers: &TierMap,
    policy: &PolicySnapshot,
    request: &[u8],
    when: KerberosTime,
) -> KdcReply {
    let view: DirectoryView<'_> = d.view_with(tiers);
    let inputs = PolicyInputs {
        snapshot: policy,
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

/// One request under the allow-all policy.
fn send(
    d: &Dir,
    kdc: &mut TestKdc,
    tiers: &TierMap,
    request: &[u8],
    when: KerberosTime,
) -> KdcReply {
    send_with(d, kdc, tiers, &policy(), request, when)
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
// The client (RFC 4120 §3.1.1, §3.3.1, 5.2.7.2, 5.5.1; RFC 6113 5.4).
// ---------------------------------------------------------------------------

const AES256: i32 = 18;
const AES128: i32 = 17;
/// The TGS authenticator subkey (mandatory under FAST, RFC 6113 5.4.2).
const TGS_SUBKEY: [u8; 32] = [0x3C; 32];

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

fn aes256(octets: &[u8; 32]) -> ProtocolKey {
    krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, octets).unwrap()
}

fn cf2(k1: &ProtocolKey, k2: &ProtocolKey, p1: &[u8], p2: &[u8]) -> ProtocolKey {
    krb_crypto::krb_fx_cf2(k1, k2, p1, p2).unwrap()
}

fn open(key: &ProtocolKey, usage_number: u32, enc: &EncryptedData) -> Vec<u8> {
    krb_crypto::decrypt(key, usage(usage_number), &enc.cipher)
        .unwrap()
        .to_vec()
}

fn seal(key: &ProtocolKey, usage_number: u32, plain: &[u8]) -> EncryptedData {
    EncryptedData {
        etype: key.enc_type().number(),
        kvno: None,
        cipher: krb_crypto::encrypt(key, usage(usage_number), &[0x5A; 16], plain).unwrap(),
    }
}

fn mic(key: &ProtocolKey, usage_number: u32, data: &[u8]) -> Checksum {
    let cksumtype = key.enc_type().checksum_type();
    Checksum {
        cksumtype: cksumtype.number(),
        checksum: krb_crypto::get_mic(key, cksumtype, usage(usage_number), data).unwrap(),
    }
}

/// PA-ENC-TS-ENC at `ts` (RFC 4120 5.2.7.2).
fn timestamp(ts: KerberosTime) -> Vec<u8> {
    PaEncTsEnc {
        patimestamp: ts,
        pausec: Some(Microseconds::new(1234).unwrap()),
    }
    .encode()
    .unwrap()
}

/// PA-ENC-TIMESTAMP (RFC 4120 5.2.7.2): key usage 1.
fn pa_enc_timestamp(key: &ProtocolKey, ts: KerberosTime) -> PaData {
    let mut sealed = seal(key, 1, &timestamp(ts));
    sealed.kvno = Some(1);
    PaData {
        padata_type: PA_ENC_TIMESTAMP,
        padata_value: sealed.encode().unwrap(),
    }
}

/// An AS-REQ body for a TGT (RFC 4120 5.4.1) until 18:00.
fn as_body(cname: PrincipalName, nonce: u32) -> KdcReqBody {
    KdcReqBody {
        kdc_options: KdcOptions::empty(),
        cname: Some(cname),
        realm: realm(),
        sname: Some(krbtgt_name()),
        from: None,
        till: kt(2026, 11, 13, 18, 0, 0),
        rtime: None,
        nonce,
        etype: vec![AES256, AES128],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    }
}

/// An unarmored AS-REQ.
fn as_req(cname: PrincipalName, padata: Option<Vec<PaData>>) -> Vec<u8> {
    AsReq(KdcReq {
        padata,
        req_body: as_body(cname, 0x0D1_4747),
    })
    .encode()
    .unwrap()
}

/// A TGT the client holds.
struct Tgt {
    ticket: Ticket,
    cname: PrincipalName,
    session: ProtocolKey,
    salt: String,
}

/// The salt of the first PA-ETYPE-INFO2 entry among `padata`.
fn first_salt(padata: &[PaData]) -> (i32, String) {
    let info = padata
        .iter()
        .find(|p| p.padata_type == PA_ETYPE_INFO2)
        .unwrap();
    let entries = EtypeInfo2::decode(&info.padata_value).unwrap();
    let first = &entries.0[0];
    (
        first.etype,
        first.salt.as_ref().unwrap().as_str().to_owned(),
    )
}

/// ws01$'s TGT by the unarmored bootstrap (docs/48 §7.3): PREAUTH_REQUIRED
/// (PA-FX-FAST, PA-ENC-TIMESTAMP, PA-ETYPE-INFO2, PA-FX-COOKIE) → the
/// computer salt → the key from the machine password → AS-REP.
fn bootstrap(d: &Dir, kdc: &mut TestKdc, tiers: &TierMap, policy: &PolicySnapshot) -> Tgt {
    let error = error_of(send_with(
        d,
        kdc,
        tiers,
        policy,
        &as_req(ws01_name(), None),
        now(),
    ));
    assert_eq!(error.error_code, KDC_ERR_PREAUTH_REQUIRED);
    let methods = MethodData::decode(error.e_data.as_deref().unwrap()).unwrap();
    let types: Vec<i32> = methods.0.iter().map(|p| p.padata_type).collect();
    assert_eq!(
        types,
        vec![PA_FX_FAST, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, PA_FX_COOKIE]
    );
    let (etype, salt) = first_salt(&methods.0);
    let key = password_key(etype, WS01_PASSWORD, &salt);
    let request = as_req(ws01_name(), Some(vec![pa_enc_timestamp(&key, now())]));
    let rep =
        AsRep::decode(&sent(send_with(d, kdc, tiers, policy, &request, now()))).expect("an AS-REP");
    assert!(rep.0.padata.is_none());
    let part = EncAsRepPart::decode(&open(&key, 3, &rep.0.enc_part)).unwrap();
    Tgt {
        ticket: rep.0.ticket,
        cname: rep.0.cname,
        session: key_from(&part.0.key),
        salt,
    }
}

/// An armor (RFC 6113 5.4.1.1) on `tgt`: the AP-REQ — authenticator with a
/// fresh subkey, no checksum, key usage 11 (Q-120) — and the armor key.
fn armor(tgt: &Tgt, n: u32) -> (KrbFastArmor, ProtocolKey) {
    let mut subkey = [0xA9u8; 32];
    subkey[..4].copy_from_slice(&n.to_be_bytes());
    let authenticator = Authenticator {
        crealm: realm(),
        cname: tgt.cname.clone(),
        cksum: None,
        cusec: Microseconds::new(n).unwrap(),
        ctime: now(),
        subkey: Some(EncryptionKey {
            keytype: AES256,
            keyvalue: KeyValue::from_slice(&subkey),
        }),
        seq_number: None,
        authorization_data: None,
    }
    .encode()
    .unwrap();
    let ap_req = ApReq {
        ap_options: ApOptions::empty(),
        ticket: tgt.ticket.clone(),
        authenticator: seal(&tgt.session, 11, &authenticator),
    };
    let key = cf2(
        &aes256(&subkey),
        &tgt.session,
        b"subkeyarmor",
        b"ticketarmor",
    );
    (
        KrbFastArmor {
            armor_type: FX_FAST_ARMOR_AP_REQUEST,
            armor_value: ap_req.encode().unwrap(),
        },
        key,
    )
}

/// PA-FX-FAST: KrbFastArmoredReq with the req-checksum over `checksummed`
/// (usage 50) and the KrbFastReq sealed in the armor key (usage 51).
/// RFC 6113 5.4.2.
fn fx_fast(
    armor: Option<KrbFastArmor>,
    key: &ProtocolKey,
    checksummed: &[u8],
    fast_req: &KrbFastReq,
) -> PaData {
    PaData {
        padata_type: PA_FX_FAST,
        padata_value: PaFxFastRequest::ArmoredData(KrbFastArmoredReq {
            armor,
            req_checksum: mic(key, 50, checksummed),
            enc_fast_req: seal(key, 51, &fast_req.encode().unwrap()),
        })
        .encode()
        .unwrap(),
    }
}

/// An armored AS-REQ for `cname` under the armor on `armor_tgt` numbered
/// `n`, with the encrypted challenge of `long_term` if given (RFC 6113
/// 5.4.2, 5.4.6). Returns the request and the armor key.
fn armored_as_req(
    armor_tgt: &Tgt,
    n: u32,
    cname: PrincipalName,
    long_term: Option<&ProtocolKey>,
) -> (Vec<u8>, ProtocolKey) {
    let (field, key) = armor(armor_tgt, n);
    let body = as_body(cname, 0x0D1_0000 + n);
    let mut padata = Vec::new();
    if let Some(long_term) = long_term {
        let challenge_key = cf2(
            &key,
            long_term,
            b"clientchallengearmor",
            b"challengelongterm",
        );
        padata.push(PaData {
            padata_type: PA_ENCRYPTED_CHALLENGE,
            padata_value: seal(&challenge_key, 54, &timestamp(now()))
                .encode()
                .unwrap(),
        });
    }
    let fast_req = KrbFastReq {
        fast_options: FastOptions::empty(),
        padata,
        req_body: body.clone(),
    };
    let request = AsReq(KdcReq {
        padata: Some(vec![fx_fast(
            Some(field),
            &key,
            &body.encode().unwrap(),
            &fast_req,
        )]),
        req_body: body,
    })
    .encode()
    .unwrap();
    (request, key)
}

/// The KrbFastResponse of a PA-FX-FAST reply padata (armor key, usage 52).
/// RFC 6113 5.4.3.
fn fast_response(pa: &PaData, armor_key: &ProtocolKey) -> KrbFastResponse {
    assert_eq!(pa.padata_type, PA_FX_FAST);
    let PaFxFastReply::ArmoredData(rep) = PaFxFastReply::decode(&pa.padata_value).unwrap();
    KrbFastResponse::decode(&open(armor_key, 52, &rep.enc_fast_rep)).unwrap()
}

/// The KrbFastResponse of an armored KRB-ERROR (RFC 6113 5.4.4): e-data =
/// METHOD-DATA with one PA-FX-FAST; inside, PA-FX-ERROR = the outer error
/// without e-data; no strengthen-key, no finished.
fn armored_error(reply: KdcReply, armor_key: &ProtocolKey) -> (KrbError, KrbFastResponse) {
    let outer = error_of(reply);
    let methods = MethodData::decode(outer.e_data.as_deref().unwrap()).unwrap();
    assert_eq!(methods.0.len(), 1);
    let response = fast_response(&methods.0[0], armor_key);
    assert!(response.strengthen_key.is_none() && response.finished.is_none());
    let fx_error = response
        .padata
        .iter()
        .find(|p| p.padata_type == PA_FX_ERROR)
        .unwrap();
    let mut outer_fields = outer.clone();
    outer_fields.e_data = None;
    assert_eq!(
        KrbError::decode(&fx_error.padata_value).unwrap(),
        outer_fields
    );
    (outer, response)
}

/// KrbFastFinished: ticket-checksum over the Ticket DER (armor key, usage
/// 53, Q-122) and the names. RFC 6113 5.4.3.
fn check_finished(response: &KrbFastResponse, armor_key: &ProtocolKey, rep: &KdcRep) {
    let finished = response.finished.as_ref().expect("finished");
    krb_crypto::verify_mic(
        armor_key,
        armor_key.enc_type().checksum_type(),
        usage(53),
        &rep.ticket.encode().unwrap(),
        &finished.ticket_checksum.checksum,
    )
    .expect("ticket-checksum");
    assert_eq!(finished.cname, rep.cname);
}

/// alice's TGT, armored by `armor_tgt`: the armored PREAUTH_REQUIRED's
/// single PA-ETYPE-INFO2 entry (Q-123) gives the salt; the encrypted
/// challenge then gives an AS-REP that opens only under the strengthened
/// reply key (RFC 6113 5.4.3, 5.4.6).
fn alice_tgt(
    d: &Dir,
    kdc: &mut TestKdc,
    tiers: &TierMap,
    policy: &PolicySnapshot,
    armor_tgt: &Tgt,
    counter: &Cell<u32>,
) -> Tgt {
    let next = || {
        counter.set(counter.get() + 1);
        counter.get()
    };
    let (request, key) = armored_as_req(armor_tgt, next(), alice_name(), None);
    let reply = send_with(d, kdc, tiers, policy, &request, now());
    let (error, response) = armored_error(reply, &key);
    assert_eq!(error.error_code, KDC_ERR_PREAUTH_REQUIRED);
    let (etype, salt) = first_salt(&response.padata);
    let client_key = password_key(etype, ALICE_PASSWORD, &salt);

    let (request, armor_key) = armored_as_req(armor_tgt, next(), alice_name(), Some(&client_key));
    let rep =
        AsRep::decode(&sent(send_with(d, kdc, tiers, policy, &request, now()))).expect("an AS-REP");
    let padata = rep.0.padata.as_ref().unwrap();
    assert_eq!(padata.len(), 1);
    let response = fast_response(&padata[0], &armor_key);
    check_finished(&response, &armor_key, &rep.0);
    assert!(krb_crypto::decrypt(&client_key, usage(3), &rep.0.enc_part.cipher).is_err());
    let strengthen = key_from(response.strengthen_key.as_ref().unwrap());
    let reply_key = cf2(&strengthen, &client_key, b"strengthenkey", b"replykey");
    let part = EncAsRepPart::decode(&open(&reply_key, 3, &rep.0.enc_part)).unwrap();
    assert_eq!(rep.0.cname, alice_name());
    assert_eq!(part.0.sname, krbtgt_name());
    Tgt {
        ticket: rep.0.ticket,
        cname: rep.0.cname,
        session: key_from(&part.0.key),
        salt,
    }
}

/// alice's TGT with a fresh bootstrap of ws01$ under the allow-all policy.
fn obtain_tgt(d: &Dir, kdc: &mut TestKdc, tiers: &TierMap) -> Tgt {
    let machine = bootstrap(d, kdc, tiers, &policy());
    alice_tgt(d, kdc, tiers, &policy(), &machine, &Cell::new(0))
}

/// An armored TGS-REQ for `sname` at `ctime` (RFC 4120 5.4.1, 5.5.1;
/// RFC 6113 5.4.2): the authenticator — with the subkey — checksums the
/// outer KDC-REQ-BODY (usage 6) and is sealed with the TGT session key
/// (usage 7); PA-FX-FAST carries no armor field, its req-checksum covers the
/// PA-TGS-REQ AP-REQ, its KrbFastReq the inner body (= the outer one).
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
    let authenticator = Authenticator {
        crealm: realm(),
        cname: tgt.cname.clone(),
        cksum: Some(mic(&tgt.session, 6, &body_bytes)),
        cusec: Microseconds::new(7).unwrap(),
        ctime,
        subkey: Some(EncryptionKey {
            keytype: AES256,
            keyvalue: KeyValue::from_slice(&TGS_SUBKEY),
        }),
        seq_number: None,
        authorization_data: None,
    }
    .encode()
    .unwrap();
    let ap_req = ApReq {
        ap_options: ApOptions::empty(),
        ticket: tgt.ticket.clone(),
        authenticator: seal(&tgt.session, 7, &authenticator),
    }
    .encode()
    .unwrap();
    let fast_req = KrbFastReq {
        fast_options: FastOptions::empty(),
        padata: Vec::new(),
        req_body: body.clone(),
    };
    let armor_key = tgs_armor_key(tgt);
    TgsReq(KdcReq {
        padata: Some(vec![
            PaData {
                padata_type: PA_TGS_REQ,
                padata_value: ap_req.clone(),
            },
            fx_fast(None, &armor_key, &ap_req, &fast_req),
        ]),
        req_body: body,
    })
    .encode()
    .unwrap()
}

/// The implicit armor key of [`tgs_req`] (RFC 6113 5.4.2).
fn tgs_armor_key(tgt: &Tgt) -> ProtocolKey {
    cf2(
        &aes256(&TGS_SUBKEY),
        &tgt.session,
        b"subkeyarmor",
        b"ticketarmor",
    )
}

/// Open an armored TGS-REP: the reply key strengthened from the subkey
/// (usage 9, Q-121), KrbFastFinished checked. RFC 6113 5.4.3.
fn open_tgs_rep(bytes: &[u8], tgt: &Tgt) -> (TgsRep, EncTgsRepPart) {
    let rep = TgsRep::decode(bytes).expect("a TGS-REP");
    let armor_key = tgs_armor_key(tgt);
    let response = fast_response(&rep.0.padata.as_ref().unwrap()[0], &armor_key);
    check_finished(&response, &armor_key, &rep.0);
    let strengthen = key_from(response.strengthen_key.as_ref().expect("strengthen-key"));
    let reply_key = cf2(
        &strengthen,
        &aes256(&TGS_SUBKEY),
        b"strengthenkey",
        b"replykey",
    );
    let part = EncTgsRepPart::decode(&open(&reply_key, 9, &rep.0.enc_part)).unwrap();
    (rep, part)
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

/// docs/47 §8.1 / R47-14 end to end, armored (docs/48 §9.2): the bootstrap
/// of ws01$ (PREAUTH_REQUIRED with the [MS-KILE] 3.1.1.2 computer salt, then
/// a TGT), alice's armored AS (the armored PREAUTH_REQUIRED's single
/// ETYPE-INFO2 entry with the user salt, then a TGT) and the armored TGS (a
/// service ticket for the computer's SPN). The service ticket opens under
/// the key a host derives from its machine password and the computer salt
/// (docs/47 §3.3 item 2), and names alice. The PDP accepted a Subject whose
/// tier came from the same view (P3), here with alice's nested group mapped
/// to Tier1.
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
    let (rep, part) = open_tgs_rep(&bytes, &tgt);
    assert_eq!(rep.0.crealm, realm());
    assert_eq!(rep.0.cname, alice_name());
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
    // One audit event per request: ws01$ PREAUTH_REQUIRED and AS-REP, alice's
    // armored PREAUTH_REQUIRED and AS-REP, the TGS-REP.
    assert_eq!(kdc.audit_sink().events.len(), 5);
}

/// The full armored flow over the directory under `pdp::mandatory_fast_rules`
/// plus a broad grant (docs/48 §7.2, §9.2; P-10 interim; Q-130 — the
/// bootstrap set is a directory group, here "workstations" holding ws01$):
/// the computer bootstraps (objectClass computer → BootstrapAllowed, a
/// member of the bootstrap group), armors alice's AS, and alice's TGT gets a
/// service ticket armored. Then: alice unarmored gets only the FAST
/// advertisement; alice's TGT is no armor (D126); a disabled computer stops
/// armoring at once (D53).
#[test]
fn full_armored_flow_over_the_directory_with_mandatory_fast_rules() {
    let d = Dir::standard("fast-mandatory");
    d.create_all(vec![d.group(
        WORKSTATIONS,
        STAFF_OU,
        "workstations",
        GLOBAL_SECURITY,
        &[WS01],
    )]);
    let mut kdc = kdc_for(&d);
    let tiers = TierMap::empty();
    let policy = mandatory_fast_policy();
    let counter = Cell::new(0);

    let machine = bootstrap(&d, &mut kdc, &tiers, &policy);
    let alice = alice_tgt(&d, &mut kdc, &tiers, &policy, &machine, &counter);
    let bytes = sent(send_with(
        &d,
        &mut kdc,
        &tiers,
        &policy,
        &tgs_req(&alice, service_name(), now()),
        now(),
    ));
    let (rep, part) = open_tgs_rep(&bytes, &alice);
    assert_eq!(rep.0.cname, alice_name());
    assert_eq!(part.0.sname, service_name());
    let events = &kdc.audit_sink().events;
    assert_eq!(events.len(), 5);
    let armor = events[3].armor.principal.as_ref().unwrap();
    assert!(armor.is(&realm(), &ws01_name()));
    assert!(events[3].armor.reply_armored && events[4].armor.reply_armored);

    // Unarmored, alice is only told to use FAST (layer 1).
    let password = password_key(AES256, ALICE_PASSWORD, &alice.salt);
    let request = as_req(alice_name(), Some(vec![pa_enc_timestamp(&password, now())]));
    let error = error_of(send_with(&d, &mut kdc, &tiers, &policy, &request, now()));
    assert_eq!(error.error_code, KDC_ERR_PREAUTH_REQUIRED);
    let methods = MethodData::decode(error.e_data.as_deref().unwrap()).unwrap();
    let types: Vec<i32> = methods.0.iter().map(|p| p.padata_type).collect();
    assert_eq!(types, vec![PA_FX_FAST, PA_FX_COOKIE]);

    // alice's TGT as armor: refused, armored (D126).
    counter.set(counter.get() + 1);
    let (request, key) = armored_as_req(&alice, counter.get(), alice_name(), Some(&password));
    let (error, _) = armored_error(
        send_with(&d, &mut kdc, &tiers, &policy, &request, now()),
        &key,
    );
    assert_eq!(error.error_code, KDC_ERR_POLICY);

    // ws01$ disabled after its TGT was issued: its TGT no longer armors.
    d.set(
        WS01,
        "userAccountControl",
        vec![bits(
            uac::ADS_UF_WORKSTATION_TRUST_ACCOUNT | uac::ADS_UF_ACCOUNT_DISABLE,
        )],
    );
    counter.set(counter.get() + 1);
    let (request, key) = armored_as_req(&machine, counter.get(), alice_name(), Some(&password));
    let (error, _) = armored_error(
        send_with(&d, &mut kdc, &tiers, &policy, &request, now()),
        &key,
    );
    assert_eq!(error.error_code, KDC_ERR_POLICY);
}

/// docs/47 §4.5 (R47-7) end to end: a password set after the TGT's authtime
/// moves revoked_before past it, and the next (armored) TGS refuses the TGT
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

/// Q-965 (a) / A-161 end to end (docs/47 §4.5, R47-7; RFC 4120 3.3.3.1,
/// 5.2.3): a password set at the whole second of the TGT's authtime (`now`,
/// the form dird writes) revokes the TGT — the next armored TGS is
/// KDC_ERR_TGT_REVOKED. Under the former `ceil_s(pwdLastSet)` cut this TGT
/// survived. pwdLastSet = FILETIME of `now` = that of `now + 30 s` less
/// 30 × 10^7 ([MS-DTYP] 2.3.3; tests/common).
#[test]
fn a_password_set_in_the_tgts_second_revokes_it() {
    const NOW_FILETIME: i64 = NOW_PLUS_30_FILETIME - 30 * 10_000_000;
    let d = Dir::standard("tgt-revoked-same-second");
    let mut kdc = kdc_for(&d);
    let tiers = TierMap::empty();
    let tgt = obtain_tgt(&d, &mut kdc, &tiers);
    d.set(ALICE, "pwdLastSet", vec![int64(NOW_FILETIME)]);
    let error = error_of(send(
        &d,
        &mut kdc,
        &tiers,
        &tgs_req(&tgt, service_name(), at(1)),
        at(1),
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
/// unknown client (unarmored — the account lookup precedes the FAST gate);
/// a service name that only differs in case, or names the computer by its
/// sAMAccountName, is an unknown server (armored TGS).
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

/// Task K5 over the directory — docs/53 §5.2 ("an unarmored AS to
/// `kadmin/changepw` is refused for every principal"; "the TGS refuses the
/// name (KDC_ERR_POLICY)"); A-142; RFC 6113 5.2, 5.4.2: the same unarmored
/// AS-REQ of ws01$ — a computer that may bootstrap its TGT, so for krbtgt it
/// is offered PA-ENC-TIMESTAMP — is, for `kadmin/changepw`, answered with
/// the FAST-only KDC_ERR_PREAUTH_REQUIRED, and so is alice's; alice's
/// armored TGS for `kadmin/changepw` is an armored KDC_ERR_POLICY.
#[test]
fn the_change_password_service_over_the_directory() {
    let d = Dir::standard("changepw-kdc");
    let mut kdc = kdc_for(&d);
    let tiers = TierMap::empty();
    let changepw = name(KRB_NT_SRV_INST, &["kadmin", "changepw"]);
    for cname in [ws01_name(), alice_name()] {
        let request = AsReq(KdcReq {
            padata: None,
            req_body: KdcReqBody {
                sname: Some(changepw.clone()),
                ..as_body(cname, 0x0D1_4749)
            },
        })
        .encode()
        .unwrap();
        let error = error_of(send(&d, &mut kdc, &tiers, &request, now()));
        assert_eq!(error.error_code, KDC_ERR_PREAUTH_REQUIRED);
        let methods = MethodData::decode(error.e_data.as_deref().unwrap()).unwrap();
        let types: Vec<i32> = methods.0.iter().map(|p| p.padata_type).collect();
        assert_eq!(types, vec![PA_FX_FAST, PA_FX_COOKIE]);
    }
    let tgt = obtain_tgt(&d, &mut kdc, &tiers);
    let reply = send(&d, &mut kdc, &tiers, &tgs_req(&tgt, changepw, at(1)), at(1));
    let (error, _) = armored_error(reply, &tgs_armor_key(&tgt));
    assert_eq!(error.error_code, KDC_ERR_POLICY);
}
