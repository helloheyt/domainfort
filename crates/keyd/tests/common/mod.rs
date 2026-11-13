//! Shared fixtures for the keyd integration tests.
//!
//! The tests act as the KDC (calling keyd) and as the Kerberos client
//! (building PA-ENC-TIMESTAMP / authenticators and opening replies with
//! krb-crypto), following RFC 4120 §3.1, §3.3, §5.2.7.2, §5.5.1 and the key
//! usages of §7.5.1. Every value here is constructed by hand for these tests;
//! no vector comes from any other implementation.
#![allow(dead_code)] // each test binary uses a different subset

use keyd::{
    AsRepParts, AsTicketTemplate, AuditRecord, AuditSink, CallerId, EntropyError, EntropySource,
    InMemoryKeyStore, KeyHandle, KeyPurpose, Keyd, KeydConfig, PrincipalBinding, PrincipalId, Role,
    TgsTicketTemplate, TgtContext,
};
use krb_crypto::{ChecksumType, EncType, KeyUsage, ProtocolKey};
use krb_proto::constants::{
    FX_FAST_ARMOR_AP_REQUEST, KRB_NT_PRINCIPAL, KRB_NT_SRV_HST, KRB_NT_SRV_INST, PA_ENC_TIMESTAMP,
};
use krb_proto::{
    ApOptions, ApReq, Authenticator, Checksum, EncAsRepPart, EncryptedData, EncryptionKey,
    FastOptions, KdcOptions, KdcReqBody, KerberosString, KerberosTime, KeyValue, KrbError,
    KrbFastArmor, KrbFastArmoredReq, KrbFastReq, Microseconds, PaData, PaEncTsEnc, PrincipalName,
    Realm, Ticket, TicketFlags,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Deterministic entropy (TESTS ONLY — keyd::OsEntropy is the only production
// source, AGENTS.md §6).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct EntropyState {
    scripted: VecDeque<Vec<u8>>,
    counter: u64,
    fail: bool,
}

/// A deterministic, NON-cryptographic test source. A scripted chunk is used
/// when the next draw has exactly its length (so a test can know a key keyd
/// generates); otherwise bytes come from a counter. `set_fail(true)` makes
/// every draw fail, to exercise the fail-closed paths.
#[derive(Clone, Default)]
pub struct TestEntropy(Arc<Mutex<EntropyState>>);

impl TestEntropy {
    pub fn push(&self, bytes: &[u8]) {
        self.0.lock().unwrap().scripted.push_back(bytes.to_vec());
    }

    pub fn set_fail(&self, fail: bool) {
        self.0.lock().unwrap().fail = fail;
    }
}

impl EntropySource for TestEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        let mut state = self.0.lock().unwrap();
        if state.fail {
            return Err(EntropyError);
        }
        if state.scripted.front().is_some_and(|c| c.len() == out.len()) {
            let chunk = state.scripted.pop_front().unwrap();
            out.copy_from_slice(&chunk);
            return Ok(());
        }
        state.counter += 1;
        let c = state.counter.wrapping_mul(0x9E37_79B9);
        for (i, b) in out.iter_mut().enumerate() {
            *b = ((c >> ((i % 4) * 8)) as u8) ^ (i as u8).wrapping_mul(13) ^ 0x6B;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Audit collection.
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct CollectingAudit {
    pub records: Vec<AuditRecord>,
}

impl AuditSink for CollectingAudit {
    fn record(&mut self, record: &AuditRecord) {
        self.records.push(record.clone());
    }
}

pub type TestKeyd = Keyd<InMemoryKeyStore, CollectingAudit, TestEntropy>;

// ---------------------------------------------------------------------------
// Identities.
// ---------------------------------------------------------------------------

pub const REALM: &str = "EXAMPLE.ORG";

pub const KDC: CallerId = CallerId {
    uid: 100,
    role: Role::Kdc,
};
pub const KDC_OTHER: CallerId = CallerId {
    uid: 101,
    role: Role::Kdc,
};
pub const DIRECTORY: CallerId = CallerId {
    uid: 200,
    role: Role::Directory,
};
pub const ADMIN: CallerId = CallerId {
    uid: 300,
    role: Role::Admin,
};

pub const ALICE_ID: PrincipalId = PrincipalId::from_bytes([0xA1; 16]);
pub const BOB_ID: PrincipalId = PrincipalId::from_bytes([0xB0; 16]);
pub const KRBTGT_ID: PrincipalId = PrincipalId::from_bytes([0x7B; 16]);
pub const SERVICE_ID: PrincipalId = PrincipalId::from_bytes([0x5E; 16]);

pub const ALICE: KeyHandle = KeyHandle::new(ALICE_ID, KeyPurpose::PrincipalLongterm);
pub const BOB: KeyHandle = KeyHandle::new(BOB_ID, KeyPurpose::PrincipalLongterm);
pub const KRBTGT: KeyHandle = KeyHandle::new(KRBTGT_ID, KeyPurpose::Krbtgt);
pub const SERVICE: KeyHandle = KeyHandle::new(SERVICE_ID, KeyPurpose::Service);

/// Passwords and keys chosen for these tests; marker bytes easy to spot.
pub const ALICE_PASSWORD: &str = "correct horse battery staple";
pub const BOB_PASSWORD: &str = "tr0ub4dor&3";
pub const ALICE_SALT: &str = "EXAMPLE.ORGalice";
pub const BOB_SALT: &str = "EXAMPLE.ORGbob";
pub const KRBTGT_KEY: [u8; 32] = [0xC1; 32];
pub const SERVICE_KEY: [u8; 32] = [0xD2; 32];

pub fn realm() -> Realm {
    Realm::new(REALM).unwrap()
}

pub fn kstr(s: &str) -> KerberosString {
    KerberosString::new(s).unwrap()
}

pub fn alice_name() -> PrincipalName {
    PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("alice")],
    }
}

pub fn bob_name() -> PrincipalName {
    PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("bob")],
    }
}

/// RFC 4120 7.3: NT-SRV-INST ("krbtgt", realm).
pub fn krbtgt_name() -> PrincipalName {
    PrincipalName {
        name_type: KRB_NT_SRV_INST,
        name_string: vec![kstr("krbtgt"), kstr(REALM)],
    }
}

pub fn service_name() -> PrincipalName {
    PrincipalName {
        name_type: KRB_NT_SRV_HST,
        name_string: vec![kstr("host"), kstr("files.example.org")],
    }
}

/// A binding (Q-040, A-19) of `name` in the test realm.
pub fn bound(name: PrincipalName) -> PrincipalBinding {
    PrincipalBinding::new(realm(), name)
}

pub fn alice_binding() -> PrincipalBinding {
    bound(alice_name())
}

pub fn bob_binding() -> PrincipalBinding {
    bound(bob_name())
}

pub fn krbtgt_binding() -> PrincipalBinding {
    bound(krbtgt_name())
}

pub fn service_binding() -> PrincipalBinding {
    bound(service_name())
}

/// KerberosTime from `YYYYMMDDHHMMSSZ`.
pub fn kt(s: &str) -> KerberosTime {
    let d: Vec<u8> = s.bytes().take(14).map(|c| c - b'0').collect();
    let n2 = |i: usize| d[i] * 10 + d[i + 1];
    let year =
        u16::from(d[0]) * 1000 + u16::from(d[1]) * 100 + u16::from(d[2]) * 10 + u16::from(d[3]);
    KerberosTime::new(year, n2(4), n2(6), n2(8), n2(10), n2(12)).unwrap()
}

/// The test "now".
pub fn now() -> KerberosTime {
    kt("20261113100000Z")
}

/// `now` shifted by whole seconds (within the same day for these tests).
pub fn at(offset_secs: i64) -> KerberosTime {
    let total = 10 * 3600 + offset_secs;
    assert!((0..86_400).contains(&total), "offset outside the test day");
    let h = (total / 3600) as u8;
    let m = ((total % 3600) / 60) as u8;
    let s = (total % 60) as u8;
    KerberosTime::new(2026, 11, 13, h, m, s).unwrap()
}

// ---------------------------------------------------------------------------
// keyd under test.
// ---------------------------------------------------------------------------

/// One enctype (aes256-cts-hmac-sha1-96, etype 18) unless a test widens it.
pub fn config() -> KeydConfig {
    let mut c = KeydConfig::new(realm());
    c.enctypes = vec![EncType::Aes256CtsHmacSha196];
    c
}

pub struct Fixture {
    pub keyd: TestKeyd,
    pub entropy: TestEntropy,
}

impl Fixture {
    /// keyd with an insecure development store (holds krbtgt — tests only),
    /// with krbtgt and a service key created from known bytes, and alice /
    /// bob passwords set.
    pub fn new() -> Self {
        Self::with_config(config())
    }

    pub fn with_config(config: KeydConfig) -> Self {
        let entropy = TestEntropy::default();
        let store = InMemoryKeyStore::new_insecure_development_allowing_krbtgt(64);
        let mut keyd =
            Keyd::with_entropy(config, store, CollectingAudit::default(), entropy.clone()).unwrap();
        let n = now();
        let enctypes = keyd.config().enctypes.clone();
        for enctype in &enctypes {
            entropy.push(&KRBTGT_KEY[..enctype.key_length()]);
        }
        keyd.create_key(&ADMIN, &KRBTGT, &krbtgt_binding(), &n)
            .unwrap();
        for enctype in &enctypes {
            entropy.push(&SERVICE_KEY[..enctype.key_length()]);
        }
        keyd.create_key(&ADMIN, &SERVICE, &service_binding(), &n)
            .unwrap();
        keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            Zeroizing::new(ALICE_PASSWORD.to_owned()),
            ALICE_SALT,
            &n,
        )
        .unwrap();
        keyd.set_secret(
            &DIRECTORY,
            &BOB,
            &bob_binding(),
            Zeroizing::new(BOB_PASSWORD.to_owned()),
            BOB_SALT,
            &n,
        )
        .unwrap();
        keyd.audit_sink_mut().records.clear();
        Fixture { keyd, entropy }
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.keyd.audit_sink().records
    }
}

// ---------------------------------------------------------------------------
// Client side (RFC 4120 §3.1.1, §3.3.1, §5.2.7.2, §5.5.1).
// ---------------------------------------------------------------------------

pub fn usage(n: u32) -> KeyUsage {
    KeyUsage::new(n).unwrap()
}

/// The client's long-term key: string-to-key (RFC 3961 §3, RFC 3962 §4).
pub fn password_key(enctype: EncType, password: &str, salt: &str) -> ProtocolKey {
    krb_crypto::string_to_key(enctype, password, salt, None, 50_000).unwrap()
}

pub fn alice_key() -> ProtocolKey {
    password_key(EncType::Aes256CtsHmacSha196, ALICE_PASSWORD, ALICE_SALT)
}

pub fn krbtgt_key() -> ProtocolKey {
    krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &KRBTGT_KEY).unwrap()
}

pub fn service_key() -> ProtocolKey {
    krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &SERVICE_KEY).unwrap()
}

/// PA-ENC-TIMESTAMP (RFC 4120 5.2.7.2): PA-ENC-TS-ENC encrypted with the
/// client key, key usage 1, carried as PA-DATA type 2.
pub fn pa_enc_timestamp(key: &ProtocolKey, kvno: Option<u32>, ts: KerberosTime) -> PaData {
    let plain = PaEncTsEnc {
        patimestamp: ts,
        pausec: Some(Microseconds::new(1234).unwrap()),
    }
    .encode()
    .unwrap();
    let cipher = krb_crypto::encrypt(key, usage(1), &[0x33; 16], &plain).unwrap();
    let enc = EncryptedData {
        etype: key.enc_type().number(),
        kvno,
        cipher,
    };
    PaData {
        padata_type: PA_ENC_TIMESTAMP,
        padata_value: enc.encode().unwrap(),
    }
}

/// A valid AS template: an 8-hour TGT for alice.
pub fn as_template() -> AsTicketTemplate {
    AsTicketTemplate {
        client: ALICE_ID,
        crealm: realm(),
        cname: alice_name(),
        sname: krbtgt_name(),
        starttime: None,
        endtime: kt("20261113180000Z"),
        renew_till: None,
        flags: TicketFlags::empty(),
        session_enctype: EncType::Aes256CtsHmacSha196,
        nonce: 0x0102_0304,
    }
}

/// Decrypt an enc-part / ticket enc-part with `key` and `usage`.
pub fn open(key: &ProtocolKey, usage_number: u32, enc: &EncryptedData) -> Zeroizing<Vec<u8>> {
    krb_crypto::decrypt(key, usage(usage_number), &enc.cipher).unwrap()
}

/// The session key from an EncryptionKey.
pub fn key_from(ek: &EncryptionKey) -> ProtocolKey {
    let enctype = EncType::from_number(ek.keytype).unwrap();
    krb_crypto::random_to_key(enctype, ek.keyvalue.as_bytes()).unwrap()
}

/// A TGT obtained through keyd's AS path at `when`.
pub struct Tgt {
    pub parts: AsRepParts,
    pub rep: EncAsRepPart,
    pub session: ProtocolKey,
}

pub fn obtain_tgt(f: &mut Fixture, when: KerberosTime, template: &AsTicketTemplate) -> Tgt {
    let proof = f
        .keyd
        .verify_preauth(
            &KDC,
            &ALICE,
            &pa_enc_timestamp(&alice_key(), Some(1), when),
            &when,
        )
        .unwrap();
    let parts = f
        .keyd
        .issue_as_rep(&KDC, &ALICE, &KRBTGT, &proof, template, &when)
        .unwrap();
    let rep = EncAsRepPart::decode(&open(&alice_key(), 3, &parts.enc_part)).unwrap();
    let session = key_from(&rep.0.key);
    Tgt {
        parts,
        rep,
        session,
    }
}

/// A KDC-REQ-BODY for a service ticket and its exact DER octets.
pub fn tgs_req_body(nonce: u32, sname: PrincipalName) -> (KdcReqBody, Vec<u8>) {
    let body = KdcReqBody {
        kdc_options: KdcOptions::empty(),
        cname: None,
        realm: realm(),
        sname: Some(sname),
        from: None,
        till: kt("20261113170000Z"),
        rtime: None,
        nonce,
        etype: vec![18],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let bytes = body.encode().unwrap();
    (body, bytes)
}

/// The authenticator of a PA-TGS-REQ (RFC 4120 5.5.1): checksum over the
/// KDC-REQ-BODY octets keyed with the session key, usage 6; the whole
/// authenticator encrypted with the session key, usage 7.
pub struct AuthenticatorSpec<'a> {
    pub crealm: Realm,
    pub cname: PrincipalName,
    pub ctime: KerberosTime,
    pub cusec: u32,
    pub cksum_over: Option<&'a [u8]>,
    pub subkey: Option<&'a [u8; 32]>,
}

impl<'a> AuthenticatorSpec<'a> {
    pub fn new(ctime: KerberosTime, cusec: u32, body: &'a [u8]) -> Self {
        AuthenticatorSpec {
            crealm: realm(),
            cname: alice_name(),
            ctime,
            cusec,
            cksum_over: Some(body),
            subkey: None,
        }
    }
}

pub fn authenticator(session: &ProtocolKey, spec: &AuthenticatorSpec<'_>) -> EncryptedData {
    let cksum = spec.cksum_over.map(|body| Checksum {
        cksumtype: ChecksumType::HmacSha196Aes256.number(),
        checksum: krb_crypto::get_mic(session, ChecksumType::HmacSha196Aes256, usage(6), body)
            .unwrap(),
    });
    let a = Authenticator {
        crealm: spec.crealm.clone(),
        cname: spec.cname.clone(),
        cksum,
        cusec: Microseconds::new(spec.cusec).unwrap(),
        ctime: spec.ctime,
        subkey: spec.subkey.map(|k| EncryptionKey {
            keytype: 18,
            keyvalue: KeyValue::from_slice(k),
        }),
        seq_number: None,
        authorization_data: None,
    };
    let plain = a.encode().unwrap();
    EncryptedData {
        etype: session.enc_type().number(),
        kvno: None,
        cipher: krb_crypto::encrypt(session, usage(7), &[0x44; 16], &plain).unwrap(),
    }
}

pub fn ap_req(ticket: &Ticket, authenticator: EncryptedData) -> ApReq {
    ApReq {
        ap_options: ApOptions::empty(),
        ticket: ticket.clone(),
        authenticator,
    }
}

/// A valid TGS template for the service named in [`tgs_req_body`].
pub fn tgs_template(nonce: u32) -> TgsTicketTemplate {
    TgsTicketTemplate {
        sname: service_name(),
        starttime: Some(now()),
        endtime: kt("20261113170000Z"),
        renew_till: None,
        flags: TicketFlags::empty(),
        session_enctype: EncType::Aes256CtsHmacSha196,
        nonce,
    }
}

/// open_and_verify_tgt for a fresh authenticator over a fresh body.
pub fn open_tgt(f: &mut Fixture, tgt: &Tgt, nonce: u32, cusec: u32) -> TgtContext {
    let (_, body) = tgs_req_body(nonce, service_name());
    let auth = authenticator(&tgt.session, &AuthenticatorSpec::new(now(), cusec, &body));
    f.keyd
        .open_and_verify_tgt(
            &KDC,
            &KRBTGT,
            &ap_req(&tgt.parts.ticket, auth),
            &body,
            &now(),
        )
        .unwrap()
}

/// `true` if `needle` occurs in `haystack`.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// FAST client side (RFC 6113 §5.1, §5.4.1.1, §5.4.2; RFC 4120 §5.5.1),
// written from the RFC text for these tests. No vector comes from any other
// implementation; the computer account and its key are made up here.
// ---------------------------------------------------------------------------

/// A computer account (D126: the armor ticket is a computer TGT, docs/48
/// §3.1). keyd holds no account kind: to keyd it is a PrincipalLongterm key.
pub const WS01_ID: PrincipalId = PrincipalId::from_bytes([0xC0; 16]);
pub const WS01: KeyHandle = KeyHandle::new(WS01_ID, KeyPurpose::PrincipalLongterm);
/// The computer's random long-term key (docs/10 §7 `create_key` draws it;
/// the test scripts the entropy so the client side knows it).
pub const WS01_KEY: [u8; 32] = [0xE1; 32];

pub fn ws01_name() -> PrincipalName {
    PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("ws01$")],
    }
}

pub fn ws01_key() -> ProtocolKey {
    krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &WS01_KEY).unwrap()
}

/// Create the computer's key set through the Admin role.
pub fn add_computer(f: &mut Fixture) {
    f.entropy.push(&WS01_KEY);
    f.keyd
        .create_key(&ADMIN, &WS01, &bound(ws01_name()), &now())
        .unwrap();
    f.keyd.audit_sink_mut().records.clear();
}

/// The computer's TGT through keyd's existing AS path (PA-ENC-TIMESTAMP).
pub fn obtain_computer_tgt(f: &mut Fixture, when: KerberosTime, endtime: KerberosTime) -> Tgt {
    let proof = f
        .keyd
        .verify_preauth(
            &KDC,
            &WS01,
            &pa_enc_timestamp(&ws01_key(), Some(1), when),
            &when,
        )
        .unwrap();
    let template = AsTicketTemplate {
        client: WS01_ID,
        crealm: realm(),
        cname: ws01_name(),
        sname: krbtgt_name(),
        starttime: None,
        endtime,
        renew_till: None,
        flags: TicketFlags::empty(),
        session_enctype: EncType::Aes256CtsHmacSha196,
        nonce: 0x0C0C_0C0C,
    };
    let parts = f
        .keyd
        .issue_as_rep(&KDC, &WS01, &KRBTGT, &proof, &template, &when)
        .unwrap();
    let rep = EncAsRepPart::decode(&open(&ws01_key(), 3, &parts.enc_part)).unwrap();
    let session = key_from(&rep.0.key);
    Tgt {
        parts,
        rep,
        session,
    }
}

/// The armor AP-REQ authenticator (RFC 4120 5.5.1; RFC 6113 5.4.1.1): the
/// subkey "MUST be present"; key usage 11 (Q-120). `cksum_over`, when set,
/// adds a checksum (usage 10) — which phase 1 refuses.
pub struct ArmorAuthSpec {
    pub crealm: Realm,
    pub cname: PrincipalName,
    pub ctime: KerberosTime,
    pub cusec: u32,
    pub subkey: Option<[u8; 32]>,
    pub usage: u32,
    pub cksum_over: Option<Vec<u8>>,
}

impl ArmorAuthSpec {
    pub fn new(ctime: KerberosTime, cusec: u32, subkey: [u8; 32]) -> Self {
        ArmorAuthSpec {
            crealm: realm(),
            cname: ws01_name(),
            ctime,
            cusec,
            subkey: Some(subkey),
            usage: 11,
            cksum_over: None,
        }
    }
}

pub fn armor_authenticator(session: &ProtocolKey, spec: &ArmorAuthSpec) -> EncryptedData {
    let cksum = spec.cksum_over.as_ref().map(|data| Checksum {
        cksumtype: ChecksumType::HmacSha196Aes256.number(),
        checksum: krb_crypto::get_mic(session, ChecksumType::HmacSha196Aes256, usage(10), data)
            .unwrap(),
    });
    let a = Authenticator {
        crealm: spec.crealm.clone(),
        cname: spec.cname.clone(),
        cksum,
        cusec: Microseconds::new(spec.cusec).unwrap(),
        ctime: spec.ctime,
        subkey: spec.subkey.map(|k| EncryptionKey {
            keytype: 18,
            keyvalue: KeyValue::from_slice(&k),
        }),
        seq_number: None,
        authorization_data: None,
    };
    let plain = a.encode().unwrap();
    EncryptedData {
        etype: session.enc_type().number(),
        kvno: None,
        cipher: krb_crypto::encrypt(session, usage(spec.usage), &[0x55; 16], &plain).unwrap(),
    }
}

/// armor_key = KRB-FX-CF2(subkey, ticket_session_key, "subkeyarmor",
/// "ticketarmor") — RFC 6113 5.4.1.1.
pub fn client_armor_key(subkey: &[u8; 32], session: &ProtocolKey) -> ProtocolKey {
    let subkey = krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, subkey).unwrap();
    krb_crypto::krb_fx_cf2(&subkey, session, b"subkeyarmor", b"ticketarmor").unwrap()
}

/// An AS-REQ KDC-REQ-BODY for alice's TGT and its exact DER octets (used as
/// the outer body and as the inner req-body, RFC 6113 5.4.2).
pub fn as_req_body(nonce: u32) -> (KdcReqBody, Vec<u8>) {
    let body = KdcReqBody {
        kdc_options: KdcOptions::empty(),
        cname: Some(alice_name()),
        realm: realm(),
        sname: Some(krbtgt_name()),
        from: None,
        till: kt("20261113180000Z"),
        rtime: None,
        nonce,
        etype: vec![18],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let bytes = body.encode().unwrap();
    (body, bytes)
}

/// The KrbFastReq of an armored AS request (RFC 6113 5.4.2).
pub fn fast_req(inner_nonce: u32) -> KrbFastReq {
    KrbFastReq {
        fast_options: FastOptions::empty(),
        padata: Vec::new(),
        req_body: as_req_body(inner_nonce).0,
    }
}

/// req-checksum over `outer_body` (armor key, its required checksum type,
/// usage 50) and enc-fast-req (armor key, usage 51). RFC 6113 5.4.2.
pub fn armored_req(
    armor_ap_req: &ApReq,
    armor_key: &ProtocolKey,
    outer_body: &[u8],
    inner: &KrbFastReq,
) -> KrbFastArmoredReq {
    let req_checksum = Checksum {
        cksumtype: ChecksumType::HmacSha196Aes256.number(),
        checksum: krb_crypto::get_mic(
            armor_key,
            ChecksumType::HmacSha196Aes256,
            usage(50),
            outer_body,
        )
        .unwrap(),
    };
    let cipher =
        krb_crypto::encrypt(armor_key, usage(51), &[0x66; 16], &inner.encode().unwrap()).unwrap();
    KrbFastArmoredReq {
        armor: Some(KrbFastArmor {
            armor_type: FX_FAST_ARMOR_AP_REQUEST,
            armor_value: armor_ap_req.encode().unwrap(),
        }),
        req_checksum,
        enc_fast_req: EncryptedData {
            etype: armor_key.enc_type().number(),
            kvno: None,
            cipher,
        },
    }
}

/// A KRB-ERROR as the KDC builds it for alice's armored AS request
/// (crates/kdc krb_error.rs rule: no e-text, stime = now, names from the
/// request — here the inner one, docs/48 §8).
pub fn fast_krb_error(code: i32) -> KrbError {
    KrbError {
        ctime: None,
        cusec: None,
        stime: now(),
        susec: Microseconds::default(),
        error_code: code,
        crealm: Some(realm()),
        cname: Some(alice_name()),
        realm: realm(),
        sname: krbtgt_name(),
        e_text: None,
        e_data: None,
    }
}
