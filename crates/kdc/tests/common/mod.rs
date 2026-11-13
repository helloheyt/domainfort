//! Shared fixtures for the KDC integration tests.
//!
//! The tests drive the KDC through `Kdc::handle` exactly as a daemon would,
//! with the real keyd (insecure development store — tests only), the
//! in-memory account source and the real PDP. The test code also plays the
//! Kerberos CLIENT, using krb-crypto (a dev-dependency only, main-session
//! decision 2): it derives the client key from the password and the
//! ETYPE-INFO2 salt (RFC 3961 §3, RFC 3962 §4), builds PA-ENC-TIMESTAMP
//! (RFC 4120 5.2.7.2, key usage 1) and TGS authenticators (5.5.1, usages 6
//! and 7), and opens replies (usages 2, 3, 8, 9 — 7.5.1).
//!
//! Every value here is constructed by hand for these tests. No vector or
//! fixture comes from any other implementation.
#![allow(dead_code)] // each test binary uses a different subset

use dtyp::{Sid, SECURITY_NT_AUTHORITY};
use kdc::{
    AccountState, AuditEvent, ClientAccount, InMemoryAccounts, Kdc, KdcConfig, KdcReply, LocalKeyd,
    Peer, PolicyInputs, RateLimiter, ServiceAccount, Transport,
};
use keyd::{
    AuditRecord, CallerId, EntropyError, EntropySource, InMemoryKeyStore, KeyHandle, KeyPurpose,
    Keyd, KeydConfig, PrincipalBinding, PrincipalId, Role, TicketPolicy,
};
use krb_crypto::{EncType, KeyUsage, ProtocolKey};
use krb_proto::constants::{
    KRB_NT_PRINCIPAL, KRB_NT_SRV_HST, KRB_NT_SRV_INST, PA_ENC_TIMESTAMP, PA_TGS_REQ,
};
use krb_proto::{
    ApOptions, ApReq, AsRep, AsReq, Authenticator, Checksum, EncAsRepPart, EncTgsRepPart,
    EncTicketPart, EncryptedData, EncryptionKey, EtypeInfo2Entry, HostAddresses, KdcOptions,
    KdcRep, KdcReq, KdcReqBody, KerberosFlags, KerberosString, KerberosTime, KeyValue, KrbError,
    Microseconds, PaData, PaEncTsEnc, PrincipalName, Realm, TgsRep, TgsReq, Ticket,
};
use pdp::{
    ActionClass, ActionMatch, AuthMatch, ContextMatch, Effect, IpScope, Match, Pip, PipError,
    PolicySnapshot, PolicyVersion, ResourceMatch, RlKey, Rule, RuleId, SubjectMatch, Tier,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Deterministic entropy (TESTS ONLY — keyd::OsEntropy is the only production
// source, AGENTS.md §6).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct EntropyState {
    scripted: VecDeque<Vec<u8>>,
    counter: u64,
}

/// A deterministic, NON-cryptographic test source: a scripted chunk is used
/// when the next draw has exactly its length (so the tests know the keys keyd
/// creates); otherwise bytes come from a counter.
#[derive(Clone, Default)]
pub struct TestEntropy(Arc<Mutex<EntropyState>>);

impl TestEntropy {
    pub fn push(&self, bytes: &[u8]) {
        self.0.lock().unwrap().scripted.push_back(bytes.to_vec());
    }
}

impl EntropySource for TestEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        let mut state = self.0.lock().unwrap();
        if state.scripted.front().is_some_and(|c| c.len() == out.len()) {
            let chunk = state.scripted.pop_front().unwrap();
            out.copy_from_slice(&chunk);
            return Ok(());
        }
        state.counter += 1;
        let c = state.counter.wrapping_mul(0x9E37_79B9);
        for (i, b) in out.iter_mut().enumerate() {
            *b = ((c >> ((i % 4) * 8)) as u8) ^ (i as u8).wrapping_mul(29) ^ 0x5C;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Audit sinks and the rate limiter.
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct KeydAudit {
    pub records: Vec<AuditRecord>,
}

impl keyd::AuditSink for KeydAudit {
    fn record(&mut self, record: &AuditRecord) {
        self.records.push(record.clone());
    }
}

#[derive(Default)]
pub struct KdcAudit {
    pub events: Vec<AuditEvent>,
}

impl kdc::AuditSink for KdcAudit {
    fn record(&mut self, event: &AuditEvent) {
        self.events.push(event.clone());
    }
}

/// Admits everything unless `refuse` is set; records the keys it saw.
#[derive(Default)]
pub struct TestRateLimiter {
    pub refuse: bool,
    pub seen: Vec<RlKey>,
}

impl RateLimiter for TestRateLimiter {
    fn admit(&mut self, key: &RlKey, _now: &KerberosTime) -> bool {
        self.seen.push(key.clone());
        !self.refuse
    }
}

// ---------------------------------------------------------------------------
// The PIP: tiers of the test principals ([MS-DTYP] 2.4.2 SID layout,
// hand-made sub-authorities).
// ---------------------------------------------------------------------------

pub fn nt_sid(sub: &[u32]) -> Sid {
    Sid::new(SECURITY_NT_AUTHORITY, sub).unwrap()
}

pub fn alice_sid() -> Sid {
    nt_sid(&[21, 7, 8, 9, 1101])
}

pub fn bob_sid() -> Sid {
    nt_sid(&[21, 7, 8, 9, 1102])
}

pub fn users_group() -> Sid {
    nt_sid(&[21, 7, 8, 9, 513])
}

pub struct TestPip {
    pub tiers: BTreeMap<Sid, Tier>,
}

impl Pip for TestPip {
    fn expand_groups(&self, _p: &Sid) -> Result<BTreeSet<Sid>, PipError> {
        Err(PipError::NotFound)
    }
    fn tier_of(&self, p: &Sid, _g: &BTreeSet<Sid>) -> Result<Tier, PipError> {
        self.tiers.get(p).copied().ok_or(PipError::NotFound)
    }
    fn object_tier(&self, _r: &pdp::Resource) -> Result<Tier, PipError> {
        Err(PipError::NotFound)
    }
    fn security_descriptor(&self, _dn: &pdp::Dn) -> Result<dtyp::SecurityDescriptor, PipError> {
        Err(PipError::NotFound)
    }
    fn attr_class(&self, _a: &pdp::AttrId) -> Result<pdp::AttrClass, PipError> {
        Err(PipError::NotFound)
    }
    fn object_classes(&self, _dn: &pdp::Dn) -> Result<pdp::ObjClassChain, PipError> {
        Err(PipError::NotFound)
    }
    fn object_sid(&self, _dn: &pdp::Dn) -> Result<Option<Sid>, PipError> {
        Err(PipError::NotFound)
    }
    fn property_set(&self, _a: &pdp::AttrId) -> Result<Option<pdp::PropertySet>, PipError> {
        Err(PipError::NotFound)
    }
}

/// docs/11 §3: an Allow rule for every Kerberos action and subject.
pub fn allow_kerberos() -> Rule {
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

pub fn snapshot(rules: Vec<Rule>) -> PolicySnapshot {
    PolicySnapshot::new(PolicyVersion(1), rules, Vec::new())
}

// ---------------------------------------------------------------------------
// Identities.
// ---------------------------------------------------------------------------

pub const REALM: &str = "EXAMPLE.ORG";

pub const KDC_CALLER: CallerId = CallerId {
    uid: 100,
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

pub const ALICE: KeyHandle = KeyHandle::new(
    PrincipalId::from_bytes([0xA1; 16]),
    KeyPurpose::PrincipalLongterm,
);
pub const BOB: KeyHandle = KeyHandle::new(
    PrincipalId::from_bytes([0xB0; 16]),
    KeyPurpose::PrincipalLongterm,
);
pub const KRBTGT: KeyHandle =
    KeyHandle::new(PrincipalId::from_bytes([0x7B; 16]), KeyPurpose::Krbtgt);
pub const SERVICE: KeyHandle =
    KeyHandle::new(PrincipalId::from_bytes([0x5E; 16]), KeyPurpose::Service);

/// Passwords and keys chosen for these tests; marker bytes easy to spot.
pub const ALICE_PASSWORD: &str = "alice-clean-room-pass";
pub const BOB_PASSWORD: &str = "bob-clean-room-pass";
pub const ALICE_SALT: &str = "EXAMPLE.ORGalice";
pub const BOB_SALT: &str = "EXAMPLE.ORGbob";
pub const KRBTGT_KEY: [u8; 32] = [0xC7; 32];
pub const SERVICE_KEY: [u8; 32] = [0xD9; 32];

/// RFC 3961 §8 assigned numbers used as the client's "weak" offers: they are
/// not in keyd's AES list, so the KDC must never select them.
pub const DES_CBC_CRC: i32 = 1;
pub const DES_CBC_MD5: i32 = 3;
pub const DES3_CBC_SHA1_KD: i32 = 16;
pub const RC4_HMAC: i32 = 23;
/// RFC 3962 §7 numbers.
pub const AES128: i32 = 17;
pub const AES256: i32 = 18;

pub fn realm() -> Realm {
    Realm::new(REALM).unwrap()
}

pub fn kstr(s: &str) -> KerberosString {
    KerberosString::new(s).unwrap()
}

pub fn name(name_type: i32, parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type,
        name_string: parts.iter().map(|p| kstr(p)).collect(),
    }
}

pub fn alice_name() -> PrincipalName {
    name(KRB_NT_PRINCIPAL, &["alice"])
}

pub fn bob_name() -> PrincipalName {
    name(KRB_NT_PRINCIPAL, &["bob"])
}

/// RFC 4120 7.3: NT-SRV-INST ("krbtgt", realm).
pub fn krbtgt_name() -> PrincipalName {
    name(KRB_NT_SRV_INST, &["krbtgt", REALM])
}

pub fn service_name() -> PrincipalName {
    name(KRB_NT_SRV_HST, &["host", "files.example.org"])
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

/// `now` shifted by whole seconds within the same day.
pub fn at(offset_secs: i64) -> KerberosTime {
    let total = 10 * 3600 + offset_secs;
    assert!((0..86_400).contains(&total), "offset outside the test day");
    KerberosTime::new(
        2026,
        11,
        13,
        (total / 3600) as u8,
        ((total % 3600) / 60) as u8,
        (total % 60) as u8,
    )
    .unwrap()
}

/// RFC 4120 5.4.1: "19700101000000Z" = maximum endtime permitted.
pub fn till_max() -> KerberosTime {
    kt("19700101000000Z")
}

// ---------------------------------------------------------------------------
// The KDC under test.
// ---------------------------------------------------------------------------

pub type TestCustody = LocalKeyd<InMemoryKeyStore, KeydAudit, TestEntropy>;
pub type TestKdc = Kdc<TestCustody, KdcAudit, TestRateLimiter>;

/// The KDC, the policy inputs and the account source handed to it with each
/// request (docs/47 R47-14).
pub struct Fixture {
    pub kdc: TestKdc,
    pub snapshot: PolicySnapshot,
    pub pip: TestPip,
    pub accounts: InMemoryAccounts,
}

/// What a test may change before the KDC is built.
pub struct Setup {
    pub keyd: KeydConfig,
    pub kdc: KdcConfig,
    pub rules: Vec<Rule>,
}

impl Setup {
    /// Two AES enctypes (aes256 preferred), RFC 4120 §8.2 default policy.
    pub fn new() -> Self {
        let mut keyd = KeydConfig::new(realm());
        keyd.enctypes = vec![EncType::Aes256CtsHmacSha196, EncType::Aes128CtsHmacSha196];
        Setup {
            keyd,
            kdc: KdcConfig::new(realm(), KRBTGT),
            rules: vec![allow_kerberos()],
        }
    }

    pub fn ticket_policy(mut self, f: impl FnOnce(&mut TicketPolicy)) -> Self {
        f(&mut self.keyd.ticket_policy);
        self
    }

    pub fn build(self) -> Fixture {
        Fixture::from_setup(self)
    }
}

/// ETYPE-INFO2 entries of a password key set (RFC 4120 5.2.7.5): one per
/// configured enctype, the salt given to keyd, default s2kparams.
pub fn etype_info(salt: &str) -> Vec<EtypeInfo2Entry> {
    [AES256, AES128]
        .iter()
        .map(|e| EtypeInfo2Entry {
            etype: *e,
            salt: Some(kstr(salt)),
            s2kparams: None,
        })
        .collect()
}

pub fn alice_account() -> ClientAccount {
    ClientAccount {
        key: ALICE,
        sid: alice_sid(),
        groups: [users_group()].into_iter().collect(),
        tier: Tier::Tier2,
        state: AccountState::ACTIVE,
        etype_info: etype_info(ALICE_SALT),
    }
}

impl Fixture {
    pub fn new() -> Self {
        Setup::new().build()
    }

    fn from_setup(setup: Setup) -> Self {
        let entropy = TestEntropy::default();
        let store = InMemoryKeyStore::new_insecure_development_allowing_krbtgt(64);
        let mut keyd =
            Keyd::with_entropy(setup.keyd, store, KeydAudit::default(), entropy.clone()).unwrap();
        let n = now();
        let enctypes = keyd.config().enctypes.clone();
        for e in &enctypes {
            entropy.push(&KRBTGT_KEY[..e.key_length()]);
        }
        keyd.create_key(
            &ADMIN,
            &KRBTGT,
            &PrincipalBinding::new(realm(), krbtgt_name()),
            &n,
        )
        .unwrap();
        for e in &enctypes {
            entropy.push(&SERVICE_KEY[..e.key_length()]);
        }
        keyd.create_key(
            &ADMIN,
            &SERVICE,
            &PrincipalBinding::new(realm(), service_name()),
            &n,
        )
        .unwrap();
        for (handle, who, password, salt) in [
            (ALICE, alice_name(), ALICE_PASSWORD, ALICE_SALT),
            (BOB, bob_name(), BOB_PASSWORD, BOB_SALT),
        ] {
            keyd.set_secret(
                &DIRECTORY,
                &handle,
                &PrincipalBinding::new(realm(), who),
                String::from(password).into(),
                salt,
                &n,
            )
            .unwrap();
        }
        keyd.audit_sink_mut().records.clear();

        let mut accounts = InMemoryAccounts::new();
        accounts
            .insert_client(&realm(), &alice_name(), alice_account())
            .unwrap();
        accounts
            .insert_client(
                &realm(),
                &bob_name(),
                ClientAccount {
                    key: BOB,
                    sid: bob_sid(),
                    groups: BTreeSet::new(),
                    tier: Tier::Tier2,
                    state: AccountState::ACTIVE,
                    etype_info: etype_info(BOB_SALT),
                },
            )
            .unwrap();
        accounts
            .insert_service(
                &realm(),
                &service_name(),
                ServiceAccount {
                    key: SERVICE,
                    state: AccountState::ACTIVE,
                    enctypes: vec![AES256, AES128],
                },
            )
            .unwrap();

        let custody = LocalKeyd::new(keyd, KDC_CALLER).unwrap();
        let kdc = Kdc::new(
            setup.kdc,
            custody,
            KdcAudit::default(),
            TestRateLimiter::default(),
        )
        .unwrap();
        let pip = TestPip {
            tiers: [(alice_sid(), Tier::Tier2), (bob_sid(), Tier::Tier2)]
                .into_iter()
                .collect(),
        };
        Fixture {
            kdc,
            snapshot: snapshot(setup.rules),
            pip,
            accounts,
        }
    }

    /// One request at `when`.
    pub fn send_at(
        &mut self,
        request: &[u8],
        transport: Transport,
        when: KerberosTime,
    ) -> KdcReply {
        let inputs = PolicyInputs {
            snapshot: &self.snapshot,
            pip: &self.pip,
        };
        self.kdc.handle(
            request,
            Peer {
                transport,
                src_net: IpScope::Internal,
            },
            when,
            &inputs,
            &self.accounts,
        )
    }

    /// One request over TCP at `now`.
    pub fn send(&mut self, request: &[u8]) -> KdcReply {
        self.send_at(request, Transport::Tcp, now())
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.kdc.audit_sink().events
    }

    pub fn keyd_records(&self) -> &[AuditRecord] {
        &self.kdc.custody().keyd().audit_sink().records
    }

    pub fn accounts(&mut self) -> &mut InMemoryAccounts {
        &mut self.accounts
    }
}

// ---------------------------------------------------------------------------
// Replies.
// ---------------------------------------------------------------------------

/// The message of a `Send` reply.
pub fn sent(reply: KdcReply) -> Vec<u8> {
    match reply {
        KdcReply::Send(bytes) => bytes,
        other => panic!("expected Send, got {other:?}"),
    }
}

/// The KRB-ERROR of a `Send` reply.
pub fn error_of(reply: KdcReply) -> KrbError {
    KrbError::decode(&sent(reply)).expect("a KRB-ERROR")
}

/// The error code of a `Send` reply that is a KRB-ERROR.
pub fn code_of(reply: KdcReply) -> i32 {
    error_of(reply).error_code
}

// ---------------------------------------------------------------------------
// Client side (RFC 4120 §3.1.1, §3.3.1, §5.2.7.2, §5.5.1).
// ---------------------------------------------------------------------------

pub fn usage(n: u32) -> KeyUsage {
    KeyUsage::new(n).unwrap()
}

pub fn enc_type(number: i32) -> EncType {
    EncType::from_number(number).unwrap()
}

/// The client's long-term key: string-to-key (RFC 3961 §3, RFC 3962 §4).
pub fn password_key(etype: i32, password: &str, salt: &str) -> ProtocolKey {
    krb_crypto::string_to_key(enc_type(etype), password, salt, None, 50_000).unwrap()
}

pub fn alice_key(etype: i32) -> ProtocolKey {
    password_key(etype, ALICE_PASSWORD, ALICE_SALT)
}

pub fn krbtgt_key() -> ProtocolKey {
    krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &KRBTGT_KEY).unwrap()
}

pub fn service_key() -> ProtocolKey {
    krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &SERVICE_KEY).unwrap()
}

/// PA-ENC-TIMESTAMP (RFC 4120 5.2.7.2): PA-ENC-TS-ENC encrypted with the
/// client key, key usage 1, as PA-DATA type 2.
pub fn pa_enc_timestamp(key: &ProtocolKey, ts: KerberosTime) -> PaData {
    let plain = PaEncTsEnc {
        patimestamp: ts,
        pausec: Some(Microseconds::new(4321).unwrap()),
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

pub fn options(bits: &[u32]) -> KdcOptions {
    let mut raw = 0u32;
    for b in bits {
        raw |= 0x8000_0000 >> b;
    }
    KdcOptions(KerberosFlags::from_bits(raw))
}

/// An AS-REQ under construction (RFC 4120 5.4.1).
#[derive(Clone)]
pub struct AsReqSpec {
    pub cname: Option<PrincipalName>,
    pub realm: Realm,
    pub sname: Option<PrincipalName>,
    pub options: KdcOptions,
    pub from: Option<KerberosTime>,
    pub till: KerberosTime,
    pub rtime: Option<KerberosTime>,
    pub nonce: u32,
    pub etypes: Vec<i32>,
    pub padata: Option<Vec<PaData>>,
    pub addresses: Option<HostAddresses>,
}

impl AsReqSpec {
    /// alice asks for an 8-hour TGT, aes256 then aes128, without padata.
    pub fn alice() -> Self {
        AsReqSpec {
            cname: Some(alice_name()),
            realm: realm(),
            sname: Some(krbtgt_name()),
            options: KdcOptions::empty(),
            from: None,
            till: kt("20261113180000Z"),
            rtime: None,
            nonce: 0x1357_9BDF,
            etypes: vec![AES256, AES128],
            padata: None,
            addresses: None,
        }
    }

    /// The same request with a PA-ENC-TIMESTAMP made with `key` at `now`.
    pub fn with_timestamp(mut self, key: &ProtocolKey) -> Self {
        self.padata = Some(vec![pa_enc_timestamp(key, now())]);
        self
    }

    pub fn body(&self) -> KdcReqBody {
        KdcReqBody {
            kdc_options: self.options,
            cname: self.cname.clone(),
            realm: self.realm.clone(),
            sname: self.sname.clone(),
            from: self.from,
            till: self.till,
            rtime: self.rtime,
            nonce: self.nonce,
            etype: self.etypes.clone(),
            addresses: self.addresses.clone(),
            enc_authorization_data: None,
            additional_tickets: None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        AsReq(KdcReq {
            padata: self.padata.clone(),
            req_body: self.body(),
        })
        .encode()
        .unwrap()
    }
}

/// Decrypt an enc-part with `key` and `usage`.
pub fn open(key: &ProtocolKey, usage_number: u32, enc: &EncryptedData) -> Vec<u8> {
    krb_crypto::decrypt(key, usage(usage_number), &enc.cipher)
        .unwrap()
        .to_vec()
}

/// A session key from an EncryptionKey.
pub fn key_from(ek: &EncryptionKey) -> ProtocolKey {
    krb_crypto::random_to_key(enc_type(ek.keytype), ek.keyvalue.as_bytes()).unwrap()
}

/// A TGT the client holds.
pub struct Tgt {
    pub rep: AsRep,
    pub part: EncAsRepPart,
    pub session: ProtocolKey,
}

/// Decode an AS-REP and open its enc-part with `key` (usage 3).
pub fn open_as_rep(bytes: &[u8], key: &ProtocolKey) -> Tgt {
    let rep = AsRep::decode(bytes).expect("an AS-REP");
    let part = EncAsRepPart::decode(&open(key, 3, &rep.0.enc_part)).unwrap();
    let session = key_from(&part.0.key);
    Tgt { rep, part, session }
}

/// alice's TGT through the KDC (TCP, at `now`).
pub fn obtain_tgt(f: &mut Fixture) -> Tgt {
    obtain_tgt_with(f, AsReqSpec::alice())
}

pub fn obtain_tgt_with(f: &mut Fixture, spec: AsReqSpec) -> Tgt {
    let request = spec.with_timestamp(&alice_key(AES256)).encode();
    let bytes = sent(f.send(&request));
    open_as_rep(&bytes, &alice_key(AES256))
}

/// The TGT's own enc-part, opened with the krbtgt key (usage 2).
pub fn open_ticket(ticket: &Ticket, key: &ProtocolKey) -> EncTicketPart {
    EncTicketPart::decode(&open(key, 2, &ticket.enc_part)).unwrap()
}

/// A TGS-REQ under construction (RFC 4120 5.4.1, 5.5.1).
#[derive(Clone)]
pub struct TgsReqSpec {
    pub sname: Option<PrincipalName>,
    pub realm: Realm,
    pub options: KdcOptions,
    pub from: Option<KerberosTime>,
    pub till: KerberosTime,
    pub rtime: Option<KerberosTime>,
    pub nonce: u32,
    pub etypes: Vec<i32>,
    pub ctime: KerberosTime,
    pub cusec: u32,
    pub subkey: Option<[u8; 32]>,
    pub extra_padata: Vec<PaData>,
    pub enc_authorization_data: Option<EncryptedData>,
    pub additional_tickets: Option<Vec<Ticket>>,
}

impl TgsReqSpec {
    /// A service ticket for host/files.example.org until 17:00.
    pub fn service() -> Self {
        TgsReqSpec {
            sname: Some(service_name()),
            realm: realm(),
            options: KdcOptions::empty(),
            from: None,
            till: kt("20261113170000Z"),
            rtime: None,
            nonce: 0x2468_ACE0,
            etypes: vec![AES256, AES128],
            ctime: now(),
            cusec: 1,
            subkey: None,
            extra_padata: Vec::new(),
            enc_authorization_data: None,
            additional_tickets: None,
        }
    }

    pub fn body(&self) -> KdcReqBody {
        KdcReqBody {
            kdc_options: self.options,
            cname: None,
            realm: self.realm.clone(),
            sname: self.sname.clone(),
            from: self.from,
            till: self.till,
            rtime: self.rtime,
            nonce: self.nonce,
            etype: self.etypes.clone(),
            addresses: None,
            enc_authorization_data: self.enc_authorization_data.clone(),
            additional_tickets: self.additional_tickets.clone(),
        }
    }

    /// The TGS-REQ octets and the exact KDC-REQ-BODY octets the
    /// authenticator checksum covers (RFC 4120 5.2.7.1).
    pub fn encode(&self, tgt: &Tgt) -> (Vec<u8>, Vec<u8>) {
        self.encode_with_ticket(&tgt.rep.0.ticket, &tgt.session)
    }

    pub fn encode_with_ticket(&self, ticket: &Ticket, session: &ProtocolKey) -> (Vec<u8>, Vec<u8>) {
        let body = self.body();
        let body_bytes = body.encode().unwrap();
        let ap_req = ApReq {
            ap_options: ApOptions::empty(),
            ticket: ticket.clone(),
            authenticator: authenticator(session, self, &body_bytes),
        };
        let mut padata = vec![PaData {
            padata_type: PA_TGS_REQ,
            padata_value: ap_req.encode().unwrap(),
        }];
        padata.extend(self.extra_padata.iter().cloned());
        let request = TgsReq(KdcReq {
            padata: Some(padata),
            req_body: body,
        })
        .encode()
        .unwrap();
        (request, body_bytes)
    }
}

/// The PA-TGS-REQ authenticator (RFC 4120 5.5.1): checksum over the
/// KDC-REQ-BODY octets keyed with the session key (usage 6), the whole
/// authenticator encrypted with the session key (usage 7).
pub fn authenticator(session: &ProtocolKey, spec: &TgsReqSpec, body: &[u8]) -> EncryptedData {
    let cksumtype = session.enc_type().checksum_type();
    let a = Authenticator {
        crealm: realm(),
        cname: alice_name(),
        cksum: Some(Checksum {
            cksumtype: cksumtype.number(),
            checksum: krb_crypto::get_mic(session, cksumtype, usage(6), body).unwrap(),
        }),
        cusec: Microseconds::new(spec.cusec).unwrap(),
        ctime: spec.ctime,
        subkey: spec.subkey.map(|k| EncryptionKey {
            keytype: AES256,
            keyvalue: KeyValue::from_slice(&k),
        }),
        seq_number: None,
        authorization_data: None,
    };
    let plain = a.encode().unwrap();
    EncryptedData {
        etype: session.enc_type().number(),
        kvno: None,
        cipher: krb_crypto::encrypt(session, usage(7), &[0x47; 16], &plain).unwrap(),
    }
}

/// Decode a TGS-REP and open its enc-part with `key` and `usage` (8 for the
/// TGT session key, 9 for an authenticator subkey — RFC 4120 5.4.2).
pub fn open_tgs_rep(bytes: &[u8], key: &ProtocolKey, usage_number: u32) -> (TgsRep, EncTgsRepPart) {
    let rep = TgsRep::decode(bytes).expect("a TGS-REP");
    let part = EncTgsRepPart::decode(&open(key, usage_number, &rep.0.enc_part)).unwrap();
    (rep, part)
}

/// `true` if `needle` occurs in `haystack`.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Keep the `KdcRep` type in use for test binaries that only inspect it.
pub fn kdc_rep_of(rep: &AsRep) -> &KdcRep {
    &rep.0
}
