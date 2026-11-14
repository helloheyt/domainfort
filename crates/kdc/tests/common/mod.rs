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
//! FAST (RFC 6113; docs/48): FAST is mandatory for every principal but a
//! computer account's bootstrap (docs/48 §7, P-10 interim). The fixture holds
//! one computer account, `ws1$` (random key from keyd's `create_key`, the
//! bootstrap exception), and gets its TGT through the unarmored AS path when
//! it is built; that TGT is the armor ticket of every armored AS request
//! (RFC 6113 5.4.1.1, D126). The client side of FAST is built here from
//! RFC 6113 only: the armor AP-REQ (authenticator key usage 11 —
//! docs/questions/Q-120 — with a fresh subkey per request and no checksum),
//! the armor key KRB-FX-CF2(subkey, ticket session key, "subkeyarmor",
//! "ticketarmor") (5.4.1.1), the req-checksum (usage 50) and enc-fast-req
//! (usage 51) (5.4.2), the encrypted challenge (5.4.6, usage 54), the implicit
//! TGS armor (5.4.2), and the opening of replies — KrbFastResponse (usage
//! 52), the strengthened reply key KRB-FX-CF2(strengthen-key, reply key,
//! "strengthenkey", "replykey") (5.4.3), KrbFastFinished's ticket-checksum
//! (usage 53, over the full Ticket DER — docs/questions/Q-122), the KDC's
//! encrypted challenge (usage 55) and the PA-FX-ERROR of armored errors
//! (5.4.4). RFC 6113 has no vectors for these derivations: these are
//! round-trip tests (docs/48 §9.2 item 15).
//!
//! Every value here is constructed by hand for these tests. No vector or
//! fixture comes from any other implementation.
#![allow(dead_code)] // each test binary uses a different subset

use dtyp::{Sid, SECURITY_NT_AUTHORITY};
use kdc::{
    AccountKind, AccountState, ArmorPolicy, AuditEvent, ClientAccount, InMemoryAccounts, Kdc,
    KdcConfig, KdcReply, KeyCustody, Peer, PolicyInputs, RateLimiter, ServiceAccount, Transport,
};
use keyd::{
    AuditRecord, CallerId, ConfigDescription, EncTypeId, EntropyError, EntropySource,
    InMemoryKeyStore, KeyHandle, KeyPurpose, Keyd, KeydConfig, LocalKeyd, PrincipalBinding,
    PrincipalId, Role, TicketPolicy,
};
use krb_crypto::{EncType, KeyUsage, ProtocolKey};
use krb_proto::constants::{
    FX_FAST_ARMOR_AP_REQUEST, KRB_NT_PRINCIPAL, KRB_NT_SRV_HST, KRB_NT_SRV_INST,
    PA_ENCRYPTED_CHALLENGE, PA_ENC_TIMESTAMP, PA_FX_ERROR, PA_FX_FAST, PA_TGS_REQ,
};
use krb_proto::{
    ApOptions, ApReq, AsRep, AsReq, Authenticator, Checksum, EncAsRepPart, EncTgsRepPart,
    EncTicketPart, EncryptedData, EncryptionKey, EtypeInfo2Entry, FastOptions, HostAddresses,
    KdcOptions, KdcRep, KdcReq, KdcReqBody, KerberosFlags, KerberosString, KerberosTime, KeyValue,
    KrbError, KrbFastArmor, KrbFastArmoredReq, KrbFastReq, KrbFastResponse, MethodData,
    Microseconds, PaData, PaEncTsEnc, PaFxFastReply, PaFxFastRequest, PrincipalName, Realm, TgsRep,
    TgsReq, Ticket,
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

/// The computer account's SID (hand-made RID).
pub fn machine_sid() -> Sid {
    nt_sid(&[21, 7, 8, 9, 1201])
}

/// The group named as the bootstrap set of `pdp::mandatory_fast_rules` in
/// these tests (Q-130: a deployment datum; hand-made RID).
pub fn bootstrap_group() -> Sid {
    nt_sid(&[21, 7, 8, 9, 1500])
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
/// The computer account's long-term key set (docs/47 §9.1: a computer client
/// is `(GUID, PrincipalLongterm)`).
pub const MACHINE: KeyHandle = KeyHandle::new(
    PrincipalId::from_bytes([0xC0; 16]),
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
/// The computer account's random key (keyd `create_key`, docs/48 §7.3: a
/// bootstrap account has a random key, not a human password).
pub const MACHINE_KEY: [u8; 32] = [0xE3; 32];
/// The default subkey of the TGS authenticators (mandatory under FAST,
/// RFC 6113 5.4.2).
pub const TGS_SUBKEY: [u8; 32] = [0x3A; 32];

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

/// The computer account's name (docs/47 §9.1: NT-PRINCIPAL, ending in "$").
pub fn machine_name() -> PrincipalName {
    name(KRB_NT_PRINCIPAL, &["ws1$"])
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

/// When the keyd behind the KDC started: the day before [`now`], so that
/// its startup hold-down (RFC 4120 3.2.3; docs/50 R50-6) is long over for
/// every test that is not about it.
pub fn keyd_started() -> KerberosTime {
    kt("20261112100000Z")
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

pub type TestKeyd = Keyd<InMemoryKeyStore, KeydAudit, TestEntropy>;

/// A keyd operation of the `Kdc` role, for [`TestCustody::unavailable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyOp {
    VerifyPreauth,
    IssueAsRep,
    OpenFastArmor,
    OpenAndVerifyTgt,
    IssueTgsRep,
    SealFastError,
}

/// The real keyd behind the KDC (`LocalKeyd`), with two test switches:
/// `refuse_seal` makes `seal_fast_error` fail as keyd does when the
/// conversation's token is gone (e.g. expired) — to exercise the KDC's
/// unarmored fallback (docs/questions/Q-125 item 10); `unavailable` makes the
/// listed operations answer `Unavailable` without reaching keyd, as the IPC
/// client must when keyd is down, the deadline passes or keyd is Busy
/// (docs/50 §3.7; A-56). TESTS ONLY.
pub struct TestCustody {
    pub inner: LocalKeyd<InMemoryKeyStore, KeydAudit, TestEntropy>,
    pub refuse_seal: bool,
    pub unavailable: Vec<CustodyOp>,
}

impl TestCustody {
    pub fn keyd(&self) -> &TestKeyd {
        self.inner.keyd()
    }

    pub fn keyd_mut(&mut self) -> &mut TestKeyd {
        self.inner.keyd_mut()
    }
}

impl TestCustody {
    fn down(&self, op: CustodyOp) -> bool {
        self.unavailable.contains(&op)
    }
}

impl KeyCustody for TestCustody {
    fn config(&self) -> &ConfigDescription {
        self.inner.config()
    }
    fn verify_preauth(
        &mut self,
        client: &KeyHandle,
        padata: &PaData,
        armor: Option<keyd::ArmorId>,
        now: &KerberosTime,
    ) -> Result<keyd::AuthnProof, keyd::AuthnError> {
        if self.down(CustodyOp::VerifyPreauth) {
            return Err(keyd::AuthnError::Unavailable);
        }
        self.inner.verify_preauth(client, padata, armor, now)
    }
    fn issue_as_rep(
        &mut self,
        client: &KeyHandle,
        krbtgt: &KeyHandle,
        proof: &keyd::AuthnProof,
        armor: Option<keyd::ArmorId>,
        template: &keyd::AsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<keyd::AsRepParts, keyd::IssueError> {
        if self.down(CustodyOp::IssueAsRep) {
            return Err(keyd::IssueError::Unavailable);
        }
        self.inner
            .issue_as_rep(client, krbtgt, proof, armor, template, now)
    }
    fn open_fast_armor(
        &mut self,
        krbtgt: &KeyHandle,
        armored_req: &KrbFastArmoredReq,
        outer_req_body: &[u8],
        now: &KerberosTime,
    ) -> Result<keyd::FastArmor, keyd::AuthnError> {
        if self.down(CustodyOp::OpenFastArmor) {
            return Err(keyd::AuthnError::Unavailable);
        }
        self.inner
            .open_fast_armor(krbtgt, armored_req, outer_req_body, now)
    }
    fn open_and_verify_tgt(
        &mut self,
        krbtgt: &KeyHandle,
        ap_req: &ApReq,
        req_body: &[u8],
        fast: Option<keyd::TgsFastRequest<'_>>,
        now: &KerberosTime,
    ) -> Result<keyd::TgtContext, keyd::AuthnError> {
        if self.down(CustodyOp::OpenAndVerifyTgt) {
            return Err(keyd::AuthnError::Unavailable);
        }
        self.inner
            .open_and_verify_tgt(krbtgt, ap_req, req_body, fast, now)
    }
    fn issue_tgs_rep(
        &mut self,
        service: &KeyHandle,
        ctx: &keyd::CtxId,
        template: &keyd::TgsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<keyd::TgsRepParts, keyd::IssueError> {
        if self.down(CustodyOp::IssueTgsRep) {
            return Err(keyd::IssueError::Unavailable);
        }
        self.inner.issue_tgs_rep(service, ctx, template, now)
    }
    fn seal_fast_error(
        &mut self,
        conversation: &keyd::FastConversation,
        error: &KrbError,
        padata: &[PaData],
        now: &KerberosTime,
    ) -> Result<EncryptedData, keyd::Error> {
        if self.down(CustodyOp::SealFastError) {
            return Err(keyd::Error::Unavailable);
        }
        if self.refuse_seal {
            return Err(keyd::Error::Denied);
        }
        self.inner.seal_fast_error(conversation, error, padata, now)
    }
}

pub type TestKdc = Kdc<TestCustody, KdcAudit, TestRateLimiter>;

/// The KDC, the policy inputs and the account source handed to it with each
/// request (docs/47 R47-14), the computer account's TGT (the armor ticket of
/// the armored AS requests, D126) and a counter that makes every armor fresh
/// (RFC 6113 5.4: "a fresh armor key for each conversation"; docs/48 §3.3: a
/// fresh armor AP-REQ per request).
pub struct Fixture {
    pub kdc: TestKdc,
    pub snapshot: PolicySnapshot,
    pub pip: TestPip,
    pub accounts: InMemoryAccounts,
    pub machine_tgt: Tgt,
    pub armor_counter: u32,
}

/// What a test may change before the KDC is built.
pub struct Setup {
    pub keyd: KeydConfig,
    pub kdc: KdcConfig,
    pub rules: Vec<Rule>,
    /// When keyd starts (default [`keyd_started`]: its hold-down is over).
    pub keyd_started: KerberosTime,
    /// The computer account's TGT, if a test brings one (from another
    /// fixture — the keys are the same scripted bytes): then the fixture
    /// does not obtain it through its own KDC, which a keyd still in its
    /// startup hold-down would refuse.
    pub machine_tgt: Option<Tgt>,
}

impl Setup {
    /// Two AES enctypes (aes256 preferred), RFC 4120 §8.2 default policy.
    pub fn new() -> Self {
        let mut keyd = KeydConfig::new(realm());
        keyd.enctypes = vec![
            EncTypeId::Aes256CtsHmacSha196,
            EncTypeId::Aes128CtsHmacSha196,
        ];
        Setup {
            keyd,
            kdc: KdcConfig::new(realm(), KRBTGT),
            rules: vec![allow_kerberos()],
            keyd_started: keyd_started(),
            machine_tgt: None,
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

/// alice: a user account, so FAST is required (docs/48 §7.1, the production
/// default).
pub fn alice_account() -> ClientAccount {
    ClientAccount {
        key: ALICE,
        sid: alice_sid(),
        groups: [users_group()].into_iter().collect(),
        tier: Tier::Tier2,
        state: AccountState::ACTIVE,
        etype_info: etype_info(ALICE_SALT),
        kind: AccountKind::User,
        armor_policy: ArmorPolicy::Required,
    }
}

/// ws1$: a computer account that may bootstrap (docs/48 §7.3), member of the
/// bootstrap group. Its keys are random (no salt is meaningful: the entries
/// carry none, RFC 4120 5.2.7.5 "salt OPTIONAL").
pub fn machine_account() -> ClientAccount {
    ClientAccount {
        key: MACHINE,
        sid: machine_sid(),
        groups: [bootstrap_group()].into_iter().collect(),
        tier: Tier::Tier2,
        state: AccountState::ACTIVE,
        etype_info: [AES256, AES128]
            .iter()
            .map(|e| EtypeInfo2Entry {
                etype: *e,
                salt: None,
                s2kparams: None,
            })
            .collect(),
        kind: AccountKind::Computer,
        armor_policy: ArmorPolicy::BootstrapAllowed,
    }
}

impl Fixture {
    pub fn new() -> Self {
        Setup::new().build()
    }

    fn from_setup(setup: Setup) -> Self {
        let entropy = TestEntropy::default();
        let store = InMemoryKeyStore::new_insecure_development_allowing_krbtgt(64);
        let mut keyd = Keyd::with_entropy(
            setup.keyd,
            store,
            KeydAudit::default(),
            entropy.clone(),
            &setup.keyd_started,
        )
        .unwrap();
        let n = now();
        let enctypes: Vec<EncType> = keyd
            .config()
            .enctypes
            .iter()
            .map(|e| EncType::from_number(e.number()).unwrap())
            .collect();
        for (handle, binding, key) in [
            (KRBTGT, krbtgt_name(), KRBTGT_KEY),
            (SERVICE, service_name(), SERVICE_KEY),
            (MACHINE, machine_name(), MACHINE_KEY),
        ] {
            for e in &enctypes {
                entropy.push(&key[..e.key_length()]);
            }
            keyd.create_key(
                &ADMIN,
                &handle,
                &PrincipalBinding::new(realm(), binding),
                &n,
            )
            .unwrap();
        }
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
                    kind: AccountKind::User,
                    armor_policy: ArmorPolicy::Required,
                },
            )
            .unwrap();
        accounts
            .insert_client(&realm(), &machine_name(), machine_account())
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

        let custody = TestCustody {
            inner: LocalKeyd::new(keyd, KDC_CALLER).unwrap(),
            refuse_seal: false,
            unavailable: Vec::new(),
        };
        let mut kdc = Kdc::new(
            setup.kdc,
            custody,
            KdcAudit::default(),
            TestRateLimiter::default(),
        )
        .unwrap();
        let pip = TestPip {
            tiers: [
                (alice_sid(), Tier::Tier2),
                (bob_sid(), Tier::Tier2),
                (machine_sid(), Tier::Tier2),
            ]
            .into_iter()
            .collect(),
        };

        // The computer account's TGT, through the unarmored bootstrap path
        // (docs/48 §7.3) under an allow-all policy of its own, whatever the
        // test's rules are — unless the test brought one; then every sink is
        // cleared so that each test sees only its own requests.
        let machine_tgt = match setup.machine_tgt {
            Some(tgt) => tgt,
            None => {
                let allow = snapshot(vec![allow_kerberos()]);
                let bootstrap = AsReqSpec::machine()
                    .with_timestamp(&machine_key(AES256))
                    .encode();
                let reply = kdc.handle(
                    &bootstrap,
                    Peer {
                        transport: Transport::Tcp,
                        src_net: IpScope::Internal,
                    },
                    n,
                    &PolicyInputs {
                        snapshot: &allow,
                        pip: &pip,
                    },
                    &accounts,
                );
                open_as_rep(&sent(reply), &machine_key(AES256))
            }
        };
        kdc.audit_sink_mut().events.clear();
        kdc.custody_mut()
            .keyd_mut()
            .audit_sink_mut()
            .records
            .clear();
        kdc.rate_limiter_mut().seen.clear();

        Fixture {
            kdc,
            snapshot: snapshot(setup.rules),
            pip,
            accounts,
            machine_tgt,
            armor_counter: 0,
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

    /// A fresh armor on the computer account's TGT at `when`.
    pub fn next_armor(&mut self, when: KerberosTime) -> Armor {
        self.armor_counter += 1;
        Armor::new(&self.machine_tgt, when, self.armor_counter)
    }

    /// A fresh armor on any TGT `tgt` (e.g. a user's — refused, D126).
    pub fn armor_on(&mut self, tgt: &Tgt, when: KerberosTime) -> Armor {
        self.armor_counter += 1;
        Armor::new(tgt, when, self.armor_counter)
    }

    /// The armored AS-REQ of `spec` at `when` under a fresh armor on the
    /// computer account's TGT, and that armor's key.
    pub fn fast_as_request(&mut self, spec: &AsReqSpec, when: KerberosTime) -> (Vec<u8>, Armor) {
        let armor = self.next_armor(when);
        (spec.encode_armored(&armor, when), armor)
    }

    /// Send `spec` as an armored AS-REQ (RFC 6113 5.4.2) at `when`.
    pub fn send_fast_at(
        &mut self,
        spec: &AsReqSpec,
        transport: Transport,
        when: KerberosTime,
    ) -> FastSent {
        let (request, armor) = self.fast_as_request(spec, when);
        FastSent {
            reply: self.send_at(&request, transport, when),
            armor_key: armor.key,
        }
    }

    /// Send `spec` as an armored AS-REQ over TCP at `now`.
    pub fn send_fast(&mut self, spec: &AsReqSpec) -> FastSent {
        self.send_fast_at(spec, Transport::Tcp, now())
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.kdc.audit_sink().events
    }

    pub fn keyd_records(&self) -> &[AuditRecord] {
        &self.kdc.custody().keyd().audit_sink().records
    }

    /// The keyd operations called so far, in order.
    pub fn keyd_ops(&self) -> Vec<keyd::Operation> {
        self.keyd_records().iter().map(|r| r.op).collect()
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

/// The error code of a `Send` reply that is a KRB-ERROR (for an armored
/// error, the outer one, whose fields "should be the same" as the
/// PA-FX-ERROR's — RFC 6113 5.4.4).
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

/// The computer account's random key of `etype` (keyd drew the scripted
/// MACHINE_KEY octets; random-to-key is the identity for AES, RFC 3962 §6).
pub fn machine_key(etype: i32) -> ProtocolKey {
    let e = enc_type(etype);
    krb_crypto::random_to_key(e, &MACHINE_KEY[..e.key_length()]).unwrap()
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

/// FastOptions with bit numbers `bits` set (RFC 6113 5.4.2; bit 0 = most
/// significant, X.680 22.4).
pub fn fast_options(bits: &[u32]) -> FastOptions {
    let mut raw = 0u32;
    for b in bits {
        raw |= 0x8000_0000 >> b;
    }
    FastOptions(KerberosFlags::from_bits(raw))
}

/// An AS-REQ under construction (RFC 4120 5.4.1). Unarmored, `padata` is the
/// request's padata. Armored ([`AsReqSpec::encode_armored`], RFC 6113
/// 5.4.2), `body()` is the INNER req-body, `inner_padata` (plus the
/// encrypted challenge when `challenge` is set) the KrbFastReq padata, and
/// `outer` — default: the inner body — the outer req-body; `padata` then
/// travels outside, next to PA-FX-FAST (and must be ignored, 5.4.5).
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
    /// The long-term key (enctype number, octets) of the encrypted
    /// challenge, if any (RFC 6113 5.4.6).
    pub challenge: Option<(i32, Vec<u8>)>,
    /// The challenge's timestamp (default: the time of sending).
    pub challenge_at: Option<KerberosTime>,
    pub fast_options: FastOptions,
    pub inner_padata: Vec<PaData>,
    pub outer: Option<KdcReqBody>,
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
            challenge: None,
            challenge_at: None,
            fast_options: FastOptions::empty(),
            inner_padata: Vec::new(),
            outer: None,
        }
    }

    /// The computer account asks for a TGT of the maximum life.
    pub fn machine() -> Self {
        AsReqSpec {
            cname: Some(machine_name()),
            till: till_max(),
            nonce: 0x0C0C_0C0C,
            ..AsReqSpec::alice()
        }
    }

    /// The request of [`AsReqSpec::alice`] for another client `cname` of
    /// `realm` (RFC 4120 §5.4.1: cname and realm name the client; the
    /// sname stays this realm's TGS, 7.3).
    pub fn for_client(realm: Realm, cname: PrincipalName) -> Self {
        AsReqSpec {
            cname: Some(cname),
            sname: Some(name(KRB_NT_SRV_INST, &["krbtgt", realm.as_str()])),
            realm,
            ..AsReqSpec::alice()
        }
    }

    /// The same request with a PA-ENC-TIMESTAMP made with `key` at `now`
    /// (the unarmored path).
    pub fn with_timestamp(self, key: &ProtocolKey) -> Self {
        self.with_timestamp_at(key, now())
    }

    /// The same request with a PA-ENC-TIMESTAMP made with `key` at `ts`
    /// (the unarmored path; RFC 4120 5.2.7.2: the client's current time).
    pub fn with_timestamp_at(mut self, key: &ProtocolKey, ts: KerberosTime) -> Self {
        self.padata = Some(vec![pa_enc_timestamp(key, ts)]);
        self
    }

    /// The same request, armored, with an encrypted challenge made with the
    /// long-term key `key` (RFC 6113 5.4.6).
    pub fn with_challenge(mut self, key: &ProtocolKey) -> Self {
        self.challenge = Some((key.enc_type().number(), key.octets().to_vec()));
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

    /// The unarmored AS-REQ.
    pub fn encode(&self) -> Vec<u8> {
        AsReq(KdcReq {
            padata: self.padata.clone(),
            req_body: self.body(),
        })
        .encode()
        .unwrap()
    }

    /// The KrbFastReq of the armored request under `armor` at `when`.
    /// Spec: RFC 6113 5.4.2, 5.4.6.
    pub fn fast_req(&self, armor_key: &ProtocolKey, when: KerberosTime) -> KrbFastReq {
        let mut padata = self.inner_padata.clone();
        if let Some((etype, octets)) = &self.challenge {
            let long_term = krb_crypto::random_to_key(enc_type(*etype), octets).unwrap();
            padata.push(encrypted_challenge(
                armor_key,
                &long_term,
                self.challenge_at.unwrap_or(when),
            ));
        }
        KrbFastReq {
            fast_options: self.fast_options,
            padata,
            req_body: self.body(),
        }
    }

    /// The armored AS-REQ under `armor` at `when` (RFC 6113 5.4.2): outer
    /// padata = [PA-FX-FAST, then `padata`], the req-checksum over the outer
    /// body's octets.
    pub fn encode_armored(&self, armor: &Armor, when: KerberosTime) -> Vec<u8> {
        let outer = self.outer.clone().unwrap_or_else(|| self.body());
        let outer_octets = outer.encode().unwrap();
        let fast_req = self.fast_req(&armor.key, when);
        let armored = armored_req(
            &armor.key,
            Some(armor.armor_field()),
            &outer_octets,
            &fast_req,
        );
        let mut padata = vec![fx_fast_padata(&armored)];
        padata.extend(self.padata.clone().unwrap_or_default());
        AsReq(KdcReq {
            padata: Some(padata),
            req_body: outer,
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

/// A TGT the client holds (and, when it came armored, the KrbFastResponse).
pub struct Tgt {
    pub rep: AsRep,
    pub part: EncAsRepPart,
    pub session: ProtocolKey,
    pub fast: Option<KrbFastResponse>,
}

/// Decode an unarmored AS-REP and open its enc-part with `key` (usage 3).
pub fn open_as_rep(bytes: &[u8], key: &ProtocolKey) -> Tgt {
    let rep = AsRep::decode(bytes).expect("an AS-REP");
    let part = EncAsRepPart::decode(&open(key, 3, &rep.0.enc_part)).unwrap();
    let session = key_from(&part.0.key);
    Tgt {
        rep,
        part,
        session,
        fast: None,
    }
}

/// alice's TGT through the KDC (armored, encrypted challenge; TCP, at
/// `now`).
pub fn obtain_tgt(f: &mut Fixture) -> Tgt {
    obtain_tgt_with(f, AsReqSpec::alice())
}

pub fn obtain_tgt_with(f: &mut Fixture, spec: AsReqSpec) -> Tgt {
    obtain_tgt_at(f, spec, now())
}

/// alice's TGT through an armored AS exchange at `when`.
pub fn obtain_tgt_at(f: &mut Fixture, spec: AsReqSpec, when: KerberosTime) -> Tgt {
    let key = alice_key(AES256);
    let fast = f.send_fast_at(&spec.with_challenge(&key), Transport::Tcp, when);
    open_fast_as_rep(&sent(fast.reply), &fast.armor_key, &key)
}

/// The TGT's own enc-part, opened with the krbtgt key (usage 2).
pub fn open_ticket(ticket: &Ticket, key: &ProtocolKey) -> EncTicketPart {
    EncTicketPart::decode(&open(key, 2, &ticket.enc_part)).unwrap()
}

// ---------------------------------------------------------------------------
// FAST, client side (RFC 6113).
// ---------------------------------------------------------------------------

/// KRB-FX-CF2 with the RFC 6113 peppers given.
pub fn cf2(k1: &ProtocolKey, k2: &ProtocolKey, p1: &[u8], p2: &[u8]) -> ProtocolKey {
    krb_crypto::krb_fx_cf2(k1, k2, p1, p2).unwrap()
}

/// An AES256 key from raw octets.
pub fn aes256(octets: &[u8; 32]) -> ProtocolKey {
    krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, octets).unwrap()
}

/// armor_key = KRB-FX-CF2(subkey, ticket_session_key, "subkeyarmor",
/// "ticketarmor"). Spec: RFC 6113 5.4.1.1 (also the implicit TGS armor key,
/// 5.4.2).
pub fn ticket_armor_key(subkey: &ProtocolKey, session: &ProtocolKey) -> ProtocolKey {
    cf2(subkey, session, b"subkeyarmor", b"ticketarmor")
}

/// The strengthened reply key: KRB-FX-CF2(strengthen-key, padata-reply-key,
/// "strengthenkey", "replykey"). Spec: RFC 6113 5.4.3.
pub fn strengthened(strengthen: &ProtocolKey, reply_key: &ProtocolKey) -> ProtocolKey {
    cf2(strengthen, reply_key, b"strengthenkey", b"replykey")
}

/// An FX_FAST_ARMOR_AP_REQUEST armor the client built, and its armor key.
pub struct Armor {
    pub ap_req: ApReq,
    pub key: ProtocolKey,
}

impl Armor {
    /// The armor AP-REQ on `tgt` at `ctime` (RFC 6113 5.4.1.1: "The subkey
    /// field in the AP-REQ MUST be present"): authenticator with the TGT's
    /// client, no checksum (Q-120 item 3), cusec `n` and a subkey derived
    /// from `n` (fresh per request), sealed in the TGT session key with key
    /// usage 11 (Q-120 item 1).
    pub fn new(tgt: &Tgt, ctime: KerberosTime, n: u32) -> Armor {
        let mut subkey = [0xA5u8; 32];
        subkey[..4].copy_from_slice(&n.to_be_bytes());
        let authenticator = Authenticator {
            crealm: tgt.rep.0.crealm.clone(),
            cname: tgt.rep.0.cname.clone(),
            cksum: None,
            cusec: Microseconds::new(n % 1_000_000).unwrap(),
            ctime,
            subkey: Some(EncryptionKey {
                keytype: AES256,
                keyvalue: KeyValue::from_slice(&subkey),
            }),
            seq_number: None,
            authorization_data: None,
        };
        let plain = authenticator.encode().unwrap();
        let ap_req = ApReq {
            ap_options: ApOptions::empty(),
            ticket: tgt.rep.0.ticket.clone(),
            authenticator: EncryptedData {
                etype: tgt.session.enc_type().number(),
                kvno: None,
                cipher: krb_crypto::encrypt(&tgt.session, usage(11), &[0x55; 16], &plain).unwrap(),
            },
        };
        let key = ticket_armor_key(&aes256(&subkey), &tgt.session);
        Armor { ap_req, key }
    }

    /// The KrbFastArmor field (RFC 6113 5.4.1, 5.4.1.1).
    pub fn armor_field(&self) -> KrbFastArmor {
        KrbFastArmor {
            armor_type: FX_FAST_ARMOR_AP_REQUEST,
            armor_value: self.ap_req.encode().unwrap(),
        }
    }
}

/// KrbFastArmoredReq: the req-checksum over `checksummed` (armor key, its
/// required checksum type, key usage 50) and enc-fast-req (armor key, key
/// usage 51). Spec: RFC 6113 5.4.2.
pub fn armored_req(
    armor_key: &ProtocolKey,
    armor: Option<KrbFastArmor>,
    checksummed: &[u8],
    fast_req: &KrbFastReq,
) -> KrbFastArmoredReq {
    let cksumtype = armor_key.enc_type().checksum_type();
    KrbFastArmoredReq {
        armor,
        req_checksum: Checksum {
            cksumtype: cksumtype.number(),
            checksum: krb_crypto::get_mic(armor_key, cksumtype, usage(50), checksummed).unwrap(),
        },
        enc_fast_req: EncryptedData {
            etype: armor_key.enc_type().number(),
            kvno: None,
            cipher: krb_crypto::encrypt(
                armor_key,
                usage(51),
                &[0x66; 16],
                &fast_req.encode().unwrap(),
            )
            .unwrap(),
        },
    }
}

/// The PA-FX-FAST padata of a request. Spec: RFC 6113 5.4.2.
pub fn fx_fast_padata(armored: &KrbFastArmoredReq) -> PaData {
    PaData {
        padata_type: PA_FX_FAST,
        padata_value: PaFxFastRequest::ArmoredData(armored.clone())
            .encode()
            .unwrap(),
    }
}

/// PA-ENCRYPTED-CHALLENGE: PA-ENC-TS-ENC at `ts` in the client challenge key
/// KRB-FX-CF2(armor_key, long_term_key, "clientchallengearmor",
/// "challengelongterm"), key usage 54, no kvno. Spec: RFC 6113 5.4.6.
pub fn encrypted_challenge(
    armor_key: &ProtocolKey,
    long_term: &ProtocolKey,
    ts: KerberosTime,
) -> PaData {
    let key = cf2(
        armor_key,
        long_term,
        b"clientchallengearmor",
        b"challengelongterm",
    );
    let plain = PaEncTsEnc {
        patimestamp: ts,
        pausec: Some(Microseconds::new(77).unwrap()),
    }
    .encode()
    .unwrap();
    PaData {
        padata_type: PA_ENCRYPTED_CHALLENGE,
        padata_value: EncryptedData {
            etype: key.enc_type().number(),
            kvno: None,
            cipher: krb_crypto::encrypt(&key, usage(54), &[0x77; 16], &plain).unwrap(),
        }
        .encode()
        .unwrap(),
    }
}

/// The reply of an armored request and the armor key its client derived.
pub struct FastSent {
    pub reply: KdcReply,
    pub armor_key: ProtocolKey,
}

/// Open the KrbFastResponse of a PA-FX-FAST reply padata with the armor key
/// (key usage 52). Spec: RFC 6113 5.4.3.
pub fn open_fast_response(pa: &PaData, armor_key: &ProtocolKey) -> KrbFastResponse {
    assert_eq!(pa.padata_type, PA_FX_FAST);
    let PaFxFastReply::ArmoredData(rep) = PaFxFastReply::decode(&pa.padata_value).unwrap();
    let plain = krb_crypto::decrypt(armor_key, usage(52), &rep.enc_fast_rep.cipher)
        .expect("enc-fast-rep opens with the armor key");
    KrbFastResponse::decode(&plain).unwrap()
}

/// `true` if the KrbFastResponse of `pa` decrypts under `key` (usage 52).
pub fn fast_response_opens_with(pa: &PaData, key: &ProtocolKey) -> bool {
    let PaFxFastReply::ArmoredData(rep) = PaFxFastReply::decode(&pa.padata_value).unwrap();
    krb_crypto::decrypt(key, usage(52), &rep.enc_fast_rep.cipher).is_ok()
}

/// Verify KrbFastFinished against the ticket of the reply: ticket-checksum
/// over the full Ticket DER (Q-122), armor key, its required checksum type,
/// key usage 53; and the names. Spec: RFC 6113 5.4.3.
pub fn check_finished(response: &KrbFastResponse, armor_key: &ProtocolKey, rep: &KdcRep) {
    let finished = response
        .finished
        .as_ref()
        .expect("finished: present in an AS-REP or a TGS-REP");
    krb_crypto::verify_mic(
        armor_key,
        armor_key.enc_type().checksum_type(),
        usage(53),
        &rep.ticket.encode().unwrap(),
        &finished.ticket_checksum.checksum,
    )
    .expect("ticket-checksum");
    assert_eq!(finished.crealm, rep.crealm);
    assert_eq!(finished.cname, rep.cname);
}

/// Decode an armored AS-REP and open it (RFC 6113 5.4.3, 5.4.6): the only
/// padata is PA-FX-FAST; the KrbFastResponse (armor key) carries the KDC's
/// encrypted challenge (usage 55 under KRB-FX-CF2(armor_key, client key,
/// "kdcchallengearmor", "challengelongterm")), the strengthen key and
/// KrbFastFinished; the enc-part opens (usage 3) only under the
/// strengthened reply key.
pub fn open_fast_as_rep(bytes: &[u8], armor_key: &ProtocolKey, client_key: &ProtocolKey) -> Tgt {
    let rep = AsRep::decode(bytes).expect("an AS-REP");
    let padata = rep.0.padata.as_ref().expect("PA-FX-FAST in the AS-REP");
    assert_eq!(padata.len(), 1, "only PA-FX-FAST outside (RFC 6113 5.4.5)");
    let response = open_fast_response(&padata[0], armor_key);
    let strengthen = key_from(response.strengthen_key.as_ref().expect("strengthen-key"));
    let reply_key = strengthened(&strengthen, client_key);
    let part = EncAsRepPart::decode(&open(&reply_key, 3, &rep.0.enc_part)).unwrap();
    assert_eq!(response.nonce, part.0.nonce);
    check_finished(&response, armor_key, &rep.0);
    let kdc_challenge = response
        .padata
        .iter()
        .find(|p| p.padata_type == PA_ENCRYPTED_CHALLENGE)
        .expect("the KDC's PA-ENCRYPTED-CHALLENGE");
    let kdc_key = cf2(
        armor_key,
        client_key,
        b"kdcchallengearmor",
        b"challengelongterm",
    );
    let challenge = EncryptedData::decode(&kdc_challenge.padata_value).unwrap();
    PaEncTsEnc::decode(&open(&kdc_key, 55, &challenge)).unwrap();
    let session = key_from(&part.0.key);
    Tgt {
        rep,
        part,
        session,
        fast: Some(response),
    }
}

/// An armored KRB-ERROR, opened (RFC 6113 5.4.4).
pub struct FastError {
    /// The outer KRB-ERROR.
    pub outer: KrbError,
    /// The PA-FX-ERROR's KRB-ERROR.
    pub inner: KrbError,
    /// The KrbFastResponse.
    pub response: KrbFastResponse,
}

impl FastError {
    /// The padata types of the KrbFastResponse, in order.
    pub fn padata_types(&self) -> Vec<i32> {
        self.response.padata.iter().map(|p| p.padata_type).collect()
    }

    /// The KrbFastResponse padata of `padata_type`.
    pub fn padata(&self, padata_type: i32) -> Option<&PaData> {
        self.response
            .padata
            .iter()
            .find(|p| p.padata_type == padata_type)
    }
}

/// The single PA-FX-FAST of an armored KRB-ERROR's e-data (METHOD-DATA).
pub fn error_fx_fast(error: &KrbError) -> PaData {
    let methods = MethodData::decode(error.e_data.as_deref().expect("e-data")).unwrap();
    assert_eq!(methods.0.len(), 1, "METHOD-DATA carries only PA-FX-FAST");
    methods.0[0].clone()
}

/// Open an armored KRB-ERROR with the armor key and check RFC 6113 5.4.3 /
/// 5.4.4: no strengthen-key, no finished; the PA-FX-ERROR is the outer
/// KRB-ERROR without e-data.
pub fn open_fast_error(reply: KdcReply, armor_key: &ProtocolKey) -> FastError {
    let outer = error_of(reply);
    let response = open_fast_response(&error_fx_fast(&outer), armor_key);
    assert!(response.strengthen_key.is_none(), "absent in KRB-ERROR");
    assert!(response.finished.is_none(), "absent in an error");
    let fx_error = response
        .padata
        .iter()
        .find(|p| p.padata_type == PA_FX_ERROR)
        .expect("PA-FX-ERROR");
    let inner = KrbError::decode(&fx_error.padata_value).unwrap();
    assert!(inner.e_data.is_none());
    let mut outer_fields = outer.clone();
    outer_fields.e_data = None;
    assert_eq!(inner, outer_fields, "all other fields are the same");
    FastError {
        outer,
        inner,
        response,
    }
}

// ---------------------------------------------------------------------------
// TGS (RFC 4120 5.4.1, 5.5.1; RFC 6113 5.4.2 implicit armor).
// ---------------------------------------------------------------------------

/// A TGS-REQ under construction. `body()` is the INNER req-body; `outer` —
/// default: the inner body — the outer one, which the authenticator checksum
/// covers (A-17, docs/questions/Q-124 item 1). Armored by default (implicit
/// armor, RFC 6113 5.4.2): the subkey is then mandatory. `crealm` / `cname`
/// name the client in the PA-TGS-REQ authenticator — "the same as those
/// described for the ticket" (RFC 4120 5.5.1) — alice by default
/// ([`TgsReqSpec::service`]); [`TgsReqSpec::for_client_of`] takes them from
/// the TGT the request is made with.
#[derive(Clone)]
pub struct TgsReqSpec {
    pub crealm: Realm,
    pub cname: PrincipalName,
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
    pub armored: bool,
    pub fast_options: FastOptions,
    pub outer: Option<KdcReqBody>,
}

impl TgsReqSpec {
    /// A service ticket for host/files.example.org until 17:00, asked by
    /// alice.
    pub fn service() -> Self {
        TgsReqSpec {
            crealm: realm(),
            cname: alice_name(),
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
            subkey: Some(TGS_SUBKEY),
            extra_padata: Vec::new(),
            enc_authorization_data: None,
            additional_tickets: None,
            armored: true,
            fast_options: FastOptions::empty(),
            outer: None,
        }
    }

    /// The same request made by the client of `tgt`: the authenticator's
    /// crealm and cname are the TGT's (RFC 4120 5.5.1; 3.3.1: the TGS-REQ
    /// carries the TGT and an authenticator of its client), and the request
    /// is for a service of that client's realm.
    pub fn for_client_of(mut self, tgt: &Tgt) -> Self {
        self.crealm = tgt.rep.0.crealm.clone();
        self.cname = tgt.rep.0.cname.clone();
        self.realm = tgt.rep.0.crealm.clone();
        self
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

    /// The outer req-body.
    pub fn outer_body(&self) -> KdcReqBody {
        self.outer.clone().unwrap_or_else(|| self.body())
    }

    /// The TGS-REQ octets and the exact outer KDC-REQ-BODY octets the
    /// authenticator checksum covers (RFC 4120 5.2.7.1).
    pub fn encode(&self, tgt: &Tgt) -> (Vec<u8>, Vec<u8>) {
        self.encode_with_ticket(&tgt.rep.0.ticket, &tgt.session)
    }

    pub fn encode_with_ticket(&self, ticket: &Ticket, session: &ProtocolKey) -> (Vec<u8>, Vec<u8>) {
        let body_bytes = self.outer_body().encode().unwrap();
        let auth = authenticator(session, self, &body_bytes);
        (self.request_with(ticket, session, auth), body_bytes)
    }

    /// The implicit armor key of this request on a TGT with `session`
    /// (RFC 6113 5.4.2). Without a subkey there is none; the session key
    /// then stands in so that the request is well-formed (keyd refuses it).
    pub fn armor_key(&self, session: &ProtocolKey) -> ProtocolKey {
        match &self.subkey {
            Some(subkey) => ticket_armor_key(&aes256(subkey), session),
            None => krb_crypto::random_to_key(session.enc_type(), session.octets()).unwrap(),
        }
    }

    /// The TGS-REQ for this spec with the authenticator `auth` (which may
    /// cover another body or be tampered with): PA-TGS-REQ, then — armored —
    /// PA-FX-FAST with no armor field, the req-checksum over the PA-TGS-REQ
    /// AP-REQ octets and the KrbFastReq of the inner body (RFC 6113 5.4.2),
    /// then `extra_padata`.
    pub fn request_with(
        &self,
        ticket: &Ticket,
        session: &ProtocolKey,
        auth: EncryptedData,
    ) -> Vec<u8> {
        let ap_req = ApReq {
            ap_options: ApOptions::empty(),
            ticket: ticket.clone(),
            authenticator: auth,
        };
        let ap_req_octets = ap_req.encode().unwrap();
        let mut padata = vec![PaData {
            padata_type: PA_TGS_REQ,
            padata_value: ap_req_octets.clone(),
        }];
        if self.armored {
            let fast_req = KrbFastReq {
                fast_options: self.fast_options,
                padata: Vec::new(),
                req_body: self.body(),
            };
            let armored = armored_req(&self.armor_key(session), None, &ap_req_octets, &fast_req);
            padata.push(fx_fast_padata(&armored));
        }
        padata.extend(self.extra_padata.iter().cloned());
        TgsReq(KdcReq {
            padata: Some(padata),
            req_body: self.outer_body(),
        })
        .encode()
        .unwrap()
    }
}

/// The PA-TGS-REQ authenticator (RFC 4120 5.5.1): the client named by the
/// spec's `crealm` / `cname`, checksum over the KDC-REQ-BODY octets keyed
/// with the session key (usage 6), the whole authenticator encrypted with
/// the session key (usage 7).
pub fn authenticator(session: &ProtocolKey, spec: &TgsReqSpec, body: &[u8]) -> EncryptedData {
    let cksumtype = session.enc_type().checksum_type();
    let a = Authenticator {
        crealm: spec.crealm.clone(),
        cname: spec.cname.clone(),
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

/// Decode an armored TGS-REP for `spec` on `tgt` and open it (RFC 6113
/// 5.4.3): the only padata is PA-FX-FAST; the KrbFastResponse (implicit
/// armor key) carries the inner nonce, the strengthen key ("MUST be set in a
/// TGS reply") and KrbFastFinished; the enc-part opens (usage 9,
/// docs/questions/Q-121) only under KRB-FX-CF2(strengthen-key, subkey,
/// "strengthenkey", "replykey").
pub fn open_tgs_rep(bytes: &[u8], tgt: &Tgt, spec: &TgsReqSpec) -> (TgsRep, EncTgsRepPart) {
    let rep = TgsRep::decode(bytes).expect("a TGS-REP");
    let padata = rep.0.padata.as_ref().expect("PA-FX-FAST in the TGS-REP");
    assert_eq!(padata.len(), 1);
    let armor_key = spec.armor_key(&tgt.session);
    let response = open_fast_response(&padata[0], &armor_key);
    assert_eq!(response.nonce, spec.nonce);
    let strengthen = key_from(response.strengthen_key.as_ref().expect("strengthen-key"));
    let subkey = aes256(&spec.subkey.expect("a subkey"));
    let reply_key = strengthened(&strengthen, &subkey);
    let part = EncTgsRepPart::decode(&open(&reply_key, 9, &rep.0.enc_part)).unwrap();
    assert_eq!(part.0.nonce, spec.nonce);
    check_finished(&response, &armor_key, &rep.0);
    (rep, part)
}

// ---------------------------------------------------------------------------
// The client/server exchange (RFC 4120 §3.2, §5.5.1).
// ---------------------------------------------------------------------------

/// A service ticket the client holds after a TGS exchange: the Ticket, its
/// session key from the opened enc-part (RFC 4120 §3.3.4 / 5.4.2: the key
/// field of EncTGSRepPart) and the client it was issued to (the reply's
/// crealm / cname, 5.4.2).
pub struct ServiceTicket {
    pub ticket: Ticket,
    pub session: ProtocolKey,
    pub crealm: Realm,
    pub cname: PrincipalName,
    pub authtime: KerberosTime,
}

/// The service ticket of an opened TGS-REP (see [`open_tgs_rep`]).
pub fn service_ticket(rep: &TgsRep, part: &EncTgsRepPart) -> ServiceTicket {
    ServiceTicket {
        ticket: rep.0.ticket.clone(),
        session: key_from(&part.0.key),
        crealm: rep.0.crealm.clone(),
        cname: rep.0.cname.clone(),
        authtime: part.0.authtime,
    }
}

impl ServiceTicket {
    /// A KRB_AP_REQ for the service, made at `ctime` / `cusec` (RFC 4120
    /// §3.2.2: "a new Authenticator from the system time and its name"; each
    /// authenticator used once — the caller varies `cusec`, §3.2.3): no
    /// ap-options, the ticket as issued, and the Authenticator — crealm and
    /// cname of the ticket's client, no checksum, no subkey, no sequence
    /// number (all OPTIONAL, 5.5.1) — encrypted in the ticket's session key
    /// with key usage 11 ("in normal application exchanges", 5.5.1; 7.5.1).
    pub fn ap_req(&self, ctime: KerberosTime, cusec: u32) -> Vec<u8> {
        let authenticator = Authenticator {
            crealm: self.crealm.clone(),
            cname: self.cname.clone(),
            cksum: None,
            cusec: Microseconds::new(cusec).unwrap(),
            ctime,
            subkey: None,
            seq_number: None,
            authorization_data: None,
        };
        let plain = authenticator.encode().unwrap();
        ApReq {
            ap_options: ApOptions::empty(),
            ticket: self.ticket.clone(),
            authenticator: EncryptedData {
                etype: self.session.enc_type().number(),
                kvno: None,
                cipher: krb_crypto::encrypt(&self.session, usage(11), &[0x4B; 16], &plain).unwrap(),
            },
        }
        .encode()
        .unwrap()
    }
}

/// `true` if `needle` occurs in `haystack`.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Keep the `KdcRep` type in use for test binaries that only inspect it.
pub fn kdc_rep_of(rep: &AsRep) -> &KdcRep {
    &rep.0
}
