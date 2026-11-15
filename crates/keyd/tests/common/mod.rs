//! Shared fixtures for the keyd integration tests.
//!
//! The tests act as the KDC (calling keyd) and as the Kerberos client
//! (building PA-ENC-TIMESTAMP / authenticators and opening replies with
//! krb-crypto), following RFC 4120 §3.1, §3.3, §5.2.7.2, §5.5.1 and the key
//! usages of §7.5.1. Every value here is constructed by hand for these tests;
//! no vector comes from any other implementation.
#![allow(dead_code)] // each test binary uses a different subset

use keyd::{
    AccountKind, AsRepParts, AsTicketTemplate, AuditRecord, AuditSink, CallerId, DecidedOperation,
    DecisionId, EntropyError, EntropySource, InMemoryKeyStore, KeyHandle, KeyPurpose, KeyStore,
    Keyd, KeydConfig, PrincipalBinding, PrincipalId, Role, SetSecretTarget, TgsTicketTemplate,
    TgtContext, MAX_DESTROY_DECISION_SECS, MAX_INITIAL_SECRET_GRANT_SECS, MAX_KEY_DECISION_SECS,
    MAX_SET_SECRET_GRANT_SECS,
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Deterministic entropy (TESTS ONLY — keyd::OsEntropy is the only production
// source, docs/CLEAN-ROOM.md).
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
/// The LDAP front (docs/questions/Q-165 item 3, A-46).
pub const LDAP: CallerId = CallerId {
    uid: 400,
    role: Role::Ldap,
};
pub const LDAP_OTHER: CallerId = CallerId {
    uid: 401,
    role: Role::Ldap,
};

pub const ALICE_ID: PrincipalId = PrincipalId::from_bytes([0xA1; 16]);
pub const BOB_ID: PrincipalId = PrincipalId::from_bytes([0xB0; 16]);
pub const KRBTGT_ID: PrincipalId = PrincipalId::from_bytes([0x7B; 16]);
pub const SERVICE_ID: PrincipalId = PrincipalId::from_bytes([0x5E; 16]);

/// Two tier-0 administrators dird verified (the requester and the
/// approver of a dual-controlled key operation, docs/51 §5.6) — the
/// approvers a key-operation decision names (A-102). Made up here.
pub const APPROVER_1: PrincipalId = PrincipalId::from_bytes([0xAA; 16]);
pub const APPROVER_2: PrincipalId = PrincipalId::from_bytes([0xBB; 16]);

pub const ALICE: KeyHandle = KeyHandle::new(ALICE_ID, KeyPurpose::PrincipalLongterm);
pub const BOB: KeyHandle = KeyHandle::new(BOB_ID, KeyPurpose::PrincipalLongterm);
pub const KRBTGT: KeyHandle = KeyHandle::new(KRBTGT_ID, KeyPurpose::Krbtgt);
pub const SERVICE: KeyHandle = KeyHandle::new(SERVICE_ID, KeyPurpose::Service);

/// Passwords and keys chosen for these tests; marker bytes easy to spot.
pub const ALICE_PASSWORD: &str = "Quartz-Mill-74-Fern";
pub const BOB_PASSWORD: &str = "Harbor-Glint-39-Vole";
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

/// When the keyd under test started: the day before [`now`], so that its
/// startup hold-down (RFC 4120 3.2.3; docs/50 R50-6) is long over for every
/// test that is not about the hold-down.
pub fn keyd_started() -> KerberosTime {
    kt("20261112100000Z")
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
    c.enctypes = vec![keyd::EncTypeId::Aes256CtsHmacSha196];
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
        Self::started(config, &keyd_started())
    }

    /// As [`Fixture::with_config`], for a keyd that started at `started_at`
    /// (the startup hold-down tests). The keys are created and the passwords
    /// set at [`now`]: Admin and Directory operations are not held.
    pub fn started(config: KeydConfig, started_at: &KerberosTime) -> Self {
        let entropy = TestEntropy::default();
        let store = InMemoryKeyStore::new_insecure_development_allowing_krbtgt(64);
        let mut keyd = Keyd::with_entropy(
            config,
            store,
            CollectingAudit::default(),
            entropy.clone(),
            started_at,
        )
        .unwrap();
        let n = now();
        let enctypes: Vec<EncType> = keyd
            .config()
            .enctypes
            .iter()
            .map(|e| EncType::from_number(e.number()).unwrap())
            .collect();
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
        grant(&mut keyd, &ALICE, &alice_binding(), ALICE_SALT, &n).unwrap();
        keyd.set_secret(
            &DIRECTORY,
            &ALICE,
            &alice_binding(),
            Zeroizing::new(ALICE_PASSWORD.to_owned()),
            ALICE_SALT,
            &n,
        )
        .unwrap();
        grant(&mut keyd, &BOB, &bob_binding(), BOB_SALT, &n).unwrap();
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

    /// The ceremony's initial-secret grant of a user's one target
    /// (`grant_set_secret`, Role::Admin before the seal — docs/51 §4.3
    /// step 11, A-102) registered as `caller` (any role: a role that may not
    /// call it is refused, with its one record).
    pub fn grant_as(
        &mut self,
        caller: &CallerId,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
        salt: &str,
        now: &KerberosTime,
    ) -> Result<(), keyd::Error> {
        self.keyd.grant_set_secret(
            caller,
            AccountKind::User,
            &[SetSecretTarget {
                handle: *handle,
                binding: binding.clone(),
                salt: salt.to_owned(),
            }],
            MAX_INITIAL_SECRET_GRANT_SECS,
            now,
        )
    }

    /// [`grant`] on this fixture's keyd.
    pub fn grant(
        &mut self,
        handle: &KeyHandle,
        binding: &PrincipalBinding,
        salt: &str,
        now: &KerberosTime,
    ) -> Result<(), keyd::Error> {
        grant(&mut self.keyd, handle, binding, salt, now)
    }

    /// [`decide`] on this fixture's keyd.
    pub fn decide(
        &mut self,
        operation: DecidedOperation,
        now: &KerberosTime,
    ) -> Result<DecisionId, keyd::Error> {
        decide(&mut self.keyd, operation, now)
    }

    /// Whether `password` (with `salt`) is the current long-term key of the
    /// PrincipalLongterm key set `handle`: keyd's AS pre-authentication
    /// (PA-ENC-TIMESTAMP, RFC 4120 5.2.7.2) succeeds with the key derived
    /// from it (RFC 3961 §3). The oracle for "the password is (un)changed"
    /// since `verify_secret` has no role (A-102, docs/52 R4). A failure is
    /// counted by keyd's pre-authentication throttle (A-34).
    pub fn password_works(&mut self, handle: &KeyHandle, password: &str, salt: &str) -> bool {
        let enctype = EncType::from_number(self.keyd.config().enctypes[0].number()).unwrap();
        let key = password_key(enctype, password, salt);
        let n = now();
        self.keyd
            .verify_preauth(&KDC, handle, &pa_enc_timestamp(&key, None, n), None, &n)
            .is_ok()
    }
}

/// A fresh decision id for every decision a test registers (dird gives each
/// decision its own id — docs/52 §4.2).
pub fn next_decision_id() -> DecisionId {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    DecisionId::new(NEXT.fetch_add(1, Ordering::Relaxed))
}

/// The approvers dird records with `operation`: the dual-control pair for a
/// key operation (docs/51 §5.6), none for a password set or a destruction.
pub fn approvers_for(operation: &DecidedOperation) -> Vec<PrincipalId> {
    match operation {
        DecidedOperation::RotateKrbtgt { .. }
        | DecidedOperation::RotateKey { .. }
        | DecidedOperation::RetireKvno { .. } => vec![APPROVER_1, APPROVER_2],
        DecidedOperation::SetSecret { .. }
        | DecidedOperation::DestroyKeySet { .. }
        | DecidedOperation::ChangePassword { .. } => Vec::new(),
    }
}

/// The longest lifetime of `operation`'s family (docs/52 §4.2; keyd-types
/// decision.rs).
pub fn ceiling_for(operation: &DecidedOperation) -> u32 {
    match operation {
        DecidedOperation::SetSecret { .. } | DecidedOperation::ChangePassword { .. } => {
            MAX_SET_SECRET_GRANT_SECS
        }
        DecidedOperation::RotateKrbtgt { .. }
        | DecidedOperation::RotateKey { .. }
        | DecidedOperation::RetireKvno { .. } => MAX_KEY_DECISION_SECS,
        DecidedOperation::DestroyKeySet { .. } => MAX_DESTROY_DECISION_SECS,
    }
}

/// Register `operation` as dird would once its PDP decided it (Role::Ldap,
/// `register_decision` — A-102, docs/52 §4.2, §4.3): a fresh id, the
/// approvers of [`approvers_for`], the family's longest lifetime. Returns
/// the decision id the Admin operation then names.
pub fn decide<S: KeyStore, A: AuditSink, E: EntropySource>(
    keyd: &mut Keyd<S, A, E>,
    operation: DecidedOperation,
    now: &KerberosTime,
) -> Result<DecisionId, keyd::Error> {
    let id = next_decision_id();
    let approvers = approvers_for(&operation);
    let lifetime = ceiling_for(&operation);
    keyd.register_decision(&LDAP, id, &operation, &approvers, lifetime, now)
        .map(|()| id)
}

/// The name of the computer account a Service key set's grant pairs it
/// with ([`grant`]); test data.
pub fn grant_computer_name() -> PrincipalName {
    PrincipalName {
        name_type: KRB_NT_PRINCIPAL,
        name_string: vec![kstr("granted$")],
    }
}

/// Register, as dird would after its PDP allowed the password set
/// (Role::Ldap; task A15a, docs/51 §5.8 option (b); A-102: a `SetSecret`
/// decision), the decision that a `set_secret` of `handle` with `binding`
/// and `salt` needs (N4: the salt is bound too): a user's one key target for
/// a PrincipalLongterm handle; for a Service handle, a computer's two — its
/// PrincipalLongterm key set (named [`grant_computer_name`]; a decision does
/// not judge bindings, the redeeming `set_secret` does) and then the Service
/// key set. Any other purpose is refused by keyd (the purposes of the
/// grant's slots).
pub fn grant<S: KeyStore, A: AuditSink, E: EntropySource>(
    keyd: &mut Keyd<S, A, E>,
    handle: &KeyHandle,
    binding: &PrincipalBinding,
    salt: &str,
    now: &KerberosTime,
) -> Result<(), keyd::Error> {
    let target = SetSecretTarget {
        handle: *handle,
        binding: binding.clone(),
        salt: salt.to_owned(),
    };
    let operation = match handle.purpose {
        KeyPurpose::Service => {
            let account = KeyHandle::new(handle.principal, KeyPurpose::PrincipalLongterm);
            DecidedOperation::SetSecret {
                kind: AccountKind::Computer,
                targets: vec![
                    SetSecretTarget {
                        handle: account,
                        binding: bound(grant_computer_name()),
                        salt: salt.to_owned(),
                    },
                    target,
                ],
            }
        }
        _ => DecidedOperation::SetSecret {
            kind: AccountKind::User,
            targets: vec![target],
        },
    };
    decide(keyd, operation, now).map(|_| ())
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
        session_enctype: keyd::EncTypeId::Aes256CtsHmacSha196,
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
            None,
            &when,
        )
        .unwrap();
    let parts = f
        .keyd
        .issue_as_rep(&KDC, &ALICE, &KRBTGT, &proof, None, template, &when)
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
        session_enctype: keyd::EncTypeId::Aes256CtsHmacSha196,
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
            None,
            &now(),
        )
        .unwrap()
}

/// `true` if `needle` occurs in `haystack`.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// The DC's LDAP service (docs/49 §3.3; docs/questions/Q-165 item 4, A-46): a
// dedicated Service key set with one name, created by the Admin role with a
// random key. The tests script that key's entropy only so that they can play
// a compromised KDC (forging tickets under it) — keyd never returns it. The
// name and key bytes are made up for these tests.
// ---------------------------------------------------------------------------

pub const LDAP_SERVICE_ID: PrincipalId = PrincipalId::from_bytes([0x1D; 16]);
pub const LDAP_SERVICE: KeyHandle = KeyHandle::new(LDAP_SERVICE_ID, KeyPurpose::Service);
pub const LDAP_SERVICE_KEY: [u8; 32] = [0xF3; 32];

/// RFC 4120 6.2.1 (NT-SRV-INST): ("ldap", "dc01.example.org").
pub fn ldap_service_name() -> PrincipalName {
    PrincipalName {
        name_type: KRB_NT_SRV_INST,
        name_string: vec![kstr("ldap"), kstr("dc01.example.org")],
    }
}

pub fn ldap_service_key() -> ProtocolKey {
    krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &LDAP_SERVICE_KEY).unwrap()
}

/// Create the LDAP service key set through `create_key` (Admin).
pub fn add_ldap_service(f: &mut Fixture) {
    f.entropy.push(&LDAP_SERVICE_KEY);
    f.keyd
        .create_key(&ADMIN, &LDAP_SERVICE, &bound(ldap_service_name()), &now())
        .unwrap();
    f.keyd.audit_sink_mut().records.clear();
}

// ---------------------------------------------------------------------------
// The DC's admin service (A-73; docs/52 §5, R2): its own key purpose,
// `AdminService`, bound to ("admind", host), drawn by `create_key`. The key
// bytes and the host name are made up for these tests.
// ---------------------------------------------------------------------------

pub const ADMIN_SERVICE_ID: PrincipalId = PrincipalId::from_bytes([0xAD; 16]);
pub const ADMIN_SERVICE: KeyHandle = KeyHandle::new(ADMIN_SERVICE_ID, KeyPurpose::AdminService);
pub const ADMIN_SERVICE_KEY: [u8; 32] = [0xA5; 32];

/// RFC 4120 6.2.1 (NT-SRV-HST): ("admind", "dc01.example.org") — A-73.
pub fn admin_service_name() -> PrincipalName {
    PrincipalName {
        name_type: KRB_NT_SRV_HST,
        name_string: vec![kstr(keyd::ADMIN_SERVICE_CLASS), kstr("dc01.example.org")],
    }
}

pub fn admin_service_key() -> ProtocolKey {
    krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &ADMIN_SERVICE_KEY).unwrap()
}

/// Create the admin service key set through `create_key` (Admin, the
/// ceremony — docs/51 §4.3 step 11).
pub fn add_admin_service(f: &mut Fixture) {
    f.entropy.push(&ADMIN_SERVICE_KEY);
    f.keyd
        .create_key(&ADMIN, &ADMIN_SERVICE, &bound(admin_service_name()), &now())
        .unwrap();
    f.keyd.audit_sink_mut().records.clear();
}

// ---------------------------------------------------------------------------
// The DC's change-password service (task K3; RFC 3244 §2; docs/53 §5.2): its
// own key purpose, `ChangePasswordService`, bound to ("kadmin", "changepw"),
// drawn by `create_key`. The key bytes are made up for these tests.
// ---------------------------------------------------------------------------

pub const CHANGE_PASSWORD_SERVICE_ID: PrincipalId = PrincipalId::from_bytes([0xCF; 16]);
pub const CHANGE_PASSWORD_SERVICE: KeyHandle = KeyHandle::new(
    CHANGE_PASSWORD_SERVICE_ID,
    KeyPurpose::ChangePasswordService,
);
pub const CHANGE_PASSWORD_SERVICE_KEY: [u8; 32] = [0xC4; 32];

/// RFC 3244 §2: "kadmin/changepw@REALM" (NT-SRV-INST, RFC 4120 6.2.1).
pub fn change_password_service_name() -> PrincipalName {
    PrincipalName {
        name_type: KRB_NT_SRV_INST,
        name_string: vec![kstr("kadmin"), kstr("changepw")],
    }
}

/// The change-password service key of `enctype` (its first K octets).
pub fn change_password_service_key(enctype: EncType) -> ProtocolKey {
    krb_crypto::random_to_key(
        enctype,
        &CHANGE_PASSWORD_SERVICE_KEY[..enctype.key_length()],
    )
    .unwrap()
}

/// Create the change-password service key set through `create_key`
/// (Admin, the ceremony — docs/53 §5.2), one key per configured enctype.
pub fn add_change_password_service(f: &mut Fixture) {
    let enctypes: Vec<EncType> = f
        .keyd
        .config()
        .enctypes
        .iter()
        .map(|e| EncType::from_number(e.number()).unwrap())
        .collect();
    for enctype in &enctypes {
        f.entropy
            .push(&CHANGE_PASSWORD_SERVICE_KEY[..enctype.key_length()]);
    }
    f.keyd
        .create_key(
            &ADMIN,
            &CHANGE_PASSWORD_SERVICE,
            &bound(change_password_service_name()),
            &now(),
        )
        .unwrap();
    f.keyd.audit_sink_mut().records.clear();
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
            None,
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
        session_enctype: keyd::EncTypeId::Aes256CtsHmacSha196,
        nonce: 0x0C0C_0C0C,
    };
    let parts = f
        .keyd
        .issue_as_rep(&KDC, &WS01, &KRBTGT, &proof, None, &template, &when)
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
