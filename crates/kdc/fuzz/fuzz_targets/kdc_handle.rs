#![no_main]
//! Fuzz target for the KDC's network-facing path: TCP record framing
//! (RFC 4120 7.2.2) and `Kdc::handle` (AS-REQ / TGS-REQ processing,
//! unarmored and FAST-armored) against in-memory backends — a real keyd with
//! an insecure development key store, the in-memory account source and the
//! real PDP with `pdp::mandatory_fast_rules` (docs/48 §7.2).
//!
//! The first input octet selects the mode:
//! - 0: a TCP byte stream (framing, then every complete record);
//! - 1: one UDP datagram; 2: one TCP record;
//! - 3: an armored AS-REQ (RFC 6113 5.4.2) under a fresh, VALID armor on the
//!   computer account's TGT, whose KrbFastReq plaintext is the rest of the
//!   input — it reaches keyd's KrbFastReq decoding and, when that decodes,
//!   the KDC's processing of the inner request;
//! - 4: an armored TGS-REQ (implicit armor, RFC 6113 5.4.2) on the user's
//!   TGT, whose KrbFastReq plaintext is the rest of the input;
//! - 5: a valid armored AS-REQ for the user whose inner padata is one PA-DATA
//!   chosen by the second octet (PA-ENCRYPTED-CHALLENGE, PA-FX-COOKIE,
//!   PA-ENC-TIMESTAMP, PA-FX-FAST) with the rest of the input as its value,
//!   and whose FastOptions come from the input — the cookie, the inner
//!   padata scan, the FastOptions check and keyd's challenge decoding.
//!
//! Invariants checked on every reply (AGENTS.md §6; main-session decisions
//! 1, 11, 12): nothing panics; a reply is bounded and decodes as AS-REP,
//! TGS-REP or KRB-ERROR; a KRB-ERROR never carries e-text, and its e-data,
//! when present, is METHOD-DATA.
//!
//! The backends are built once and reused across inputs. The computer
//! account's and the user's keys come from keyd's `set_secret` with
//! passwords known to the harness, so that it can play the FAST client
//! (RFC 6113 5.4.1.1, 5.4.6; keys from krb-crypto, as the integration tests
//! do); the krbtgt and service keys come from `create_key` (kernel CSPRNG).
//! The harness clock advances one second every 50 inputs, so that keyd's
//! bounded replay cache and token tables keep expiring entries instead of
//! filling up (fail closed would otherwise stop the armored paths early);
//! it stays within the armor TGT's life. Every table the KDC and keyd keep
//! is bounded, so state growth is bounded.
//!
//! Every account record carries the name resolution dird would attest for it
//! (task PN10; docs/59 §7.1, §7.5), tagged with a harness key through crate
//! name-attestation's `tag`. Since task PN11 the KDC forwards it and keyd
//! verifies it (30 s on keyd's clock — docs/59 §7.2): keyd's ceremony
//! installs the harness key, and each input's lookups are answered through
//! [`AtTime`], which states every resolution again at the input's time, as
//! dird signs at lookup time — so the harness clock's advance never turns
//! the fuzzed paths into stale-resolution refusals.
//!
//! Spec: RFC 4120 7.2.1, 7.2.2, 5.1.4, 5.9.1; RFC 6113 5.4.1.1, 5.4.2,
//! 5.4.3, 5.4.6; docs/48 §9.2 item 16; docs/59 §7.1; AGENTS.md §6.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

use dtyp::{Sid, SECURITY_NT_AUTHORITY};
use kdc::{
    tcp_decode_frame, AccountKind, AccountState, ArmorPolicy, AuditEvent, ClientAccount,
    InMemoryAccounts, Kdc, KdcConfig, KdcReply, Peer, PolicyInputs, RateLimiter, ServiceAccount,
    TcpFrame, Transport,
};
// keyd's account kind (of a set-secret decision) beside the KDC's (of an
// account record): two types, so keyd's is renamed here (the harness did
// not build with both under one name — docs/questions/Q-1046 item 8).
use keyd::{
    AccountKind as SecretAccountKind, AttestationKey, AuditRecord, CallerId, InMemoryKeyStore, KeyHandle, KeyPurpose, Keyd, KeydConfig,
    LocalKeyd, OsEntropy, PrincipalBinding, PrincipalId, Role, SetSecretTarget,
    MAX_SET_SECRET_GRANT_SECS,
};
use keyd_types::{AttestedNameResolution, NameResolution, NameResolutionFields};
use krb_crypto::{EncType, KeyUsage, ProtocolKey};
use krb_proto::constants::{
    FX_FAST_ARMOR_AP_REQUEST, PA_ENCRYPTED_CHALLENGE, PA_ENC_TIMESTAMP, PA_FX_COOKIE, PA_FX_FAST,
    PA_TGS_REQ,
};
use krb_proto::limits::MAX_MESSAGE_LEN;
use krb_proto::{
    ApOptions, ApReq, AsRep, AsReq, Authenticator, Checksum, EncAsRepPart, EncryptedData,
    EncryptionKey, EtypeInfo2Entry, FastOptions, KdcOptions, KdcReq, KdcReqBody, KerberosFlags,
    KerberosString, KerberosTime, KeyValue, KrbError, KrbFastArmor, KrbFastArmoredReq, KrbFastReq,
    KrbFastResponse, MethodData, Microseconds, PaData, PaEncTsEnc, PaFxFastReply, PaFxFastRequest,
    PrincipalName, Realm, TgsRep, TgsReq, Ticket,
};
use libfuzzer_sys::fuzz_target;
use pdp::{
    ActionClass, ActionMatch, AuthMatch, ContextMatch, Effect, IpScope, Match, Pip, PipError,
    PolicySnapshot, PolicyVersion, ResourceMatch, RlKey, Rule, RuleId, SubjectMatch, Tier,
};

/// The resolution dird would attest for `name` in `realm` resolving to `key`
/// (docs/59 §7.1), issued at the harness's base time and tagged with a
/// harness key (task PN10).
fn resolution(realm: &Realm, name: &PrincipalName, key: KeyHandle) -> AttestedNameResolution {
    let resolution = NameResolution::new(NameResolutionFields {
        realm_as_sent: realm.clone(),
        name_as_sent: name.clone(),
        canonical_realm: realm.clone(),
        canonical_name: name.clone(),
        principal: key.principal,
        key_purpose: key.purpose,
        snapshot: 1,
        issued_at: base_time(),
    })
    .expect("a resolution within its bounds");
    let harness_key =
        name_attestation::AttestationKey::from_bytes(&HARNESS_ATTESTATION_KEY).expect("a harness key");
    name_attestation::tag(&harness_key, &resolution).expect("a tagged resolution")
}

/// The harness's attestation key: dird's (its `tag`) and keyd's (installed
/// in the ceremony, task PN11).
const HARNESS_ATTESTATION_KEY: [u8; 32] = [0x4B; 32];

/// `attested` stated again at `at`: the same fields, a new issue time, the
/// harness key's tag — what dird answers for the same lookup at `at`.
fn restated(attested: &AttestedNameResolution, at: &KerberosTime) -> AttestedNameResolution {
    let mut fields = attested.resolution().clone().into_fields();
    fields.issued_at = *at;
    let resolution = NameResolution::new(fields).expect("a resolution within its bounds");
    let harness_key =
        name_attestation::AttestationKey::from_bytes(&HARNESS_ATTESTATION_KEY).expect("a harness key");
    name_attestation::tag(&harness_key, &resolution).expect("a tagged resolution")
}

/// The account source of one input at its time (task PN11): every record
/// carries its resolution stated again at `at` (module docs).
struct AtTime<'a> {
    inner: &'a InMemoryAccounts,
    at: KerberosTime,
}

impl kdc::AccountSource for AtTime<'_> {
    fn client(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ClientAccount>, kdc::AccountSourceError> {
        Ok(self.inner.client(realm, name)?.map(|mut account| {
            account.resolution = restated(&account.resolution, &self.at);
            account
        }))
    }

    fn service(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ServiceAccount>, kdc::AccountSourceError> {
        Ok(self.inner.service(realm, name)?.map(|mut account| {
            account.resolution = restated(&account.resolution, &self.at);
            account
        }))
    }
}

struct NoKeydAudit;
impl keyd::AuditSink for NoKeydAudit {
    fn record(&mut self, _record: &AuditRecord) {}
}

struct NoKdcAudit;
impl kdc::AuditSink for NoKdcAudit {
    fn record(&mut self, _event: &AuditEvent) {}
}

struct AdmitAll;
impl RateLimiter for AdmitAll {
    fn admit(&mut self, _key: &RlKey, _now: &KerberosTime) -> bool {
        true
    }
}

struct FuzzPip {
    tiers: BTreeMap<Sid, Tier>,
}

impl Pip for FuzzPip {
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

type FuzzKdc = Kdc<LocalKeyd<InMemoryKeyStore, NoKeydAudit, OsEntropy>, NoKdcAudit, AdmitAll>;

/// A TGT the harness holds as a client.
struct HeldTgt {
    ticket: Ticket,
    cname: PrincipalName,
    session: ProtocolKey,
}

/// The KDC, its policy inputs and the account source passed with each
/// request (docs/47 R47-14), and the harness's FAST client state.
struct FuzzState {
    kdc: FuzzKdc,
    snapshot: PolicySnapshot,
    pip: FuzzPip,
    accounts: InMemoryAccounts,
    /// The computer account's TGT: the armor ticket (D126).
    machine: HeldTgt,
    /// The user's TGT (obtained armored): the TGS mode's ticket.
    user: HeldTgt,
    /// The user's long-term key (for the encrypted challenge).
    user_key: ProtocolKey,
    /// Inputs seen: drives the clock and makes every armor fresh.
    counter: u32,
}

const REALM: &str = "FUZZ.EXAMPLE";
const ADMIN: CallerId = CallerId {
    uid: 3,
    role: Role::Admin,
};
const DIRECTORY: CallerId = CallerId {
    uid: 2,
    role: Role::Directory,
};
/// dird's role, which registers the set_secret grant (task A15a).
const LDAP: CallerId = CallerId {
    uid: 4,
    role: Role::Ldap,
};
const KDC_CALLER: CallerId = CallerId {
    uid: 1,
    role: Role::Kdc,
};
const USER_PASSWORD: &str = "Pallas-Sable-91-Teal";
const USER_SALT: &str = "FUZZ.EXAMPLEfuzzer";
const MACHINE_PASSWORD: &str = "Rowan-Thrush-14-Vetch";
const MACHINE_SALT: &str = "FUZZ.EXAMPLEhostfuzzhost.fuzz.example";
/// Inputs per harness second (module docs).
const INPUTS_PER_SECOND: u32 = 50;
/// The harness clock wraps within the armor TGT's life (24 h, RFC 4120 §8.2
/// default policy) minus an hour of margin.
const CLOCK_SPAN_SECS: u32 = 23 * 3600;

fn kstr(s: &str) -> KerberosString {
    KerberosString::new(s).expect("valid KerberosString")
}

fn name(name_type: i32, parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type,
        name_string: parts.iter().map(|p| kstr(p)).collect(),
    }
}

fn realm() -> Realm {
    Realm::new(REALM).expect("valid realm")
}

fn krbtgt_name() -> PrincipalName {
    name(2, &["krbtgt", REALM])
}

fn base_time() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 0, 0, 0).expect("valid time")
}

/// The harness clock: the base time plus one second per INPUTS_PER_SECOND
/// inputs, wrapping within CLOCK_SPAN_SECS.
fn clock(counter: u32) -> KerberosTime {
    let secs = (counter / INPUTS_PER_SECOND) % CLOCK_SPAN_SECS;
    let hour = u8::try_from(secs / 3600).expect("< 24");
    let minute = u8::try_from((secs % 3600) / 60).expect("< 60");
    let second = u8::try_from(secs % 60).expect("< 60");
    KerberosTime::new(2026, 11, 13, hour, minute, second).expect("valid time")
}

fn usage(n: u32) -> KeyUsage {
    KeyUsage::new(n).expect("valid key usage")
}

fn aes256_key(password: &str, salt: &str) -> ProtocolKey {
    krb_crypto::string_to_key(EncType::Aes256CtsHmacSha196, password, salt, None, 50_000)
        .expect("string-to-key")
}

fn cf2(k1: &ProtocolKey, k2: &ProtocolKey, p1: &[u8], p2: &[u8]) -> ProtocolKey {
    krb_crypto::krb_fx_cf2(k1, k2, p1, p2).expect("KRB-FX-CF2")
}

fn seal(key: &ProtocolKey, usage_number: u32, plain: &[u8]) -> EncryptedData {
    EncryptedData {
        etype: key.enc_type().number(),
        kvno: None,
        cipher: krb_crypto::encrypt(key, usage(usage_number), &[0x46; 16], plain).expect("encrypt"),
    }
}

fn open(key: &ProtocolKey, usage_number: u32, enc: &EncryptedData) -> Vec<u8> {
    krb_crypto::decrypt(key, usage(usage_number), &enc.cipher)
        .expect("decrypt")
        .to_vec()
}

fn mic(key: &ProtocolKey, usage_number: u32, data: &[u8]) -> Checksum {
    let cksumtype = key.enc_type().checksum_type();
    Checksum {
        cksumtype: cksumtype.number(),
        checksum: krb_crypto::get_mic(key, cksumtype, usage(usage_number), data).expect("mic"),
    }
}

fn key_from(ek: &EncryptionKey) -> ProtocolKey {
    let enc_type = EncType::from_number(ek.keytype).expect("AES enctype");
    krb_crypto::random_to_key(enc_type, ek.keyvalue.as_bytes()).expect("random-to-key")
}

fn timestamp(ts: KerberosTime) -> Vec<u8> {
    PaEncTsEnc {
        patimestamp: ts,
        pausec: None,
    }
    .encode()
    .expect("PA-ENC-TS-ENC")
}

/// An AS-REQ body for this realm's TGT (RFC 4120 5.4.1).
fn as_body(cname: PrincipalName, nonce: u32) -> KdcReqBody {
    KdcReqBody {
        kdc_options: KdcOptions::empty(),
        cname: Some(cname),
        realm: realm(),
        sname: Some(krbtgt_name()),
        from: None,
        till: KerberosTime::new(1970, 1, 1, 0, 0, 0).expect("valid time"),
        rtime: None,
        nonce,
        etype: vec![18, 17],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    }
}

/// A TGS-REQ body for the fuzz service (RFC 4120 5.4.1).
fn tgs_body(nonce: u32) -> KdcReqBody {
    KdcReqBody {
        kdc_options: KdcOptions::empty(),
        cname: None,
        realm: realm(),
        sname: Some(name(3, &["host", "target.fuzz.example"])),
        from: None,
        till: KerberosTime::new(1970, 1, 1, 0, 0, 0).expect("valid time"),
        rtime: None,
        nonce,
        etype: vec![18, 17],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    }
}

/// A subkey distinct per `n` (RFC 6113 5.4: a fresh armor key per
/// conversation).
fn subkey(n: u32) -> ProtocolKey {
    let mut octets = [0xF0u8; 32];
    octets[..4].copy_from_slice(&n.to_be_bytes());
    krb_crypto::random_to_key(EncType::Aes256CtsHmacSha196, &octets).expect("random-to-key")
}

/// An AP-REQ on `tgt` whose authenticator (key usage `auth_usage`) carries
/// `sub` and, when given, a checksum over `cksum_over` (usage 6).
/// RFC 4120 5.5.1.
fn ap_req(
    tgt: &HeldTgt,
    sub: &ProtocolKey,
    ctime: KerberosTime,
    n: u32,
    auth_usage: u32,
    cksum_over: Option<&[u8]>,
) -> ApReq {
    let authenticator = Authenticator {
        crealm: realm(),
        cname: tgt.cname.clone(),
        cksum: cksum_over.map(|body| mic(&tgt.session, 6, body)),
        cusec: Microseconds::new(n % 1_000_000).expect("valid cusec"),
        ctime,
        subkey: Some(EncryptionKey {
            keytype: sub.enc_type().number(),
            keyvalue: KeyValue::from_slice(sub.octets()),
        }),
        seq_number: None,
        authorization_data: None,
    }
    .encode()
    .expect("Authenticator");
    ApReq {
        ap_options: ApOptions::empty(),
        ticket: tgt.ticket.clone(),
        authenticator: seal(&tgt.session, auth_usage, &authenticator),
    }
}

/// The PA-FX-FAST of a request: the req-checksum over `checksummed` (armor
/// key, usage 50) and `fast_req_plain` sealed in the armor key (usage 51).
/// RFC 6113 5.4.2.
fn fx_fast(
    armor: Option<KrbFastArmor>,
    armor_key: &ProtocolKey,
    checksummed: &[u8],
    fast_req_plain: &[u8],
) -> PaData {
    PaData {
        padata_type: PA_FX_FAST,
        padata_value: PaFxFastRequest::ArmoredData(KrbFastArmoredReq {
            armor,
            req_checksum: mic(armor_key, 50, checksummed),
            enc_fast_req: seal(armor_key, 51, fast_req_plain),
        })
        .encode()
        .expect("PA-FX-FAST-REQUEST"),
    }
}

/// An armored AS-REQ under a fresh armor on `machine` (RFC 6113 5.4.1.1:
/// authenticator key usage 11, subkey, no checksum — Q-120), whose
/// KrbFastReq plaintext is `fast_req_plain`. Returns the request and the
/// armor key.
fn armored_as(
    machine: &HeldTgt,
    n: u32,
    when: KerberosTime,
    outer: &KdcReqBody,
    fast_req_plain: &[u8],
) -> (Vec<u8>, ProtocolKey) {
    let sub = subkey(n);
    let ap = ap_req(machine, &sub, when, n, 11, None);
    let armor_key = cf2(&sub, &machine.session, b"subkeyarmor", b"ticketarmor");
    let armor = KrbFastArmor {
        armor_type: FX_FAST_ARMOR_AP_REQUEST,
        armor_value: ap.encode().expect("AP-REQ"),
    };
    let outer_octets = outer.encode().expect("KDC-REQ-BODY");
    let request = AsReq(KdcReq {
        padata: Some(vec![fx_fast(
            Some(armor),
            &armor_key,
            &outer_octets,
            fast_req_plain,
        )]),
        req_body: outer.clone(),
    })
    .encode()
    .expect("AS-REQ");
    (request, armor_key)
}

/// The encrypted challenge of `long_term` under `armor_key` at `ts`
/// (RFC 6113 5.4.6, key usage 54).
fn encrypted_challenge(
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
    PaData {
        padata_type: PA_ENCRYPTED_CHALLENGE,
        padata_value: seal(&key, 54, &timestamp(ts))
            .encode()
            .expect("EncryptedChallenge"),
    }
}

fn build() -> FuzzState {
    let realm = realm();
    let krbtgt = KeyHandle::new(PrincipalId::from_bytes([1; 16]), KeyPurpose::Krbtgt);
    let client = KeyHandle::new(
        PrincipalId::from_bytes([2; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    let service = KeyHandle::new(PrincipalId::from_bytes([3; 16]), KeyPurpose::Service);
    let machine_handle = KeyHandle::new(
        PrincipalId::from_bytes([4; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    let client_name = name(1, &["fuzzer"]);
    let machine_name = name(1, &["fuzzhost$"]);
    let service_name = name(3, &["host", "target.fuzz.example"]);

    let n = base_time();
    // keyd started a day before the harness clock: its startup hold-down
    // (RFC 4120 3.2.3; docs/50 R50-6) is over, so the fuzzer reaches every
    // keyd path.
    let started = KerberosTime::new(2026, 11, 12, 0, 0, 0).expect("valid time");
    let mut keyd = Keyd::new(
        KeydConfig::new(realm.clone()),
        InMemoryKeyStore::new_insecure_development_allowing_krbtgt(16),
        NoKeydAudit,
        &started,
    )
    .expect("valid keyd config");
    for (handle, binding) in [(krbtgt, krbtgt_name()), (service, service_name.clone())] {
        keyd.create_key(
            &ADMIN,
            &handle,
            &PrincipalBinding::new(realm.clone(), binding),
            &n,
        )
        .expect("key created");
    }
    // The ceremony installs dird's attestation key (task PN11).
    keyd.install_attestation_key(
        &ADMIN,
        AttestationKey::from_bytes(&HARNESS_ATTESTATION_KEY).expect("a harness key"),
        &n,
    )
    .expect("attestation key installed");
    for (kind, handle, binding, password, salt) in [
        (
            SecretAccountKind::User,
            client,
            client_name.clone(),
            USER_PASSWORD,
            USER_SALT,
        ),
        (
            SecretAccountKind::Computer,
            machine_handle,
            machine_name.clone(),
            MACHINE_PASSWORD,
            MACHINE_SALT,
        ),
    ] {
        // The set-secret decision dird registers after its PDP (task A15a;
        // docs/51 §5.8; A-102: binding and salt bound, N4).
        keyd.register_decision(
            &LDAP,
            keyd::DecisionId::new(u64::from(handle.principal.as_bytes()[0])),
            &keyd::DecidedOperation::SetSecret {
                kind,
                targets: vec![SetSecretTarget {
                    handle,
                    binding: PrincipalBinding::new(realm.clone(), binding.clone()),
                    salt: String::from(salt),
                }],
            },
            &[],
            MAX_SET_SECRET_GRANT_SECS,
            &n,
        )
        .expect("decision registered");
        keyd.set_secret(
            &DIRECTORY,
            &handle,
            &PrincipalBinding::new(realm.clone(), binding),
            String::from(password).into(),
            salt,
            &n,
        )
        .expect("secret set");
    }

    let etype_info = |salt: &str| -> Vec<EtypeInfo2Entry> {
        [18, 17]
            .iter()
            .map(|e| EtypeInfo2Entry {
                etype: *e,
                salt: Some(kstr(salt)),
                s2kparams: None,
            })
            .collect()
    };
    let sid = Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 1000]).expect("valid SID");
    let machine_sid = Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 1001]).expect("valid SID");
    let bootstrap = Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 1500]).expect("valid SID");
    let mut accounts = InMemoryAccounts::new();
    accounts
        .insert_client(
            &realm,
            &client_name,
            ClientAccount {
                sid,
                groups: BTreeSet::new(),
                tier: Tier::Tier2,
                state: AccountState::ACTIVE,
                etype_info: etype_info(USER_SALT),
                kind: AccountKind::User,
                armor_policy: ArmorPolicy::Required,
                resolution: resolution(&realm, &client_name, client),
            },
        )
        .expect("client inserted");
    accounts
        .insert_client(
            &realm,
            &machine_name,
            ClientAccount {
                sid: machine_sid,
                groups: [bootstrap].into_iter().collect(),
                tier: Tier::Tier2,
                state: AccountState::ACTIVE,
                etype_info: etype_info(MACHINE_SALT),
                kind: AccountKind::Computer,
                armor_policy: ArmorPolicy::BootstrapAllowed,
                resolution: resolution(&realm, &machine_name, machine_handle),
            },
        )
        .expect("computer inserted");
    accounts
        .insert_service(
            &realm,
            &service_name,
            ServiceAccount {
                state: AccountState::ACTIVE,
                enctypes: vec![18, 17],
                resolution: resolution(&realm, &service_name, service),
            },
        )
        .expect("service inserted");

    let mut kdc = Kdc::new(
        KdcConfig::new(realm, krbtgt),
        LocalKeyd::new(keyd, KDC_CALLER).expect("Kdc role"),
        NoKdcAudit,
        AdmitAll,
    )
    .expect("valid KDC config");
    // docs/48 §7.2: the mandatory-FAST rules plus a broad grant.
    let mut rules = pdp::mandatory_fast_rules(bootstrap, RuleId(100)).expect("rule ids");
    rules.push(Rule {
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
    });
    let snapshot = PolicySnapshot::new(PolicyVersion(1), rules, Vec::new());
    let pip = FuzzPip {
        tiers: [(sid, Tier::Tier2), (machine_sid, Tier::Tier2)]
            .into_iter()
            .collect(),
    };
    let tcp = Peer {
        transport: Transport::Tcp,
        src_net: IpScope::Internal,
    };

    // The computer account's TGT: the unarmored bootstrap (docs/48 §7.3).
    let machine_key = aes256_key(MACHINE_PASSWORD, MACHINE_SALT);
    let mut ts = seal(&machine_key, 1, &timestamp(n));
    ts.kvno = Some(1);
    let bootstrap_req = AsReq(KdcReq {
        padata: Some(vec![PaData {
            padata_type: PA_ENC_TIMESTAMP,
            padata_value: ts.encode().expect("PA-ENC-TIMESTAMP"),
        }]),
        req_body: as_body(machine_name.clone(), 1),
    })
    .encode()
    .expect("AS-REQ");
    let inputs = PolicyInputs {
        snapshot: &snapshot,
        pip: &pip,
    };
    let KdcReply::Send(bytes) = kdc.handle(&bootstrap_req, tcp, n, &inputs, &accounts) else {
        panic!("bootstrap AS answered");
    };
    let rep = AsRep::decode(&bytes).expect("bootstrap AS-REP");
    let part = EncAsRepPart::decode(&open(&machine_key, 3, &rep.0.enc_part)).expect("EncAsRepPart");
    let machine = HeldTgt {
        ticket: rep.0.ticket,
        cname: rep.0.cname,
        session: key_from(&part.0.key),
    };

    // The user's TGT: an armored AS with the encrypted challenge (RFC 6113
    // 5.4.6), opened under the strengthened reply key (5.4.3).
    let user_key = aes256_key(USER_PASSWORD, USER_SALT);
    let outer = as_body(client_name.clone(), 2);
    let sub = subkey(0);
    let armor_key = cf2(&sub, &machine.session, b"subkeyarmor", b"ticketarmor");
    let fast_req = KrbFastReq {
        fast_options: FastOptions::empty(),
        padata: vec![encrypted_challenge(&armor_key, &user_key, n)],
        req_body: outer.clone(),
    }
    .encode()
    .expect("KrbFastReq");
    let ap = ap_req(&machine, &sub, n, 0, 11, None);
    let request = AsReq(KdcReq {
        padata: Some(vec![fx_fast(
            Some(KrbFastArmor {
                armor_type: FX_FAST_ARMOR_AP_REQUEST,
                armor_value: ap.encode().expect("AP-REQ"),
            }),
            &armor_key,
            &outer.encode().expect("KDC-REQ-BODY"),
            &fast_req,
        )]),
        req_body: outer,
    })
    .encode()
    .expect("AS-REQ");
    let KdcReply::Send(bytes) = kdc.handle(&request, tcp, n, &inputs, &accounts) else {
        panic!("armored AS answered");
    };
    let rep = AsRep::decode(&bytes).expect("armored AS-REP");
    let fx = rep
        .0
        .padata
        .as_ref()
        .and_then(|p| p.first())
        .expect("PA-FX-FAST");
    let PaFxFastReply::ArmoredData(armored) =
        PaFxFastReply::decode(&fx.padata_value).expect("PA-FX-FAST-REPLY");
    let response = KrbFastResponse::decode(&open(&armor_key, 52, &armored.enc_fast_rep))
        .expect("KrbFastResponse");
    let strengthen = key_from(response.strengthen_key.as_ref().expect("strengthen-key"));
    let reply_key = cf2(&strengthen, &user_key, b"strengthenkey", b"replykey");
    let part = EncAsRepPart::decode(&open(&reply_key, 3, &rep.0.enc_part)).expect("EncAsRepPart");
    let user = HeldTgt {
        ticket: rep.0.ticket,
        cname: rep.0.cname,
        session: key_from(&part.0.key),
    };

    FuzzState {
        kdc,
        snapshot,
        pip,
        accounts,
        machine,
        user,
        user_key,
        counter: 1,
    }
}

fn state() -> &'static Mutex<FuzzState> {
    static STATE: OnceLock<Mutex<FuzzState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(build()))
}

/// The invariants every reply must satisfy (decisions 11, 12; RFC 4120
/// 5.9.1; RFC 6113 5.4.4).
fn check(reply: KdcReply) {
    match reply {
        KdcReply::Silent => {}
        KdcReply::Send(bytes) | KdcReply::SendAndClose(bytes) => {
            assert!(bytes.len() <= MAX_MESSAGE_LEN);
            match KrbError::decode(&bytes) {
                Ok(error) => {
                    assert!(error.e_text.is_none(), "KRB-ERROR with e-text");
                    if let Some(e_data) = &error.e_data {
                        assert!(MethodData::decode(e_data).is_ok(), "e-data not METHOD-DATA");
                    }
                }
                Err(_) => assert!(
                    AsRep::decode(&bytes).is_ok() || TgsRep::decode(&bytes).is_ok(),
                    "reply is neither KRB-ERROR nor KDC-REP"
                ),
            }
        }
    }
}

/// Mode 4: an armored TGS-REQ on the user's TGT (implicit armor, RFC 6113
/// 5.4.2) whose KrbFastReq plaintext is `fast_req_plain`.
fn armored_tgs(state: &FuzzState, n: u32, when: KerberosTime, fast_req_plain: &[u8]) -> Vec<u8> {
    let body = tgs_body(n);
    let body_octets = body.encode().expect("KDC-REQ-BODY");
    let sub = subkey(n);
    let ap = ap_req(&state.user, &sub, when, n, 7, Some(&body_octets))
        .encode()
        .expect("AP-REQ");
    let armor_key = cf2(&sub, &state.user.session, b"subkeyarmor", b"ticketarmor");
    TgsReq(KdcReq {
        padata: Some(vec![
            PaData {
                padata_type: PA_TGS_REQ,
                padata_value: ap.clone(),
            },
            fx_fast(None, &armor_key, &ap, fast_req_plain),
        ]),
        req_body: body,
    })
    .encode()
    .expect("TGS-REQ")
}

/// Mode 5: a valid armored AS-REQ for the user with one fuzzed inner padata
/// and fuzzed FastOptions (module docs).
fn armored_as_fuzzed_padata(
    state: &FuzzState,
    n: u32,
    when: KerberosTime,
    input: &[u8],
) -> Vec<u8> {
    let (selector, rest): (u8, &[u8]) = match input.split_first() {
        Some((selector, rest)) => (*selector, rest),
        None => (0, &[]),
    };
    let (options, value) = if rest.len() >= 4 {
        let (o, v) = rest.split_at(4);
        (u32::from_be_bytes([o[0], o[1], o[2], o[3]]), v)
    } else {
        (0, rest)
    };
    let padata_type = [
        PA_ENCRYPTED_CHALLENGE,
        PA_FX_COOKIE,
        PA_ENC_TIMESTAMP,
        PA_FX_FAST,
    ][usize::from(selector % 4)];
    let outer = as_body(state.user.cname.clone(), n);
    let sub = subkey(n);
    let armor_key = cf2(&sub, &state.machine.session, b"subkeyarmor", b"ticketarmor");
    let mut padata = vec![PaData {
        padata_type,
        padata_value: value.to_vec(),
    }];
    if selector & 0x80 != 0 {
        padata.push(encrypted_challenge(&armor_key, &state.user_key, when));
    }
    let fast_req = KrbFastReq {
        fast_options: FastOptions(KerberosFlags::from_bits(options)),
        padata,
        req_body: outer.clone(),
    };
    match fast_req.encode() {
        Ok(plain) => armored_as(&state.machine, n, when, &outer, &plain).0,
        // A padata value too large to encode: the plain bytes instead.
        Err(_) => armored_as(&state.machine, n, when, &outer, value).0,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, input)) = data.split_first() else {
        return;
    };
    let mut guard = match state().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.counter = guard.counter.wrapping_add(1);
    let n = guard.counter;
    let when = clock(n);
    let tcp = Peer {
        transport: Transport::Tcp,
        src_net: IpScope::Internal,
    };
    let udp = Peer {
        transport: Transport::Udp,
        src_net: IpScope::Internal,
    };
    // Requests built from the client state, before the KDC is borrowed.
    let built = match mode % 6 {
        3 => {
            let outer = as_body(guard.user.cname.clone(), n);
            Some(armored_as(&guard.machine, n, when, &outer, input).0)
        }
        4 => Some(armored_tgs(&guard, n, when, input)),
        5 => Some(armored_as_fuzzed_padata(&guard, n, when, input)),
        _ => None,
    };
    let FuzzState {
        kdc,
        snapshot,
        pip,
        accounts,
        ..
    } = &mut *guard;
    // dird states each resolution at lookup time (module docs; task PN11).
    let at_time = AtTime {
        inner: accounts,
        at: when,
    };
    let accounts: &AtTime<'_> = &at_time;
    let inputs = PolicyInputs {
        snapshot: &*snapshot,
        pip: &*pip,
    };
    if let Some(request) = built {
        check(kdc.handle(&request, tcp, when, &inputs, accounts));
        return;
    }
    match mode % 6 {
        0 => {
            // A TCP byte stream: framing, then each complete record.
            let mut rest = input;
            loop {
                match tcp_decode_frame(rest) {
                    Ok(TcpFrame::Complete {
                        message,
                        rest: next,
                    }) => {
                        check(kdc.handle(message, tcp, when, &inputs, accounts));
                        if next.len() >= rest.len() {
                            break;
                        }
                        rest = next;
                    }
                    Ok(TcpFrame::Incomplete) => break,
                    Err(error) => {
                        check(kdc.reject_frame(error, tcp, when));
                        break;
                    }
                }
            }
        }
        1 => check(kdc.handle(input, udp, when, &inputs, accounts)),
        _ => check(kdc.handle(input, tcp, when, &inputs, accounts)),
    }
});
