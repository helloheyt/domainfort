#![no_main]
//! Fuzz target for the KDC's network-facing path: TCP record framing
//! (RFC 4120 7.2.2) and `Kdc::handle` (AS-REQ / TGS-REQ processing) against
//! in-memory backends — a real keyd with an insecure development key store,
//! the in-memory account source and the real PDP.
//!
//! The first input octet selects the mode: a TCP byte stream (framing, then
//! every complete record), one UDP datagram, or one TCP record. Invariants
//! checked on every reply (AGENTS.md §6; main-session decisions 1, 11, 12):
//! nothing panics; a reply is bounded and decodes as AS-REP, TGS-REP or
//! KRB-ERROR; a KRB-ERROR never carries e-text.
//!
//! The backends are built once and reused across inputs (keys are created
//! with keyd's `create_key` from the kernel CSPRNG); every table the KDC and
//! keyd keep is bounded, so state growth is bounded.
//!
//! Spec: RFC 4120 7.2.1, 7.2.2, 5.1.4, 5.9.1; AGENTS.md §6.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

use dtyp::{Sid, SECURITY_NT_AUTHORITY};
use kdc::{
    tcp_decode_frame, AccountState, AuditEvent, ClientAccount, InMemoryAccounts, Kdc, KdcConfig,
    KdcReply, LocalKeyd, Peer, PolicyInputs, RateLimiter, ServiceAccount, TcpFrame, Transport,
};
use keyd::{
    AuditRecord, CallerId, InMemoryKeyStore, KeyHandle, KeyPurpose, Keyd, KeydConfig, OsEntropy,
    PrincipalBinding, PrincipalId, Role,
};
use krb_proto::limits::MAX_MESSAGE_LEN;
use krb_proto::{
    AsRep, EtypeInfo2Entry, KerberosString, KerberosTime, KrbError, PrincipalName, Realm, TgsRep,
};
use libfuzzer_sys::fuzz_target;
use pdp::{
    ActionClass, ActionMatch, AuthMatch, ContextMatch, Effect, IpScope, Match, Pip, PipError,
    PolicySnapshot, PolicyVersion, ResourceMatch, RlKey, Rule, RuleId, SubjectMatch, Tier,
};

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

/// The KDC, its policy inputs and the account source passed with each
/// request (docs/47 R47-14).
struct FuzzState {
    kdc: FuzzKdc,
    snapshot: PolicySnapshot,
    pip: FuzzPip,
    accounts: InMemoryAccounts,
}

const REALM: &str = "FUZZ.EXAMPLE";
const ADMIN: CallerId = CallerId {
    uid: 3,
    role: Role::Admin,
};
const KDC_CALLER: CallerId = CallerId {
    uid: 1,
    role: Role::Kdc,
};

fn kstr(s: &str) -> KerberosString {
    KerberosString::new(s).expect("valid KerberosString")
}

fn name(name_type: i32, parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type,
        name_string: parts.iter().map(|p| kstr(p)).collect(),
    }
}

fn now() -> KerberosTime {
    KerberosTime::new(2026, 11, 13, 10, 0, 0).expect("valid time")
}

fn build() -> FuzzState {
    let realm = Realm::new(REALM).expect("valid realm");
    let krbtgt = KeyHandle::new(PrincipalId::from_bytes([1; 16]), KeyPurpose::Krbtgt);
    let client = KeyHandle::new(
        PrincipalId::from_bytes([2; 16]),
        KeyPurpose::PrincipalLongterm,
    );
    let service = KeyHandle::new(PrincipalId::from_bytes([3; 16]), KeyPurpose::Service);
    let client_name = name(1, &["fuzzer"]);
    let service_name = name(3, &["host", "target.fuzz.example"]);

    let mut keyd = Keyd::new(
        KeydConfig::new(realm.clone()),
        InMemoryKeyStore::new_insecure_development_allowing_krbtgt(16),
        NoKeydAudit,
    )
    .expect("valid keyd config");
    let n = now();
    for (handle, binding) in [
        (krbtgt, name(2, &["krbtgt", REALM])),
        (client, client_name.clone()),
        (service, service_name.clone()),
    ] {
        keyd.create_key(
            &ADMIN,
            &handle,
            &PrincipalBinding::new(realm.clone(), binding),
            &n,
        )
        .expect("key created");
    }

    let sid = Sid::new(SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 1000]).expect("valid SID");
    let mut accounts = InMemoryAccounts::new();
    accounts
        .insert_client(
            &realm,
            &client_name,
            ClientAccount {
                key: client,
                sid,
                groups: BTreeSet::new(),
                tier: Tier::Tier2,
                state: AccountState::ACTIVE,
                etype_info: [18, 17]
                    .iter()
                    .map(|e| EtypeInfo2Entry {
                        etype: *e,
                        salt: Some(kstr("FUZZ.EXAMPLEfuzzer")),
                        s2kparams: None,
                    })
                    .collect(),
            },
        )
        .expect("client inserted");
    accounts
        .insert_service(
            &realm,
            &service_name,
            ServiceAccount {
                key: service,
                state: AccountState::ACTIVE,
                enctypes: vec![18, 17],
            },
        )
        .expect("service inserted");

    let kdc = Kdc::new(
        KdcConfig::new(realm, krbtgt),
        LocalKeyd::new(keyd, KDC_CALLER).expect("Kdc role"),
        NoKdcAudit,
        AdmitAll,
    )
    .expect("valid KDC config");
    let snapshot = PolicySnapshot::new(
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
    );
    FuzzState {
        kdc,
        snapshot,
        pip: FuzzPip {
            tiers: [(sid, Tier::Tier2)].into_iter().collect(),
        },
        accounts,
    }
}

fn state() -> &'static Mutex<FuzzState> {
    static STATE: OnceLock<Mutex<FuzzState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(build()))
}

/// The invariants every reply must satisfy (decisions 11, 12).
fn check(reply: KdcReply) {
    match reply {
        KdcReply::Silent => {}
        KdcReply::Send(bytes) | KdcReply::SendAndClose(bytes) => {
            assert!(bytes.len() <= MAX_MESSAGE_LEN);
            match KrbError::decode(&bytes) {
                Ok(error) => assert!(error.e_text.is_none(), "KRB-ERROR with e-text"),
                Err(_) => assert!(
                    AsRep::decode(&bytes).is_ok() || TgsRep::decode(&bytes).is_ok(),
                    "reply is neither KRB-ERROR nor KDC-REP"
                ),
            }
        }
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
    let FuzzState {
        kdc,
        snapshot,
        pip,
        accounts,
    } = &mut *guard;
    let accounts: &InMemoryAccounts = accounts;
    let inputs = PolicyInputs {
        snapshot: &*snapshot,
        pip: &*pip,
    };
    let tcp = Peer {
        transport: Transport::Tcp,
        src_net: IpScope::Internal,
    };
    let udp = Peer {
        transport: Transport::Udp,
        src_net: IpScope::Internal,
    };
    match mode % 3 {
        0 => {
            // A TCP byte stream: framing, then each complete record.
            let mut rest = input;
            loop {
                match tcp_decode_frame(rest) {
                    Ok(TcpFrame::Complete {
                        message,
                        rest: next,
                    }) => {
                        check(kdc.handle(message, tcp, now(), &inputs, accounts));
                        if next.len() >= rest.len() {
                            break;
                        }
                        rest = next;
                    }
                    Ok(TcpFrame::Incomplete) => break,
                    Err(error) => {
                        check(kdc.reject_frame(error, tcp, now()));
                        break;
                    }
                }
            }
        }
        1 => check(kdc.handle(input, udp, now(), &inputs, accounts)),
        _ => check(kdc.handle(input, tcp, now(), &inputs, accounts)),
    }
});
