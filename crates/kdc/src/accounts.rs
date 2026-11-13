//! Where the KDC reads principals from: a KDC-owned trait, not the directory
//! store (main-session decision 3).
//!
//! An [`AccountSource`] answers, for an exact (realm, name), a NON-SECRET
//! account record: the keyd [`KeyHandle`] (never a key), the SID, group SIDs
//! and tier the PDP Subject needs, the account state, and the PA-ETYPE-INFO2
//! data (enctype, salt, s2kparams — public string-to-key hints, RFC 4120
//! 5.2.7.5). Every method returns `Result`; an `Err` fails the request closed:
//! [`AccountSourceError::Unavailable`] (the source cannot be reached — the
//! directory process down, an IPC deadline, Busy) as KDC_ERR_SVC_UNAVAILABLE,
//! [`AccountSourceError::Failed`] (it answered but cannot tell) as
//! KRB_ERR_GENERIC (docs/50 §3.7, R50-8; A-56).
//!
//! Lookup is exact (main-session decision 4; RFC 4120 6.1, 6.2): realm octets
//! and every name-string component, the name-type not significant. A source
//! holds at most one record per (realm, name) and role; returning two
//! (RFC 4120 7.5.9 KDC_ERR_PRINCIPAL_NOT_UNIQUE) is not expressible here.
//!
//! [`InMemoryAccounts`] is the in-memory implementation used by the tests and
//! the fuzz target. The directory-backed implementation (dirstore + the AD
//! schema subset of [MS-ADSC] / [MS-ADA1-3]) is the `directory-pip` crate
//! (docs/47 R47-11). The KDC receives the source with each request, not at
//! construction (docs/47 R47-14).
//!
//! Spec: main-session decisions 3, 4, 8; docs/11 §1 (Subject: principal,
//! groups, tier — from authoritative data, never client-claimed, P3); docs/25
//! §4 (re-evaluation at use, D53); RFC 4120 3.1.3, 3.3.3.1, 5.2.7.5, 6.2,
//! 7.5.9; docs/50 §3.7 (R50-8); docs/questions/Q-217 (A-56).

use crate::names::{same_name, same_realm};
use dtyp::Sid;
use keyd::KeyHandle;
use krb_proto::{EtypeInfo2Entry, KerberosString, KerberosTime, PrincipalName, Realm};
use pdp::Tier;
use std::collections::{BTreeMap, BTreeSet};

/// Whether an account may obtain tickets now.
///
/// Spec: main-session decision 8 (enabled, expiry, locked); RFC 4120 3.3.3.1
/// (hot-list by authentication time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountState {
    /// The account is enabled.
    pub enabled: bool,
    /// The account is locked out.
    pub locked: bool,
    /// The account expires at this instant (unusable from then on), if set.
    /// Ticket end and renew-till times are also capped at it (RFC 4120 3.1.3:
    /// principal-specific limits).
    pub expires: Option<KerberosTime>,
    /// Tickets whose initial authentication (authtime) is earlier than this
    /// instant are revoked: the RFC 4120 3.3.3.1 hot-list ("storing a range of
    /// issue timestamps for 'suspect tickets'; if a presented ticket had an
    /// authtime in that range, it would be rejected"). Set it when a password
    /// is reset or an account name is reassigned, so that a TGT issued before
    /// can no longer obtain service tickets. Phase 1 has no PAC: the TGT
    /// identifies its client by name only, so this is what keeps a reused
    /// name from inheriting an older account's TGTs.
    pub revoked_before: Option<KerberosTime>,
}

impl AccountState {
    /// An enabled, unlocked, non-expiring account with no revocation.
    pub const ACTIVE: AccountState = AccountState {
        enabled: true,
        locked: false,
        expires: None,
        revoked_before: None,
    };

    /// `true` if the account is enabled, not locked and not expired at `now`.
    /// Spec: main-session decision 8.
    pub fn usable_at(&self, now: &KerberosTime) -> bool {
        self.enabled && !self.locked && self.expires.is_none_or(|end| *now < end)
    }

    /// `true` if a ticket first authenticated at `authtime` is on the
    /// hot-list. Spec: RFC 4120 3.3.3.1.
    pub fn revokes(&self, authtime: &KerberosTime) -> bool {
        self.revoked_before.is_some_and(|cut| *authtime < cut)
    }
}

/// What kind of account a client principal is, as the directory says
/// (authoritative data, never client-claimed — like `tier`, docs/11 P3).
///
/// The KDC uses it for one decision: only a computer account's TGT may armor
/// an AS request (D126; docs/48 §3.1).
///
/// Spec: docs/48 §3.1, §7.2; Q-127 interim decision (ב) — `kind` derived by
/// the AccountSource from objectClass (P-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountKind {
    /// A user account.
    User,
    /// A computer account.
    Computer,
}

/// Whether an account may obtain a ticket without FAST armor (layer 1 of the
/// mandatory-FAST enforcement, docs/48 §7.2).
///
/// Spec: docs/48 §7.1 (FAST is required for every principal and every
/// exchange, with one exception), §7.2 (`armor_policy: Required |
/// BootstrapAllowed`, derived by the AccountSource from authoritative data:
/// objectClass computer → BootstrapAllowed, everything else → Required),
/// §7.3 (the bootstrap exception (א)); Q-127 interim decision (P-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmorPolicy {
    /// Every AS exchange must be FAST-armored. The default for every
    /// principal (docs/48 §7.1).
    Required,
    /// An unarmored AS request for this realm's TGT, pre-authenticated with
    /// PA-ENC-TIMESTAMP, is allowed — the bootstrap of a computer account,
    /// which needs a TGT before it can armor anything (docs/48 §7.3, H8). It
    /// takes effect only together with [`AccountKind::Computer`]
    /// ([`ClientAccount::may_bootstrap`]). The TGS is armored regardless.
    BootstrapAllowed,
}

/// A principal that requests tickets (the AS-REQ cname; the TGT's client at
/// TGS time). Not secret.
///
/// Spec: main-session decision 3; docs/11 §1 (Subject); RFC 4120 5.2.7.5;
/// docs/48 §3.1, §7.2 (`kind`, `armor_policy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAccount {
    /// keyd handle of the client's long-term key set (purpose
    /// `PrincipalLongterm`, docs/10 §4).
    pub key: KeyHandle,
    /// The account SID: the PDP Subject principal ([MS-DTYP] 2.4.2).
    pub sid: Sid,
    /// Expanded group SIDs: the PDP Subject groups (docs/11 §1).
    pub groups: BTreeSet<Sid>,
    /// Administrative tier, as the PIP derives it (docs/11 §1, P3).
    pub tier: Tier,
    /// Account state.
    pub state: AccountState,
    /// One entry per enctype of the client's keys: etype, salt and s2kparams
    /// (RFC 4120 5.2.7.5). Must describe the key set keyd holds for `key`.
    pub etype_info: Vec<EtypeInfo2Entry>,
    /// User or computer (docs/48 §3.1; Q-127 interim (ב)).
    pub kind: AccountKind,
    /// Whether an unarmored AS is allowed (docs/48 §7.2 layer 1).
    pub armor_policy: ArmorPolicy,
}

impl ClientAccount {
    /// `true` if this account may make an unarmored AS request (the
    /// bootstrap): a computer account whose policy is BootstrapAllowed.
    /// BootstrapAllowed on any other kind of account counts as Required —
    /// the exception is for computer accounts only (fail closed).
    /// Spec: docs/48 §7.2, §7.3 ("AS unarmored, only for armor_policy =
    /// BootstrapAllowed (computer account)"); Q-127 interim (P-10); AGENTS.md
    /// §6 (fail closed).
    pub(crate) fn may_bootstrap(&self) -> bool {
        self.kind == AccountKind::Computer && self.armor_policy == ArmorPolicy::BootstrapAllowed
    }

    /// `true` if a TGT of this account may serve as FAST armor ticket in an
    /// AS request: computer accounts only.
    /// Spec: docs/48 §3.1 (option (b): "only a TGT of a computer account",
    /// D126); RFC 6113 5.4.1.1 (the host machine's TGT as the armor ticket).
    pub(crate) fn may_armor(&self) -> bool {
        self.kind == AccountKind::Computer
    }
}

/// A principal tickets are issued FOR (the TGS-REQ sname). Not secret.
///
/// Spec: main-session decisions 3, 8; RFC 4120 3.1.3 ("information from the
/// Kerberos database indicating acceptable encryption methods for the
/// application server").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    /// keyd handle of the service key set (purpose `Service`, docs/10 §5).
    pub key: KeyHandle,
    /// Account state.
    pub state: AccountState,
    /// Encryption types the service accepts for its session keys.
    pub enctypes: Vec<i32>,
}

/// The account source could not answer. The request fails closed either
/// way. Carries no data (no name, no directory value).
///
/// Spec: main-session decision 3; docs/50 §3.7 (R50-8: "keyd / dird down ⇒
/// fail closed with an explicit `Unavailable`"); docs/questions/Q-217 (A-56).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountSourceError {
    /// The source answered but cannot tell: an inconsistent or unusable
    /// record, an inconsistent view, a store failure, a bound exceeded. The
    /// KDC answers KRB_ERR_GENERIC (main-session decision 3).
    Failed,
    /// The source cannot be reached now: the directory process is down, an
    /// IPC deadline passed, the server is Busy (docs/50 §3.6, §3.7). Decided
    /// before the source looked at the request — independent of its content
    /// and of every secret — so it is no oracle (A-56). The KDC answers
    /// KDC_ERR_SVC_UNAVAILABLE (RFC 4120 7.5.9, code 29) over TCP, nothing
    /// over UDP.
    Unavailable,
}

/// Where the KDC reads principals from.
///
/// `Ok(None)` means "no such principal in this role"; `Err` means "cannot
/// tell" and always refuses the request — an implementation reached over
/// IPC reports its transport failures as [`AccountSourceError::Unavailable`],
/// never as `Ok(None)` (which would read as an unknown principal).
///
/// Spec: main-session decision 3; RFC 4120 3.1.3, 3.3.3; docs/50 §3.7.
pub trait AccountSource {
    /// The client principal (realm, name), matched exactly.
    fn client(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ClientAccount>, AccountSourceError>;

    /// The service principal (realm, name), matched exactly.
    fn service(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ServiceAccount>, AccountSourceError>;
}

/// The lookup key of the in-memory source: realm octets and the name-string
/// components (the name-type is not part of it, RFC 4120 6.2).
type NameKey = (Vec<u8>, Vec<Vec<u8>>);

fn name_key(realm: &Realm, name: &PrincipalName) -> NameKey {
    (
        realm.as_bytes().to_vec(),
        name.name_string
            .iter()
            .map(|c| c.as_bytes().to_vec())
            .collect(),
    )
}

/// A record already exists for this (realm, name) and role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicatePrincipal;

/// In-memory account source (tests and fuzzing).
///
/// Spec: main-session decision 3.
#[derive(Debug, Clone, Default)]
pub struct InMemoryAccounts {
    clients: BTreeMap<NameKey, ClientAccount>,
    services: BTreeMap<NameKey, ServiceAccount>,
    fault: Option<AccountSourceError>,
}

impl InMemoryAccounts {
    /// An empty source.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a client record; refuses a second record for the same name.
    pub fn insert_client(
        &mut self,
        realm: &Realm,
        name: &PrincipalName,
        account: ClientAccount,
    ) -> Result<(), DuplicatePrincipal> {
        let key = name_key(realm, name);
        if self.clients.contains_key(&key) {
            return Err(DuplicatePrincipal);
        }
        self.clients.insert(key, account);
        Ok(())
    }

    /// Add a service record; refuses a second record for the same name.
    pub fn insert_service(
        &mut self,
        realm: &Realm,
        name: &PrincipalName,
        account: ServiceAccount,
    ) -> Result<(), DuplicatePrincipal> {
        let key = name_key(realm, name);
        if self.services.contains_key(&key) {
            return Err(DuplicatePrincipal);
        }
        self.services.insert(key, account);
        Ok(())
    }

    /// Mutable access to a client record (e.g. to disable it).
    pub fn client_mut(
        &mut self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Option<&mut ClientAccount> {
        self.clients.get_mut(&name_key(realm, name))
    }

    /// Mutable access to a service record.
    pub fn service_mut(
        &mut self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Option<&mut ServiceAccount> {
        self.services.get_mut(&name_key(realm, name))
    }

    /// Remove a client record, returning it.
    pub fn remove_client(&mut self, realm: &Realm, name: &PrincipalName) -> Option<ClientAccount> {
        self.clients.remove(&name_key(realm, name))
    }

    /// Make every lookup fail as [`AccountSourceError::Unavailable`] — the
    /// source cannot be reached (to exercise KDC_ERR_SVC_UNAVAILABLE); `false`
    /// restores normal answers.
    pub fn set_unavailable(&mut self, unavailable: bool) {
        self.fault = unavailable.then_some(AccountSourceError::Unavailable);
    }

    /// Make every lookup fail as [`AccountSourceError::Failed`] — the source
    /// cannot tell (to exercise the KRB_ERR_GENERIC path); `false` restores
    /// normal answers.
    pub fn set_failing(&mut self, failing: bool) {
        self.fault = failing.then_some(AccountSourceError::Failed);
    }
}

impl AccountSource for InMemoryAccounts {
    fn client(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ClientAccount>, AccountSourceError> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        Ok(self.clients.get(&name_key(realm, name)).cloned())
    }

    fn service(
        &self,
        realm: &Realm,
        name: &PrincipalName,
    ) -> Result<Option<ServiceAccount>, AccountSourceError> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        Ok(self.services.get(&name_key(realm, name)).cloned())
    }
}

/// A (realm, name) pair, for audit and error replies. Not secret.
/// Spec: RFC 4120 5.2.2 ("Taken together, a PrincipalName and a Realm form a
/// principal identifier").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedPrincipal {
    /// The realm.
    pub realm: Realm,
    /// The name.
    pub name: PrincipalName,
}

impl NamedPrincipal {
    /// `true` if this identifies (`realm`, `name`) under the exact-match rule.
    /// Spec: RFC 4120 6.1, 6.2.
    pub fn is(&self, realm: &Realm, name: &PrincipalName) -> bool {
        same_realm(&self.realm, realm) && same_name(&self.name, name)
    }

    /// Convenience constructor from text (tests, tools). `None` if a part is
    /// not a valid KerberosString (RFC 4120 5.2.1).
    pub fn from_text(realm: &str, name_type: i32, parts: &[&str]) -> Option<Self> {
        let realm = Realm::new(realm).ok()?;
        let mut name_string = Vec::with_capacity(parts.len());
        for part in parts {
            name_string.push(KerberosString::new(part).ok()?);
        }
        Some(NamedPrincipal {
            realm,
            name: PrincipalName {
                name_type,
                name_string,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyd::{KeyPurpose, PrincipalId};

    fn principal(parts: &[&str], name_type: i32) -> NamedPrincipal {
        NamedPrincipal::from_text("EXAMPLE.ORG", name_type, parts).unwrap()
    }

    fn service() -> ServiceAccount {
        ServiceAccount {
            key: KeyHandle::new(PrincipalId::from_bytes([1; 16]), KeyPurpose::Service),
            state: AccountState::ACTIVE,
            enctypes: vec![18],
        }
    }

    /// Exact match, name-type not significant (RFC 4120 6.2; decision 4).
    #[test]
    fn lookup_is_exact() {
        let mut source = InMemoryAccounts::new();
        let p = principal(&["host", "a.example.org"], 3);
        source.insert_service(&p.realm, &p.name, service()).unwrap();
        let other_type = principal(&["host", "a.example.org"], 0);
        assert!(source
            .service(&other_type.realm, &other_type.name)
            .unwrap()
            .is_some());
        let case = principal(&["HOST", "a.example.org"], 3);
        assert!(source.service(&case.realm, &case.name).unwrap().is_none());
        let joined = principal(&["host/a.example.org"], 3);
        assert!(source
            .service(&joined.realm, &joined.name)
            .unwrap()
            .is_none());
        assert_eq!(
            source.insert_service(&other_type.realm, &other_type.name, service()),
            Err(DuplicatePrincipal)
        );
        source.set_unavailable(true);
        assert_eq!(
            source.service(&p.realm, &p.name),
            Err(AccountSourceError::Unavailable)
        );
        source.set_failing(true);
        assert_eq!(
            source.client(&p.realm, &p.name),
            Err(AccountSourceError::Failed)
        );
        source.set_failing(false);
        assert!(source.service(&p.realm, &p.name).unwrap().is_some());
    }

    /// docs/48 §7.3 / Q-127 interim (P-10): only a computer account with
    /// BootstrapAllowed may bootstrap; BootstrapAllowed on a user counts as
    /// Required (fail closed). docs/48 §3.1 (D126): only a computer account
    /// may armor.
    #[test]
    fn bootstrap_and_armor_need_a_computer_account() {
        let account = |kind, armor_policy| ClientAccount {
            key: KeyHandle::new(
                PrincipalId::from_bytes([2; 16]),
                KeyPurpose::PrincipalLongterm,
            ),
            sid: Sid::new(dtyp::SECURITY_NT_AUTHORITY, &[21, 1, 2, 3, 1000]).unwrap(),
            groups: BTreeSet::new(),
            tier: Tier::Tier2,
            state: AccountState::ACTIVE,
            etype_info: Vec::new(),
            kind,
            armor_policy,
        };
        let cases = [
            (
                AccountKind::Computer,
                ArmorPolicy::BootstrapAllowed,
                true,
                true,
            ),
            (AccountKind::Computer, ArmorPolicy::Required, false, true),
            (
                AccountKind::User,
                ArmorPolicy::BootstrapAllowed,
                false,
                false,
            ),
            (AccountKind::User, ArmorPolicy::Required, false, false),
        ];
        for (kind, policy, bootstrap, armor) in cases {
            let a = account(kind, policy);
            assert_eq!(a.may_bootstrap(), bootstrap, "{kind:?} {policy:?}");
            assert_eq!(a.may_armor(), armor, "{kind:?} {policy:?}");
        }
    }

    /// Decision 8 states and the RFC 4120 3.3.3.1 hot-list.
    #[test]
    fn state_rules() {
        let now = KerberosTime::new(2026, 11, 13, 10, 0, 0).unwrap();
        let later = KerberosTime::new(2026, 11, 13, 11, 0, 0).unwrap();
        assert!(AccountState::ACTIVE.usable_at(&now));
        let mut s = AccountState::ACTIVE;
        s.enabled = false;
        assert!(!s.usable_at(&now));
        let mut s = AccountState::ACTIVE;
        s.locked = true;
        assert!(!s.usable_at(&now));
        let mut s = AccountState::ACTIVE;
        s.expires = Some(now);
        assert!(!s.usable_at(&now));
        s.expires = Some(later);
        assert!(s.usable_at(&now));
        let mut s = AccountState::ACTIVE;
        s.revoked_before = Some(later);
        assert!(s.revokes(&now));
        assert!(!s.revokes(&later));
    }
}
