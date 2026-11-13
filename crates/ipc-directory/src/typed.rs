//! The typed layer: the requests and records of the channel as the kdc's and
//! dird's own types, each value passed through its strict decoder —
//! `PrincipalName` through krb-proto's DER, realms and salts through the
//! KerberosString rules, times through `KerberosTime::new`, SIDs through
//! dtyp's [MS-DTYP] 2.4.2.2 decoder. Group sets must arrive in ascending SID
//! order with no repetition, so every value has exactly one encoding and
//! `encode(decode(b)) == b` holds for everything that decodes.
//!
//! Spec: docs/50 §3.3 ("Kerberos values … decoded in `krb-proto`"; "a single
//! encoding per value"; replies decoded with the same strictness), §3.4;
//! docs/questions/Q-245 item 1 (A-63).

use crate::channel::ViewFailure;
use crate::wire::{
    DirectoryReply, DirectoryRequest, WireClient, WireEtypeInfo, WireService, WireState, WireTime,
};
use core::fmt;
use dtyp::Sid;
use ipc::DerBlob;
use kdc::{AccountSourceError, AccountState, ClientAccount, ServiceAccount};
use keyd_types::KeyHandle;
use krb_proto::{EtypeInfo2Entry, KerberosString, KerberosTime, PrincipalName, Realm};
use pdp::{PipError, PolicyVersion, Tier};
use std::collections::BTreeSet;

/// A value on the wire did not pass its strict decoder, or a reply does not
/// belong to the request. Carries no octet.
/// Spec: docs/50 §3.3, §8.2 ("IPC errors carry a code, not content").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionError {
    /// A realm or salt is not a valid KerberosString (RFC 4120 5.2.1).
    KerberosString,
    /// A `PrincipalName` DER did not decode strictly, or could not be encoded.
    PrincipalName,
    /// A `KerberosTime` field set is not a valid time (RFC 4120 5.2.3).
    KerberosTime,
    /// A SID packet did not decode ([MS-DTYP] 2.4.2.2).
    Sid,
    /// A group set is not in strictly ascending SID order.
    GroupOrder,
    /// A naming-context label is empty or not printable ASCII.
    Label,
    /// The reply is valid but answers another request.
    UnexpectedReply,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConversionError::KerberosString => "invalid KerberosString",
            ConversionError::PrincipalName => "invalid PrincipalName",
            ConversionError::KerberosTime => "invalid KerberosTime",
            ConversionError::Sid => "invalid SID",
            ConversionError::GroupOrder => "group SIDs not in ascending order",
            ConversionError::Label => "invalid naming-context label",
            ConversionError::UnexpectedReply => "reply does not answer the request",
        })
    }
}

impl std::error::Error for ConversionError {}

/// A question answered over a pinned view (the four rows of docs/50 §3.4
/// that read the directory).
/// Spec: docs/50 §3.4; crates/kdc accounts.rs; crates/pdp pip.rs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// `AccountSource::client`.
    Client {
        /// The realm.
        realm: Realm,
        /// The name.
        name: PrincipalName,
    },
    /// `AccountSource::service`.
    Service {
        /// The realm.
        realm: Realm,
        /// The name.
        name: PrincipalName,
    },
    /// `Pip::expand_groups`.
    ExpandGroups {
        /// The principal.
        sid: Sid,
    },
    /// `Pip::tier_of`.
    TierOf {
        /// The principal.
        sid: Sid,
        /// Its groups.
        groups: BTreeSet<Sid>,
    },
}

/// A typed request.
/// Spec: docs/50 §3.4, §7.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Pin a snapshot to the connection.
    BeginView,
    /// A question over view `view`.
    Query {
        /// The pinned view's id.
        view: u64,
        /// The question.
        query: Query,
    },
    /// Release view `view`.
    EndView {
        /// The pinned view's id.
        view: u64,
    },
    /// Describe the domain.
    DescribeDomain,
    /// Health check.
    Ping,
}

/// The domain as dird describes it once at the kdc's start (docs/50 §7.5:
/// `DescribeDomain` → `KdcConfig::new(realm, krbtgt)`).
/// Spec: docs/50 §3.4 (`DescribeDomain | — | krbtgt: KeyHandle, realm`),
/// §7.5; A-53 (naming context); R50-2 (policy version).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainDescription {
    /// The realm.
    pub realm: Realm,
    /// The naming context's labels n1 … nk, leaf first (A-53).
    pub naming_context: Vec<String>,
    /// keyd's handle of the krbtgt key set (`DirectoryView::krbtgt_handle`,
    /// docs/47 R47-2).
    pub krbtgt: KeyHandle,
    /// The version of dird's policy.
    pub policy_version: PolicyVersion,
}

// ---- conversions of single values ------------------------------------------

/// Spec: RFC 4120 5.2.1 (krb-proto's KerberosString rule).
fn kerberos_string(octets: &[u8]) -> Result<KerberosString, ConversionError> {
    KerberosString::from_bytes(octets).map_err(|_| ConversionError::KerberosString)
}

/// Spec: docs/50 §3.3 ("decoded in krb-proto").
fn principal_name(der: &DerBlob) -> Result<PrincipalName, ConversionError> {
    PrincipalName::decode(der.as_der()).map_err(|_| ConversionError::PrincipalName)
}

/// Spec: docs/50 §3.3.
fn principal_name_der(name: &PrincipalName) -> Result<DerBlob, ConversionError> {
    name.encode()
        .map(DerBlob::new)
        .map_err(|_| ConversionError::PrincipalName)
}

/// Spec: [MS-DTYP] 2.4.2.2 (strict; the packet must be the whole field).
fn sid(octets: &[u8]) -> Result<Sid, ConversionError> {
    Sid::decode(octets).map_err(|_| ConversionError::Sid)
}

/// A set of SIDs from its packets, which must be in strictly ascending SID
/// order — the order a `BTreeSet<Sid>` is encoded in, so the set has exactly
/// one encoding.
/// Spec: docs/50 §3.3 ("a single encoding per value").
fn sid_set(packets: &[Vec<u8>]) -> Result<BTreeSet<Sid>, ConversionError> {
    let mut set = BTreeSet::new();
    let mut last: Option<Sid> = None;
    for packet in packets {
        let next = sid(packet)?;
        if last.as_ref().is_some_and(|previous| *previous >= next) {
            return Err(ConversionError::GroupOrder);
        }
        set.insert(next);
        last = Some(next);
    }
    Ok(set)
}

/// The packets of a SID set, in its (ascending) order.
fn sid_packets(set: &BTreeSet<Sid>) -> Vec<Vec<u8>> {
    set.iter().map(Sid::encode).collect()
}

/// Spec: RFC 4120 5.2.3 (krb-proto's `KerberosTime::new`).
fn time(wire: &WireTime) -> Result<KerberosTime, ConversionError> {
    KerberosTime::new(
        wire.year,
        wire.month,
        wire.day,
        wire.hour,
        wire.minute,
        wire.second,
    )
    .map_err(|_| ConversionError::KerberosTime)
}

/// Spec: RFC 4120 5.2.3.
fn wire_time(time: &KerberosTime) -> WireTime {
    WireTime {
        year: time.year(),
        month: time.month(),
        day: time.day(),
        hour: time.hour(),
        minute: time.minute(),
        second: time.second(),
    }
}

/// Spec: crates/kdc accounts.rs (`AccountState`).
fn state(wire: &WireState) -> Result<AccountState, ConversionError> {
    Ok(AccountState {
        enabled: wire.enabled,
        locked: wire.locked,
        expires: wire.expires.as_ref().map(time).transpose()?,
        revoked_before: wire.revoked_before.as_ref().map(time).transpose()?,
    })
}

/// Spec: crates/kdc accounts.rs.
fn wire_state(state: &AccountState) -> WireState {
    WireState {
        enabled: state.enabled,
        locked: state.locked,
        expires: state.expires.as_ref().map(wire_time),
        revoked_before: state.revoked_before.as_ref().map(wire_time),
    }
}

// ---- records ---------------------------------------------------------------

impl WireClient {
    /// The wire form of a client record. Spec: docs/50 §3.4.
    #[must_use]
    pub fn from_account(account: &ClientAccount) -> WireClient {
        WireClient {
            key: account.key,
            sid: account.sid.encode(),
            groups: sid_packets(&account.groups),
            tier: account.tier,
            state: wire_state(&account.state),
            etype_info: account
                .etype_info
                .iter()
                .map(|entry| WireEtypeInfo {
                    etype: entry.etype,
                    salt: entry.salt.as_ref().map(|s| s.as_bytes().to_vec()),
                    s2kparams: entry.s2kparams.clone(),
                })
                .collect(),
            kind: account.kind,
            armor_policy: account.armor_policy,
        }
    }

    /// The client record, every value through its strict decoder.
    ///
    /// # Errors
    /// [`ConversionError`].
    ///
    /// Spec: docs/50 §3.3, §3.4.
    pub fn to_account(&self) -> Result<ClientAccount, ConversionError> {
        let etype_info = self
            .etype_info
            .iter()
            .map(|entry| {
                Ok(EtypeInfo2Entry {
                    etype: entry.etype,
                    salt: entry.salt.as_deref().map(kerberos_string).transpose()?,
                    s2kparams: entry.s2kparams.clone(),
                })
            })
            .collect::<Result<Vec<_>, ConversionError>>()?;
        Ok(ClientAccount {
            key: self.key,
            sid: sid(&self.sid)?,
            groups: sid_set(&self.groups)?,
            tier: self.tier,
            state: state(&self.state)?,
            etype_info,
            kind: self.kind,
            armor_policy: self.armor_policy,
        })
    }
}

impl WireService {
    /// The wire form of a service record. Spec: docs/50 §3.4.
    #[must_use]
    pub fn from_account(account: &ServiceAccount) -> WireService {
        WireService {
            key: account.key,
            state: wire_state(&account.state),
            enctypes: account.enctypes.clone(),
        }
    }

    /// The service record, every value through its strict decoder.
    ///
    /// # Errors
    /// [`ConversionError`].
    ///
    /// Spec: docs/50 §3.3, §3.4.
    pub fn to_account(&self) -> Result<ServiceAccount, ConversionError> {
        Ok(ServiceAccount {
            key: self.key,
            state: state(&self.state)?,
            enctypes: self.enctypes.clone(),
        })
    }
}

// ---- requests --------------------------------------------------------------

impl Request {
    /// The wire form.
    ///
    /// # Errors
    /// [`ConversionError::PrincipalName`] if a name cannot be encoded.
    ///
    /// Spec: docs/50 §3.4.
    pub fn to_wire(&self) -> Result<DirectoryRequest, ConversionError> {
        Ok(match self {
            Request::BeginView => DirectoryRequest::BeginView,
            Request::EndView { view } => DirectoryRequest::EndView { view: *view },
            Request::DescribeDomain => DirectoryRequest::DescribeDomain,
            Request::Ping => DirectoryRequest::Ping,
            Request::Query { view, query } => match query {
                Query::Client { realm, name } => DirectoryRequest::Client {
                    view: *view,
                    realm: realm.as_bytes().to_vec(),
                    name: principal_name_der(name)?,
                },
                Query::Service { realm, name } => DirectoryRequest::Service {
                    view: *view,
                    realm: realm.as_bytes().to_vec(),
                    name: principal_name_der(name)?,
                },
                Query::ExpandGroups { sid } => DirectoryRequest::ExpandGroups {
                    view: *view,
                    sid: sid.encode(),
                },
                Query::TierOf { sid, groups } => DirectoryRequest::TierOf {
                    view: *view,
                    sid: sid.encode(),
                    groups: sid_packets(groups),
                },
            },
        })
    }

    /// The typed request, every value through its strict decoder.
    ///
    /// # Errors
    /// [`ConversionError`] — the server answers `Refused::Malformed`.
    ///
    /// Spec: docs/50 §3.3, §3.4.
    pub fn from_wire(wire: &DirectoryRequest) -> Result<Request, ConversionError> {
        Ok(match wire {
            DirectoryRequest::BeginView => Request::BeginView,
            DirectoryRequest::EndView { view } => Request::EndView { view: *view },
            DirectoryRequest::DescribeDomain => Request::DescribeDomain,
            DirectoryRequest::Ping => Request::Ping,
            DirectoryRequest::Client { view, realm, name } => Request::Query {
                view: *view,
                query: Query::Client {
                    realm: kerberos_string(realm)?,
                    name: principal_name(name)?,
                },
            },
            DirectoryRequest::Service { view, realm, name } => Request::Query {
                view: *view,
                query: Query::Service {
                    realm: kerberos_string(realm)?,
                    name: principal_name(name)?,
                },
            },
            DirectoryRequest::ExpandGroups { view, sid: packet } => Request::Query {
                view: *view,
                query: Query::ExpandGroups { sid: sid(packet)? },
            },
            DirectoryRequest::TierOf {
                view,
                sid: packet,
                groups,
            } => Request::Query {
                view: *view,
                query: Query::TierOf {
                    sid: sid(packet)?,
                    groups: sid_set(groups)?,
                },
            },
        })
    }
}

// ---- replies ---------------------------------------------------------------

impl DirectoryReply {
    /// The reply to a `Client` query.
    /// Spec: docs/50 §3.4; crates/kdc accounts.rs.
    #[must_use]
    pub fn from_client(result: &Result<Option<ClientAccount>, AccountSourceError>) -> Self {
        match result {
            Ok(record) => DirectoryReply::Client(record.as_ref().map(WireClient::from_account)),
            Err(error) => DirectoryReply::AccountFailure(*error),
        }
    }

    /// The reply to a `Service` query.
    /// Spec: docs/50 §3.4; crates/kdc accounts.rs.
    #[must_use]
    pub fn from_service(result: &Result<Option<ServiceAccount>, AccountSourceError>) -> Self {
        match result {
            Ok(record) => DirectoryReply::Service(record.as_ref().map(WireService::from_account)),
            Err(error) => DirectoryReply::AccountFailure(*error),
        }
    }

    /// The reply to an `ExpandGroups` query.
    /// Spec: docs/50 §3.4; crates/pdp pip.rs.
    #[must_use]
    pub fn from_groups(result: &Result<BTreeSet<Sid>, PipError>) -> Self {
        match result {
            Ok(groups) => DirectoryReply::Groups(sid_packets(groups)),
            Err(error) => DirectoryReply::PipFailure(*error),
        }
    }

    /// The reply to a `TierOf` query.
    /// Spec: docs/50 §3.4; crates/pdp pip.rs.
    #[must_use]
    pub fn from_tier(result: &Result<Tier, PipError>) -> Self {
        match result {
            Ok(tier) => DirectoryReply::Tier(*tier),
            Err(error) => DirectoryReply::PipFailure(*error),
        }
    }

    /// The reply to `DescribeDomain`.
    /// Spec: docs/50 §3.4.
    #[must_use]
    pub fn from_domain(domain: &DomainDescription) -> Self {
        DirectoryReply::Domain {
            realm: domain.realm.as_bytes().to_vec(),
            naming_context: domain
                .naming_context
                .iter()
                .map(|label| label.as_bytes().to_vec())
                .collect(),
            krbtgt: domain.krbtgt,
            policy_version: domain.policy_version.0,
        }
    }

    /// Read the answer to a `Client` query.
    ///
    /// # Errors
    /// [`ConversionError`] if a value does not decode or the reply answers
    /// another request.
    ///
    /// Spec: docs/50 §3.3, §3.4.
    pub fn into_client(
        self,
    ) -> Result<Result<Option<ClientAccount>, AccountSourceError>, ConversionError> {
        match self {
            DirectoryReply::Client(None) => Ok(Ok(None)),
            DirectoryReply::Client(Some(record)) => Ok(Ok(Some(record.to_account()?))),
            DirectoryReply::AccountFailure(error) => Ok(Err(error)),
            _ => Err(ConversionError::UnexpectedReply),
        }
    }

    /// Read the answer to a `Service` query.
    ///
    /// # Errors
    /// [`ConversionError`].
    ///
    /// Spec: docs/50 §3.3, §3.4.
    pub fn into_service(
        self,
    ) -> Result<Result<Option<ServiceAccount>, AccountSourceError>, ConversionError> {
        match self {
            DirectoryReply::Service(None) => Ok(Ok(None)),
            DirectoryReply::Service(Some(record)) => Ok(Ok(Some(record.to_account()?))),
            DirectoryReply::AccountFailure(error) => Ok(Err(error)),
            _ => Err(ConversionError::UnexpectedReply),
        }
    }

    /// Read the answer to an `ExpandGroups` query.
    ///
    /// # Errors
    /// [`ConversionError`].
    ///
    /// Spec: docs/50 §3.3, §3.4.
    pub fn into_groups(self) -> Result<Result<BTreeSet<Sid>, PipError>, ConversionError> {
        match self {
            DirectoryReply::Groups(packets) => Ok(Ok(sid_set(&packets)?)),
            DirectoryReply::PipFailure(error) => Ok(Err(error)),
            _ => Err(ConversionError::UnexpectedReply),
        }
    }

    /// Read the answer to a `TierOf` query.
    ///
    /// # Errors
    /// [`ConversionError`].
    ///
    /// Spec: docs/50 §3.4.
    pub fn into_tier(self) -> Result<Result<Tier, PipError>, ConversionError> {
        match self {
            DirectoryReply::Tier(tier) => Ok(Ok(tier)),
            DirectoryReply::PipFailure(error) => Ok(Err(error)),
            _ => Err(ConversionError::UnexpectedReply),
        }
    }

    /// Read the answer to `DescribeDomain`.
    ///
    /// # Errors
    /// [`ConversionError`].
    ///
    /// Spec: docs/50 §3.3, §3.4; A-53.
    pub fn into_domain(self) -> Result<DomainDescription, ConversionError> {
        match self {
            DirectoryReply::Domain {
                realm,
                naming_context,
                krbtgt,
                policy_version,
            } => Ok(DomainDescription {
                realm: kerberos_string(&realm)?,
                naming_context: naming_context
                    .iter()
                    .map(|label| label_text(label))
                    .collect::<Result<Vec<_>, _>>()?,
                krbtgt,
                policy_version: PolicyVersion(policy_version),
            }),
            _ => Err(ConversionError::UnexpectedReply),
        }
    }

    /// Read the answer to `BeginView`: the view id and dird's policy
    /// version, or the view protocol's refusal.
    ///
    /// # Errors
    /// [`ConversionError::UnexpectedReply`].
    ///
    /// Spec: docs/50 §3.4.
    pub fn into_view_begun(
        self,
    ) -> Result<Result<(u64, PolicyVersion), ViewFailure>, ConversionError> {
        match self {
            DirectoryReply::ViewBegun {
                view,
                policy_version,
            } => Ok(Ok((view, PolicyVersion(policy_version)))),
            DirectoryReply::ViewFailure(failure) => Ok(Err(failure)),
            _ => Err(ConversionError::UnexpectedReply),
        }
    }
}

/// A naming-context label: non-empty printable ASCII (A-53; P-6, Q-080).
/// Spec: crates/directory-pip naming.rs (label rules).
fn label_text(octets: &[u8]) -> Result<String, ConversionError> {
    if octets.is_empty() || !octets.iter().all(|b| (0x20..=0x7E).contains(b)) {
        return Err(ConversionError::Label);
    }
    core::str::from_utf8(octets)
        .map(str::to_owned)
        .map_err(|_| ConversionError::Label)
}
