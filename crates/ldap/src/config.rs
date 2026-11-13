//! The engine's configuration: the values the rootDSE reports about this DC.
//!
//! The rootDSE "is a mechanism for clients of an LDAP server to interact with
//! the server itself" ([MS-ADTS] 3.1.1.3); it is not a directory object, so
//! the engine computes it (docs/49 §5.2, R49-10). Two values come from the
//! deployment: the naming context and the DC's DNS name. They are
//! configuration data, not client input, and are checked once here so that
//! every rootDSE response encodes.
//!
//! # One source of truth for the naming context (A-53)
//!
//! The naming context is the directory's own [`NamingContext`] value — the
//! same one the deployment gives `directory_pip::DirectoryContext::new`, whose
//! `dn_of` appends it to every DN of the NC. The rootDSE's namingContexts /
//! defaultNamingContext / rootDomainNamingContext are its RFC 4514 encoding
//! (parse-ldap's `Dn::encode` of its components, task L5), never a separate
//! string; and a directory search refuses (other) a view whose naming
//! context differs from this one (crate::search), so the two cannot drift.
//!
//! Spec: [MS-ADTS] v20261026 3.1.1.1.4, 3.1.1.1.5, 3.1.1.3, 3.1.1.3.2.3,
//! 3.1.1.3.2.4, 3.1.1.3.2.13, 3.1.1.3.2.16; RFC 4514 §2; docs/49 §5.2
//! (R49-10), §7 (phase 1 names are ASCII only — P-6, Q-080); A-53.

use directory_pip::NamingContext;
use parse_ldap::dn::Dn as LdapDn;
use parse_ldap::MAX_LDAPDN_OCTETS;

/// What the rootDSE says about this DC. Spec: docs/49 §5.2 (the phase-1
/// attribute table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootDseConfig {
    /// The DN of the root of the domain NC — the single value of
    /// namingContexts, defaultNamingContext and rootDomainNamingContext in a
    /// one-domain, one-NC phase 1 (docs/49 §5.2; docs/32 §2). The same value
    /// the directory context holds (module documentation; A-53).
    /// Spec: [MS-ADTS] 3.1.1.3.2.3, 3.1.1.3.2.13, 3.1.1.3.2.16.
    pub naming_context: NamingContext,
    /// "the DNS address of this DC" (dNSHostName).
    /// Spec: [MS-ADTS] 3.1.1.3.2.4.
    pub dns_host_name: String,
}

/// The engine's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfig {
    /// The rootDSE values (docs/49 §5.2).
    pub root_dse: RootDseConfig,
}

/// Why a configuration was refused. Carries no data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// The naming context does not encode as an LDAPDN of at most
    /// [`MAX_LDAPDN_OCTETS`] printable-ASCII octets.
    NamingContext,
    /// `dns_host_name` is empty, longer than [`MAX_LDAPDN_OCTETS`], or not
    /// printable ASCII.
    DnsHostName,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigError::NamingContext => f.write_str("invalid rootDSE naming context"),
            ConfigError::DnsHostName => f.write_str("invalid rootDSE DNS host name"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// A configuration value the engine will put on the wire: non-empty, bounded
/// by the codec's LDAPDN bound (so the response always encodes), printable
/// ASCII (phase 1 names are ASCII only — P-6, Q-080; docs/49 §7).
/// Spec: parse-ldap `MAX_LDAPDN_OCTETS` (docs/49 §2.4); docs/49 §7.
pub(crate) fn acceptable(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LDAPDN_OCTETS
        && value.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// The checked rootDSE values the engine sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootDseValues {
    /// The naming context's RFC 4514 string. Spec: RFC 4514 §2; A-53.
    pub(crate) naming_context: String,
    /// dNSHostName.
    pub(crate) dns_host_name: String,
}

/// The RFC 4514 string of the naming context: parse-ldap's encoding of the
/// directory's canonical components (`dc=n1`, …). `None` if it cannot be
/// encoded within the LDAPDN bound.
/// Spec: RFC 4514 §2; docs/49 §7 (R49-11: `dn_of` → string); Q-195 item 8.
pub(crate) fn naming_context_string(naming_context: &NamingContext) -> Option<String> {
    LdapDn::from_directory_rdns(naming_context.dn().rdns())
        .ok()
        .map(|dn| dn.encode())
}

impl RootDseConfig {
    /// Check both values and produce what the rootDSE sends.
    /// Spec: module documentation.
    pub(crate) fn validate(&self) -> Result<RootDseValues, ConfigError> {
        let naming_context =
            naming_context_string(&self.naming_context).ok_or(ConfigError::NamingContext)?;
        if !acceptable(&naming_context) {
            return Err(ConfigError::NamingContext);
        }
        if !acceptable(&self.dns_host_name) {
            return Err(ConfigError::DnsHostName);
        }
        Ok(RootDseValues {
            naming_context,
            dns_host_name: self.dns_host_name.clone(),
        })
    }
}
