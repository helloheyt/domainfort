//! The engine's configuration: the values the rootDSE reports about this DC.
//!
//! The rootDSE "is a mechanism for clients of an LDAP server to interact with
//! the server itself" ([MS-ADTS] 3.1.1.3); it is not a directory object, so
//! the engine computes it (docs/49 §5.2, R49-10). Two values come from the
//! deployment: the DN of the domain NC and the DC's DNS name. They are
//! configuration data, not client input, and are checked once here so that
//! every rootDSE response encodes.
//!
//! The DN is held as the string the rootDSE returns. Producing an RFC 4514
//! string from the directory is task L5 (docs/49 §7, R49-11); until then the
//! deployment supplies it.
//!
//! Spec: [MS-ADTS] v20261026 3.1.1.3, 3.1.1.3.2.3, 3.1.1.3.2.4, 3.1.1.3.2.13,
//! 3.1.1.3.2.16; docs/49 §5.2 (R49-10), §7 (phase 1 names are ASCII only —
//! P-6, Q-080).

use parse_ldap::MAX_LDAPDN_OCTETS;

/// What the rootDSE says about this DC. Spec: docs/49 §5.2 (the phase-1
/// attribute table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootDseConfig {
    /// The DN of the root of the domain NC — the single value of
    /// namingContexts, defaultNamingContext and rootDomainNamingContext in a
    /// one-domain, one-NC phase 1 (docs/49 §5.2; docs/32 §2).
    /// Spec: [MS-ADTS] 3.1.1.3.2.3, 3.1.1.3.2.13, 3.1.1.3.2.16.
    pub naming_context: String,
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
    /// `naming_context` is empty, longer than [`MAX_LDAPDN_OCTETS`], or not
    /// printable ASCII.
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

impl RootDseConfig {
    /// Check both values. Spec: module documentation.
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if !acceptable(&self.naming_context) {
            return Err(ConfigError::NamingContext);
        }
        if !acceptable(&self.dns_host_name) {
            return Err(ConfigError::DnsHostName);
        }
        Ok(())
    }
}
