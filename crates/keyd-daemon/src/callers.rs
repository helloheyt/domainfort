//! The static `uid → Role` map: the only source of a caller's role.
//!
//! A connection's identity is its peer credentials' uid (tokio
//! `UnixStream::peer_cred`, "effective credentials of the process which
//! called `connect`"), mapped through this table to a [`CallerId`] **once per
//! connection** and handed to every operation; keyd's compile-time
//! capability table stays the PEP (docs/10 §2, I2). Nothing the peer sends
//! can name a role: the channel has no role field (docs/50 §3.4).
//!
//! Invariants (the same rules crates/config enforces on `uid_roles`, checked
//! again here because tests build the map directly): at least one entry;
//! uid 0 is never mapped ("the host's root does not get a Role for free");
//! each uid at most one role ("a uid that appears twice ⇒ keyd does not
//! start"); each role at most one uid (docs/questions/Q-230 item 5, A-60).
//! An unmapped uid gets no role: its connection is closed without a reply
//! (docs/50 §3.2).
//!
//! Spec: docs/50 R50-3, §3.2; docs/10 §2; docs/questions/Q-230 item 5 (A-60).

use config::{RoleMap, RoleName};
use core::fmt;
use keyd::{CallerId, Role};

/// Why a `uid → Role` table was refused.
/// Spec: docs/50 R50-3, §3.2; docs/questions/Q-230 item 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerMapError {
    /// The table is empty.
    Empty,
    /// uid 0 is mapped.
    RootUid,
    /// A uid appears twice.
    DuplicateUid,
    /// A role appears twice.
    DuplicateRole,
}

impl fmt::Display for CallerMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CallerMapError::Empty => "uid to role map is empty",
            CallerMapError::RootUid => "uid 0 must never be mapped to a role",
            CallerMapError::DuplicateUid => "a uid is mapped twice",
            CallerMapError::DuplicateRole => "a role is mapped to two uids",
        })
    }
}

impl std::error::Error for CallerMapError {}

/// keyd's `uid → Role` table.
/// Spec: docs/50 R50-3, §3.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerMap {
    entries: Vec<(u32, Role)>,
}

/// The keyd role a configuration role name names (the names are keyd's
/// own variant names, crates/config keyd.rs).
/// Spec: docs/50 §3.2; docs/10 §2.
const fn role_of(name: RoleName) -> Role {
    match name {
        RoleName::Kdc => Role::Kdc,
        RoleName::Directory => Role::Directory,
        RoleName::Admin => Role::Admin,
        RoleName::Ldap => Role::Ldap,
    }
}

impl CallerMap {
    /// A table from `(uid, role)` entries, checked against the invariants in
    /// the module documentation.
    ///
    /// # Errors
    /// [`CallerMapError`].
    ///
    /// Spec: docs/50 R50-3, §3.2; docs/questions/Q-230 item 5.
    pub fn new(entries: &[(u32, Role)]) -> Result<CallerMap, CallerMapError> {
        if entries.is_empty() {
            return Err(CallerMapError::Empty);
        }
        for (index, &(uid, role)) in entries.iter().enumerate() {
            if uid == 0 {
                return Err(CallerMapError::RootUid);
            }
            let later = entries.get(index + 1..).unwrap_or_default();
            if later.iter().any(|&(other, _)| other == uid) {
                return Err(CallerMapError::DuplicateUid);
            }
            if later.iter().any(|&(_, other)| other == role) {
                return Err(CallerMapError::DuplicateRole);
            }
        }
        Ok(CallerMap {
            entries: entries.to_vec(),
        })
    }

    /// The table of keyd's configuration file (`uid_roles`).
    ///
    /// # Errors
    /// [`CallerMapError`] (not reachable for a parsed `RoleMap`, which obeys
    /// the same rules).
    ///
    /// Spec: docs/50 R50-3, §7.1.
    pub fn from_role_map(map: &RoleMap) -> Result<CallerMap, CallerMapError> {
        let entries: Vec<(u32, Role)> =
            map.iter().map(|(uid, name)| (uid, role_of(name))).collect();
        CallerMap::new(&entries)
    }

    /// The caller identity of a connection whose peer uid is `uid`, or `None`
    /// if the uid is not mapped (the connection is then closed without a
    /// reply). `caller(0)` is always `None`.
    ///
    /// Spec: docs/50 §3.2 ("`CallerId { uid, role }` built once per
    /// connection"); docs/10 §2.
    #[must_use]
    pub fn caller(&self, uid: u32) -> Option<CallerId> {
        self.entries
            .iter()
            .find(|&&(mapped, _)| mapped == uid)
            .map(|&(uid, role)| CallerId { uid, role })
    }

    /// The number of mapped uids (at least one).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Always `false`: an empty table is refused.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/50 R50-3, §3.2: a mapped uid gets exactly its role; an unmapped
    /// uid gets none.
    #[test]
    fn maps_each_uid_to_its_role() {
        let map = CallerMap::new(&[(803, Role::Kdc), (806, Role::Directory)]).unwrap();
        assert_eq!(
            map.caller(803),
            Some(CallerId {
                uid: 803,
                role: Role::Kdc
            })
        );
        assert_eq!(map.caller(806).map(|c| c.role), Some(Role::Directory));
        assert_eq!(map.caller(804), None);
        assert_eq!(map.caller(0), None);
        assert_eq!(map.len(), 2);
    }

    /// docs/50 R50-3 ("uid 0 is never mapped"; "a uid that appears twice ⇒
    /// keyd does not start"); docs/questions/Q-230 item 5 (one uid per role,
    /// at least one entry).
    #[test]
    fn refuses_what_r50_3_forbids() {
        assert_eq!(CallerMap::new(&[]), Err(CallerMapError::Empty));
        assert_eq!(
            CallerMap::new(&[(0, Role::Admin)]),
            Err(CallerMapError::RootUid)
        );
        assert_eq!(
            CallerMap::new(&[(7, Role::Kdc), (7, Role::Ldap)]),
            Err(CallerMapError::DuplicateUid)
        );
        assert_eq!(
            CallerMap::new(&[(7, Role::Kdc), (8, Role::Kdc)]),
            Err(CallerMapError::DuplicateRole)
        );
    }
}
