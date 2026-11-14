//! The PDP `Subject` of an administrator, built from a service ticket keyd
//! verified.
//!
//! The verified context is an **input** here: dird's admin service (task
//! A8) has keyd run `open_and_verify_service_ticket` on the AP-REQ admind
//! forwarded opaquely, and passes the ticket's facts (crealm, cname,
//! authtime). This crate never accepts a SID, a name, groups or a tier that
//! the caller claims (A-73; docs/06 §2 and docs/11 §10 P3 as cited in
//! docs/51 §5.3): the cname is resolved through the directory exactly as the
//! KDC resolves an AS client (`AccountSource::client`, docs/47 §1.3), and
//! the SID, the transitive groups and the tier all come from that one view.
//!
//! Spec: docs/51 §5.3 (option D, R51-8; "principal = the account's
//! objectSid; groups = the transitive closure; tier = tier_of from the same
//! view; auth = {Kerberos, armored: false, ticket_age: now − authtime,
//! ticket_verified: true}"), §5.5 (R51-10); docs/47 §1.3, §4, §4.5
//! (`usable_at`, `revokes` — RFC 4120 §3.3.3.1 as cited there); A-73.

use core::time::Duration;
use std::collections::BTreeMap;

use directory_pip::DirectoryView;
use dtyp::{Guid, Sid};
use kdc::AccountSource;
use keyd_types::{OperationDigest, ServiceContext};
use krb_proto::{KerberosTime, PrincipalName, Realm};
use pdp::{AuthContext, AuthStrength, Subject};

use crate::time;

/// The facts of a service ticket keyd verified (RFC 4120 §3.2.3 under the
/// admin service's key), as the caller received them from keyd.
/// Spec: docs/51 §5.3, §7.4 step 1; crate keyd-types `ServiceContext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTicket {
    /// The client realm of the ticket.
    pub crealm: Realm,
    /// The client name of the ticket.
    pub cname: PrincipalName,
    /// The time of the initial authentication (RFC 4120 §5.3 authtime).
    pub authtime: KerberosTime,
    /// The operation digest keyd verified the AP-REQ's Authenticator `cksum`
    /// over (RFC 4120 §5.5.1, key usage 10) — the operation the ticket's
    /// holder bound it to; `None` if keyd reported no binding. Copied from
    /// keyd's answer, never computed here.
    /// Spec: docs/52 §5 items 3-4 (R2); crate keyd-types
    /// `ServiceContext::bound_operation`.
    pub bound_operation: Option<OperationDigest>,
}

impl VerifiedTicket {
    /// The facts of keyd's verification result (no key, no context id).
    /// Spec: crate keyd-types `ServiceContext` (docs/49 §3.3); docs/52 §5
    /// item 4 (the verified binding).
    #[must_use]
    pub fn from_service_context(context: &ServiceContext) -> VerifiedTicket {
        VerifiedTicket {
            crealm: context.crealm.clone(),
            cname: context.cname.clone(),
            authtime: context.authtime,
            bound_operation: context.bound_operation,
        }
    }

    /// `true` if keyd verified this ticket's AP-REQ bound to `digest`.
    /// Spec: docs/52 §5 item 4.
    #[must_use]
    pub fn bound_to(&self, digest: &OperationDigest) -> bool {
        self.bound_operation.as_ref() == Some(digest)
    }
}

/// `true` if every ticket a request relies on — the requester's and each
/// approval's — was verified by keyd bound to `digest`, the digest of the
/// request being decided. Only then does the PEP report `channel_bound` to
/// the PDP (docs/11 §4: a write needs it).
/// Spec: docs/52 §5 item 4 ("`transport_sec.channel_bound = true` only after
/// verification"); docs/11 §1, §4.
pub(crate) fn all_bound<'t>(
    digest: &OperationDigest,
    tickets: impl IntoIterator<Item = &'t VerifiedTicket>,
) -> bool {
    tickets.into_iter().all(|t| t.bound_to(digest))
}

/// Why no Subject was built. Both are refusals; neither says why to the
/// client (A-26: a uniform `Denied`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectError {
    /// The name resolves to no account, to an account that is not usable
    /// now (disabled, expired, no password set), or the ticket predates the
    /// account's last password set or creation (revoked).
    NotUsable,
    /// The directory could not answer (fail closed).
    Unavailable,
}

/// An administrator's PDP Subject, with the facts it was built from.
/// Spec: docs/51 §5.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSubject {
    subject: Subject,
    ticket_age: Duration,
    guid: Guid,
}

impl AdminSubject {
    /// Build the Subject of the ticket's client (module documentation):
    ///
    /// 1. `AccountSource::client(crealm, cname)` on `view` — the configured
    ///    realm, exactly one component, the sAMAccountName index and an
    ///    octet-for-octet compare, user or computer, never krbtgt (docs/47
    ///    §1.3). No account ⇒ [`SubjectError::NotUsable`].
    /// 2. The account must be usable at `now` and must not revoke a ticket
    ///    first authenticated at `authtime` (docs/47 §4, §4.5) — otherwise
    ///    [`SubjectError::NotUsable`], the same answer as for an unknown name.
    /// 3. `principal` = its objectSid, `groups` = its transitive security
    ///    groups, `tier` = `tier_of` from the same view, `claims` = none,
    ///    `auth = {Kerberos, armored: false, ticket_age: now − authtime,
    ///    ticket_verified: true}` (an AP-REQ is not FAST).
    ///
    /// Spec: docs/51 §5.3; docs/47 §1.3, §4, §4.5; A-73.
    pub fn from_verified_ticket(
        view: &DirectoryView<'_>,
        crealm: &Realm,
        cname: &PrincipalName,
        authtime: &KerberosTime,
        now: &KerberosTime,
    ) -> Result<AdminSubject, SubjectError> {
        let account = match view.client(crealm, cname) {
            Ok(Some(account)) => account,
            Ok(None) => return Err(SubjectError::NotUsable),
            Err(_) => return Err(SubjectError::Unavailable),
        };
        // Usable now, and the ticket is not on the hot-list (docs/47 §4.5,
        // R47-7: a password set or a reused name revokes older tickets).
        if !account.state.usable_at(now) || account.state.revokes(authtime) {
            return Err(SubjectError::NotUsable);
        }
        let ticket_age = time::ticket_age(now, authtime);
        // The account's objectGUID: the principal id of its key set handle
        // (docs/47 §1.3: the handle is `(objectGUID, PrincipalLongterm)`).
        let guid = Guid::from_packet(account.key.principal.as_bytes());
        Ok(AdminSubject {
            subject: Subject {
                principal: account.sid,
                groups: account.groups,
                claims: BTreeMap::new(),
                auth: AuthContext {
                    strength: AuthStrength::Kerberos,
                    armored: false,
                    ticket_age,
                    ticket_verified: true,
                },
                tier: account.tier,
            },
            ticket_age,
            guid,
        })
    }

    /// The account's objectGUID — what keyd's `DualControlToken` names an
    /// approver by (crates/keyd-types model.rs; docs/51 §6). Spec: docs/47
    /// §1.3 (the key handle's principal is the objectGUID).
    #[must_use]
    pub fn guid(&self) -> Guid {
        self.guid
    }

    /// The Subject for `pdp::decide`.
    #[must_use]
    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    /// The account's objectSid.
    #[must_use]
    pub fn sid(&self) -> &Sid {
        &self.subject.principal
    }

    /// `now − authtime`.
    #[must_use]
    pub fn ticket_age(&self) -> Duration {
        self.ticket_age
    }
}
