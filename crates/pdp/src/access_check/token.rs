//! The authorization context ("Token") and SID matching.
//!
//! Spec: [MS-DTYP] 2.5.2 (Token / authorization context: `Sids[]`, which
//! "always contains at least the SID of the account"; `Privileges[]`),
//! 2.5.3.1.1 (SidInToken, with the PRINCIPAL_SELF substitution), 2.4.2.4
//! (well-known SIDs PRINCIPAL_SELF S-1-5-10 and OWNER_RIGHTS S-1-3-4);
//! [MS-ADTS] 5.1.3.3 ("Principal Self ... S-1-5-10 ... the server replaces
//! them with O!objectSid"), 6.1.1.2.6.18 (Owner Rights, objectSid S-1-3-4).
//!
//! The token here is `{Subject.principal} ∪ Subject.groups`. It carries no
//! privileges: docs/11 §1 gives the `Subject` none, so `Token.Privileges` is
//! empty in this model (affects the ACCESS_SYSTEM_SECURITY / WRITE_OWNER
//! clauses of [MS-DTYP] 2.5.3.2).

use dtyp::{Sid, CREATOR_SID_AUTHORITY, SECURITY_NT_AUTHORITY};

use crate::model::Subject;

/// Which kind of ACE is being matched. Only OWNER_RIGHTS needs the
/// distinction (see [`AccessContext::ace_applies`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AceKind {
    /// An ACE that grants (Allow / Object Allow).
    Grant,
    /// An ACE that denies (Deny / Object Deny).
    Deny,
}

/// PRINCIPAL_SELF, S-1-5-10. Spec: [MS-DTYP] 2.4.2.4; [MS-ADTS] 5.1.3.3.
pub(crate) fn is_principal_self(sid: &Sid) -> bool {
    sid.identifier_authority() == SECURITY_NT_AUTHORITY && sid.sub_authority() == [10]
}

/// OWNER_RIGHTS, S-1-3-4. Spec: [MS-DTYP] 2.4.2.4; [MS-ADTS] 6.1.1.2.6.18.
pub(crate) fn is_owner_rights(sid: &Sid) -> bool {
    sid.identifier_authority() == CREATOR_SID_AUTHORITY && sid.sub_authority() == [4]
}

/// Everything an access check needs to know about the requester and the
/// object, apart from the DACL.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AccessContext<'a> {
    subject: &'a Subject,
    /// `PrincipalSelfSubst` = O!objectSid, if the object has one.
    /// Spec: [MS-DTYP] 2.5.3.2 ("It can be null"); [MS-ADTS] 5.1.3.3.
    principal_self_substitute: Option<&'a Sid>,
    /// `SecurityDescriptor.Owner`. Spec: [MS-DTYP] 2.4.6, 2.5.3.2.
    owner: Option<&'a Sid>,
}

impl<'a> AccessContext<'a> {
    pub(crate) fn new(
        subject: &'a Subject,
        principal_self_substitute: Option<&'a Sid>,
        owner: Option<&'a Sid>,
    ) -> AccessContext<'a> {
        AccessContext {
            subject,
            principal_self_substitute,
            owner,
        }
    }

    /// The owner SID of the security descriptor, if any.
    pub(crate) fn owner(&self) -> Option<&'a Sid> {
        self.owner
    }

    /// "matches any SID in the requester's security context" — a plain
    /// membership test of `Token.Sids[]`. Spec: [MS-ADTS] 5.1.3.3.2 step 3;
    /// [MS-DTYP] 2.5.2.
    pub(crate) fn in_security_context(&self, sid: &Sid) -> bool {
        self.subject.principal == *sid || self.subject.groups.contains(sid)
    }

    /// SidInToken(Token, SidToTest, PrincipalSelfSubstitute).
    ///
    /// Spec: [MS-DTYP] 2.5.3.1.1, step by step:
    /// "IF SidToTest is the Well Known SID PRINCIPAL_SELF THEN set SidToTest
    /// to be PrincipalSelfSubstitute" — a null substitute matches no SID;
    /// "FOR EACH SID s in Token.Sids[] DO IF s equals SidToTest THEN return
    /// TRUE"; "Return FALSE".
    pub(crate) fn sid_in_token(&self, sid_to_test: &Sid) -> bool {
        let sid = if is_principal_self(sid_to_test) {
            match self.principal_self_substitute {
                Some(substitute) => substitute,
                None => return false,
            }
        } else {
            sid_to_test
        };
        self.in_security_context(sid)
    }

    /// `CALL SidInToken(Token, SecurityDescriptor.Owner, PrincipalSelfSubst)`.
    /// A descriptor without an owner has no owner in the token.
    /// Spec: [MS-DTYP] 2.5.3.2.
    pub(crate) fn owner_in_token(&self) -> bool {
        self.owner.is_some_and(|owner| self.sid_in_token(owner))
    }

    /// Does an ACE with trustee `ace_sid` apply to the requester?
    ///
    /// For every SID but OWNER_RIGHTS this is exactly SidInToken
    /// ([MS-DTYP] 2.5.3.2: "CALL SidInToken( Token, ACE.Sid, ... )"; [MS-ADTS]
    /// 5.1.3.3.2-5.1.3.3.4 step "If the SID in the ACE does not match any SID
    /// in the requester's security context, skip the ACE").
    ///
    /// OWNER_RIGHTS (S-1-3-4) — Q-050 (A-21), strict interim reading, verify
    /// in lab recording (docs/44): [MS-DTYP] 2.4.2.4 defines it as "A group
    /// that represents the current owner of the object", but the exact
    /// SidInToken algorithm only compares `Token.Sids[]`, which (built from
    /// the PAC) does not normally contain S-1-3-4. The two readings differ, so
    /// this follows the project's fail-closed resolution: a granting ACE
    /// applies only if BOTH readings say so (S-1-3-4 is in the token AND the
    /// requester holds the owner SID); a denying ACE applies if EITHER reading
    /// says so.
    pub(crate) fn ace_applies(&self, ace_sid: &Sid, kind: AceKind) -> bool {
        let literal = self.sid_in_token(ace_sid);
        if !is_owner_rights(ace_sid) {
            return literal;
        }
        let represents_owner = self.owner_in_token();
        match kind {
            AceKind::Grant => literal && represents_owner,
            AceKind::Deny => literal || represents_owner,
        }
    }
}
