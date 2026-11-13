//! The seam between the KDC and keyd: the four `Kdc`-role operations of the
//! capability table, behind a trait.
//!
//! The KDC never sees a long-term key, a session key or a plaintext ticket:
//! it hands keyd handles, the client's padata, the AP-REQ and the raw
//! KDC-REQ-BODY, and receives one-time tokens, non-secret ticket facts and
//! sealed parts ("compute, don't give").
//!
//! [`LocalKeyd`] binds an in-process [`keyd::Keyd`] to the KDC's caller
//! identity. In the product, keyd is a separate process reached over the
//! minimal IPC codec (D34); that client is a later crate and will implement
//! the same trait.
//!
//! Spec: docs/10 §2 (Role `Kdc`: verify_preauth, issue_as_rep,
//! open_and_verify_tgt, issue_tgs_rep), §4, §5, §8; docs/09 א.1; docs/30 §1.

use crate::config::ConfigError;
use keyd::{
    AsRepParts, AsTicketTemplate, AuthnError, AuthnProof, CallerId, CtxId, EntropySource,
    IssueError, KeyHandle, KeyStore, Keyd, KeydConfig, Role, TgsRepParts, TgsTicketTemplate,
    TgtContext,
};
use krb_proto::{ApReq, KerberosTime, PaData};

/// The keyd operations the KDC calls (role `Kdc`).
///
/// Spec: docs/10 §2, §4, §5.
pub trait KeyCustody {
    /// keyd's configuration: realm, AES encryption types, clock skew and the
    /// ticket policy the KDC must plan within. Not secret.
    /// Spec: docs/10 §1; RFC 4120 §8.2.
    fn config(&self) -> &KeydConfig;

    /// docs/10 §4 `verify_preauth`.
    fn verify_preauth(
        &mut self,
        client: &KeyHandle,
        padata: &PaData,
        now: &KerberosTime,
    ) -> Result<AuthnProof, AuthnError>;

    /// docs/10 §4 `issue_as_rep`.
    fn issue_as_rep(
        &mut self,
        client: &KeyHandle,
        krbtgt: &KeyHandle,
        proof: &AuthnProof,
        template: &AsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<AsRepParts, IssueError>;

    /// docs/10 §5 `open_and_verify_tgt` (A-17: the authenticator checksum is
    /// verified over the raw KDC-REQ-BODY octets).
    fn open_and_verify_tgt(
        &mut self,
        krbtgt: &KeyHandle,
        ap_req: &ApReq,
        req_body: &[u8],
        now: &KerberosTime,
    ) -> Result<TgtContext, AuthnError>;

    /// docs/10 §5 `issue_tgs_rep`.
    fn issue_tgs_rep(
        &mut self,
        service: &KeyHandle,
        ctx: &CtxId,
        template: &TgsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<TgsRepParts, IssueError>;
}

/// An in-process keyd, called with the KDC's caller identity.
///
/// Spec: docs/10 §2 (`CallerId`, role `Kdc`).
pub struct LocalKeyd<S: KeyStore, A: keyd::AuditSink, E: EntropySource> {
    keyd: Keyd<S, A, E>,
    caller: CallerId,
}

impl<S: KeyStore, A: keyd::AuditSink, E: EntropySource> LocalKeyd<S, A, E> {
    /// Bind `keyd` to `caller`, which must hold the `Kdc` role (otherwise
    /// keyd would refuse every call; refusing here fails fast).
    /// Spec: docs/10 §2.
    pub fn new(keyd: Keyd<S, A, E>, caller: CallerId) -> Result<Self, ConfigError> {
        if caller.role != Role::Kdc {
            return Err(ConfigError::CustodyRole);
        }
        Ok(LocalKeyd { keyd, caller })
    }

    /// The wrapped keyd (e.g. to read its audit sink).
    pub fn keyd(&self) -> &Keyd<S, A, E> {
        &self.keyd
    }

    /// Mutable access to the wrapped keyd (its other roles' operations still
    /// require their own caller identities).
    pub fn keyd_mut(&mut self) -> &mut Keyd<S, A, E> {
        &mut self.keyd
    }
}

impl<S: KeyStore, A: keyd::AuditSink, E: EntropySource> KeyCustody for LocalKeyd<S, A, E> {
    fn config(&self) -> &KeydConfig {
        self.keyd.config()
    }

    fn verify_preauth(
        &mut self,
        client: &KeyHandle,
        padata: &PaData,
        now: &KerberosTime,
    ) -> Result<AuthnProof, AuthnError> {
        // Unarmored (no FAST armor): the armored AS path is docs/48 task T5.
        self.keyd
            .verify_preauth(&self.caller, client, padata, None, now)
    }

    fn issue_as_rep(
        &mut self,
        client: &KeyHandle,
        krbtgt: &KeyHandle,
        proof: &AuthnProof,
        template: &AsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<AsRepParts, IssueError> {
        // Unarmored (no FAST armor): the armored AS path is docs/48 task T5.
        self.keyd
            .issue_as_rep(&self.caller, client, krbtgt, proof, None, template, now)
    }

    fn open_and_verify_tgt(
        &mut self,
        krbtgt: &KeyHandle,
        ap_req: &ApReq,
        req_body: &[u8],
        now: &KerberosTime,
    ) -> Result<TgtContext, AuthnError> {
        self.keyd
            .open_and_verify_tgt(&self.caller, krbtgt, ap_req, req_body, now)
    }

    fn issue_tgs_rep(
        &mut self,
        service: &KeyHandle,
        ctx: &CtxId,
        template: &TgsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<TgsRepParts, IssueError> {
        self.keyd
            .issue_tgs_rep(&self.caller, service, ctx, template, now)
    }
}
