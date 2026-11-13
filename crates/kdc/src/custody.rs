//! The seam between the KDC and keyd: the `Kdc`-role operations of the
//! capability table, behind a trait.
//!
//! The KDC never sees a long-term key, a session key, a FAST key or a
//! plaintext ticket: it hands keyd handles, the client's padata, the AP-REQ,
//! the raw KDC-REQ-BODY and the FAST armored request, and receives one-time
//! tokens, non-secret ticket facts, the decrypted KrbFastReq and sealed parts
//! ("compute, don't give"; for FAST: docs/48 §2, A-33 — no armor, challenge,
//! strengthen or reply key ever enters the KDC).
//!
//! [`LocalKeyd`] binds an in-process [`keyd::Keyd`] to the KDC's caller
//! identity. In the product, keyd is a separate process reached over the
//! minimal IPC codec (D34); that client is a later crate and will implement
//! the same trait.
//!
//! Spec: docs/10 §2 (Role `Kdc`: verify_preauth, issue_as_rep,
//! open_and_verify_tgt, issue_tgs_rep, open_fast_armor, seal_fast_error),
//! §4, §5, §5א, §8; docs/48 §2.3; docs/09 א.1; docs/30 §1.

use crate::config::ConfigError;
use keyd::{
    ArmorId, AsRepParts, AsTicketTemplate, AuthnError, AuthnProof, CallerId, CtxId, EntropySource,
    FastArmor, FastConversation, IssueError, KeyHandle, KeyStore, Keyd, KeydConfig, Role,
    TgsFastRequest, TgsRepParts, TgsTicketTemplate, TgtContext,
};
use krb_proto::{ApReq, EncryptedData, KerberosTime, KrbError, KrbFastArmoredReq, PaData};

/// The keyd operations the KDC calls (role `Kdc`).
///
/// Spec: docs/10 §2, §4, §5, §5א; docs/48 §2.3.
pub trait KeyCustody {
    /// keyd's configuration: realm, AES encryption types, clock skew and the
    /// ticket policy the KDC must plan within. Not secret.
    /// Spec: docs/10 §1; RFC 4120 §8.2.
    fn config(&self) -> &KeydConfig;

    /// docs/10 §4 `verify_preauth`: PA-ENC-TIMESTAMP when `armor` is `None`
    /// (the bootstrap, docs/48 §7.3); the encrypted challenge under that
    /// armor otherwise (docs/48 §4.5).
    fn verify_preauth(
        &mut self,
        client: &KeyHandle,
        padata: &PaData,
        armor: Option<ArmorId>,
        now: &KerberosTime,
    ) -> Result<AuthnProof, AuthnError>;

    /// docs/10 §4 `issue_as_rep`; armored when `armor` is `Some` (then
    /// `fast_rep` is `Some`, docs/48 §2.3).
    fn issue_as_rep(
        &mut self,
        client: &KeyHandle,
        krbtgt: &KeyHandle,
        proof: &AuthnProof,
        armor: Option<ArmorId>,
        template: &AsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<AsRepParts, IssueError>;

    /// docs/10 §5א `open_fast_armor`: the FX_FAST_ARMOR_AP_REQUEST armor of
    /// an AS request and its KrbFastReq; the req-checksum is verified over
    /// the raw outer KDC-REQ-BODY octets (RFC 6113 5.4.2).
    fn open_fast_armor(
        &mut self,
        krbtgt: &KeyHandle,
        armored_req: &KrbFastArmoredReq,
        outer_req_body: &[u8],
        now: &KerberosTime,
    ) -> Result<FastArmor, AuthnError>;

    /// docs/10 §5 `open_and_verify_tgt` (A-17: the authenticator checksum is
    /// verified over the raw KDC-REQ-BODY octets); with `fast`, the implicit
    /// FAST armor of the TGS request (docs/10 §5א, docs/48 §5).
    fn open_and_verify_tgt(
        &mut self,
        krbtgt: &KeyHandle,
        ap_req: &ApReq,
        req_body: &[u8],
        fast: Option<TgsFastRequest<'_>>,
        now: &KerberosTime,
    ) -> Result<TgtContext, AuthnError>;

    /// docs/10 §5 `issue_tgs_rep` (armored exactly when the context is).
    fn issue_tgs_rep(
        &mut self,
        service: &KeyHandle,
        ctx: &CtxId,
        template: &TgsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<TgsRepParts, IssueError>;

    /// docs/10 §5א `seal_fast_error`: the enc-fast-rep of an armored
    /// KRB-ERROR (RFC 6113 5.4.4), consuming the conversation's token.
    fn seal_fast_error(
        &mut self,
        conversation: &FastConversation,
        error: &KrbError,
        padata: &[PaData],
        now: &KerberosTime,
    ) -> Result<EncryptedData, keyd::Error>;
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
        armor: Option<ArmorId>,
        now: &KerberosTime,
    ) -> Result<AuthnProof, AuthnError> {
        self.keyd
            .verify_preauth(&self.caller, client, padata, armor, now)
    }

    fn issue_as_rep(
        &mut self,
        client: &KeyHandle,
        krbtgt: &KeyHandle,
        proof: &AuthnProof,
        armor: Option<ArmorId>,
        template: &AsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<AsRepParts, IssueError> {
        self.keyd
            .issue_as_rep(&self.caller, client, krbtgt, proof, armor, template, now)
    }

    fn open_fast_armor(
        &mut self,
        krbtgt: &KeyHandle,
        armored_req: &KrbFastArmoredReq,
        outer_req_body: &[u8],
        now: &KerberosTime,
    ) -> Result<FastArmor, AuthnError> {
        self.keyd
            .open_fast_armor(&self.caller, krbtgt, armored_req, outer_req_body, now)
    }

    fn open_and_verify_tgt(
        &mut self,
        krbtgt: &KeyHandle,
        ap_req: &ApReq,
        req_body: &[u8],
        fast: Option<TgsFastRequest<'_>>,
        now: &KerberosTime,
    ) -> Result<TgtContext, AuthnError> {
        self.keyd
            .open_and_verify_tgt(&self.caller, krbtgt, ap_req, req_body, fast, now)
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

    fn seal_fast_error(
        &mut self,
        conversation: &FastConversation,
        error: &KrbError,
        padata: &[PaData],
        now: &KerberosTime,
    ) -> Result<EncryptedData, keyd::Error> {
        self.keyd
            .seal_fast_error(&self.caller, conversation, error, padata, now)
    }
}
