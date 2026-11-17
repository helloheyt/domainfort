//! The in-process implementation of the KDC's custody seam:
//! [`LocalKeyd`] binds an in-process [`Keyd`] to the KDC's caller identity
//! and implements [`KeyCustody`] (keyd-types) by calling keyd's `Kdc`-role
//! operations directly.
//!
//! In the product, keyd is a separate process and the kdc reaches it through
//! ipc-keyd's `IpcKeyd`, the other implementation of the same trait (docs/50
//! §3). `LocalKeyd` serves tests, fuzzing and development. It moved here
//! from the kdc crate together with the trait's move to keyd-types, so that
//! the kdc names the seam without linking keyd or its crypto profile (D182;
//! decision A-63). The behaviour is unchanged.
//!
//! Spec: docs/10 §2 (`CallerId`, role `Kdc`: verify_preauth, issue_as_rep,
//! open_and_verify_tgt, issue_tgs_rep, open_fast_armor, seal_fast_error),
//! §4, §5, §5a; docs/48 §2.3; docs/50 §3.4; D182; A-63.

use crate::audit::AuditSink;
use crate::authz::{CallerId, Role};
use crate::config::ConfigDescription;
use crate::entropy::EntropySource;
use crate::error::{AuthnError, ConfigError, Error, IssueError};
use crate::keyd::Keyd;
use crate::model::KeyHandle;
use crate::store::KeyStore;
use crate::tokens::{ArmorId, CtxId};
use keyd_types::{
    AsRepParts, AsServerKeySet, AsTicketTemplate, AttestedNameResolution, AuthnProof, FastArmor,
    FastConversation, KeyCustody, TgsFastRequest, TgsRepParts, TgsTicketTemplate, TgtContext,
};
use krb_proto::{ApReq, EncryptedData, KerberosTime, KrbError, KrbFastArmoredReq, PaData};

/// An in-process keyd, called with the KDC's caller identity.
///
/// Spec: docs/10 §2 (`CallerId`, role `Kdc`).
pub struct LocalKeyd<S: KeyStore, A: AuditSink, E: EntropySource> {
    keyd: Keyd<S, A, E>,
    caller: CallerId,
    /// keyd's non-secret configuration, taken once: keyd's configuration
    /// does not change after construction. Spec: docs/50 §3.4.
    description: ConfigDescription,
}

impl<S: KeyStore, A: AuditSink, E: EntropySource> LocalKeyd<S, A, E> {
    /// Bind `keyd` to `caller`, which must hold the `Kdc` role (otherwise
    /// keyd would refuse every call; refusing here fails fast with
    /// [`ConfigError::CustodyRole`]).
    /// Spec: docs/10 §2.
    pub fn new(keyd: Keyd<S, A, E>, caller: CallerId) -> Result<Self, ConfigError> {
        if caller.role != Role::Kdc {
            return Err(ConfigError::CustodyRole);
        }
        let description = keyd.config().description();
        Ok(LocalKeyd {
            keyd,
            caller,
            description,
        })
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

impl<S: KeyStore, A: AuditSink, E: EntropySource> KeyCustody for LocalKeyd<S, A, E> {
    fn config(&self) -> &ConfigDescription {
        &self.description
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
        client: &AttestedNameResolution,
        server: AsServerKeySet<'_>,
        proof: &AuthnProof,
        armor: Option<ArmorId>,
        template: &AsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<AsRepParts, IssueError> {
        self.keyd
            .issue_as_rep(&self.caller, client, server, proof, armor, template, now)
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
        service: &AttestedNameResolution,
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
    ) -> Result<EncryptedData, Error> {
        self.keyd
            .seal_fast_error(&self.caller, conversation, error, padata, now)
    }
}
