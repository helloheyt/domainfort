//! keyd behind the A-57 gate: [`GatedCustody`] passes every call to keyd
//! while the gate is open, and answers every call `Unavailable` without
//! asking keyd while it is closed.
//!
//! The engine closes it for a request whose audit slot could not be
//! reserved (auditd unreachable, or the window full — `crate::audit`): the
//! request then goes through `Kdc::handle` as for an unavailable keyd and
//! directory — KDC_ERR_SVC_UNAVAILABLE (29) over TCP, nothing over UDP, its
//! one audit event offered as noise — and keyd issues nothing for it, and is
//! not even asked (docs/questions/Q-218, A-57: "the kdc refuses every
//! request that would produce issuance"; A-64). `Unavailable` is the
//! variant every keyd error has for "not served now" (A-56): decided before
//! any secret-dependent work and independently of the request, so it is no
//! oracle.
//!
//! `config` is never gated: it is keyd's non-secret configuration, fetched
//! once at start (docs/50 §7.5 step 4).
//!
//! Spec: docs/50 §3.7 (R50-8), §8.1, R50-17; docs/questions/Q-217 (A-56),
//! Q-218 (A-57), Q-252 item 8 (A-64); crates/keyd-types custody.rs.

use keyd_types::{
    ArmorId, AsRepParts, AsResolutions, AsTicketTemplate, AttestedNameResolution, AuthnError,
    AuthnProof, ConfigDescription, CtxId, Error, FastArmor, FastConversation, IssueError,
    KeyCustody, KeyHandle, TgsFastRequest, TgsRepParts, TgsTicketTemplate, TgtContext,
};
use krb_proto::{ApReq, EncryptedData, KerberosTime, KrbError, KrbFastArmoredReq, PaData};

/// keyd behind the gate (module documentation).
#[derive(Debug)]
pub struct GatedCustody<K: KeyCustody> {
    inner: K,
    serving: bool,
}

impl<K: KeyCustody> GatedCustody<K> {
    /// `inner`, with the gate closed until [`GatedCustody::set_serving`]
    /// opens it (fail closed).
    pub fn new(inner: K) -> GatedCustody<K> {
        GatedCustody {
            inner,
            serving: false,
        }
    }

    /// Open (`true`) or close (`false`) the gate for the next request.
    pub fn set_serving(&mut self, serving: bool) {
        self.serving = serving;
    }

    /// Whether calls reach keyd.
    #[must_use]
    pub fn is_serving(&self) -> bool {
        self.serving
    }

    /// The custody behind the gate.
    pub fn inner(&self) -> &K {
        &self.inner
    }

    /// Mutable access to the custody behind the gate.
    pub fn inner_mut(&mut self) -> &mut K {
        &mut self.inner
    }
}

/// Every operation: keyd's answer while serving, `Unavailable` otherwise.
/// Spec: module documentation; crates/keyd-types custody.rs.
impl<K: KeyCustody> KeyCustody for GatedCustody<K> {
    fn config(&self) -> &ConfigDescription {
        self.inner.config()
    }

    fn verify_preauth(
        &mut self,
        client: &KeyHandle,
        padata: &PaData,
        armor: Option<ArmorId>,
        now: &KerberosTime,
    ) -> Result<AuthnProof, AuthnError> {
        if !self.serving {
            return Err(AuthnError::Unavailable);
        }
        self.inner.verify_preauth(client, padata, armor, now)
    }

    fn issue_as_rep(
        &mut self,
        client: &KeyHandle,
        krbtgt: &KeyHandle,
        proof: &AuthnProof,
        armor: Option<ArmorId>,
        template: &AsTicketTemplate,
        resolutions: AsResolutions<'_>,
        now: &KerberosTime,
    ) -> Result<AsRepParts, IssueError> {
        if !self.serving {
            return Err(IssueError::Unavailable);
        }
        self.inner
            .issue_as_rep(client, krbtgt, proof, armor, template, resolutions, now)
    }

    fn open_fast_armor(
        &mut self,
        krbtgt: &KeyHandle,
        armored_req: &KrbFastArmoredReq,
        outer_req_body: &[u8],
        now: &KerberosTime,
    ) -> Result<FastArmor, AuthnError> {
        if !self.serving {
            return Err(AuthnError::Unavailable);
        }
        self.inner
            .open_fast_armor(krbtgt, armored_req, outer_req_body, now)
    }

    fn open_and_verify_tgt(
        &mut self,
        krbtgt: &KeyHandle,
        ap_req: &ApReq,
        req_body: &[u8],
        fast: Option<TgsFastRequest<'_>>,
        now: &KerberosTime,
    ) -> Result<TgtContext, AuthnError> {
        if !self.serving {
            return Err(AuthnError::Unavailable);
        }
        self.inner
            .open_and_verify_tgt(krbtgt, ap_req, req_body, fast, now)
    }

    fn issue_tgs_rep(
        &mut self,
        service: &KeyHandle,
        service_resolution: &AttestedNameResolution,
        ctx: &CtxId,
        template: &TgsTicketTemplate,
        now: &KerberosTime,
    ) -> Result<TgsRepParts, IssueError> {
        if !self.serving {
            return Err(IssueError::Unavailable);
        }
        self.inner
            .issue_tgs_rep(service, service_resolution, ctx, template, now)
    }

    fn seal_fast_error(
        &mut self,
        conversation: &FastConversation,
        error: &KrbError,
        padata: &[PaData],
        now: &KerberosTime,
    ) -> Result<EncryptedData, Error> {
        if !self.serving {
            return Err(Error::Unavailable);
        }
        self.inner.seal_fast_error(conversation, error, padata, now)
    }
}
