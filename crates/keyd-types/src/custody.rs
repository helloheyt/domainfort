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
//! Two implementations: keyd's `LocalKeyd` binds an in-process keyd to the
//! KDC's caller identity (tests, development); ipc-keyd's `IpcKeyd` reaches
//! the keyd process over the minimal IPC codec (D34; docs/50 §3). The trait
//! lives in this crypto-free crate — moved unchanged from the kdc crate — so
//! that the KDC names the seam without linking keyd or its crypto profile
//! (D182; decision A-63).
//!
//! # Unavailable (decision A-56, docs/questions/Q-217)
//!
//! Every operation can answer with the `Unavailable` variant of its error
//! type ([`AuthnError::Unavailable`], [`IssueError::Unavailable`],
//! [`Error::Unavailable`]): keyd did not serve the call. keyd itself
//! says so during its startup hold-down (RFC 4120 3.2.3); an IPC
//! implementation MUST say so for every transport failure — keyd down, the
//! deadline passed, a `Busy` or `Unavailable` refusal of the server (docs/50
//! §3.6, §3.7) — and never turn one into `Denied`, which the KDC would
//! report as a wrong password (KDC_ERR_PREAUTH_FAILED) or a forged request
//! (KRB_AP_ERR_BAD_INTEGRITY). The KDC answers every `Unavailable` with
//! KDC_ERR_SVC_UNAVAILABLE (RFC 4120 7.5.9, code 29) over TCP and nothing
//! over UDP (docs/50 §3.7). It is decided before any secret-dependent work —
//! keyd checks the hold-down right after the role and purpose checks; a
//! transport failure does not depend on the request at all — so it is no
//! oracle (A-26 concerns failures that depend on a secret).
//!
//! The configuration the KDC plans with is keyd's non-secret
//! [`ConfigDescription`] — what `describe_config` returns over IPC (docs/50
//! §3.4, §7.5 step 4) — never keyd's whole configuration.
//!
//! # Name resolutions (task PN11)
//!
//! `issue_as_rep` and `issue_tgs_rep` carry dird's attested name
//! resolutions ([`AttestedNameResolution`]) as the account records brought
//! them: the KDC forwards them, it cannot make or change one (it links no
//! MAC — A-65, D182), and keyd binds a client or service key only through a
//! resolution it verified (docs/59 §7.2).
//!
//! Spec: docs/10 §2 (Role `Kdc`: verify_preauth, issue_as_rep,
//! open_and_verify_tgt, issue_tgs_rep, open_fast_armor, seal_fast_error),
//! §4, §5, §5א, §8, §9; docs/48 §2.3; docs/09 א.1; docs/30 §1; docs/50 R50-8,
//! §3.4, §3.6, §3.7, §7.5; RFC 4120 3.2.3, 7.5.9; docs/questions/Q-217,
//! Q-222 (A-56); D182; A-63; docs/59 §7.5 (task PN11).

use crate::as_exchange::{AsRepParts, AsResolutions, AsTicketTemplate, AuthnProof};
use crate::config::ConfigDescription;
use crate::error::{AuthnError, Error, IssueError};
use crate::fast_armor::{FastArmor, FastConversation};
use crate::model::KeyHandle;
use crate::name_resolution::AttestedNameResolution;
use crate::tgs_exchange::{TgsFastRequest, TgsRepParts, TgsTicketTemplate, TgtContext};
use crate::tokens::{ArmorId, CtxId};
use krb_proto::{ApReq, EncryptedData, KerberosTime, KrbError, KrbFastArmoredReq, PaData};

/// The keyd operations the KDC calls (role `Kdc`). Each may answer
/// `Unavailable` (module docs): keyd did not serve the call.
///
/// Spec: docs/10 §2, §4, §5, §5א, §9; docs/48 §2.3; docs/50 §3.7 (R50-8);
/// docs/questions/Q-217 (A-56).
pub trait KeyCustody {
    /// keyd's non-secret configuration: realm, AES encryption types, clock
    /// skew and the ticket policy the KDC must plan within — over IPC, the
    /// answer of `describe_config`, obtained once before the KDC is built.
    /// Spec: docs/10 §1; RFC 4120 §8.2; docs/50 §3.4, §7.5 step 4.
    fn config(&self) -> &ConfigDescription;

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
    /// `fast_rep` is `Some`, docs/48 §2.3). `server` is the key set the
    /// ticket is sealed under: this realm's krbtgt (a TGT), or — armored
    /// only — the change-password service's (`kadmin/changepw`, under its
    /// ticket profile); keyd refuses any other (`crate::AsServer`, the
    /// closed server slot of task K3b). `resolutions` are dird's attested
    /// name resolutions the account records carried (task PN11): keyd binds
    /// the client key set — and the change-password service's — only through
    /// them ([`AsResolutions`]).
    /// Spec: docs/10 §4; docs/53 §5.2; docs/questions/Q-915 items 1, 3
    /// (A-151); docs/59 §7.2, §7.5.
    #[allow(clippy::too_many_arguments)]
    fn issue_as_rep(
        &mut self,
        client: &KeyHandle,
        server: &KeyHandle,
        proof: &AuthnProof,
        armor: Option<ArmorId>,
        template: &AsTicketTemplate,
        resolutions: AsResolutions<'_>,
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
    /// `service_resolution` is dird's attested resolution of the template's
    /// sname to the `service` key set, which the service account record
    /// carried; keyd reaches the service key only through it (task PN11).
    /// The client needs none: it comes from the TGT keyd sealed
    /// (docs/questions/Q-1011 item 7).
    /// Spec: docs/10 §5; docs/59 §7.2, §7.5; docs/questions/Q-1011 items 4,
    /// 7, 8 (A-173).
    fn issue_tgs_rep(
        &mut self,
        service: &KeyHandle,
        service_resolution: &AttestedNameResolution,
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
    ) -> Result<EncryptedData, Error>;
}
