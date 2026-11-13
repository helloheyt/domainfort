//! The typed layer: a keyd call ([`Call`]) and its outcome ([`Answer`]) with
//! every Kerberos value as its `krb-proto` / `keyd` type, and the
//! conversions to and from the wire messages of [`crate::wire`].
//!
//! Decoding direction (wire → typed): every DER blob is decoded by
//! `krb-proto`'s strict decoder, every realm by its KerberosString check,
//! every time by `KerberosTime::new`, every password and salt by a UTF-8
//! check (keyd takes them as text). Any refusal is a [`ConversionError`]: on
//! the server the request is refused `Malformed` (docs/50 §3.3), on the
//! client the reply is treated as keyd unavailable (docs/50 §3.7).
//!
//! Encoding direction (typed → wire): `krb-proto`'s canonical encoder. Since
//! krb-proto decodes losslessly and encodes canonically, and every other
//! field has exactly one encoding, a decoded call or answer re-encodes to
//! the octets it came from (docs/50 §3.3, round-trip row).
//!
//! Spec: docs/50 §3.3 (Kerberos values as DER "decoded in `krb-proto` (strict
//! DER, already fuzzed and inside keyd's TCB)"; secret-bearing buffers
//! zeroized), §3.4; docs/10 §4-§9; docs/questions/Q-225 item 6 (A-59),
//! Q-245 item 1.

use crate::wire::{
    CreateKeyRequest, IssueAsRepRequest, IssueTgsRepRequest, KeydReply, KeydRequest,
    OpenAndVerifyServiceTicketRequest, OpenAndVerifyTgtRequest, OpenFastArmorRequest,
    RetireKvnoRequest, RotateKrbtgtRequest, SealFastErrorRequest, SetSecretRequest,
    VerifyPreauthRequest, VerifySecretRequest, WireAsTemplate, WireAuthnProof, WireBinding,
    WireConfigDescription, WireFastArmor, WireRepParts, WireServiceContext, WireTgsFast,
    WireTgsTemplate, WireTgtContext, WireTime,
};
use core::fmt;
use ipc::{DerBlob, Secret};
use keyd_types::{
    ArmorId, AsRepParts, AsTicketTemplate, AuthnError, AuthnProof, ConfigDescription, CtxId,
    DualControlToken, FastArmor, FastConversation, IssueError, KeyHandle, Kvno, Operation,
    PrincipalBinding, Role, ServiceContext, TgsRepParts, TgsTicketTemplate, TgtContext,
};
use krb_proto::{
    ApReq, EncryptedData, KerberosTime, KrbError, KrbFastArmoredReq, KrbFastReq, PaData,
    PrincipalName, Realm, Ticket,
};
use zeroize::Zeroizing;

/// Why a value could not cross between the typed and the wire form. Carries
/// no octet of the value (AGENTS.md §6; docs/50 §8.2: "IPC errors carry a
/// code, not content").
///
/// Spec: docs/50 §3.3, §8.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversionError {
    /// krb-proto refused a Kerberos value: a DER blob that is not the strict
    /// DER of its type, a realm that is not a KerberosString, calendar fields
    /// that are not a KerberosTime, or a value it will not encode.
    /// Spec: docs/50 §3.3; RFC 4120 5.1.1, 5.2.1, 5.2.3.
    KerberosValue,
    /// A password, candidate or salt that is not UTF-8 text (keyd takes them
    /// as text). Spec: docs/10 §6.
    Text,
    /// A reply that does not belong to the operation that was called.
    /// Spec: docs/50 §3.4 (a request kind and its reply kind), R50-7 (strict
    /// request → reply).
    UnexpectedReply,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConversionError::KerberosValue => "Kerberos value refused by krb-proto",
            ConversionError::Text => "text field is not UTF-8",
            ConversionError::UnexpectedReply => "reply does not belong to the operation called",
        })
    }
}

impl std::error::Error for ConversionError {}

/// Result alias of the conversions.
type Converted<T> = Result<T, ConversionError>;

// ===========================================================================
// Value conversions.
// ===========================================================================

/// The canonical DER of a krb-proto value, as a blob.
/// Spec: docs/50 §3.3; RFC 4120 5.1.1.
fn der(encoded: krb_proto::Result<Vec<u8>>) -> Converted<DerBlob> {
    encoded
        .map(DerBlob::new)
        .map_err(|_| ConversionError::KerberosValue)
}

/// Decode a blob with krb-proto's strict decoder for its type.
/// Spec: docs/50 §3.3 ("decoded in `krb-proto` (strict DER)").
fn decoded<T>(blob: &DerBlob, decode: fn(&[u8]) -> krb_proto::Result<T>) -> Converted<T> {
    decode(blob.as_der()).map_err(|_| ConversionError::KerberosValue)
}

/// A KerberosTime as its calendar fields. Spec: RFC 4120 5.2.3.
fn wire_time(time: &KerberosTime) -> WireTime {
    WireTime {
        year: time.year(),
        month: time.month(),
        day: time.day(),
        hour: time.hour(),
        minute: time.minute(),
        second: time.second(),
    }
}

/// Calendar fields checked by krb-proto into a KerberosTime.
/// Spec: RFC 4120 5.2.3 (krb-proto `KerberosTime::new`); docs/questions/Q-245
/// item 1.
fn time(wire: &WireTime) -> Converted<KerberosTime> {
    KerberosTime::new(
        wire.year,
        wire.month,
        wire.day,
        wire.hour,
        wire.minute,
        wire.second,
    )
    .map_err(|_| ConversionError::KerberosValue)
}

/// Spec: RFC 4120 5.2.3.
fn opt_time(wire: Option<&WireTime>) -> Converted<Option<KerberosTime>> {
    wire.map(time).transpose()
}

/// A realm's KerberosString octets checked by krb-proto.
/// Spec: RFC 4120 5.2.1, 5.2.2 (krb-proto `KerberosString::from_bytes`);
/// docs/questions/Q-245 item 1.
fn realm(octets: &[u8]) -> Converted<Realm> {
    Realm::from_bytes(octets).map_err(|_| ConversionError::KerberosValue)
}

/// UTF-8 text of a non-secret field (the salt).
/// Spec: docs/10 §6 (`salt`).
fn text(octets: &[u8]) -> Converted<String> {
    core::str::from_utf8(octets)
        .map(str::to_owned)
        .map_err(|_| ConversionError::Text)
}

/// A password or candidate, moved from its zeroizing wire buffer into a
/// zeroizing `String` without a copy: the octets leave the [`Secret`] by
/// value, `String::from_utf8` takes the vector as it is, and on a UTF-8
/// failure the octets are handed back and wiped.
/// Spec: docs/50 §3.3 (secret-bearing buffers zeroized, in both sides);
/// docs/10 I7.
fn secret_text(secret: Secret) -> Converted<Password> {
    let mut octets = secret.into_zeroizing();
    let vector = core::mem::take(&mut *octets);
    match String::from_utf8(vector) {
        Ok(text) => Ok(Password(Zeroizing::new(text))),
        Err(error) => {
            drop(Zeroizing::new(error.into_bytes()));
            Err(ConversionError::Text)
        }
    }
}

/// A `PrincipalBinding` on the wire. Spec: docs/50 §3.4.
fn wire_binding(binding: &PrincipalBinding) -> Converted<WireBinding> {
    Ok(WireBinding {
        realm: binding.realm.as_bytes().to_vec(),
        name: der(binding.name.encode())?,
    })
}

/// Spec: docs/50 §3.4; RFC 4120 5.2.2.
fn binding(wire: &WireBinding) -> Converted<PrincipalBinding> {
    Ok(PrincipalBinding::new(
        realm(&wire.realm)?,
        decoded(&wire.name, PrincipalName::decode)?,
    ))
}

/// A password or candidate passed to keyd: zeroizing text whose `Debug`
/// prints nothing. No `Clone` (no silent second copy).
/// Spec: docs/10 §6, I7; docs/50 §8.2; AGENTS.md §6.
pub struct Password(Zeroizing<String>);

impl Password {
    /// Wrap a password the caller already holds in a zeroizing string.
    /// Spec: docs/10 I7.
    #[must_use]
    pub fn new(text: Zeroizing<String>) -> Password {
        Password(text)
    }

    /// The text, by value, for keyd (which takes `Zeroizing<String>`).
    /// Spec: docs/10 I7.
    #[must_use]
    pub fn into_inner(self) -> Zeroizing<String> {
        self.0
    }

    /// A zeroizing wire copy of the octets.
    fn to_secret(&self) -> Secret {
        Secret::from_slice(self.0.as_bytes())
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Not even the length (docs/questions/Q-225 item 9).
        f.write_str("Password(<redacted>)")
    }
}

// ===========================================================================
// Calls.
// ===========================================================================

/// The FAST part of an `open_and_verify_tgt` call, owned.
/// Spec: docs/10 §5א (`TgsFastRequest`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TgsFast {
    /// The raw PA-TGS-REQ padata-value octets.
    pub ap_req_octets: Vec<u8>,
    /// The PA-FX-FAST armored request.
    pub armored_req: KrbFastArmoredReq,
}

/// One keyd call with its typed arguments — everything but the caller and
/// `now`, which the server takes from the transport and from its own clock.
///
/// Spec: docs/50 §3.4, R50-3, R50-5; docs/10 §4-§7א; A-56.
#[derive(Debug)]
pub enum Call {
    /// Spec: docs/10 §4.
    VerifyPreauth {
        /// PrincipalLongterm handle.
        client: KeyHandle,
        /// The client's PA-DATA.
        padata: PaData,
        /// The FAST armor, if armored.
        armor: Option<ArmorId>,
    },
    /// Spec: docs/10 §4.
    IssueAsRep {
        /// PrincipalLongterm handle.
        client: KeyHandle,
        /// Krbtgt handle.
        krbtgt: KeyHandle,
        /// The proof of `verify_preauth`.
        proof: AuthnProof,
        /// The FAST armor, if armored.
        armor: Option<ArmorId>,
        /// The ticket template.
        template: AsTicketTemplate,
    },
    /// Spec: docs/10 §5א.
    OpenFastArmor {
        /// Krbtgt handle.
        krbtgt: KeyHandle,
        /// The PA-FX-FAST armored request.
        armored_req: KrbFastArmoredReq,
        /// The raw outer KDC-REQ-BODY octets.
        outer_req_body: Vec<u8>,
    },
    /// Spec: docs/10 §5; A-17.
    OpenAndVerifyTgt {
        /// Krbtgt handle.
        krbtgt: KeyHandle,
        /// The PA-TGS-REQ AP-REQ.
        ap_req: ApReq,
        /// The raw KDC-REQ-BODY octets.
        req_body: Vec<u8>,
        /// The implicit FAST armor, if armored.
        fast: Option<TgsFast>,
    },
    /// Spec: docs/10 §5.
    IssueTgsRep {
        /// Service handle.
        service: KeyHandle,
        /// The context of `open_and_verify_tgt`.
        ctx: CtxId,
        /// The ticket template.
        template: TgsTicketTemplate,
    },
    /// Spec: docs/10 §5א.
    SealFastError {
        /// The armored conversation.
        conversation: FastConversation,
        /// The KRB-ERROR to seal.
        error: KrbError,
        /// The KrbFastResponse padata.
        padata: Vec<PaData>,
    },
    /// Spec: docs/10 §5ב.
    OpenAndVerifyServiceTicket {
        /// Service handle.
        service: KeyHandle,
        /// The raw KRB_AP_REQ octets.
        ap_req_octets: Vec<u8>,
    },
    /// Spec: docs/10 §6.
    SetSecret {
        /// The key set's handle.
        handle: KeyHandle,
        /// The principal name.
        binding: PrincipalBinding,
        /// The password.
        password: Password,
        /// The salt.
        salt: String,
    },
    /// Spec: docs/10 §6.
    VerifySecret {
        /// The key set's handle.
        handle: KeyHandle,
        /// The candidate password.
        candidate: Password,
    },
    /// Spec: docs/10 §7.
    CreateKey {
        /// The new key set's handle.
        handle: KeyHandle,
        /// The principal name.
        binding: PrincipalBinding,
    },
    /// Spec: docs/10 §7.
    RotateKey {
        /// The key set's handle.
        handle: KeyHandle,
    },
    /// Spec: docs/10 §7.
    RotateKrbtgt {
        /// Krbtgt handle.
        krbtgt: KeyHandle,
        /// The dual-control approval.
        approval: DualControlToken,
    },
    /// Spec: docs/10 §7.
    RetireKvno {
        /// The key set's handle.
        handle: KeyHandle,
        /// The kvno to retire.
        kvno: Kvno,
    },
    /// Spec: docs/10 §7; A-35.
    DestroyKeySet {
        /// The key set's handle.
        handle: KeyHandle,
    },
    /// Spec: docs/10 §7א.
    DescribeConfig,
    /// Spec: docs/10 §7א.
    Ping,
}

impl Call {
    /// The keyd operation this call invokes.
    /// Spec: docs/10 §2 (`Operation`).
    #[must_use]
    pub fn operation(&self) -> Operation {
        match self {
            Call::VerifyPreauth { .. } => Operation::VerifyPreauth,
            Call::IssueAsRep { .. } => Operation::IssueAsRep,
            Call::OpenFastArmor { .. } => Operation::OpenFastArmor,
            Call::OpenAndVerifyTgt { .. } => Operation::OpenAndVerifyTgt,
            Call::IssueTgsRep { .. } => Operation::IssueTgsRep,
            Call::SealFastError { .. } => Operation::SealFastError,
            Call::OpenAndVerifyServiceTicket { .. } => Operation::OpenAndVerifyServiceTicket,
            Call::SetSecret { .. } => Operation::SetSecret,
            Call::VerifySecret { .. } => Operation::VerifySecret,
            Call::CreateKey { .. } => Operation::CreateKey,
            Call::RotateKey { .. } => Operation::RotateKey,
            Call::RotateKrbtgt { .. } => Operation::RotateKrbtgt,
            Call::RetireKvno { .. } => Operation::RetireKvno,
            Call::DestroyKeySet { .. } => Operation::DestroyKeySet,
            Call::DescribeConfig => Operation::DescribeConfig,
            Call::Ping => Operation::Ping,
        }
    }

    /// The wire request of this call (Kerberos values as canonical DER).
    /// Spec: docs/50 §3.3, §3.4.
    pub fn to_wire(&self) -> Result<KeydRequest, ConversionError> {
        Ok(match self {
            Call::VerifyPreauth {
                client,
                padata,
                armor,
            } => KeydRequest::VerifyPreauth(VerifyPreauthRequest {
                client: *client,
                padata: der(padata.encode())?,
                armor: *armor,
            }),
            Call::IssueAsRep {
                client,
                krbtgt,
                proof,
                armor,
                template,
            } => KeydRequest::IssueAsRep(IssueAsRepRequest {
                client: *client,
                krbtgt: *krbtgt,
                proof: wire_proof(proof),
                armor: *armor,
                template: WireAsTemplate {
                    client: template.client,
                    crealm: template.crealm.as_bytes().to_vec(),
                    cname: der(template.cname.encode())?,
                    sname: der(template.sname.encode())?,
                    starttime: template.starttime.as_ref().map(wire_time),
                    endtime: wire_time(&template.endtime),
                    renew_till: template.renew_till.as_ref().map(wire_time),
                    flags: template.flags,
                    session_enctype: template.session_enctype,
                    nonce: template.nonce,
                },
            }),
            Call::OpenFastArmor {
                krbtgt,
                armored_req,
                outer_req_body,
            } => KeydRequest::OpenFastArmor(OpenFastArmorRequest {
                krbtgt: *krbtgt,
                armored_req: der(armored_req.encode())?,
                outer_req_body: outer_req_body.clone(),
            }),
            Call::OpenAndVerifyTgt {
                krbtgt,
                ap_req,
                req_body,
                fast,
            } => KeydRequest::OpenAndVerifyTgt(OpenAndVerifyTgtRequest {
                krbtgt: *krbtgt,
                ap_req: der(ap_req.encode())?,
                req_body: req_body.clone(),
                fast: match fast {
                    Some(fast) => Some(WireTgsFast {
                        ap_req_octets: fast.ap_req_octets.clone(),
                        armored_req: der(fast.armored_req.encode())?,
                    }),
                    None => None,
                },
            }),
            Call::IssueTgsRep {
                service,
                ctx,
                template,
            } => KeydRequest::IssueTgsRep(IssueTgsRepRequest {
                service: *service,
                ctx: *ctx,
                template: WireTgsTemplate {
                    sname: der(template.sname.encode())?,
                    starttime: template.starttime.as_ref().map(wire_time),
                    endtime: wire_time(&template.endtime),
                    renew_till: template.renew_till.as_ref().map(wire_time),
                    flags: template.flags,
                    session_enctype: template.session_enctype,
                    nonce: template.nonce,
                },
            }),
            Call::SealFastError {
                conversation,
                error,
                padata,
            } => KeydRequest::SealFastError(SealFastErrorRequest {
                conversation: *conversation,
                error: der(error.encode())?,
                padata: padata
                    .iter()
                    .map(|p| der(p.encode()))
                    .collect::<Converted<Vec<DerBlob>>>()?,
            }),
            Call::OpenAndVerifyServiceTicket {
                service,
                ap_req_octets,
            } => KeydRequest::OpenAndVerifyServiceTicket(OpenAndVerifyServiceTicketRequest {
                service: *service,
                ap_req_octets: ap_req_octets.clone(),
            }),
            Call::SetSecret {
                handle,
                binding,
                password,
                salt,
            } => KeydRequest::SetSecret(SetSecretRequest {
                handle: *handle,
                binding: wire_binding(binding)?,
                password: password.to_secret(),
                salt: salt.as_bytes().to_vec(),
            }),
            Call::VerifySecret { handle, candidate } => {
                KeydRequest::VerifySecret(VerifySecretRequest {
                    handle: *handle,
                    candidate: candidate.to_secret(),
                })
            }
            Call::CreateKey { handle, binding } => KeydRequest::CreateKey(CreateKeyRequest {
                handle: *handle,
                binding: wire_binding(binding)?,
            }),
            Call::RotateKey { handle } => KeydRequest::RotateKey(*handle),
            Call::RotateKrbtgt { krbtgt, approval } => {
                KeydRequest::RotateKrbtgt(RotateKrbtgtRequest {
                    krbtgt: *krbtgt,
                    approval: *approval,
                })
            }
            Call::RetireKvno { handle, kvno } => KeydRequest::RetireKvno(RetireKvnoRequest {
                handle: *handle,
                kvno: *kvno,
            }),
            Call::DestroyKeySet { handle } => KeydRequest::DestroyKeySet(*handle),
            Call::DescribeConfig => KeydRequest::DescribeConfig,
            Call::Ping => KeydRequest::Ping,
        })
    }

    /// The typed call of a wire request: every Kerberos value through
    /// krb-proto's strict decoder, passwords and salt as UTF-8. The request
    /// is consumed so that a password moves into the call without a copy.
    /// Spec: docs/50 §3.3 (Kerberos values; secret-bearing buffers), §3.4.
    pub fn from_wire(request: KeydRequest) -> Result<Call, ConversionError> {
        Ok(match request {
            KeydRequest::VerifyPreauth(m) => Call::VerifyPreauth {
                client: m.client,
                padata: decoded(&m.padata, PaData::decode)?,
                armor: m.armor,
            },
            KeydRequest::IssueAsRep(m) => Call::IssueAsRep {
                client: m.client,
                krbtgt: m.krbtgt,
                proof: proof(&m.proof)?,
                armor: m.armor,
                template: AsTicketTemplate {
                    client: m.template.client,
                    crealm: realm(&m.template.crealm)?,
                    cname: decoded(&m.template.cname, PrincipalName::decode)?,
                    sname: decoded(&m.template.sname, PrincipalName::decode)?,
                    starttime: opt_time(m.template.starttime.as_ref())?,
                    endtime: time(&m.template.endtime)?,
                    renew_till: opt_time(m.template.renew_till.as_ref())?,
                    flags: m.template.flags,
                    session_enctype: m.template.session_enctype,
                    nonce: m.template.nonce,
                },
            },
            KeydRequest::OpenFastArmor(m) => Call::OpenFastArmor {
                krbtgt: m.krbtgt,
                armored_req: decoded(&m.armored_req, KrbFastArmoredReq::decode)?,
                outer_req_body: m.outer_req_body,
            },
            KeydRequest::OpenAndVerifyTgt(m) => Call::OpenAndVerifyTgt {
                krbtgt: m.krbtgt,
                ap_req: decoded(&m.ap_req, ApReq::decode)?,
                req_body: m.req_body,
                fast: match m.fast {
                    Some(fast) => Some(TgsFast {
                        armored_req: decoded(&fast.armored_req, KrbFastArmoredReq::decode)?,
                        ap_req_octets: fast.ap_req_octets,
                    }),
                    None => None,
                },
            },
            KeydRequest::IssueTgsRep(m) => Call::IssueTgsRep {
                service: m.service,
                ctx: m.ctx,
                template: TgsTicketTemplate {
                    sname: decoded(&m.template.sname, PrincipalName::decode)?,
                    starttime: opt_time(m.template.starttime.as_ref())?,
                    endtime: time(&m.template.endtime)?,
                    renew_till: opt_time(m.template.renew_till.as_ref())?,
                    flags: m.template.flags,
                    session_enctype: m.template.session_enctype,
                    nonce: m.template.nonce,
                },
            },
            KeydRequest::SealFastError(m) => Call::SealFastError {
                conversation: m.conversation,
                error: decoded(&m.error, KrbError::decode)?,
                padata: m
                    .padata
                    .iter()
                    .map(|p| decoded(p, PaData::decode))
                    .collect::<Converted<Vec<PaData>>>()?,
            },
            KeydRequest::OpenAndVerifyServiceTicket(m) => Call::OpenAndVerifyServiceTicket {
                service: m.service,
                ap_req_octets: m.ap_req_octets,
            },
            KeydRequest::SetSecret(m) => {
                // Check the non-secret fields first, then move the password.
                let binding = binding(&m.binding)?;
                let salt = text(&m.salt)?;
                Call::SetSecret {
                    handle: m.handle,
                    binding,
                    password: secret_text(m.password)?,
                    salt,
                }
            }
            KeydRequest::VerifySecret(m) => Call::VerifySecret {
                handle: m.handle,
                candidate: secret_text(m.candidate)?,
            },
            KeydRequest::CreateKey(m) => Call::CreateKey {
                handle: m.handle,
                binding: binding(&m.binding)?,
            },
            KeydRequest::RotateKey(handle) => Call::RotateKey { handle },
            KeydRequest::RotateKrbtgt(m) => Call::RotateKrbtgt {
                krbtgt: m.krbtgt,
                approval: m.approval,
            },
            KeydRequest::RetireKvno(m) => Call::RetireKvno {
                handle: m.handle,
                kvno: m.kvno,
            },
            KeydRequest::DestroyKeySet(handle) => Call::DestroyKeySet { handle },
            KeydRequest::DescribeConfig => Call::DescribeConfig,
            KeydRequest::Ping => Call::Ping,
        })
    }
}

/// Spec: docs/50 §3.4 (`AuthnProof { exchange_id, client, authtime }`).
fn wire_proof(proof: &AuthnProof) -> WireAuthnProof {
    WireAuthnProof {
        exchange_id: proof.exchange_id,
        client: proof.client,
        authtime: wire_time(&proof.authtime),
    }
}

/// Spec: docs/50 §3.4.
fn proof(wire: &WireAuthnProof) -> Converted<AuthnProof> {
    Ok(AuthnProof {
        exchange_id: wire.exchange_id,
        client: wire.client,
        authtime: time(&wire.authtime)?,
    })
}

// ===========================================================================
// Answers.
// ===========================================================================

/// The success result of `describe_config` on the keyd channel: keyd's
/// non-secret description, and the role keyd resolved for the **caller**
/// from the connection's peer uid.
///
/// keyd's own `describe_config` returns the description; the server side
/// (`ipc_keyd_server::execute`) adds the role from the same `CallerId` it
/// handed keyd for the call — the identity keyd authorized with. The role
/// is not secret, and it is only reported: no request carries a role, and
/// keyd never takes one from a peer (docs/50 R50-3, §3.2). A client that
/// requires its own role (`KeydClient::require_caller_role`) can thus tell
/// the Kdc role from the Ldap role, which may both call `describe_config`
/// (docs/10 §2) and which the description alone does not distinguish.
///
/// Spec: docs/10 §2, §7א; docs/50 §3.4 (`DescribeConfig`), §3.7;
/// docs/questions/Q-351 (A-87).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescribedConfig {
    /// keyd's non-secret configuration ([`ConfigDescription`]).
    pub description: ConfigDescription,
    /// The caller's role, as keyd resolved it from the peer uid.
    pub caller_role: Role,
}

/// The outcome of one keyd call, as keyd returned it.
/// Spec: docs/10 §4-§9; docs/50 §3.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Spec: docs/10 §4.
    VerifyPreauth(Result<AuthnProof, AuthnError>),
    /// Spec: docs/10 §4.
    IssueAsRep(Result<AsRepParts, IssueError>),
    /// Spec: docs/10 §5א.
    OpenFastArmor(Result<FastArmor, AuthnError>),
    /// Spec: docs/10 §5.
    OpenAndVerifyTgt(Result<TgtContext, AuthnError>),
    /// Spec: docs/10 §5.
    IssueTgsRep(Result<TgsRepParts, IssueError>),
    /// Spec: docs/10 §5א.
    SealFastError(Result<EncryptedData, keyd_types::Error>),
    /// Spec: docs/10 §5ב.
    OpenAndVerifyServiceTicket(Result<ServiceContext, AuthnError>),
    /// Spec: docs/10 §6.
    SetSecret(Result<Kvno, keyd_types::Error>),
    /// Spec: docs/10 §6.
    VerifySecret(Result<(), keyd_types::Error>),
    /// Spec: docs/10 §7.
    CreateKey(Result<Kvno, keyd_types::Error>),
    /// Spec: docs/10 §7.
    RotateKey(Result<Kvno, keyd_types::Error>),
    /// Spec: docs/10 §7.
    RotateKrbtgt(Result<Kvno, keyd_types::Error>),
    /// Spec: docs/10 §7.
    RetireKvno(Result<(), keyd_types::Error>),
    /// Spec: docs/10 §7.
    DestroyKeySet(Result<(), keyd_types::Error>),
    /// keyd's description and the caller's role ([`DescribedConfig`]).
    /// Spec: docs/10 §7א; docs/questions/Q-351 (A-87).
    DescribeConfig(Result<DescribedConfig, keyd_types::Error>),
    /// Spec: docs/10 §7א.
    Ping(Result<(), keyd_types::Error>),
}

/// A success payload, or keyd's error carried by `failure`.
fn outcome<T, E>(
    result: &Result<T, E>,
    success: impl FnOnce(&T) -> Converted<KeydReply>,
    failure: impl FnOnce(E) -> KeydReply,
) -> Converted<KeydReply>
where
    E: Copy,
{
    match result {
        Ok(value) => success(value),
        Err(error) => Ok(failure(*error)),
    }
}

impl Answer {
    /// The keyd operation this answer belongs to.
    /// Spec: docs/10 §2.
    #[must_use]
    pub fn operation(&self) -> Operation {
        match self {
            Answer::VerifyPreauth(_) => Operation::VerifyPreauth,
            Answer::IssueAsRep(_) => Operation::IssueAsRep,
            Answer::OpenFastArmor(_) => Operation::OpenFastArmor,
            Answer::OpenAndVerifyTgt(_) => Operation::OpenAndVerifyTgt,
            Answer::IssueTgsRep(_) => Operation::IssueTgsRep,
            Answer::SealFastError(_) => Operation::SealFastError,
            Answer::OpenAndVerifyServiceTicket(_) => Operation::OpenAndVerifyServiceTicket,
            Answer::SetSecret(_) => Operation::SetSecret,
            Answer::VerifySecret(_) => Operation::VerifySecret,
            Answer::CreateKey(_) => Operation::CreateKey,
            Answer::RotateKey(_) => Operation::RotateKey,
            Answer::RotateKrbtgt(_) => Operation::RotateKrbtgt,
            Answer::RetireKvno(_) => Operation::RetireKvno,
            Answer::DestroyKeySet(_) => Operation::DestroyKeySet,
            Answer::DescribeConfig(_) => Operation::DescribeConfig,
            Answer::Ping(_) => Operation::Ping,
        }
    }

    /// The wire reply of this answer: the operation's success message, or
    /// the failure message of its error type carrying keyd's variant exactly
    /// (A-26 classes and `Unavailable` included).
    /// Spec: docs/50 §3.3 (errors row: "exactly the keyd variant"), §3.4;
    /// docs/10 §9; A-26; A-56.
    pub fn to_wire(&self) -> Result<KeydReply, ConversionError> {
        match self {
            Answer::VerifyPreauth(r) => outcome(
                r,
                |p| Ok(KeydReply::VerifyPreauth(wire_proof(p))),
                KeydReply::AuthnFailure,
            ),
            Answer::IssueAsRep(r) => outcome(
                r,
                |p| {
                    Ok(KeydReply::IssueAsRep(wire_parts(
                        &p.ticket,
                        &p.enc_part,
                        p.fast_rep.as_ref(),
                    )?))
                },
                KeydReply::IssueFailure,
            ),
            Answer::OpenFastArmor(r) => outcome(
                r,
                |a| {
                    Ok(KeydReply::OpenFastArmor(WireFastArmor {
                        armor_id: a.armor_id,
                        armor_crealm: a.armor_crealm.as_bytes().to_vec(),
                        armor_cname: der(a.armor_cname.encode())?,
                        armor_authtime: wire_time(&a.armor_authtime),
                        fast_req: der(a.fast_req.encode())?,
                    }))
                },
                KeydReply::AuthnFailure,
            ),
            Answer::OpenAndVerifyTgt(r) => outcome(
                r,
                |c| {
                    Ok(KeydReply::OpenAndVerifyTgt(WireTgtContext {
                        ctx_id: c.ctx_id,
                        crealm: c.crealm.as_bytes().to_vec(),
                        cname: der(c.cname.encode())?,
                        authtime: wire_time(&c.authtime),
                        starttime: c.starttime.as_ref().map(wire_time),
                        endtime: wire_time(&c.endtime),
                        renew_till: c.renew_till.as_ref().map(wire_time),
                        flags: c.flags,
                        fast_req: match &c.fast_req {
                            Some(req) => Some(der(req.encode())?),
                            None => None,
                        },
                    }))
                },
                KeydReply::AuthnFailure,
            ),
            Answer::IssueTgsRep(r) => outcome(
                r,
                |p| {
                    Ok(KeydReply::IssueTgsRep(wire_parts(
                        &p.ticket,
                        &p.enc_part,
                        p.fast_rep.as_ref(),
                    )?))
                },
                KeydReply::IssueFailure,
            ),
            Answer::SealFastError(r) => outcome(
                r,
                |sealed| Ok(KeydReply::SealFastError(der(sealed.encode())?)),
                KeydReply::Failure,
            ),
            Answer::OpenAndVerifyServiceTicket(r) => outcome(
                r,
                |c| {
                    Ok(KeydReply::OpenAndVerifyServiceTicket(WireServiceContext {
                        ctx_id: c.ctx_id,
                        crealm: c.crealm.as_bytes().to_vec(),
                        cname: der(c.cname.encode())?,
                        authtime: wire_time(&c.authtime),
                        endtime: wire_time(&c.endtime),
                        flags: c.flags,
                        subkey_present: c.subkey_present,
                    }))
                },
                KeydReply::AuthnFailure,
            ),
            Answer::SetSecret(r) => {
                outcome(r, |k| Ok(KeydReply::SetSecret(*k)), KeydReply::Failure)
            }
            Answer::VerifySecret(r) => {
                outcome(r, |()| Ok(KeydReply::VerifySecret), KeydReply::Failure)
            }
            Answer::CreateKey(r) => {
                outcome(r, |k| Ok(KeydReply::CreateKey(*k)), KeydReply::Failure)
            }
            Answer::RotateKey(r) => {
                outcome(r, |k| Ok(KeydReply::RotateKey(*k)), KeydReply::Failure)
            }
            Answer::RotateKrbtgt(r) => {
                outcome(r, |k| Ok(KeydReply::RotateKrbtgt(*k)), KeydReply::Failure)
            }
            Answer::RetireKvno(r) => outcome(r, |()| Ok(KeydReply::RetireKvno), KeydReply::Failure),
            Answer::DestroyKeySet(r) => {
                outcome(r, |()| Ok(KeydReply::DestroyKeySet), KeydReply::Failure)
            }
            Answer::DescribeConfig(r) => outcome(
                r,
                |described| {
                    let d = &described.description;
                    Ok(KeydReply::DescribeConfig(WireConfigDescription {
                        realm: d.realm.as_bytes().to_vec(),
                        enctypes: d.enctypes.clone(),
                        clock_skew_secs: d.clock_skew_secs,
                        token_lifetime_secs: d.token_lifetime_secs,
                        ticket_policy: d.ticket_policy,
                        s2k_params: d.s2k_params,
                        caller_role: described.caller_role,
                    }))
                },
                KeydReply::Failure,
            ),
            Answer::Ping(r) => outcome(r, |()| Ok(KeydReply::Ping), KeydReply::Failure),
        }
    }

    /// The typed answer of a wire reply to a call of `operation`. A reply
    /// that is neither that operation's success message nor the failure
    /// message of its error type is [`ConversionError::UnexpectedReply`];
    /// every Kerberos value goes through krb-proto's strict decoder (replies
    /// are decoded with the same strictness as requests).
    /// Spec: docs/50 §3.3 ("replies are decoded with the same strictness",
    /// citing docs/07 §5), §3.4, R50-7.
    pub fn from_wire(operation: Operation, reply: KeydReply) -> Result<Answer, ConversionError> {
        use KeydReply as R;
        Ok(match (operation, reply) {
            (Operation::VerifyPreauth, R::VerifyPreauth(p)) => {
                Answer::VerifyPreauth(Ok(proof(&p)?))
            }
            (Operation::VerifyPreauth, R::AuthnFailure(e)) => Answer::VerifyPreauth(Err(e)),
            (Operation::IssueAsRep, R::IssueAsRep(p)) => {
                let (ticket, enc_part, fast_rep) = parts(&p)?;
                Answer::IssueAsRep(Ok(AsRepParts {
                    ticket,
                    enc_part,
                    fast_rep,
                }))
            }
            (Operation::IssueAsRep, R::IssueFailure(e)) => Answer::IssueAsRep(Err(e)),
            (Operation::OpenFastArmor, R::OpenFastArmor(a)) => {
                Answer::OpenFastArmor(Ok(FastArmor {
                    armor_id: a.armor_id,
                    armor_crealm: realm(&a.armor_crealm)?,
                    armor_cname: decoded(&a.armor_cname, PrincipalName::decode)?,
                    armor_authtime: time(&a.armor_authtime)?,
                    fast_req: decoded(&a.fast_req, KrbFastReq::decode)?,
                }))
            }
            (Operation::OpenFastArmor, R::AuthnFailure(e)) => Answer::OpenFastArmor(Err(e)),
            (Operation::OpenAndVerifyTgt, R::OpenAndVerifyTgt(c)) => {
                Answer::OpenAndVerifyTgt(Ok(TgtContext {
                    ctx_id: c.ctx_id,
                    crealm: realm(&c.crealm)?,
                    cname: decoded(&c.cname, PrincipalName::decode)?,
                    authtime: time(&c.authtime)?,
                    starttime: opt_time(c.starttime.as_ref())?,
                    endtime: time(&c.endtime)?,
                    renew_till: opt_time(c.renew_till.as_ref())?,
                    flags: c.flags,
                    fast_req: match &c.fast_req {
                        Some(blob) => Some(decoded(blob, KrbFastReq::decode)?),
                        None => None,
                    },
                }))
            }
            (Operation::OpenAndVerifyTgt, R::AuthnFailure(e)) => Answer::OpenAndVerifyTgt(Err(e)),
            (Operation::IssueTgsRep, R::IssueTgsRep(p)) => {
                let (ticket, enc_part, fast_rep) = parts(&p)?;
                Answer::IssueTgsRep(Ok(TgsRepParts {
                    ticket,
                    enc_part,
                    fast_rep,
                }))
            }
            (Operation::IssueTgsRep, R::IssueFailure(e)) => Answer::IssueTgsRep(Err(e)),
            (Operation::SealFastError, R::SealFastError(sealed)) => {
                Answer::SealFastError(Ok(decoded(&sealed, EncryptedData::decode)?))
            }
            (Operation::SealFastError, R::Failure(e)) => Answer::SealFastError(Err(e)),
            (Operation::OpenAndVerifyServiceTicket, R::OpenAndVerifyServiceTicket(c)) => {
                Answer::OpenAndVerifyServiceTicket(Ok(ServiceContext {
                    ctx_id: c.ctx_id,
                    crealm: realm(&c.crealm)?,
                    cname: decoded(&c.cname, PrincipalName::decode)?,
                    authtime: time(&c.authtime)?,
                    endtime: time(&c.endtime)?,
                    flags: c.flags,
                    subkey_present: c.subkey_present,
                }))
            }
            (Operation::OpenAndVerifyServiceTicket, R::AuthnFailure(e)) => {
                Answer::OpenAndVerifyServiceTicket(Err(e))
            }
            (Operation::SetSecret, R::SetSecret(k)) => Answer::SetSecret(Ok(k)),
            (Operation::SetSecret, R::Failure(e)) => Answer::SetSecret(Err(e)),
            (Operation::VerifySecret, R::VerifySecret) => Answer::VerifySecret(Ok(())),
            (Operation::VerifySecret, R::Failure(e)) => Answer::VerifySecret(Err(e)),
            (Operation::CreateKey, R::CreateKey(k)) => Answer::CreateKey(Ok(k)),
            (Operation::CreateKey, R::Failure(e)) => Answer::CreateKey(Err(e)),
            (Operation::RotateKey, R::RotateKey(k)) => Answer::RotateKey(Ok(k)),
            (Operation::RotateKey, R::Failure(e)) => Answer::RotateKey(Err(e)),
            (Operation::RotateKrbtgt, R::RotateKrbtgt(k)) => Answer::RotateKrbtgt(Ok(k)),
            (Operation::RotateKrbtgt, R::Failure(e)) => Answer::RotateKrbtgt(Err(e)),
            (Operation::RetireKvno, R::RetireKvno) => Answer::RetireKvno(Ok(())),
            (Operation::RetireKvno, R::Failure(e)) => Answer::RetireKvno(Err(e)),
            (Operation::DestroyKeySet, R::DestroyKeySet) => Answer::DestroyKeySet(Ok(())),
            (Operation::DestroyKeySet, R::Failure(e)) => Answer::DestroyKeySet(Err(e)),
            (Operation::DescribeConfig, R::DescribeConfig(d)) => {
                Answer::DescribeConfig(Ok(DescribedConfig {
                    description: ConfigDescription {
                        realm: realm(&d.realm)?,
                        enctypes: d.enctypes,
                        clock_skew_secs: d.clock_skew_secs,
                        token_lifetime_secs: d.token_lifetime_secs,
                        ticket_policy: d.ticket_policy,
                        s2k_params: d.s2k_params,
                    },
                    caller_role: d.caller_role,
                }))
            }
            (Operation::DescribeConfig, R::Failure(e)) => Answer::DescribeConfig(Err(e)),
            (Operation::Ping, R::Ping) => Answer::Ping(Ok(())),
            (Operation::Ping, R::Failure(e)) => Answer::Ping(Err(e)),
            _ => return Err(ConversionError::UnexpectedReply),
        })
    }
}

/// `AsRepParts` / `TgsRepParts` on the wire. Spec: docs/50 §3.4.
fn wire_parts(
    ticket: &Ticket,
    enc_part: &EncryptedData,
    fast_rep: Option<&EncryptedData>,
) -> Converted<WireRepParts> {
    Ok(WireRepParts {
        ticket: der(ticket.encode())?,
        enc_part: der(enc_part.encode())?,
        fast_rep: match fast_rep {
            Some(sealed) => Some(der(sealed.encode())?),
            None => None,
        },
    })
}

/// Spec: docs/50 §3.4; RFC 4120 5.3, 5.2.9.
fn parts(wire: &WireRepParts) -> Converted<(Ticket, EncryptedData, Option<EncryptedData>)> {
    Ok((
        decoded(&wire.ticket, Ticket::decode)?,
        decoded(&wire.enc_part, EncryptedData::decode)?,
        match &wire.fast_rep {
            Some(blob) => Some(decoded(blob, EncryptedData::decode)?),
            None => None,
        },
    ))
}
