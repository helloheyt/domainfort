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
//! An attested name resolution (task PN11) crosses as its realms, names,
//! fields and tag: on decode every value through its strict decoder and the
//! whole through `keyd_types::NameResolution::new` (the bounds); the tag is
//! carried as received, never checked here (keyd verifies it — docs/59
//! §7.2).
//!
//! Spec: docs/50 §3.3 (Kerberos values as DER "decoded in `krb-proto` (strict
//! DER, already fuzzed and inside keyd's TCB)"; secret-bearing buffers
//! zeroized), §3.4; docs/10 §4-§9; docs/questions/Q-225 item 6 (A-59),
//! Q-245 item 1; docs/59 §7.1, §7.5.

use crate::channel::ATTESTATION_KEY_OCTETS;
use crate::wire::{
    CompleteChangePasswordRequest, CreateKeyRequest, GrantSetSecretRequest,
    InstallAttestationKeyRequest, IssueAsRepRequest, IssueTgsRepRequest, KeydReply, KeydRequest,
    OpenAndVerifyServiceTicketRequest, OpenAndVerifyTgtRequest, OpenChangePasswordRequestFields,
    OpenFastArmorRequest, RegisterDecisionRequest, SealChangePasswordErrorRequest,
    SealFastErrorRequest, SetSecretRequest, VerifyOperationTicketRequest, VerifyPreauthRequest,
    VerifySecretRequest, WireAsTemplate, WireAuthnProof, WireBinding, WireChangePasswordContext,
    WireConfigDescription, WireDecidedOperation, WireDestructionPage, WireFastArmor,
    WireNameResolution, WireOperationTicket, WireRepParts, WireSealedReply, WireServiceContext,
    WireSetSecretTarget, WireTgsFast, WireTgsTemplate, WireTgtContext, WireTime,
};
use core::fmt;
use ipc::{DerBlob, Secret};
use keyd_types::{
    AccountKind, ArmorId, AsRepParts, AsTicketTemplate, AttestedNameResolution, AuthnError,
    AuthnProof, ChangePasswordContext, ChangePasswordCtxId, ConfigDescription, CtxId,
    DecidedOperation, DecisionId, DestructionPage, FastArmor, FastConversation, HostAddr,
    IssueError, KeyHandle, Kvno, NameResolution, NameResolutionFields, Operation, OperationDigest,
    OperationTicket, PrincipalBinding, PrincipalId, Role, SealedReply, ServiceContext,
    SetSecretTarget, TgsRepParts, TgsTicketTemplate, TgtContext,
};
use krb_proto::{
    ApRep, ApReq, EncryptedData, KerberosTime, KrbError, KrbFastArmoredReq, KrbFastReq, KrbPriv,
    NonZeroResultCode, PaData, PrincipalName, Realm, Ticket,
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
    /// An attestation key of all-zero octets (task PN9): a buffer that was
    /// never filled — the key is drawn at random — so it is not a key
    /// ([`AttestationKeyOctets`]). Carries no octet.
    /// Spec: docs/questions/Q-1011 item 2 (A-173: provision draws the key);
    /// crate name-attestation `AttestationKey::from_bytes` (the same rule);
    /// AGENTS.md §6 (fail closed).
    AttestationKey,
    /// An attested name resolution outside a resolution's bounds (task
    /// PN11): `keyd_types::NameResolution::new` refused it. Carries no
    /// value.
    /// Spec: docs/59 §7.1 (the bounds); docs/50 §3.3.
    NameResolution,
}

impl fmt::Display for ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ConversionError::KerberosValue => "Kerberos value refused by krb-proto",
            ConversionError::Text => "text field is not UTF-8",
            ConversionError::UnexpectedReply => "reply does not belong to the operation called",
            ConversionError::AttestationKey => "attestation key refused",
            ConversionError::NameResolution => "name resolution outside its bounds",
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

/// The wire form of an attested name resolution: its realms' octets, its
/// names' DER, its other fields and its tag, unchanged (task PN11).
/// Spec: docs/59 §7.1, §7.5; docs/50 §3.3.
fn wire_resolution(attested: &AttestedNameResolution) -> Converted<WireNameResolution> {
    let resolution = attested.resolution();
    Ok(WireNameResolution {
        realm_as_sent: resolution.realm_as_sent().as_bytes().to_vec(),
        name_as_sent: der(resolution.name_as_sent().encode())?,
        canonical_realm: resolution.canonical_realm().as_bytes().to_vec(),
        canonical_name: der(resolution.canonical_name().encode())?,
        principal: resolution.principal(),
        key_purpose: resolution.key_purpose(),
        snapshot: resolution.snapshot(),
        issued_at: wire_time(&resolution.issued_at()),
        tag: *attested.tag(),
    })
}

/// The attested name resolution of a wire value: every Kerberos value
/// through krb-proto's strict decoder, the whole through
/// `NameResolution::new` (the bounds — else
/// [`ConversionError::NameResolution`]). The tag is carried as received —
/// **not verified** here (keyd verifies it first, docs/59 §7.2 step 1).
/// Spec: docs/59 §7.1, §7.2 step 1, §7.5; docs/50 §3.3.
fn resolution(wire: &WireNameResolution) -> Converted<AttestedNameResolution> {
    let resolution = NameResolution::new(NameResolutionFields {
        realm_as_sent: realm(&wire.realm_as_sent)?,
        name_as_sent: decoded(&wire.name_as_sent, PrincipalName::decode)?,
        canonical_realm: realm(&wire.canonical_realm)?,
        canonical_name: decoded(&wire.canonical_name, PrincipalName::decode)?,
        principal: wire.principal,
        key_purpose: wire.key_purpose,
        snapshot: wire.snapshot,
        issued_at: time(&wire.issued_at)?,
    })
    .map_err(|_| ConversionError::NameResolution)?;
    Ok(AttestedNameResolution::new(resolution, wire.tag))
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

/// The attestation key's octets on their way to keyd (task PN9): exactly
/// [`ATTESTATION_KEY_OCTETS`] octets, never all zero, in one heap buffer that
/// is wiped when the value is dropped. Moving the value moves only the
/// pointer, so no copy of the key is left behind by a move.
///
/// * `Debug` prints neither the octets nor anything derived from them;
///   there is no `Display`, `Clone` or `PartialEq` (no silent second copy, no
///   variable-time comparison of key material).
/// * The octets are reachable only through [`AttestationKeyOctets::expose`],
///   so every place that touches them is visible in review — in the keyd
///   process, the one place that turns them into keyd's key (crate
///   ipc-keyd-server); in keyadm, none (it only sends them).
/// * The all-zero key is unrepresentable: it is a buffer that was never
///   filled (provision draws the key at random — A-173), and crate
///   name-attestation refuses it too (`AttestationKey::from_bytes`). Refusing
///   it here, at the codec, means a zero key never reaches keyd's
///   classification — it is `Malformed`, no intent is written for it, and
///   the key keyd builds from an admitted call always exists (the two rules
///   are pinned equal in crate ipc-keyd-server).
///
/// This crate links no crypto code (D182; A-63, A-173: only dird and keyd
/// link name-attestation): this is a carrier of octets, not a key — it can
/// neither tag nor verify.
///
/// Spec: docs/59 §7.4, §7.5; docs/questions/Q-1011 item 2 (A-173: "delivered
/// to keyd in ceremony mode only, never exported"), Q-1033 (A-177); docs/50
/// §3.3 (secret-bearing buffers zeroized, in both sides), §8.2; AGENTS.md §6.
pub struct AttestationKeyOctets(Box<Zeroizing<[u8; ATTESTATION_KEY_OCTETS]>>);

impl AttestationKeyOctets {
    /// Copy `octets` into a new zeroizing buffer — `None` unless they are
    /// exactly [`ATTESTATION_KEY_OCTETS`] octets and not all zero. The caller
    /// stays responsible for wiping its own copy.
    /// Spec: docs/59 §7.4; docs/questions/Q-1011 item 2; AGENTS.md §6 (fail
    /// closed).
    #[must_use]
    pub fn from_slice(octets: &[u8]) -> Option<AttestationKeyOctets> {
        let octets: &[u8; ATTESTATION_KEY_OCTETS] = octets.try_into().ok()?;
        if octets.iter().all(|&octet| octet == 0) {
            return None;
        }
        // The buffer is allocated (zeroed) first and filled in place: the
        // key is copied once, from `octets` to the heap.
        let mut buffer = Box::new(Zeroizing::new([0u8; ATTESTATION_KEY_OCTETS]));
        let target: &mut [u8; ATTESTATION_KEY_OCTETS] = &mut buffer;
        target.copy_from_slice(octets);
        Some(AttestationKeyOctets(buffer))
    }

    /// The key's octets. Named so every use is visible in review.
    /// Spec: AGENTS.md §6 (secrets never in logs, panics or errors).
    #[must_use]
    pub fn expose(&self) -> &[u8; ATTESTATION_KEY_OCTETS] {
        &self.0
    }

    /// A zeroizing wire copy of the octets.
    fn to_secret(&self) -> Secret {
        Secret::from_slice(self.expose())
    }
}

impl fmt::Debug for AttestationKeyOctets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AttestationKeyOctets(<redacted>)")
    }
}

/// The attestation key of a wire request: the octets move out of the wire's
/// [`Secret`] into an [`AttestationKeyOctets`] (one more zeroizing copy; the
/// `Secret` is wiped when it drops here). All zeros ⇒
/// [`ConversionError::AttestationKey`].
/// Spec: docs/50 §3.3 (secret-bearing buffers zeroized); docs/59 §7.5.
fn attestation_key(secret: &Secret) -> Converted<AttestationKeyOctets> {
    AttestationKeyOctets::from_slice(secret.expose()).ok_or(ConversionError::AttestationKey)
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
    /// Spec: docs/10 §4; docs/59 §7.5.
    IssueAsRep {
        /// PrincipalLongterm handle.
        client: KeyHandle,
        /// The server's handle: Krbtgt, or (armored) ChangePasswordService.
        krbtgt: KeyHandle,
        /// The proof of `verify_preauth`.
        proof: AuthnProof,
        /// The FAST armor, if armored.
        armor: Option<ArmorId>,
        /// The ticket template.
        template: AsTicketTemplate,
        /// dird's resolution of the client's name (task PN11; boxed — the
        /// call enum stays small).
        client_resolution: Box<AttestedNameResolution>,
        /// dird's resolution of the change-password service's name; `None`
        /// for a TGT (task PN11).
        server_resolution: Option<Box<AttestedNameResolution>>,
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
    /// Spec: docs/10 §5; docs/59 §7.5.
    IssueTgsRep {
        /// Service handle.
        service: KeyHandle,
        /// The context of `open_and_verify_tgt`.
        ctx: CtxId,
        /// The ticket template.
        template: TgsTicketTemplate,
        /// dird's resolution of the service's name (task PN11; boxed).
        service_resolution: Box<AttestedNameResolution>,
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
    /// The unbound verification (the LDAP front). Spec: docs/10 §5ב;
    /// docs/52 §5 item 3 (R2: keyd derives the key set's purpose from the
    /// binding); docs/questions/Q-523.
    OpenAndVerifyServiceTicket {
        /// The service key set's principal.
        service: PrincipalId,
        /// The raw KRB_AP_REQ octets.
        ap_req_octets: Vec<u8>,
    },
    /// The operation-bound verification (dird's admin channel): keeps no
    /// service context. Spec: docs/10 §5ב; docs/52 §5 items 3-4;
    /// docs/questions/Q-523.
    VerifyOperationTicket {
        /// The admin service key set's principal.
        service: PrincipalId,
        /// The operation the AP-REQ must be bound to.
        operation: OperationDigest,
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
    /// No role may call it since A-102 (docs/52 R4); keyd refuses it at the
    /// capability table, with its record. Spec: docs/10 §6.
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
    /// Run dird's `RotateKey` decision. Spec: docs/10 §7; docs/52 §4.2.
    RotateKey {
        /// The decision id.
        decision: DecisionId,
    },
    /// Run dird's `RotateKrbtgt` decision (keyd builds the dual-control
    /// token from its approvers). Spec: docs/10 §7; docs/52 §4.2.
    RotateKrbtgt {
        /// The decision id.
        decision: DecisionId,
    },
    /// Run dird's `RetireKvno` decision. Spec: docs/10 §7; docs/52 §4.2.
    RetireKvno {
        /// The decision id.
        decision: DecisionId,
    },
    /// Run dird's `DestroyKeySet` decision. Spec: docs/10 §7; A-35;
    /// docs/52 §4.2.
    DestroyKeySet {
        /// The decision id.
        decision: DecisionId,
    },
    /// Spec: docs/10 §7א.
    DescribeConfig,
    /// Spec: docs/10 §7א.
    Ping,
    /// Spec: docs/51 §5.8 option (b); docs/questions/Q-450.
    GrantSetSecret {
        /// The account kind.
        kind: AccountKind,
        /// The key targets.
        targets: Vec<SetSecretTarget>,
        /// How long the grant stays live, in seconds (keyd's clock).
        lifetime_secs: u32,
    },
    /// dird registers a decision (Role::Ldap). Spec: docs/52 §4.2.
    RegisterDecision {
        /// dird's decision id.
        id: DecisionId,
        /// What dird decided.
        operation: DecidedOperation,
        /// The approvers dird verified.
        approvers: Vec<PrincipalId>,
        /// How long the decision stays live, in seconds (keyd's clock).
        lifetime_secs: u32,
    },
    /// End the provisioning ceremony (Role::Admin). Spec: docs/52 §4.4.
    SealCeremony,
    /// One page of pending destroy decisions (Role::Admin). Spec: docs/52
    /// §4.6.
    ListDestroyDecisions {
        /// Resume strictly after this decision id.
        after: Option<DecisionId>,
    },
    /// Open an RFC 3244 request (Role::Ldap; task K4). No password field:
    /// the password is inside the KRB-PRIV, which only keyd decrypts.
    /// Spec: docs/53 §5.5; RFC 3244 §2.
    OpenChangePasswordRequest {
        /// The change-password service key set's principal.
        service: PrincipalId,
        /// The raw KRB_AP_REQ octets.
        ap_req_octets: Vec<u8>,
        /// The raw KRB-PRIV octets.
        krb_priv_octets: Vec<u8>,
        /// The peer's address, as the front's kernel reported it.
        peer: HostAddr,
        /// The connection's local address.
        local: HostAddr,
    },
    /// Complete a request on dird's decision (Role::Ldap; task K4) — a
    /// state call. Spec: docs/53 §5.5.
    CompleteChangePassword {
        /// The request context.
        ctx: ChangePasswordCtxId,
        /// The user's password key set.
        target: KeyHandle,
    },
    /// Seal a request's error reply (Role::Ldap; task K4). Spec: docs/53
    /// §5.5, §5.7.
    SealChangePasswordError {
        /// The request context.
        ctx: ChangePasswordCtxId,
        /// The non-zero result code.
        code: NonZeroResultCode,
    },
    /// Revoke dird's key-operation decision (Role::Ldap; task F3). Not a
    /// state call: it only makes keyd stricter. Spec: docs/52 §4.2;
    /// docs/questions/Q-937 item 6, Q-976.
    RevokeDecision {
        /// The decision id (dird's request id).
        id: DecisionId,
    },
    /// Install the attestation key of dird's name resolutions (Role::Admin,
    /// the ceremony only; task PN9) — a state call. Spec: docs/59 §7.4,
    /// §7.5; docs/questions/Q-1011 items 2, 8, Q-1033.
    InstallAttestationKey {
        /// The key's octets (exactly 32, never all zero).
        key: AttestationKeyOctets,
    },
}

impl Call {
    /// The decision id an execution names (`rotate_key`, `rotate_krbtgt`,
    /// `retire_kvno`, `destroy_key_set`), else `None`.
    /// Spec: docs/52 §4.2.
    #[must_use]
    pub fn decision(&self) -> Option<DecisionId> {
        match self {
            Call::RotateKey { decision }
            | Call::RotateKrbtgt { decision }
            | Call::RetireKvno { decision }
            | Call::DestroyKeySet { decision } => Some(*decision),
            _ => None,
        }
    }

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
            Call::VerifyOperationTicket { .. } => Operation::VerifyOperationTicket,
            Call::SetSecret { .. } => Operation::SetSecret,
            Call::VerifySecret { .. } => Operation::VerifySecret,
            Call::CreateKey { .. } => Operation::CreateKey,
            Call::RotateKey { .. } => Operation::RotateKey,
            Call::RotateKrbtgt { .. } => Operation::RotateKrbtgt,
            Call::RetireKvno { .. } => Operation::RetireKvno,
            Call::DestroyKeySet { .. } => Operation::DestroyKeySet,
            Call::DescribeConfig => Operation::DescribeConfig,
            Call::Ping => Operation::Ping,
            Call::GrantSetSecret { .. } => Operation::GrantSetSecret,
            Call::RegisterDecision { .. } => Operation::RegisterDecision,
            Call::SealCeremony => Operation::SealCeremony,
            Call::ListDestroyDecisions { .. } => Operation::ListDestroyDecisions,
            Call::OpenChangePasswordRequest { .. } => Operation::OpenChangePasswordRequest,
            Call::CompleteChangePassword { .. } => Operation::CompleteChangePassword,
            Call::SealChangePasswordError { .. } => Operation::SealChangePasswordError,
            Call::RevokeDecision { .. } => Operation::RevokeDecision,
            Call::InstallAttestationKey { .. } => Operation::InstallAttestationKey,
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
                client_resolution,
                server_resolution,
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
                client_resolution: Box::new(wire_resolution(client_resolution)?),
                server_resolution: match server_resolution {
                    Some(server) => Some(Box::new(wire_resolution(server)?)),
                    None => None,
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
                service_resolution,
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
                service_resolution: Box::new(wire_resolution(service_resolution)?),
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
            Call::VerifyOperationTicket {
                service,
                operation,
                ap_req_octets,
            } => KeydRequest::VerifyOperationTicket(VerifyOperationTicketRequest {
                service: *service,
                operation: *operation,
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
            Call::RotateKey { decision } => KeydRequest::RotateKey(*decision),
            Call::RotateKrbtgt { decision } => KeydRequest::RotateKrbtgt(*decision),
            Call::RetireKvno { decision } => KeydRequest::RetireKvno(*decision),
            Call::DestroyKeySet { decision } => KeydRequest::DestroyKeySet(*decision),
            Call::DescribeConfig => KeydRequest::DescribeConfig,
            Call::Ping => KeydRequest::Ping,
            Call::GrantSetSecret {
                kind,
                targets,
                lifetime_secs,
            } => KeydRequest::GrantSetSecret(GrantSetSecretRequest {
                kind: *kind,
                targets: wire_targets(targets)?,
                lifetime_secs: *lifetime_secs,
            }),
            Call::RegisterDecision {
                id,
                operation,
                approvers,
                lifetime_secs,
            } => KeydRequest::RegisterDecision(RegisterDecisionRequest {
                id: *id,
                operation: wire_decided(operation)?,
                approvers: approvers.clone(),
                lifetime_secs: *lifetime_secs,
            }),
            Call::SealCeremony => KeydRequest::SealCeremony,
            Call::ListDestroyDecisions { after } => KeydRequest::ListDestroyDecisions(*after),
            Call::OpenChangePasswordRequest {
                service,
                ap_req_octets,
                krb_priv_octets,
                peer,
                local,
            } => KeydRequest::OpenChangePasswordRequest(OpenChangePasswordRequestFields {
                service: *service,
                ap_req_octets: ap_req_octets.clone(),
                krb_priv_octets: krb_priv_octets.clone(),
                peer: *peer,
                local: *local,
            }),
            Call::CompleteChangePassword { ctx, target } => {
                KeydRequest::CompleteChangePassword(CompleteChangePasswordRequest {
                    ctx: *ctx,
                    target: *target,
                })
            }
            Call::SealChangePasswordError { ctx, code } => {
                KeydRequest::SealChangePasswordError(SealChangePasswordErrorRequest {
                    ctx: *ctx,
                    code: *code,
                })
            }
            Call::RevokeDecision { id } => KeydRequest::RevokeDecision(*id),
            Call::InstallAttestationKey { key } => {
                KeydRequest::InstallAttestationKey(InstallAttestationKeyRequest {
                    key: key.to_secret(),
                })
            }
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
                client_resolution: Box::new(resolution(&m.client_resolution)?),
                server_resolution: match &m.server_resolution {
                    Some(server) => Some(Box::new(resolution(server)?)),
                    None => None,
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
                service_resolution: Box::new(resolution(&m.service_resolution)?),
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
            KeydRequest::VerifyOperationTicket(m) => Call::VerifyOperationTicket {
                service: m.service,
                operation: m.operation,
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
            KeydRequest::RotateKey(decision) => Call::RotateKey { decision },
            KeydRequest::RotateKrbtgt(decision) => Call::RotateKrbtgt { decision },
            KeydRequest::RetireKvno(decision) => Call::RetireKvno { decision },
            KeydRequest::DestroyKeySet(decision) => Call::DestroyKeySet { decision },
            KeydRequest::DescribeConfig => Call::DescribeConfig,
            KeydRequest::Ping => Call::Ping,
            KeydRequest::GrantSetSecret(m) => Call::GrantSetSecret {
                kind: m.kind,
                targets: targets(&m.targets)?,
                lifetime_secs: m.lifetime_secs,
            },
            KeydRequest::RegisterDecision(m) => Call::RegisterDecision {
                id: m.id,
                operation: decided(&m.operation)?,
                approvers: m.approvers,
                lifetime_secs: m.lifetime_secs,
            },
            KeydRequest::SealCeremony => Call::SealCeremony,
            KeydRequest::ListDestroyDecisions(after) => Call::ListDestroyDecisions { after },
            KeydRequest::OpenChangePasswordRequest(m) => Call::OpenChangePasswordRequest {
                service: m.service,
                ap_req_octets: m.ap_req_octets,
                krb_priv_octets: m.krb_priv_octets,
                peer: m.peer,
                local: m.local,
            },
            KeydRequest::CompleteChangePassword(m) => Call::CompleteChangePassword {
                ctx: m.ctx,
                target: m.target,
            },
            KeydRequest::SealChangePasswordError(m) => Call::SealChangePasswordError {
                ctx: m.ctx,
                code: m.code,
            },
            KeydRequest::RevokeDecision(id) => Call::RevokeDecision { id },
            KeydRequest::InstallAttestationKey(m) => Call::InstallAttestationKey {
                key: attestation_key(&m.key)?,
            },
        })
    }
}

// ===========================================================================
// The two kinds of call: state calls and issuance calls (task R9).
// ===========================================================================

impl Call {
    /// Whether this is a **state call**: it changes keyd's key state or
    /// loosens keyd's authorization, so keyd-daemon has its intent
    /// acknowledged by auditd before keyd runs it, and only a request keyd
    /// refused with the shared `Refused` is known "not performed" (A-88).
    /// Decided by keyd's one table,
    /// `keyd_types::authz::requires_acknowledged_intent` — the table
    /// keyd-daemon's classification reads too (crate ipc-keyd-server
    /// `classify`), so the client and the server cannot disagree on which
    /// calls these are.
    ///
    /// Spec: docs/52 §3.10 (c), §7 R9; docs/10 §10; docs/questions/Q-365
    /// (A-88), Q-466 item 3 (A-102).
    #[must_use]
    pub fn is_state_call(&self) -> bool {
        keyd_types::authz::requires_acknowledged_intent(self.operation())
    }

    /// This call as its kind ([`RoutedCall`]), by [`Call::is_state_call`].
    /// Spec: docs/questions/Q-466 item 3 (A-102).
    #[must_use]
    pub fn route(self) -> RoutedCall {
        if self.is_state_call() {
            RoutedCall::State(StateCall(self))
        } else {
            RoutedCall::Issuance(IssuanceCall(self))
        }
    }
}

/// A call that is **not** a state call ([`Call::is_state_call`]): issuance
/// and verification (the Kdc and Ldap exchanges — the change-password
/// request's opening and error seal included, task K4), `describe_config`,
/// `ping`, `seal_ceremony`, `list_destroy_decisions`, `revoke_decision`
/// (task F3: it only makes keyd stricter) — and `verify_secret`,
/// which no role holds. The only kind of call the fate-dropping
/// `KeydClient::call` accepts.
///
/// Made only from a [`Call`] that is not a state call ([`Call::route`],
/// [`IssuanceCall::new`]): the field is private, so a state call can never be an
/// `IssuanceCall` — a state call sent through `KeydClient::call` does not
/// compile (it is a [`StateCall`] or a [`Call`], neither of which `call`
/// takes).
///
/// # The API shape, checked by the compiler
///
/// A state call passed to the fate-dropping `KeydClient::call` as a
/// [`Call`] does not compile:
///
/// ```compile_fail
/// fn send<C: ipc_keyd::Connector>(client: &mut ipc_keyd::KeydClient<C>) {
///     let call = ipc_keyd::Call::RotateKey {
///         decision: ipc_keyd::DecisionId::new(1),
///     };
///     let _ = client.call(&call);
/// }
/// ```
///
/// nor as a [`StateCall`]:
///
/// ```compile_fail
/// fn send<C: ipc_keyd::Connector>(
///     client: &mut ipc_keyd::KeydClient<C>,
///     state: ipc_keyd::StateCall,
/// ) {
///     let _ = client.call(&state);
/// }
/// ```
///
/// and an `IssuanceCall` cannot be built around one (the field is private):
///
/// ```compile_fail
/// let _ = ipc_keyd::IssuanceCall(ipc_keyd::Call::RotateKey {
///     decision: ipc_keyd::DecisionId::new(1),
/// });
/// ```
///
/// The paths that exist compile: the state call through
/// `KeydClient::call_with_fate` (which reports the fate), an issuance call
/// through either.
///
/// ```
/// fn send<C: ipc_keyd::Connector>(client: &mut ipc_keyd::KeydClient<C>) {
///     let call = ipc_keyd::Call::RotateKey {
///         decision: ipc_keyd::DecisionId::new(1),
///     };
///     let _ = client.call_with_fate(&call);
///     if let Some(ping) = ipc_keyd::IssuanceCall::new(ipc_keyd::Call::Ping) {
///         let _ = client.call(&ping);
///     }
/// }
/// ```
///
/// Spec: docs/52 §3.10 (c), §7 R9; docs/questions/Q-367 (A-88), Q-466 item
/// 3 (A-102).
#[derive(Debug)]
pub struct IssuanceCall(Call);

impl IssuanceCall {
    /// `call` as an issuance call; `None` for a state call (which is
    /// dropped — send it with `KeydClient::call_with_fate`, or keep it with
    /// [`Call::route`]).
    /// Spec: docs/questions/Q-466 item 3 (A-102).
    #[must_use]
    pub fn new(call: Call) -> Option<IssuanceCall> {
        match call.route() {
            RoutedCall::Issuance(issuance) => Some(issuance),
            RoutedCall::State(_) => None,
        }
    }

    /// The call.
    #[must_use]
    pub fn call(&self) -> &Call {
        &self.0
    }

    /// The call, by value.
    #[must_use]
    pub fn into_call(self) -> Call {
        self.0
    }
}

/// A **state call** ([`Call::is_state_call`]): `set_secret`, `create_key`,
/// `rotate_key`, `rotate_krbtgt`, `retire_kvno`, `destroy_key_set`,
/// `grant_set_secret`, `register_decision`, `complete_change_password`
/// (task K4: it installs a password), `install_attestation_key` (task PN9:
/// it installs the attestation key). Its request's fate matters —
/// "not performed" (keyd refused it before running it, A-88) and "outcome
/// unknown" (it may have run) must not be folded into one `Unavailable` —
/// so the keyd client sends it only through `KeydClient::call_with_fate`
/// (or a typed method that returns the fate). `KeydClient::call` takes
/// only an [`IssuanceCall`].
///
/// Spec: docs/52 §3.10 (c), §7 R9; docs/10 §10; docs/questions/Q-367
/// (A-88), Q-466 item 3 (A-102).
#[derive(Debug)]
pub struct StateCall(Call);

impl StateCall {
    /// `call` as a state call; `None` for a call that is not one (it is
    /// dropped — keep it with [`Call::route`]).
    /// Spec: docs/questions/Q-466 item 3 (A-102).
    #[must_use]
    pub fn new(call: Call) -> Option<StateCall> {
        match call.route() {
            RoutedCall::State(state) => Some(state),
            RoutedCall::Issuance(_) => None,
        }
    }

    /// The call.
    #[must_use]
    pub fn call(&self) -> &Call {
        &self.0
    }

    /// The call, by value.
    #[must_use]
    pub fn into_call(self) -> Call {
        self.0
    }
}

/// A call split into its kind by keyd's one table ([`Call::route`]).
/// Spec: docs/questions/Q-466 item 3 (A-102).
#[derive(Debug)]
pub enum RoutedCall {
    /// Not a state call: it may be sent with `KeydClient::call`.
    Issuance(IssuanceCall),
    /// A state call: only with `KeydClient::call_with_fate`.
    State(StateCall),
}

impl RoutedCall {
    /// The call.
    #[must_use]
    pub fn call(&self) -> &Call {
        match self {
            RoutedCall::Issuance(issuance) => issuance.call(),
            RoutedCall::State(state) => state.call(),
        }
    }
}

/// Set-secret targets on the wire (the salt as its UTF-8 octets).
/// Spec: docs/questions/Q-450 item 9; docs/52 §4.2 (N4).
fn wire_targets(targets: &[SetSecretTarget]) -> Converted<Vec<WireSetSecretTarget>> {
    targets
        .iter()
        .map(|t| {
            Ok(WireSetSecretTarget {
                handle: t.handle,
                binding: wire_binding(&t.binding)?,
                salt: t.salt.as_bytes().to_vec(),
            })
        })
        .collect()
}

/// Set-secret targets from the wire: each binding through krb-proto, each
/// salt as UTF-8.
/// Spec: docs/questions/Q-450 item 9; docs/52 §4.2 (N4).
fn targets(wire: &[WireSetSecretTarget]) -> Converted<Vec<SetSecretTarget>> {
    wire.iter()
        .map(|t| {
            Ok(SetSecretTarget {
                handle: t.handle,
                binding: binding(&t.binding)?,
                salt: text(&t.salt)?,
            })
        })
        .collect()
}

/// A decided operation on the wire. Spec: docs/52 §4.2, §4.6.
fn wire_decided(operation: &DecidedOperation) -> Converted<WireDecidedOperation> {
    Ok(match operation {
        DecidedOperation::SetSecret { kind, targets } => WireDecidedOperation::SetSecret {
            kind: *kind,
            targets: wire_targets(targets)?,
        },
        DecidedOperation::RotateKrbtgt { krbtgt } => WireDecidedOperation::RotateKrbtgt(*krbtgt),
        DecidedOperation::RotateKey { handle } => WireDecidedOperation::RotateKey(*handle),
        DecidedOperation::RetireKvno { handle, kvno } => {
            WireDecidedOperation::RetireKvno(*handle, *kvno)
        }
        DecidedOperation::DestroyKeySet { principal } => {
            WireDecidedOperation::DestroyKeySet(*principal)
        }
        DecidedOperation::ChangePassword { target } => {
            WireDecidedOperation::ChangePassword(WireSetSecretTarget {
                handle: target.handle,
                binding: wire_binding(&target.binding)?,
                salt: target.salt.as_bytes().to_vec(),
            })
        }
    })
}

/// A decided operation from the wire. Spec: docs/52 §4.2, §4.6.
fn decided(wire: &WireDecidedOperation) -> Converted<DecidedOperation> {
    Ok(match wire {
        WireDecidedOperation::SetSecret { kind, targets: t } => DecidedOperation::SetSecret {
            kind: *kind,
            targets: targets(t)?,
        },
        WireDecidedOperation::RotateKrbtgt(krbtgt) => {
            DecidedOperation::RotateKrbtgt { krbtgt: *krbtgt }
        }
        WireDecidedOperation::RotateKey(handle) => DecidedOperation::RotateKey { handle: *handle },
        WireDecidedOperation::RetireKvno(handle, kvno) => DecidedOperation::RetireKvno {
            handle: *handle,
            kvno: *kvno,
        },
        WireDecidedOperation::DestroyKeySet(principal) => DecidedOperation::DestroyKeySet {
            principal: *principal,
        },
        WireDecidedOperation::ChangePassword(target) => DecidedOperation::ChangePassword {
            target: SetSecretTarget {
                handle: target.handle,
                binding: binding(&target.binding)?,
                salt: text(&target.salt)?,
            },
        },
    })
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
/// keyd never takes one from a peer (docs/50 R50-3, §3.2). A client — which
/// always expects its own role (`KeydClient`'s `ExpectedPeer`, task R9) —
/// can thus tell the Kdc role from the Ldap role, which may both call
/// `describe_config` (docs/10 §2) and which the description alone does not
/// distinguish. The `Ping` answer carries the same role for every role.
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
    /// Spec: docs/10 §5ב; docs/questions/Q-523.
    VerifyOperationTicket(Result<OperationTicket, AuthnError>),
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
    /// keyd's health answer: on success the role keyd resolved for the
    /// caller from the connection's peer uid (reported, never claimed —
    /// the server side fills it from the `CallerId` keyd authorized the
    /// call with). Every role may ping, so this is how a client of any
    /// role verifies its own role (task R9).
    /// Spec: docs/10 §2, §7א; docs/questions/Q-403 option (c), Q-466 item
    /// 2 (A-102).
    Ping(Result<Role, keyd_types::Error>),
    /// Spec: docs/51 §5.8 option (b); docs/questions/Q-450.
    GrantSetSecret(Result<(), keyd_types::Error>),
    /// Spec: docs/52 §4.2.
    RegisterDecision(Result<(), keyd_types::Error>),
    /// Spec: docs/52 §4.4.
    SealCeremony(Result<(), keyd_types::Error>),
    /// Spec: docs/52 §4.6.
    ListDestroyDecisions(Result<DestructionPage, keyd_types::Error>),
    /// Spec: docs/53 §5.5 (task K4).
    OpenChangePasswordRequest(Result<ChangePasswordContext, AuthnError>),
    /// The success reply. Spec: docs/53 §5.5 (task K4).
    CompleteChangePassword(Result<SealedReply, keyd_types::Error>),
    /// An error reply. Spec: docs/53 §5.5 (task K4).
    SealChangePasswordError(Result<SealedReply, keyd_types::Error>),
    /// Spec: docs/52 §4.2; docs/questions/Q-976 (task F3).
    RevokeDecision(Result<(), keyd_types::Error>),
    /// Spec: docs/59 §7.5; docs/questions/Q-1033 (task PN9).
    InstallAttestationKey(Result<(), keyd_types::Error>),
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
            Answer::VerifyOperationTicket(_) => Operation::VerifyOperationTicket,
            Answer::SetSecret(_) => Operation::SetSecret,
            Answer::VerifySecret(_) => Operation::VerifySecret,
            Answer::CreateKey(_) => Operation::CreateKey,
            Answer::RotateKey(_) => Operation::RotateKey,
            Answer::RotateKrbtgt(_) => Operation::RotateKrbtgt,
            Answer::RetireKvno(_) => Operation::RetireKvno,
            Answer::DestroyKeySet(_) => Operation::DestroyKeySet,
            Answer::DescribeConfig(_) => Operation::DescribeConfig,
            Answer::Ping(_) => Operation::Ping,
            Answer::GrantSetSecret(_) => Operation::GrantSetSecret,
            Answer::RegisterDecision(_) => Operation::RegisterDecision,
            Answer::SealCeremony(_) => Operation::SealCeremony,
            Answer::ListDestroyDecisions(_) => Operation::ListDestroyDecisions,
            Answer::OpenChangePasswordRequest(_) => Operation::OpenChangePasswordRequest,
            Answer::CompleteChangePassword(_) => Operation::CompleteChangePassword,
            Answer::SealChangePasswordError(_) => Operation::SealChangePasswordError,
            Answer::RevokeDecision(_) => Operation::RevokeDecision,
            Answer::InstallAttestationKey(_) => Operation::InstallAttestationKey,
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
            Answer::VerifyOperationTicket(r) => outcome(
                r,
                |t| {
                    Ok(KeydReply::VerifyOperationTicket(WireOperationTicket {
                        crealm: t.crealm.as_bytes().to_vec(),
                        cname: der(t.cname.encode())?,
                        authtime: wire_time(&t.authtime),
                        endtime: wire_time(&t.endtime),
                        flags: t.flags,
                        operation: *t.operation.as_bytes(),
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
            Answer::Ping(r) => outcome(r, |role| Ok(KeydReply::Ping(*role)), KeydReply::Failure),
            Answer::GrantSetSecret(r) => {
                outcome(r, |()| Ok(KeydReply::GrantSetSecret), KeydReply::Failure)
            }
            Answer::RegisterDecision(r) => {
                outcome(r, |()| Ok(KeydReply::RegisterDecision), KeydReply::Failure)
            }
            Answer::SealCeremony(r) => {
                outcome(r, |()| Ok(KeydReply::SealCeremony), KeydReply::Failure)
            }
            Answer::ListDestroyDecisions(r) => outcome(
                r,
                |page| {
                    Ok(KeydReply::ListDestroyDecisions(WireDestructionPage {
                        entries: page.entries.clone(),
                        next: page.next,
                    }))
                },
                KeydReply::Failure,
            ),
            Answer::OpenChangePasswordRequest(r) => outcome(
                r,
                |c| {
                    Ok(KeydReply::OpenChangePasswordRequest(
                        WireChangePasswordContext {
                            ctx_id: c.ctx_id,
                            crealm: c.crealm.as_bytes().to_vec(),
                            cname: der(c.cname.encode())?,
                            authtime: wire_time(&c.authtime),
                            endtime: wire_time(&c.endtime),
                            flags: c.flags,
                            verdict: c.verdict,
                        },
                    ))
                },
                KeydReply::AuthnFailure,
            ),
            Answer::CompleteChangePassword(r) => outcome(
                r,
                |reply| Ok(KeydReply::CompleteChangePassword(wire_sealed(reply)?)),
                KeydReply::Failure,
            ),
            Answer::SealChangePasswordError(r) => outcome(
                r,
                |reply| Ok(KeydReply::SealChangePasswordError(wire_sealed(reply)?)),
                KeydReply::Failure,
            ),
            Answer::RevokeDecision(r) => {
                outcome(r, |()| Ok(KeydReply::RevokeDecision), KeydReply::Failure)
            }
            Answer::InstallAttestationKey(r) => outcome(
                r,
                |()| Ok(KeydReply::InstallAttestationKey),
                KeydReply::Failure,
            ),
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
            (Operation::VerifyOperationTicket, R::VerifyOperationTicket(t)) => {
                Answer::VerifyOperationTicket(Ok(OperationTicket {
                    crealm: realm(&t.crealm)?,
                    cname: decoded(&t.cname, PrincipalName::decode)?,
                    authtime: time(&t.authtime)?,
                    endtime: time(&t.endtime)?,
                    flags: t.flags,
                    operation: OperationDigest::new(t.operation),
                }))
            }
            (Operation::VerifyOperationTicket, R::AuthnFailure(e)) => {
                Answer::VerifyOperationTicket(Err(e))
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
            (Operation::Ping, R::Ping(role)) => Answer::Ping(Ok(role)),
            (Operation::Ping, R::Failure(e)) => Answer::Ping(Err(e)),
            (Operation::GrantSetSecret, R::GrantSetSecret) => Answer::GrantSetSecret(Ok(())),
            (Operation::GrantSetSecret, R::Failure(e)) => Answer::GrantSetSecret(Err(e)),
            (Operation::RegisterDecision, R::RegisterDecision) => Answer::RegisterDecision(Ok(())),
            (Operation::RegisterDecision, R::Failure(e)) => Answer::RegisterDecision(Err(e)),
            (Operation::SealCeremony, R::SealCeremony) => Answer::SealCeremony(Ok(())),
            (Operation::SealCeremony, R::Failure(e)) => Answer::SealCeremony(Err(e)),
            (Operation::ListDestroyDecisions, R::ListDestroyDecisions(page)) => {
                Answer::ListDestroyDecisions(Ok(DestructionPage {
                    entries: page.entries,
                    next: page.next,
                }))
            }
            (Operation::ListDestroyDecisions, R::Failure(e)) => {
                Answer::ListDestroyDecisions(Err(e))
            }
            (Operation::OpenChangePasswordRequest, R::OpenChangePasswordRequest(c)) => {
                Answer::OpenChangePasswordRequest(Ok(ChangePasswordContext {
                    ctx_id: c.ctx_id,
                    crealm: realm(&c.crealm)?,
                    cname: decoded(&c.cname, PrincipalName::decode)?,
                    authtime: time(&c.authtime)?,
                    endtime: time(&c.endtime)?,
                    flags: c.flags,
                    verdict: c.verdict,
                }))
            }
            (Operation::OpenChangePasswordRequest, R::AuthnFailure(e)) => {
                Answer::OpenChangePasswordRequest(Err(e))
            }
            (Operation::CompleteChangePassword, R::CompleteChangePassword(s)) => {
                Answer::CompleteChangePassword(Ok(sealed(&s)?))
            }
            (Operation::CompleteChangePassword, R::Failure(e)) => {
                Answer::CompleteChangePassword(Err(e))
            }
            (Operation::SealChangePasswordError, R::SealChangePasswordError(s)) => {
                Answer::SealChangePasswordError(Ok(sealed(&s)?))
            }
            (Operation::SealChangePasswordError, R::Failure(e)) => {
                Answer::SealChangePasswordError(Err(e))
            }
            (Operation::RevokeDecision, R::RevokeDecision) => Answer::RevokeDecision(Ok(())),
            (Operation::RevokeDecision, R::Failure(e)) => Answer::RevokeDecision(Err(e)),
            (Operation::InstallAttestationKey, R::InstallAttestationKey) => {
                Answer::InstallAttestationKey(Ok(()))
            }
            (Operation::InstallAttestationKey, R::Failure(e)) => {
                Answer::InstallAttestationKey(Err(e))
            }
            _ => return Err(ConversionError::UnexpectedReply),
        })
    }
}

/// A `SealedReply` on the wire: the AP-REP and the KRB-PRIV as canonical
/// DER. Spec: docs/53 §5.5; docs/50 §3.3.
fn wire_sealed(reply: &SealedReply) -> Converted<WireSealedReply> {
    Ok(WireSealedReply {
        ap_rep: der(reply.ap_rep.encode())?,
        krb_priv: der(reply.krb_priv.encode())?,
    })
}

/// A `SealedReply` from the wire: both through krb-proto's strict decoder.
/// Spec: docs/53 §5.5; docs/50 §3.3 (replies decoded as strictly as
/// requests).
fn sealed(wire: &WireSealedReply) -> Converted<SealedReply> {
    Ok(SealedReply {
        ap_rep: decoded(&wire.ap_rep, ApRep::decode)?,
        krb_priv: decoded(&wire.krb_priv, KrbPriv::decode)?,
    })
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
