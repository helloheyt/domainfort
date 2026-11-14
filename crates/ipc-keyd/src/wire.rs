//! The wire messages of the keyd channel: fixed-order fields, one struct per
//! message, and the two closed message sets ([`KeydRequest`],
//! [`KeydReply`]).
//!
//! What a field holds on the wire:
//!
//! | value | encoding |
//! |---|---|
//! | `KeyHandle` | 16-octet `PrincipalId` ‖ purpose `u8` (closed table) |
//! | `ExchangeId` / `CtxId` / `ArmorId` / `ServiceCtxId` | `TOKEN_ID_LENGTH` octets |
//! | `Kvno`, `nonce`, flags (`TicketFlags`, 32 bits) | `u32` |
//! | `EncTypeId` | `u8` = the etype number, closed table of keyd-types (= krb-crypto's, pinned in keyd) |
//! | Kerberos structures (`PA-DATA`, `AP-REQ`, `KrbFastArmoredReq`, `KrbFastReq`, `KRB-ERROR`, `Ticket`, `EncryptedData`, `PrincipalName`) | [`DerBlob`], decoded by `krb-proto` after the ipc layer |
//! | `Realm` | its KerberosString octets, checked by `krb-proto` after the ipc layer |
//! | `KerberosTime` | [`WireTime`]: year `u16` ‖ month ‖ day ‖ hour ‖ minute ‖ second (`u8` each), checked by `krb-proto` after the ipc layer |
//! | raw octets keyd itself parses (`outer_req_body`, `req_body`, `ap_req_octets`) | `bytes<max>`, opaque |
//! | password / candidate | [`Secret`] (zeroizing; `Debug` redacted) |
//! | salt | `bytes<max>`, UTF-8 checked after the ipc layer |
//! | `AccountKind` of a grant | `u8` (closed table: 1 User, 2 Computer) |
//! | grant lifetime | `u32` seconds, relative — keyd adds its own clock's `now` |
//!
//! The ipc layer here checks only what it can check without interpreting a
//! Kerberos value (lengths, markers, closed tables); every Kerberos value is
//! then decoded strictly by `krb-proto` in [`crate::typed`] — one decoder, no
//! second representation (docs/50 §3.3; docs/questions/Q-225 item 6). The
//! realm and time encodings are recorded in docs/questions/Q-245 item 1.
//!
//! **No request carries the caller's role, and no message carries the
//! operation's `now`.** The role keyd authorizes with comes only from the
//! transport's peer credentials (R50-3) and `now` from the keyd daemon's own
//! clock (R50-5, A-56); the time fields below are ticket facts and template
//! times only (`authtime`, `starttime`, `endtime`, `renew_till`,
//! `armor_authtime`) — never passed to keyd as its `now`. The one role on the
//! wire travels the other way: the `DescribeConfig` reply reports the role
//! keyd resolved for the caller from its peer uid ([`WireConfigDescription`];
//! docs/questions/Q-351, A-87), so that a client can refuse a keyd that does
//! not give it its own role. No request field is ever read as a role.
//!
//! Spec: docs/50 §3.3, §3.4, R50-3, R50-4, R50-5; docs/10 §1-§9; A-56, A-59;
//! docs/questions/Q-351 (A-87).

use crate::channel::{
    reply_kind, request_kind, MAX_ENCTYPES, MAX_GRANT_TARGETS, MAX_REPLY_FIELD, MAX_REQUEST_FIELD,
    MAX_SALT, MAX_SEAL_PADATA, MAX_SECRET,
};
use ipc::{DerBlob, Error, MessageSet, Payload, Reader, Result, Secret, Writer};
use keyd_types::{
    AccountKind, ArmorId, AuthnError, CtxId, DualControlToken, EncTypeId, ExchangeId,
    FastConversation, IssueError, KeyHandle, KeyPurpose, Kvno, PrincipalId, Role, ServiceCtxId,
    TicketPolicy, TOKEN_ID_LENGTH,
};
use krb_proto::{KerberosFlags, TicketFlags};

// ===========================================================================
// Field helpers for keyd's own (non-Kerberos) types.
// ===========================================================================

/// Wire code of a key purpose. Project choice (closed table).
/// Spec: docs/50 §3.3 ("`KeyHandle` = 16 octets `PrincipalId` + `u8`
/// purpose"); docs/10 §1.
const fn purpose_code(purpose: KeyPurpose) -> u8 {
    match purpose {
        KeyPurpose::PrincipalLongterm => 0x01,
        KeyPurpose::Krbtgt => 0x02,
        KeyPurpose::Service => 0x03,
    }
}

/// The key purpose of a wire code, or `None` outside the closed table.
/// Spec: docs/50 §3.3; docs/10 §1.
const fn purpose_from_code(code: u8) -> Option<KeyPurpose> {
    match code {
        0x01 => Some(KeyPurpose::PrincipalLongterm),
        0x02 => Some(KeyPurpose::Krbtgt),
        0x03 => Some(KeyPurpose::Service),
        _ => None,
    }
}

/// `KeyHandle` = `PrincipalId` (16 octets) ‖ purpose (`u8`).
/// Spec: docs/50 §3.3 (keyd types row).
pub(crate) fn write_handle(writer: &mut Writer, handle: &KeyHandle) -> Result<()> {
    writer.write_array(handle.principal.as_bytes())?;
    writer.write_enum(purpose_code(handle.purpose))
}

/// Spec: docs/50 §3.3 (keyd types row).
pub(crate) fn read_handle(reader: &mut Reader<'_>) -> Result<KeyHandle> {
    let principal = PrincipalId::from_bytes(reader.read_array()?);
    let purpose = reader.read_enum(purpose_from_code)?;
    Ok(KeyHandle::new(principal, purpose))
}

/// A one-time token: `TOKEN_ID_LENGTH` octets.
/// Spec: docs/50 §3.3 ("tokens … = `TOKEN_ID_LENGTH` octets").
fn read_token(reader: &mut Reader<'_>) -> Result<[u8; TOKEN_ID_LENGTH]> {
    reader.read_array()
}

/// `EncTypeId` as one octet: its etype number, from keyd-types' closed table
/// (17-20; the same as krb-crypto's, D182 / A-63). Spec: docs/50 §3.3
/// ("enum = `u8` from a closed table"); docs/10 §1 (no weak variant is
/// expressible); RFC 3962 §7; RFC 8009 §7.
fn write_enctype(writer: &mut Writer, enctype: EncTypeId) -> Result<()> {
    let code = u8::try_from(enctype.number()).map_err(|_| Error::UnknownCode)?;
    writer.write_enum(code)
}

/// Spec: docs/50 §3.3; docs/10 §1.
fn read_enctype(reader: &mut Reader<'_>) -> Result<EncTypeId> {
    reader.read_enum(|code| EncTypeId::from_number(i32::from(code)))
}

/// `TicketFlags` as its 32 bits. Every 32-bit value is a KerberosFlags value
/// (RFC 4120 5.2.8: "at least 32 bits"; krb-proto keeps exactly 32); which
/// flags are acceptable is keyd's policy, not the codec's.
/// Spec: docs/50 §3.3 (`u32`); RFC 4120 5.2.8, 5.3.
fn read_flags(reader: &mut Reader<'_>) -> Result<TicketFlags> {
    reader
        .read_u32()
        .map(|bits| TicketFlags(KerberosFlags::from_bits(bits)))
}

/// Spec: docs/50 §3.3; RFC 4120 5.2.8.
fn write_flags(writer: &mut Writer, flags: TicketFlags) -> Result<()> {
    writer.write_u32(flags.0.bits())
}

/// `FastConversation` = which (`u8`: 1 As, 2 Tgs) ‖ its token.
/// Spec: docs/50 §3.4 (`conversation: As(ArmorId) | Tgs(CtxId)`); docs/10
/// §5א.
fn write_conversation(writer: &mut Writer, conversation: &FastConversation) -> Result<()> {
    match conversation {
        FastConversation::As(armor) => {
            writer.write_enum(CONVERSATION_AS)?;
            writer.write_array(armor.as_bytes())
        }
        FastConversation::Tgs(ctx) => {
            writer.write_enum(CONVERSATION_TGS)?;
            writer.write_array(ctx.as_bytes())
        }
    }
}

/// Wire code of `FastConversation::As`. Project choice.
const CONVERSATION_AS: u8 = 0x01;
/// Wire code of `FastConversation::Tgs`. Project choice.
const CONVERSATION_TGS: u8 = 0x02;

/// Spec: docs/50 §3.4; docs/10 §5א.
fn read_conversation(reader: &mut Reader<'_>) -> Result<FastConversation> {
    #[derive(Clone, Copy)]
    enum Which {
        As,
        Tgs,
    }
    let which = reader.read_enum(|code| match code {
        CONVERSATION_AS => Some(Which::As),
        CONVERSATION_TGS => Some(Which::Tgs),
        _ => None,
    })?;
    let token = read_token(reader)?;
    Ok(match which {
        Which::As => FastConversation::As(ArmorId::from_bytes(token)),
        Which::Tgs => FastConversation::Tgs(CtxId::from_bytes(token)),
    })
}

/// A byte string of at most `max` octets, owned.
/// Spec: docs/50 §3.3 (`bytes<max>`).
fn read_owned(reader: &mut Reader<'_>, max: u32) -> Result<Vec<u8>> {
    reader.read_bytes(max).map(<[u8]>::to_vec)
}

// ===========================================================================
// Kerberos-valued field groups (checked by krb-proto in `typed`).
// ===========================================================================

/// A `KerberosTime` as its six calendar fields (UTC). On the wire every
/// combination of values is accepted; `krb_proto::KerberosTime::new` decides
/// which are times (docs/questions/Q-245 item 1).
///
/// Spec: docs/50 §3.3 (Kerberos values decoded by krb-proto); RFC 4120 5.2.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireTime {
    /// Year (0000-9999 when valid).
    pub year: u16,
    /// Month (1-12 when valid).
    pub month: u8,
    /// Day of the month.
    pub day: u8,
    /// Hour (0-23 when valid).
    pub hour: u8,
    /// Minute (0-59 when valid).
    pub minute: u8,
    /// Second (0-59 when valid).
    pub second: u8,
}

impl Payload for WireTime {
    /// Spec: docs/50 §3.3 (fixed-width big-endian integers); RFC 4120 5.2.3.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_u16(self.year)?;
        writer.write_u8(self.month)?;
        writer.write_u8(self.day)?;
        writer.write_u8(self.hour)?;
        writer.write_u8(self.minute)?;
        writer.write_u8(self.second)
    }

    /// Spec: docs/50 §3.3; RFC 4120 5.2.3.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireTime> {
        let year = reader.read_u16()?;
        let month = reader.read_u8()?;
        let day = reader.read_u8()?;
        let hour = reader.read_u8()?;
        let minute = reader.read_u8()?;
        let second = reader.read_u8()?;
        Ok(WireTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
        })
    }
}

/// An optional [`WireTime`]. Spec: docs/50 §3.3 (`Option<T>`).
fn write_opt_time(writer: &mut Writer, time: Option<&WireTime>) -> Result<()> {
    writer.write_option(time, |w, t| t.write_fields(w))
}

/// Spec: docs/50 §3.3.
fn read_opt_time(reader: &mut Reader<'_>) -> Result<Option<WireTime>> {
    reader.read_option(WireTime::read_fields)
}

/// `PrincipalBinding` = realm (KerberosString octets) ‖ name (DER
/// PrincipalName).
/// Spec: docs/50 §3.4 (`binding: { realm, name: DER }`); docs/10 §6, §7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireBinding {
    /// The realm's KerberosString octets.
    pub realm: Vec<u8>,
    /// DER `PrincipalName`.
    pub name: DerBlob,
}

impl Payload for WireBinding {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_bytes(&self.realm, MAX_REQUEST_FIELD)?;
        writer.write_der(&self.name, MAX_REQUEST_FIELD)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireBinding> {
        let realm = read_owned(reader, MAX_REQUEST_FIELD)?;
        let name = reader.read_der(MAX_REQUEST_FIELD)?;
        Ok(WireBinding { realm, name })
    }
}

// ===========================================================================
// Requests.
// ===========================================================================

/// `verify_preauth`. Spec: docs/50 §3.4 (`client: KeyHandle`, `padata: DER`,
/// `armor: Option<ArmorId>`); docs/10 §4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyPreauthRequest {
    /// PrincipalLongterm handle of the client.
    pub client: KeyHandle,
    /// DER `PA-DATA`.
    pub padata: DerBlob,
    /// The FAST armor of an armored request.
    pub armor: Option<ArmorId>,
}

impl Payload for VerifyPreauthRequest {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.client)?;
        writer.write_der(&self.padata, MAX_REQUEST_FIELD)?;
        writer.write_option(self.armor.as_ref(), |w, a| w.write_array(a.as_bytes()))
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<VerifyPreauthRequest> {
        let client = read_handle(reader)?;
        let padata = reader.read_der(MAX_REQUEST_FIELD)?;
        let armor = reader.read_option(|r| read_token(r).map(ArmorId::from_bytes))?;
        Ok(VerifyPreauthRequest {
            client,
            padata,
            armor,
        })
    }
}

/// `AuthnProof` — the success reply of `verify_preauth`, and the proof the
/// KDC hands back to `issue_as_rep`.
/// Spec: docs/50 §3.4 (`AuthnProof { exchange_id, client, authtime }`);
/// docs/10 §4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireAuthnProof {
    /// The one-time exchange token.
    pub exchange_id: ExchangeId,
    /// The pre-authenticated principal.
    pub client: PrincipalId,
    /// Authentication time (a ticket fact, not keyd's `now`).
    pub authtime: WireTime,
}

impl Payload for WireAuthnProof {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_array(self.exchange_id.as_bytes())?;
        writer.write_array(self.client.as_bytes())?;
        self.authtime.write_fields(writer)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireAuthnProof> {
        let exchange_id = ExchangeId::from_bytes(read_token(reader)?);
        let client = PrincipalId::from_bytes(reader.read_array()?);
        let authtime = WireTime::read_fields(reader)?;
        Ok(WireAuthnProof {
            exchange_id,
            client,
            authtime,
        })
    }
}

/// `AsTicketTemplate`.
/// Spec: docs/50 §3.4 (`template: AsTicketTemplate (client, crealm, cname,
/// sname, starttime?, endtime, renew_till?, flags)`); docs/10 §4; keyd
/// `AsTicketTemplate` (session_enctype, nonce).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireAsTemplate {
    /// The client principal.
    pub client: PrincipalId,
    /// Client realm, KerberosString octets.
    pub crealm: Vec<u8>,
    /// DER `PrincipalName` of the client.
    pub cname: DerBlob,
    /// DER `PrincipalName` of the TGS.
    pub sname: DerBlob,
    /// Requested starttime.
    pub starttime: Option<WireTime>,
    /// Expiration time.
    pub endtime: WireTime,
    /// Renew-till.
    pub renew_till: Option<WireTime>,
    /// Requested ticket flags.
    pub flags: TicketFlags,
    /// Session-key encryption type.
    pub session_enctype: EncTypeId,
    /// The AS-REQ nonce.
    pub nonce: u32,
}

impl Payload for WireAsTemplate {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_array(self.client.as_bytes())?;
        writer.write_bytes(&self.crealm, MAX_REQUEST_FIELD)?;
        writer.write_der(&self.cname, MAX_REQUEST_FIELD)?;
        writer.write_der(&self.sname, MAX_REQUEST_FIELD)?;
        write_opt_time(writer, self.starttime.as_ref())?;
        self.endtime.write_fields(writer)?;
        write_opt_time(writer, self.renew_till.as_ref())?;
        write_flags(writer, self.flags)?;
        write_enctype(writer, self.session_enctype)?;
        writer.write_u32(self.nonce)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireAsTemplate> {
        let client = PrincipalId::from_bytes(reader.read_array()?);
        let crealm = read_owned(reader, MAX_REQUEST_FIELD)?;
        let cname = reader.read_der(MAX_REQUEST_FIELD)?;
        let sname = reader.read_der(MAX_REQUEST_FIELD)?;
        let starttime = read_opt_time(reader)?;
        let endtime = WireTime::read_fields(reader)?;
        let renew_till = read_opt_time(reader)?;
        let flags = read_flags(reader)?;
        let session_enctype = read_enctype(reader)?;
        let nonce = reader.read_u32()?;
        Ok(WireAsTemplate {
            client,
            crealm,
            cname,
            sname,
            starttime,
            endtime,
            renew_till,
            flags,
            session_enctype,
            nonce,
        })
    }
}

/// `issue_as_rep`. Spec: docs/50 §3.4 (`client`, `krbtgt`, `proof`, `armor`,
/// `template`); docs/10 §4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueAsRepRequest {
    /// PrincipalLongterm handle of the client.
    pub client: KeyHandle,
    /// Krbtgt handle.
    pub krbtgt: KeyHandle,
    /// The proof `verify_preauth` returned.
    pub proof: WireAuthnProof,
    /// The FAST armor of an armored request.
    pub armor: Option<ArmorId>,
    /// The ticket template.
    pub template: WireAsTemplate,
}

impl Payload for IssueAsRepRequest {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.client)?;
        write_handle(writer, &self.krbtgt)?;
        self.proof.write_fields(writer)?;
        writer.write_option(self.armor.as_ref(), |w, a| w.write_array(a.as_bytes()))?;
        self.template.write_fields(writer)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<IssueAsRepRequest> {
        let client = read_handle(reader)?;
        let krbtgt = read_handle(reader)?;
        let proof = WireAuthnProof::read_fields(reader)?;
        let armor = reader.read_option(|r| read_token(r).map(ArmorId::from_bytes))?;
        let template = WireAsTemplate::read_fields(reader)?;
        Ok(IssueAsRepRequest {
            client,
            krbtgt,
            proof,
            armor,
            template,
        })
    }
}

/// `open_fast_armor`. Spec: docs/50 §3.4 (`krbtgt`, `armored_req: DER`,
/// `outer_req_body: bytes`); docs/10 §5א.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFastArmorRequest {
    /// Krbtgt handle.
    pub krbtgt: KeyHandle,
    /// DER `KrbFastArmoredReq`.
    pub armored_req: DerBlob,
    /// The raw outer KDC-REQ-BODY octets (the req-checksum input; keyd uses
    /// them as they are).
    pub outer_req_body: Vec<u8>,
}

impl Payload for OpenFastArmorRequest {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.krbtgt)?;
        writer.write_der(&self.armored_req, MAX_REQUEST_FIELD)?;
        writer.write_bytes(&self.outer_req_body, MAX_REQUEST_FIELD)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<OpenFastArmorRequest> {
        let krbtgt = read_handle(reader)?;
        let armored_req = reader.read_der(MAX_REQUEST_FIELD)?;
        let outer_req_body = read_owned(reader, MAX_REQUEST_FIELD)?;
        Ok(OpenFastArmorRequest {
            krbtgt,
            armored_req,
            outer_req_body,
        })
    }
}

/// The FAST part of `open_and_verify_tgt`.
/// Spec: docs/50 §3.4 (`fast: Option<{ ap_req_octets: bytes, armored_req:
/// DER }>`); docs/10 §5א (`TgsFastRequest`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireTgsFast {
    /// The raw PA-TGS-REQ padata-value octets (keyd decodes and compares
    /// them).
    pub ap_req_octets: Vec<u8>,
    /// DER `KrbFastArmoredReq`.
    pub armored_req: DerBlob,
}

impl Payload for WireTgsFast {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_bytes(&self.ap_req_octets, MAX_REQUEST_FIELD)?;
        writer.write_der(&self.armored_req, MAX_REQUEST_FIELD)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireTgsFast> {
        let ap_req_octets = read_owned(reader, MAX_REQUEST_FIELD)?;
        let armored_req = reader.read_der(MAX_REQUEST_FIELD)?;
        Ok(WireTgsFast {
            ap_req_octets,
            armored_req,
        })
    }
}

/// `open_and_verify_tgt`. Spec: docs/50 §3.4 (`krbtgt`, `ap_req: DER`,
/// `req_body: bytes`, `fast`); docs/10 §5; A-17.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAndVerifyTgtRequest {
    /// Krbtgt handle.
    pub krbtgt: KeyHandle,
    /// DER `AP-REQ`.
    pub ap_req: DerBlob,
    /// The raw KDC-REQ-BODY octets the authenticator checksum covers (A-17).
    pub req_body: Vec<u8>,
    /// The implicit FAST armor of an armored request.
    pub fast: Option<WireTgsFast>,
}

impl Payload for OpenAndVerifyTgtRequest {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.krbtgt)?;
        writer.write_der(&self.ap_req, MAX_REQUEST_FIELD)?;
        writer.write_bytes(&self.req_body, MAX_REQUEST_FIELD)?;
        writer.write_option(self.fast.as_ref(), |w, f| f.write_fields(w))
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<OpenAndVerifyTgtRequest> {
        let krbtgt = read_handle(reader)?;
        let ap_req = reader.read_der(MAX_REQUEST_FIELD)?;
        let req_body = read_owned(reader, MAX_REQUEST_FIELD)?;
        let fast = reader.read_option(WireTgsFast::read_fields)?;
        Ok(OpenAndVerifyTgtRequest {
            krbtgt,
            ap_req,
            req_body,
            fast,
        })
    }
}

/// `TgsTicketTemplate`.
/// Spec: docs/50 §3.4 (`template: TgsTicketTemplate (sname, starttime?,
/// endtime, renew_till?, flags, session_enctype, nonce)`); docs/10 §5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireTgsTemplate {
    /// DER `PrincipalName` of the service.
    pub sname: DerBlob,
    /// Requested starttime.
    pub starttime: Option<WireTime>,
    /// Expiration time.
    pub endtime: WireTime,
    /// Renew-till.
    pub renew_till: Option<WireTime>,
    /// Requested ticket flags.
    pub flags: TicketFlags,
    /// Session-key encryption type.
    pub session_enctype: EncTypeId,
    /// The TGS-REQ nonce.
    pub nonce: u32,
}

impl Payload for WireTgsTemplate {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_der(&self.sname, MAX_REQUEST_FIELD)?;
        write_opt_time(writer, self.starttime.as_ref())?;
        self.endtime.write_fields(writer)?;
        write_opt_time(writer, self.renew_till.as_ref())?;
        write_flags(writer, self.flags)?;
        write_enctype(writer, self.session_enctype)?;
        writer.write_u32(self.nonce)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireTgsTemplate> {
        let sname = reader.read_der(MAX_REQUEST_FIELD)?;
        let starttime = read_opt_time(reader)?;
        let endtime = WireTime::read_fields(reader)?;
        let renew_till = read_opt_time(reader)?;
        let flags = read_flags(reader)?;
        let session_enctype = read_enctype(reader)?;
        let nonce = reader.read_u32()?;
        Ok(WireTgsTemplate {
            sname,
            starttime,
            endtime,
            renew_till,
            flags,
            session_enctype,
            nonce,
        })
    }
}

/// `issue_tgs_rep`. Spec: docs/50 §3.4 (`service`, `ctx: CtxId`,
/// `template`); docs/10 §5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueTgsRepRequest {
    /// Service (or krbtgt) handle.
    pub service: KeyHandle,
    /// The context `open_and_verify_tgt` returned.
    pub ctx: CtxId,
    /// The ticket template.
    pub template: WireTgsTemplate,
}

impl Payload for IssueTgsRepRequest {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.service)?;
        writer.write_array(self.ctx.as_bytes())?;
        self.template.write_fields(writer)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<IssueTgsRepRequest> {
        let service = read_handle(reader)?;
        let ctx = CtxId::from_bytes(read_token(reader)?);
        let template = WireTgsTemplate::read_fields(reader)?;
        Ok(IssueTgsRepRequest {
            service,
            ctx,
            template,
        })
    }
}

/// `seal_fast_error`. Spec: docs/50 §3.4 (`conversation`, `error: DER`,
/// `padata: seq<DER>`); docs/10 §5א.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealFastErrorRequest {
    /// The armored conversation answered.
    pub conversation: FastConversation,
    /// DER `KRB-ERROR`.
    pub error: DerBlob,
    /// DER `PA-DATA` items.
    pub padata: Vec<DerBlob>,
}

impl Payload for SealFastErrorRequest {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_conversation(writer, &self.conversation)?;
        writer.write_der(&self.error, MAX_REQUEST_FIELD)?;
        writer.write_seq(&self.padata, MAX_SEAL_PADATA, |w, p| {
            w.write_der(p, MAX_REQUEST_FIELD)
        })
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<SealFastErrorRequest> {
        let conversation = read_conversation(reader)?;
        let error = reader.read_der(MAX_REQUEST_FIELD)?;
        let padata = reader.read_seq(MAX_SEAL_PADATA, |r| r.read_der(MAX_REQUEST_FIELD))?;
        Ok(SealFastErrorRequest {
            conversation,
            error,
            padata,
        })
    }
}

/// `open_and_verify_service_ticket`. Spec: docs/50 §3.4 (`service`,
/// `ap_req_octets: bytes`); docs/10 §5ב.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAndVerifyServiceTicketRequest {
    /// Service handle.
    pub service: KeyHandle,
    /// The raw KRB_AP_REQ octets (keyd decodes them itself).
    pub ap_req_octets: Vec<u8>,
}

impl Payload for OpenAndVerifyServiceTicketRequest {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.service)?;
        writer.write_bytes(&self.ap_req_octets, MAX_REQUEST_FIELD)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<OpenAndVerifyServiceTicketRequest> {
        let service = read_handle(reader)?;
        let ap_req_octets = read_owned(reader, MAX_REQUEST_FIELD)?;
        Ok(OpenAndVerifyServiceTicketRequest {
            service,
            ap_req_octets,
        })
    }
}

/// `set_secret`. The password travels only in a zeroizing [`Secret`] whose
/// `Debug` prints nothing (not even its length).
/// Spec: docs/50 §3.3 ("the `SetSecret`/`VerifySecret` body (password) is
/// read into `Zeroizing`"), §3.4 (`handle`, `binding: { realm, name: DER }`,
/// `password: secret bytes<1024>`, `salt: bytes`); docs/10 §6, I7.
#[derive(Debug)]
pub struct SetSecretRequest {
    /// The key set's handle.
    pub handle: KeyHandle,
    /// The principal name the key set is (or becomes) bound to.
    pub binding: WireBinding,
    /// The password.
    pub password: Secret,
    /// The string-to-key salt (UTF-8).
    pub salt: Vec<u8>,
}

impl Payload for SetSecretRequest {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.handle)?;
        self.binding.write_fields(writer)?;
        writer.write_secret(&self.password, MAX_SECRET)?;
        writer.write_bytes(&self.salt, MAX_SALT)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<SetSecretRequest> {
        let handle = read_handle(reader)?;
        let binding = WireBinding::read_fields(reader)?;
        let password = reader.read_secret(MAX_SECRET)?;
        let salt = read_owned(reader, MAX_SALT)?;
        Ok(SetSecretRequest {
            handle,
            binding,
            password,
            salt,
        })
    }
}

/// `verify_secret`. Spec: docs/50 §3.3, §3.4 (`handle`, `candidate: secret
/// bytes<1024>`); docs/10 §6, I6, I7.
#[derive(Debug)]
pub struct VerifySecretRequest {
    /// The key set's handle.
    pub handle: KeyHandle,
    /// The candidate password.
    pub candidate: Secret,
}

impl Payload for VerifySecretRequest {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.handle)?;
        writer.write_secret(&self.candidate, MAX_SECRET)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<VerifySecretRequest> {
        let handle = read_handle(reader)?;
        let candidate = reader.read_secret(MAX_SECRET)?;
        Ok(VerifySecretRequest { handle, candidate })
    }
}

/// `create_key`. Spec: docs/50 §3.4 ("as the signatures in crates/keyd
/// admin.rs": handle, binding); docs/10 §7; A-35.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateKeyRequest {
    /// The new key set's handle.
    pub handle: KeyHandle,
    /// The principal name it is bound to.
    pub binding: WireBinding,
}

impl Payload for CreateKeyRequest {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.handle)?;
        self.binding.write_fields(writer)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<CreateKeyRequest> {
        let handle = read_handle(reader)?;
        let binding = WireBinding::read_fields(reader)?;
        Ok(CreateKeyRequest { handle, binding })
    }
}

/// `rotate_krbtgt`. Spec: docs/50 §3.4 (`krbtgt`, `approval:
/// DualControlToken { approver_1, approver_2 }`); docs/10 §7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotateKrbtgtRequest {
    /// Krbtgt handle.
    pub krbtgt: KeyHandle,
    /// The dual-control approval.
    pub approval: DualControlToken,
}

impl Payload for RotateKrbtgtRequest {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.krbtgt)?;
        writer.write_array(self.approval.approver_1.as_bytes())?;
        writer.write_array(self.approval.approver_2.as_bytes())
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<RotateKrbtgtRequest> {
        let krbtgt = read_handle(reader)?;
        let approver_1 = PrincipalId::from_bytes(reader.read_array()?);
        let approver_2 = PrincipalId::from_bytes(reader.read_array()?);
        Ok(RotateKrbtgtRequest {
            krbtgt,
            approval: DualControlToken {
                approver_1,
                approver_2,
            },
        })
    }
}

/// `retire_kvno`. Spec: docs/50 §3.4 (admin.rs signature: handle, kvno);
/// docs/10 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetireKvnoRequest {
    /// The key set's handle.
    pub handle: KeyHandle,
    /// The key version to retire.
    pub kvno: Kvno,
}

impl Payload for RetireKvnoRequest {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.handle)?;
        writer.write_u32(self.kvno.get())
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<RetireKvnoRequest> {
        let handle = read_handle(reader)?;
        let kvno = Kvno::new(reader.read_u32()?);
        Ok(RetireKvnoRequest { handle, kvno })
    }
}

/// Wire code of a grant's account kind. Project choice (closed table).
/// Spec: docs/50 §3.3 ("enum = `u8` from a closed table"); docs/51 §7.3
/// (`kind` User/Computer).
const fn account_kind_code(kind: AccountKind) -> u8 {
    match kind {
        AccountKind::User => 0x01,
        AccountKind::Computer => 0x02,
    }
}

/// The account kind of a wire code, or `None` outside the closed table.
/// Spec: docs/50 §3.3; docs/51 §7.3.
const fn account_kind_from_code(code: u8) -> Option<AccountKind> {
    match code {
        0x01 => Some(AccountKind::User),
        0x02 => Some(AccountKind::Computer),
        _ => None,
    }
}

/// One key target of `grant_set_secret`: `KeyHandle` ‖ `PrincipalBinding`.
/// Spec: docs/51 §7.3 ("handles (1 or 2), bindings"); docs/questions/Q-450
/// item 9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireSetSecretTarget {
    /// The key set's handle.
    pub handle: KeyHandle,
    /// The principal name the `set_secret` must name.
    pub binding: WireBinding,
}

impl Payload for WireSetSecretTarget {
    /// Spec: docs/questions/Q-450 item 9.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        write_handle(writer, &self.handle)?;
        self.binding.write_fields(writer)
    }

    /// Spec: docs/questions/Q-450 item 9.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireSetSecretTarget> {
        let handle = read_handle(reader)?;
        let binding = WireBinding::read_fields(reader)?;
        Ok(WireSetSecretTarget { handle, binding })
    }
}

/// `grant_set_secret` = kind (`u8`: 1 User, 2 Computer) ‖ targets
/// (`seq<WireSetSecretTarget, MAX_GRANT_TARGETS>`) ‖ lifetime in seconds
/// (`u32`). The lifetime is relative: keyd computes the expiry from its own
/// clock (no time from the peer, R50-5). The codec checks structure only —
/// the count bound and the closed kind table; keyd judges the shape, the
/// purposes and the lifetime, and records its refusal.
/// Spec: docs/51 §5.8 option (b) ("`(handle, binding, expiry)`"); docs/50
/// §3.3, R50-5; docs/questions/Q-389 item 3 (precedent), Q-450 item 9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSetSecretRequest {
    /// The account kind.
    pub kind: AccountKind,
    /// The key targets (1 or 2 for keyd to accept them).
    pub targets: Vec<WireSetSecretTarget>,
    /// How long the grant stays live, in seconds.
    pub lifetime_secs: u32,
}

impl Payload for GrantSetSecretRequest {
    /// Spec: docs/questions/Q-450 item 9.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_enum(account_kind_code(self.kind))?;
        writer.write_seq(&self.targets, MAX_GRANT_TARGETS, |w, t| t.write_fields(w))?;
        writer.write_u32(self.lifetime_secs)
    }

    /// Spec: docs/50 §3.3 (closed tables, bounded counts); docs/questions/
    /// Q-450 item 9.
    fn read_fields(reader: &mut Reader<'_>) -> Result<GrantSetSecretRequest> {
        let kind = reader.read_enum(account_kind_from_code)?;
        let targets = reader.read_seq(MAX_GRANT_TARGETS, WireSetSecretTarget::read_fields)?;
        let lifetime_secs = reader.read_u32()?;
        Ok(GrantSetSecretRequest {
            kind,
            targets,
            lifetime_secs,
        })
    }
}

/// Every request of the keyd channel. There is no field for the caller's
/// role or for `now` in any of them (module docs).
///
/// Spec: docs/50 §3.4 (the keyd channel's request rows; `DescribeConfig`
/// and `Ping` without fields), R50-3, R50-5; docs/10 §2 (roles).
#[derive(Debug)]
pub enum KeydRequest {
    /// Spec: docs/10 §4.
    VerifyPreauth(VerifyPreauthRequest),
    /// Spec: docs/10 §4.
    IssueAsRep(IssueAsRepRequest),
    /// Spec: docs/10 §5א.
    OpenFastArmor(OpenFastArmorRequest),
    /// Spec: docs/10 §5.
    OpenAndVerifyTgt(OpenAndVerifyTgtRequest),
    /// Spec: docs/10 §5.
    IssueTgsRep(IssueTgsRepRequest),
    /// Spec: docs/10 §5א.
    SealFastError(SealFastErrorRequest),
    /// Spec: docs/10 §5ב.
    OpenAndVerifyServiceTicket(OpenAndVerifyServiceTicketRequest),
    /// Spec: docs/10 §6.
    SetSecret(SetSecretRequest),
    /// Spec: docs/10 §6.
    VerifySecret(VerifySecretRequest),
    /// Spec: docs/10 §7.
    CreateKey(CreateKeyRequest),
    /// `rotate_key(handle)`. Spec: docs/10 §7.
    RotateKey(KeyHandle),
    /// Spec: docs/10 §7.
    RotateKrbtgt(RotateKrbtgtRequest),
    /// Spec: docs/10 §7.
    RetireKvno(RetireKvnoRequest),
    /// `destroy_key_set(handle)`. Spec: docs/10 §7; A-35.
    DestroyKeySet(KeyHandle),
    /// No field. Spec: docs/10 §7א.
    DescribeConfig,
    /// No field. Spec: docs/10 §7א.
    Ping,
    /// Spec: docs/51 §5.8 option (b); docs/questions/Q-450.
    GrantSetSecret(GrantSetSecretRequest),
}

impl MessageSet for KeydRequest {
    const KINDS: &'static [u8] = request_kind::ALL;

    /// Spec: docs/50 §3.4.
    fn kind(&self) -> u8 {
        match self {
            KeydRequest::VerifyPreauth(_) => request_kind::VERIFY_PREAUTH,
            KeydRequest::IssueAsRep(_) => request_kind::ISSUE_AS_REP,
            KeydRequest::OpenFastArmor(_) => request_kind::OPEN_FAST_ARMOR,
            KeydRequest::OpenAndVerifyTgt(_) => request_kind::OPEN_AND_VERIFY_TGT,
            KeydRequest::IssueTgsRep(_) => request_kind::ISSUE_TGS_REP,
            KeydRequest::SealFastError(_) => request_kind::SEAL_FAST_ERROR,
            KeydRequest::OpenAndVerifyServiceTicket(_) => {
                request_kind::OPEN_AND_VERIFY_SERVICE_TICKET
            }
            KeydRequest::SetSecret(_) => request_kind::SET_SECRET,
            KeydRequest::VerifySecret(_) => request_kind::VERIFY_SECRET,
            KeydRequest::CreateKey(_) => request_kind::CREATE_KEY,
            KeydRequest::RotateKey(_) => request_kind::ROTATE_KEY,
            KeydRequest::RotateKrbtgt(_) => request_kind::ROTATE_KRBTGT,
            KeydRequest::RetireKvno(_) => request_kind::RETIRE_KVNO,
            KeydRequest::DestroyKeySet(_) => request_kind::DESTROY_KEY_SET,
            KeydRequest::DescribeConfig => request_kind::DESCRIBE_CONFIG,
            KeydRequest::Ping => request_kind::PING,
            KeydRequest::GrantSetSecret(_) => request_kind::GRANT_SET_SECRET,
        }
    }

    /// Spec: docs/50 §3.3, §3.4.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            KeydRequest::VerifyPreauth(m) => m.write_fields(writer),
            KeydRequest::IssueAsRep(m) => m.write_fields(writer),
            KeydRequest::OpenFastArmor(m) => m.write_fields(writer),
            KeydRequest::OpenAndVerifyTgt(m) => m.write_fields(writer),
            KeydRequest::IssueTgsRep(m) => m.write_fields(writer),
            KeydRequest::SealFastError(m) => m.write_fields(writer),
            KeydRequest::OpenAndVerifyServiceTicket(m) => m.write_fields(writer),
            KeydRequest::SetSecret(m) => m.write_fields(writer),
            KeydRequest::VerifySecret(m) => m.write_fields(writer),
            KeydRequest::CreateKey(m) => m.write_fields(writer),
            KeydRequest::RotateKey(handle) | KeydRequest::DestroyKeySet(handle) => {
                write_handle(writer, handle)
            }
            KeydRequest::RotateKrbtgt(m) => m.write_fields(writer),
            KeydRequest::RetireKvno(m) => m.write_fields(writer),
            KeydRequest::DescribeConfig | KeydRequest::Ping => Ok(()),
            KeydRequest::GrantSetSecret(m) => m.write_fields(writer),
        }
    }

    /// Spec: docs/50 §3.3, §3.4.
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<KeydRequest> {
        Ok(match kind {
            request_kind::VERIFY_PREAUTH => {
                KeydRequest::VerifyPreauth(VerifyPreauthRequest::read_fields(reader)?)
            }
            request_kind::ISSUE_AS_REP => {
                KeydRequest::IssueAsRep(IssueAsRepRequest::read_fields(reader)?)
            }
            request_kind::OPEN_FAST_ARMOR => {
                KeydRequest::OpenFastArmor(OpenFastArmorRequest::read_fields(reader)?)
            }
            request_kind::OPEN_AND_VERIFY_TGT => {
                KeydRequest::OpenAndVerifyTgt(OpenAndVerifyTgtRequest::read_fields(reader)?)
            }
            request_kind::ISSUE_TGS_REP => {
                KeydRequest::IssueTgsRep(IssueTgsRepRequest::read_fields(reader)?)
            }
            request_kind::SEAL_FAST_ERROR => {
                KeydRequest::SealFastError(SealFastErrorRequest::read_fields(reader)?)
            }
            request_kind::OPEN_AND_VERIFY_SERVICE_TICKET => {
                KeydRequest::OpenAndVerifyServiceTicket(
                    OpenAndVerifyServiceTicketRequest::read_fields(reader)?,
                )
            }
            request_kind::SET_SECRET => {
                KeydRequest::SetSecret(SetSecretRequest::read_fields(reader)?)
            }
            request_kind::VERIFY_SECRET => {
                KeydRequest::VerifySecret(VerifySecretRequest::read_fields(reader)?)
            }
            request_kind::CREATE_KEY => {
                KeydRequest::CreateKey(CreateKeyRequest::read_fields(reader)?)
            }
            request_kind::ROTATE_KEY => KeydRequest::RotateKey(read_handle(reader)?),
            request_kind::ROTATE_KRBTGT => {
                KeydRequest::RotateKrbtgt(RotateKrbtgtRequest::read_fields(reader)?)
            }
            request_kind::RETIRE_KVNO => {
                KeydRequest::RetireKvno(RetireKvnoRequest::read_fields(reader)?)
            }
            request_kind::DESTROY_KEY_SET => KeydRequest::DestroyKeySet(read_handle(reader)?),
            request_kind::DESCRIBE_CONFIG => KeydRequest::DescribeConfig,
            request_kind::PING => KeydRequest::Ping,
            request_kind::GRANT_SET_SECRET => {
                KeydRequest::GrantSetSecret(GrantSetSecretRequest::read_fields(reader)?)
            }
            _ => return Err(Error::UnknownKind),
        })
    }
}

// ===========================================================================
// Replies.
// ===========================================================================

/// `AsRepParts` / `TgsRepParts`: DER `Ticket`, DER `EncryptedData`, optional
/// DER `EncryptedData` (the enc-fast-rep).
/// Spec: docs/50 §3.4 (`AsRepParts { ticket: DER, enc_part: DER, fast_rep:
/// Option<DER> }`, `TgsRepParts { ticket, enc_part, fast_rep? }`); docs/10
/// §4, §5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireRepParts {
    /// DER `Ticket`.
    pub ticket: DerBlob,
    /// DER `EncryptedData` (the enc-part).
    pub enc_part: DerBlob,
    /// DER `EncryptedData` (the enc-fast-rep), when armored.
    pub fast_rep: Option<DerBlob>,
}

impl Payload for WireRepParts {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_der(&self.ticket, MAX_REPLY_FIELD)?;
        writer.write_der(&self.enc_part, MAX_REPLY_FIELD)?;
        writer.write_option(self.fast_rep.as_ref(), |w, d| {
            w.write_der(d, MAX_REPLY_FIELD)
        })
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireRepParts> {
        let ticket = reader.read_der(MAX_REPLY_FIELD)?;
        let enc_part = reader.read_der(MAX_REPLY_FIELD)?;
        let fast_rep = reader.read_option(|r| r.read_der(MAX_REPLY_FIELD))?;
        Ok(WireRepParts {
            ticket,
            enc_part,
            fast_rep,
        })
    }
}

/// `FastArmor`. Spec: docs/50 §3.4 (`FastArmor { armor_id, armor_crealm,
/// armor_cname, armor_authtime, fast_req: DER }`); docs/10 §5א.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFastArmor {
    /// The one-time armor token.
    pub armor_id: ArmorId,
    /// Armor ticket's client realm, KerberosString octets.
    pub armor_crealm: Vec<u8>,
    /// DER `PrincipalName` of the armor ticket's client.
    pub armor_cname: DerBlob,
    /// Armor ticket's authtime (a ticket fact).
    pub armor_authtime: WireTime,
    /// DER `KrbFastReq`.
    pub fast_req: DerBlob,
}

impl Payload for WireFastArmor {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_array(self.armor_id.as_bytes())?;
        writer.write_bytes(&self.armor_crealm, MAX_REPLY_FIELD)?;
        writer.write_der(&self.armor_cname, MAX_REPLY_FIELD)?;
        self.armor_authtime.write_fields(writer)?;
        writer.write_der(&self.fast_req, MAX_REPLY_FIELD)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireFastArmor> {
        let armor_id = ArmorId::from_bytes(read_token(reader)?);
        let armor_crealm = read_owned(reader, MAX_REPLY_FIELD)?;
        let armor_cname = reader.read_der(MAX_REPLY_FIELD)?;
        let armor_authtime = WireTime::read_fields(reader)?;
        let fast_req = reader.read_der(MAX_REPLY_FIELD)?;
        Ok(WireFastArmor {
            armor_id,
            armor_crealm,
            armor_cname,
            armor_authtime,
            fast_req,
        })
    }
}

/// `TgtContext`. Spec: docs/50 §3.4 (`TgtContext { ctx_id, crealm, cname,
/// authtime, starttime?, endtime, renew_till?, flags, fast_req? }`); docs/10
/// §5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireTgtContext {
    /// The one-time context token.
    pub ctx_id: CtxId,
    /// Client realm, KerberosString octets.
    pub crealm: Vec<u8>,
    /// DER `PrincipalName` of the client.
    pub cname: DerBlob,
    /// TGT authtime.
    pub authtime: WireTime,
    /// TGT starttime.
    pub starttime: Option<WireTime>,
    /// TGT endtime.
    pub endtime: WireTime,
    /// TGT renew-till.
    pub renew_till: Option<WireTime>,
    /// TGT flags.
    pub flags: TicketFlags,
    /// DER `KrbFastReq` of an armored request.
    pub fast_req: Option<DerBlob>,
}

impl Payload for WireTgtContext {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_array(self.ctx_id.as_bytes())?;
        writer.write_bytes(&self.crealm, MAX_REPLY_FIELD)?;
        writer.write_der(&self.cname, MAX_REPLY_FIELD)?;
        self.authtime.write_fields(writer)?;
        write_opt_time(writer, self.starttime.as_ref())?;
        self.endtime.write_fields(writer)?;
        write_opt_time(writer, self.renew_till.as_ref())?;
        write_flags(writer, self.flags)?;
        writer.write_option(self.fast_req.as_ref(), |w, d| {
            w.write_der(d, MAX_REPLY_FIELD)
        })
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireTgtContext> {
        let ctx_id = CtxId::from_bytes(read_token(reader)?);
        let crealm = read_owned(reader, MAX_REPLY_FIELD)?;
        let cname = reader.read_der(MAX_REPLY_FIELD)?;
        let authtime = WireTime::read_fields(reader)?;
        let starttime = read_opt_time(reader)?;
        let endtime = WireTime::read_fields(reader)?;
        let renew_till = read_opt_time(reader)?;
        let flags = read_flags(reader)?;
        let fast_req = reader.read_option(|r| r.read_der(MAX_REPLY_FIELD))?;
        Ok(WireTgtContext {
            ctx_id,
            crealm,
            cname,
            authtime,
            starttime,
            endtime,
            renew_till,
            flags,
            fast_req,
        })
    }
}

/// `ServiceContext`. Spec: docs/50 §3.4 (`ServiceContext { ctx_id, crealm,
/// cname, authtime, endtime, flags, subkey_present }`); docs/10 §5ב.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireServiceContext {
    /// The one-time service-context token.
    pub ctx_id: ServiceCtxId,
    /// Client realm, KerberosString octets.
    pub crealm: Vec<u8>,
    /// DER `PrincipalName` of the client.
    pub cname: DerBlob,
    /// Ticket authtime.
    pub authtime: WireTime,
    /// Ticket endtime.
    pub endtime: WireTime,
    /// Ticket flags.
    pub flags: TicketFlags,
    /// Whether the authenticator offered a subkey.
    pub subkey_present: bool,
}

impl Payload for WireServiceContext {
    /// Spec: docs/50 §3.4.
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_array(self.ctx_id.as_bytes())?;
        writer.write_bytes(&self.crealm, MAX_REPLY_FIELD)?;
        writer.write_der(&self.cname, MAX_REPLY_FIELD)?;
        self.authtime.write_fields(writer)?;
        self.endtime.write_fields(writer)?;
        write_flags(writer, self.flags)?;
        writer.write_bool(self.subkey_present)
    }

    /// Spec: docs/50 §3.4.
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireServiceContext> {
        let ctx_id = ServiceCtxId::from_bytes(read_token(reader)?);
        let crealm = read_owned(reader, MAX_REPLY_FIELD)?;
        let cname = reader.read_der(MAX_REPLY_FIELD)?;
        let authtime = WireTime::read_fields(reader)?;
        let endtime = WireTime::read_fields(reader)?;
        let flags = read_flags(reader)?;
        let subkey_present = reader.read_bool()?;
        Ok(WireServiceContext {
            ctx_id,
            crealm,
            cname,
            authtime,
            endtime,
            flags,
            subkey_present,
        })
    }
}

/// Wire code of the caller's role in the `DescribeConfig` reply. Project
/// choice: a closed table in the order of `keyd_types::Role`; 0x00 and
/// 0x05-0xFF name no role and are refused.
/// Spec: docs/50 §3.3 ("enum = `u8` from a closed table"); docs/10 §2
/// (`enum Role`, the phase-1 variants of keyd-types); docs/questions/Q-351
/// (A-87).
const fn caller_role_code(role: Role) -> u8 {
    match role {
        Role::Kdc => 0x01,
        Role::Directory => 0x02,
        Role::Admin => 0x03,
        Role::Ldap => 0x04,
    }
}

/// The role of a wire code, or `None` outside the closed table.
/// Spec: docs/50 §3.3; docs/10 §2; docs/questions/Q-351 (A-87).
const fn caller_role_from_code(code: u8) -> Option<Role> {
    match code {
        0x01 => Some(Role::Kdc),
        0x02 => Some(Role::Directory),
        0x03 => Some(Role::Admin),
        0x04 => Some(Role::Ldap),
        _ => None,
    }
}

/// The payload of the `DescribeConfig` reply: keyd's `ConfigDescription`,
/// then — the last field — the role keyd resolved for the caller from the
/// connection's peer uid.
///
/// The role is not secret: the caller holds it, and keyd puts it in every
/// audit record (docs/10 §10, `caller_role`). It is reported, never
/// claimed: keyd authorizes with the role its own `uid → Role` map gives the
/// peer (R50-3, docs/50 §3.2), and no request carries one. It lets a client
/// refuse a keyd that maps it to another role that may also call
/// `DescribeConfig` — the kdc's uid mapped to Ldap — before any operation
/// is sent (docs/questions/Q-351, A-87).
///
/// Spec: docs/50 §3.4 (`DescribeConfig`: "realm, enctypes, clock_skew_secs,
/// token_lifetime_secs, ticket_policy"), §3.7; docs/10 §2, §7א
/// (`s2k_params` added, Q-240 item 2); docs/questions/Q-351 (A-87: the reply
/// "carries the caller's Role as keyd resolved it from the peer uid (not
/// secret)").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireConfigDescription {
    /// The realm, KerberosString octets.
    pub realm: Vec<u8>,
    /// The encryption types, in keyd's preference order.
    pub enctypes: Vec<EncTypeId>,
    /// The acceptable clock skew in seconds.
    pub clock_skew_secs: u32,
    /// The one-time token lifetime in seconds.
    pub token_lifetime_secs: u32,
    /// The ticket policy keyd enforces.
    pub ticket_policy: TicketPolicy,
    /// The string-to-key parameters.
    pub s2k_params: Option<[u8; 4]>,
    /// The caller's role, as keyd resolved it from the peer uid.
    /// Spec: docs/questions/Q-351 (A-87).
    pub caller_role: Role,
}

impl Payload for WireConfigDescription {
    /// Spec: docs/50 §3.4; docs/10 §7א; docs/questions/Q-351 (A-87).
    fn write_fields(&self, writer: &mut Writer) -> Result<()> {
        writer.write_bytes(&self.realm, MAX_REPLY_FIELD)?;
        writer.write_seq(&self.enctypes, MAX_ENCTYPES, |w, e| write_enctype(w, *e))?;
        writer.write_u32(self.clock_skew_secs)?;
        writer.write_u32(self.token_lifetime_secs)?;
        write_flags(writer, self.ticket_policy.allowed_flags)?;
        writer.write_u32(self.ticket_policy.min_lifetime_secs)?;
        writer.write_u32(self.ticket_policy.max_lifetime_secs)?;
        writer.write_u32(self.ticket_policy.max_renewable_lifetime_secs)?;
        writer.write_option(self.s2k_params.as_ref(), |w, p| w.write_array(p))?;
        writer.write_enum(caller_role_code(self.caller_role))
    }

    /// Spec: docs/50 §3.3 (closed tables; nothing after the last field),
    /// §3.4; docs/10 §7א; docs/questions/Q-351 (A-87).
    fn read_fields(reader: &mut Reader<'_>) -> Result<WireConfigDescription> {
        let realm = read_owned(reader, MAX_REPLY_FIELD)?;
        let enctypes = reader.read_seq(MAX_ENCTYPES, read_enctype)?;
        let clock_skew_secs = reader.read_u32()?;
        let token_lifetime_secs = reader.read_u32()?;
        let allowed_flags = read_flags(reader)?;
        let min_lifetime_secs = reader.read_u32()?;
        let max_lifetime_secs = reader.read_u32()?;
        let max_renewable_lifetime_secs = reader.read_u32()?;
        let s2k_params = reader.read_option(|r| r.read_array())?;
        let caller_role = reader.read_enum(caller_role_from_code)?;
        Ok(WireConfigDescription {
            realm,
            enctypes,
            clock_skew_secs,
            token_lifetime_secs,
            ticket_policy: TicketPolicy {
                allowed_flags,
                min_lifetime_secs,
                max_lifetime_secs,
                max_renewable_lifetime_secs,
            },
            s2k_params,
            caller_role,
        })
    }
}

/// Wire codes of `keyd_types::AuthnError`, one-to-one (closed table; project
/// choice). Spec: docs/10 §9 (A-26 classes; `Unavailable`, A-56).
const fn authn_error_code(error: AuthnError) -> u8 {
    match error {
        AuthnError::Denied => 0x01,
        AuthnError::TicketExpired => 0x02,
        AuthnError::TicketNotYetValid => 0x03,
        AuthnError::Skew => 0x04,
        AuthnError::Replay => 0x05,
        AuthnError::Unavailable => 0x06,
    }
}

/// Spec: docs/10 §9.
const fn authn_error_from_code(code: u8) -> Option<AuthnError> {
    match code {
        0x01 => Some(AuthnError::Denied),
        0x02 => Some(AuthnError::TicketExpired),
        0x03 => Some(AuthnError::TicketNotYetValid),
        0x04 => Some(AuthnError::Skew),
        0x05 => Some(AuthnError::Replay),
        0x06 => Some(AuthnError::Unavailable),
        _ => None,
    }
}

/// Wire codes of `keyd_types::IssueError`, one-to-one (closed table; project
/// choice). Spec: docs/10 §9.
const fn issue_error_code(error: IssueError) -> u8 {
    match error {
        IssueError::Denied => 0x01,
        IssueError::BadTemplate => 0x02,
        IssueError::Unavailable => 0x03,
    }
}

/// Spec: docs/10 §9.
const fn issue_error_from_code(code: u8) -> Option<IssueError> {
    match code {
        0x01 => Some(IssueError::Denied),
        0x02 => Some(IssueError::BadTemplate),
        0x03 => Some(IssueError::Unavailable),
        _ => None,
    }
}

/// Wire codes of `keyd_types::Error`, one-to-one (closed table; project choice).
/// Spec: docs/10 §9.
const fn error_code(error: keyd_types::Error) -> u8 {
    match error {
        keyd_types::Error::Denied => 0x01,
        keyd_types::Error::Unavailable => 0x02,
        keyd_types::Error::RateLimited => 0x03,
    }
}

/// Spec: docs/10 §9.
const fn error_from_code(code: u8) -> Option<keyd_types::Error> {
    match code {
        0x01 => Some(keyd_types::Error::Denied),
        0x02 => Some(keyd_types::Error::Unavailable),
        0x03 => Some(keyd_types::Error::RateLimited),
        _ => None,
    }
}

/// Every reply of the keyd channel (the shared transport refusal travels
/// separately, with `ipc::REFUSED_KIND`).
///
/// keyd's refusals are carried exactly as keyd classified them — the A-26
/// classes and `Unavailable` included; the codec does not "improve" them
/// (docs/50 §3.3, errors row).
///
/// Spec: docs/50 §3.3, §3.4; docs/10 §9; A-26; A-56; A-59.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeydReply {
    /// Spec: docs/10 §4.
    VerifyPreauth(WireAuthnProof),
    /// Spec: docs/10 §4.
    IssueAsRep(WireRepParts),
    /// Spec: docs/10 §5א.
    OpenFastArmor(WireFastArmor),
    /// Spec: docs/10 §5.
    OpenAndVerifyTgt(WireTgtContext),
    /// Spec: docs/10 §5.
    IssueTgsRep(WireRepParts),
    /// DER `EncryptedData`. Spec: docs/10 §5א.
    SealFastError(DerBlob),
    /// Spec: docs/10 §5ב.
    OpenAndVerifyServiceTicket(WireServiceContext),
    /// Spec: docs/10 §6.
    SetSecret(Kvno),
    /// Spec: docs/10 §6.
    VerifySecret,
    /// Spec: docs/10 §7.
    CreateKey(Kvno),
    /// Spec: docs/10 §7.
    RotateKey(Kvno),
    /// Spec: docs/10 §7.
    RotateKrbtgt(Kvno),
    /// Spec: docs/10 §7.
    RetireKvno,
    /// Spec: docs/10 §7.
    DestroyKeySet,
    /// keyd's description and the caller's role.
    /// Spec: docs/10 §7א; docs/questions/Q-351 (A-87).
    DescribeConfig(WireConfigDescription),
    /// Spec: docs/10 §7א.
    Ping,
    /// The grant is registered. Spec: docs/51 §5.8 option (b);
    /// docs/questions/Q-450.
    GrantSetSecret,
    /// Spec: docs/10 §9; A-26; A-56.
    AuthnFailure(AuthnError),
    /// Spec: docs/10 §9; A-56.
    IssueFailure(IssueError),
    /// Spec: docs/10 §9.
    Failure(keyd_types::Error),
}

impl MessageSet for KeydReply {
    const KINDS: &'static [u8] = reply_kind::ALL;

    /// Spec: docs/50 §3.4.
    fn kind(&self) -> u8 {
        match self {
            KeydReply::VerifyPreauth(_) => reply_kind::VERIFY_PREAUTH,
            KeydReply::IssueAsRep(_) => reply_kind::ISSUE_AS_REP,
            KeydReply::OpenFastArmor(_) => reply_kind::OPEN_FAST_ARMOR,
            KeydReply::OpenAndVerifyTgt(_) => reply_kind::OPEN_AND_VERIFY_TGT,
            KeydReply::IssueTgsRep(_) => reply_kind::ISSUE_TGS_REP,
            KeydReply::SealFastError(_) => reply_kind::SEAL_FAST_ERROR,
            KeydReply::OpenAndVerifyServiceTicket(_) => reply_kind::OPEN_AND_VERIFY_SERVICE_TICKET,
            KeydReply::SetSecret(_) => reply_kind::SET_SECRET,
            KeydReply::VerifySecret => reply_kind::VERIFY_SECRET,
            KeydReply::CreateKey(_) => reply_kind::CREATE_KEY,
            KeydReply::RotateKey(_) => reply_kind::ROTATE_KEY,
            KeydReply::RotateKrbtgt(_) => reply_kind::ROTATE_KRBTGT,
            KeydReply::RetireKvno => reply_kind::RETIRE_KVNO,
            KeydReply::DestroyKeySet => reply_kind::DESTROY_KEY_SET,
            KeydReply::DescribeConfig(_) => reply_kind::DESCRIBE_CONFIG,
            KeydReply::Ping => reply_kind::PING,
            KeydReply::GrantSetSecret => reply_kind::GRANT_SET_SECRET,
            KeydReply::AuthnFailure(_) => reply_kind::AUTHN_FAILURE,
            KeydReply::IssueFailure(_) => reply_kind::ISSUE_FAILURE,
            KeydReply::Failure(_) => reply_kind::FAILURE,
        }
    }

    /// Spec: docs/50 §3.3, §3.4.
    fn write_payload(&self, writer: &mut Writer) -> Result<()> {
        match self {
            KeydReply::VerifyPreauth(m) => m.write_fields(writer),
            KeydReply::IssueAsRep(m) | KeydReply::IssueTgsRep(m) => m.write_fields(writer),
            KeydReply::OpenFastArmor(m) => m.write_fields(writer),
            KeydReply::OpenAndVerifyTgt(m) => m.write_fields(writer),
            KeydReply::SealFastError(der) => writer.write_der(der, MAX_REPLY_FIELD),
            KeydReply::OpenAndVerifyServiceTicket(m) => m.write_fields(writer),
            KeydReply::SetSecret(kvno)
            | KeydReply::CreateKey(kvno)
            | KeydReply::RotateKey(kvno)
            | KeydReply::RotateKrbtgt(kvno) => writer.write_u32(kvno.get()),
            KeydReply::VerifySecret
            | KeydReply::RetireKvno
            | KeydReply::DestroyKeySet
            | KeydReply::Ping
            | KeydReply::GrantSetSecret => Ok(()),
            KeydReply::DescribeConfig(m) => m.write_fields(writer),
            KeydReply::AuthnFailure(e) => writer.write_enum(authn_error_code(*e)),
            KeydReply::IssueFailure(e) => writer.write_enum(issue_error_code(*e)),
            KeydReply::Failure(e) => writer.write_enum(error_code(*e)),
        }
    }

    /// Spec: docs/50 §3.3 ("replies are decoded with the same strictness"),
    /// §3.4.
    fn read_payload(kind: u8, reader: &mut Reader<'_>) -> Result<KeydReply> {
        Ok(match kind {
            reply_kind::VERIFY_PREAUTH => {
                KeydReply::VerifyPreauth(WireAuthnProof::read_fields(reader)?)
            }
            reply_kind::ISSUE_AS_REP => KeydReply::IssueAsRep(WireRepParts::read_fields(reader)?),
            reply_kind::OPEN_FAST_ARMOR => {
                KeydReply::OpenFastArmor(WireFastArmor::read_fields(reader)?)
            }
            reply_kind::OPEN_AND_VERIFY_TGT => {
                KeydReply::OpenAndVerifyTgt(WireTgtContext::read_fields(reader)?)
            }
            reply_kind::ISSUE_TGS_REP => KeydReply::IssueTgsRep(WireRepParts::read_fields(reader)?),
            reply_kind::SEAL_FAST_ERROR => {
                KeydReply::SealFastError(reader.read_der(MAX_REPLY_FIELD)?)
            }
            reply_kind::OPEN_AND_VERIFY_SERVICE_TICKET => {
                KeydReply::OpenAndVerifyServiceTicket(WireServiceContext::read_fields(reader)?)
            }
            reply_kind::SET_SECRET => KeydReply::SetSecret(Kvno::new(reader.read_u32()?)),
            reply_kind::VERIFY_SECRET => KeydReply::VerifySecret,
            reply_kind::CREATE_KEY => KeydReply::CreateKey(Kvno::new(reader.read_u32()?)),
            reply_kind::ROTATE_KEY => KeydReply::RotateKey(Kvno::new(reader.read_u32()?)),
            reply_kind::ROTATE_KRBTGT => KeydReply::RotateKrbtgt(Kvno::new(reader.read_u32()?)),
            reply_kind::RETIRE_KVNO => KeydReply::RetireKvno,
            reply_kind::DESTROY_KEY_SET => KeydReply::DestroyKeySet,
            reply_kind::DESCRIBE_CONFIG => {
                KeydReply::DescribeConfig(WireConfigDescription::read_fields(reader)?)
            }
            reply_kind::PING => KeydReply::Ping,
            reply_kind::GRANT_SET_SECRET => KeydReply::GrantSetSecret,
            reply_kind::AUTHN_FAILURE => {
                KeydReply::AuthnFailure(reader.read_enum(authn_error_from_code)?)
            }
            reply_kind::ISSUE_FAILURE => {
                KeydReply::IssueFailure(reader.read_enum(issue_error_from_code)?)
            }
            reply_kind::FAILURE => KeydReply::Failure(reader.read_enum(error_from_code)?),
            _ => return Err(Error::UnknownKind),
        })
    }
}

// Definition-site check that both tables leave out the reserved kind (A-59).
const _: () = assert!(ipc::kinds_exclude_refused(KeydRequest::KINDS));
const _: () = assert!(ipc::kinds_exclude_refused(KeydReply::KINDS));
