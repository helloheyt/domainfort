//! The conversion from the KDC's audit event (crates/kdc `AuditEvent`) to
//! its wire shape on the audit channel (`ipc_audit::KdcEvent`).
//!
//! # Why here (task IB1)
//!
//! Until task IB1 this was `From<&kdc::AuditEvent> for KdcEvent` in crate
//! ipc-audit, behind its feature `kdc`, which made kdc, pdp and krb-proto
//! optional dependencies of ipc-audit. Cargo unifies features within one
//! build, so in a shared build the other daemons' features (`keyd`, `ldap`)
//! reached this one and linked keyd, krb-crypto, dirstore and redb into the
//! kdc process (class C40; docs/questions/Q-851, decision A-144). Now no
//! manifest declares an `optional` dependency and the conversion lives on
//! the side that already links kdc, pdp and krb-proto: this daemon. Both
//! types are foreign here, so the Rust orphan rule allows no `From` impl:
//! it is the plain function [`kdc_event`].
//!
//! Every field of the source type is carried; none of them is secret (the
//! KDC's event was built without any field that could hold one — crates/kdc
//! audit.rs). Client strings pass the `ipc_audit::AuditText` rule again on
//! the way. Enumerations map variant to same-named table entry (`Source::X
//! => Table::X`), so a misspelled or renamed variant fails to compile; a
//! variant added to a `#[non_exhaustive]` source enumeration later maps to
//! `Unlisted` until its table entry is added (crates/ipc-audit codes.rs).
//!
//! Moved unchanged from crates/ipc-audit `convert.rs` (this project's own
//! code, task P6), written there only from docs/50 §8.1, §8.2, docs/37 §2,
//! docs/questions/Q-252 items 3, 4 and the public API of crates/kdc (audit,
//! accounts, transport), crates/pdp (model) and crates/krb-proto (basic).
//! No other implementation was consulted or recalled (docs/CLEAN-ROOM.md).
//!
//! Spec: docs/50 §8.1, §8.2; docs/37 §2; docs/questions/Q-252 items 3, 4.
//! Decision: A-144; Q-851.

use ipc_audit::{
    AuditText, CalendarTime, KdcEvent, KdcExchange, KdcOutcome, KdcReason, KdcTransport, PdpReason,
    PdpReasonCode, Principal,
};

/// Map the unit variants of a source enum to the same-named variants of a
/// code table, then any further arms.
macro_rules! map_units {
    ($value:expr, $src:ident => $dst:ident { $($variant:ident),* $(,)? } $($rest:tt)*) => {
        match $value {
            $( $src::$variant => $dst::$variant, )*
            $($rest)*
        }
    };
}

/// `krb_proto::KerberosTime` → [`CalendarTime`].
fn calendar_time(time: &krb_proto::KerberosTime) -> CalendarTime {
    // KerberosTime holds only validated calendar fields (crates/krb-proto
    // basic.rs: year ≤ 9999, month 1-12, day within the month, hour 0-23,
    // minute 0-59, second 0-59), so the ranges always hold; the fallback is
    // unreachable and only avoids a panic path.
    CalendarTime::new(
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
    )
    .unwrap_or(CalendarTime::EPOCH)
}

/// `pdp::ReasonCode` → [`PdpReason`]. Spec: crates/pdp model.rs.
fn pdp_reason(code: &pdp::ReasonCode) -> PdpReason {
    use pdp::ReasonCode as Src;
    let mut rule = None;
    let code = map_units!(code, Src => PdpReasonCode {
        Allowed, InvalidRequest, Unauthenticated, WeakTransport, PipFailure,
        SubjectMismatch, NoGrant, TierViolation, Acl, NoSuchPath, Sensitive,
    }
        Src::CoarseDeny(id) => {
            rule = Some(id.0);
            PdpReasonCode::CoarseDeny
        }
    );
    PdpReason { code, rule }
}

/// `kdc::NamedPrincipal` → [`Principal`] (each string by the [`AuditText`]
/// rule). Spec: crates/kdc accounts.rs; docs/50 §8.2.
fn principal(named: &kdc::NamedPrincipal) -> Principal {
    Principal::new(
        AuditText::from_client(named.realm.as_str()),
        named.name.name_type,
        named
            .name
            .name_string
            .iter()
            .map(|component| AuditText::from_client(component.as_str()))
            .collect(),
    )
}

fn reason(reason: &kdc::AuditReason) -> KdcReason {
    use kdc::AuditReason as Src;
    map_units!(reason, Src => KdcReason {
        Issued, Retransmission, ReplyTooBigForUdp, RequestTooLong, ReservedLengthBit,
        UnsupportedMessageType, BadProtocolVersion, Malformed, CrossRealm, MissingName,
        AsServerNotTgs, TgsForTgs, UnsupportedOption, UnsupportedContent, CannotPostdate,
        NeverValid, ClientUnknown, ServiceUnknown, ClientRevoked, TgtRevoked,
        ServiceRevoked, AccountSourceFailure, AccountSourceUnavailable, CustodyUnavailable,
        AccountRecordInvalid, NoCommonEncType, PreauthRequired, PreauthAmbiguous,
        PreauthUnacceptable, PreauthDenied, PreauthSkew, TgsPadataMissing,
        TgsPadataAmbiguous, ApReqMalformed, NotLocalTgt, TgtDenied, TgtExpired,
        TgtNotYetValid, AuthenticatorSkew, AuthenticatorReplay, RateLimited,
        UnsupportedObligation, AmbiguousServiceName, ClockOutOfRange, IssueDenied,
        TemplateRejected, InternalFailure, FastRequired, FastPadataAmbiguous,
        FastMalformed, FastArmorMissing, FastArmorTypeUnsupported, TgsExplicitArmor,
        ArmorDenied, ArmorSkew, ArmorNotYetValid, ArmorExpired, ArmorReplay,
        ArmorPrincipalUnknown, ArmorNotComputer, ArmorPrincipalRevoked,
        UnknownCriticalFastOption, CookieMismatch, FastContextMissing,
    }
        Src::PolicyDenied(_) => KdcReason::PolicyDenied,
        _ => KdcReason::Unlisted,
    )
}

/// The KDC's audit event → [`KdcEvent`]: every field of the KDC's event.
/// The former `KdcEvent::from(&event)` of crate ipc-audit (feature `kdc`),
/// unchanged.
///
/// Spec: crates/kdc audit.rs; docs/50 §8.1. Decision: A-144; Q-851.
#[must_use]
pub fn kdc_event(event: &kdc::AuditEvent) -> KdcEvent {
    use kdc::{AuditOutcome, Exchange, Transport};
    let policy_reason = match &event.reason {
        kdc::AuditReason::PolicyDenied(code) => Some(pdp_reason(code)),
        _ => None,
    };
    KdcEvent {
        time: calendar_time(&event.time),
        transport: map_units!(&event.transport, Transport => KdcTransport { Udp, Tcp }),
        exchange: event
            .exchange
            .as_ref()
            .map(|exchange| map_units!(exchange, Exchange => KdcExchange { As, Tgs })),
        client: event.client.as_ref().map(principal),
        service: event.service.as_ref().map(principal),
        armor_principal: event.armor.principal.as_ref().map(principal),
        reply_armored: event.armor.reply_armored,
        outcome: match event.outcome {
            AuditOutcome::Issued => KdcOutcome::Issued,
            AuditOutcome::Refused { error_code } => KdcOutcome::Refused { error_code },
            AuditOutcome::Dropped => KdcOutcome::Dropped,
        },
        reason: reason(&event.reason),
        policy_reason,
    }
}
