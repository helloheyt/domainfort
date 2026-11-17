//! Why a name has no key. No variant carries the name itself: an error is
//! never an oracle and never echoes input (docs/CLEAN-ROOM.md; the style of
//! crates/directory-pip `error.rs`).
//!
//! Spec: docs/CLEAN-ROOM.md (fail closed); docs/59 §4.2 ("refusal (not
//! correction)"), §4.4.

/// A stored name, or the realm's DNS name, that the namespace refuses
/// (docs/59 §4.4: refusal, not correction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NameRefused {
    /// A name (or a component of one) is empty. Spec: docs/59 §4.2; Q-1007
    /// item 5.
    Empty,
    /// A name holds an octet that is not printable ASCII. Spec: Q-080 item 1
    /// (P-6, P-9); docs/59 §2.
    NotPrintable,
    /// A name is longer than `MAX_KEY_OCTETS`. Spec: Q-1008 item 2.
    TooLong,
    /// A "/" or "@" where the name's kind has none: inside a component, in a
    /// sAMAccountName, a UPN's local part, a dNSHostName, or anywhere in an
    /// SPN. Spec: docs/59 §4.2 (injectivity), §4.4 N2-N4; Q-1007 item 5;
    /// [MS-SAMR] 3.1.1.6 item 10.
    Separator,
    /// The final "$" rule: a computer's sAMAccountName must end with a single
    /// "$" and every other sAMAccountName must not end with "$".
    /// Spec: [MS-SAMR] 3.1.1.6 item 11; docs/59 §4.4 N2; Q-355 item 2.
    ComputerSuffix,
    /// A userPrincipalName without exactly one "@", or whose local part ends
    /// with "$". Spec: docs/59 §4.4 N3.
    UpnForm,
    /// A userPrincipalName whose suffix is not a realm alias. Spec: docs/59
    /// §4.4 N3; Q-1007 item 3; Q-1012 (P-84).
    UpnSuffix,
    /// A servicePrincipalName that is not two parts (phase 1) or whose host
    /// part carries an ":instancename". Spec: [MS-ADTS] 2.2.21,
    /// 3.1.1.5.3.1.1.4; docs/59 §4.4 N4.
    SpnForm,
    /// More servicePrincipalName values than `MAX_SERVICE_PRINCIPAL_NAMES`.
    /// Spec: R47-13; Q-1008 item 2.
    TooManyServicePrincipalNames,
    /// A name reserved for the ticket-granting service — an initial
    /// component "krbtgt" on any object but the krbtgt account, a krbtgt
    /// account whose sAMAccountName is not "krbtgt", a key equal to a realm
    /// alias on any object but the krbtgt account, or a realm alias that is
    /// itself "krbtgt". Spec: RFC 4120 §6.2, §7.3; [MS-SAMR] 3.1.1.6 item 14;
    /// docs/59 §4.4 N4, N5.
    Reserved,
    /// A name of a kind the object's class does not carry (a group's UPN, a
    /// user's SPN, the krbtgt account's dNSHostName, …).
    /// Spec: docs/59 §4.1, §4.3.
    NotForClass,
    /// The realm's DNS name is not a domain-style realm name usable as an
    /// alias. Spec: RFC 4120 §6.1; docs/59 §4.2 (`NameContext`).
    RealmName,
}

impl core::fmt::Display for NameRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            NameRefused::Empty => "a name or a component of one is empty",
            NameRefused::NotPrintable => "a name is not printable ASCII",
            NameRefused::TooLong => "a name is too long",
            NameRefused::Separator => "a name holds a separator its kind does not allow",
            NameRefused::ComputerSuffix => "the final \"$\" rule of sAMAccountName is broken",
            NameRefused::UpnForm => "a userPrincipalName is malformed",
            NameRefused::UpnSuffix => "a userPrincipalName suffix is not a realm alias",
            NameRefused::SpnForm => "a servicePrincipalName is malformed",
            NameRefused::TooManyServicePrincipalNames => "too many servicePrincipalName values",
            NameRefused::Reserved => "a name is reserved for the ticket-granting service",
            NameRefused::NotForClass => "a name of a kind the object's class does not carry",
            NameRefused::RealmName => "the realm's DNS name is not a valid realm alias",
        })
    }
}

impl std::error::Error for NameRefused {}
