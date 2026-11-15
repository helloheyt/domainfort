//! The namespace's key: the one fold, the key type, and the kinds of name a
//! key carries as metadata.
//!
//! # The fold
//!
//! A name is a key's source only if every octet is printable ASCII,
//! `0x20..=0x7E`; `A`-`Z` fold to `a`-`z` and every other octet is kept
//! (Q-080 items 1-2, the interim rule A-29 / P-9 adopted until
//! [MS-UCODEREF] is an allowed source). [MS-KILE] 3.1.5.7: "Name
//! comparisons, whether for users or domains, MUST NOT be case sensitive in
//! KILE." A name with any other octet has no key: it is refused on the
//! write path and "no such principal" on the lookup path (docs/59 §2, P-6 /
//! P-9).
//!
//! This is the namespace's definition. `dirstore`'s comparison key is a
//! second definition of the same rule, kept because dirstore is a leaf that
//! must not depend on a Kerberos-name crate; the two are pinned equal on
//! all 95 printable octets by a test in crates/directory-pip (Q-1008 item 4,
//! decided A-173; docs/59 §9 S1).
//!
//! # The key
//!
//! A [`PrincipalKey`] is built only here, from one to
//! [`MAX_KEY_COMPONENTS`] components, each non-empty, printable, without
//! "/" and without "@", folded and joined with "/", at most
//! [`MAX_KEY_OCTETS`] octets. So by construction a key never contains "@",
//! "/" only separates non-empty components, and joining cannot produce one
//! key from two component lists that differ after the fold (docs/59 §4.2
//! "injectivity"; RFC 4120 §6.2: "Ignoring the name type, no two names can
//! be the same"; Q-1007 item 5).
//!
//! # The kinds
//!
//! The kind of a name ([`NameKind`]) is not part of the key: one key space
//! holds every kind, and the kinds are re-derived from the object after the
//! one probe (docs/59 §4.1; Q-1007 item 1; RFC 4120 §6.2: "The name type
//! does not partition the name space"). One key of one object may carry
//! several kinds ([`KindSet`]; Q-1007 item 4).
//!
//! Spec: docs/59 §4.1, §4.2, §4.5; Q-080 items 1-2; Q-1007 items 1, 4, 5;
//! Q-1008 items 2, 4; [MS-KILE] 3.1.5.7; [MS-ADTS] 2.2.21; RFC 4120 §6.2.

use crate::error::NameRefused;

/// The most octets of one key (and so of any name that is a key's source).
/// Spec: docs/59 §4.6; Q-1008 item 2 (decided A-173: "a value ≤ 2048
/// octets" — dNSHostName's bound, docs/46 §5.4).
pub const MAX_KEY_OCTETS: usize = 2048;

/// The most components of a key: an SPN "consists of either two parts or
/// three parts" ([MS-ADTS] 2.2.21); every other kind is one component.
/// Spec: [MS-ADTS] 2.2.21; docs/59 §4.2.
pub const MAX_KEY_COMPONENTS: usize = 3;

/// The separator of an SPN's parts in its single-string form, and of the
/// components a multi-component request is joined with. Spec: [MS-ADTS]
/// 2.2.21 ("each separated by a forward slash ("/")"); [MS-KILE] 3.1.5.11
/// (`serviceclass "/" hostname`), 3.3.5.1.1 (`KerberosString[0] + "/" + …`).
pub(crate) const COMPONENT_SEPARATOR: char = '/';

/// The separator of a userPrincipalName's local part and suffix. Spec:
/// [MS-KILE] 3.3.5.6.1 (NT-ENTERPRISE: "the contents of cname before the @
/// character", "after the @ character"); [MS-DRSR] 4.1.4.2.22 ("the
/// component before the '@'").
pub(crate) const UPN_SEPARATOR: char = '@';

/// The fold of one octet: `Some` of its lower-case form for a printable
/// ASCII octet (`A`-`Z` → `a`-`z`, every other printable octet kept),
/// `None` for any other octet. Every comparison of names in this crate goes
/// through this one function.
/// Spec: Q-080 items 1-2 (A-29, P-9); [MS-KILE] 3.1.5.7.
pub(crate) const fn fold_octet(octet: u8) -> Option<u8> {
    match octet {
        0x20..=0x7E => Some(octet.to_ascii_lowercase()),
        _ => None,
    }
}

/// `true` if the already folded `folded` equals the fold of `name`, octet
/// for octet (no allocation). Spec: Q-080 item 2; [MS-KILE] 3.1.5.7.
pub(crate) fn folded_eq(folded: &str, name: &str) -> bool {
    folded.len() == name.len()
        && folded
            .bytes()
            .zip(name.bytes())
            .all(|(f, n)| fold_octet(n) == Some(f))
}

/// The namespace fold of `name` (module documentation): `None` if `name` is
/// empty, longer than [`MAX_KEY_OCTETS`], or holds an octet that is not
/// printable ASCII. The result is a comparison form only; keys are built by
/// `key_of_request` and `keys_of_names`, which apply the separator rules too.
/// Spec: Q-080 items 1-2; [MS-KILE] 3.1.5.7; Q-1008 item 2.
#[must_use]
pub fn fold(name: &str) -> Option<String> {
    if name.is_empty() || name.len() > MAX_KEY_OCTETS {
        return None;
    }
    name.bytes()
        .map(|octet| fold_octet(octet).map(char::from))
        .collect()
}

/// One key of the principal namespace (module documentation): the folded
/// components of a name joined with "/". Names are not secrets (docs/59
/// §4.6), so the key may be shown in `Debug`.
/// Spec: docs/59 §4.1, §4.2; Q-1007 items 1, 5.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalKey(String);

impl PrincipalKey {
    /// The key of `components` (module documentation, "The key"), or why
    /// there is none. The total length is checked before anything is
    /// allocated (AGENTS.md §6: no allocation from an unchecked length).
    /// Spec: docs/59 §4.2; [MS-ADTS] 2.2.21; RFC 4120 §6.2; Q-080; Q-1007
    /// item 5; Q-1008 item 2.
    pub(crate) fn of_components(components: &[&str]) -> Result<PrincipalKey, NameRefused> {
        if components.is_empty() {
            return Err(NameRefused::Empty);
        }
        if components.len() > MAX_KEY_COMPONENTS {
            return Err(NameRefused::SpnForm);
        }
        let separators = components.len() - 1;
        let total = components
            .iter()
            .try_fold(separators, |sum, part| sum.checked_add(part.len()))
            .ok_or(NameRefused::TooLong)?;
        if total > MAX_KEY_OCTETS {
            return Err(NameRefused::TooLong);
        }
        let mut key = String::with_capacity(total);
        for (i, part) in components.iter().enumerate() {
            if part.is_empty() {
                return Err(NameRefused::Empty);
            }
            if i > 0 {
                key.push(COMPONENT_SEPARATOR);
            }
            for octet in part.bytes() {
                let folded = fold_octet(octet).ok_or(NameRefused::NotPrintable)?;
                let folded = char::from(folded);
                if folded == COMPONENT_SEPARATOR || folded == UPN_SEPARATOR {
                    return Err(NameRefused::Separator);
                }
                key.push(folded);
            }
        }
        Ok(PrincipalKey(key))
    }

    /// The key as text (printable ASCII, lower case).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The key's octets: the value the namespace attribute stores
    /// (`PRINCIPAL_NAME_KEY`, an OctetString — docs/59 §4.6).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The key's first component (the whole key when it has one).
    /// Spec: RFC 4120 §6.2 ("an initial component"); docs/59 §4.2.
    pub(crate) fn first_component(&self) -> &str {
        self.0
            .split(COMPONENT_SEPARATOR)
            .next()
            .unwrap_or(self.0.as_str())
    }

    /// The key's components, in order.
    pub(crate) fn components(&self) -> core::str::Split<'_, char> {
        self.0.split(COMPONENT_SEPARATOR)
    }
}

/// The kind of a principal name — metadata of a key, never part of it.
/// Spec: docs/59 §4.1 (the table); Q-1007 items 1, 2, 7, 8, 9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameKind {
    /// The sAMAccountName of a user, computer or group (`fold(sam)`).
    /// Spec: [MS-SAMR] 3.1.1.8.4 item 2; docs/59 §4.1.
    SamAccountName,
    /// A computer's sAMAccountName without its final "$" (`fold(base)`): the
    /// name [MS-KILE] 3.3.5.6.1 step 2 reaches by appending "$".
    /// Spec: [MS-KILE] 3.3.5.6.1; [MS-ADTS] 3.1.1.5.3.1.1.2 ("without the
    /// final "$" character"); docs/59 §4.1.
    ComputerBase,
    /// The local part of a userPrincipalName whose suffix is a realm alias
    /// (`fold(local)`). Spec: [MS-KILE] 3.3.5.6.1 (NT-PRINCIPAL step 3,
    /// NT-ENTERPRISE steps 4-5); Q-1007 item 2; docs/59 §4.1.
    UpnLocal,
    /// A servicePrincipalName (`fold(c0 "/" c1 ["/" c2])`).
    /// Spec: [MS-ADTS] 2.2.21; [MS-KILE] 3.1.5.11; docs/59 §4.1.
    ServicePrincipalName,
    /// A computer's dNSHostName (`fold(host)`); no lookup context accepts it.
    /// Spec: docs/59 §4.1, §6.2; Q-1007 item 8; Q-1010 items 1-3.
    HostName,
    /// A realm alias, held by the krbtgt account only; no lookup context
    /// accepts it. Spec: docs/59 §4.1, §4.4 N5; Q-1007 item 9; RFC 4120 §7.3.
    RealmAlias,
}

impl NameKind {
    /// Every kind, in declaration order.
    pub const ALL: [NameKind; 6] = [
        NameKind::SamAccountName,
        NameKind::ComputerBase,
        NameKind::UpnLocal,
        NameKind::ServicePrincipalName,
        NameKind::HostName,
        NameKind::RealmAlias,
    ];

    /// The kind's bit in a [`KindSet`].
    const fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// A set of [`NameKind`]s: the kinds one key of one object carries (Q-1007
/// item 4), or the kinds a lookup context accepts (docs/59 §6.2).
/// Spec: docs/59 §4.1, §4.7 (`matched: KindSet`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct KindSet(u8);

impl KindSet {
    /// The empty set.
    pub const EMPTY: KindSet = KindSet(0);

    /// This set with `kind` added.
    #[must_use]
    pub const fn with(self, kind: NameKind) -> KindSet {
        KindSet(self.0 | kind.bit())
    }

    /// `true` if `kind` is in the set.
    #[must_use]
    pub const fn contains(self, kind: NameKind) -> bool {
        self.0 & kind.bit() != 0
    }

    /// `true` if the set has no kind.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The kinds in both sets.
    #[must_use]
    pub const fn intersection(self, other: KindSet) -> KindSet {
        KindSet(self.0 & other.0)
    }

    /// The kinds in the set, in [`NameKind::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = NameKind> {
        NameKind::ALL
            .into_iter()
            .filter(move |kind| self.contains(*kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Q-080 items 1-2: printable ASCII only, A-Z folded, nothing else
    /// changed — checked on all 256 octet values.
    #[test]
    fn the_fold_is_ascii_with_a_to_z_folded() {
        for octet in 0u8..=255 {
            let expected = match octet {
                b'A'..=b'Z' => Some(octet + 32),
                0x20..=0x7E => Some(octet),
                _ => None,
            };
            assert_eq!(fold_octet(octet), expected, "{octet:#04x}");
        }
        assert_eq!(fold("Alice").as_deref(), Some("alice"));
        assert_eq!(fold(""), None);
        assert_eq!(fold("caf\u{e9}"), None);
        assert_eq!(fold("a\tb"), None);
        assert_eq!(
            fold(&"a".repeat(MAX_KEY_OCTETS)).map(|f| f.len()),
            Some(2048)
        );
        assert_eq!(fold(&"a".repeat(MAX_KEY_OCTETS + 1)), None);
        assert!(folded_eq("krbtgt", "KrbTgt"));
        assert!(!folded_eq("krbtgt", "krbtgt$"));
    }

    /// docs/59 §4.2 (injectivity); Q-1007 item 5; [MS-ADTS] 2.2.21.
    #[test]
    fn keys_join_components_and_refuse_separators() {
        let key = PrincipalKey::of_components(&["HOST", "WS01.example.test"]).unwrap();
        assert_eq!(key.as_str(), "host/ws01.example.test");
        assert_eq!(key.first_component(), "host");
        assert_eq!(key.components().count(), 2);
        assert_eq!(
            PrincipalKey::of_components(&["host", "a/b"]),
            Err(NameRefused::Separator)
        );
        assert_eq!(
            PrincipalKey::of_components(&["a@b"]),
            Err(NameRefused::Separator)
        );
        assert_eq!(
            PrincipalKey::of_components(&["host", ""]),
            Err(NameRefused::Empty)
        );
        assert_eq!(PrincipalKey::of_components(&[]), Err(NameRefused::Empty));
        assert_eq!(
            PrincipalKey::of_components(&["a", "b", "c", "d"]),
            Err(NameRefused::SpnForm)
        );
        let long = "a".repeat(MAX_KEY_OCTETS - 2);
        assert!(PrincipalKey::of_components(&["a", &long]).is_ok());
        assert_eq!(
            PrincipalKey::of_components(&["ab", &long]),
            Err(NameRefused::TooLong)
        );
    }

    /// docs/59 §4.1, §4.7; Q-1007 item 4.
    #[test]
    fn kind_sets() {
        let set = KindSet::EMPTY
            .with(NameKind::SamAccountName)
            .with(NameKind::UpnLocal);
        assert!(set.contains(NameKind::UpnLocal));
        assert!(!set.contains(NameKind::HostName));
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            [NameKind::SamAccountName, NameKind::UpnLocal]
        );
        assert!(set
            .intersection(KindSet::EMPTY.with(NameKind::HostName))
            .is_empty());
        assert!(KindSet::EMPTY.is_empty());
        assert_eq!(NameKind::ALL.len(), 6);
    }
}
