//! Filter evaluation: three-valued, over what the requester may read.
//!
//! # The logic (RFC 4511 §4.5.1.7)
//!
//! "A filter of the "and" choice is TRUE if all the filters in the SET OF
//! evaluate to TRUE, FALSE if at least one filter is FALSE, and Undefined
//! otherwise. A filter of the "or" choice is FALSE if all the filters in the
//! SET OF evaluate to FALSE, TRUE if at least one filter is TRUE, and
//! Undefined otherwise." 'not' swaps TRUE and FALSE and keeps Undefined.
//! Only TRUE selects an entry. Nothing here is an error: "Servers MUST NOT
//! return errors if attribute descriptions or matching rule ids are not
//! recognized, assertion values are invalid, or the assertion syntax is not
//! supported" — those are Undefined.
//!
//! # A filter item, in this order
//!
//! 1. The description is not recognised (crate::search::attrs) → Undefined
//!    ("(shoeSize=*) ... would each evaluate to Undefined").
//! 2. memberOf, a back link and so a constructed attribute ([MS-ADTS]
//!    3.1.1.4.5) → Undefined: AD answers inappropriateMatching
//!    (3.1.1.3.1.3.1), which RFC 4511 forbids; Q-168 item 2.
//! 3. A Secret attribute or nTSecurityDescriptor "does not exist" (docs/49
//!    §6.5) → FALSE, without asking the PDP (docs/11 P6).
//! 4. The assertion, independently of the object: a choice the attribute's
//!    comparison rule does not support ([MS-ADTS] 3.1.1.2.2.4 table), or an
//!    assertion value that is not valid for the syntax → Undefined.
//! 5. The attribute is not readable by the requester (`DirRead(attr)`
//!    denied): its values "are treated as "does not exist" in ... the LDAP
//!    filter" ([MS-ADTS] 3.1.1.4.3, 3.1.1.4.4) — evaluated over no values, so
//!    a filter is no oracle for a value the requester may not read (docs/49
//!    §6.1 item 4).
//! 6. Otherwise the rule is applied to every value (crate::search::syntax):
//!    TRUE if some value matches, FALSE if none can, Undefined otherwise. A
//!    DN-valued attribute's values are only the targets the requester can see
//!    (docs/49 §6.5), so a DN assertion naming a hidden object and one naming
//!    no object behave alike (FALSE) — no existence oracle.
//!
//! approxMatch is equalityMatch ([MS-ADTS] 3.1.1.3.1.3.1; RFC 4511
//! §4.5.1.7.6). extensibleMatch: with no matchingRule and a type, an
//! equality on the type (RFC 4511 §4.5.1.7.7); with no type, Undefined
//! ([MS-ADTS] 3.1.1.3.1.3.1); with any matchingRule — the
//! LDAP_MATCHING_RULE_* of [MS-ADTS] 3.1.1.3.4.4 included — Undefined in
//! phase 1 (Q-168 item 6); dnAttributes "is ignored and always treated as if
//! set to FALSE" (3.1.1.3.1.3.1). objectCategory with an lDAPDisplayName of
//! a class V matches the objects whose most specific class has the
//! defaultObjectCategory of V ([MS-ADTS] 3.1.1.3.1.3.5); any other value
//! (a DN — there is no schema NC in phase 1) is Undefined (Q-168 item 3).
//! The always-TRUE clauses (objectClass=*), (distinguishedName=*), (name=*)
//! and (objectGUID=*) ([MS-ADTS] 3.1.1.3.1.3.1) follow from these rules —
//! the derived attribute is present on every object — provided the requester
//! may read it (docs/49 §6.2).
//!
//! Spec: RFC 4511 §4.5.1.7-§4.5.1.7.7; [MS-ADTS] v20261026 3.1.1.2.2.4,
//! 3.1.1.3.1.3.1, 3.1.1.3.1.3.5, 3.1.1.3.4.4, 3.1.1.4.3, 3.1.1.4.4,
//! 3.1.1.4.5; docs/49 §6.1 item 4, §6.2, §6.5; Q-080; Q-168 items 2, 3, 6, 7.

use core::cmp::Ordering;

use dirstore::{ClassId, ValueSyntax};
use dtyp::Guid;
use parse_ldap::{Filter, Substring};

use super::attrs::{describe, Attr, Kind};
use super::syntax::{
    any, compare_time, folded, is_oid, parse_boolean, parse_generalized_time, parse_integer,
    substrings_match, AssertedTime, Tri,
};
use super::{resolve_ldap_dn, Candidate, Search, Stop};
use crate::audit::AuditReason;

/// The comparison a filter item asks for.
#[derive(Debug, Clone, Copy)]
pub(super) enum Op<'f> {
    Present,
    Equal(&'f [u8]),
    Greater(&'f [u8]),
    Less(&'f [u8]),
    Substrings(&'f [Substring]),
}

/// equality / greaterOrEqual / lessOrEqual. Spec: RFC 4511 §4.5.1.7.1,
/// §4.5.1.7.3, §4.5.1.7.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cmp {
    Eq,
    Ge,
    Le,
}

impl Cmp {
    /// Apply to the ordering of a value against the assertion.
    /// Spec: RFC 4511 §4.5.1.7.3 (greaterOrEqual: TRUE when the ORDERING
    /// rule — value less than assertion — returns FALSE), §4.5.1.7.4
    /// (lessOrEqual: ORDERING or EQUALITY TRUE).
    fn holds(self, ordering: Ordering) -> bool {
        match self {
            Cmp::Eq => ordering == Ordering::Equal,
            Cmp::Ge => ordering != Ordering::Less,
            Cmp::Le => ordering != Ordering::Greater,
        }
    }
}

/// The comparison rule of an attribute ([MS-ADTS] 3.1.1.2.2.4 mapping).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rule {
    /// Secret / nTSecurityDescriptor: does not exist.
    Never,
    /// memberOf: constructed, not in filters.
    Constructed,
    /// UnicodeString (interim, Q-080).
    Text,
    /// Integer (Integer, LargeInteger).
    Integer,
    /// Time (Generalized-Time).
    Time,
    /// Bool.
    Bool,
    /// Octet and Sid.
    Octet,
    /// DN.
    Dn,
    /// OID (objectClass).
    Oid,
    /// objectCategory ([MS-ADTS] 3.1.1.3.1.3.5).
    Category,
}

/// The rule of each kind. Spec: [MS-ADTS] 3.1.1.2.2.4 (Boolean → Bool;
/// Integer, LargeInteger → Integer; Object(DS-DN) → DN; String(Octet) →
/// Octet; String(Sid) → Sid, compared by the Octet rule (.11);
/// String(Object-Identifier) → OID; String(Unicode) → UnicodeString;
/// String(Generalized-Time) → Time); docs/46 §1, §5.4.
fn rule_of(kind: Kind) -> Rule {
    match kind {
        Kind::Never | Kind::Stored(ValueSyntax::SecurityDescriptor) => Rule::Never,
        Kind::MemberOf => Rule::Constructed,
        Kind::Stored(ValueSyntax::Utf8String) | Kind::Name => Rule::Text,
        Kind::Stored(ValueSyntax::Integer32 | ValueSyntax::Integer) | Kind::InstanceType => {
            Rule::Integer
        }
        Kind::Stored(ValueSyntax::DsTime) => Rule::Time,
        Kind::Stored(ValueSyntax::Boolean) => Rule::Bool,
        Kind::Stored(ValueSyntax::OctetString | ValueSyntax::Guid | ValueSyntax::Sid)
        | Kind::ObjectGuid => Rule::Octet,
        Kind::Stored(ValueSyntax::ObjectRef) | Kind::DistinguishedName => Rule::Dn,
        Kind::ObjectClass => Rule::Oid,
        Kind::ObjectCategory => Rule::Category,
    }
}

/// A validated assertion. Text pieces are already folded (Q-080).
pub(super) enum Assertion<'f> {
    Present,
    Text(Cmp, Vec<u8>),
    TextSubstrings(Pieces<Vec<u8>>),
    Integer(Cmp, i128),
    Time(Cmp, AssertedTime),
    Bool(Cmp, bool),
    Octets(Cmp, &'f [u8]),
    OctetSubstrings(Pieces<&'f [u8]>),
    /// The object a DN assertion names, if any.
    Dn(Option<Guid>),
    /// The class an OID assertion names, if any.
    Class(Option<ClassId>),
    /// The defaultObjectCategory to match.
    Category(ClassId),
}

/// The pieces of a substrings assertion. Spec: RFC 4511 §4.5.1 (initial /
/// any / final).
pub(super) struct Pieces<T> {
    initial: Option<T>,
    anys: Vec<T>,
    last: Option<T>,
}

/// The values of a candidate's attribute, as the rule compares them.
pub(super) enum Values {
    Bytes(Vec<Vec<u8>>),
    Integers(Vec<i128>),
    Times(Vec<i64>),
    Bools(Vec<bool>),
    Guids(Vec<Guid>),
    Classes(Vec<ClassId>),
}

impl Values {
    fn is_empty(&self) -> bool {
        match self {
            Values::Bytes(v) => v.is_empty(),
            Values::Integers(v) => v.is_empty(),
            Values::Times(v) => v.is_empty(),
            Values::Bools(v) => v.is_empty(),
            Values::Guids(v) => v.is_empty(),
            Values::Classes(v) => v.is_empty(),
        }
    }
}

/// A stored value that does not have its syntax's canonical form: the
/// record passed dirstore's validation, so this cannot happen — fail closed.
fn malformed() -> Stop {
    Stop::Fail(AuditReason::DirectoryUnavailable)
}

/// What filter evaluation needs from the entry it evaluates: the one seam
/// between this module's logic (the three-valued tree, the items' steps,
/// assertion parsing, comparison) and the directory. A search candidate is
/// the directory-backed view ([`CandidateEntry`]); the fuzz hooks use a fixed
/// in-memory entry (crate::search::fuzz), so that the same code is fuzzed.
/// Spec: RFC 4511 §4.5.1.7; docs/CLEAN-ROOM.md (parsers of network input get a
/// fuzz target).
pub(super) trait EntryView {
    /// A recognised attribute of this entry.
    type Attr;

    /// Step 1: the attribute a description names and its comparison rule;
    /// `None` if the description is not recognised.
    fn describe(&self, description: &str) -> Option<(Self::Attr, Rule)>;

    /// Step 4 for the rules whose assertion names a directory object or a
    /// schema class (DN, OID, objectCategory — equality only): `None` if the
    /// assertion is invalid (Undefined).
    fn directory_assertion(
        &mut self,
        rule: Rule,
        value: &[u8],
    ) -> Result<Option<Assertion<'static>>, Stop>;

    /// Step 5: may the requester read the attribute?
    fn readable(&mut self, attr: &Self::Attr) -> bool;

    /// Step 6: the attribute's values, as its rule compares them.
    fn values(&mut self, attr: &Self::Attr) -> Result<Values, Stop>;
}

/// Evaluate `filter` for an entry (module documentation).
/// Spec: RFC 4511 §4.5.1.7.
pub(super) fn evaluate<E: EntryView>(entry: &mut E, filter: &Filter) -> Result<Tri, Stop> {
    match filter {
        Filter::And(items) => {
            let mut undefined = false;
            for item in items {
                match evaluate(entry, item)? {
                    Tri::False => return Ok(Tri::False),
                    Tri::Undefined => undefined = true,
                    Tri::True => {}
                }
            }
            Ok(if undefined { Tri::Undefined } else { Tri::True })
        }
        Filter::Or(items) => {
            let mut undefined = false;
            for item in items {
                match evaluate(entry, item)? {
                    Tri::True => return Ok(Tri::True),
                    Tri::Undefined => undefined = true,
                    Tri::False => {}
                }
            }
            Ok(if undefined {
                Tri::Undefined
            } else {
                Tri::False
            })
        }
        Filter::Not(inner) => Ok(evaluate(entry, inner)?.not()),
        // approxMatch "is implemented identically to equalityMatch".
        // Spec: [MS-ADTS] 3.1.1.3.1.3.1; RFC 4511 §4.5.1.7.6.
        Filter::EqualityMatch(a) | Filter::ApproxMatch(a) => {
            item(entry, &a.attribute_desc, Op::Equal(&a.assertion_value))
        }
        Filter::GreaterOrEqual(a) => {
            item(entry, &a.attribute_desc, Op::Greater(&a.assertion_value))
        }
        Filter::LessOrEqual(a) => item(entry, &a.attribute_desc, Op::Less(&a.assertion_value)),
        Filter::Present(description) => item(entry, description, Op::Present),
        Filter::Substrings(s) => item(entry, &s.r#type, Op::Substrings(&s.substrings)),
        // Spec: RFC 4511 §4.5.1.7.7; [MS-ADTS] 3.1.1.3.1.3.1; Q-168 item 6.
        Filter::ExtensibleMatch(m) => match (&m.matching_rule, &m.r#type) {
            (None, Some(t)) => item(entry, t, Op::Equal(&m.match_value)),
            _ => Ok(Tri::Undefined),
        },
        // "The type of filtering requested is not implemented."
        // Spec: RFC 4511 §4.5.1.7; docs/49 §2.3 E13.
        Filter::Unrecognized { .. } => Ok(Tri::Undefined),
    }
}

/// One filter item, steps 1-6 of the module documentation.
fn item<E: EntryView>(entry: &mut E, description: &str, op: Op<'_>) -> Result<Tri, Stop> {
    let Some((attr, rule)) = entry.describe(description) else {
        return Ok(Tri::Undefined);
    };
    match rule {
        Rule::Constructed => return Ok(Tri::Undefined),
        Rule::Never => return Ok(Tri::False),
        _ => {}
    }
    let Some(assertion) = assertion(entry, rule, op)? else {
        return Ok(Tri::Undefined);
    };
    if !entry.readable(&attr) {
        // "does not exist": no values. Spec: [MS-ADTS] 3.1.1.4.3.
        return Ok(Tri::False);
    }
    let values = entry.values(&attr)?;
    Ok(compare(&values, &assertion))
}

/// Step 4: the assertion for `rule`, or `None` (Undefined) if the rule does
/// not support the choice or the value is invalid.
/// Spec: [MS-ADTS] 3.1.1.2.2.4 (the supported-choice table); RFC 4511
/// §4.5.1.7 ("The assertion value is invalid"); RFC 4517 §3.3.3, §3.3.13,
/// §3.3.16; Q-080; Q-168 items 3, 7.
fn assertion<'f, E: EntryView>(
    entry: &mut E,
    rule: Rule,
    op: Op<'f>,
) -> Result<Option<Assertion<'f>>, Stop> {
    let ordered = |op: Op<'f>| -> Option<(Cmp, &'f [u8])> {
        match op {
            Op::Equal(v) => Some((Cmp::Eq, v)),
            Op::Greater(v) => Some((Cmp::Ge, v)),
            Op::Less(v) => Some((Cmp::Le, v)),
            Op::Present | Op::Substrings(_) => None,
        }
    };
    if matches!(op, Op::Present) {
        return Ok(Some(Assertion::Present));
    }
    Ok(match rule {
        Rule::Never | Rule::Constructed => None,
        Rule::Text => match op {
            Op::Substrings(pieces) => text_pieces(pieces).map(Assertion::TextSubstrings),
            other => ordered(other).and_then(|(cmp, v)| folded(v).map(|f| Assertion::Text(cmp, f))),
        },
        Rule::Octet => match op {
            Op::Substrings(pieces) => Some(Assertion::OctetSubstrings(octet_pieces(pieces))),
            other => ordered(other).map(|(cmp, v)| Assertion::Octets(cmp, v)),
        },
        Rule::Integer => {
            ordered(op).and_then(|(cmp, v)| parse_integer(v).map(|n| Assertion::Integer(cmp, n)))
        }
        Rule::Time => ordered(op)
            .and_then(|(cmp, v)| parse_generalized_time(v).map(|t| Assertion::Time(cmp, t))),
        Rule::Bool => {
            ordered(op).and_then(|(cmp, v)| parse_boolean(v).map(|b| Assertion::Bool(cmp, b)))
        }
        // DN, OID and objectCategory: present and equality only.
        // Spec: [MS-ADTS] 3.1.1.2.2.4 (table), 3.1.1.3.1.3.5.
        Rule::Dn | Rule::Oid | Rule::Category => match op {
            Op::Equal(v) => entry.directory_assertion(rule, v)?,
            _ => None,
        },
    })
}

/// A search candidate as an [`EntryView`]: the directory, the PDP and the
/// schema behind each step (crate::search).
struct CandidateEntry<'a, 'r> {
    search: &'a mut Search<'r>,
    cand: &'a mut Candidate<'r>,
}

impl EntryView for CandidateEntry<'_, '_> {
    type Attr = Attr;

    /// Spec: crate::search::attrs; [MS-ADTS] 3.1.1.2.2.4 (the rule of each
    /// syntax).
    fn describe(&self, description: &str) -> Option<(Attr, Rule)> {
        describe(self.search.p1, &self.search.known, description).map(|a| (a, rule_of(a.kind)))
    }

    fn directory_assertion(
        &mut self,
        rule: Rule,
        value: &[u8],
    ) -> Result<Option<Assertion<'static>>, Stop> {
        Ok(match rule {
            Rule::Dn => self.search.dn_assertion(value)?.map(Assertion::Dn),
            Rule::Oid => self.search.class_assertion(value).map(Assertion::Class),
            Rule::Category => self
                .search
                .category_assertion(value)
                .map(Assertion::Category),
            _ => None,
        })
    }

    fn readable(&mut self, attr: &Attr) -> bool {
        self.search.readable(self.cand, attr)
    }

    fn values(&mut self, attr: &Attr) -> Result<Values, Stop> {
        self.search.values(self.cand, attr)
    }
}

impl<'r> Search<'r> {
    /// Evaluate `filter` for the candidate (module documentation).
    /// Spec: RFC 4511 §4.5.1.7.
    pub(super) fn eval(&mut self, cand: &mut Candidate<'r>, filter: &Filter) -> Result<Tri, Stop> {
        evaluate(&mut CandidateEntry { search: self, cand }, filter)
    }

    /// A DN assertion value: `None` if it is not a valid LDAPDN (Undefined),
    /// `Some(None)` if it names no object of the NC (including a well-formed
    /// DN no phase-1 object can carry), `Some(Some(guid))` otherwise.
    /// Resolved once per distinct value, within the DN-value bound.
    /// Spec: [MS-ADTS] 3.1.1.2.2.4.5 ("DN values are equal when they name the
    /// same object"); RFC 4517 §3.3.9; docs/49 §7; Q-195 item 4.
    fn dn_assertion(&mut self, value: &[u8]) -> Result<Option<Option<Guid>>, Stop> {
        if let Some(known) = self.dn_assertions.get(value) {
            return Ok(*known);
        }
        self.count_dn_value()?;
        let resolved = match core::str::from_utf8(value) {
            Err(_) => None,
            Ok(text) => match resolve_ldap_dn(self.view, text) {
                Ok(Ok(guid)) => Some(Some(guid)),
                Ok(Err(parse_ldap::ResultCode::InvalidDnSyntax)) => None,
                Ok(Err(_)) => Some(None),
                Err(()) => return Err(Stop::Fail(AuditReason::DirectoryUnavailable)),
            },
        };
        self.dn_assertions.insert(value.to_vec(), resolved);
        Ok(resolved)
    }

    /// An OID assertion (objectClass): a descr names a class by its
    /// lDAPDisplayName (ASCII case-insensitive), a numericoid by its
    /// governsID; a valid OID naming no class names nothing (`Some(None)`);
    /// anything else is invalid (`None`). Spec: [MS-ADTS] 3.1.1.2.2.4.10,
    /// 3.1.1.2.2.2 note †††; RFC 4512 §1.4.
    fn class_assertion(&self, value: &[u8]) -> Option<Option<ClassId>> {
        let text = core::str::from_utf8(value).ok()?;
        if !is_oid(text) {
            return None;
        }
        if text.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            Some(
                self.p1
                    .classes()
                    .find(|c| c.entry.governs_id == text)
                    .map(|c| c.id),
            )
        } else {
            Some(self.p1.class_by_name(text))
        }
    }

    /// An objectCategory assertion: the lDAPDisplayName V of a class gives
    /// V's defaultObjectCategory; anything else (a DN) is Undefined.
    /// Spec: [MS-ADTS] 3.1.1.3.1.3.5; Q-168 item 3.
    fn category_assertion(&self, value: &[u8]) -> Option<ClassId> {
        let text = core::str::from_utf8(value).ok()?;
        let class = self.p1.class_by_name(text)?;
        self.p1.class(class).map(|c| c.default_object_category)
    }

    /// One more DN-valued value resolved, within the search's bound.
    /// Spec: crate::search::limits (`MAX_DN_VALUES_RESOLVED`).
    pub(super) fn count_dn_value(&mut self) -> Result<(), Stop> {
        if self.dn_values >= self.limits.max_dn_values {
            return Err(Stop::Limit(
                parse_ldap::ResultCode::AdminLimitExceeded,
                AuditReason::ValueBudgetExceeded,
            ));
        }
        self.dn_values += 1;
        Ok(())
    }

    /// The candidate's values of a readable attribute, as its rule compares
    /// them (step 6). Spec: docs/46 §1, §5.4; docs/49 §6.4, §6.5.
    fn values(&mut self, cand: &Candidate<'_>, attr: &Attr) -> Result<Values, Stop> {
        let stored: Vec<&[u8]> = cand
            .obj()
            .attribute(attr.id)
            .map(|a| a.values.iter().map(|v| v.value.as_slice()).collect())
            .unwrap_or_default();
        Ok(match attr.kind {
            Kind::Stored(ValueSyntax::Utf8String | ValueSyntax::OctetString)
            | Kind::Stored(ValueSyntax::Guid | ValueSyntax::Sid) => {
                Values::Bytes(stored.iter().map(|v| v.to_vec()).collect())
            }
            Kind::Stored(ValueSyntax::Integer32) => Values::Integers(
                stored
                    .iter()
                    .map(|v| {
                        <[u8; 4]>::try_from(*v)
                            .map(|b| i128::from(i32::from_be_bytes(b)))
                            .map_err(|_| malformed())
                    })
                    .collect::<Result<_, _>>()?,
            ),
            Kind::Stored(ValueSyntax::Integer) => Values::Integers(
                stored
                    .iter()
                    .map(|v| {
                        <[u8; 8]>::try_from(*v)
                            .map(|b| i128::from(i64::from_be_bytes(b)))
                            .map_err(|_| malformed())
                    })
                    .collect::<Result<_, _>>()?,
            ),
            Kind::Stored(ValueSyntax::DsTime) => Values::Times(
                stored
                    .iter()
                    .map(|v| {
                        <[u8; 8]>::try_from(*v)
                            .map(i64::from_be_bytes)
                            .map_err(|_| malformed())
                    })
                    .collect::<Result<_, _>>()?,
            ),
            Kind::Stored(ValueSyntax::Boolean) => Values::Bools(
                stored
                    .iter()
                    .map(|v| match v {
                        [0x00] => Ok(false),
                        [0x01] => Ok(true),
                        _ => Err(malformed()),
                    })
                    .collect::<Result<_, _>>()?,
            ),
            Kind::Stored(ValueSyntax::ObjectRef) => {
                let mut visible = Vec::new();
                for v in stored {
                    let target = Guid::decode(v).map_err(|_| malformed())?;
                    if self.visible_ref(target)?.is_some() {
                        visible.push(target);
                    }
                }
                Values::Guids(visible)
            }
            Kind::Name => Values::Bytes(vec![self.rdn_value(cand.obj())?.to_vec()]),
            Kind::ObjectGuid => Values::Bytes(vec![cand.obj().guid.to_packet().to_vec()]),
            Kind::InstanceType => Values::Integers(vec![i128::from(instance_type(cand))]),
            Kind::DistinguishedName => Values::Guids(vec![cand.obj().guid]),
            Kind::ObjectClass => Values::Classes(self.class_of(cand.obj())?.object_class.clone()),
            Kind::ObjectCategory => {
                Values::Classes(vec![self.class_of(cand.obj())?.default_object_category])
            }
            // Unreachable: handled by the rule (steps 2-3).
            Kind::Never | Kind::MemberOf | Kind::Stored(ValueSyntax::SecurityDescriptor) => {
                Values::Bytes(Vec::new())
            }
        })
    }
}

/// instanceType: "writable on this directory" (0x4), plus "head of naming
/// context" (0x1) for the NC root. Spec: docs/46 §5.4 ([MS-ADA1] 2.309).
pub(super) fn instance_type(cand: &Candidate<'_>) -> i64 {
    const WRITABLE: i64 = 0x4;
    const NC_HEAD: i64 = 0x1;
    if cand.is_nc_root() {
        WRITABLE | NC_HEAD
    } else {
        WRITABLE
    }
}

/// The folded pieces of a String(Unicode) substrings assertion; `None` if a
/// piece is not printable ASCII. Spec: Q-080; Q-168 item 7.
fn text_pieces(pieces: &[Substring]) -> Option<Pieces<Vec<u8>>> {
    let mut out = Pieces {
        initial: None,
        anys: Vec::new(),
        last: None,
    };
    for piece in pieces {
        match piece {
            Substring::Initial(v) => out.initial = Some(folded(v)?),
            Substring::Any(v) => out.anys.push(folded(v)?),
            Substring::Final(v) => out.last = Some(folded(v)?),
        }
    }
    Some(out)
}

/// The pieces of an octet-string substrings assertion ("each byte in the
/// value is treated as if it was a character", case-sensitive).
/// Spec: [MS-ADTS] 3.1.1.2.2.4.7.
fn octet_pieces(pieces: &[Substring]) -> Pieces<&[u8]> {
    let mut out = Pieces {
        initial: None,
        anys: Vec::new(),
        last: None,
    };
    for piece in pieces {
        match piece {
            Substring::Initial(v) => out.initial = Some(v.as_slice()),
            Substring::Any(v) => out.anys.push(v.as_slice()),
            Substring::Final(v) => out.last = Some(v.as_slice()),
        }
    }
    out
}

/// Apply a validated assertion to the values (step 6).
/// Spec: [MS-ADTS] 3.1.1.2.2.4.1, .2, .5, .7, .10-.14; RFC 4511 §4.5.1.7.
fn compare(values: &Values, assertion: &Assertion<'_>) -> Tri {
    match (assertion, values) {
        (Assertion::Present, values) => Tri::of(!values.is_empty()),
        (Assertion::Text(cmp, a), Values::Bytes(vs)) => any(vs.iter().map(|v| match folded(v) {
            Some(f) => Tri::of(cmp.holds(f.as_slice().cmp(a.as_slice()))),
            None => Tri::Undefined,
        })),
        (Assertion::TextSubstrings(p), Values::Bytes(vs)) => {
            let anys: Vec<&[u8]> = p.anys.iter().map(Vec::as_slice).collect();
            any(vs.iter().map(|v| match folded(v) {
                Some(f) => Tri::of(substrings_match(
                    &f,
                    p.initial.as_deref(),
                    &anys,
                    p.last.as_deref(),
                )),
                None => Tri::Undefined,
            }))
        }
        (Assertion::Octets(cmp, a), Values::Bytes(vs)) => {
            any(vs.iter().map(|v| Tri::of(cmp.holds(v.as_slice().cmp(a)))))
        }
        (Assertion::OctetSubstrings(p), Values::Bytes(vs)) => any(vs
            .iter()
            .map(|v| Tri::of(substrings_match(v, p.initial, &p.anys, p.last)))),
        (Assertion::Integer(cmp, a), Values::Integers(vs)) => {
            any(vs.iter().map(|v| Tri::of(cmp.holds(v.cmp(a)))))
        }
        (Assertion::Time(cmp, a), Values::Times(vs)) => {
            any(vs.iter().map(|v| Tri::of(cmp.holds(compare_time(*v, *a)))))
        }
        // "A value of TRUE is considered to be greater than a value of
        // FALSE." Spec: [MS-ADTS] 3.1.1.2.2.4.1.
        (Assertion::Bool(cmp, a), Values::Bools(vs)) => {
            any(vs.iter().map(|v| Tri::of(cmp.holds(v.cmp(a)))))
        }
        (Assertion::Dn(target), Values::Guids(vs)) => match target {
            Some(g) => Tri::of(vs.contains(g)),
            None => Tri::False,
        },
        (Assertion::Class(class), Values::Classes(vs)) => match class {
            Some(c) => Tri::of(vs.contains(c)),
            None => Tri::False,
        },
        (Assertion::Category(c), Values::Classes(vs)) => Tri::of(vs.contains(c)),
        // A rule / value mismatch cannot arise (both come from the kind);
        // fail safe.
        _ => Tri::Undefined,
    }
}
