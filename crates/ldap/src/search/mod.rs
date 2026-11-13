//! Search over the directory (docs/49 R49-9, §6; build task L8).
//!
//! # The algorithm (docs/49 §6.1), against ONE snapshot
//!
//! Every read comes from the request's directory view: one dirstore
//! snapshot, which is also the PIP of every PDP question ([MS-ADTS]
//! 3.1.1.5.1.4: "Each Search request ... is performed as a transaction";
//! docs/11 §6 P9).
//!
//! 0. **The operation's preconditions**, before the base is even parsed, so
//!    that no answer below depends on whether a DN exists: the caller's time
//!    is a PDP instant; the view's naming context is the engine's (one
//!    source of truth, A-53); the requester's subject (crate::subject); and
//!    a `DirList` question on the NC root — if the PDP refuses it for a
//!    reason that does not depend on the object (layer 1 `Unauthenticated`
//!    → operationsError, Q-169 item 3; layer 2 `WeakTransport` →
//!    confidentialityRequired / strongerAuthRequired; the subject's tier or
//!    a PIP failure → other), the search ends here with that code
//!    (docs/questions/Q-200 item 5). Otherwise an anonymous requester would
//!    get noSuchObject for a nonexistent base and operationsError for an
//!    existing one — an existence oracle.
//! 1. **The base** (docs/49 §7, R49-11): parse-ldap's RFC 4514 parser; a
//!    syntax error (the grammar, a multi-valued RDN, an alternative form
//!    other than `<GUID=hex>`) → invalidDNSyntax; a well-formed DN no
//!    phase-1 object can carry (a value that is not printable ASCII, empty,
//!    too long, or a hexstring) → noSuchObject (Q-195 item 4). The DN is
//!    resolved by `DirectoryView::lookup_dn` (the NC suffix compared by its
//!    case-folded key and stripped, then the name index from the NC root —
//!    A-53); `<GUID=hex>` through `get_object` ([MS-ADTS] 3.1.1.3.1.2.4).
//!    No such object, or one outside the NC → noSuchObject (R49-17: no
//!    referral). The PDP then only ever sees the directory's canonical DN
//!    (`dn_of`), never the client's spelling.
//! 2. **The base's visibility** = `DirList` on its parent (on the base itself
//!    for the NC root) — the operation-level decision, whose obligations are
//!    honoured (RateLimit → the caller's limiter, busy if refused;
//!    Constrain(MaxPageSize) → the page bound) and which the one audit event
//!    records. Denied → noSuchObject, identical to a nonexistent base
//!    (R49-13, A-48), except for the object-independent reasons of step 0.
//! 3. **Candidates by scope** (RFC 4511 §4.5.1.2): baseObject = the base;
//!    singleLevel = its children (`Snapshot::children`, in pages of
//!    [`limits::CHILD_PAGE_SIZE`]); wholeSubtree = the base and every
//!    descendant, depth first in name-index order (deterministic).
//!    **Visibility before the filter:** a container's children are
//!    enumerated only if the requester may list it ([MS-ADTS] 5.1.3.3.6),
//!    so an invisible object is never read as a candidate, and a container
//!    it may not list is not descended into at all — the whole subtree is
//!    pruned (docs/49 §6.1 item 3: a subset, never more; counted in the
//!    audit). **Fast path:** a filter that is, or whose top-level AND holds,
//!    an equality on a unique attribute (sAMAccountName, userPrincipalName,
//!    servicePrincipalName, objectSid) is answered from `lookup_unique`: the
//!    one candidate is accepted only if it is in scope and every container
//!    between the base and it may be listed — exactly the candidates the
//!    full walk would reach — and is then evaluated like any other.
//! 4. **Per candidate:** the visit budget and the time limits, then the
//!    filter (crate::search::filter: three-valued, an unreadable attribute
//!    "does not exist" — [MS-ADTS] 3.1.1.4.3), then on TRUE the size bound
//!    and the entry (crate::search::entry).
//! 5. **Limits** (crate::search::limits): the client's sizeLimit →
//!    sizeLimitExceeded; the server's page bound, the visit budget, the
//!    response octet bound, the DN-value bound, the depth bound →
//!    adminLimitExceeded; the client's timeLimit and the server's query
//!    duration, both on the caller's clock → timeLimitExceeded. The entries
//!    already sent stand, followed by the SearchResultDone with that code
//!    (RFC 4511 §4.5.2). A failure of the directory (integrity,
//!    consistency, storage) → other (docs/49 §9), likewise after the entries
//!    already sent.
//!
//! derefAliases is ignored: "Aliases are not supported in Active Directory"
//! ([MS-ADTS] 3.1.1.3.1.8; R49-17).
//!
//! Spec: RFC 4511 §4.5.1-§4.5.3, A.2; [MS-ADTS] v20261026 3.1.1.3.1.2.4,
//! 3.1.1.3.1.3.1, 3.1.1.3.1.8, 3.1.1.3.4.6, 3.1.1.4.3, 3.1.1.5.1.4,
//! 5.1.3.3.6; docs/49 §6 (R49-9), §7 (R49-11), §9 (R49-13), §10 (R49-14);
//! A-48, A-49, A-53; Q-168, Q-169, Q-195.

mod access;
mod attrs;
mod entry;
mod filter;
#[cfg(feature = "fuzz-hooks")]
pub mod fuzz;
pub(crate) mod limits;
mod syntax;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ad_schema::{ClassInfo, Phase1Schema};
use directory_pip::{DirectoryView, NamingContext, MAX_DN_DEPTH};
use dirstore::{AttrId, ChildCursor, ChildPage, Object};
use dtyp::Guid;
use krb_proto::KerberosTime;
use parse_ldap::dn::{parse_ldap_dn, DnError, LdapDn};
use parse_ldap::{Filter, MessageId, ResultCode, Scope, SearchRequest};
use pdp::{Context, Dn, Effect, IpScope, Obligation, PolicySnapshot, ReasonCode, TransportSec};

use crate::audit::{AuditReason, SearchAudit};
use crate::inputs::{RateLimiter, SearchClock};
use crate::respond;
use crate::session::Channel;
use crate::subject::{context_transport, denial_code, subject, visibility_denial_code, Requester};
use crate::time::{seconds_between, unix_instant};

use access::{list_target, Access};
use attrs::{describe, Attr, Known};
pub(crate) use limits::SearchLimits;

/// Everything one directory search needs. Spec: crate::inputs; docs/49 §11.
pub(crate) struct SearchParams<'r> {
    pub(crate) message_id: MessageId,
    pub(crate) request: &'r SearchRequest,
    pub(crate) requester: &'r Requester,
    pub(crate) policy: &'r PolicySnapshot,
    pub(crate) rate: &'r mut dyn RateLimiter,
    pub(crate) now: KerberosTime,
    pub(crate) src_net: IpScope,
    pub(crate) channel: Channel,
    pub(crate) transport_sec: TransportSec,
    pub(crate) view: &'r DirectoryView<'r>,
    pub(crate) clock: &'r dyn SearchClock,
    pub(crate) naming_context: &'r NamingContext,
    pub(crate) limits: SearchLimits,
}

/// The result of one directory search: the encoded entries, the
/// SearchResultDone code, and the audit facts.
pub(crate) struct SearchOutcome {
    pub(crate) entries: Vec<Vec<u8>>,
    pub(crate) code: ResultCode,
    pub(crate) reason: AuditReason,
    pub(crate) target: Option<Guid>,
    pub(crate) audit: SearchAudit,
}

/// Why a search stopped before considering every candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// A bound: this code, the entries already sent standing.
    /// Spec: RFC 4511 §4.5.2; docs/49 §6.1 item 7, §9.
    Limit(ResultCode, AuditReason),
    /// The directory failed: other (fail closed). Spec: docs/49 §9.
    Fail(AuditReason),
}

/// The page bound of a search and the code its exhaustion gets.
/// Spec: RFC 4511 §4.5.1.4; docs/49 §6.1 item 7; Q-168 item 5.
#[derive(Debug, Clone, Copy)]
struct Cap {
    limit: u64,
    code: ResultCode,
    reason: AuditReason,
}

/// What the attribute selection asks for. Spec: RFC 4511 §4.5.1.8.
struct Selection {
    /// An empty list or "*": "all user attributes".
    all_user: bool,
    /// Attributes named, each once (the subsequent names are ignored).
    named: Vec<Attr>,
}

/// A candidate: a live object of the NC, its canonical DN, and the read
/// decisions taken for it so far.
pub(crate) struct Candidate {
    pub(crate) obj: Object,
    pub(crate) dn: Dn,
    readable: BTreeMap<AttrId, bool>,
}

impl Candidate {
    fn new(obj: Object, dn: Dn) -> Candidate {
        Candidate {
            obj,
            dn,
            readable: BTreeMap::new(),
        }
    }

    /// The NC root has no parent (A-53: the only parentless object with a
    /// DN). Spec: [MS-ADTS] 3.1.1.1.5.
    pub(crate) fn is_nc_root(&self) -> bool {
        self.obj.parent.is_none()
    }
}

/// One frame of the depth-first walk: a listable container and the rest of
/// its current page of children.
struct Frame {
    guid: Guid,
    dn: Dn,
    page: VecDeque<Guid>,
    next: Option<ChildCursor>,
}

/// The state of one search.
pub(crate) struct Search<'r> {
    view: &'r DirectoryView<'r>,
    p1: &'r Phase1Schema,
    known: Known,
    access: Access<'r>,
    request: &'r SearchRequest,
    message_id: MessageId,
    clock: &'r dyn SearchClock,
    start: KerberosTime,
    limits: SearchLimits,
    cap: Cap,
    selection: Selection,
    /// Resolved DN assertions of the filter: `None` = invalid (Undefined),
    /// `Some(None)` = names no object.
    dn_assertions: BTreeMap<Vec<u8>, Option<Option<Guid>>>,
    entries: Vec<Vec<u8>>,
    response_octets: usize,
    visited: u32,
    pruned: u32,
    dn_values: usize,
}

/// Run one directory search (module documentation).
pub(crate) fn run(p: SearchParams<'_>) -> SearchOutcome {
    let mut out = SearchOutcome {
        entries: Vec::new(),
        code: ResultCode::Other,
        reason: AuditReason::InternalFailure,
        target: None,
        audit: SearchAudit::new(crate::engine::audit_scope(p.request.scope)),
    };
    let p1 = p.view.context().schema();
    let Some(known) = Known::resolve(p1) else {
        return out.end(ResultCode::Other, AuditReason::DirectoryUnavailable);
    };
    out.audit.filter_attrs = filter_attributes(p1, &known, &p.request.filter);

    // 0. Preconditions. Spec: docs/11 §1, P9; A-53; crate::subject.
    let Some(time) = unix_instant(&p.now) else {
        return out.end(ResultCode::Other, AuditReason::ClockOutOfRange);
    };
    if p.view.context().naming_context() != p.naming_context {
        return out.end(ResultCode::Other, AuditReason::NamingContextMismatch);
    }
    let Ok(subject) = subject(p.requester, p.view) else {
        return out.end(ResultCode::Other, AuditReason::SubjectUnavailable);
    };
    let context = Context {
        src_net: p.src_net,
        time,
        transport: context_transport(p.channel),
        transport_sec: p.transport_sec,
    };
    let mut access = Access::new(subject, context, p.policy, p.view);
    // The object-independent refusals, before the base is looked at
    // (module documentation, step 0). Spec: Q-169 item 3; docs/49 §9.
    let probe = access.decide_list(p.naming_context.dn());
    if probe.effect != Effect::Allow && object_independent(probe.reason) {
        return out.end(
            denial_code(probe.reason, p.transport_sec),
            AuditReason::PolicyDenied(probe.reason),
        );
    }

    // 1. The base. Spec: docs/49 §7; Q-195 item 4; A-53.
    let base = match resolve_base(p.view, &p.request.base_object) {
        Ok(Ok(guid)) => guid,
        Ok(Err(code)) => {
            let reason = if code == ResultCode::InvalidDnSyntax {
                AuditReason::BaseDnSyntax
            } else {
                AuditReason::BaseNotFound
            };
            return out.end(code, reason);
        }
        Err(()) => return out.end(ResultCode::Other, AuditReason::DirectoryUnavailable),
    };
    out.target = Some(base);
    let base_obj = match p.view.snapshot().get_object(base) {
        Ok(Some(obj)) => obj,
        Ok(None) => return out.end(ResultCode::NoSuchObject, AuditReason::BaseNotFound),
        Err(_) => return out.end(ResultCode::Other, AuditReason::DirectoryUnavailable),
    };
    let base_dn = match p.view.dn_of(base) {
        Ok(Some(dn)) => dn,
        Ok(None) => return out.end(ResultCode::NoSuchObject, AuditReason::BaseNotFound),
        Err(_) => return out.end(ResultCode::Other, AuditReason::DirectoryUnavailable),
    };

    // 2. The base's visibility: the operation-level decision.
    // Spec: docs/49 §6.1 item 2; [MS-ADTS] 5.1.3.3.6; docs/11 §2, §8.
    let decision = access.decide_list(&list_target(&base_dn, base_obj.parent.is_none()));
    if decision.effect != Effect::Allow {
        let code = visibility_denial_code(decision.reason, p.transport_sec);
        let reason = if code == ResultCode::NoSuchObject {
            AuditReason::BaseNotVisible
        } else {
            AuditReason::PolicyDenied(decision.reason)
        };
        return out.end(code, reason);
    }
    let mut server_page = p.limits.max_page_size;
    for obligation in &decision.obligations {
        match obligation {
            // This search's one audit event (crate::audit).
            Obligation::Audit => {}
            Obligation::RateLimit(key) => {
                if !p.rate.admit(key, &p.now) {
                    return out.end(ResultCode::Busy, AuditReason::RateLimited);
                }
            }
            Obligation::Constrain(pdp::Constraint::MaxPageSize(n)) => {
                server_page = server_page.min(*n);
            }
        }
    }

    // 3-5. Candidates, filter, entries, limits.
    let mut search = Search {
        view: p.view,
        p1,
        known,
        access,
        request: p.request,
        message_id: p.message_id,
        clock: p.clock,
        start: p.now,
        limits: p.limits,
        cap: cap(p.request.size_limit, server_page),
        selection: selection(p1, &known, &p.request.attributes),
        dn_assertions: BTreeMap::new(),
        entries: Vec::new(),
        response_octets: 0,
        visited: 0,
        pruned: 0,
        dn_values: 0,
    };
    let status = search.scan(Candidate::new(base_obj, base_dn));
    out.audit.entries_returned = u32::try_from(search.entries.len()).unwrap_or(u32::MAX);
    out.audit.candidates_visited = search.visited;
    out.audit.pruned_subtrees = search.pruned;
    out.entries = core::mem::take(&mut search.entries);
    match status {
        Ok(()) => out.end(ResultCode::Success, AuditReason::SearchCompleted),
        Err(Stop::Limit(code, reason)) => out.end(code, reason),
        Err(Stop::Fail(reason)) => out.end(ResultCode::Other, reason),
    }
}

impl SearchOutcome {
    fn end(mut self, code: ResultCode, reason: AuditReason) -> SearchOutcome {
        self.code = code;
        self.reason = reason;
        self
    }
}

/// The PDP reasons that do not depend on the object asked about: layer 1,
/// layer 2, the subject's tier, a malformed request, and a PIP failure
/// (which, on the NC root, means the directory or the PIP is broken).
/// Spec: docs/11 §4 (layers 1-2 precede every object lookup; P3);
/// Q-169 item 3; docs/49 §9.
fn object_independent(reason: ReasonCode) -> bool {
    matches!(
        reason,
        ReasonCode::Unauthenticated
            | ReasonCode::WeakTransport
            | ReasonCode::SubjectMismatch
            | ReasonCode::InvalidRequest
            | ReasonCode::PipFailure
    )
}

/// A DnError that marks a well-formed DN no phase-1 object can carry
/// (noSuchObject), as opposed to a syntax error (invalidDNSyntax).
/// Spec: Q-195 item 4; docs/49 §7, §9.
pub(crate) fn names_nothing(error: DnError) -> bool {
    matches!(
        error,
        DnError::ValueNotPrintableAscii
            | DnError::EmptyValue
            | DnError::ValueTooLong
            | DnError::HexStringValue
    )
}

/// Resolve an LDAPDN to a live object of the naming context: `Ok(Ok(guid))`,
/// `Ok(Err(code))` (invalidDNSyntax / noSuchObject), or `Err(())` when the
/// directory could not answer.
/// Spec: RFC 4511 §4.1.3; docs/49 §7 (R49-11); [MS-ADTS] 3.1.1.3.1.2.4;
/// Q-195 items 1, 4; A-53.
pub(crate) fn resolve_ldap_dn(
    view: &DirectoryView<'_>,
    text: &str,
) -> Result<Result<Guid, ResultCode>, ()> {
    match parse_ldap_dn(text) {
        Ok(LdapDn::Distinguished(dn)) => {
            let rdns: Vec<(&str, &str)> = dn
                .rdns()
                .iter()
                .map(|r| (r.attribute_type().as_str(), r.value()))
                .collect();
            match view.lookup_dn(&rdns) {
                Ok(Some(guid)) => Ok(Ok(guid)),
                Ok(None) => Ok(Err(ResultCode::NoSuchObject)),
                Err(_) => Err(()),
            }
        }
        // "the hexadecimal representation of the binary form of a GUID"
        // ([MS-DTYP] 2.3.4.2 packet). Spec: [MS-ADTS] 3.1.1.3.1.2.4.
        Ok(LdapDn::ObjectGuid(octets)) => {
            let guid = Guid::from_packet(&octets);
            match view.dn_of(guid) {
                Ok(Some(_)) => Ok(Ok(guid)),
                Ok(None) => Ok(Err(ResultCode::NoSuchObject)),
                Err(_) => Err(()),
            }
        }
        Err(error) if names_nothing(error) => Ok(Err(ResultCode::NoSuchObject)),
        Err(_) => Ok(Err(ResultCode::InvalidDnSyntax)),
    }
}

/// The search base, resolved (step 1 of the module documentation).
fn resolve_base(view: &DirectoryView<'_>, base: &str) -> Result<Result<Guid, ResultCode>, ()> {
    resolve_ldap_dn(view, base)
}

/// The page bound: the client's sizeLimit (0 = none) and the server's,
/// whichever is smaller; reaching the client's is sizeLimitExceeded, the
/// server's adminLimitExceeded. Spec: RFC 4511 §4.5.1.4 ("Servers may also
/// enforce a maximum number of entries to return"); docs/49 §6.1 item 7;
/// Q-168 item 5.
fn cap(size_limit: u32, server: u32) -> Cap {
    let server = u64::from(server);
    if size_limit != 0 && u64::from(size_limit) <= server {
        Cap {
            limit: u64::from(size_limit),
            code: ResultCode::SizeLimitExceeded,
            reason: AuditReason::SizeLimitExceeded,
        }
    } else {
        Cap {
            limit: server,
            code: ResultCode::AdminLimitExceeded,
            reason: AuditReason::PageLimitExceeded,
        }
    }
}

/// The selection of RFC 4511 §4.5.1.8: an empty list or "*" asks for all
/// user attributes; "1.1" is ignored (alone it asks for none); an
/// unrecognised description is ignored; each attribute at most once.
/// Spec: RFC 4511 §4.5.1.8; docs/49 §6.3.
fn selection(p1: &Phase1Schema, known: &Known, selectors: &[String]) -> Selection {
    let mut all_user = selectors.is_empty();
    let mut named: Vec<Attr> = Vec::new();
    for selector in selectors {
        match selector.as_str() {
            "*" => all_user = true,
            "1.1" => {}
            description => {
                if let Some(attr) = describe(p1, known, description) {
                    if !named.iter().any(|a| a.id == attr.id) {
                        named.push(attr);
                    }
                }
            }
        }
    }
    Selection { all_user, named }
}

/// The lDAPDisplayNames of the recognised attributes a filter names, sorted
/// and each once (audit: schema names, never values or client spellings).
/// Spec: docs/49 §10.1 (`filter_attrs`).
fn filter_attributes(p1: &Phase1Schema, known: &Known, filter: &Filter) -> Vec<&'static str> {
    fn walk<'f>(filter: &'f Filter, out: &mut Vec<&'f str>) {
        match filter {
            Filter::And(items) | Filter::Or(items) => {
                items.iter().for_each(|f| walk(f, out));
            }
            Filter::Not(inner) => walk(inner, out),
            Filter::EqualityMatch(a)
            | Filter::GreaterOrEqual(a)
            | Filter::LessOrEqual(a)
            | Filter::ApproxMatch(a) => out.push(&a.attribute_desc),
            Filter::Substrings(s) => out.push(&s.r#type),
            Filter::Present(d) => out.push(d),
            Filter::ExtensibleMatch(m) => {
                if let Some(t) = &m.r#type {
                    out.push(t);
                }
            }
            Filter::Unrecognized { .. } => {}
        }
    }
    let mut descriptions = Vec::new();
    walk(filter, &mut descriptions);
    descriptions
        .into_iter()
        .filter_map(|d| describe(p1, known, d).map(|a| a.name))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

impl<'r> Search<'r> {
    /// The class information of a candidate's most specific class.
    /// Spec: [MS-ADTS] 3.1.1.2.4.3; docs/46 §8.3 item 1.
    fn class_of(&self, obj: &Object) -> Result<&'r ClassInfo, Stop> {
        let p1 = self.p1;
        let id = p1
            .schema()
            .most_specific_class(&obj.classes)
            .ok_or(Stop::Fail(AuditReason::DirectoryUnavailable))?;
        p1.class(id)
            .ok_or(Stop::Fail(AuditReason::DirectoryUnavailable))
    }

    /// Whether the requester may read `attr` of the candidate, decided once
    /// per candidate and attribute. Spec: crate::search::access.
    fn readable(&mut self, cand: &mut Candidate, attr: &Attr) -> bool {
        if let Some(r) = cand.readable.get(&attr.id) {
            return *r;
        }
        let r = self.access.may_read(&cand.dn, attr.guid);
        cand.readable.insert(attr.id, r);
        r
    }

    /// Steps 3-5 of the module documentation: the candidates of the scope,
    /// starting from the (visible) base.
    fn scan(&mut self, base: Candidate) -> Result<(), Stop> {
        let request = self.request;
        let scope = request.scope;
        if self.limits.unique_index {
            if let Some((id, value)) = self.unique_equality(&request.filter) {
                return self.unique_path(base, scope, id, value);
            }
        }
        match scope {
            Scope::BaseObject => self.visit(base),
            Scope::SingleLevel => self.one_level(base),
            Scope::WholeSubtree => self.subtree(base),
            // Refused by the dispatcher before the search (docs/49 E14).
            Scope::Unrecognized(_) => Err(Stop::Limit(
                ResultCode::ProtocolError,
                AuditReason::ScopeUnrecognized,
            )),
        }
    }

    /// One candidate: the visit budget, the time limits, the filter, and on
    /// TRUE the entry. Spec: docs/49 §6.1 items 3-7; RFC 4511 §4.5.1.5,
    /// §4.5.1.7.
    fn visit(&mut self, mut cand: Candidate) -> Result<(), Stop> {
        self.check_time()?;
        if self.visited >= self.limits.visit_budget {
            return Err(Stop::Limit(
                ResultCode::AdminLimitExceeded,
                AuditReason::VisitBudgetExceeded,
            ));
        }
        self.visited += 1;
        let request = self.request;
        if self.eval(&mut cand, &request.filter)? == syntax::Tri::True {
            self.emit(&mut cand)?;
        }
        Ok(())
    }

    /// The client's timeLimit and the server's query duration, on the
    /// caller's clock: more than the limit's seconds since the request's
    /// `now` → timeLimitExceeded. A clock that went backwards counts as no
    /// time elapsed. Spec: RFC 4511 §4.5.1.5 ("A value of zero in this field
    /// indicates that no client-requested time limit restrictions are in
    /// effect"; "Servers may also enforce a maximum time limit"); [MS-ADTS]
    /// 3.1.1.3.4.6 (MaxQueryDuration); docs/49 §9.
    fn check_time(&self) -> Result<(), Stop> {
        let elapsed = seconds_between(&self.clock.now(), &self.start)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let client = self.request.time_limit;
        if client != 0 && elapsed > u64::from(client) {
            return Err(Stop::Limit(
                ResultCode::TimeLimitExceeded,
                AuditReason::TimeLimitExceeded,
            ));
        }
        if elapsed > self.limits.max_query_seconds {
            return Err(Stop::Limit(
                ResultCode::TimeLimitExceeded,
                AuditReason::QueryDurationExceeded,
            ));
        }
        Ok(())
    }

    /// Send the entry of a matching candidate, within the page bound and the
    /// response octet bound. Spec: RFC 4511 §4.5.1.4, §4.5.2; docs/49 §6.1
    /// item 7.
    fn emit(&mut self, cand: &mut Candidate) -> Result<(), Stop> {
        if self.entries.len() as u64 >= self.cap.limit {
            return Err(Stop::Limit(self.cap.code, self.cap.reason));
        }
        let entry = self.entry(cand)?;
        let octets = respond::entry(self.message_id, entry)
            .map_err(|_| Stop::Fail(AuditReason::InternalFailure))?;
        let total = self.response_octets.saturating_add(octets.len());
        if total > self.limits.max_response_octets {
            return Err(Stop::Limit(
                ResultCode::AdminLimitExceeded,
                AuditReason::ResponseTooLarge,
            ));
        }
        self.response_octets = total;
        self.entries.push(octets);
        Ok(())
    }

    /// One page of the children of `parent`. Spec: A-49 (`children`:
    /// authenticated, cross-checked, complete on the final page).
    fn page(
        &self,
        parent: Guid,
        after: Option<&ChildCursor>,
        limit: usize,
    ) -> Result<ChildPage, Stop> {
        self.view
            .snapshot()
            .children(Some(parent), after, limit)
            .map_err(|_| Stop::Fail(AuditReason::DirectoryUnavailable))
    }

    /// The candidate for a child `guid` of the container `parent_dn`: its DN
    /// is its RDN followed by the parent's DN ([MS-ADTS] 3.1.1.1.4).
    fn child(&self, guid: Guid, parent_dn: &Dn) -> Result<Candidate, Stop> {
        let obj = self
            .view
            .snapshot()
            .get_object(guid)
            .map_err(|_| Stop::Fail(AuditReason::DirectoryUnavailable))?
            .ok_or(Stop::Fail(AuditReason::DirectoryUnavailable))?;
        let component = self
            .view
            .rdn_component(&obj)
            .map_err(|_| Stop::Fail(AuditReason::DirectoryUnavailable))?;
        if parent_dn.rdns().len() >= MAX_DN_DEPTH {
            return Err(Stop::Limit(
                ResultCode::AdminLimitExceeded,
                AuditReason::DepthExceeded,
            ));
        }
        let mut rdns = Vec::with_capacity(parent_dn.rdns().len() + 1);
        rdns.push(component);
        rdns.extend(parent_dn.rdns().iter().cloned());
        Ok(Candidate::new(obj, Dn::new(rdns)))
    }

    /// singleLevel: the children of the base, if the requester may list it.
    /// Spec: RFC 4511 §4.5.1.2 ("the immediate subordinates"); [MS-ADTS]
    /// 5.1.3.3.6; docs/49 §6.1 item 3.
    fn one_level(&mut self, base: Candidate) -> Result<(), Stop> {
        if !self.access.may_list(&base.dn) {
            self.pruned += 1;
            return Ok(());
        }
        let mut cursor: Option<ChildCursor> = None;
        loop {
            let page = self.page(base.obj.guid, cursor.as_ref(), self.limits.child_page)?;
            for guid in page.children {
                let cand = self.child(guid, &base.dn)?;
                self.visit(cand)?;
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => return Ok(()),
            }
        }
    }

    /// wholeSubtree: the base and every descendant the requester can see,
    /// depth first in name-index order; a container it may not list is not
    /// descended into (pruned). Spec: RFC 4511 §4.5.1.2 ("the entry named
    /// by baseObject and ... all its subordinates"); [MS-ADTS] 5.1.3.3.6;
    /// docs/49 §6.1 item 3.
    fn subtree(&mut self, base: Candidate) -> Result<(), Stop> {
        let (guid, dn) = (base.obj.guid, base.dn.clone());
        self.visit(base)?;
        let mut stack: Vec<Frame> = Vec::new();
        self.descend(guid, dn, &mut stack)?;
        while let Some(top) = stack.last_mut() {
            if let Some(child) = top.page.pop_front() {
                let parent_dn = top.dn.clone();
                let cand = self.child(child, &parent_dn)?;
                let (guid, dn) = (cand.obj.guid, cand.dn.clone());
                self.visit(cand)?;
                self.descend(guid, dn, &mut stack)?;
            } else if let Some(next) = top.next.take() {
                let page = self.page(top.guid, Some(&next), self.limits.child_page)?;
                top.page = page.children.into();
                top.next = page.next;
            } else {
                stack.pop();
            }
        }
        Ok(())
    }

    /// Push a frame for the container `guid` if it has children and the
    /// requester may list it; a non-empty container it may not list is
    /// pruned. Emptiness is probed with a one-entry page first, so a pruned
    /// container costs one index read, not a page.
    /// Spec: docs/49 §6.1 item 3; [MS-ADTS] 5.1.3.3.6.
    fn descend(&mut self, guid: Guid, dn: Dn, stack: &mut Vec<Frame>) -> Result<(), Stop> {
        let probe = self.page(guid, None, 1)?;
        if probe.children.is_empty() {
            return Ok(());
        }
        if !self.access.may_list(&dn) {
            self.pruned += 1;
            return Ok(());
        }
        if stack.len() >= MAX_DN_DEPTH {
            return Err(Stop::Limit(
                ResultCode::AdminLimitExceeded,
                AuditReason::DepthExceeded,
            ));
        }
        let first = self.page(guid, None, self.limits.child_page)?;
        stack.push(Frame {
            guid,
            dn,
            page: first.children.into(),
            next: first.next,
        });
        Ok(())
    }

    /// The fast path's equality: the filter itself, or the first item of its
    /// top-level AND, that is an equalityMatch on a unique stored attribute
    /// (docs/46 §8.5). Spec: docs/49 §6.1 item 3.
    fn unique_equality<'f>(&self, filter: &'f Filter) -> Option<(AttrId, &'f [u8])> {
        let unique = |f: &'f Filter| -> Option<(AttrId, &'f [u8])> {
            let Filter::EqualityMatch(ava) = f else {
                return None;
            };
            let attr = describe(self.p1, &self.known, &ava.attribute_desc)?;
            let def = self.p1.schema().attribute(attr.id)?;
            (def.unique && matches!(attr.kind, attrs::Kind::Stored(_)))
                .then_some((attr.id, ava.assertion_value.as_slice()))
        };
        match filter {
            Filter::And(items) => items.iter().find_map(unique),
            other => unique(other),
        }
    }

    /// The fast path (module documentation, step 3): the one object holding
    /// `value` in the unique attribute `id`, if it is a candidate the full
    /// walk of `scope` would reach. Spec: docs/49 §6.1 item 3; [MS-ADTS]
    /// 5.1.3.3.6.
    fn unique_path(
        &mut self,
        base: Candidate,
        scope: Scope,
        id: AttrId,
        value: &[u8],
    ) -> Result<(), Stop> {
        let snapshot = self.view.snapshot();
        let guid = match snapshot.lookup_unique(id, value) {
            Ok(Some(guid)) => guid,
            // A value no stored value can equal (too long, or a string that
            // has no comparison key): no candidate. Spec: Q-080.
            Ok(None) | Err(dirstore::Error::Rejected(_)) => return Ok(()),
            Err(_) => return Err(Stop::Fail(AuditReason::DirectoryUnavailable)),
        };
        if guid == base.obj.guid {
            return match scope {
                Scope::BaseObject | Scope::WholeSubtree => self.visit(base),
                _ => Ok(()),
            };
        }
        let obj = snapshot
            .get_object(guid)
            .map_err(|_| Stop::Fail(AuditReason::DirectoryUnavailable))?
            .ok_or(Stop::Fail(AuditReason::DirectoryUnavailable))?;
        match scope {
            Scope::SingleLevel => {
                if obj.parent != Some(base.obj.guid) {
                    return Ok(());
                }
                if !self.access.may_list(&base.dn) {
                    self.pruned += 1;
                    return Ok(());
                }
                let cand = self.child(guid, &base.dn)?;
                self.visit(cand)
            }
            Scope::WholeSubtree => {
                // The distance from the object up to the base, if the base is
                // an ancestor. Each object below the NC root adds one DN
                // component, so the k-th ancestor's DN is the object's DN
                // without its first k components ([MS-ADTS] 3.1.1.1.4).
                let mut distance = 0usize;
                let mut at = obj.parent;
                loop {
                    let Some(ancestor) = at else {
                        return Ok(());
                    };
                    distance += 1;
                    if distance > MAX_DN_DEPTH {
                        return Err(Stop::Limit(
                            ResultCode::AdminLimitExceeded,
                            AuditReason::DepthExceeded,
                        ));
                    }
                    if ancestor == base.obj.guid {
                        break;
                    }
                    at = snapshot
                        .get_object(ancestor)
                        .map_err(|_| Stop::Fail(AuditReason::DirectoryUnavailable))?
                        .ok_or(Stop::Fail(AuditReason::DirectoryUnavailable))?
                        .parent;
                }
                let dn = self
                    .view
                    .dn_of(guid)
                    .map_err(|_| Stop::Fail(AuditReason::DirectoryUnavailable))?
                    .ok_or(Stop::Fail(AuditReason::DirectoryUnavailable))?;
                for k in 1..=distance {
                    let container = Dn::new(
                        dn.rdns()
                            .get(k..)
                            .map(<[String]>::to_vec)
                            .unwrap_or_default(),
                    );
                    if !self.access.may_list(&container) {
                        self.pruned += 1;
                        return Ok(());
                    }
                }
                self.visit(Candidate::new(obj, dn))
            }
            Scope::BaseObject | Scope::Unrecognized(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests;
